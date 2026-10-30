"""Loads the saved models and runs the agents, campaign engine, investigation and policy over flows."""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from backend.agents.anomaly_agent import AnomalyAgent
from backend.agents.fusion_agent import FusionConfig, FusionResult, fuse_batch
from backend.agents.investigation_orchestrator import (
    VERDICT_CONFLICTING, Orchestrator, trigger_mask, triggers_for)
from backend.agents.threat_agent import ThreatAgent
from backend.config import load_config, resolve
from backend.intelligence.campaign_engine import CampaignConfig, CampaignEngine, CampaignResult
from backend.investigation.audit import AuditLog
from backend.investigation.registry import ToolRegistry
from backend.investigation.tools import EvidenceStore
from backend.policy.policy_engine import CALIBRATED_PATH, PolicyThresholds, decide_batch
from backend.preprocessing.data_processor import Partition

CAMPAIGN_CONFIG_PATH = "configs/campaign_baseline.json"
HIGH_ANOMALY = 0.99  # Investigate flows more unusual than 99% of benign calibration flows.


def load_fusion_config() -> FusionConfig:
    path = resolve(CALIBRATED_PATH)
    if not path.exists():
        return FusionConfig()
    return FusionConfig(**json.loads(path.read_text())["fusion"])


@dataclass
class Analysis:
    """Everything known about one partition after a full pipeline run."""

    partition: Partition
    proba: np.ndarray
    scores: np.ndarray
    campaign: CampaignResult
    fusion: FusionResult
    frame: pd.DataFrame
    store: EvidenceStore
    triggered: np.ndarray
    investigations: dict = field(default_factory=dict)


@dataclass
class Pipeline:
    threat: ThreatAgent
    anomaly: AnomalyAgent
    fusion_config: FusionConfig
    thresholds: PolicyThresholds
    campaign_engine: CampaignEngine

    @classmethod
    def load(cls) -> "Pipeline":
        cfg = load_config()["models"]
        return cls(ThreatAgent.load(resolve(cfg["threat"])),
                   AnomalyAgent.load(resolve(cfg["anomaly"])),
                   load_fusion_config(), PolicyThresholds.calibrated(),
                   CampaignEngine(CampaignConfig.load(resolve(CAMPAIGN_CONFIG_PATH))))

    def fuse_level1(self, proba: np.ndarray, scores: np.ndarray) -> FusionResult:
        """Agents 1-3 alone, with no cross-flow evidence. This is what classification.csv reports."""
        return self.fuse(proba, scores)

    def score(self, features: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        return self.threat.predict_proba(features), self.anomaly.score(features)

    def fuse(self, proba: np.ndarray, scores: np.ndarray, **signals) -> FusionResult:
        return fuse_batch(proba, self.threat.classes, scores, self.anomaly.threshold,
                          self.fusion_config, **signals)

    def results_frame(self, flow_ids, proba: np.ndarray, fusion: FusionResult,
                      flow_campaign: np.ndarray | None = None) -> pd.DataFrame:
        decision, reason = decide_batch(fusion, self.thresholds)
        frame = pd.DataFrame({
            "flow_id": flow_ids,
            "threat_class": fusion.threat_class,
            "threat_confidence": fusion.threat_confidence,
            "anomaly_score": fusion.anomaly_score,
            "is_anomaly": fusion.is_anomaly,
            "agreement": fusion.agreement,
            "final_class": fusion.final_class,
            "final_class_source": fusion.final_class_source,
            "evidence_status": fusion.evidence_status,
            "low_confidence": fusion.low_confidence,
            "campaign_support": fusion.campaign_support,
            "campaign_conflict": fusion.campaign_conflict,
            "investigation_conflict": fusion.investigation_conflict,
            "campaign_id": flow_campaign if flow_campaign is not None else None,
            "policy_decision": decision,
            "policy_rule": reason,
        })
        for i, cls in enumerate(self.threat.classes):
            frame[f"proba_{cls}"] = proba[:, i]
        return frame

    def analyse(self, partition: Partition) -> Analysis:
        """Score and correlate a partition. Investigations run separately because they are per-flow."""
        proba, scores = self.score(partition.features)
        threat_class = np.array(self.threat.classes)[proba.argmax(axis=1)]
        is_anomaly = scores >= self.anomaly.threshold
        campaign = self.campaign_engine.detect(partition.metadata, partition.features, is_anomaly)
        support, conflict = campaign.signals(threat_class)
        fusion = self.fuse(proba, scores, campaign_support=support, campaign_conflict=conflict)
        ids = partition.metadata["flow_id"].to_numpy()
        frame = self.results_frame(ids, proba, fusion, campaign.flow_campaign)
        store = EvidenceStore(
            flow_ids=ids, features=partition.features, metadata=partition.metadata,
            threat_class=fusion.threat_class, threat_confidence=fusion.threat_confidence,
            anomaly_score=scores, is_anomaly=is_anomaly, flow_campaign=campaign.flow_campaign,
            campaigns={c["campaign_id"]: c for c in campaign.campaigns}, anomaly_agent=self.anomaly)
        triggered = trigger_mask(fusion.threat_class, fusion.agreement, fusion.low_confidence, scores,
                                 HIGH_ANOMALY, campaign.flow_campaign != None, conflict)  # noqa: E711
        return Analysis(partition, proba, scores, campaign, fusion, frame, store, triggered)

    def flow_triggers(self, analysis: Analysis, row: int) -> list[str]:
        f = analysis.fusion
        return triggers_for(str(f.threat_class[row]), f.agreement[row] == "DISAGREE", bool(f.low_confidence[row]),
                            float(f.anomaly_score[row]), HIGH_ANOMALY,
                            analysis.campaign.flow_campaign[row] is not None, bool(f.campaign_conflict[row]))

    def investigate_flow(self, analysis: Analysis, row: int, audit: AuditLog,
                         cancel: threading.Event | None = None) -> dict:
        registry = ToolRegistry(analysis.store, audit)
        try:
            return Orchestrator(registry, cancel=cancel).investigate(
                str(analysis.frame["flow_id"].iat[row]), self.flow_triggers(analysis, row))
        finally:
            registry.close()

    def run_investigations(self, analysis: Analysis, audit: AuditLog, limit: int | None = None,
                           cancel: threading.Event | None = None) -> dict:
        """Investigate triggered flows, then feed unresolved conflicts back into fusion and policy."""
        rows = np.flatnonzero(analysis.triggered)
        considered = rows if limit is None else rows[:limit]
        registry = ToolRegistry(analysis.store, audit)
        started = time.perf_counter()
        verdicts: dict[str, int] = {}
        conflict = np.zeros(len(analysis.frame), bool)
        solo = self.thresholds.block_classifier_only_confidence
        orchestrator = Orchestrator(registry, cancel=cancel)
        try:
            for row in considered:
                result = orchestrator.investigate(str(analysis.frame["flow_id"].iat[row]),
                                                  self.flow_triggers(analysis, row))
                analysis.investigations[result["flow_id"]] = result
                verdicts[result["verdict"]] = verdicts.get(result["verdict"], 0) + 1
                # Conflicting evidence only holds back a decision the classifier is not sure of.
                if result["verdict"] == VERDICT_CONFLICTING and analysis.fusion.threat_confidence[row] < solo:
                    conflict[row] = True
        finally:
            registry.close()
        analysis.fusion.investigation_conflict = conflict
        analysis.frame = self.results_frame(analysis.frame["flow_id"].to_numpy(), analysis.proba, analysis.fusion,
                                            analysis.campaign.flow_campaign)
        return {
            "triggered": int(len(rows)), "investigated": int(len(considered)),
            "verdicts": verdicts, "seconds": round(time.perf_counter() - started, 2),
            "conflicts_holding_decisions": int(conflict.sum()),
        }
