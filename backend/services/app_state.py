"""Application state behind the API: the analysed eval partition, audit, replay and live policy."""
from __future__ import annotations

import json
import os
import threading
import time

import numpy as np
import pandas as pd

from backend.agents.fusion_agent import fusion_output
from backend.config import load_config, resolve
from backend.intelligence.evidence_engine import build_evidence_graph
from backend.investigation.audit import AuditLog
from backend.services.model_service import Analysis, Pipeline
from backend.policy.policy_engine import PolicyThresholds, policy_output, simulate
from backend.preprocessing.data_processor import load_flows, load_partition
from backend.replay.replay_engine import ReplayEngine

SUBMITTED_FLOW_ID = "submitted"
AUDIT_DB = "data/processed/cybersentinel.sqlite3"
REPLAY_INPUT_ENV = "CYBERSENTINEL_REPLAY_INPUT"  # Replay this flow file instead of the official eval partition.
REPORTS = ("training_report", "calibration_report", "evaluation_report", "leakage_audit",
           "level1_summary", "dataset_profile")


def plain(value):
    """Make numpy and pandas scalars JSON-safe."""
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    if isinstance(value, np.ndarray):
        return [plain(v) for v in value.tolist()]
    if isinstance(value, (np.bool_,)):
        return bool(value)
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, (float, np.floating)):
        return None if not np.isfinite(value) else float(value)
    return value


def records(frame: pd.DataFrame) -> list[dict]:
    return [plain(r) for r in frame.to_dict(orient="records")]


class AppState:
    def __init__(self, pipeline: Pipeline, analysis: Analysis, persist: bool = True,
                 replay_input: str = "official eval partition"):
        self.pipeline = pipeline
        self.analysis = analysis
        self.replay_input = replay_input
        self.audit = AuditLog(db_path=resolve(AUDIT_DB) if persist else None)
        self.replay = ReplayEngine(pipeline, analysis, self.audit, persist=persist)
        self.policy_history: list[dict] = [
            {k: e[k] for k in ("time", "previous", "new", "reason", "decisions_before", "decisions_after")}
            for e in self.audit.list("policy_change", limit=50)[::-1]]
        if self.policy_history:
            self._apply_thresholds(self.policy_history[-1]["new"])
        self._lock = threading.Lock()
        self.audit.record("system", action="loaded", flows=len(analysis.frame),
                          campaign_mode=analysis.campaign.mode)

    @classmethod
    def load(cls, persist: bool = True, partition: str = "eval") -> "AppState":
        pipeline = Pipeline.load()
        replay_input = os.environ.get(REPLAY_INPUT_ENV)
        data = load_flows(replay_input) if replay_input else load_partition(partition)
        # A separately supplied file gets its own saved state, so the two runs never mix.
        return cls(pipeline, pipeline.analyse(data), persist=persist and not replay_input,
                   replay_input=str(replay_input or "official eval partition"))

    # ---- Flows --------------------------------------------------------------------------------
    def scope_frame(self, scope: str) -> pd.DataFrame:
        if scope == "replay":
            return self.replay.replayed_frame()
        return self.analysis.frame

    def resolve_scope(self, scope: str | None) -> str:
        if scope in ("replay", "historical"):
            return scope
        return "replay" if self.replay.cursor else "historical"

    def list_flows(self, scope, offset, limit, decision=None, final_class=None, status=None, disagree=None,
                   campaign_id=None, search=None) -> dict:
        scope = self.resolve_scope(scope)
        frame = self.scope_frame(scope)
        if len(frame):
            if decision:
                frame = frame[frame["policy_decision"] == decision]
            if final_class:
                frame = frame[frame["final_class"] == final_class]
            if status:
                frame = frame[frame["evidence_status"] == status]
            if disagree is not None:
                frame = frame[(frame["agreement"] == "DISAGREE") == disagree]
            if campaign_id:
                frame = frame[frame["campaign_id"] == campaign_id]
            if search:
                frame = frame[frame["flow_id"].astype(str).str.contains(search, regex=False)]
        page = frame.iloc[offset:offset + limit] if len(frame) else frame
        return {"scope": scope, "total": int(len(frame)), "offset": offset, "limit": limit, "items": records(page)}

    def flow_row(self, flow_id: str) -> int:
        return self.analysis.store.row(flow_id)

    def flow_detail(self, flow_id: str, investigate: bool = True) -> dict:
        analysis, pipe = self.analysis, self.pipeline
        row = self.flow_row(flow_id)
        features = analysis.partition.features.iloc[[row]]
        supporting = pipe.anomaly.supporting_features(features)[0]
        result = analysis.frame.iloc[row]
        campaign_id = analysis.campaign.flow_campaign[row]
        campaign = analysis.store.campaigns.get(campaign_id) if campaign_id else None
        triggers = pipe.flow_triggers(analysis, row)

        investigation = self.replay.investigations.get(flow_id) or analysis.investigations.get(flow_id)
        if investigation is None and investigate and triggers:
            investigation = pipe.investigate_flow(analysis, row, self.audit)
            with self._lock:
                analysis.investigations[flow_id] = investigation
        labels = analysis.partition.labels
        detail = {
            "flow_id": flow_id,
            "network": plain({c: analysis.partition.metadata[c].iat[row]
                              for c in analysis.partition.metadata.columns if c != "flow_id"}),
            "unavailable_metadata": [c for c in load_config()["data"]["metadata_columns"]
                                     if c not in analysis.partition.metadata.columns],
            "threat": pipe.threat.to_output(flow_id, analysis.proba[row]),
            "anomaly": pipe.anomaly.to_output(flow_id, analysis.scores[row], supporting),
            "fusion": fusion_output(analysis.fusion, row, flow_id, supporting,
                                    campaign["campaign_type"] if campaign else None, investigation, campaign_id),
            "policy": policy_output(str(result["policy_decision"]), str(result["policy_rule"]), flow_id,
                                    float(result["threat_confidence"]), float(result["anomaly_score"]), campaign_id,
                                    investigation["investigation_id"] if investigation else None),
            "campaign": plain(_brief_campaign(campaign)) if campaign else None,
            "triggers": triggers,
            "investigation": plain(investigation) if investigation else None,
            "replay": self._flow_replay(flow_id),
            "ground_truth_evaluation_only": str(labels.iat[row]) if labels is not None else None,
        }
        detail["evidence_graph"] = build_evidence_graph(detail)
        return detail

    def _flow_replay(self, flow_id: str) -> dict | None:
        position = self.replay.position_of(flow_id)
        frame = self.replay.replayed_frame()
        if position is None or position >= len(frame):
            return None
        r = frame.iloc[position]
        return {"action": r["defense_action"], "applied_policy_id": r["applied_policy_id"] or None,
                "replay_decision": r["policy_decision"], "replay_evidence_status": r["evidence_status"]}

    def defense_state(self, member_limit: int = 25, group_limit: int = 200) -> dict:
        loop = self.replay.defense
        if loop is None:
            return {"available": False, "config": {}, "policies": [], "log": [], "groups": [], "groups_total": 0,
                    "unavailable_reason": "Agents 4 and 5 need source_ip and destination_ip. The participant pack "
                                          "omits them; the organisers ship them with the hidden set."}
        with self.replay.lock:
            groups = loop.temporal.public_groups(member_limit)
            return plain({"available": True, "unavailable_reason": None, "config": loop.defense.config.to_dict(),
                          "policies": loop.defense.public_policies(), "log": loop.defense.log[-500:][::-1],
                          "groups": groups[-group_limit:][::-1], "groups_total": len(groups)})

    def analyse_features(self, features: dict[str, float]) -> dict:
        frame = pd.DataFrame([features])
        pipe = self.pipeline
        proba, scores = pipe.score(frame)
        supporting = pipe.anomaly.supporting_features(frame)[0]
        fusion = pipe.fuse(proba, scores)
        result = pipe.results_frame([SUBMITTED_FLOW_ID], proba, fusion).iloc[0]
        self.audit.record("analyse_flow", final_class=str(result["final_class"]))
        return {
            "threat": pipe.threat.to_output(SUBMITTED_FLOW_ID, proba[0]),
            "anomaly": pipe.anomaly.to_output(SUBMITTED_FLOW_ID, scores[0], supporting),
            "fusion": fusion_output(fusion, 0, SUBMITTED_FLOW_ID, supporting),
            "policy": policy_output(str(result["policy_decision"]), str(result["policy_rule"]), SUBMITTED_FLOW_ID,
                                    float(proba[0].max()), float(scores[0])),
            "campaign": "not assessed: one submitted flow has no cross-flow context",
        }

    # ---- Campaigns and incidents ----------------------------------------------------------------
    def campaigns(self, scope: str | None) -> dict:
        scope = self.resolve_scope(scope)
        items = self.replay.tracker.public_campaigns() if scope == "replay" else self.analysis.campaign.campaigns
        return {"scope": scope, "mode": self.analysis.campaign.mode,
                "limitations": self.analysis.campaign.limitations, "items": plain(items)}

    def port_distribution(self, scope: str | None, top: int = 15) -> dict:
        scope = self.resolve_scope(scope)
        frame = self.scope_frame(scope)
        if not len(frame):
            return {"scope": scope, "items": []}
        rows = np.array([self.flow_row(str(f)) for f in frame["flow_id"]])
        ports = self.analysis.partition.metadata["destination_port"].to_numpy()[rows]
        data = pd.DataFrame({"port": ports, "attack": frame["final_class"].to_numpy() != "BENIGN"})
        grouped = data.groupby("port")["attack"].agg(flows="size", attacks="sum").sort_values("flows", ascending=False)
        return {"scope": scope, "distinct_ports": int(len(grouped)), "items": [
            {"port": float(p), "flows": int(r.flows), "attacks": int(r.attacks)} for p, r in grouped.head(top).iterrows()]}

    def incidents(self, scope: str | None, limit: int = 200) -> dict:
        scope = self.resolve_scope(scope)
        frame = self.scope_frame(scope)
        items: list[dict] = []
        for c in self.campaigns(scope)["items"]:
            items.append({
                "incident_id": f"INC-{c['campaign_id']}", "kind": "campaign", "severity": "high",
                "title": f"{c['campaign_type']} on {c['target']}",
                "summary": c["confidence_basis"], "flow_count": c["flow_count"], "campaign_id": c["campaign_id"],
                "flow_ids": c["related_flow_ids"][:25], "first_observed": c["first_observed"],
                "last_observed": c["last_observed"],
            })
        if len(frame):
            anomalies = frame[frame["evidence_status"] == "ANOMALY_ONLY"].nlargest(limit, "anomaly_score")
            for r in anomalies.itertuples(index=False):
                items.append({
                    "incident_id": f"INC-{r.flow_id}", "kind": "anomaly_only", "severity": "medium",
                    "title": f"Unexplained anomaly in {r.flow_id}",
                    "summary": f"Agent 1 called it BENIGN at {r.threat_confidence:.3f}; Agent 2 scored {r.anomaly_score:.3f}.",
                    "flow_count": 1, "flow_ids": [str(r.flow_id)], "campaign_id": None,
                    "first_observed": str(r.flow_id), "last_observed": str(r.flow_id),
                })
        return {"scope": scope, "total": len(items), "items": plain(items[:limit])}

    def incident(self, incident_id: str) -> dict:
        for scope in ("replay", "historical"):
            for item in self.incidents(scope, limit=100_000)["items"]:
                if item["incident_id"] == incident_id:
                    return item
        raise KeyError(incident_id)

    def investigation(self, investigation_id: str) -> dict:
        flow_id = investigation_id.removeprefix("INV-")
        found = self.replay.investigations.get(flow_id) or self.analysis.investigations.get(flow_id)
        if found is None:
            raise KeyError(investigation_id)
        return plain(found)

    def investigations(self, limit: int = 100) -> list[dict]:
        merged = {**self.analysis.investigations, **self.replay.investigations}
        items = list(merged.values())[-limit:][::-1]
        return [plain({k: v[k] for k in ("investigation_id", "flow_id", "triggers", "verdict", "planner")}
                      | {"tools": [c["tool"] for c in v["tool_calls"]]}) for v in items]

    # ---- Policy ---------------------------------------------------------------------------------
    def policy(self) -> dict:
        return {"thresholds": self.pipeline.thresholds.to_dict(), "history": self.policy_history[-50:],
                "calibrated": PolicyThresholds.calibrated().to_dict(), "simulated_only": True}

    def configure_policy(self, new: dict, reason: str) -> dict:
        previous = self.pipeline.thresholds.to_dict()
        before = self.analysis.frame["policy_decision"].value_counts().to_dict()
        self._apply_thresholds(new)
        entry = {"time": time.time(), "previous": previous, "new": new, "reason": reason,
                 "decisions_before": before,
                 "decisions_after": self.analysis.frame["policy_decision"].value_counts().to_dict()}
        self.policy_history.append(plain(entry))
        self.audit.record("policy_change", **plain(entry))
        return self.policy()

    def _apply_thresholds(self, new: dict) -> None:
        self.pipeline.thresholds = PolicyThresholds(**new)
        self.analysis.frame = self.pipeline.results_frame(
            self.analysis.frame["flow_id"].to_numpy(), self.analysis.proba, self.analysis.fusion,
            self.analysis.campaign.flow_campaign)

    def simulate_policy(self, proposed: dict, max_examples: int) -> dict:
        out = simulate(self.analysis.fusion, self.pipeline.thresholds, PolicyThresholds(**proposed),
                       self.analysis.frame["flow_id"].to_numpy(), max_examples)
        self.audit.record("policy_simulation", proposed=proposed, changed=out["changed"])
        return plain(out)

    # ---- Reports ----------------------------------------------------------------------------------
    def report(self, name: str) -> dict | None:
        path = resolve(load_config()["data"]["reports_dir"]) / f"{name}.json"
        return json.loads(path.read_text()) if path.exists() else None

    def metrics(self) -> dict:
        out = {name: self.report(name) for name in REPORTS if name != "dataset_profile"}
        profile = self.report("dataset_profile")
        if profile:
            out["dataset"] = {
                name: {k: p[k] for k in ("rows", "feature_count", "label_distribution",
                                         "duplicate_records_full_features", "constant_features",
                                         "duplicate_columns", "total_missing", "total_inf",
                                         "class_imbalance_ratio_max_over_min")}
                for name, p in profile["partitions"].items()} | {"cross_partition": profile["cross_partition"]}
        return out

    def summary(self) -> dict:
        snapshot = self.replay.snapshot()
        scope = self.resolve_scope(None)
        return {"replay": snapshot, "incidents": self.incidents(scope, limit=8),
                "campaign_mode": self.analysis.campaign.mode,
                "limitations": self.analysis.campaign.limitations}


def _brief_campaign(campaign: dict) -> dict:
    related = campaign["related_flow_ids"]
    return {**campaign, "related_flow_ids": related[:25], "related_flow_ids_total": len(related)}
