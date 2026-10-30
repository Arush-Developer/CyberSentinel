"""Conditional investigation of suspicious flows, using a deterministic planner.

The planner picks tools from the trigger set and adapts the next pick to what earlier tools found.
No LLM is involved and none is required. The verdict is computed only from tool results.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

import numpy as np

from backend.investigation.registry import ToolRegistry
from backend.investigation.tools import SUPPORTS_ATTACK, SUPPORTS_BENIGN

MAX_ACTIONS_DEFAULT = 3
TRIGGER_DISAGREEMENT = "AGENT_DISAGREEMENT"
TRIGGER_LOW_CONFIDENCE = "LOW_CONFIDENCE"
TRIGGER_HIGH_ANOMALY = "HIGH_ANOMALY"
TRIGGER_CAMPAIGN = "CAMPAIGN_ACTIVITY"
TRIGGER_CAMPAIGN_CONFLICT = "CAMPAIGN_CLASS_CONFLICT"

VERDICT_ATTACK = "SUPPORTS_ATTACK"
VERDICT_BENIGN = "SUPPORTS_BENIGN"
VERDICT_CONFLICTING = "CONFLICTING"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"


class InvestigationCancelled(Exception):
    pass


def triggers_for(threat_class: str, disagree: bool, low_confidence: bool, anomaly_score: float,
                 high_anomaly: float, in_campaign: bool, campaign_conflict: bool) -> list[str]:
    triggers = []
    if disagree:
        triggers.append(TRIGGER_DISAGREEMENT)
    if low_confidence:
        triggers.append(TRIGGER_LOW_CONFIDENCE)
    if anomaly_score >= high_anomaly:
        triggers.append(TRIGGER_HIGH_ANOMALY)
    if in_campaign and threat_class == "BENIGN":
        triggers.append(TRIGGER_CAMPAIGN)
    if campaign_conflict:
        triggers.append(TRIGGER_CAMPAIGN_CONFLICT)
    return triggers


def trigger_mask(threat_class: np.ndarray, agreement: np.ndarray, low_confidence: np.ndarray,
                 anomaly_score: np.ndarray, high_anomaly: float, in_campaign: np.ndarray,
                 campaign_conflict: np.ndarray) -> np.ndarray:
    return ((agreement == "DISAGREE") | low_confidence | (anomaly_score >= high_anomaly)
            | (in_campaign & (threat_class == "BENIGN")) | campaign_conflict)


def plan(triggers: list[str], has_endpoints: bool) -> list[str]:
    """Ordered tool preference. The orchestrator stops at its action budget."""
    order: list[str] = []
    if TRIGGER_DISAGREEMENT in triggers or TRIGGER_LOW_CONFIDENCE in triggers:
        order.append("inspect_agent_disagreement")
    if TRIGGER_HIGH_ANOMALY in triggers or TRIGGER_DISAGREEMENT in triggers:
        order.append("inspect_feature_deviations")
    if TRIGGER_CAMPAIGN in triggers or TRIGGER_CAMPAIGN_CONFLICT in triggers:
        order.append("inspect_campaign_context")
    order.append("inspect_source_activity" if has_endpoints else "find_related_flows")
    order.extend(["compare_against_benign_baseline", "inspect_port_distribution"])
    if has_endpoints:
        order.append("inspect_destination_activity")
    return list(dict.fromkeys(order))


@dataclass
class Orchestrator:
    registry: ToolRegistry
    max_actions: int = MAX_ACTIONS_DEFAULT
    cancel: threading.Event | None = None

    def investigate(self, flow_id: str, triggers: list[str]) -> dict:
        investigation_id = f"INV-{flow_id}"
        store = self.registry.store
        has_endpoints = store.has("source_ip", "destination_ip")
        audit = self.registry.audit
        audit.record("investigation_started", investigation_id=investigation_id, flow_id=flow_id, triggers=triggers)
        calls: list[dict] = []
        for name in plan(triggers, has_endpoints):
            if len(calls) >= self.max_actions:
                break
            if self.cancel is not None and self.cancel.is_set():
                audit.record("investigation_cancelled", investigation_id=investigation_id)
                raise InvestigationCancelled(investigation_id)
            if calls and name == "inspect_port_distribution" and not self._wants_port_view(calls):
                continue
            calls.append(self.registry.call(name, investigation_id, flow_id=flow_id))
        result = self._conclude(investigation_id, flow_id, triggers, calls)
        audit.record("investigation_finished", investigation_id=investigation_id, flow_id=flow_id,
                     verdict=result["verdict"], actions=len(calls))
        return result

    @staticmethod
    def _wants_port_view(calls: list[dict]) -> bool:
        """Port distribution only helps if the flow still looks undecided."""
        return not any(c["result"]["supports"] == SUPPORTS_ATTACK for c in calls)

    @staticmethod
    def _conclude(investigation_id: str, flow_id: str, triggers: list[str], calls: list[dict]) -> dict:
        usable = [c for c in calls if c["result"]["available"]]
        attack = [c for c in usable if c["result"]["supports"] == SUPPORTS_ATTACK]
        benign = [c for c in usable if c["result"]["supports"] == SUPPORTS_BENIGN]
        neutral = [c for c in usable if c not in attack and c not in benign]
        if attack and benign:
            verdict = VERDICT_CONFLICTING
        elif attack:
            verdict = VERDICT_ATTACK
        elif benign:
            verdict = VERDICT_BENIGN
        else:
            verdict = VERDICT_INCONCLUSIVE
        return {
            "investigation_id": investigation_id,
            "flow_id": flow_id,
            "triggers": triggers,
            "tools_selected": [c["tool"] for c in calls],
            "tool_calls": calls,
            # Relative to the suspicion being investigated: supporting points to an attack.
            "supporting_observations": [c["result"]["summary"] for c in attack],
            "contradicting_observations": [c["result"]["summary"] for c in benign],
            "neutral_observations": [c["result"]["summary"] for c in neutral],
            "unavailable_evidence": [c["result"]["summary"] for c in calls if not c["result"]["available"]],
            "status": "COMPLETED",
            "verdict": verdict,
            "planner": "deterministic",
        }
