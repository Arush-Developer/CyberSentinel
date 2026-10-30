"""Simulated ALLOW/BLOCK/REVIEW policy. Decisions are records only: nothing touches a network."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

import numpy as np

from backend.agents.fusion_agent import BENIGN, MULTI_SIGNAL_CONFIRMED, FusionResult
from backend.config import resolve
from backend.schemas.contracts import PolicyOutcome

ALLOW, BLOCK, REVIEW = "ALLOW", "BLOCK", "REVIEW"
CALIBRATED_PATH = "configs/calibrated.json"

RULE_REASONS = {
    "CONFIDENT_BENIGN_NO_OTHER_SIGNAL": "Confident benign call with no anomaly, campaign or investigation conflict.",
    "BENIGN_BELOW_ALLOW_THRESHOLD": "Benign call, but confidence is below the allow threshold.",
    "ANOMALY_ONLY_NEEDS_REVIEW": "Classifier says benign but the flow is statistically unusual.",
    "CAMPAIGN_ONLY_NEEDS_REVIEW": "Classifier says benign but the flow sits inside a campaign hypothesis.",
    "CONFIDENT_ATTACK_WITH_INDEPENDENT_SUPPORT": "Confident attack call with independent anomaly or campaign support.",
    "VERY_CONFIDENT_CLASSIFIER_ONLY": "Very confident attack call, with no second signal.",
    "ATTACK_BELOW_BLOCK_THRESHOLD": "Attack call, but confidence is below the block threshold for its evidence.",
    "UNRESOLVED_CONFLICT": "Campaign or investigation evidence conflicts with the classifier.",
    "WEAK_OR_INCOMPLETE_EVIDENCE": "Evidence is weak or incomplete.",
}


@dataclass
class PolicyThresholds:
    allow_benign_confidence: float = 0.90
    block_multi_signal_confidence: float = 0.90
    block_classifier_only_confidence: float = 0.99

    @classmethod
    def calibrated(cls) -> "PolicyThresholds":
        path = resolve(CALIBRATED_PATH)
        if not path.exists():
            return cls()
        return cls(**json.loads(path.read_text())["policy"])

    def to_dict(self) -> dict:
        return asdict(self)


def decide_batch(fusion: FusionResult, t: PolicyThresholds) -> tuple[np.ndarray, np.ndarray]:
    """Return (decision, rule) per flow. Rules are applied in order; first match wins."""
    n = len(fusion.final_class)
    conf = fusion.threat_confidence
    attack = fusion.final_class != BENIGN
    multi = fusion.evidence_status == MULTI_SIGNAL_CONFIRMED
    unresolved = fusion.campaign_conflict | fusion.investigation_conflict

    decision = np.full(n, REVIEW, dtype=object)
    reason = np.full(n, "WEAK_OR_INCOMPLETE_EVIDENCE", dtype=object)

    benign_clean = ~attack & ~fusion.is_anomaly & ~fusion.campaign_support & ~unresolved
    allow = benign_clean & (conf >= t.allow_benign_confidence)
    decision[allow], reason[allow] = ALLOW, "CONFIDENT_BENIGN_NO_OTHER_SIGNAL"
    reason[benign_clean & ~allow] = "BENIGN_BELOW_ALLOW_THRESHOLD"
    reason[~attack & fusion.is_anomaly] = "ANOMALY_ONLY_NEEDS_REVIEW"
    reason[~attack & fusion.campaign_support] = "CAMPAIGN_ONLY_NEEDS_REVIEW"

    block_multi = attack & multi & (conf >= t.block_multi_signal_confidence) & ~unresolved
    decision[block_multi], reason[block_multi] = BLOCK, "CONFIDENT_ATTACK_WITH_INDEPENDENT_SUPPORT"
    block_solo = attack & ~multi & (conf >= t.block_classifier_only_confidence) & ~unresolved
    decision[block_solo], reason[block_solo] = BLOCK, "VERY_CONFIDENT_CLASSIFIER_ONLY"
    reason[attack & ~block_multi & ~block_solo] = "ATTACK_BELOW_BLOCK_THRESHOLD"
    reason[attack & unresolved] = "UNRESOLVED_CONFLICT"
    reason[~attack & unresolved] = "UNRESOLVED_CONFLICT"
    return decision, reason


def policy_output(decision: str, rule: str, flow_id: str, confidence: float, anomaly_score: float,
                  campaign_id: str | None = None, investigation_id: str | None = None) -> dict:
    refs = [f"flow:{flow_id}", "agent:threat_detection", "agent:anomaly_detection"]
    if campaign_id:
        refs.append(f"campaign:{campaign_id}")
    if investigation_id:
        refs.append(f"investigation:{investigation_id}")
    return PolicyOutcome(
        decision=decision,
        policy_rule=rule,
        decision_reason=f"{RULE_REASONS[rule]} Confidence {confidence:.3f}, anomaly score {anomaly_score:.3f}.",
        evidence_refs=refs,
    ).model_dump()


def simulate(fusion: FusionResult, current: PolicyThresholds, proposed: PolicyThresholds,
             flow_ids=None, max_examples: int = 50) -> dict:
    """What-if comparison over already-processed flows. Stored results are not changed."""
    before, _ = decide_batch(fusion, current)
    after, reason = decide_batch(fusion, proposed)
    changed = np.flatnonzero(before != after)
    transitions: dict[str, int] = {}
    for a, b in zip(before[changed], after[changed]):
        key = f"{a}->{b}"
        transitions[key] = transitions.get(key, 0) + 1
    examples = [{
        "flow_id": str(flow_ids[i]) if flow_ids is not None else int(i),
        "before": str(before[i]), "after": str(after[i]), "reason": str(reason[i]),
        "final_class": str(fusion.final_class[i]),
        "confidence": float(fusion.threat_confidence[i]),
        "anomaly_score": float(fusion.anomaly_score[i]),
        "evidence_status": str(fusion.evidence_status[i]),
    } for i in changed[:max_examples]]
    count = lambda d: {k: int((d == k).sum()) for k in (ALLOW, BLOCK, REVIEW)}
    return {
        "flows_evaluated": len(before),
        "previous_thresholds": current.to_dict(),
        "new_thresholds": proposed.to_dict(),
        "decisions_before": count(before),
        "decisions_after": count(after),
        "changed": int(len(changed)),
        "transitions": transitions,
        "examples": examples,
    }
