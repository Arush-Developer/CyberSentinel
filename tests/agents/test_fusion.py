"""SYNTHETIC inputs: fusion logic."""
import numpy as np

from backend.agents.fusion_agent import FusionConfig, fuse_batch, fusion_output, rationale
from backend.policy.policy_engine import PolicyThresholds, decide_batch, policy_output
from backend.schemas.contracts import FusionAssessment, PolicyOutcome

CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]
THRESHOLDS = PolicyThresholds(allow_benign_confidence=0.9, block_multi_signal_confidence=0.9,
                              block_classifier_only_confidence=0.99)


def proba(cls, confidence):
    row = np.full(5, (1 - confidence) / 4)
    row[CLASSES.index(cls)] = confidence
    return row


def run(cls, confidence, score, campaign=False, conflict=False, config=None):
    fused = fuse_batch(np.array([proba(cls, confidence)]), CLASSES, np.array([score]), 0.95,
                       config or FusionConfig(), campaign_support=np.array([campaign]),
                       campaign_conflict=np.array([conflict]))
    decision, reason = decide_batch(fused, THRESHOLDS)
    return fused, decision[0], reason[0]


def test_final_class_is_always_a_benchmark_class():
    fused, _, _ = run("BRUTE_FORCE", 0.55, 0.1)
    assert fused.final_class[0] in CLASSES and fused.low_confidence[0]


def test_override_only_applies_when_configured():
    row = np.array([[0.55, 0.05, 0.30, 0.05, 0.05]])
    plain = fuse_batch(row, CLASSES, np.array([0.99]), 0.95, FusionConfig())
    assert plain.final_class[0] == "BENIGN"
    over = fuse_batch(row, CLASSES, np.array([0.99]), 0.95, FusionConfig(benign_override_below=0.6))
    assert over.final_class[0] == "DOS" and over.final_class_source[0] == "validated_benign_override"
    assert over.threat_class[0] == "BENIGN"


def test_rationale_uses_measured_values():
    fused, _, _ = run("BENIGN", 0.97, 0.99)
    text = rationale(fused, 0, supporting=[{
        "feature": "Flow Packets/s", "measured_value": 12500.0, "benign_median": 12.0, "robust_z": 50.0}])
    assert "0.970" in text and "12500" in text and "disagree" in text


def test_outputs_match_contracts_and_carry_references():
    fused, decision, rule = run("BENIGN", 0.97, 0.99)
    output = fusion_output(fused, 0, "F1", investigation={"investigation_id": "INV-F1", "verdict": "CONFLICTING"})
    FusionAssessment(**output)
    assert output["investigation_refs"] == ["INV-F1"] and "CONFLICTING" in output["rationale"]
    policy = policy_output(decision, rule, "F1", 0.97, 0.99, investigation_id="INV-F1")
    PolicyOutcome(**policy)
    assert policy["policy_rule"] == rule and "investigation:INV-F1" in policy["evidence_refs"]
    assert "0.970" in policy["decision_reason"]
