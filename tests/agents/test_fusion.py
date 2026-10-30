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


def test_the_briefs_five_evidence_conditions():
    assert run("BENIGN", 0.99, 0.10)[0].evidence_status[0] == "AGREED_BENIGN"
    assert run("DOS", 0.99, 0.99)[0].evidence_status[0] == "MULTI_SIGNAL_ATTACK"
    assert run("DOS", 0.99, 0.10)[0].evidence_status[0] == "CLASSIFIER_ONLY"
    assert run("BENIGN", 0.99, 0.99)[0].evidence_status[0] == "ANOMALY_ONLY"
    assert run("DOS", 0.40, 0.99)[0].evidence_status[0] == "UNCERTAIN"
    assert run("BENIGN", 0.40, 0.10)[0].evidence_status[0] == "UNCERTAIN"


def test_anomaly_never_overwrites_the_classifier_class():
    fused, decision, _ = run("BENIGN", 0.99, 0.99)
    assert fused.final_class[0] == "BENIGN" and fused.agreement[0] == "DISAGREE" and decision == "REVIEW"


def test_campaign_evidence_is_not_reported_as_agent2_support():
    fused, decision, _ = run("DOS", 0.95, 0.10, campaign=True)
    assert fused.evidence_status[0] == "CAMPAIGN_CORROBORATED" and fused.agreement[0] == "DISAGREE"
    assert decision == "BLOCK"
    assert run("DOS", 0.95, 0.99, campaign=True)[0].evidence_status[0] == "MULTI_SIGNAL_ATTACK"
    assert run("BENIGN", 0.99, 0.10, campaign=True)[0].evidence_status[0] == "CAMPAIGN_ONLY"
    assert run("BENIGN", 0.99, 0.99, campaign=True)[0].evidence_status[0] == "ANOMALY_ONLY"


def test_uncertain_attack_is_never_blocked():
    assert run("DOS", 0.40, 0.99)[1] == "REVIEW"


def test_output_reports_confidence_status_and_evidence_references():
    fused, _, _ = run("DOS", 0.40, 0.99)
    out = fusion_output(fused, 0, "S1", [{"feature": "F", "measured_value": 1.0, "benign_median": 0.0, "robust_z": 9}],
                        campaign_type="DOS_CANDIDATE", campaign_id="CMP-1")
    assert out["confidence_status"] == "LOW_CONFIDENCE"
    assert {"flow:S1", "feature:F", "campaign:CMP-1"} <= set(out["evidence_refs"])

