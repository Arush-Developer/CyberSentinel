"""SYNTHETIC inputs: policy decisions for the cases in the brief for the cases in the brief."""
import numpy as np

from backend.agents.fusion_agent import (
    AGREED_BENIGN, ANOMALY_ONLY, CAMPAIGN_ONLY, CLASSIFIER_ONLY, MULTI_SIGNAL_CONFIRMED, FusionConfig, fuse_batch)
from backend.policy.policy_engine import ALLOW, BLOCK, REVIEW, PolicyThresholds, decide_batch, simulate

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


def test_case_a_multi_signal_blocks():
    fused, decision, _ = run("DDOS", 0.96, 0.99, campaign=True)
    assert fused.final_class[0] == "DDOS"
    assert fused.evidence_status[0] == MULTI_SIGNAL_CONFIRMED
    assert decision == BLOCK


def test_case_b_anomaly_only_reviews_without_changing_class():
    fused, decision, reason = run("BENIGN", 0.97, 0.99)
    assert fused.final_class[0] == "BENIGN"
    assert fused.evidence_status[0] == ANOMALY_ONLY
    assert fused.agreement[0] == "DISAGREE"
    assert decision == REVIEW and reason == "ANOMALY_ONLY_NEEDS_REVIEW"


def test_case_c_classifier_only_depends_on_validated_threshold():
    fused, decision, _ = run("PORT_SCAN", 0.95, 0.40)
    assert fused.evidence_status[0] == CLASSIFIER_ONLY and decision == REVIEW
    _, decision_high, _ = run("PORT_SCAN", 0.995, 0.40)
    assert decision_high == BLOCK


def test_case_d_agreed_benign_allows():
    fused, decision, _ = run("BENIGN", 0.99, 0.30)
    assert fused.evidence_status[0] == AGREED_BENIGN and fused.agreement[0] == "AGREE"
    assert decision == ALLOW


def test_campaign_only_reviews():
    fused, decision, _ = run("BENIGN", 0.99, 0.30, campaign=True)
    assert fused.evidence_status[0] == CAMPAIGN_ONLY and decision == REVIEW


def test_conflict_prevents_block():
    _, decision, reason = run("DOS", 0.999, 0.99, conflict=True)
    assert decision == REVIEW and reason == "UNRESOLVED_CONFLICT"


def test_simulation_reports_differences_without_changing_inputs():
    rows = np.array([proba("PORT_SCAN", 0.95), proba("BENIGN", 0.95)])
    fused = fuse_batch(rows, CLASSES, np.array([0.1, 0.1]), 0.95, FusionConfig())
    lower = PolicyThresholds(0.9, 0.9, 0.90)
    out = simulate(fused, THRESHOLDS, lower, flow_ids=["F1", "F2"])
    assert out["changed"] == 1 and out["transitions"] == {"REVIEW->BLOCK": 1}
    assert out["examples"][0]["flow_id"] == "F1"
    assert decide_batch(fused, THRESHOLDS)[0][0] == REVIEW
