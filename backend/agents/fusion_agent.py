"""Agent 3: evidence fusion.

Evidence types are kept separate rather than averaged, because a class probability, a benign
percentile and a cross-flow hypothesis do not share a scale. final_class comes from Agent 1
unless an override rule was validated on internal holdout data (see scripts/calibrate_fusion.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from backend.schemas.contracts import FusionAssessment

BENIGN = "BENIGN"

MULTI_SIGNAL_CONFIRMED = "MULTI_SIGNAL_CONFIRMED"
CLASSIFIER_ONLY = "CLASSIFIER_ONLY"
ANOMALY_ONLY = "ANOMALY_ONLY"
CAMPAIGN_ONLY = "CAMPAIGN_ONLY"
AGREED_BENIGN = "AGREED_BENIGN"

AGREE = "AGREE"
DISAGREE = "DISAGREE"


@dataclass
class FusionConfig:
    low_confidence: float = 0.60
    # Validated override: a BENIGN call this unsure, on a flagged anomaly, takes the top attack class.
    benign_override_below: float | None = None


@dataclass
class FusionResult:
    final_class: np.ndarray
    final_class_source: np.ndarray
    threat_class: np.ndarray
    threat_confidence: np.ndarray
    anomaly_score: np.ndarray
    is_anomaly: np.ndarray
    agreement: np.ndarray
    evidence_status: np.ndarray
    low_confidence: np.ndarray
    campaign_support: np.ndarray = field(default_factory=lambda: np.array([], dtype=bool))
    campaign_conflict: np.ndarray = field(default_factory=lambda: np.array([], dtype=bool))
    investigation_conflict: np.ndarray = field(default_factory=lambda: np.array([], dtype=bool))


def fuse_batch(proba: np.ndarray, classes: list[str], anomaly_score: np.ndarray, anomaly_threshold: float,
               config: FusionConfig, campaign_support: np.ndarray | None = None,
               campaign_conflict: np.ndarray | None = None,
               investigation_conflict: np.ndarray | None = None) -> FusionResult:
    n = len(proba)
    names = np.array(classes)
    benign_idx = classes.index(BENIGN)
    top = proba.argmax(axis=1)
    threat_class = names[top]
    confidence = proba[np.arange(n), top]
    is_anomaly = anomaly_score >= anomaly_threshold
    campaign_support = np.zeros(n, bool) if campaign_support is None else campaign_support
    campaign_conflict = np.zeros(n, bool) if campaign_conflict is None else campaign_conflict
    investigation_conflict = np.zeros(n, bool) if investigation_conflict is None else investigation_conflict

    final_class = threat_class.copy()
    source = np.full(n, "classifier", dtype=object)
    if config.benign_override_below is not None:
        masked = proba.copy()
        masked[:, benign_idx] = -1
        hit = (top == benign_idx) & is_anomaly & (confidence < config.benign_override_below)
        final_class[hit] = names[masked[hit].argmax(axis=1)]
        source[hit] = "validated_benign_override"

    predicted_attack = final_class != BENIGN
    status = np.full(n, AGREED_BENIGN, dtype=object)
    status[~predicted_attack & is_anomaly] = ANOMALY_ONLY
    status[~predicted_attack & campaign_support] = CAMPAIGN_ONLY
    status[predicted_attack] = CLASSIFIER_ONLY
    status[predicted_attack & (is_anomaly | campaign_support)] = MULTI_SIGNAL_CONFIRMED

    # Agreement is about Agent 1 versus Agent 2 only: attack call against anomaly flag.
    agreement = np.where((threat_class != BENIGN) == is_anomaly, AGREE, DISAGREE)
    return FusionResult(final_class, source, threat_class, confidence, anomaly_score, is_anomaly,
                        agreement, status, confidence < config.low_confidence,
                        campaign_support, campaign_conflict, investigation_conflict)


def rationale(result: FusionResult, i: int, supporting: list[dict] | None = None,
              campaign_type: str | None = None, investigation_note: str | None = None) -> str:
    """Plain-language explanation built only from measured values for flow i."""
    parts = [
        f"Agent 1 predicted {result.threat_class[i]} at confidence {result.threat_confidence[i]:.3f}"
        + (" (low confidence)." if result.low_confidence[i] else "."),
        f"Agent 2 scored {result.anomaly_score[i]:.3f} "
        f"({'flagged anomalous' if result.is_anomaly[i] else 'not flagged'}; "
        "percentile among benign calibration flows).",
    ]
    if supporting:
        top = supporting[0]
        parts.append(f"Largest deviation: {top['feature']} = {top['measured_value']:g} "
                     f"against benign median {top['benign_median']:g} (robust z {top['robust_z']}).")
    if result.agreement[i] == DISAGREE:
        parts.append("The two agents disagree: "
                     + ("the classifier sees an attack but the flow looks statistically normal."
                        if result.threat_class[i] != BENIGN
                        else "the classifier sees benign traffic but the flow looks statistically unusual."))
    else:
        parts.append("The two agents agree.")
    if result.final_class_source[i] != "classifier":
        parts.append(f"Final class {result.final_class[i]} comes from the validated benign-override rule.")
    if campaign_type:
        parts.append(f"Flow belongs to a {campaign_type} cross-flow hypothesis"
                     + (" that conflicts with the classifier." if result.campaign_conflict[i] else "."))
    if investigation_note:
        parts.append(investigation_note)
    return " ".join(parts)


def fusion_output(result: FusionResult, i: int, flow_id: str, supporting: list[dict] | None = None,
                  campaign_type: str | None = None, investigation: dict | None = None) -> dict:
    note = f"Investigation verdict: {investigation['verdict']}." if investigation else None
    return FusionAssessment(
        flow_id=flow_id,
        final_class=str(result.final_class[i]),
        final_class_source=str(result.final_class_source[i]),
        evidence_status=str(result.evidence_status[i]),
        agreement=str(result.agreement[i]),
        low_confidence=bool(result.low_confidence[i]),
        investigation_refs=[investigation["investigation_id"]] if investigation else [],
        rationale=rationale(result, i, supporting, campaign_type, note),
    ).model_dump()
