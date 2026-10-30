"""Classification, anomaly and calibration metrics. All values are measured, none are estimated."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

BENIGN = "BENIGN"


def classification_report(y_true, y_pred, classes: list[str]) -> dict:
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=classes, zero_division=0)
    per_class = {}
    for i, cls in enumerate(classes):
        negatives = y_true != cls
        per_class[cls] = {
            "precision": float(p[i]),
            "recall": float(r[i]),
            "f1": float(f[i]),
            "support": int(s[i]),
            "false_negative_rate": float(1 - r[i]) if s[i] else None,
            "false_positive_rate": float((y_pred[negatives] == cls).mean()) if negatives.any() else None,
        }
    attack_true, attack_pred = y_true != BENIGN, y_pred != BENIGN
    return {
        "rows": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "binary_attack_false_positive_rate": float(attack_pred[~attack_true].mean()) if (~attack_true).any() else None,
        "binary_attack_false_negative_rate": float((~attack_pred[attack_true]).mean()) if attack_true.any() else None,
        "per_class": per_class,
        "confusion_matrix": {
            "labels": classes,
            "rows_true_columns_predicted": confusion_matrix(y_true, y_pred, labels=classes).tolist(),
        },
    }


def anomaly_report(is_attack, scores, flags=None) -> dict:
    is_attack = np.asarray(is_attack, dtype=bool)
    scores = np.asarray(scores, dtype=np.float64)
    report = {
        "rows": int(len(scores)),
        "roc_auc": float(roc_auc_score(is_attack, scores)),
        "pr_auc": float(average_precision_score(is_attack, scores)),
        "attack_prevalence": float(is_attack.mean()),
    }
    if flags is not None:
        flags = np.asarray(flags, dtype=bool)
        report["recall"] = float(flags[is_attack].mean())
        report["false_positive_rate"] = float(flags[~is_attack].mean())
        report["precision"] = float(is_attack[flags].mean()) if flags.any() else None
    return report


def threshold_curve(is_attack, scores, thresholds) -> list[dict]:
    is_attack = np.asarray(is_attack, dtype=bool)
    out = []
    for t in thresholds:
        flags = scores >= t
        out.append({
            "threshold": float(t),
            "recall": float(flags[is_attack].mean()),
            "false_positive_rate": float(flags[~is_attack].mean()),
        })
    return out


def expected_calibration_error(confidence, correct, bins: int = 15) -> float:
    confidence, correct = np.asarray(confidence), np.asarray(correct, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(confidence, edges[1:-1]), 0, bins - 1)
    total = 0.0
    for b in range(bins):
        mask = idx == b
        if mask.any():
            total += mask.mean() * abs(correct[mask].mean() - confidence[mask].mean())
    return float(total)


def multiclass_brier(proba, y_idx) -> float:
    one_hot = np.eye(proba.shape[1])[y_idx]
    return float(((proba - one_hot) ** 2).sum(axis=1).mean())
