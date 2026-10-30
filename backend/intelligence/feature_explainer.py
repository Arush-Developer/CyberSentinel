"""Feature-level deviation analysis against the benign baseline, using median and MAD."""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

Z_CAP = 50.0
MIN_EVIDENCE_Z = 3.5  # Conventional modified z-score outlier cut-off (Iglewicz & Hoaglin).


@dataclass
class RobustBaseline:
    """Median/MAD description of benign traffic, per feature."""

    columns: list[str]
    median: np.ndarray
    mad: np.ndarray
    scale: np.ndarray
    p01: np.ndarray
    p99: np.ndarray

    @classmethod
    def fit(cls, X: np.ndarray, columns: list[str]) -> "RobustBaseline":
        median = np.median(X, axis=0)
        mad = np.median(np.abs(X - median), axis=0)
        # Many flow features have MAD 0 (mostly-zero flags); fall back to mean absolute deviation.
        mean_ad = np.mean(np.abs(X - median), axis=0)
        scale = np.where(mad > 0, mad / 0.6745, mean_ad * 1.2533)
        scale = np.where(scale > 0, scale, 1.0)
        return cls(columns, median, mad, scale,
                   np.percentile(X, 1, axis=0), np.percentile(X, 99, axis=0))

    def z(self, X: np.ndarray) -> np.ndarray:
        return np.clip((X - self.median) / self.scale, -Z_CAP, Z_CAP)


def explain_deviations(baseline: RobustBaseline, X: np.ndarray, top: int = 5) -> list[list[dict]]:
    """Largest benign-baseline deviations per flow, with the measured values."""
    z = baseline.z(X)
    order = np.argsort(-np.abs(z), axis=1)[:, :top]
    evidence = []
    for row, idx in enumerate(order):
        items = []
        for j in idx:
            if abs(z[row, j]) < MIN_EVIDENCE_Z:
                continue
            items.append({
                "feature": baseline.columns[j],
                "deviation": "high" if z[row, j] > 0 else "low",
                "measured_value": float(X[row, j]),
                "benign_median": float(baseline.median[j]),
                "benign_mad": float(baseline.mad[j]),
                "robust_z": round(float(z[row, j]), 2),
            })
        evidence.append(items)
    return evidence
