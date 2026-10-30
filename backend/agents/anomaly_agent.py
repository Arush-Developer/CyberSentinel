"""Agent 2: independent anomaly detection.

Trained on BENIGN flows only, with its own preprocessing. It imports nothing from Agent 1 and
sees neither classifier outputs nor attack labels when scoring.

anomaly_score is an empirical percentile: the share of held-out benign calibration flows that
looked less unusual than this flow. 0.97 means "more unusual than 97% of benign calibration
flows". It is not the probability that a flow is an attack.
"""
from __future__ import annotations

from dataclasses import dataclass

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# RobustBaseline must stay importable from this module: the saved model was pickled against this path.
from backend.intelligence.feature_explainer import RobustBaseline, explain_deviations
from backend.preprocessing.data_processor import PORT_FEATURE, FeaturePipeline
from backend.schemas.contracts import AnomalyAssessment

TOP_K_FOR_SCORE = 5


@dataclass
class AnomalyAgent:
    forest: IsolationForest
    pipeline: FeaturePipeline
    baseline: RobustBaseline
    forest_reference: np.ndarray | None = None
    robust_reference: np.ndarray | None = None
    combined_reference: np.ndarray | None = None
    detector: str = "combined"
    threshold: float = 0.95
    model_version: str = ""

    @classmethod
    def train(cls, benign_features: pd.DataFrame, seed: int = 42, n_estimators: int = 200,
              max_samples: int = 4096, model_version: str = "") -> "AnomalyAgent":
        pipeline = FeaturePipeline(exclude=(PORT_FEATURE,)).fit(benign_features)
        X = pipeline.transform(benign_features)
        forest = IsolationForest(n_estimators=n_estimators, max_samples=min(max_samples, len(X)),
                                 n_jobs=-1, random_state=seed).fit(X)
        baseline = RobustBaseline.fit(X, pipeline.columns_)
        return cls(forest, pipeline, baseline, model_version=model_version)

    def _raw(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        forest_raw = -self.forest.score_samples(X)
        k = min(TOP_K_FOR_SCORE, X.shape[1])
        top = np.partition(np.abs(self.baseline.z(X)), -k, axis=1)[:, -k:]
        return forest_raw, top.mean(axis=1)

    def calibrate(self, benign_features: pd.DataFrame, target_fpr: float, detector: str | None = None) -> None:
        """Build percentile references and the threshold from benign flows unseen in training."""
        forest_raw, robust_raw = self._raw(self.pipeline.transform(benign_features))
        self.forest_reference = np.sort(forest_raw)
        self.robust_reference = np.sort(robust_raw)
        self.combined_reference = np.sort(self._combine(forest_raw, robust_raw))
        self.threshold = 1.0 - target_fpr
        if detector:
            self.detector = detector

    def _percentile(self, raw: np.ndarray, reference: np.ndarray) -> np.ndarray:
        return np.searchsorted(reference, raw, side="left") / len(reference)

    def _combine(self, forest_raw: np.ndarray, robust_raw: np.ndarray) -> np.ndarray:
        return (self._percentile(forest_raw, self.forest_reference)
                + self._percentile(robust_raw, self.robust_reference)) / 2

    def score_detectors(self, features: pd.DataFrame) -> dict[str, np.ndarray]:
        forest_raw, robust_raw = self._raw(self.pipeline.transform(features))
        return {
            "isolation_forest": self._percentile(forest_raw, self.forest_reference),
            "robust_deviation": self._percentile(robust_raw, self.robust_reference),
            "combined": self._percentile(self._combine(forest_raw, robust_raw), self.combined_reference),
        }

    def score(self, features: pd.DataFrame) -> np.ndarray:
        return self.score_detectors(features)[self.detector]

    def supporting_features(self, features: pd.DataFrame, top: int = 5) -> list[list[dict]]:
        return explain_deviations(self.baseline, self.pipeline.transform(features), top)

    def to_output(self, flow_id: str, score: float, supporting: list[dict]) -> dict:
        return AnomalyAssessment(
            flow_id=flow_id,
            anomaly_score=float(score),
            score_meaning="percentile among held-out benign calibration flows; not a probability",
            is_anomaly=bool(score >= self.threshold),
            threshold=self.threshold,
            supporting_features=supporting,
            baseline_reference="benign_training_distribution",
            model_version=self.model_version,
        ).model_dump()

    def save(self, path) -> None:
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path) -> "AnomalyAgent":
        return joblib.load(path)
