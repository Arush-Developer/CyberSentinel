"""Agent 1: supervised five-class threat detection."""
from __future__ import annotations

from dataclasses import dataclass

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.utils.class_weight import compute_sample_weight

from backend.preprocessing.data_processor import FeaturePipeline
from backend.schemas.contracts import ThreatAssessment


def make_candidates(seed: int = 42) -> dict:
    """Balanced class weights handle the 43:1 imbalance; no synthetic samples are added."""
    candidates = {
        "extra_trees": ExtraTreesClassifier(
            n_estimators=120, min_samples_leaf=2, max_features="sqrt",
            class_weight="balanced", n_jobs=-1, random_state=seed),
        "random_forest": RandomForestClassifier(
            n_estimators=120, min_samples_leaf=2, max_features="sqrt",
            class_weight="balanced", n_jobs=-1, random_state=seed),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.1, class_weight="balanced", random_state=seed),
    }
    try:
        from catboost import CatBoostClassifier
        candidates["catboost"] = CatBoostClassifier(
            iterations=400, depth=8, learning_rate=0.15, auto_class_weights="Balanced",
            random_seed=seed, verbose=False, thread_count=-1, allow_writing_files=False)
    except ImportError:
        pass
    return candidates


def fit_model(model, X: np.ndarray, y: np.ndarray):
    if hasattr(model, "class_weight") and getattr(model, "class_weight") is None:
        model.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    else:
        model.fit(X, y)
    return model


def temperature_scale(proba: np.ndarray, temperature: float) -> np.ndarray:
    """Soften or sharpen probabilities; the arg-max class never changes."""
    if temperature == 1.0:
        return proba
    logp = np.log(np.clip(proba, 1e-12, 1.0)) / temperature
    logp -= logp.max(axis=1, keepdims=True)
    scaled = np.exp(logp)
    return scaled / scaled.sum(axis=1, keepdims=True)


@dataclass
class ThreatAgent:
    model: object
    pipeline: FeaturePipeline
    classes: list[str]
    model_version: str
    temperature: float = 1.0
    calibration_status: str = "not_evaluated"

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        """Probabilities in self.classes order."""
        proba = self.model.predict_proba(self.pipeline.transform(features))
        order = [list(map(str, np.ravel(self.model.classes_))).index(c) for c in self.classes]
        return temperature_scale(proba[:, order], self.temperature)

    def to_output(self, flow_id: str, proba_row: np.ndarray) -> dict:
        idx = int(np.argmax(proba_row))
        return ThreatAssessment(
            flow_id=flow_id,
            predicted_class=self.classes[idx],
            confidence=float(proba_row[idx]),
            probabilities={c: float(p) for c, p in zip(self.classes, proba_row)},
            model_version=self.model_version,
            calibration_status=self.calibration_status,
        ).model_dump()

    def feature_importance(self, top: int = 20) -> list[dict]:
        importances = getattr(self.model, "feature_importances_", None)
        if importances is None:
            return []
        order = np.argsort(importances)[::-1][:top]
        return [{"feature": self.pipeline.columns_[i], "importance": float(importances[i])} for i in order]

    def save(self, path) -> None:
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path) -> "ThreatAgent":
        return joblib.load(path)
