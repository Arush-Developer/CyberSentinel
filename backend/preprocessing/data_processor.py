"""Loading, cleaning and leakage control for the Cyber flow partitions.

Two representations are kept apart:
  * ML features: the numeric flow statistics only (see FeaturePipeline).
  * Network metadata: record_id plus any endpoint columns present in the file.
Labels are returned separately and never reach a feature matrix.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit

from backend.config import load_config, resolve

PORT_FEATURE = "Destination Port"


@dataclass
class Partition:
    features: pd.DataFrame
    metadata: pd.DataFrame
    labels: pd.Series | None


def map_labels(raw: pd.Series) -> pd.Series:
    """Apply the explicit label mapping. Unknown labels raise rather than being coerced."""
    mapping = load_config()["labels"]["mapping"]
    unknown = sorted(set(raw.dropna().astype(str)) - set(mapping))
    if unknown or raw.isna().any():
        raise ValueError(f"unmapped labels (confirm with Arush before training): {unknown or 'null values'}")
    return raw.astype(str).map(mapping)


def split_representations(df: pd.DataFrame) -> Partition:
    cfg = load_config()["data"]
    id_col, label_col = cfg["id_column"], cfg["label_column"]
    meta_cols = [c for c in cfg["metadata_columns"] if c in df.columns]
    drop = {id_col, label_col, *meta_cols}
    features = df[[c for c in df.columns if c not in drop]]
    metadata = df[[id_col, *meta_cols]].rename(columns={id_col: "flow_id"}).reset_index(drop=True)
    # Destination Port is a flow feature in this pack, and also needed for campaign analysis.
    if "destination_port" not in metadata and PORT_FEATURE in features:
        metadata["destination_port"] = features[PORT_FEATURE].to_numpy()
    labels = map_labels(df[label_col]).reset_index(drop=True) if label_col in df else None
    return Partition(features.reset_index(drop=True), metadata, labels)


def load_partition(which: str) -> Partition:
    key = {"training": "training_parquet", "eval": "eval_parquet"}[which]
    return split_representations(pd.read_parquet(resolve(load_config()["data"][key])))


@dataclass
class FeaturePipeline:
    """Cleans features with statistics learned from the data passed to fit() only."""

    exclude: tuple[str, ...] = ()
    columns_: list[str] = field(default_factory=list)
    medians_: np.ndarray | None = None
    dropped_: dict[str, str] = field(default_factory=dict)

    def fit(self, X: pd.DataFrame) -> "FeaturePipeline":
        self.dropped_ = {c: "excluded" for c in self.exclude if c in X}
        kept: list[str] = []
        seen: dict[int, str] = {}
        for col in X.columns:
            if col in self.dropped_:
                continue
            values = self._clean_column(X[col])
            if np.nanmin(values) == np.nanmax(values):
                self.dropped_[col] = "constant in training"
                continue
            digest = int(pd.util.hash_pandas_object(pd.Series(values), index=False).sum())
            if digest in seen:
                self.dropped_[col] = f"duplicate of {seen[digest]}"
                continue
            seen[digest] = col
            kept.append(col)
        self.columns_ = kept
        self.medians_ = np.nanmedian(self._matrix(X), axis=0)
        return self

    @staticmethod
    def _clean_column(col: pd.Series) -> np.ndarray:
        values = col.to_numpy(dtype=np.float64)
        return np.where(np.isfinite(values), values, np.nan)

    def _matrix(self, X: pd.DataFrame) -> np.ndarray:
        missing = [c for c in self.columns_ if c not in X]
        if missing:
            raise ValueError(f"input is missing required feature columns: {missing}")
        values = X[self.columns_].to_numpy(dtype=np.float64)
        values[~np.isfinite(values)] = np.nan
        return values

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        values = self._matrix(X)
        holes = np.isnan(values)
        if holes.any():
            values[holes] = np.take(self.medians_, np.nonzero(holes)[1])
        return values.astype(np.float32)


@dataclass
class InternalSplits:
    fit: np.ndarray
    selection: np.ndarray
    calibration: np.ndarray


def row_groups(features: pd.DataFrame) -> np.ndarray:
    return pd.util.hash_pandas_object(features, index=False).to_numpy()


def internal_splits(features: pd.DataFrame, labels: pd.Series, seed: int = 42,
                    fractions: tuple[float, float] = (0.15, 0.15)) -> InternalSplits:
    """Stratified 70/15/15 split of training data, grouped so identical rows stay together.

    Training holds 24,132 exact-duplicate feature rows; a plain split would let them straddle
    the boundary and inflate holdout scores.
    """
    groups = pd.DataFrame({"g": row_groups(features), "y": labels.to_numpy()})
    uniq = groups.drop_duplicates("g").reset_index(drop=True)
    holdout = fractions[0] + fractions[1]
    outer = StratifiedShuffleSplit(n_splits=1, test_size=holdout, random_state=seed)
    fit_idx, hold_idx = next(outer.split(uniq, uniq["y"]))
    hold = uniq.iloc[hold_idx]
    inner = StratifiedShuffleSplit(n_splits=1, test_size=fractions[1] / holdout, random_state=seed)
    sel_idx, cal_idx = next(inner.split(hold, hold["y"]))
    assign = {g: 0 for g in uniq.iloc[fit_idx]["g"]}
    assign.update({g: 1 for g in hold.iloc[sel_idx]["g"]})
    assign.update({g: 2 for g in hold.iloc[cal_idx]["g"]})
    which = groups["g"].map(assign).to_numpy()
    return InternalSplits(np.flatnonzero(which == 0), np.flatnonzero(which == 1), np.flatnonzero(which == 2))


def record_order_split(metadata: pd.DataFrame, labels: pd.Series, test_fraction: float = 0.3):
    """Per-class split on record_id order: earliest records fit, latest test.

    A proxy for temporal validation. record_id numbering clusters by class (112,710 label runs in
    456,737 rows), but the pack does not say it is chronological, so it is never a model input.
    """
    numeric = metadata["flow_id"].str.extract(r"(\d+)")[0].astype(np.int64).to_numpy()
    test = np.zeros(len(labels), dtype=bool)
    y = labels.to_numpy()
    for cls in np.unique(y):
        idx = np.flatnonzero(y == cls)
        cut = np.quantile(numeric[idx], 1 - test_fraction)
        test[idx[numeric[idx] > cut]] = True
    return np.flatnonzero(~test), np.flatnonzero(test)
