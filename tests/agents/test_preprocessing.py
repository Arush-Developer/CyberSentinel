"""SYNTHETIC fixtures only: these tests check preprocessing logic, not dataset results."""
import numpy as np
import pandas as pd
import pytest

from backend.preprocessing.data_processor import (
    FeaturePipeline, internal_splits, map_labels, replay_order, row_groups, split_representations)


def frame():
    return pd.DataFrame({
        "record_id": ["C1", "C2", "C3", "C4"],
        "Destination Port": [80.0, 21.0, 53.0, 80.0],
        "A": [1.0, np.inf, 3.0, np.nan],
        "A_copy": [1.0, np.inf, 3.0, np.nan],
        "Const": [7.0, 7.0, 7.0, 7.0],
        "label": ["BENIGN", "DOS", "BENIGN", "DDOS"],
    })


def test_label_mapping_is_explicit_and_rejects_unknown():
    assert map_labels(pd.Series(["BENIGN", "PORT_SCAN"])).tolist() == ["BENIGN", "PORT_SCAN"]
    with pytest.raises(ValueError, match="Heartbleed"):
        map_labels(pd.Series(["BENIGN", "Heartbleed"]))


def test_label_and_identifier_never_reach_features():
    part = split_representations(frame())
    assert "label" not in part.features and "record_id" not in part.features
    assert part.metadata["flow_id"].tolist() == ["C1", "C2", "C3", "C4"]
    assert part.metadata["destination_port"].tolist() == [80.0, 21.0, 53.0, 80.0]


def test_pipeline_cleans_nonfinite_and_drops_useless_columns():
    part = split_representations(frame())
    pipe = FeaturePipeline().fit(part.features)
    assert pipe.dropped_["Const"] == "constant in training"
    assert pipe.dropped_["A_copy"] == "duplicate of A"
    X = pipe.transform(part.features)
    assert np.isfinite(X).all()
    assert X[1, pipe.columns_.index("A")] == 2.0  # Median of the finite values 1 and 3.


def test_pipeline_uses_training_statistics_only():
    pipe = FeaturePipeline().fit(pd.DataFrame({"A": [1.0, 2.0, 3.0], "B": [0.0, 1.0, 0.0]}))
    X = pipe.transform(pd.DataFrame({"A": [np.nan, 1000.0], "B": [1.0, 1.0]}))
    assert X[0, 0] == 2.0


def test_pipeline_reports_missing_columns():
    pipe = FeaturePipeline().fit(pd.DataFrame({"A": [1.0, 2.0], "B": [0.0, 1.0]}))
    with pytest.raises(ValueError, match="B"):
        pipe.transform(pd.DataFrame({"A": [1.0]}))


def test_internal_splits_keep_duplicates_together():
    rng = np.random.default_rng(0)
    base = pd.DataFrame(rng.integers(0, 40, size=(4000, 3)).astype(float), columns=list("abc"))
    labels = pd.Series(np.where(base["a"] > 20, "BENIGN", "DOS"))
    s = internal_splits(base, labels)
    groups = row_groups(base)
    assert not set(groups[s.fit]) & set(groups[s.selection])
    assert not set(groups[s.fit]) & set(groups[s.calibration])
    assert not set(groups[s.selection]) & set(groups[s.calibration])
    assert len(s.fit) + len(s.selection) + len(s.calibration) == len(base)


def test_column_and_label_strings_are_standardised():
    raw = frame().rename(columns={"A": " A ", "Destination Port": " Destination Port"})
    raw["label"] = [" BENIGN", "DOS ", "BENIGN", "DDOS"]
    raw["Source IP"] = "10.0.0.1"
    part = split_representations(raw)
    assert "A" in part.features and "Destination Port" in part.features
    assert part.labels.tolist() == ["BENIGN", "DOS", "BENIGN", "DDOS"]
    assert part.metadata["source_ip"].tolist() == ["10.0.0.1"] * 4 and "Source IP" not in part.features


def test_unlabelled_file_is_accepted_and_port_metadata_is_recovered():
    raw = frame().drop(columns=["label", "Destination Port"]).assign(destination_port=[1.0, 2.0, 3.0, 4.0])
    part = split_representations(raw)
    assert part.labels is None and part.features["Destination Port"].tolist() == [1.0, 2.0, 3.0, 4.0]


@pytest.mark.parametrize("meta, expected", [
    ({"flow_id": ["C3", "C1", "C2"], "seq": [2, 0, 1]}, [1, 2, 0]),
    ({"flow_id": ["C3", "C1", "C2"]}, [1, 2, 0]),
    ({"flow_id": ["a-x", "b-y", "c-z"]}, [0, 1, 2]),
    ({"flow_id": ["C1", "C2"], "timestamp": ["2017-07-07 10:00:02", "2017-07-07 10:00:01"]}, [1, 0]),
])
def test_replay_order_prefers_the_supplied_order(meta, expected):
    assert replay_order(pd.DataFrame(meta)).tolist() == expected

