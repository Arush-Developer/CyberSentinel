"""Saved models and measured metrics, recomputed here from the official records with no shared code."""
import json

import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

from backend.agents.anomaly_agent import AnomalyAgent
from backend.agents.threat_agent import ThreatAgent
from backend.config import load_config, resolve

pytestmark = pytest.mark.real_data
CFG = load_config()


@pytest.fixture(scope="module")
def eval_frame():
    return pd.read_parquet(resolve(CFG["data"]["eval_parquet"]))


def test_training_and_validation_partitions_share_no_records(eval_frame):
    train_ids = pd.read_parquet(resolve(CFG["data"]["training_parquet"]), columns=["record_id"])["record_id"]
    assert not set(train_ids) & set(eval_frame["record_id"])


def test_saved_classifier_reproduces_the_reported_metrics(eval_frame):
    agent = ThreatAgent.load(resolve(CFG["models"]["threat"]))
    proba = agent.predict_proba(eval_frame.drop(columns=["record_id", "label"]))
    predicted = np.array(agent.classes)[proba.argmax(axis=1)]
    summary = json.loads((resolve(CFG["data"]["reports_dir"]) / "level1_summary.json").read_text())
    assert accuracy_score(eval_frame["label"], predicted) == pytest.approx(summary["accuracy"], abs=1e-12)
    assert f1_score(eval_frame["label"], predicted, average="macro") == pytest.approx(summary["macro_f1"], abs=1e-12)
    report = json.loads((resolve(CFG["data"]["reports_dir"]) / "evaluation_report.json").read_text())
    matrix = confusion_matrix(eval_frame["label"], predicted, labels=agent.classes).tolist()
    assert matrix == report["agent1"]["confusion_matrix"]["rows_true_columns_predicted"]


def test_model_save_and_load_round_trip_gives_identical_predictions(eval_frame, tmp_path):
    sample = eval_frame.drop(columns=["record_id", "label"]).iloc[:500]
    agent = ThreatAgent.load(resolve(CFG["models"]["threat"]))
    agent.save(tmp_path / "threat.joblib")
    assert np.array_equal(agent.predict_proba(sample), ThreatAgent.load(tmp_path / "threat.joblib").predict_proba(sample))
    anomaly = AnomalyAgent.load(resolve(CFG["models"]["anomaly"]))
    anomaly.save(tmp_path / "anomaly.joblib")
    assert np.array_equal(anomaly.score(sample), AnomalyAgent.load(tmp_path / "anomaly.joblib").score(sample))


def test_anomaly_threshold_is_from_training_calibration_not_validation():
    report = json.loads((resolve(CFG["data"]["reports_dir"]) / "training_report.json").read_text())
    assert report["eval_partition_used"] is False


def test_supporting_evidence_uses_values_from_the_actual_flow(eval_frame):
    anomaly = AnomalyAgent.load(resolve(CFG["models"]["anomaly"]))
    features = eval_frame.drop(columns=["record_id", "label"])
    top = np.argmax(anomaly.score(features.iloc[:5000]))
    row = features.iloc[[top]]
    evidence = anomaly.supporting_features(row)[0]
    assert evidence
    for item in evidence:
        assert item["measured_value"] == pytest.approx(float(row[item["feature"]].iloc[0]), rel=1e-5)


def test_label_columns_are_exactly_the_five_benchmark_classes(eval_frame):
    assert set(eval_frame["label"]) == {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}
