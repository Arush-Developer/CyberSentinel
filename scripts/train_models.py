"""Train and select Agent 1 and Agent 2 using training data only. The eval partition is never read.

Outputs: models/threat_model/threat_agent.joblib, models/anomaly_model/anomaly_agent.joblib,
data/reports/training_report.json, data/processed/internal_splits.npz
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402

from backend.agents.anomaly_agent import AnomalyAgent  # noqa: E402
from backend.agents.threat_agent import ThreatAgent, fit_model, make_candidates, temperature_scale  # noqa: E402
from backend.config import load_config, resolve  # noqa: E402
from backend.evaluation.metrics import (  # noqa: E402
    anomaly_report, classification_report, expected_calibration_error, multiclass_brier, threshold_curve)
from backend.preprocessing.data_processor import (  # noqa: E402
    PORT_FEATURE, FeaturePipeline, internal_splits, load_partition, record_order_split)

SEED = 42
PORT_GAIN_REQUIRED = 0.001  # Keep Destination Port only if it earns at least this much macro-F1.


def predict_classes(model, X, classes):
    proba = model.predict_proba(X)
    order = [list(map(str, np.ravel(model.classes_))).index(c) for c in classes]
    return proba[:, order]


def fit_and_score(name, features, y, fit_idx, test_idx, classes, exclude=()):
    pipeline = FeaturePipeline(exclude=exclude).fit(features.iloc[fit_idx])
    X_fit, X_test = pipeline.transform(features.iloc[fit_idx]), pipeline.transform(features.iloc[test_idx])
    model = make_candidates(SEED)[name]
    start = time.perf_counter()
    fit_model(model, X_fit, y[fit_idx])
    fit_seconds = time.perf_counter() - start
    start = time.perf_counter()
    proba = predict_classes(model, X_test, classes)
    predict_seconds = time.perf_counter() - start
    pred = np.array(classes)[proba.argmax(axis=1)]
    return classification_report(y[test_idx], pred, classes) | {
        "fit_seconds": round(fit_seconds, 1),
        "inference_ms_per_1k_flows": round(1000 * predict_seconds / len(test_idx) * 1000, 2),
    }


def summary(report):
    return {k: report[k] for k in ("macro_f1", "accuracy", "balanced_accuracy", "fit_seconds",
                                   "inference_ms_per_1k_flows")} | {
        "recall": {c: round(v["recall"], 4) for c, v in report["per_class"].items()}}


def calibration_study(proba, y_idx, seed=SEED):
    """Fit temperature on half the calibration split, measure on the other half."""
    rng = np.random.default_rng(seed)
    perm = rng.permutation(len(y_idx))
    half = len(perm) // 2
    fit_i, test_i = perm[:half], perm[half:]
    grid = [0.25, 0.33, 0.5, 0.67, 0.8, 1.0, 1.25, 1.5, 2.0, 3.0]

    def nll(p, idx):
        return float(-np.log(np.clip(p[np.arange(len(idx)), idx], 1e-12, 1)).mean())

    best_t = min(grid, key=lambda t: nll(temperature_scale(proba[fit_i], t), y_idx[fit_i]))

    def measure(t):
        p = temperature_scale(proba[test_i], t)
        return {
            "temperature": t,
            "ece_15_bins": expected_calibration_error(p.max(axis=1), p.argmax(axis=1) == y_idx[test_i]),
            "brier": multiclass_brier(p, y_idx[test_i]),
            "nll": nll(p, y_idx[test_i]),
        }

    raw, tuned = measure(1.0), measure(best_t)
    chosen = best_t if tuned["nll"] < raw["nll"] else 1.0
    return {"raw": raw, "temperature_scaled": tuned, "chosen_temperature": chosen, "rows_measured": len(test_i)}


def main() -> None:
    cfg = load_config()
    classes = cfg["labels"]["classes"]
    threat_path, anomaly_path = resolve(cfg["models"]["threat"]), resolve(cfg["models"]["anomaly"])
    threat_path.parent.mkdir(parents=True, exist_ok=True)
    anomaly_path.parent.mkdir(parents=True, exist_ok=True)
    resolve(cfg["data"]["processed_dir"]).mkdir(parents=True, exist_ok=True)

    part = load_partition("training")
    features, y = part.features, part.labels.to_numpy()
    splits = internal_splits(features, part.labels, seed=SEED)
    np.savez(resolve(cfg["data"]["processed_dir"]) / "internal_splits.npz",
             fit=splits.fit, selection=splits.selection, calibration=splits.calibration)
    report = {"seed": SEED, "eval_partition_used": False, "split_sizes": {
        "fit": len(splits.fit), "selection": len(splits.selection), "calibration": len(splits.calibration)}}
    print(report["split_sizes"], flush=True)

    # 1. Compare candidates on the selection split.
    comparison = {}
    for name in make_candidates(SEED):
        comparison[name] = fit_and_score(name, features, y, splits.fit, splits.selection, classes)
        print(name, summary(comparison[name]), flush=True)
    best = max(comparison, key=lambda n: comparison[n]["macro_f1"])
    report["model_comparison_selection_split"] = comparison
    report["selected_model"] = best

    # 2. Does Destination Port earn its place? It is near-deterministic for some classes here
    #    (DoS/DDoS always 80, brute force always 21/22), which may not generalise.
    no_port = fit_and_score(best, features, y, splits.fit, splits.selection, classes, exclude=(PORT_FEATURE,))
    gain = comparison[best]["macro_f1"] - no_port["macro_f1"]
    use_port = gain >= PORT_GAIN_REQUIRED
    exclude = () if use_port else (PORT_FEATURE,)
    report["destination_port_study"] = {
        "with_port_macro_f1": comparison[best]["macro_f1"], "without_port": no_port,
        "macro_f1_gain": gain, "required_gain": PORT_GAIN_REQUIRED, "use_port": use_port,
    }
    print("port study", {"gain": gain, "use_port": use_port, "no_port": summary(no_port)}, flush=True)

    # 3. Harder check: fit on early record_ids, test on late ones within each class.
    early, late = record_order_split(part.metadata, part.labels)
    report["record_order_validation"] = fit_and_score(best, features, y, early, late, classes, exclude=exclude)
    print("record-order", summary(report["record_order_validation"]), flush=True)

    # 4. Refit on fit+selection; calibration split stays unseen.
    trainval = np.concatenate([splits.fit, splits.selection])
    pipeline = FeaturePipeline(exclude=exclude).fit(features.iloc[trainval])
    model = make_candidates(SEED)[best]
    fit_model(model, pipeline.transform(features.iloc[trainval]), y[trainval])
    version = f"{best}-fit_selection-seed{SEED}-{'port' if use_port else 'noport'}"
    agent = ThreatAgent(model, pipeline, classes, version)

    cal_features = features.iloc[splits.calibration]
    cal_proba = agent.predict_proba(cal_features)
    y_idx = np.array([classes.index(c) for c in y[splits.calibration]])
    report["threat_calibration_split"] = classification_report(
        y[splits.calibration], np.array(classes)[cal_proba.argmax(axis=1)], classes)
    study = calibration_study(cal_proba, y_idx)
    agent.temperature = study["chosen_temperature"]
    agent.calibration_status = (
        f"evaluated on internal holdout: ECE {study['raw']['ece_15_bins']:.4f} raw, "
        f"temperature {agent.temperature} chosen")
    report["calibration_study"] = study
    report["preprocessing"] = {"threat_dropped": pipeline.dropped_, "threat_features": len(pipeline.columns_)}
    report["feature_importance"] = agent.feature_importance(25)
    agent.save(threat_path)
    print("calibration", study, flush=True)

    # 5. Agent 2: benign-only fit, percentile references from unseen benign calibration flows.
    benign_fit = splits.fit[y[splits.fit] == "BENIGN"]
    benign_cal = splits.calibration[y[splits.calibration] == "BENIGN"]
    anomaly = AnomalyAgent.train(features.iloc[benign_fit], seed=SEED,
                                 model_version=f"iforest-benign-seed{SEED}")
    target_fpr = 0.05
    anomaly.calibrate(features.iloc[benign_cal], target_fpr)
    sel = features.iloc[splits.selection]
    is_attack = y[splits.selection] != "BENIGN"
    scores = anomaly.score_detectors(sel)
    detectors = {name: anomaly_report(is_attack, s, s >= anomaly.threshold) for name, s in scores.items()}
    best_detector = max(detectors, key=lambda d: detectors[d]["pr_auc"])
    anomaly.detector = best_detector
    chosen_scores = scores[best_detector]
    report["anomaly"] = {
        "benign_fit_rows": len(benign_fit), "benign_calibration_rows": len(benign_cal),
        "target_false_positive_rate": target_fpr, "threshold": anomaly.threshold,
        "detector_comparison_selection_split": detectors, "selected_detector": best_detector,
        "per_class_recall_at_threshold": {
            c: float((chosen_scores[y[splits.selection] == c] >= anomaly.threshold).mean()) for c in classes},
        "threshold_curve": threshold_curve(is_attack, chosen_scores, [0.8, 0.9, 0.95, 0.98, 0.99]),
        "features_used": len(anomaly.pipeline.columns_),
    }
    anomaly.save(anomaly_path)
    print("anomaly", detectors, report["anomaly"]["per_class_recall_at_threshold"], flush=True)

    out = resolve(cfg["data"]["reports_dir"]) / "training_report.json"
    out.write_text(json.dumps(report, indent=2))
    print("wrote", out, {p.name: os.path.getsize(p) for p in (threat_path, anomaly_path)})


if __name__ == "__main__":
    main()
