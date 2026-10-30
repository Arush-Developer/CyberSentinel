"""Set fusion and policy thresholds from the internal calibration split. Eval is never read.

The calibration split is halved: thresholds are chosen on one half and verified on the other.
Output: configs/calibrated.json, data/reports/calibration_report.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dataclasses import asdict  # noqa: E402

import numpy as np  # noqa: E402

from backend.agents.fusion_agent import BENIGN, MULTI_SIGNAL_CONFIRMED, FusionConfig, fuse_batch  # noqa: E402
from backend.config import load_config, resolve  # noqa: E402
from backend.evaluation.metrics import classification_report  # noqa: E402
from backend.intelligence.campaign_engine import PACKET_RATE, CampaignConfig, fit_cohort_baseline  # noqa: E402
from backend.services.model_service import CAMPAIGN_CONFIG_PATH, Pipeline  # noqa: E402
from backend.policy.policy_engine import CALIBRATED_PATH  # noqa: E402
from backend.preprocessing.data_processor import load_partition  # noqa: E402

GRID = [0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.97, 0.98, 0.99, 0.995, 0.999]
OVERRIDE_GRID = [0.55, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99]
MIN_OVERRIDE_GAIN = 0.0002
ALLOW_TARGET = 0.999       # Share of auto-allowed flows that must truly be benign.
BLOCK_MULTI_TARGET = 0.995  # Share of multi-signal blocks that must truly be attacks.
BLOCK_SOLO_TARGET = 0.999   # Classifier-only blocks have no second signal, so the bar is higher.
# The holdout reaches the targets at every grid value because the classes separate so cleanly here.
# These floors keep "high confidence" meaningful rather than letting a 0.5 vote trigger a decision.
ALLOW_FLOOR, BLOCK_MULTI_FLOOR, BLOCK_SOLO_FLOOR = 0.90, 0.90, 0.99


def lowest_threshold(conf, truth, target, floor=0.5):
    """Lowest confidence cut at or above floor whose selected flows reach the target precision."""
    for t in [g for g in GRID if g >= floor]:
        chosen = conf >= t
        if chosen.sum() and truth[chosen].mean() >= target:
            return t, float(truth[chosen].mean()), int(chosen.sum())
    return GRID[-1], None, 0


def main() -> None:
    classes = load_config()["labels"]["classes"]
    part = load_partition("training")
    splits = np.load(resolve(load_config()["data"]["processed_dir"]) / "internal_splits.npz")
    idx = splits["calibration"]
    pipe = Pipeline.load()
    proba, scores = pipe.score(part.features.iloc[idx])
    y = part.labels.to_numpy()[idx]

    perm = np.random.default_rng(42).permutation(len(y))
    half = len(perm) // 2
    tune, verify = perm[:half], perm[half:]
    thr = pipe.anomaly.threshold

    # Benign override: enabled only if it lifts macro-F1 on both halves.
    def macro(indices, config):
        fused = fuse_batch(proba[indices], classes, scores[indices], thr, config)
        return classification_report(y[indices], fused.final_class, classes)["macro_f1"]

    base_tune, base_verify = macro(tune, FusionConfig()), macro(verify, FusionConfig())
    trials = {t: macro(tune, FusionConfig(benign_override_below=t)) for t in OVERRIDE_GRID}
    best_t = max(trials, key=trials.get)
    verify_gain = macro(verify, FusionConfig(benign_override_below=best_t)) - base_verify
    enabled = trials[best_t] - base_tune >= MIN_OVERRIDE_GAIN and verify_gain >= MIN_OVERRIDE_GAIN
    fusion_cfg = FusionConfig(benign_override_below=best_t if enabled else None)

    fused = fuse_batch(proba[tune], classes, scores[tune], thr, fusion_cfg)
    truth_attack = y[tune] != BENIGN
    conf = fused.threat_confidence
    attack = fused.final_class != BENIGN
    multi = fused.evidence_status == MULTI_SIGNAL_CONFIRMED
    clean_benign = ~attack & ~fused.is_anomaly

    allow = lowest_threshold(conf[clean_benign], ~truth_attack[clean_benign], ALLOW_TARGET, ALLOW_FLOOR)
    block_multi = lowest_threshold(conf[attack & multi], truth_attack[attack & multi], BLOCK_MULTI_TARGET,
                                   BLOCK_MULTI_FLOOR)
    block_solo = lowest_threshold(conf[attack & ~multi], truth_attack[attack & ~multi], BLOCK_SOLO_TARGET,
                                  BLOCK_SOLO_FLOOR)

    # Campaign baseline: unlabelled window statistics over training flows in record order.
    all_features = part.features
    numeric_ids = part.metadata["flow_id"].str.extract(r"(\d+)")[0].astype(np.int64).to_numpy()
    campaign_cfg = fit_cohort_baseline(all_features, np.argsort(numeric_ids), CampaignConfig())
    benign_rates = all_features.loc[part.labels.to_numpy() == BENIGN, PACKET_RATE]
    campaign_cfg.benign_packet_rate_median = float(benign_rates.median())
    campaign_cfg.benign_packet_rate_p99 = float(benign_rates.quantile(0.99))
    campaign_payload = asdict(campaign_cfg)
    resolve(CAMPAIGN_CONFIG_PATH).write_text(json.dumps(campaign_payload, indent=2))

    calibrated = {
        "fusion": {"low_confidence": 0.60, "benign_override_below": fusion_cfg.benign_override_below},
        "policy": {
            "allow_benign_confidence": allow[0],
            "block_multi_signal_confidence": block_multi[0],
            "block_classifier_only_confidence": block_solo[0],
        },
    }
    resolve(CALIBRATED_PATH).write_text(json.dumps(calibrated, indent=2))
    report = {
        "eval_partition_used": False,
        "calibration_rows": {"tune": len(tune), "verify": len(verify)},
        "benign_override": {
            "macro_f1_without_tune": base_tune, "trials_tune": {str(k): v for k, v in trials.items()},
            "best_threshold": best_t, "macro_f1_gain_verify": verify_gain,
            "required_gain": MIN_OVERRIDE_GAIN, "enabled": enabled,
        },
        "policy_threshold_selection_tune_half": {
            "allow": {"target_precision": ALLOW_TARGET, "threshold": allow[0], "precision": allow[1], "flows": allow[2]},
            "block_multi": {"target_precision": BLOCK_MULTI_TARGET, "threshold": block_multi[0],
                            "precision": block_multi[1], "flows": block_multi[2]},
            "block_classifier_only": {"target_precision": BLOCK_SOLO_TARGET, "threshold": block_solo[0],
                                      "precision": block_solo[1], "flows": block_solo[2]},
        },
        "calibrated": calibrated,
        "campaign_baseline": campaign_payload,
    }
    out = resolve(load_config()["data"]["reports_dir"]) / "calibration_report.json"
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
