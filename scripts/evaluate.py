"""Run the full pipeline over the official eval records and report measured performance.

Labels are read only to score predictions that have already been made; nothing is tuned here.
Outputs: data/reports/evaluation_report.json, data/reports/level1_summary.json,
data/processed/eval_predictions.parquet
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402

from backend.agents.fusion_agent import BENIGN, FusionConfig, fuse_batch  # noqa: E402
from backend.config import load_config, resolve  # noqa: E402
from backend.evaluation.metrics import anomaly_report, classification_report, threshold_curve  # noqa: E402
from backend.intelligence.campaign_engine import COMPATIBLE_CLASSES  # noqa: E402
from backend.investigation.audit import AuditLog  # noqa: E402
from backend.services.model_service import Pipeline  # noqa: E402
from backend.policy.policy_engine import decide_batch  # noqa: E402
from backend.preprocessing.data_processor import load_partition, row_groups  # noqa: E402


def policy_outcomes(decision, y) -> dict:
    attack = y != BENIGN
    return {
        "counts": {k: int((decision == k).sum()) for k in ("ALLOW", "BLOCK", "REVIEW")},
        "attacks_blocked_rate": float((decision[attack] == "BLOCK").mean()),
        "attacks_allowed_rate": float((decision[attack] == "ALLOW").mean()),
        "attacks_reviewed_rate": float((decision[attack] == "REVIEW").mean()),
        "benign_allowed_rate": float((decision[~attack] == "ALLOW").mean()),
        "benign_blocked_rate": float((decision[~attack] == "BLOCK").mean()),
        "benign_reviewed_rate": float((decision[~attack] == "REVIEW").mean()),
    }


def campaign_evaluation(analysis, y) -> dict:
    """Scores campaign hypotheses against labels after detection has finished."""
    campaigns = analysis.campaign.campaigns
    per_type: dict[str, dict] = {}
    cid_types = {c["campaign_id"]: c["campaign_type"] for c in campaigns}
    member_types = np.array([cid_types.get(c) for c in analysis.campaign.flow_campaign], dtype=object)
    for ctype in sorted({c["campaign_type"] for c in campaigns}):
        mask = member_types == ctype
        truth = y[mask]
        per_type[ctype] = {
            "campaigns": sum(c["campaign_type"] == ctype for c in campaigns),
            "member_flows": int(mask.sum()),
            "member_share_of_matching_class": float(np.isin(truth, list(COMPATIBLE_CLASSES[ctype])).mean()),
            "member_share_benign": float((truth == BENIGN).mean()),
        }
    in_any = member_types != None  # noqa: E711
    return {
        "mode": analysis.campaign.mode,
        "limitations": analysis.campaign.limitations,
        "total_campaigns": len(campaigns),
        "per_type": per_type,
        "share_of_each_class_in_a_campaign": {
            c: float(in_any[y == c].mean()) for c in np.unique(y)},
    }


def main() -> None:
    cfg = load_config()
    classes = cfg["labels"]["classes"]
    pipe = Pipeline.load()
    train_part = load_partition("training")
    part = load_partition("eval")
    y = part.labels.to_numpy()

    start = time.perf_counter()
    proba = pipe.threat.predict_proba(part.features)
    threat_seconds = time.perf_counter() - start
    start = time.perf_counter()
    pipe.anomaly.score(part.features)
    anomaly_seconds = time.perf_counter() - start

    start = time.perf_counter()
    analysis = pipe.analyse(part)
    analyse_seconds = time.perf_counter() - start
    scores = analysis.scores

    # Layers measured before investigation feeds back into fusion.
    after_campaign = analysis.fusion
    campaign_decision = decide_batch(after_campaign, pipe.thresholds)[0].copy()

    audit = AuditLog(maxlen=500_000)
    investigation_stats = pipe.run_investigations(analysis, audit)
    fusion = analysis.fusion
    frame = analysis.frame
    decision = frame["policy_decision"].to_numpy(dtype=object)

    agent1 = classification_report(y, fusion.threat_class, classes)
    system = classification_report(y, fusion.final_class, classes)
    is_attack = y != BENIGN
    agent2 = anomaly_report(is_attack, scores, fusion.is_anomaly) | {
        "per_class_flag_rate": {c: float(fusion.is_anomaly[y == c].mean()) for c in classes},
        "threshold_curve": threshold_curve(is_attack, scores, [0.8, 0.9, 0.95, 0.98, 0.99]),
        "score_histogram_by_class": {
            c: np.histogram(scores[y == c], bins=20, range=(0, 1))[0].tolist() for c in classes},
    }

    # Metrics again, excluding eval rows whose exact features also occur in training.
    seen = np.isin(row_groups(part.features), np.unique(row_groups(train_part.features)))
    unseen = classification_report(y[~seen], fusion.threat_class[~seen], classes)

    # Ablation: each layer's measured effect on classes and on decisions.
    agent1_only = pipe.fuse(proba, np.zeros(len(y)))
    with_agent2 = fuse_batch(proba, classes, scores, pipe.anomaly.threshold, FusionConfig())

    def layer(fused, decisions):
        rep = classification_report(y, fused.final_class, classes)
        return {"macro_f1": rep["macro_f1"], "accuracy": rep["accuracy"], "policy": policy_outcomes(decisions, y)}

    ablation = {
        "agent1_alone": layer(agent1_only, decide_batch(agent1_only, pipe.thresholds)[0]),
        "agent1_plus_agent2": layer(with_agent2, decide_batch(with_agent2, pipe.thresholds)[0]),
        "plus_campaign_intelligence": layer(after_campaign, campaign_decision),
        "plus_investigation": layer(fusion, decision),
        "note": "Agent 2, campaigns and investigation change evidence and policy routing. They change "
                "final_class only if the benign override passed internal validation.",
    }

    report = {
        "partition": "eval",
        "labels_used_for": "scoring only; no model or threshold was tuned on this partition",
        "model_version": pipe.threat.model_version,
        "anomaly_version": pipe.anomaly.model_version,
        "anomaly_detector": pipe.anomaly.detector,
        "fusion_config": pipe.fusion_config.__dict__,
        "policy_thresholds": pipe.thresholds.to_dict(),
        "agent1": agent1,
        "agent1_excluding_rows_also_in_training": unseen | {"excluded_rows": int(seen.sum())},
        "agent2": agent2,
        "system": system,
        "ablation": ablation,
        "agent_agreement_rate": float((fusion.agreement == "AGREE").mean()),
        "evidence_status_counts": {k: int(v) for k, v in frame["evidence_status"].value_counts().items()},
        "policy": policy_outcomes(decision, y),
        "policy_rule_counts": {k: int(v) for k, v in frame["policy_rule"].value_counts().items()},
        "campaign_intelligence": campaign_evaluation(analysis, y),
        "investigation": investigation_stats,
        "latency": {
            "agent1_ms_per_1k_flows": 1e6 * threat_seconds / len(y),
            "agent2_ms_per_1k_flows": 1e6 * anomaly_seconds / len(y),
            "scoring_campaign_fusion_policy_flows_per_second": len(y) / analyse_seconds,
            "investigation_seconds": investigation_stats["seconds"],
        },
    }
    reports = resolve(cfg["data"]["reports_dir"])
    (reports / "evaluation_report.json").write_text(json.dumps(report, indent=2))

    summary = {
        "track": "Cyber", "level": 1, "partition": "eval", "rows": len(y),
        "accuracy": system["accuracy"], "macro_f1": system["macro_f1"],
        "agent1": {"accuracy": agent1["accuracy"], "macro_f1": agent1["macro_f1"],
                   "model": pipe.threat.model_version},
        "agent2": {k: agent2[k] for k in ("roc_auc", "pr_auc", "recall", "false_positive_rate")},
        "agent3": {"agreement_rate": report["agent_agreement_rate"],
                   "evidence_status_counts": report["evidence_status_counts"],
                   "policy_counts": report["policy"]["counts"]},
    }
    (reports / "level1_summary.json").write_text(json.dumps(summary, indent=2))
    processed = resolve(cfg["data"]["processed_dir"])
    processed.mkdir(parents=True, exist_ok=True)
    frame.assign(ground_truth_evaluation_only=y).to_parquet(processed / "eval_predictions.parquet", index=False)
    print(json.dumps(summary, indent=2))
    print(json.dumps({k: {"macro_f1": v["macro_f1"], "policy": v["policy"]} for k, v in ablation.items()
                      if isinstance(v, dict)}, indent=2))
    print("excluding train-duplicate rows:", unseen["macro_f1"], unseen["accuracy"], "excluded", int(seen.sum()))
    print(json.dumps(report["campaign_intelligence"], indent=2))
    print(json.dumps(investigation_stats, indent=2))
    print(json.dumps(report["latency"], indent=2))
    print({c: round(v["recall"], 4) for c, v in system["per_class"].items()})
    print(json.dumps(system["confusion_matrix"]))


if __name__ == "__main__":
    main()
