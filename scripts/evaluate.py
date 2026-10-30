"""Run the full pipeline over the official eval records and report measured performance.

Labels are read only to score predictions that have already been made; nothing is tuned here.
Three modes run over the same records: A is the classifier alone, B adds independent anomaly evidence
and fusion, and C is the complete system with campaign intelligence and conditional investigation.
Level 1 is Mode B, because the brief's Level 1 is Agents 1 to 3.
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

from backend.agents.fusion_agent import BENIGN  # noqa: E402
from backend.config import load_config, resolve  # noqa: E402
from backend.evaluation.metrics import anomaly_report, classification_report, threshold_curve  # noqa: E402
from backend.intelligence.campaign_engine import COMPATIBLE_CLASSES  # noqa: E402
from backend.investigation.audit import AuditLog  # noqa: E402
from backend.services.model_service import Pipeline  # noqa: E402
from backend.policy.policy_engine import decide_batch  # noqa: E402
from backend.preprocessing.data_processor import load_partition, row_groups  # noqa: E402
from backend.replay.replay_engine import ReplayEngine  # noqa: E402


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


def mode_report(y, fused, decisions, classes, seconds: float, extra: dict | None = None) -> dict:
    """The same measures for every mode, so they can be compared directly."""
    rep = classification_report(y, fused.final_class, classes)
    return {
        "accuracy": rep["accuracy"], "macro_f1": rep["macro_f1"], "balanced_accuracy": rep["balanced_accuracy"],
        "per_class_recall": {c: rep["per_class"][c]["recall"] for c in classes},
        "per_class_precision": {c: rep["per_class"][c]["precision"] for c in classes},
        "confusion_matrix": rep["confusion_matrix"],
        "false_positive_rate": rep["binary_attack_false_positive_rate"],
        "false_negative_rate": rep["binary_attack_false_negative_rate"],
        "agent_agreement_rate": float((fused.agreement == "AGREE").mean()),
        "evidence_status_counts": {str(k): int(v) for k, v in zip(*np.unique(fused.evidence_status.astype(str),
                                                                               return_counts=True))},
        "policy": policy_outcomes(decisions, y),
        "seconds": round(seconds, 3),
        "latency_ms_per_1k_flows": round(1e6 * seconds / len(y), 3),
        **(extra or {}),
    }


def causal_replay(pipe, analysis, y) -> dict:
    """Run the live replay engine to the end: per-batch campaigns, tools that cannot see later records."""
    audit = AuditLog(maxlen=500_000)
    engine = ReplayEngine(pipe, analysis, audit, persist=False)
    started = time.perf_counter()
    engine.start(speed=100_000, batch_size=1000, max_investigations_per_batch=5)
    engine._thread.join()
    wall = time.perf_counter() - started
    frame = engine.replayed_frame()
    truth = y[engine.order]
    decision = frame["policy_decision"].to_numpy(dtype=object)
    rep = classification_report(truth, frame["final_class"].to_numpy(), pipe.threat.classes)
    return {
        "status": engine.status, "rows": len(frame), "macro_f1": rep["macro_f1"], "accuracy": rep["accuracy"],
        "policy": policy_outcomes(decision, truth),
        "campaigns": len(engine.tracker.campaigns),
        "investigations_run": len(engine.investigations),
        "investigation_triggers": engine.investigation_triggers,
        "replay_analysis_flows_per_second": engine.snapshot()["inference_flows_per_second"],
        "wall_seconds_at_requested_100k_flows_per_second": round(wall, 2),
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
    with_agent2 = pipe.fuse_level1(proba, scores)
    mode_b_decisions = decide_batch(with_agent2, pipe.thresholds)[0]

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

    evaluation_modes = {
        "rows": len(y),
        "note": "All modes use the same official eval records. Mode C's batch view assigns a flow to a campaign "
                "using its whole window; mode_c_causal_replay is the strictly forward run.",
        "mode_a_classifier_alone": mode_report(
            y, agent1_only, decide_batch(agent1_only, pipe.thresholds)[0], classes, threat_seconds,
            {"agent_agreement_rate": None, "evidence_status_counts": None}),  # Agent 2 is not part of this mode.
        "mode_b_with_anomaly_and_fusion": mode_report(
            y, with_agent2, mode_b_decisions, classes, threat_seconds + anomaly_seconds),
        "mode_c_complete_system": mode_report(
            y, fusion, decision, classes, analyse_seconds + investigation_stats["seconds"], {
                "investigation_coverage": {
                    "triggered": investigation_stats["triggered"], "investigated": investigation_stats["investigated"],
                    "share_of_flows": investigation_stats["investigated"] / len(y),
                    "verdicts": investigation_stats["verdicts"]},
                "campaign_grouping": {"campaigns": len(analysis.campaign.campaigns),
                                      "flows_in_a_campaign": int((analysis.campaign.flow_campaign != None).sum())},  # noqa: E711
            }),
        "mode_c_causal_replay": causal_replay(pipe, analysis, y),
    }

    report = {
        "partition": "eval",
        "evaluation_modes": evaluation_modes,
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

    level1 = evaluation_modes["mode_b_with_anomaly_and_fusion"]
    summary = {
        "track": "Cyber", "level": 1, "partition": "eval", "rows": len(y),
        "scope": "Agents 1 to 3 only (Mode B)",
        "accuracy": level1["accuracy"], "macro_f1": level1["macro_f1"],
        "agent1": {"accuracy": agent1["accuracy"], "macro_f1": agent1["macro_f1"],
                   "model": pipe.threat.model_version},
        "agent2": {k: agent2[k] for k in ("roc_auc", "pr_auc", "recall", "false_positive_rate")},
        "agent3": {"agreement_rate": level1["agent_agreement_rate"],
                   "evidence_status_counts": level1["evidence_status_counts"],
                   "policy_counts": level1["policy"]["counts"]},
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
    print(json.dumps(evaluation_modes["mode_c_causal_replay"], indent=2))
    print({c: round(v["recall"], 4) for c, v in system["per_class"].items()})
    print(json.dumps(system["confusion_matrix"]))


if __name__ == "__main__":
    main()
