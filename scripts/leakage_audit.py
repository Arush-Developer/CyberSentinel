"""Why is the classifier near-perfect? Looks for single features or simple rules that give the label away.

Uses the training partition only. Output: data/reports/leakage_audit.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: E402
from sklearn.metrics import f1_score  # noqa: E402
from sklearn.tree import DecisionTreeClassifier, export_text  # noqa: E402

from backend.config import load_config, resolve  # noqa: E402
from backend.preprocessing.data_processor import PORT_FEATURE, FeaturePipeline, load_partition  # noqa: E402


def macro(y_true, y_pred) -> float:
    return float(f1_score(y_true, y_pred, average="macro"))


def main() -> None:
    cfg = load_config()
    part = load_partition("training")
    splits = np.load(resolve(cfg["data"]["processed_dir"]) / "internal_splits.npz")
    fit, test = splits["fit"], splits["selection"]
    y = part.labels.to_numpy()
    pipe = FeaturePipeline().fit(part.features.iloc[fit])
    X = pipe.transform(part.features)
    names = pipe.columns_

    single = {}
    for j, name in enumerate(names):
        tree = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=0)
        tree.fit(X[fit][:, [j]], y[fit])
        single[name] = macro(y[test], tree.predict(X[test][:, [j]]))
    ranked = sorted(single.items(), key=lambda kv: -kv[1])

    depth = {}
    for d in (1, 2, 3, 4, 6, 8):
        tree = DecisionTreeClassifier(max_depth=d, class_weight="balanced", random_state=0).fit(X[fit], y[fit])
        depth[d] = {"macro_f1": macro(y[test], tree.predict(X[test])), "per_class": dict(zip(
            sorted(set(y)), map(float, f1_score(y[test], tree.predict(X[test]), average=None, labels=sorted(set(y))))))}
    small = DecisionTreeClassifier(max_depth=3, class_weight="balanced", random_state=0).fit(X[fit], y[fit])
    rules = export_text(small, feature_names=names, max_depth=3)

    # Knock out the most informative features cumulatively and refit a fast booster.
    knockout = []
    removed: list[str] = []
    sample = np.random.default_rng(0).choice(fit, size=min(120_000, len(fit)), replace=False)
    for name, _ in [("none", 0.0)] + ranked[:25]:
        if name != "none":
            removed.append(name)
        keep = [j for j, n in enumerate(names) if n not in removed]
        model = HistGradientBoostingClassifier(max_iter=60, class_weight="balanced", random_state=0)
        model.fit(X[sample][:, keep], y[sample])
        knockout.append({"removed": len(removed), "last_removed": name, "macro_f1": macro(y[test], model.predict(X[test][:, keep]))})

    # Benign flows' port mix against attacks: do classes share any behaviour at all?
    per_class = {}
    for cls in sorted(set(y)):
        mask = y == cls
        frame = part.features[mask]
        per_class[cls] = {
            "rows": int(mask.sum()),
            "unique_feature_rows": int(len(frame.drop_duplicates())),
            "ports": int(frame[PORT_FEATURE].nunique()),
            "median_flow_duration": float(frame["Flow Duration"].median()),
            "median_init_win_fwd": float(frame["Init_Win_bytes_forward"].median()),
            "init_win_fwd_unique": int(frame["Init_Win_bytes_forward"].nunique()),
            "median_init_win_bwd": float(frame["Init_Win_bytes_backward"].median()),
            "init_win_bwd_unique": int(frame["Init_Win_bytes_backward"].nunique()),
            "median_fwd_packets": float(frame["Total Fwd Packets"].median()),
        }

    report = {
        "split": "fit vs selection, training partition only",
        "top_single_features_depth4_tree": ranked[:15],
        "tree_depth_vs_macro_f1": depth,
        "depth3_rules": rules,
        "cumulative_top_feature_knockout": knockout,
        "per_class_profile": per_class,
    }
    out = resolve(cfg["data"]["reports_dir"]) / "leakage_audit.json"
    out.write_text(json.dumps(report, indent=2))
    print("top single:", json.dumps(ranked[:15]))
    print("depth:", {k: round(v["macro_f1"], 4) for k, v in depth.items()})
    print(rules)
    print("knockout:", [(k["removed"], k["last_removed"], round(k["macro_f1"], 4)) for k in knockout])
    print(pd.DataFrame(per_class).T.to_string())


if __name__ == "__main__":
    main()
