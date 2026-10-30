"""Phase 0: inspect the official archive, extract it safely and profile the Cyber partitions.

Writes data/reports/dataset_profile.json and a readable data/reports/dataset_profile.md.
Nothing inside the archive is executed; only parquet/json/markdown are read as data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.config import load_config  # noqa: E402

SUSPICIOUS_ID_TOKENS = ("ip", "addr", "flow id", "timestamp", "seq", "host", "mac")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def unsafe_member(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    return name.startswith(("/", "\\")) or ".." in parts or (len(parts[0]) == 2 and parts[0][1] == ":")


def inspect_archive(zip_path: Path) -> dict:
    with zipfile.ZipFile(zip_path) as zf:
        members = [
            {
                "name": i.filename,
                "compressed_bytes": i.compress_size,
                "uncompressed_bytes": i.file_size,
                "is_dir": i.is_dir(),
                "is_symlink": (i.external_attr >> 16) & 0o170000 == 0o120000,
                "unsafe_path": unsafe_member(i.filename),
            }
            for i in zf.infolist()
        ]
    return {
        "path": str(zip_path.relative_to(ROOT)),
        "sha256": sha256(zip_path),
        "bytes": zip_path.stat().st_size,
        "members": members,
        "any_unsafe": any(m["unsafe_path"] or m["is_symlink"] for m in members),
    }


def extract(zip_path: Path, dest: Path) -> None:
    """Extract only regular files, refusing any path that would escape dest."""
    dest = dest.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = (dest / info.filename).resolve()
            if unsafe_member(info.filename) or not target.is_relative_to(dest):
                raise ValueError(f"unsafe archive member refused: {info.filename}")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"symlink archive member refused: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                while block := src.read(1 << 20):
                    out.write(block)


def json_safe(v):
    if isinstance(v, (float, np.floating)):
        return None if not np.isfinite(v) else float(v)
    if isinstance(v, (np.integer,)):
        return int(v)
    return v


def profile_partition(path: Path, label_col: str, id_col: str, known_labels: list[str]) -> dict:
    meta = pq.ParquetFile(path)
    df = pd.read_parquet(path)
    features = [c for c in df.columns if c not in (label_col, id_col)]
    numeric = df[features].select_dtypes(include=[np.number])
    non_numeric = [c for c in features if c not in numeric.columns]
    values = numeric.to_numpy(dtype=np.float64)

    stats = {}
    for i, col in enumerate(numeric.columns):
        v = values[:, i]
        finite = v[np.isfinite(v)]
        stats[col] = {
            "dtype": str(numeric[col].dtype),
            "missing": int(np.isnan(v).sum()),
            "pos_inf": int(np.isposinf(v).sum()),
            "neg_inf": int(np.isneginf(v).sum()),
            "negative": int((finite < 0).sum()),
            "n_unique": int(numeric[col].nunique(dropna=True)),
            "min": json_safe(finite.min()) if finite.size else None,
            "p50": json_safe(np.median(finite)) if finite.size else None,
            "p99": json_safe(np.percentile(finite, 99)) if finite.size else None,
            "max": json_safe(finite.max()) if finite.size else None,
            "mean": json_safe(finite.mean()) if finite.size else None,
            "std": json_safe(finite.std()) if finite.size else None,
        }

    # Hashing each column finds exact duplicates; NaN compares equal under the hash.
    hashes: dict[int, list[str]] = {}
    for col in numeric.columns:
        hashes.setdefault(int(pd.util.hash_pandas_object(numeric[col], index=False).sum()), []).append(col)
    duplicate_cols = [g for g in hashes.values() if len(g) > 1]

    counts = df[label_col].value_counts(dropna=False)
    ids = df[id_col]
    row_hash = pd.util.hash_pandas_object(df[features], index=False)
    suspicious = [c for c in df.columns if any(t in c.lower() for t in SUSPICIOUS_ID_TOKENS)
                  and c not in ("Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min")]

    # Does row position or record_id encode the label? Either would be leakage.
    position_runs = int((df[label_col] != df[label_col].shift()).sum())
    return {
        "rows": int(len(df)),
        "columns": int(df.shape[1]),
        "parquet_row_groups": meta.num_row_groups,
        "schema": {c: str(t) for c, t in df.dtypes.items()},
        "feature_count": len(features),
        "non_numeric_features": non_numeric,
        "total_missing": int(np.isnan(values).sum()),
        "total_inf": int(np.isinf(values).sum()),
        "rows_with_nonfinite": int((~np.isfinite(values)).any(axis=1).sum()),
        "columns_with_nonfinite": [c for c, s in stats.items() if s["missing"] + s["pos_inf"] + s["neg_inf"]],
        "constant_features": [c for c, s in stats.items() if s["n_unique"] <= 1],
        "duplicate_columns": duplicate_cols,
        "duplicate_records_full_features": int(row_hash.duplicated().sum()),
        "duplicate_records_same_features_conflicting_label": int(
            pd.DataFrame({"h": row_hash, "l": df[label_col]}).groupby("h")["l"].nunique().gt(1).sum()
        ),
        "record_id": {
            "dtype": str(ids.dtype),
            "unique": bool(ids.is_unique),
            "sample": [str(x) for x in ids.head(5)],
        },
        "label_distribution": {str(k): int(v) for k, v in counts.items()},
        "class_imbalance_ratio_max_over_min": float(counts.max() / counts.min()),
        "unmapped_labels": sorted(set(map(str, counts.index)) - set(known_labels)),
        "label_runs_in_file_order": position_runs,
        "suspicious_identifier_columns": suspicious,
        "numeric_feature_stats": stats,
        "_row_hash": row_hash,
        "_ids": ids,
    }


def misleading_features(report_dir: Path) -> list[str]:
    """Features that look useful but should not be trusted blindly, from this pack's measured audits."""
    notes = [
        "`record_id`: identifier whose numbering clusters by class. Never a model input.",
        "`Destination Port`: near-deterministic for some classes in this capture. Dropped from both models "
        "after the port study showed no macro-F1 gain; kept as network metadata.",
        "`Init_Win_bytes_forward` and similar TCP fingerprints: almost constant within each attack class, so "
        "they describe this capture's attack tools and may not generalise.",
        "Rate features such as `Flow Bytes/s`: originally prone to infinities in CICIDS2017. This pack has none, "
        "but the pipeline still handles them.",
    ]
    path = report_dir / "leakage_audit.json"
    if path.exists():
        notes.append("Measured leakage audit: `data/reports/leakage_audit.json`.")
    return notes


def write_markdown(report: dict, path: Path, misleading: list[str]) -> None:
    lines = ["# Dataset profile", "", f"Generated by `scripts/profile_dataset.py` from `{report['archive']['path']}`.", "",
             f"SHA-256 `{report['archive']['sha256']}`, {report['archive']['bytes']:,} bytes.", "",
             "## Files and partitions", "",
             "| Partition | Role | Rows | Columns | Features | Missing | Infinite | Duplicate rows | Duplicate columns | Constant |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    roles = {"training": "Training", "eval": "Official validation"}
    for name, p in report["partitions"].items():
        lines.append(f"| `{name}` | {roles.get(name, name)} | {p['rows']:,} | {p['columns']} | {p['feature_count']} | "
                     f"{p['total_missing']} | {p['total_inf']} | {p['duplicate_records_full_features']:,} | "
                     f"{len(p['duplicate_columns'])} | {len(p['constant_features'])} |")
    cross = report["cross_partition"]
    lines += ["", f"Schemas identical: **{cross['schema_identical']}**. Shared record IDs: **{cross['record_id_overlap']}**. "
              f"Validation rows whose exact features also occur in training: **{cross['eval_rows_with_identical_features_in_training']:,}**.",
              "", "## Label column and distribution", "", "Label column: `label`. Identifier: `record_id`.", "",
              "| Class | Training | Validation |", "|---|---:|---:|"]
    train, ev = report["partitions"]["training"], report["partitions"]["eval"]
    for cls in train["label_distribution"]:
        lines.append(f"| `{cls}` | {train['label_distribution'][cls]:,} | {ev['label_distribution'].get(cls, 0):,} |")
    lines += ["", f"Class imbalance, largest over smallest: {train['class_imbalance_ratio_max_over_min']:.1f} to 1.",
              f"Unmapped labels: training {train['unmapped_labels'] or 'none'}, validation {ev['unmapped_labels'] or 'none'}. "
              "The pack's labels are already the five benchmark classes, so `configs/default.yaml` holds an explicit identity mapping.",
              "", "## Data types and categorical features", "",
              f"Non-numeric features: {train['non_numeric_features'] or 'none'}. Every feature is numeric, so there is nothing "
              "to encode; `record_id` and `label` are the only string columns.", "",
              "## Network metadata", "",
              "| Column | In the participant pack |", "|---|---|"]
    lines += [f"| `{c}` | {'yes' if v else 'no'} |" for c, v in report["network_metadata_available"].items()]
    lines += ["", "The pack's README says endpoint columns ship with the hidden set.", "",
              "## Potentially misleading features", ""] + [f"- {m}" for m in misleading]
    lines += ["", "## Duplicates and columns", "",
              f"Duplicate column groups in training: {train['duplicate_columns'] or 'none'}.",
              f"Constant features in training: {train['constant_features'] or 'none'}.",
              f"Feature rows with conflicting labels in training: {train['duplicate_records_same_features_conflicting_label']}.",
              "", "## Numerical feature statistics (training)", "",
              "| Feature | Unique | Min | Median | P99 | Max | Mean | Negative values |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    fmt = lambda v: "n/a" if v is None else f"{v:,.4g}"
    for col, st in train["numeric_feature_stats"].items():
        lines.append(f"| {col} | {st['n_unique']:,} | {fmt(st['min'])} | {fmt(st['p50'])} | {fmt(st['p99'])} | "
                     f"{fmt(st['max'])} | {fmt(st['mean'])} | {st['negative']:,} |")
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-extract", action="store_true")
    args = ap.parse_args()
    cfg = load_config()
    zip_path = next((ROOT / a for a in (cfg["data"]["archive"], cfg["data"]["archive_alternate"])
                     if (ROOT / a).exists()), None)
    if zip_path is None:
        raise SystemExit(f"official archive not found; expected {cfg['data']['archive']}")
    extracted = ROOT / cfg["data"]["extracted_dir"]
    report_dir = ROOT / cfg["data"]["reports_dir"]
    report_dir.mkdir(parents=True, exist_ok=True)

    report = {"archive": inspect_archive(zip_path)}
    if report["archive"]["any_unsafe"]:
        raise SystemExit("archive contains unsafe members; refusing to extract")
    if not args.no_extract:
        extract(zip_path, extracted)

    manifest = json.loads((extracted / "manifest.json").read_text())
    cyber = manifest["tracks"]["cyber"]
    report["manifest_checks"] = {}
    labels = cfg["labels"]["classes"]
    label_col, id_col = cfg["data"]["label_column"], cfg["data"]["id_column"]

    partitions = {}
    for name, part in cyber["partitions"].items():
        path = extracted / part["path"]
        digest = sha256(path)
        prof = profile_partition(path, label_col, id_col, labels)
        report["manifest_checks"][name] = {
            "sha256_matches": digest == part["sha256"],
            "rows_match": prof["rows"] == part["rows"],
            "classes_match": prof["label_distribution"] == part["classes"],
        }
        partitions[name] = prof

    train, ev = partitions["training"], partitions["eval"]
    report["cross_partition"] = {
        "schema_identical": list(train["schema"].items()) == list(ev["schema"].items()),
        "record_id_overlap": int(train["_ids"].astype(str).isin(set(ev["_ids"].astype(str))).sum()),
        "eval_rows_with_identical_features_in_training": int(ev["_row_hash"].isin(set(train["_row_hash"])).sum()),
    }
    for p in partitions.values():
        p.pop("_row_hash"), p.pop("_ids")
    report["partitions"] = partitions
    report["network_metadata_available"] = {
        c: c in train["schema"] for c in cfg["data"]["metadata_columns"]
    }
    out = report_dir / "dataset_profile.json"
    out.write_text(json.dumps(report, indent=2, default=json_safe))
    write_markdown(report, report_dir / "dataset_profile.md", misleading_features(report_dir))
    print(f"wrote {out} and dataset_profile.md")


if __name__ == "__main__":
    main()
