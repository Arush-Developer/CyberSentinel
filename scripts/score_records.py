"""Run the full pipeline over a parquet of flows, such as the hidden set when it is released.

Writes one row per flow. Does not submit anything. Campaign detection uses endpoint mode by itself
if the file carries source_ip, destination_ip and seq or timestamp.

Usage: .venv/bin/python scripts/score_records.py --input PATH.parquet --output PATH.parquet
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from backend.investigation.audit import AuditLog  # noqa: E402
from backend.services.model_service import Pipeline  # noqa: E402
from backend.preprocessing.data_processor import split_representations  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--skip-investigations", action="store_true")
    args = ap.parse_args()
    pipe = Pipeline.load()
    analysis = pipe.analyse(split_representations(pd.read_parquet(args.input)))
    if not args.skip_investigations:
        print(pipe.run_investigations(analysis, AuditLog(maxlen=500_000)))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    analysis.frame.to_parquet(args.output, index=False)
    print(f"mode={analysis.campaign.mode} campaigns={len(analysis.campaign.campaigns)} rows={len(analysis.frame)}")
    print(analysis.frame["final_class"].value_counts().to_string())
    print(analysis.frame["policy_decision"].value_counts().to_string())
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
