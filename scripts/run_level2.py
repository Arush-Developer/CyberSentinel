"""Run all five agents over a flow file in the supplied order and write the three Level 2 CSVs.

Nothing is uploaded: the organisers' Level 2 API details are not yet available. The file's labels, if
it has any, are ignored. Checks the output against the brief's rules and refuses to report success otherwise.

Usage: .venv/bin/python scripts/run_level2.py --input PATH/TO/hidden.parquet --out-dir data/processed/level2
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.preprocessing.data_processor import load_flows, replay_order  # noqa: E402
from backend.services.level2 import run_level2, validate_outputs, write_outputs  # noqa: E402
from backend.services.model_service import Pipeline  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--out-dir", type=Path, default=ROOT / "data/processed/level2")
    args = ap.parse_args()
    partition = load_flows(args.input)
    result = run_level2(Pipeline.load(), partition)
    meta = partition.metadata.iloc[replay_order(partition.metadata)]
    problems = validate_outputs(result["classification"], result["policy"], result["replay"],
                                meta["flow_id"], meta["source_ip"])
    paths = write_outputs(result, args.out_dir)
    print(f"records={len(result['replay'])} policies={len(result['policy'])} groups={len(result['groups'])} "
          f"blocked={(result['replay']['action'] == 'BLOCK').sum()}")
    for name, path in paths.items():
        print(f"wrote {name}: {path}")
    if problems:
        print("\n".join(problems[:50]))
        raise SystemExit(f"{len(problems)} rule violations; do not submit these files")
    print("rule check: passed")


if __name__ == "__main__":
    main()
