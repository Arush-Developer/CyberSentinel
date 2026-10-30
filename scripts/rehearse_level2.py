"""Rehearse Level 2 on official eval flows with SYNTHETIC endpoints.

The participant pack has no endpoints, so this script invents them and labels them as invented. It
proves the mechanism and the file rules; its containment numbers do not predict hidden-set scores,
because they depend on how the endpoints were assigned here. Labels are used for scoring afterwards only.

Writes data/processed/rehearsal/flows.parquet (no labels), the three CSVs beside it, and
data/reports/level2_rehearsal.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from backend.agents.defense_agent import BLOCK  # noqa: E402
from backend.config import load_config, resolve  # noqa: E402
from backend.preprocessing.data_processor import load_flows, replay_order  # noqa: E402
from backend.services.level2 import run_level2, validate_outputs, write_outputs  # noqa: E402
from backend.services.model_service import Pipeline  # noqa: E402

COLLATERAL_BENIGN_SHARE = 0.02


def synthetic_endpoints(labels: pd.Series, seed: int = 7) -> pd.DataFrame:
    """One attacker per class, except DDoS with 30 sources; 2% of benign flows share an attacker's address."""
    rng = np.random.default_rng(seed)
    n = len(labels)
    benign_hosts = np.array([f"10.20.{i // 250}.{i % 250 + 1}" for i in range(400)])
    # Object arrays: a fixed-width string array would silently cut longer addresses when they are assigned.
    source = rng.choice(benign_hosts, n).astype(object)
    destination = rng.choice([f"192.0.2.{i}" for i in range(1, 41)], n).astype(object)
    attackers = {"BRUTE_FORCE": ["198.51.100.10"], "DOS": ["198.51.100.20"], "PORT_SCAN": ["198.51.100.30"],
                 "DDOS": [f"203.0.113.{i}" for i in range(1, 31)]}
    victims = {"BRUTE_FORCE": "192.0.2.100", "DOS": "192.0.2.101", "PORT_SCAN": "192.0.2.102", "DDOS": "192.0.2.103"}
    y = labels.to_numpy()
    for cls, hosts in attackers.items():
        mask = y == cls
        source[mask] = rng.choice(hosts, mask.sum())
        destination[mask] = victims[cls]
    shared = (y == "BENIGN") & (rng.random(n) < COLLATERAL_BENIGN_SHARE)
    source[shared] = rng.choice([h[0] for h in attackers.values()], shared.sum())
    return pd.DataFrame({"source_ip": source, "destination_ip": destination})


def main() -> None:
    cfg = load_config()
    raw = pd.read_parquet(resolve(cfg["data"]["eval_parquet"]))
    labels = raw[cfg["data"]["label_column"]]
    endpoints = synthetic_endpoints(labels)
    out_dir = resolve(cfg["data"]["processed_dir"]) / "rehearsal"
    out_dir.mkdir(parents=True, exist_ok=True)
    flows = raw.drop(columns=[cfg["data"]["label_column"]]).assign(
        source_ip=endpoints["source_ip"], destination_ip=endpoints["destination_ip"],
        seq=np.arange(len(raw)))
    flows_path = out_dir / "flows.parquet"
    flows.to_parquet(flows_path, index=False)

    partition = load_flows(flows_path)
    result = run_level2(Pipeline.load(), partition)
    meta = partition.metadata.iloc[replay_order(partition.metadata)]
    problems = validate_outputs(result["classification"], result["policy"], result["replay"],
                                meta["flow_id"], meta["source_ip"])
    write_outputs(result, out_dir)

    truth = labels.to_numpy()[result["order"]]
    blocked = result["replay"]["action"].to_numpy() == BLOCK
    attack = truth != "BENIGN"
    report = {
        "warning": "SYNTHETIC endpoints on real flows. Proves the mechanism and file rules only; "
                   "not a prediction of hidden-set performance.",
        "assignment": "one source per attack class, 30 sources for DDoS, "
                      f"{COLLATERAL_BENIGN_SHARE:.0%} of benign flows share an attacker address",
        "rows": len(truth),
        "rule_violations": problems[:50],
        "policies": len(result["policy"]),
        "correlation_groups": len(result["groups"]),
        "attack_flows_blocked_share": float(blocked[attack].mean()),
        "benign_flows_blocked_share": float(blocked[~attack].mean()),
        "benign_flows_blocked": int(blocked[~attack].sum()),
        "attack_blocked_share_by_class": {c: float(blocked[truth == c].mean()) for c in np.unique(truth) if c != "BENIGN"},
    }
    (resolve(cfg["data"]["reports_dir"]) / "level2_rehearsal.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    if problems:
        raise SystemExit("rule violations found")


if __name__ == "__main__":
    main()
