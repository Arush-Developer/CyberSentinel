"""Level 2 outputs: classification.csv, policy.csv and replay.csv, plus a checker for their rules.

Scoring is per-flow, so it can be batched without seeing other flows. Agents 4 and 5 then run one
record at a time in the supplied order, through the same DefenseLoop as the live replay.
"""
from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

import numpy as np
import pandas as pd

from backend.agents.defense_agent import ALLOW, BLOCK, DefenseConfig, DefenseLoop
from backend.agents.temporal_agent import TemporalConfig
from backend.config import load_config
from backend.preprocessing.data_processor import Partition, replay_order

POLICY_COLUMNS = ["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id",
                  "policy_action"]


def _known(cls, values: dict) -> dict:
    allowed = {f.name for f in fields(cls)}
    return {k: v for k, v in values.items() if k in allowed}


def temporal_config(level2: dict | None = None) -> TemporalConfig:
    level2 = load_config().get("level2", {}) if level2 is None else level2
    return TemporalConfig(**_known(TemporalConfig, level2.get("temporal", {})))


def defense_config(level2: dict | None = None) -> DefenseConfig:
    level2 = load_config().get("level2", {}) if level2 is None else level2
    return DefenseConfig(**_known(DefenseConfig, level2.get("defense", {})))


def run_level2(pipeline, partition: Partition, temporal: TemporalConfig | None = None,
               defense: DefenseConfig | None = None) -> dict:
    """Run all five agents. Labels are never read, even if the file carries them."""
    meta = partition.metadata
    missing = {"source_ip", "destination_ip"} - set(meta.columns)
    if missing:
        raise ValueError(f"Agents 4 and 5 need endpoint columns; missing: {sorted(missing)}")
    order = replay_order(meta)
    features = partition.features.iloc[order].reset_index(drop=True)
    meta = meta.iloc[order].reset_index(drop=True)
    proba, scores = pipeline.score(features)
    fusion = pipeline.fuse_level1(proba, scores)
    ids = meta["flow_id"].astype(str).to_numpy()
    classification = pd.DataFrame({"record_id": ids, "predicted_class": fusion.final_class,
                                   "anomaly_score": np.round(scores, 6), "evidence_status": fusion.evidence_status})

    loop = DefenseLoop(temporal or temporal_config(), defense or defense_config())
    actions, applied = [], []
    ports = pd.to_numeric(meta["destination_port"]).to_numpy(dtype=float) if "destination_port" in meta else [None] * len(ids)
    sources, destinations = meta["source_ip"].astype(str).to_numpy(), meta["destination_ip"].astype(str).to_numpy()
    for i, record_id in enumerate(ids):
        step = loop.step(i, record_id, sources[i], destinations[i], ports[i], fusion.final_class[i],
                         float(fusion.threat_confidence[i]), float(scores[i]), bool(fusion.is_anomaly[i]),
                         fusion.evidence_status[i])
        actions.append(step["action"])
        applied.append(step["applied_policy_id"])
    if len(ids):
        loop.finish(len(ids) - 1, ids[-1])
    return {
        "classification": classification,
        "replay": pd.DataFrame({"record_id": ids, "action": actions, "applied_policy_id": applied}),
        "policy": pd.DataFrame([{c: p[c] for c in POLICY_COLUMNS} for p in loop.defense.public_policies()],
                               columns=POLICY_COLUMNS),
        "policies": loop.defense.public_policies(),
        "log": loop.defense.log,
        "groups": loop.temporal.public_groups(),
        "order": order,
    }


def validate_outputs(classification: pd.DataFrame, policy: pd.DataFrame, replay: pd.DataFrame, record_ids,
                     sources) -> list[str]:
    """Check the brief's rules. Returns every problem found; an empty list means the files are consistent.

    record_ids and sources must be in official replay order.
    """
    problems: list[str] = []
    ids = [str(r) for r in record_ids]
    position = {r: i for i, r in enumerate(ids)}
    source_of = dict(zip(ids, map(str, sources)))
    for name, frame in (("classification", classification), ("replay", replay)):
        got = frame["record_id"].astype(str)
        if got.duplicated().any():
            problems.append(f"{name}.csv repeats record ids")
        if set(got) != set(ids):
            problems.append(f"{name}.csv does not cover every record exactly once")
    classes = set(load_config()["labels"]["classes"])
    if not set(classification["predicted_class"]) <= classes:
        problems.append("classification.csv has a class outside the five benchmark classes")
    if policy["policy_id"].duplicated().any():
        problems.append("policy.csv repeats policy ids")
    if len(policy) and (set(policy["scope_type"]) != {"SOURCE_IP"} or set(policy["policy_action"]) != {BLOCK}):
        problems.append("policy.csv must use scope_type SOURCE_IP and policy_action BLOCK")
    if len(replay["record_id"]) and not set(replay["action"]) <= {ALLOW, BLOCK}:
        problems.append("replay.csv action must be ALLOW or BLOCK")
    policies = {p.policy_id: p for p in policy.itertuples(index=False)}
    for p in policies.values():
        if str(p.activated_after_record_id) not in position or str(p.expires_after_record_id) not in position:
            problems.append(f"{p.policy_id}: activation or expiry names an unknown record")
        elif position[str(p.expires_after_record_id)] <= position[str(p.activated_after_record_id)]:
            problems.append(f"{p.policy_id}: expires at or before its activation")
        elif source_of[str(p.activated_after_record_id)] != str(p.scope_value):
            problems.append(f"{p.policy_id}: triggering record is not from the policy's source")
    for r in replay.itertuples(index=False):
        record = str(r.record_id)
        applied = "" if pd.isna(r.applied_policy_id) else str(r.applied_policy_id)
        if r.action == ALLOW:
            if applied:
                problems.append(f"{record}: ALLOW must have an empty applied_policy_id")
            continue
        p = policies.get(applied)
        if p is None:
            problems.append(f"{record}: BLOCK references no known policy")
        elif source_of.get(record) != str(p.scope_value):
            problems.append(f"{record}: BLOCK by {applied} from a different source")
        elif str(p.activated_after_record_id) in position and str(p.expires_after_record_id) in position and not (
                position[str(p.activated_after_record_id)] < position[record] <= position[str(p.expires_after_record_id)]):
            problems.append(f"{record}: BLOCK by {applied} outside its active range")
    # Every flow from a source inside an active range must be blocked, or a policy was not applied.
    for p in policies.values():
        start, end = position.get(str(p.activated_after_record_id)), position.get(str(p.expires_after_record_id))
        if start is None or end is None:
            continue
        by_record = dict(zip(replay["record_id"].astype(str), replay["action"]))
        leaked = [r for r in ids[start + 1:end + 1] if source_of[r] == str(p.scope_value) and by_record.get(r) != BLOCK]
        if leaked:
            problems.append(f"{p.policy_id}: {len(leaked)} matching records were not blocked while it was active")
    return problems


def write_outputs(result: dict, out_dir: Path) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    names = load_config().get("level2", {}).get("columns", {})
    paths = {}
    for name in ("classification", "policy", "replay"):
        frame = result[name].rename(columns=names.get(name, {}))
        paths[name] = out_dir / f"{name}.csv"
        frame.to_csv(paths[name], index=False)
    logs = {"policies": result["policies"], "activation_and_expiry_log": result["log"], "correlation_groups": result["groups"]}
    paths["evidence"] = out_dir / "agent4_agent5_evidence.json"
    paths["evidence"].write_text(json.dumps(logs, indent=1, default=str))
    return paths
