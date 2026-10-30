"""Investigation tools. Each reads real evidence from an EvidenceStore and cites what it measured.

Result shape: {"available", "summary", "supports": attack|benign|neutral, "evidence": {...}}.
A tool whose required metadata is absent returns available=False and says why; it never guesses.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from backend.agents.anomaly_agent import AnomalyAgent
from backend.intelligence.feature_explainer import MIN_EVIDENCE_Z

SUPPORTS_ATTACK, SUPPORTS_BENIGN, NEUTRAL = "attack", "benign", "neutral"


@dataclass
class EvidenceStore:
    """Read-only evidence for one batch of processed flows."""

    flow_ids: np.ndarray
    features: pd.DataFrame
    metadata: pd.DataFrame
    threat_class: np.ndarray
    threat_confidence: np.ndarray
    anomaly_score: np.ndarray
    is_anomaly: np.ndarray
    flow_campaign: np.ndarray
    campaigns: dict
    anomaly_agent: AnomalyAgent

    def __post_init__(self) -> None:
        self.index = {str(fid): i for i, fid in enumerate(self.flow_ids)}
        numeric = self.metadata["flow_id"].astype(str).str.extract(r"(\d+)")[0]
        self.order_key = pd.to_numeric(numeric, errors="coerce").to_numpy()
        self.sorted_rows = np.argsort(self.order_key, kind="stable")
        self.rank_of = np.empty(len(self.sorted_rows), dtype=np.int64)
        self.rank_of[self.sorted_rows] = np.arange(len(self.sorted_rows))
        self._X = None
        self._z = None

    @property
    def X(self) -> np.ndarray:
        if self._X is None:
            self._X = self.anomaly_agent.pipeline.transform(self.features)
        return self._X

    @property
    def z(self) -> np.ndarray:
        if self._z is None:
            self._z = self.anomaly_agent.baseline.z(self.X)
        return self._z

    def row(self, flow_id: str) -> int:
        if str(flow_id) not in self.index:
            raise KeyError(f"unknown flow_id {flow_id}")
        return self.index[str(flow_id)]

    def neighbours(self, row: int, window: int) -> np.ndarray:
        rank = self.rank_of[row]
        start, stop = max(rank - window, 0), rank + window + 1
        return self.sorted_rows[start:stop]

    def has(self, *columns: str) -> bool:
        return set(columns) <= set(self.metadata.columns)


def _unavailable(reason: str) -> dict:
    return {"available": False, "summary": reason, "supports": NEUTRAL, "evidence": {}}


def inspect_feature_deviations(store: EvidenceStore, flow_id: str) -> dict:
    row = store.row(flow_id)
    z = store.z[row]
    base = store.anomaly_agent.baseline
    values = store.X[row]
    order = np.argsort(-np.abs(z))[:6]
    extreme = [{
        "flow_id": str(flow_id), "feature": base.columns[j], "measured_value": float(values[j]),
        "benign_median": float(base.median[j]), "robust_z": round(float(z[j]), 2),
    } for j in order if abs(z[j]) >= MIN_EVIDENCE_Z]
    return {
        "available": True,
        "summary": (f"{len(extreme)} of the top features deviate beyond |z|>={MIN_EVIDENCE_Z} from the benign baseline."
                    if extreme else f"No feature deviates beyond |z|>={MIN_EVIDENCE_Z} from the benign baseline."),
        "supports": SUPPORTS_ATTACK if len(extreme) >= 3 else SUPPORTS_BENIGN if not extreme else NEUTRAL,
        "evidence": {"deviations": extreme},
    }


def compare_against_benign_baseline(store: EvidenceStore, flow_id: str) -> dict:
    row = store.row(flow_id)
    base = store.anomaly_agent.baseline
    values = store.X[row]
    outside = (values < base.p01) | (values > base.p99)
    share = float(outside.mean())
    names = [base.columns[j] for j in np.flatnonzero(outside)[:8]]
    return {
        "available": True,
        "summary": f"{int(outside.sum())} of {len(values)} features fall outside the benign 1st-99th percentile range.",
        "supports": SUPPORTS_ATTACK if share >= 0.15 else SUPPORTS_BENIGN if share <= 0.03 else NEUTRAL,
        "evidence": {"flow_id": str(flow_id), "share_outside": round(share, 4), "features_outside": names},
    }


def find_related_flows(store: EvidenceStore, flow_id: str, time_window: int = 100) -> dict:
    """Flows near this one in record order that share its destination port."""
    row = store.row(flow_id)
    near = store.neighbours(row, time_window)
    port = store.metadata["destination_port"].to_numpy() if "destination_port" in store.metadata else None
    if port is None:
        return _unavailable("Destination port is not available for this partition.")
    same = near[(port[near] == port[row]) & (near != row)]
    predicted = pd.Series(store.threat_class[same]).value_counts().to_dict()
    anomalous = float(store.is_anomaly[same].mean()) if len(same) else 0.0
    attack_share = float((store.threat_class[same] != "BENIGN").mean()) if len(same) else 0.0
    return {
        "available": True,
        "summary": (f"{len(same)} flows within {time_window} records share destination port "
                    f"{port[row]:g}; {attack_share:.0%} predicted attack, {anomalous:.0%} flagged anomalous."),
        "supports": SUPPORTS_ATTACK if len(same) >= 10 and attack_share >= 0.5
        else SUPPORTS_BENIGN if len(same) >= 10 and attack_share <= 0.05 else NEUTRAL,
        "evidence": {"related_flow_ids": [str(store.flow_ids[i]) for i in same[:25]],
                     "predicted_classes": {str(k): int(v) for k, v in predicted.items()},
                     "anomalous_share": round(anomalous, 4)},
    }


def _activity(store: EvidenceStore, column: str, value: str, time_window: int, anchor: int | None) -> dict:
    meta = store.metadata[column].astype(str).to_numpy()
    candidates = np.flatnonzero(meta == str(value))
    if anchor is not None:
        rank = store.rank_of
        candidates = candidates[np.abs(rank[candidates] - rank[anchor]) <= time_window]
    return {"rows": candidates, "flows": len(candidates)}


def inspect_source_activity(store: EvidenceStore, source_ip: str | None = None, time_window: int = 500,
                            flow_id: str | None = None) -> dict:
    if not store.has("source_ip"):
        return _unavailable("source_ip is absent from this partition, so source activity cannot be measured.")
    anchor = store.row(flow_id) if flow_id else None
    source_ip = source_ip or str(store.metadata["source_ip"].iloc[anchor])
    rows = _activity(store, "source_ip", source_ip, time_window, anchor)["rows"]
    attack = float((store.threat_class[rows] != "BENIGN").mean()) if len(rows) else 0.0
    return {
        "available": True,
        "summary": f"Source {source_ip} produced {len(rows)} flows in the window; {attack:.0%} predicted attack.",
        "supports": SUPPORTS_ATTACK if len(rows) >= 10 and attack >= 0.5 else NEUTRAL,
        "evidence": {"source_ip": source_ip, "flow_ids": [str(store.flow_ids[i]) for i in rows[:25]],
                     "distinct_destinations": int(store.metadata["destination_ip"].iloc[rows].nunique())
                     if store.has("destination_ip") else None},
    }


def inspect_destination_activity(store: EvidenceStore, destination_ip: str | None = None, time_window: int = 500,
                                 flow_id: str | None = None) -> dict:
    if not store.has("destination_ip"):
        return _unavailable("destination_ip is absent from this partition, so destination activity cannot be measured.")
    anchor = store.row(flow_id) if flow_id else None
    destination_ip = destination_ip or str(store.metadata["destination_ip"].iloc[anchor])
    rows = _activity(store, "destination_ip", destination_ip, time_window, anchor)["rows"]
    sources = int(store.metadata["source_ip"].iloc[rows].nunique()) if store.has("source_ip") else None
    return {
        "available": True,
        "summary": f"Destination {destination_ip} received {len(rows)} flows from {sources} sources in the window.",
        "supports": SUPPORTS_ATTACK if len(rows) >= 30 and float(store.is_anomaly[rows].mean()) >= 0.3 else NEUTRAL,
        "evidence": {"destination_ip": destination_ip, "distinct_sources": sources,
                     "flow_ids": [str(store.flow_ids[i]) for i in rows[:25]]},
    }


def inspect_port_distribution(store: EvidenceStore, source_ip: str | None = None, time_window: int = 500,
                              flow_id: str | None = None) -> dict:
    """Per-source when addresses exist; otherwise window-wide, stated as such."""
    if "destination_port" not in store.metadata:
        return _unavailable("Destination port is not available for this partition.")
    anchor = store.row(flow_id) if flow_id else None
    port = store.metadata["destination_port"].to_numpy()
    if store.has("source_ip") and (source_ip or anchor is not None):
        source_ip = source_ip or str(store.metadata["source_ip"].iloc[anchor])
        rows = _activity(store, "source_ip", source_ip, time_window, anchor)["rows"]
        scope = f"source {source_ip}"
    elif anchor is not None:
        rows = store.neighbours(anchor, time_window)
        scope = "nearby records, no source attribution available"
    else:
        return _unavailable("source_ip is absent and no flow was given to anchor a window.")
    counts = pd.Series(port[rows]).value_counts()
    return {
        "available": True,
        "summary": f"{counts.size} distinct destination ports across {len(rows)} flows ({scope}).",
        "supports": SUPPORTS_ATTACK if counts.size >= 50 else NEUTRAL,
        "evidence": {"scope": scope, "distinct_ports": int(counts.size),
                     "top_ports": {f"{k:g}": int(v) for k, v in counts.head(8).items()}},
    }


def inspect_campaign_context(store: EvidenceStore, flow_id: str) -> dict:
    cid = store.flow_campaign[store.row(flow_id)]
    if cid is None:
        return {"available": True, "summary": "This flow belongs to no campaign hypothesis.",
                "supports": NEUTRAL, "evidence": {"campaign_id": None}}
    campaign = store.campaigns[cid]
    return {
        "available": True,
        "summary": f"Flow is part of {cid}, a {campaign['campaign_type']} hypothesis with "
                   f"{campaign['flow_count']} flows ({campaign['confidence']} confidence).",
        "supports": SUPPORTS_ATTACK,
        "evidence": {"campaign_id": cid, "campaign_type": campaign["campaign_type"],
                     "flow_count": campaign["flow_count"], "basis": campaign["confidence_basis"]},
    }


def inspect_agent_disagreement(store: EvidenceStore, flow_id: str) -> dict:
    row = store.row(flow_id)
    predicted = str(store.threat_class[row])
    flagged = bool(store.is_anomaly[row])
    disagree = (predicted != "BENIGN") != flagged
    return {
        "available": True,
        "summary": (f"Agent 1 says {predicted} ({store.threat_confidence[row]:.3f}); Agent 2 score "
                    f"{store.anomaly_score[row]:.3f} ({'flagged' if flagged else 'not flagged'}). "
                    + ("They disagree." if disagree else "They agree.")),
        "supports": NEUTRAL,
        "evidence": {"flow_id": str(flow_id), "threat_class": predicted,
                     "threat_confidence": float(store.threat_confidence[row]),
                     "anomaly_score": float(store.anomaly_score[row]), "disagree": disagree},
    }
