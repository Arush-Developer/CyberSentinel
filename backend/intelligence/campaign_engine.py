"""Cross-flow campaign intelligence.

Works from flow behaviour only: it never reads ground-truth labels or Agent 1's output.
Two modes, chosen by the metadata actually present:

  endpoint  source_ip, destination_ip and an ordering column (timestamp or seq) exist.
            Full DDoS / DoS / port-scan / brute-force-pattern detection.
  cohort    only Destination Port and record order exist (the participant pack). Source attribution
            is impossible, so DoS and DDoS are reported together as VOLUMETRIC_CANDIDATE and
            distinct_sources is null. record_id order is a proxy, not verified chronology.

Every record separates what was observed from the hypothesis inferred from it. Brute-force records
are behavioural indicators: this dataset holds no authentication events.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import numpy as np
import pandas as pd

from backend.preprocessing.data_processor import replay_order

PORT = "Destination Port"
PACKET_RATE = "Flow Packets/s"
BYTE_RATE = "Flow Bytes/s"
FWD_PACKETS = "Total Fwd Packets"
DURATION = "Flow Duration"

DDOS = "DDOS_CANDIDATE"
DOS = "DOS_CANDIDATE"
VOLUMETRIC = "VOLUMETRIC_CANDIDATE"
SCAN = "PORT_SCAN_CANDIDATE"
BRUTE = "BRUTE_FORCE_CANDIDATE"

COMPATIBLE_CLASSES = {
    DDOS: {"DDOS", "DOS"}, DOS: {"DOS", "DDOS"}, VOLUMETRIC: {"DOS", "DDOS"},
    SCAN: {"PORT_SCAN"}, BRUTE: {"BRUTE_FORCE"},
}
MAX_RELATED_IDS = 500
MAX_RELATIONSHIPS = 20
HYPOTHESES = {
    DDOS: "Possible distributed denial of service against {target}.",
    DOS: "Possible denial of service against {target}.",
    VOLUMETRIC: "Possible denial-of-service traffic against {target}; DoS and DDoS cannot be separated here.",
    SCAN: "Possible port scan from {target}.",
    BRUTE: "Possible brute-force behaviour against {target}, from flow patterns only.",
}


@dataclass
class CampaignConfig:
    window_flows: int = 500
    window_seconds: float = 60.0
    ddos_min_sources: int = 10
    dos_max_sources: int = 3
    volume_min_flows: int = 30
    volume_min_anomaly_share: float = 0.30
    scan_min_ports: int = 20
    scan_max_fwd_packets: int = 3
    brute_min_flows: int = 5
    service_ports: tuple[int, ...] = (21, 22, 23, 25, 110, 143, 389, 445, 993, 995, 1433, 3306, 3389, 5900)
    # Learned without labels from windows of training flows; see fit_cohort_baseline.
    cohort_scan_ports: float | None = None
    cohort_brute_flows: float | None = None
    benign_packet_rate_median: float | None = None
    benign_packet_rate_p99: float | None = None

    @classmethod
    def load(cls, path) -> "CampaignConfig":
        return cls(**{**json.loads(path.read_text())}) if path.exists() else cls()


def fit_cohort_baseline(features: pd.DataFrame, order: np.ndarray, config: CampaignConfig) -> CampaignConfig:
    """Set cohort thresholds at median + 5*MAD of per-window behaviour over training windows.

    Unlabelled on purpose. Attack windows are in this population too, and the median/MAD are robust
    to them only while attacks are a minority of windows; the report records the resulting values.
    """
    port = features[PORT].to_numpy()[order]
    fwd = features[FWD_PACKETS].to_numpy()[order]
    size = config.window_flows
    diversity, service = [], []
    services = np.array(config.service_ports)
    for start in range(0, len(port) - size + 1, size):
        p, f = port[start:start + size], fwd[start:start + size]
        diversity.append(len(np.unique(p[f <= config.scan_max_fwd_packets])))
        service.append(int(np.isin(p, services).sum()))

    def robust_cut(values, floor):
        values = np.asarray(values, dtype=float)
        median = np.median(values)
        return float(max(median + 5 * np.median(np.abs(values - median)), floor))

    config.cohort_scan_ports = robust_cut(diversity, config.scan_min_ports)
    config.cohort_brute_flows = robust_cut(service, config.brute_min_flows)
    return config


@dataclass
class CampaignResult:
    mode: str
    limitations: list[str]
    campaigns: list[dict]
    flow_campaign: np.ndarray  # Campaign id per input row, or None.

    def signals(self, predicted: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """(campaign_support, campaign_conflict) given classes predicted independently of this engine."""
        types = {c["campaign_id"]: c["campaign_type"] for c in self.campaigns}
        support = np.zeros(len(predicted), bool)
        conflict = np.zeros(len(predicted), bool)
        for i, cid in enumerate(self.flow_campaign):
            if cid is None:
                continue
            allowed = COMPATIBLE_CLASSES[types[cid]]
            if predicted[i] == "BENIGN" or predicted[i] in allowed:
                support[i] = True
            else:
                conflict[i] = True
        return support, conflict


def detect_mode(metadata: pd.DataFrame, features: pd.DataFrame) -> tuple[str, list[str]]:
    has_endpoints = {"source_ip", "destination_ip"} <= set(metadata.columns)
    has_order = bool({"timestamp", "seq"} & set(metadata.columns))
    if has_endpoints and has_order:
        return "endpoint", []
    if PORT in features.columns and "flow_id" in metadata.columns:
        return "cohort", [
            "source and destination addresses are absent from this partition, so source diversity, "
            "destination concentration and host counts cannot be measured",
            "DoS and DDoS cannot be separated without source addresses; both report as VOLUMETRIC_CANDIDATE",
            "record order stands in for time and is not verified chronology",
        ]
    return "disabled", ["neither endpoint metadata nor Destination Port is available"]


def _window_ids(metadata: pd.DataFrame, order: np.ndarray, config: CampaignConfig) -> np.ndarray:
    if "timestamp" in metadata:
        ts = pd.to_datetime(metadata["timestamp"], errors="coerce").to_numpy()[order]
        seconds = (ts - ts[0]) / np.timedelta64(1, "s")
        return (seconds // config.window_seconds).astype(np.int64)
    return np.arange(len(order)) // config.window_flows


def _intensity(rate: float, config: CampaignConfig) -> str:
    if config.benign_packet_rate_median is None:
        return "unrated: no benign baseline loaded"
    if rate >= (config.benign_packet_rate_p99 or np.inf):
        return f"high: median {rate:.1f} packets/s, above benign p99"
    if rate > config.benign_packet_rate_median:
        return f"elevated: median {rate:.1f} packets/s, above benign median"
    return f"normal: median {rate:.1f} packets/s"


class CampaignTracker:
    """Builds campaigns window by window. Adjacent windows with the same type and target merge."""

    def __init__(self, mode: str, config: CampaignConfig):
        self.mode = mode
        self.config = config
        self.campaigns: list[dict] = []
        self._open: dict[tuple, dict] = {}
        self._counter = 0

    def _relationships(self, rows: pd.DataFrame) -> list[dict]:
        if self.mode == "endpoint":
            grouped = rows.groupby(["source_ip", "destination_ip", "destination_port"]).size()
            return [{"source": str(s), "destination": str(d), "destination_port": float(p), "flows": int(n)}
                    for (s, d, p), n in grouped.items()]
        return [{"source": None, "destination": None, "destination_port": float(p), "flows": int(n)}
                for p, n in rows[PORT].value_counts().items()]

    def _merge_observations(self, record: dict, rows: pd.DataFrame, rate: float) -> None:
        """Keep running totals, then restate what the measurements say against this hypothesis."""
        record["_anomalous_flows"] += int(rows["_anomalous"].sum())
        for rel in self._relationships(rows):
            key = f"{rel['source']}|{rel['destination']}|{rel['destination_port']}"
            known = record["_relationships"].setdefault(key, {**rel, "flows": 0})
            known["flows"] += rel["flows"]
        contradicting = []
        share = record["_anomalous_flows"] / record["flow_count"]
        if share < 0.5:
            contradicting.append(f"Only {share:.1%} of member flows were flagged anomalous by Agent 2.")
        benign_rate = self.config.benign_packet_rate_median
        if benign_rate is not None and rate <= benign_rate and record["campaign_type"] in (DDOS, DOS, VOLUMETRIC):
            contradicting.append(f"Median rate of {rate:.1f} packets/s in the latest window is not above "
                                 f"the benign median of {benign_rate:.1f}.")
        if record["windows_observed"] == 1:
            contradicting.append("Seen in a single window, so it may be a chance concentration.")
        record["contradicting_evidence"] = contradicting

    def _emit(self, window: int, ctype: str, target: str, flow_ids: np.ndarray, rows: pd.DataFrame,
              observed: dict, basis: str, distinct_sources: int | None, target_count: int | None) -> dict:
        key = (ctype, target)
        rate = float(rows[PACKET_RATE].median())
        anomaly_share = float(rows["_anomalous"].mean())
        evidence = {
            "window": int(window), "flows": len(rows), "median_packets_per_second": rate,
            "median_bytes_per_second": float(rows[BYTE_RATE].median()),
            "anomalous_flow_share": round(anomaly_share, 4), **observed,
        }
        current = self._open.get(key)
        if current is not None and window - current["_last_window"] <= 1:
            current["_last_window"] = window
            current["flow_count"] += len(rows)
            current["last_observed"] = str(flow_ids[-1])
            room = MAX_RELATED_IDS - len(current["related_flow_ids"])
            current["related_flow_ids"].extend(map(str, flow_ids[:max(room, 0)]))
            current["windows_observed"] += 1
            if len(current["supporting_evidence"]) < 5:
                current["supporting_evidence"].append(evidence)
            if distinct_sources is not None:
                current["distinct_sources"] = max(current["distinct_sources"] or 0, distinct_sources)
            current["traffic_intensity"] = _intensity(rate, self.config)
            self._set_confidence(current)
            self._merge_observations(current, rows, rate)
            return current
        self._counter += 1
        record = {
            "campaign_id": f"CMP-{self._counter:05d}",
            "campaign_type": ctype,
            "hypothesis": HYPOTHESES[ctype].format(target=target),
            "detection_mode": self.mode,
            "target": target,
            "first_observed": str(flow_ids[0]),
            "last_observed": str(flow_ids[-1]),
            "related_flow_ids": list(map(str, flow_ids[:MAX_RELATED_IDS])),
            "flow_count": len(rows),
            "distinct_sources": distinct_sources,
            "target_count": target_count,
            "traffic_intensity": _intensity(rate, self.config),
            "supporting_evidence": [evidence],
            "confidence_basis": basis,
            "windows_observed": 1,
            "contradicting_evidence": [],
            "_last_window": window,
            "_anomalous_flows": 0,
            "_relationships": {},
        }
        self._set_confidence(record)
        self._merge_observations(record, rows, rate)
        self._open[key] = record
        self.campaigns.append(record)
        return record

    @staticmethod
    def _set_confidence(record: dict) -> None:
        windows = record["windows_observed"]
        record["confidence"] = "medium" if windows >= 3 else "low"
        record["uncertainty"] = (
            "Hypothesis from flow behaviour, not a confirmed attack. "
            f"Seen in {windows} window(s); no single window proves coordination.")

    def process_window(self, window: int, rows: pd.DataFrame) -> list[tuple[np.ndarray, str]]:
        """Return (row positions, campaign_id) for this window. rows needs a _pos column."""
        if self.mode == "endpoint":
            return self._endpoint_window(window, rows)
        if self.mode == "cohort":
            return self._cohort_window(window, rows)
        return []

    def _add(self, out, window, ctype, target, members, observed, basis, sources=None, targets=None):
        record = self._emit(window, ctype, target, members["flow_id"].to_numpy(), members, observed,
                            basis, sources, targets)
        out.append((members["_pos"].to_numpy(), record["campaign_id"]))

    def _cohort_window(self, window: int, rows: pd.DataFrame):
        cfg = self.config
        out: list = []
        counts = rows[PORT].map(rows[PORT].value_counts())
        small = rows[FWD_PACKETS] <= cfg.scan_max_fwd_packets
        diversity = rows.loc[small, PORT].nunique()
        scan_cut = cfg.cohort_scan_ports or cfg.scan_min_ports
        if diversity >= scan_cut:
            members = rows[small & (counts <= 3)]
            if len(members) >= cfg.scan_min_ports:
                self._add(out, window, SCAN, "unattributed", members,
                          {"distinct_ports_in_small_flows": int(diversity), "threshold": scan_cut},
                          "Many distinct destination ports among small flows in one window, above the "
                          "unsupervised training baseline. Source cannot be attributed.")
        for port, group in rows.groupby(PORT):
            share = float(group["_anomalous"].mean())
            if port in cfg.service_ports:
                brute_cut = cfg.cohort_brute_flows or cfg.brute_min_flows
                if len(group) >= brute_cut:
                    self._add(out, window, BRUTE, f"port {int(port)}", group,
                              {"flows_to_service_port": len(group), "threshold": brute_cut},
                              "Repeated flows to one login-capable service port in a window. A behavioural "
                              "indicator only: the data has no authentication events.")
            elif len(group) >= cfg.volume_min_flows and share >= cfg.volume_min_anomaly_share:
                self._add(out, window, VOLUMETRIC, f"port {int(port)}", group,
                          {"flows_to_port": len(group), "share_of_window": round(len(group) / len(rows), 4)},
                          "Concentrated flows to one port with an unusually high anomalous share. "
                          "DoS and DDoS cannot be separated without source addresses.")
        return out

    def _endpoint_window(self, window: int, rows: pd.DataFrame):
        cfg = self.config
        out: list = []
        claimed = np.zeros(len(rows), bool)
        positions = {p: i for i, p in enumerate(rows["_pos"])}

        def take(members):
            for p in members["_pos"]:
                claimed[positions[p]] = True

        for src, group in rows.groupby("source_ip"):
            ports = group["destination_port"].nunique()
            small = group[FWD_PACKETS].median() <= cfg.scan_max_fwd_packets
            if ports >= cfg.scan_min_ports and small:
                hosts = group["destination_ip"].nunique()
                self._add(out, window, SCAN, f"source {src}", group,
                          {"distinct_destination_ports": int(ports), "destination_hosts": int(hosts)},
                          "One source touching many destination ports with small flows in one window.",
                          1, int(hosts))
                take(group)
        for (src, dst, port), group in rows[~claimed].groupby(["source_ip", "destination_ip", "destination_port"]):
            if int(port) in cfg.service_ports and len(group) >= cfg.brute_min_flows:
                self._add(out, window, BRUTE, f"{dst}:{int(port)}", group,
                          {"repeat_flows": len(group), "source": str(src)},
                          "Repeated flows from one source to one login-capable service. A behavioural "
                          "indicator only: the data has no authentication events.", 1, 1)
                take(group)
        for dst, group in rows[~claimed].groupby("destination_ip"):
            if len(group) < cfg.volume_min_flows or group["_anomalous"].mean() < cfg.volume_min_anomaly_share:
                continue
            sources = group["source_ip"].nunique()
            if sources >= cfg.ddos_min_sources:
                ctype, basis = DDOS, "Many distinct sources converging on one destination at high anomalous share."
            elif sources <= cfg.dos_max_sources:
                ctype, basis = DOS, "Few sources sending concentrated traffic to one destination at high anomalous share."
            else:
                continue
            self._add(out, window, ctype, f"destination {dst}", group,
                      {"distinct_sources": int(sources), "flows_to_destination": len(group)}, basis, int(sources), 1)
        return out

    def public_campaigns(self) -> list[dict]:
        return [{
            **{k: v for k, v in c.items() if not k.startswith("_")},
            "relationships": sorted(c["_relationships"].values(), key=lambda r: -r["flows"])[:MAX_RELATIONSHIPS],
        } for c in self.campaigns]


class CampaignEngine:
    def __init__(self, config: CampaignConfig | None = None):
        self.config = config or CampaignConfig()

    def detect(self, metadata: pd.DataFrame, features: pd.DataFrame, is_anomaly: np.ndarray) -> CampaignResult:
        mode, limitations = detect_mode(metadata, features)
        flow_campaign = np.full(len(metadata), None, dtype=object)
        if mode == "disabled" or len(metadata) == 0:
            return CampaignResult(mode, limitations, [], flow_campaign)
        order = replay_order(metadata)
        windows = _window_ids(metadata, order, self.config)
        tracker = CampaignTracker(mode, self.config)
        frame = self.prepare(metadata, features, is_anomaly).iloc[order]
        frame["_window"] = windows
        for window, rows in frame.groupby("_window", sort=True):
            for positions, cid in tracker.process_window(int(window), rows):
                flow_campaign[positions] = cid
        return CampaignResult(mode, limitations, tracker.public_campaigns(), flow_campaign)

    @staticmethod
    def prepare(metadata: pd.DataFrame, features: pd.DataFrame, is_anomaly: np.ndarray) -> pd.DataFrame:
        columns = [PORT, PACKET_RATE, BYTE_RATE, FWD_PACKETS, DURATION]
        frame = features[columns].reset_index(drop=True).copy()
        for col in metadata.columns:
            frame[col] = metadata[col].to_numpy()
        frame["_anomalous"] = is_anomaly
        frame["_pos"] = np.arange(len(frame))
        return frame
