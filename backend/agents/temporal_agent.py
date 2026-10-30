"""Agent 4: temporal correlation of suspicious flows, from observed endpoints and a sliding window.

Strictly causal: observe() is called once per analysed flow in replay order, and a group only ever
holds flows already seen. It reads Agents 1-3 output and endpoints, never labels or later records.
Windows are counted in replay records because the participant pack promises `seq`, not timestamps.
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field

BENIGN = "BENIGN"
SOURCE, DESTINATION = "SOURCE_IP", "DESTINATION_IP"


@dataclass
class TemporalConfig:
    window_records: int = 2000
    scan_min_ports: int = 20
    converging_min_sources: int = 10
    max_member_ids: int = 5000


@dataclass
class _Observation:
    position: int
    record_id: str
    source: str
    destination: str
    port: float | None
    predicted_class: str
    is_anomaly: bool
    confident_attack: bool


@dataclass
class _Window:
    """Running totals over the observations of one endpoint still inside the window."""

    items: deque = field(default_factory=deque)
    attack_flows: int = 0
    anomalous: int = 0
    classes: Counter = field(default_factory=Counter)
    sources: Counter = field(default_factory=Counter)
    destinations: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)

    def add(self, o: _Observation) -> None:
        self.items.append(o)
        self._apply(o, 1)

    def evict(self, oldest_position: int) -> None:
        while self.items and self.items[0].position < oldest_position:
            self._apply(self.items.popleft(), -1)

    def _apply(self, o: _Observation, sign: int) -> None:
        self.attack_flows += sign * o.confident_attack
        self.anomalous += sign * o.is_anomaly
        if o.confident_attack:
            self.classes[o.predicted_class] += sign
            self.sources[o.source] += sign
        for counter, key in ((self.destinations, o.destination), (self.ports, o.port)):
            counter[key] += sign
            if counter[key] <= 0:
                del counter[key]

    @property
    def flows(self) -> int:
        return len(self.items)


class TemporalCorrelationAgent:
    def __init__(self, config: TemporalConfig | None = None, min_attack_confidence: float = 0.9):
        self.config = config or TemporalConfig()
        self.min_attack_confidence = min_attack_confidence
        self.groups: list[dict] = []
        self._open: dict[tuple[str, str], dict] = {}
        self._windows: dict[tuple[str, str], _Window] = {}

    def observe(self, position: int, record_id: str, source: str, destination: str, port: float | None,
                predicted_class: str, confidence: float, is_anomaly: bool) -> dict | None:
        """Record one analysed flow. Returns the source's current group, or None if not suspicious."""
        attack = predicted_class != BENIGN
        observation = _Observation(position, record_id, source, destination, port, predicted_class, is_anomaly,
                                   attack and confidence >= self.min_attack_confidence)
        oldest = position - self.config.window_records + 1
        by_source = self._window(SOURCE, source, oldest)
        by_destination = self._window(DESTINATION, destination, oldest)
        by_source.add(observation)
        by_destination.add(observation)
        if not (attack or is_anomaly):
            return None
        group = self._touch(SOURCE, source, by_source, observation)
        # A destination only becomes a group once several sources converge on it with attack calls.
        if len(by_destination.sources) >= self.config.converging_min_sources:
            self._touch(DESTINATION, destination, by_destination, observation)
        return group

    def source_evidence(self, source: str) -> dict:
        return self._evidence(self._windows[(SOURCE, source)])

    def converging_group(self, destination: str) -> dict | None:
        """The destination's group, if it still has enough attacking sources inside the window."""
        window = self._windows.get((DESTINATION, destination))
        if window is None or len(window.sources) < self.config.converging_min_sources:
            return None
        return self._open.get((DESTINATION, destination))

    def _window(self, scope: str, value: str, oldest: int) -> _Window:
        window = self._windows.setdefault((scope, value), _Window())
        window.evict(oldest)
        return window

    def _touch(self, scope: str, value: str, window: _Window, o: _Observation) -> dict:
        key = (scope, value)
        group = self._open.get(key)
        # A gap longer than the window means this is a new episode, not a continuation.
        if group is None or o.position - group["_last_position"] >= self.config.window_records:
            group = {
                "group_id": f"GRP-{len(self.groups) + 1:05d}", "scope_type": scope, "scope_value": value,
                "first_record_id": o.record_id, "member_record_ids": [], "member_count": 0,
            }
            self.groups.append(group)
            self._open[key] = group
        group["_last_position"] = o.position
        group["last_record_id"] = o.record_id
        group["member_count"] += 1
        if len(group["member_record_ids"]) < self.config.max_member_ids:
            group["member_record_ids"].append(o.record_id)
        group["evidence"] = self._evidence(window)
        return group

    def _evidence(self, window: _Window) -> dict:
        dominant = window.classes.most_common(1)[0][0] if +window.classes else None
        share = window.attack_flows / window.flows if window.flows else 0.0
        return {
            "window_records": self.config.window_records,
            "flows_in_window": window.flows,
            "confident_attack_flows": window.attack_flows,
            "attack_share": round(share, 4),
            "anomalous_flows": window.anomalous,
            "dominant_predicted_class": dominant,
            "distinct_destinations": len(window.destinations),
            "distinct_destination_ports": len(window.ports),
            "distinct_attacking_sources": len(+window.sources),
            "pattern": self._pattern(window, dominant),
        }

    def _pattern(self, window: _Window, dominant: str | None) -> str:
        if len(+window.sources) >= self.config.converging_min_sources:
            return "many sources converging on one destination"
        if len(window.ports) >= self.config.scan_min_ports:
            return "one source touching many destination ports"
        if dominant is None:
            return "unusual flows with no attack call from the classifier"
        if len(window.ports) == 1:
            return "repeated flows to one service port"
        return "repeated suspicious flows from one source"

    def public_groups(self, member_limit: int | None = None) -> list[dict]:
        out = []
        for group in self.groups:
            item = {k: v for k, v in group.items() if not k.startswith("_")}
            if member_limit is not None:
                item["member_record_ids"] = group["member_record_ids"][:member_limit]
            out.append(item)
        return out
