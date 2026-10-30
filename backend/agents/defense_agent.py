"""Agent 5: adaptive defence through temporary, simulated SOURCE_IP BLOCK policies.

Nothing here touches a network. The order at each record is fixed by the brief:
  1. apply policies already active from earlier records (BLOCK, and the flow is not analysed);
  2. otherwise ALLOW, analyse the flow, and possibly activate a policy for LATER records only.
A flow can therefore never be blocked by a policy its own evidence created.

A policy lasts ttl_records replay records. A repeat offender's next policy lasts twice as long, up to
max_ttl_records. expires_after_record_id is filled in when the replay reaches that record, so no
future record is read to create a policy.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from backend.agents.fusion_agent import MULTI_SIGNAL_ATTACK
from backend.agents.temporal_agent import TemporalConfig, TemporalCorrelationAgent

ALLOW, BLOCK = "ALLOW", "BLOCK"
MISSING_ADDRESSES = {"", "nan", "none", "nat", "<na>"}


@dataclass
class DefenseConfig:
    min_confidence: float = 0.90  # Agent 1 confidence for a flow to count towards, or trigger, a policy.
    min_attack_flows_multi_signal: int = 3  # When the triggering flow also has Agent 2 support.
    min_attack_flows_classifier_only: int = 5  # Agent 2 barely sees brute force or port scans.
    min_attack_flows_converging: int = 2  # Source joins a many-to-one pattern already seen.
    min_attack_share: float = 0.60  # Protects shared sources that mostly send benign traffic.
    ttl_records: int = 2000
    max_ttl_records: int = 16000

    def to_dict(self) -> dict:
        return asdict(self)


class AdaptiveDefenseAgent:
    def __init__(self, config: DefenseConfig | None = None):
        self.config = config or DefenseConfig()
        self.policies: list[dict] = []
        self.log: list[dict] = []
        self._active: dict[str, dict] = {}
        self._activations: dict[str, int] = {}

    @property
    def active_count(self) -> int:
        return len(self._active)

    def apply_active(self, position: int, record_id: str, source: str) -> dict | None:
        """Step 1. The policy that blocks this record, if any. Lapsed policies were expired by advance()."""
        policy = self._active.get(source)
        if policy is not None:
            policy["blocked_records"] += 1
        return policy

    def advance(self, position: int, record_id: str) -> None:
        """Expire every policy whose last active record is this one, whichever source it belongs to."""
        for policy in [p for p in self._active.values() if p["_last_position"] <= position]:
            self._expire(policy, record_id, position)

    def _expire(self, policy: dict, record_id: str, position: int) -> None:
        policy["expires_after_record_id"] = record_id
        policy["status"] = "EXPIRED"
        self._active.pop(policy["scope_value"], None)
        self.log.append({"event": "EXPIRED", "policy_id": policy["policy_id"], "record_id": record_id,
                         "position": position, "scope_value": policy["scope_value"],
                         "blocked_records": policy["blocked_records"]})

    def consider(self, position: int, record_id: str, source: str, destination: str, predicted_class: str,
                 confidence: float, anomaly_score: float, evidence_status: str,
                 agent4: TemporalCorrelationAgent, group: dict | None) -> dict | None:
        """Step 2. Activate a policy for later records if the evidence so far justifies one."""
        cfg = self.config
        if group is None or predicted_class == "BENIGN" or confidence < cfg.min_confidence or source in self._active:
            return None
        evidence = agent4.source_evidence(source)
        converging = agent4.converging_group(destination)
        multi_signal = evidence_status == MULTI_SIGNAL_ATTACK
        required = (cfg.min_attack_flows_converging if converging
                    else cfg.min_attack_flows_multi_signal if multi_signal
                    else cfg.min_attack_flows_classifier_only)
        if evidence["confident_attack_flows"] < required or evidence["attack_share"] < cfg.min_attack_share:
            return None
        repeats = self._activations.get(source, 0)
        ttl = min(cfg.ttl_records * 2 ** repeats, cfg.max_ttl_records)
        self._activations[source] = repeats + 1
        policy = {
            "policy_id": f"POL-{len(self.policies) + 1:05d}",
            "activated_after_record_id": record_id,
            "scope_type": "SOURCE_IP",
            "scope_value": source,
            "expires_after_record_id": None,
            "policy_action": BLOCK,
            "status": "ACTIVE",
            "ttl_records": ttl,
            "blocked_records": 0,
            "group_id": group["group_id"],
            "converging_group_id": converging["group_id"] if converging else None,
            "rationale": self._rationale(predicted_class, confidence, anomaly_score, evidence_status, evidence,
                                         converging, ttl, repeats),
            "evidence": evidence,
            "_last_position": position + ttl,
        }
        self.policies.append(policy)
        self._active[source] = policy
        self.log.append({"event": "ACTIVATED", "policy_id": policy["policy_id"], "record_id": record_id,
                         "position": position, "scope_value": source, "ttl_records": ttl})
        return policy

    @staticmethod
    def _rationale(predicted_class, confidence, anomaly_score, status, evidence, converging, ttl, repeats) -> str:
        parts = [
            f"Triggering flow: Agent 1 {predicted_class} at {confidence:.3f}, Agent 2 score {anomaly_score:.3f}, "
            f"evidence status {status}.",
            f"Agent 4 saw {evidence['confident_attack_flows']} confident attack flows among "
            f"{evidence['flows_in_window']} analysed from this source in the last {evidence['window_records']} "
            f"records ({evidence['attack_share']:.0%}); pattern: {evidence['pattern']}.",
        ]
        if converging:
            parts.append(f"The destination is also in converging group {converging['group_id']}.")
        if repeats:
            parts.append(f"Policy number {repeats + 1} for this source, so it lasts longer.")
        parts.append(f"Blocks later flows from this source for {ttl} records.")
        return " ".join(parts)

    def finish(self, last_position: int, last_record_id: str) -> None:
        """End of replay: anything still active stops applying at the last record."""
        for policy in list(self._active.values()):
            self._expire(policy, last_record_id, last_position)

    def public_policies(self) -> list[dict]:
        return [{k: v for k, v in p.items() if not k.startswith("_")} for p in self.policies]


class DefenseLoop:
    """The fixed per-record order. The replay engine and the Level 2 export both run through this."""

    def __init__(self, temporal: TemporalConfig | None = None, defense: DefenseConfig | None = None):
        self.defense = AdaptiveDefenseAgent(defense)
        self.temporal = TemporalCorrelationAgent(temporal, self.defense.config.min_confidence)

    def step(self, position: int, record_id: str, source: str, destination: str, port: float | None,
             predicted_class: str, confidence: float, anomaly_score: float, is_anomaly: bool,
             evidence_status: str) -> dict:
        # A flow with no usable source cannot match a policy or be attributed. It must not become one big "source".
        known_source = source.strip().lower() not in MISSING_ADDRESSES
        blocking = self.defense.apply_active(position, record_id, source) if known_source else None
        activated = None
        if blocking is None and known_source:
            group = self.temporal.observe(position, record_id, source, destination, port, predicted_class,
                                          confidence, is_anomaly)
            activated = self.defense.consider(position, record_id, source, destination, predicted_class, confidence,
                                              anomaly_score, evidence_status, self.temporal, group)
        applied = blocking["policy_id"] if blocking else ""
        self.defense.advance(position, record_id)
        return {"action": BLOCK if blocking else ALLOW, "applied_policy_id": applied,
                "activated_policy": activated}

    def finish(self, last_position: int, last_record_id: str) -> None:
        self.defense.finish(last_position, last_record_id)
