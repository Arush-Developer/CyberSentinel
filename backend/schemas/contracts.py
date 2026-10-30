"""Authoritative request and response schemas. Matching TypeScript lives in frontend/src/services/types.ts.

tests/api/test_contract_sync.py fails if the agent-output fields here and there drift apart.
Explained in docs/MODULE_CONTRACTS.md.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Decision = Literal["ALLOW", "BLOCK", "REVIEW"]


# ---- Agent and engine outputs ---------------------------------------------------------------

class ThreatAssessment(BaseModel):
    """Agent 1."""

    agent: Literal["threat_detection"] = "threat_detection"
    flow_id: str
    predicted_class: str
    confidence: float
    probabilities: dict[str, float]
    model_version: str
    calibration_status: str


class SupportingFeature(BaseModel):
    feature: str
    deviation: Literal["high", "low"]
    measured_value: float
    benign_median: float
    benign_mad: float
    robust_z: float


class AnomalyAssessment(BaseModel):
    """Agent 2. anomaly_score is a percentile among benign calibration flows, not a probability."""

    agent: Literal["anomaly_detection"] = "anomaly_detection"
    flow_id: str
    anomaly_score: float
    score_meaning: str
    is_anomaly: bool
    threshold: float
    supporting_features: list[SupportingFeature]
    baseline_reference: str
    model_version: str


class CampaignRelationship(BaseModel):
    """source and destination are null when the partition has no endpoint addresses."""

    source: str | None
    destination: str | None
    destination_port: float | None
    flows: int


class CampaignRecord(BaseModel):
    campaign_id: str
    campaign_type: str
    hypothesis: str
    detection_mode: str
    target: str
    first_observed: str
    last_observed: str
    related_flow_ids: list[str]
    related_flow_ids_total: int | None = None
    flow_count: int
    distinct_sources: int | None
    target_count: int | None
    relationships: list[CampaignRelationship]
    traffic_intensity: str
    supporting_evidence: list[dict]
    contradicting_evidence: list[str]
    confidence_basis: str
    confidence: str
    uncertainty: str
    windows_observed: int


class ToolResult(BaseModel):
    available: bool
    summary: str
    supports: Literal["attack", "benign", "neutral"]
    evidence: dict


class ToolCall(BaseModel):
    tool: str
    arguments: dict
    status: Literal["ok", "timeout", "error"]
    duration_ms: float
    result: ToolResult


class InvestigationResult(BaseModel):
    investigation_id: str
    flow_id: str
    triggers: list[str]
    tools_selected: list[str]
    tool_calls: list[ToolCall]
    supporting_observations: list[str]
    contradicting_observations: list[str]
    neutral_observations: list[str]
    unavailable_evidence: list[str]
    status: Literal["COMPLETED"]
    verdict: Literal["SUPPORTS_ATTACK", "SUPPORTS_BENIGN", "CONFLICTING", "INCONCLUSIVE"]
    planner: str


class FusionAssessment(BaseModel):
    """Agent 3."""

    agent: Literal["evidence_fusion"] = "evidence_fusion"
    flow_id: str
    final_class: str
    final_class_source: str
    evidence_status: str
    agreement: Literal["AGREE", "DISAGREE"]
    low_confidence: bool
    confidence_status: Literal["CONFIDENT", "LOW_CONFIDENCE"]
    evidence_refs: list[str]
    investigation_refs: list[str]
    rationale: str


class PolicyOutcome(BaseModel):
    decision: Decision
    policy_rule: str
    decision_reason: str
    evidence_refs: list[str]
    simulated: Literal[True] = True


class GraphNode(BaseModel):
    id: str
    kind: str
    label: str
    data: dict


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: str


class EvidenceGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class CorrelationEvidence(BaseModel):
    window_records: int
    flows_in_window: int
    confident_attack_flows: int
    attack_share: float
    anomalous_flows: int
    dominant_predicted_class: str | None
    distinct_destinations: int
    distinct_destination_ports: int
    distinct_attacking_sources: int
    pattern: str


class CorrelationGroup(BaseModel):
    """Agent 4."""

    group_id: str
    scope_type: Literal["SOURCE_IP", "DESTINATION_IP"]
    scope_value: str
    first_record_id: str
    last_record_id: str
    member_record_ids: list[str]
    member_count: int
    evidence: CorrelationEvidence


class DefensePolicy(BaseModel):
    """Agent 5. A simulated, temporary policy that applies only to later records."""

    policy_id: str
    activated_after_record_id: str
    scope_type: Literal["SOURCE_IP"]
    scope_value: str
    expires_after_record_id: str | None
    policy_action: Literal["BLOCK"]
    status: Literal["ACTIVE", "EXPIRED"]
    ttl_records: int
    blocked_records: int
    group_id: str
    converging_group_id: str | None
    rationale: str
    evidence: CorrelationEvidence


class DefenseState(BaseModel):
    available: bool
    unavailable_reason: str | None
    config: dict
    policies: list[DefensePolicy]
    log: list[dict]
    groups: list[CorrelationGroup]
    groups_total: int


class FlowDefense(BaseModel):
    """What the last replay did with this flow."""

    action: Literal["ALLOW", "BLOCK"] | None
    applied_policy_id: str | None
    replay_decision: Decision
    replay_evidence_status: str


class FlowDetail(BaseModel):
    flow_id: str
    network: dict
    unavailable_metadata: list[str]
    threat: ThreatAssessment
    anomaly: AnomalyAssessment
    fusion: FusionAssessment
    policy: PolicyOutcome
    campaign: CampaignRecord | None
    triggers: list[str]
    investigation: InvestigationResult | None
    replay: FlowDefense | None
    ground_truth_evaluation_only: str | None
    evidence_graph: EvidenceGraph


# ---- Requests ---------------------------------------------------------------------------------

class Thresholds(BaseModel):
    allow_benign_confidence: float = Field(ge=0, le=1)
    block_multi_signal_confidence: float = Field(ge=0, le=1)
    block_classifier_only_confidence: float = Field(ge=0, le=1)


class PolicyConfigureRequest(BaseModel):
    thresholds: Thresholds
    reason: str = Field(default="", max_length=500)


class PolicySimulateRequest(BaseModel):
    thresholds: Thresholds
    max_examples: int = Field(default=50, ge=0, le=500)


class ReplayStartRequest(BaseModel):
    speed: float = Field(default=500.0, gt=0, le=100_000, description="Flows per second")
    batch_size: int = Field(default=500, ge=10, le=5000)
    limit: int | None = Field(default=None, ge=1)
    resume_saved: bool = False
    max_investigations_per_batch: int = Field(default=5, ge=0, le=100)


class AnalyseFlowRequest(BaseModel):
    features: dict[str, float]


# ---- Status responses -------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: Literal["ok", "loading", "unavailable"]
    detail: str | None = None
    simulated_defence_only: bool = True


class ModelStatusResponse(BaseModel):
    threat_model: str
    threat_calibration: str
    threat_features: int
    anomaly_model: str
    anomaly_detector: str
    anomaly_threshold: float
    anomaly_features: int
    campaign_mode: str
    campaign_limitations: list[str]
    defense_available: bool
    replay_input: str
    llm_in_use: bool = False


class ReplayStatus(BaseModel):
    status: str
    cursor: int
    total: int
    progress: float
    speed: float
    batch_size: int
    counts: dict
    campaigns: int
    campaign_mode: str
    investigations: int
    investigation_triggers: int
    inference_flows_per_second: float | None
    latest_seq: int
    defense_available: bool
    active_policies: int
    policies_activated: int
    correlation_groups: int
