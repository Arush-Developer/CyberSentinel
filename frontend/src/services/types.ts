// TypeScript mirror of backend/schemas/contracts.py. tests/api/test_contract_sync.py compares the two.
export const CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"] as const;
export type Decision = "ALLOW" | "BLOCK" | "REVIEW";

export interface ThreatAssessment {
  agent: string;
  flow_id: string;
  predicted_class: string;
  confidence: number;
  probabilities: Record<string, number>;
  model_version: string;
  calibration_status: string;
}

export interface SupportingFeature {
  feature: string;
  deviation: string;
  measured_value: number;
  benign_median: number;
  benign_mad: number;
  robust_z: number;
}

export interface AnomalyAssessment {
  agent: string;
  flow_id: string;
  anomaly_score: number;
  score_meaning: string;
  is_anomaly: boolean;
  threshold: number;
  supporting_features: SupportingFeature[];
  baseline_reference: string;
  model_version: string;
}

export interface CampaignRelationship {
  source: string | null;
  destination: string | null;
  destination_port: number | null;
  flows: number;
}

export interface CampaignRecord {
  campaign_id: string;
  campaign_type: string;
  hypothesis: string;
  detection_mode: string;
  target: string;
  first_observed: string;
  last_observed: string;
  related_flow_ids: string[];
  related_flow_ids_total?: number | null;
  flow_count: number;
  distinct_sources: number | null;
  target_count: number | null;
  relationships: CampaignRelationship[];
  traffic_intensity: string;
  supporting_evidence: Record<string, number | string>[];
  contradicting_evidence: string[];
  confidence_basis: string;
  confidence: string;
  uncertainty: string;
  windows_observed: number;
}

export interface ToolResult {
  available: boolean;
  summary: string;
  supports: string;
  evidence: Record<string, unknown>;
}

export interface ToolCall {
  tool: string;
  arguments: Record<string, unknown>;
  status: string;
  duration_ms: number;
  result: ToolResult;
}

export interface InvestigationResult {
  investigation_id: string;
  flow_id: string;
  triggers: string[];
  tools_selected: string[];
  tool_calls: ToolCall[];
  supporting_observations: string[];
  contradicting_observations: string[];
  neutral_observations: string[];
  unavailable_evidence: string[];
  status: string;
  verdict: string;
  planner: string;
}

export interface FusionAssessment {
  agent: string;
  flow_id: string;
  final_class: string;
  final_class_source: string;
  evidence_status: string;
  agreement: string;
  low_confidence: boolean;
  confidence_status: "CONFIDENT" | "LOW_CONFIDENCE";
  evidence_refs: string[];
  investigation_refs: string[];
  rationale: string;
}

export interface PolicyOutcome {
  decision: Decision;
  policy_rule: string;
  decision_reason: string;
  evidence_refs: string[];
  simulated: boolean;
}

export interface GraphNode { id: string; kind: string; label: string; data: Record<string, unknown> }
export interface GraphEdge { id: string; source: string; target: string; relation: string }
export interface EvidenceGraph { nodes: GraphNode[]; edges: GraphEdge[] }

export interface FlowDetail {
  flow_id: string;
  network: Record<string, string | number | null>;
  unavailable_metadata: string[];
  threat: ThreatAssessment;
  anomaly: AnomalyAssessment;
  fusion: FusionAssessment;
  policy: PolicyOutcome;
  campaign: CampaignRecord | null;
  triggers: string[];
  investigation: InvestigationResult | null;
  replay: FlowDefense | null;
  ground_truth_evaluation_only: string | null;
  evidence_graph: EvidenceGraph;
}

export interface FlowDefense {
  action: "ALLOW" | "BLOCK" | null;
  applied_policy_id: string | null;
  replay_decision: Decision;
  replay_evidence_status: string;
}

export interface CorrelationEvidence {
  window_records: number;
  flows_in_window: number;
  confident_attack_flows: number;
  attack_share: number;
  anomalous_flows: number;
  dominant_predicted_class: string | null;
  distinct_destinations: number;
  distinct_destination_ports: number;
  distinct_attacking_sources: number;
  pattern: string;
}

export interface CorrelationGroup {
  group_id: string;
  scope_type: "SOURCE_IP" | "DESTINATION_IP";
  scope_value: string;
  first_record_id: string;
  last_record_id: string;
  member_record_ids: string[];
  member_count: number;
  evidence: CorrelationEvidence;
}

export interface DefensePolicy {
  policy_id: string;
  activated_after_record_id: string;
  scope_type: "SOURCE_IP";
  scope_value: string;
  expires_after_record_id: string | null;
  policy_action: "BLOCK";
  status: "ACTIVE" | "EXPIRED";
  ttl_records: number;
  blocked_records: number;
  group_id: string;
  converging_group_id: string | null;
  rationale: string;
  evidence: CorrelationEvidence;
}

export interface DefenseLogEntry {
  event: "ACTIVATED" | "EXPIRED";
  policy_id: string;
  record_id: string;
  position: number;
  scope_value: string;
}

export interface DefenseState {
  available: boolean;
  unavailable_reason: string | null;
  config: Record<string, number>;
  policies: DefensePolicy[];
  log: DefenseLogEntry[];
  groups: CorrelationGroup[];
  groups_total: number;
}

export interface PolicyEvent {
  seq: number;
  action: string;
  policy: Pick<DefensePolicy, "policy_id" | "scope_type" | "scope_value" | "activated_after_record_id" | "ttl_records" | "group_id" | "rationale">;
}

export interface FlowRow {
  flow_id: string;
  threat_class: string;
  threat_confidence: number;
  anomaly_score: number;
  is_anomaly: boolean;
  agreement: string;
  final_class: string;
  evidence_status: string;
  policy_decision: Decision;
  policy_rule: string;
  campaign_id: string | null;
}

export interface ReplayStatus {
  status: string;
  cursor: number;
  total: number;
  progress: number;
  speed: number;
  batch_size: number;
  counts: {
    total: number;
    classes: Record<string, number>;
    decisions: Record<Decision, number>;
    agreement: Record<string, number>;
    evidence: Record<string, number>;
    defense: Record<"ALLOW" | "BLOCK", number>;
  };
  campaigns: number;
  campaign_mode: string;
  investigations: number;
  investigation_triggers: number;
  inference_flows_per_second: number | null;
  latest_seq: number;
  defense_available: boolean;
  active_policies: number;
  policies_activated: number;
  correlation_groups: number;
}

export interface ModelStatus {
  threat_model: string;
  threat_calibration: string;
  threat_features: number;
  anomaly_model: string;
  anomaly_detector: string;
  anomaly_threshold: number;
  anomaly_features: number;
  campaign_mode: string;
  campaign_limitations: string[];
  defense_available: boolean;
  replay_input: string;
  llm_in_use: boolean;
}

export interface Incident {
  incident_id: string;
  kind: string;
  severity: string;
  title: string;
  summary: string;
  flow_count: number;
  flow_ids: string[];
  campaign_id: string | null;
}

export interface Thresholds {
  allow_benign_confidence: number;
  block_multi_signal_confidence: number;
  block_classifier_only_confidence: number;
}

export interface PolicyState {
  thresholds: Thresholds;
  calibrated: Thresholds;
  history: { time: number; previous: Thresholds; new: Thresholds; reason: string; decisions_before: Record<string, number>; decisions_after: Record<string, number> }[];
}

export interface Simulation {
  flows_evaluated: number;
  previous_thresholds: Thresholds;
  new_thresholds: Thresholds;
  decisions_before: Record<Decision, number>;
  decisions_after: Record<Decision, number>;
  changed: number;
  transitions: Record<string, number>;
  examples: { flow_id: string; before: string; after: string; reason: string; final_class: string; confidence: number; anomaly_score: number; evidence_status: string }[];
}

export interface ReplayFlowEvent {
  flow_id: string;
  threat_class: string;
  confidence: number;
  anomaly_score: number;
  is_anomaly: boolean;
  agreement: string;
  final_class: string;
  evidence_status: string;
  policy_decision: Decision;
  policy_rule: string;
  campaign_id: string | null;
  investigation_triggered: boolean;
  defense_action: "ALLOW" | "BLOCK" | null;
  applied_policy_id: string | null;
  ground_truth_evaluation_only: string | null;
}
export interface CampaignEvent { seq: number; action: string; campaign: CampaignRecord }
export interface InvestigationEvent { seq: number; flow_id: string; investigation_id: string; triggers: string[]; verdict: string; tools: string[] }
