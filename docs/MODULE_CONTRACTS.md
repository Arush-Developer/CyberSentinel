# Module contracts

The authoritative definitions are the Pydantic models in [contracts.py](../backend/schemas/contracts.py), mirrored in [types.ts](../frontend/src/services/types.ts). Don't redefine them anywhere else. Change both together and agree it with the other owners first; `tests/api/test_contract_sync.py` fails if their fields differ.

## Agent 1: `ThreatAssessment`

Produced by `ThreatAgent.to_output(flow_id, proba_row)`.

| Field | Meaning |
|---|---|
| `flow_id` | Flow identifier |
| `predicted_class` | One of the five classes |
| `confidence` | Probability of the predicted class |
| `probabilities` | All five classes |
| `model_version` | Which saved model produced this |
| `calibration_status` | What was measured about calibration |

For batches, `predict_proba(features)` returns an `(n, 5)` array in `agent.classes` order.

## Agent 2: `AnomalyAssessment`

Produced by `AnomalyAgent.to_output(flow_id, score, supporting)`. It must not import Agent 1 or 3; a test enforces this.

| Field | Meaning |
|---|---|
| `flow_id` | Flow identifier |
| `anomaly_score` | Percentile among held-out benign flows, 0 to 1. **Never call it a probability** |
| `is_anomaly`, `threshold` | The anomaly decision and the cut that made it |
| `supporting_features` | Largest deviations: measured value, benign median, MAD, robust z |
| `baseline_reference` | The baseline compared against |
| `score_meaning`, `model_version` | Plain-language score definition; saved model |

## Campaign engine: `CampaignRecord`

`CampaignEngine.detect(metadata, features, is_anomaly)` returns `CampaignResult(mode, limitations, campaigns, flow_campaign)`. Inputs must never include labels or Agent 1's output; `signals(predicted)` is the only place campaigns meet the classifier.

| Field | Meaning |
|---|---|
| `campaign_id` | Identifier |
| `campaign_type`, `hypothesis` | Hypothesis as a code and in words. It is a hypothesis, not a confirmed attack |
| `related_flow_ids`, `flow_count` | Member flows (up to 500 IDs) and the full count |
| `relationships` | Source, destination, port and flow count. Source and destination are `null` when unmeasurable |
| `distinct_sources`, `target_count` | `null` when unmeasurable. Never estimate them |
| `supporting_evidence` | Measured values per window |
| `contradicting_evidence` | Measurements that argue against the hypothesis |
| `confidence_basis`, `confidence`, `uncertainty` | Why it was raised and how far to trust it |
| `detection_mode`, `target`, `first_observed`, `last_observed`, `windows_observed`, `traffic_intensity` | Context |

`mode` is `endpoint`, `cohort` or `disabled`, chosen from the columns present. Brute-force records are behavioural indicators only; the data has no authentication events.

## Investigation: `InvestigationResult`

Produced by `Orchestrator.investigate(flow_id, triggers)`.

| Field | Meaning |
|---|---|
| `investigation_id` | `INV-<flow_id>` |
| `triggers` | Why it was opened |
| `tools_selected` | Tools run, at most three |
| `tool_calls` | Actual arguments, status, duration and result of each call |
| `supporting_observations` | Results pointing to an attack |
| `contradicting_observations` | Results pointing to benign traffic |
| `neutral_observations`, `unavailable_evidence` | Inconclusive results; tools missing the metadata they need |
| `status` | `COMPLETED`. A cancelled investigation raises `InvestigationCancelled` and returns no result |
| `verdict` | `SUPPORTS_ATTACK`, `SUPPORTS_BENIGN`, `CONFLICTING` or `INCONCLUSIVE` |
| `planner` | `deterministic` |

### Tools: `ToolResult`

Each tool takes an `EvidenceStore` and arguments, and returns `available`, `summary`, `supports` (`attack`, `benign` or `neutral`) and `evidence`. If required metadata is absent, return `available: false` and say why; never guess. Only tools registered in `registry.TOOLS` can run, and tools must not call the registry.

An LLM, if added, may only propose registered tools or summarise results. It must never invent evidence, change predictions or override policy, and the system must keep working without a key.

## Agent 3: `FusionAssessment`

Batch: `fuse_batch(...)` returns `FusionResult`. Single flow: `fusion_output(...)`.

| Field | Meaning |
|---|---|
| `final_class`, `final_class_source` | One of the five classes, and where it came from. It stays with Agent 1 unless a validated rule is enabled |
| `evidence_status` | With Agents 1 and 2: `AGREED_BENIGN`, `MULTI_SIGNAL_ATTACK`, `CLASSIFIER_ONLY`, `ANOMALY_ONLY` or `UNCERTAIN` (confidence below the threshold). With cross-flow evidence, also `CAMPAIGN_CORROBORATED` (attack call, Agent 2 normal, campaign support) and `CAMPAIGN_ONLY` (benign call, Agent 2 normal, inside a campaign) |
| `confidence_status` | `CONFIDENT` or `LOW_CONFIDENCE` |
| `evidence_refs` | The flow, agents, features, campaign and investigation behind this result |
| `agreement` | `AGREE` or `DISAGREE`, Agent 1 against Agent 2 only |
| `low_confidence` | Below the configured confidence |
| `investigation_refs` | Investigations behind this result |
| `rationale` | Explanation built only from measured values |

## Agent 4: `CorrelationGroup`

Built one analysed flow at a time, from records already observed. Blocked flows are not analysed, so they do not join a group.

| Field | Meaning |
|---|---|
| `group_id` | `GRP-00001` |
| `scope_type`, `scope_value` | `SOURCE_IP` or `DESTINATION_IP`, and the address |
| `first_record_id`, `last_record_id` | First and latest member |
| `member_record_ids`, `member_count` | Members. The API truncates the list; `agent4_agent5_evidence.json` keeps up to 5,000 per group |
| `evidence` | `CorrelationEvidence`: flows in the window, confident attack flows, attack share, anomalous flows, dominant class, distinct destinations, ports and attacking sources, and the named pattern |

## Agent 5: `DefensePolicy`

| Field | Meaning |
|---|---|
| `policy_id` | `POL-00001` |
| `activated_after_record_id` | The triggering record. The policy applies only after it |
| `scope_type`, `scope_value` | Always `SOURCE_IP`, and the address |
| `expires_after_record_id` | Last record the policy covers. Null while active, because it is filled in when replay reaches that record |
| `policy_action` | Always `BLOCK` |
| `status`, `ttl_records`, `blocked_records` | `ACTIVE` or `EXPIRED`, length in records, flows blocked |
| `group_id`, `converging_group_id` | The Agent 4 groups behind it |
| `rationale`, `evidence` | Measured explanation, and the group evidence at activation |

The order at each record is fixed in `DefenseLoop.step`: apply active policies; if not blocked, analyse and possibly activate for later records; then expire. Replay and the CSV export both use it, and read Agents 1 to 3 evidence only, so a fresh replay reproduces the files.

## Level 2 files

| File | Columns |
|---|---|
| `classification.csv` | `record_id`, `predicted_class`, `anomaly_score`, `evidence_status`, one row per record, including blocked flows |
| `policy.csv` | `policy_id`, `activated_after_record_id`, `scope_type`, `scope_value`, `expires_after_record_id`, `policy_action` |
| `replay.csv` | `record_id`, `action`, `applied_policy_id`, one row per record. `applied_policy_id` is empty on ALLOW |

The brief's table repeats the policy columns for `replay.csv`, while its text names `action` and `applied_policy_id`. **These replay columns and the snake_case spelling of `anomaly_score` and `evidence_status` are inferred; confirm them with the organisers.** They can be renamed in `configs/default.yaml` under `level2.columns` without code changes.

## Policy: `PolicyOutcome`

Batch: `decide_batch(fusion, thresholds)` returns `(decision, rule)`. Single flow: `policy_output(...)`.

| Field | Meaning |
|---|---|
| `decision` | `ALLOW`, `BLOCK` or `REVIEW`. Never mixed with class labels |
| `policy_rule` | The rule applied, such as `ANOMALY_ONLY_NEEDS_REVIEW` |
| `decision_reason` | Plain-language reason with measured values |
| `evidence_refs` | For example `flow:C000003`, `investigation:INV-C000003` |
| `simulated` | Always `true`. Nothing touches a network |

`simulate(...)` must never change stored results.

## Preprocessing

`load_partition(which)` and `split_representations(df)` return `Partition(features, metadata, labels)`.

- `features`: numeric flow statistics only. Never the label, `record_id` or endpoint columns.
- `metadata`: `flow_id`, any endpoint columns present, and `destination_port`.
- `labels`: mapped benchmark classes, or `None` for unlabelled files. Used for scoring only.
- `FeaturePipeline`: fit on training data only. `transform` raises `ValueError` if a column is missing.

## Flow detail: `FlowDetail`

`GET /api/flows/{flow_id}` combines all of the above, plus `network`, `unavailable_metadata`, `triggers` and `evidence_graph`. `ground_truth_evaluation_only` is for display, and no logic may read it.

## Replay events

Sent over SSE: `state`, `flows`, `campaign`, `investigation`, `error`. Each carries `seq`, `type` and `time`. The frontend shape is `ReplayFlowEvent`, `CampaignEvent` and `InvestigationEvent` in `types.ts`.

## Frontend rule

Screens render only what the backend returns. No hard-coded metrics, sample flows or placeholder charts: show an empty state instead.

## Compatibility note

`RobustBaseline` lives in `intelligence/feature_explainer.py`, but the saved anomaly model was pickled when it was in `agents/anomaly_agent.py`. That module keeps importing it, so the artifact loads without retraining. Keep that import until the model is next retrained.
