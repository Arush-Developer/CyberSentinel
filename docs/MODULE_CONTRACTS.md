# Module contracts

Changing anything here affects another owner, so agree it first. Field names and types live in [contracts.py](../backend/schemas/contracts.py) and [api.ts](../frontend/src/services/api.ts); keep those two in step.

## Preprocessing to agents

`load_partition(which)` and `split_representations(df)` return `Partition(features, metadata, labels)`.

- `features`: numeric flow statistics only. Never contains the label, `record_id` or endpoint columns.
- `metadata`: `flow_id`, any endpoint columns present, and `destination_port`.
- `labels`: mapped benchmark classes, or `None` for unlabelled files.
- `FeaturePipeline`: fit on training data only. `transform` raises `ValueError` if a column is missing.

## Agent 1

`ThreatAgent.predict_proba(features)` returns an array of shape `(n, 5)` in `agent.classes` order. `to_output(row)` returns:

```json
{"agent": "threat_detection", "predicted_class": "...", "confidence": 0.0, "probabilities": {}, "model_version": "...", "calibration_status": "..."}
```

## Agent 2

Must not import Agent 1 or Agent 3; a test enforces this. `AnomalyAgent.score(features)` returns a percentile from 0 to 1, flagged at or above `agent.threshold`. Never describe it as a probability. `to_output(score, supporting)` returns:

```json
{"agent": "anomaly_detection", "anomaly_score": 0.0, "score_meaning": "...", "is_anomaly": false, "threshold": 0.95, "supporting_features": [{"feature": "...", "deviation": "high", "measured_value": 0.0, "benign_median": 0.0, "benign_mad": 0.0, "robust_z": 0.0}], "baseline_reference": "benign_training_distribution", "model_version": "..."}
```

## Campaign engine

`CampaignEngine.detect(metadata, features, is_anomaly)` returns `CampaignResult(mode, limitations, campaigns, flow_campaign)`.

- Inputs must never include labels or Agent 1's output. `signals(predicted)` is the only place campaigns meet classifier output.
- `mode` is `endpoint`, `cohort` or `disabled`, chosen from the columns present.
- `distinct_sources` and `target_count` are `null` when unmeasurable. Never fill them with an estimate.
- Brute-force records are behavioural indicators; never claim authentication events.

## Fusion

`fuse_batch(proba, classes, anomaly_score, threshold, config, campaign_support, campaign_conflict, investigation_conflict)` returns `FusionResult`.

- `final_class`: always one of the five classes, from Agent 1 unless a validated rule is enabled. `final_class_source` records which.
- `evidence_status`: `MULTI_SIGNAL_CONFIRMED`, `CLASSIFIER_ONLY`, `ANOMALY_ONLY`, `CAMPAIGN_ONLY` or `AGREED_BENIGN`.
- `agreement`: `AGREE` or `DISAGREE`, comparing Agent 1 and Agent 2 only.

## Policy

`decide_batch(fusion, thresholds)` returns `(decision, reason)`. Decisions are `ALLOW`, `BLOCK` or `REVIEW`, and are kept separate from class labels. `simulate(...)` must never change stored results.

## Investigation tools

Each tool takes an `EvidenceStore` and arguments, and returns:

```json
{"available": true, "summary": "...", "supports": "attack|benign|neutral", "evidence": {}}
```

- If required metadata is absent, return `available: false` and say why. Never guess.
- Register new tools in `registry.TOOLS`; only registered tools can run. Tools must not call the registry.
- The orchestrator spends at most three actions per flow.
- An LLM, if added, may only propose registered tools or summarise results. It must never invent evidence, change predictions or override policy, and the system must keep working without a key.

## Replay events

Sent over SSE: `state`, `flows`, `campaign`, `investigation`, `error`. Each event carries `seq`, `type` and `time`. `ground_truth_evaluation_only` is for display; no decision logic may read it.

## Frontend rule

Screens render only what the backend returns. No hard-coded metrics, sample flows or placeholder charts: show an empty state instead.
