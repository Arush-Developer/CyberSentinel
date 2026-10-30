# API reference

Base URL `http://localhost:8000/api`. Interactive docs are at `http://localhost:8000/docs`. Schemas are in [contracts.py](../backend/schemas/contracts.py).

All decisions are simulated. While models load, data endpoints return 503 and `/health` reports `loading`.

`scope` is `replay` (flows replayed so far) or `historical` (batch analysis of the whole validation set). If omitted, it is `replay` when a replay has progress, otherwise `historical`.

## Status and metrics

| Method and path | Purpose |
|---|---|
| `GET /health` | `ok`, `loading` or `unavailable`, with detail |
| `GET /models/status` | Model versions, calibration status, campaign mode and limitations |
| `GET /metrics` | Saved training, calibration, evaluation and leakage reports, plus a dataset summary |
| `GET /summary` | Replay counts and recent incidents for the Command Centre |

## Flows

| Method and path | Purpose |
|---|---|
| `GET /flows` | Paged results. Params: `scope`, `offset`, `limit` (up to 500), `decision`, `final_class`, `evidence_status`, `disagree`, `campaign_id`, `search` |
| `GET /flows/{flow_id}` | Agent outputs, fusion rationale, policy, campaign, investigation and evidence graph. Runs an investigation if a trigger fired and none exists yet. Labels appear only as `ground_truth_evaluation_only` |
| `POST /flows/analyse` | Body `{"features": {name: value}}`. Runs Agents 1 to 3 and policy on one flow, with no cross-flow context. Returns 422 if a required feature is missing |

## Campaigns, incidents, investigations

| Method and path | Purpose |
|---|---|
| `GET /campaigns?scope=` | Hypotheses, detection mode and limitations |
| `GET /ports?scope=` | Top destination ports, split by attack and benign final class |
| `GET /incidents?scope=&limit=` | Campaign and anomaly-only incidents |
| `GET /incidents/{incident_id}` | One incident |
| `GET /investigations?limit=` | Recent investigations |
| `GET /investigations/{investigation_id}` | Tool calls, results and verdict. The ID format is `INV-<flow_id>` |
| `GET /audit?kind=&limit=` | Audit events: `tool_call`, `investigation_*`, `policy_change`, `policy_simulation`, `replay_control`, `analyse_flow`, `system`, `replay_error` |

## Policy

| Method and path | Purpose |
|---|---|
| `GET /policy` | Current and calibrated thresholds, and change history |
| `POST /policy/simulate` | Body `{"thresholds": {...}, "max_examples": 50}`. Reports decision differences without changing anything |
| `POST /policy/configure` | Body `{"thresholds": {...}, "reason": "..."}`. Applies the thresholds and audits the previous and new values. Resets when the backend restarts |

Threshold fields: `allow_benign_confidence`, `block_multi_signal_confidence`, `block_classifier_only_confidence`, each from 0 to 1.

## Replay

| Method and path | Purpose |
|---|---|
| `POST /replay/start` | Body (all optional): `speed` (flows/s), `batch_size`, `limit`, `resume_saved`, `max_investigations_per_batch`. Returns 409 if already active |
| `POST /replay/pause`, `/resume` | Returns 409 from the wrong state |
| `POST /replay/stop` | Global stop. Also cancels running investigations |
| `GET /replay/status` | Status, cursor, progress and counts |
| `GET /replay/events?since=&once=` | Server-Sent Events: `state`, `flows`, `campaign`, `investigation`, `error`. `once=true` returns the backlog and closes |

## Agents 4 and 5

| Method and path | Purpose |
|---|---|
| `GET /defense?member_limit=25&group_limit=200` | Correlation groups, policies, the activation and expiry log, and the configuration. `available` is false, with a reason, when the replay input has no source addresses |

Replay events also include `policy` (activation), and each flow carries `defense_action` and `applied_policy_id`. To replay a file with endpoints, set `CYBERSENTINEL_REPLAY_INPUT=PATH` when starting the backend.
