# Team ownership

This records who is responsible for each module, not who wrote it. The first version of this code was generated with Claude Code from the team brief. A person owns a module once they have reviewed it, can explain it, and have contributed to it. Use real commits under your own name for that work; do not attribute generated code to anyone.

`docs/TEAM_HANDOFF.md` has what each person must review. `docs/MODULE_CONTRACTS.md` defines the interfaces below.

## Arush: backend architecture and integration

| Files | Responsibility |
|---|---|
| `backend/main.py`, `backend/config.py` | Entry point, configuration |
| `backend/api/routes.py`, `backend/api/submission_adapter.py` | HTTP and SSE API; Level 1 submission |
| `backend/services/model_service.py`, `backend/services/app_state.py` | Runs the agents; state behind the API |
| `backend/agents/fusion_agent.py`, `backend/agents/investigation_orchestrator.py` | Agent 3; investigation planning |
| `backend/intelligence/evidence_engine.py` | Evidence graph |
| `backend/investigation/audit.py` | Audit log |
| `backend/policy/policy_engine.py` | Simulated decisions, what-if |
| `backend/replay/replay_engine.py` | Replay |
| `backend/schemas/contracts.py` | Shared contracts, coordinated with everyone |
| `scripts/calibrate_fusion.py`, `scripts/score_records.py`, `scripts/run_all.sh` | Thresholds, scoring, full rebuild |
| `tests/agents/test_fusion.py`, `tests/policy/`, `tests/replay/`, `tests/api/`, `tests/integration/` | Backend and end-to-end tests |

- **Inputs:** Agent 1 and 2 outputs, campaign results, tool results, HTTP requests.
- **Outputs:** `FusionAssessment`, `PolicyOutcome`, `InvestigationResult`, the REST and SSE API.
- **Test:** `.venv/bin/python -m pytest tests/agents/test_fusion.py tests/policy tests/replay tests/api tests/integration -v`

## Arpit: data engineering and supervised ML

| Files | Responsibility |
|---|---|
| `backend/preprocessing/data_processor.py` | Loading, cleaning, splits, leakage control |
| `backend/agents/threat_agent.py` | Agent 1 |
| `backend/evaluation/metrics.py` | Metrics |
| `models/threat_model/` | Threat model artifact |
| `scripts/profile_dataset.py`, `scripts/train_models.py`, `scripts/leakage_audit.py`, `scripts/evaluate.py` | Profiling, training, audit, evaluation |
| `tests/agents/test_preprocessing.py`, threat tests in `tests/agents/test_agents.py` | Classification and data tests |

- **Inputs:** `data/raw/cyber-pack.zip`, extracted parquet.
- **Outputs:** `Partition`, `FeaturePipeline`, `ThreatAssessment`, `data/reports/`.
- **Test:** `.venv/bin/python -m pytest tests/agents/test_preprocessing.py tests/agents/test_agents.py -v`

## Arnav: anomaly and security intelligence

| Files | Responsibility |
|---|---|
| `backend/agents/anomaly_agent.py` | Agent 2 |
| `backend/intelligence/campaign_engine.py` | Cross-flow hypotheses |
| `backend/intelligence/feature_explainer.py` | Median/MAD baseline, deviation evidence |
| `backend/investigation/tools.py`, `backend/investigation/registry.py` | Investigation tools, bounded execution |
| `models/anomaly_model/` | Anomaly model artifact |
| `tests/intelligence/`, `tests/investigation/`, anomaly tests in `tests/agents/test_agents.py` | Campaign, investigation and anomaly tests |

- **Inputs:** feature frames, flow metadata, anomaly flags. Never labels or Agent 1's output for detection.
- **Outputs:** `AnomalyAssessment`, `CampaignRecord`, `ToolResult`.
- **Test:** `.venv/bin/python -m pytest tests/intelligence tests/investigation tests/agents/test_agents.py -v`

## Lucky: frontend foundation

| Files | Responsibility |
|---|---|
| `frontend/src/app/`, `frontend/src/main.tsx` | App, routes |
| `frontend/src/components/` | `Layout`, `Sidebar`, `Navbar`, `AgentStatus`, shared `ui.tsx` |
| `frontend/src/pages/CommandCenter.tsx` | Command Centre |
| `frontend/src/replay/` | `ReplayLab`, `ReplayControls`, `ReplayTimeline`, `LiveFlowFeed` |
| `frontend/src/styles/`, `frontend/tailwind.config.js`, `frontend/vite.config.ts` | Styling, build |
| `frontend/src/services/api.ts`, `frontend/src/services/replay.ts` | REST client, SSE stream |
| `frontend/src/services/types.ts` | Shared with Arush; mirrors `contracts.py` |

- **Inputs:** REST and SSE responses.
- **Outputs:** the app shell, replay screens, and the client every screen uses.
- **Test:** `npm --prefix frontend run build`, then run the checks in `docs/TEAM_HANDOFF.md`. No automated frontend tests exist yet.

## Agrim: frontend analytics and investigation

| Files | Responsibility |
|---|---|
| `frontend/src/analytics/` | `ThreatAnalytics` (Attack Intelligence screen), `ModelMetrics`, `AnomalyAnalytics`, `ConfusionMatrix` |
| `frontend/src/investigations/` | `InvestigationWorkbench`, `HypothesisPanel`, `IncidentTimeline` |
| `frontend/src/evidence-graph/EvidenceGraph.tsx` | Evidence graph |
| `frontend/src/audit/` | `DefenceAudit`, `PolicyControls`, `DecisionHistory`, `AuditLogs` |

- **Inputs:** `/metrics`, `/campaigns`, `/ports`, `/flows`, `/incidents`, `/investigations`, `/policy`, `/audit`.
- **Outputs:** the analytics, investigation and audit screens.
- **Test:** `npm --prefix frontend run build`, then run the checks in `docs/TEAM_HANDOFF.md`.

## Shared

`backend/schemas/contracts.py` and `frontend/src/services/types.ts` must change together. `tests/api/test_contract_sync.py` fails if their fields drift apart.
