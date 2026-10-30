# Refactor audit

Written before any file was moved. It covers every source file in the repository at that point: 21 backend modules, 6 scripts, 5 test files and 12 frontend source files.

**Checkpoint:** the folder is not a Git repository, so there were no branches or uncommitted changes to preserve. A code-only copy and SHA-256 checksums of the models and data were taken before refactoring. The dataset was not copied.

## Findings

| Check | Result |
|---|---|
| Duplicate implementations | **None.** One classifier, one anomaly detector, one fusion agent, one replay engine, one API. CatBoost is the selected model; the three other candidates exist only as comparison entries in `make_candidates` and are never saved |
| Circular dependencies | **None** (checked by walking the import graph) |
| Broken imports | **None** before the move |
| Mock implementations | **None.** Synthetic data exists only in unit-test fixtures and is labelled as such |
| Unused code | `Page` schema in `contracts.py`; `EvidenceStore.order_positions`; `ReplayEngine.flow_campaign` (written, never read) |
| Incomplete modules | Level 1 submission (no official API details); endpoint-mode campaign detection (tested on synthetic fixtures only); frontend has no automated tests |
| Missing document | The README had no status document yet: `docs/IMPLEMENTATION_STATUS.md` |

## Gaps against the requested contracts

| Module | Missing |
|---|---|
| Agent 1 | `flow_id` |
| Agent 2 | `flow_id`; structured baseline information |
| Campaign engine | Source/destination relationships; contradicting evidence; explicit hypothesis text |
| Investigation | `tools_selected`, `status`, separate supporting and contradicting observations |
| Agent 3 | Investigation references |
| Policy | Separate rule, human-readable reason, evidence references |
| Schemas | Domain outputs had no Pydantic models, only request and status schemas. TypeScript types were inside `api.ts` |

## Must be preserved

Trained models with no retraining (`RobustBaseline` is pickled inside the anomaly model, so it must stay importable from its original path); every API route; all six screens; replay start, pause, resume, stop and restore; audit logging; what-if simulation; measured reports.

## Inventory

### Backend

| Existing file | Purpose | Main contents | Internal dependencies | Destination | Owner |
|---|---|---|---|---|---|
| `backend/main.py` | App entry, background load | `app`, `_load` | routes, state | Same | Arush |
| `backend/config.py` | Config and path resolution | `load_config`, `resolve` | None | Same (shared utility, kept) | Arush |
| `backend/pipeline.py` | Loads models, runs agents | `Pipeline`, `Analysis` | agents, campaign, investigation, policy | `backend/services/model_service.py` | Arush |
| `backend/services/state.py` | Application state behind the API | `AppState`, `plain` | pipeline, replay, policy | `backend/services/app_state.py` (name freed `model_service` for models) | Arush |
| `backend/api/routes.py` | HTTP routes, SSE | 24 route functions | contracts | Same | Arush |
| `backend/submission/level1_adapter.py` | Isolated submission adapter | `submit`, `build_payload` | config | `backend/api/submission_adapter.py` | Arush |
| `backend/schemas/contracts.py` | Request and status schemas | 9 models | None | Same, extended | Arush, shared |
| `backend/agents/threat_agent.py` | Agent 1 | `ThreatAgent`, `make_candidates` | data_processor | Same | Arpit |
| `backend/agents/anomaly_agent.py` | Agent 2 plus deviation analysis | `AnomalyAgent`, `RobustBaseline` | data_processor | Same; deviation analysis moves out | Arnav |
| `backend/agents/fusion_agent.py` | Agent 3 | `fuse_batch`, `rationale` | None | Same | Arush |
| `backend/agents/investigation_orchestrator.py` | Planner, triggers | `Orchestrator`, `plan` | registry, tools | Same | Arush |
| `backend/intelligence/campaign_engine.py` | Campaign hypotheses | `CampaignEngine`, `CampaignTracker` | None | Same | Arnav |
| `backend/intelligence/evidence_engine.py` | Evidence graph | `build_evidence_graph` | None | Same | Arush |
| *(in `anomaly_agent.py`)* | Median/MAD baseline, evidence | `RobustBaseline`, `supporting_features` | None | `backend/intelligence/feature_explainer.py` | Arnav |
| `backend/investigation/tools.py` | Eight tools, evidence store | `EvidenceStore`, tools | anomaly_agent | Same | Arnav |
| `backend/investigation/registry.py` | Bounded tool calls | `ToolRegistry`, `TOOLS` | tools, audit | Same | Arnav |
| `backend/investigation/audit.py` | Audit log | `AuditLog` | None | Same | Arush |
| `backend/policy/policy_engine.py` | Decisions, what-if | `decide_batch`, `simulate` | fusion, config | Same | Arush |
| `backend/replay/replay_engine.py` | Replay | `ReplayEngine` | orchestrator, campaign, registry, pipeline | Same | Arush |
| `backend/preprocessing/data_processor.py` | Loading, cleaning, splits | `FeaturePipeline`, `internal_splits` | config | Same | Arpit |
| `backend/evaluation/metrics.py` | Metrics | `classification_report`, others | None | Same | Arpit |

### Scripts, config and artifacts

| Existing path | Purpose | Destination | Owner |
|---|---|---|---|
| `scripts/profile_dataset.py` | Archive inspection, profile | Same | Arpit |
| `scripts/train_models.py` | Trains Agents 1 and 2 | Same, new artifact paths | Arpit (Agent 2 section: Arnav) |
| `scripts/leakage_audit.py` | Separability audit | Same | Arpit |
| `scripts/evaluate.py` | Official evaluation | Same | Arpit |
| `scripts/calibrate_fusion.py` | Thresholds, campaign baseline | Same | Arush |
| `scripts/score_records.py` | Scores any parquet | Same | Arush |
| `scripts/run_all.sh` | Full rebuild | Same | Arush |
| `models/threat_agent.joblib` | Agent 1 artifact | `models/threat_model/threat_agent.joblib` | Arpit |
| `models/anomaly_agent.joblib` | Agent 2 artifact | `models/anomaly_model/anomaly_agent.joblib` | Arnav |
| `configs/*` | Settings, calibrated values | Same, plus artifact paths | Arush, shared |
| `package.json` (root) | Convenience scripts | Removed: not in the target layout and it only forwards to `frontend/` | N/A |

### Frontend

| Existing file | Contents | Destination | Owner |
|---|---|---|---|
| `src/main.tsx` | Mount | Same | Lucky |
| `src/index.css` | Base styles | `src/styles/globals.css` | Lucky |
| `src/app/App.tsx` | Shell, nav, routes, health | `app/App.tsx`, `app/router.tsx`, `components/Layout.tsx`, `Sidebar.tsx`, `Navbar.tsx` | Lucky |
| `src/components/ui.tsx` | Shared primitives | Same (kept: reused by all screens) | Lucky |
| `src/components/EvidenceGraph.tsx` | React Flow graph | `src/evidence-graph/EvidenceGraph.tsx` | Agrim |
| `src/pages/CommandCentre.tsx` | Command Centre | `pages/CommandCenter.tsx`; incident list to `investigations/IncidentTimeline.tsx` | Lucky, Agrim |
| `src/pages/ReplayLab.tsx` | Replay screen | `replay/ReplayLab.tsx`, `ReplayControls.tsx`, `ReplayTimeline.tsx`, `LiveFlowFeed.tsx` | Lucky |
| `src/pages/AttackIntelligence.tsx` | Campaign screen | `analytics/ThreatAnalytics.tsx` | Agrim |
| `src/pages/ModelIntelligence.tsx` | Metrics screen | `analytics/ModelMetrics.tsx`, `AnomalyAnalytics.tsx`, `ConfusionMatrix.tsx` | Agrim |
| `src/pages/InvestigationWorkbench.tsx` | Workbench | `investigations/InvestigationWorkbench.tsx`, `HypothesisPanel.tsx` | Agrim |
| `src/pages/DefenceAudit.tsx` | Policy and audit | `audit/DefenceAudit.tsx`, `PolicyControls.tsx`, `DecisionHistory.tsx`, `AuditLogs.tsx` | Agrim |
| `src/services/api.ts` | Client, types, SSE hook | `services/api.ts`, `types.ts`, `replay.ts` | Lucky, Arush |
| *(new)* | Agent status cards | `components/AgentStatus.tsx`, reads `/api/models/status` | Lucky |

### Tests

| Existing file | Destination |
|---|---|
| `tests/test_preprocessing.py` | `tests/agents/test_preprocessing.py` |
| `tests/test_fusion_policy.py` | `tests/agents/test_fusion.py`, `tests/policy/test_policy.py` |
| `tests/test_campaign_investigation.py` | `tests/intelligence/test_campaign_engine.py`, `tests/investigation/test_investigation.py` |
| `tests/test_submission_and_agents.py` | `tests/agents/test_agents.py`, `tests/api/test_submission_adapter.py` |
| `tests/test_api_replay.py` | `tests/api/test_api.py`, `tests/replay/test_replay.py` |
| *(new)* | `tests/integration/test_pipeline_e2e.py` and `tests/conftest.py` |
