# Codebase audit

Audited at commit `1e52673`, before any repair, on 30 October 2026. **The status column is the state found at that point**, not the state now. The current state is in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

The brief expected many empty or placeholder files. That is not what the repository contained: the first version was substantial, and the models are real. The defects were narrower, and some were serious.

## Summary

| Status | Files |
|---|---:|
| WORKING | 65 |
| PARTIALLY IMPLEMENTED | 40 |
| EMPTY | 0 |
| PLACEHOLDER | 0 |
| BROKEN | 1 |
| DUPLICATE | 1 |
| NOT REQUIRED | 22 |

Files marked WORKING were checked by reading them and running their tests. The two models were also loaded and re-scored against the official labels with separate code, which reproduced accuracy 0.99995 and macro-F1 0.99982.

## Most important defects

1. **Level 1 numbers were misattributed.** `level1_summary.json` reported evidence and decision counts from the system with campaign intelligence, not from Agents 1 to 3. Accuracy and macro-F1 were correct.
2. **Agent 3 did not follow the brief.** There was no `UNCERTAIN` status, and `MULTI_SIGNAL_CONFIRMED` counted flows Agent 2 had called normal as multi-signal.
3. **Replay could read the future.** Investigation tools looked both ways in record order and read whole-set campaign records. The problem statement forbids future records.
4. **Replay order was wrong for the hidden set.** It sorted by numeric ID, ignored `seq`, and would crash on non-numeric IDs.
5. **Level 2 did not exist.** No Agent 4, no Agent 5, no `SOURCE_IP` policies, no CSV export. The plan document does not spell these out, but the problem statement requires them.
6. **Replay resume corrupted results.** Resuming after a mid-batch stop duplicated rows.
7. **Investigation verdicts never reached replay decisions**, although the batch path used them.
8. **Audit and policy history were lost on restart.**
9. **Missing deliverables:** `dataset_profile.md`, this file, `IMPLEMENTATION_STATUS.md` (the README linked to it), `GIT_WORKFLOW.md`, Modes A to C, and any frontend tests.

## Checks the brief asked for

| Check | Result |
|---|---|
| Zero-byte files | 14, all `__init__.py` package markers |
| Comment-only files | None |
| Files with only `pass` | None. Three `pass` statements: an `except ImportError` for optional CatBoost, and two exception class bodies |
| `NotImplementedError` | None |
| TODO-only implementations | None. No TODO or FIXME anywhere in source |
| Functions returning hardcoded values | None found. Static values are limited to labels and configuration |
| Dummy model predictions | None |
| Empty classes | Two exception classes, which is correct |
| Unused modules | None. `Page` schema was removed earlier |
| Duplicate implementations | One duplicate data folder, `data/raw/cyber-pack/`. No duplicate code |
| Broken imports | None. Now enforced by `tests/test_imports.py` |
| Circular dependencies | None |
| Frontend components never rendered | None |
| Backend services never invoked | None |
| APIs with no real function | None. All routes read the live pipeline or saved reports |
| Model loading pointing to missing artifacts | None |
| Tests that only test mocks | None. There are no mock objects; synthetic fixtures are labelled, and 21 tests used the real models and records. Gap: no frontend tests |
| Fake metrics on screen | None. Every figure comes from the API |

## Every file

| Path | Purpose | Status | Genuinely implemented | Missing | Internal dependencies | Owner | Repair |
|---|---|---|---|---|---|---|---|
| `.claude/launch.json` | Editor launch settings for API and web | WORKING | Yes | None | – | Arush | None |
| `.gitignore` | Keeps data, models and secrets out of Git | WORKING | Yes | None | – | Arush | None |
| `README.md` | Project overview, results, setup | PARTIALLY IMPLEMENTED | Partly | Linked a missing status doc; no Level 2; stale limitations | – | Arush | Rewritten where wrong |
| `backend/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `backend/agents/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `backend/agents/anomaly_agent.py` | Agent 2: benign-only Isolation Forest | WORKING | Yes | None | intelligence.feature_explainer, preprocessing.data_processor, schemas.contracts | Arnav | None |
| `backend/agents/fusion_agent.py` | Agent 3: evidence fusion | PARTIALLY IMPLEMENTED | Partly | No `UNCERTAIN` status; `MULTI_SIGNAL_CONFIRMED` included flows Agent 2 called normal; no confidence status or evidence references | schemas.contracts | Arush | Brief's five conditions implemented; campaign support kept separate |
| `backend/agents/investigation_orchestrator.py` | Deterministic investigation planner | WORKING | Yes | None | investigation.registry, investigation.tools | Arush | None |
| `backend/agents/threat_agent.py` | Agent 1: CatBoost five-class classifier | WORKING | Yes | None | preprocessing.data_processor, schemas.contracts | Arpit | None. Metrics reproduced independently |
| `backend/api/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `backend/api/routes.py` | REST and SSE routes | PARTIALLY IMPLEMENTED | Partly | No Agent 4 or 5 endpoint | schemas.contracts | Arush | Added `GET /api/defense` |
| `backend/api/submission_adapter.py` | Level 1 submission adapter | PARTIALLY IMPLEMENTED | Partly | Official URL, auth and payload are not in the repository, so it cannot send | config | Arush | **BLOCKED** on organiser details; refuses to send until configured |
| `backend/config.py` | Config and path resolution | WORKING | Yes | None | None internal | Arush | None |
| `backend/evaluation/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arpit | None |
| `backend/evaluation/metrics.py` | Metrics | WORKING | Yes | None | None internal | Arpit | None |
| `backend/intelligence/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `backend/intelligence/campaign_engine.py` | Cross-flow campaign hypotheses | PARTIALLY IMPLEMENTED | Partly | Own ordering rule ignored the replay rule; endpoint mode only tested on synthetic data | preprocessing.data_processor | Arnav | Uses shared `replay_order`. Endpoint mode still unproven on real endpoints |
| `backend/intelligence/evidence_engine.py` | Evidence graph | PARTIALLY IMPLEMENTED | Partly | No Agent 5 node | None internal | Arush | Adds the blocking policy |
| `backend/intelligence/feature_explainer.py` | Median/MAD feature evidence | WORKING | Yes | None | None internal | Arnav | None |
| `backend/investigation/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `backend/investigation/audit.py` | Audit log | PARTIALLY IMPLEMENTED | Partly | Memory only: lost on restart | None internal | Arush | SQLite persistence |
| `backend/investigation/registry.py` | Bounded tool execution | WORKING | Yes | None | investigation, investigation.audit | Arnav | None |
| `backend/investigation/tools.py` | Eight investigation tools | PARTIALLY IMPLEMENTED | Partly | Could read later records during replay | agents.anomaly_agent, intelligence.feature_explainer, preprocessing.data_processor | Arnav | `causal` mode: replay sees only earlier records |
| `backend/main.py` | FastAPI entry point, background model load | WORKING | Yes | None | api.routes, services.app_state | Arush | None |
| `backend/policy/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `backend/policy/policy_engine.py` | ALLOW/BLOCK/REVIEW, what-if | WORKING | Yes | Only needed the status rename | agents.fusion_agent, config, schemas.contracts | Arush | Status names updated |
| `backend/preprocessing/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arpit | None |
| `backend/preprocessing/data_processor.py` | Loading, cleaning, splits | PARTIALLY IMPLEMENTED | Partly | No column or label standardisation; failed on non-numeric IDs in replay ordering; no unlabelled-file loader | config | Arpit | Added all three, plus `replay_order` |
| `backend/replay/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `backend/replay/replay_engine.py` | Offline replay | PARTIALLY IMPLEMENTED | Partly | Ignored `seq`; crashed on non-numeric IDs; investigations read later records and whole-set campaigns; their verdicts never reached the decision; resume after a mid-batch stop duplicated rows; no Agents 4 or 5 | agents.defense_agent, agents.investigation_orchestrator, config, intelligence.campaign_engine, investigation.audit, investigation.registry, preprocessing.data_processor, services.level2, services.model_service | Arush | All repaired and tested |
| `backend/schemas/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `backend/schemas/contracts.py` | Pydantic contracts | PARTIALLY IMPLEMENTED | Partly | No Agent 4 or 5 contracts | None internal | Arush | Added |
| `backend/services/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `backend/services/app_state.py` | State behind the API | PARTIALLY IMPLEMENTED | Partly | Policy history lost on restart; no way to replay another file | agents.fusion_agent, config, intelligence.evidence_engine, investigation.audit, policy.policy_engine, preprocessing.data_processor, replay.replay_engine, services.model_service | Arush | Restored from SQLite; `CYBERSENTINEL_REPLAY_INPUT` |
| `backend/services/model_service.py` | Loads models, runs the pipeline | WORKING | Yes | None | agents.anomaly_agent, agents.fusion_agent, agents.investigation_orchestrator, agents.threat_agent, config, intelligence.campaign_engine, investigation.audit, investigation.registry, investigation.tools, policy.policy_engine, preprocessing.data_processor | Arush | Added a named Agents 1 to 3 view |
| `configs/calibrated.json` | Thresholds chosen on training holdout | WORKING | Yes | None | – | Arush | None |
| `configs/campaign_baseline.json` | Unsupervised campaign thresholds | WORKING | Yes | None | – | Arush | None |
| `configs/default.yaml` | Main configuration, label mapping | PARTIALLY IMPLEMENTED | Partly | No Level 2 settings | – | Arush | Added `level2` block |
| `data/reports/calibration_report.json` | Threshold selection record | WORKING | Yes | None | – | Arpit | None |
| `data/reports/dataset_profile.json` | Measured dataset profile | WORKING | Yes | None | – | Arpit | Regenerated |
| `data/reports/evaluation_report.json` | Measured evaluation | PARTIALLY IMPLEMENTED | Partly | No Modes A, B, C | – | Arpit | Regenerated |
| `data/reports/leakage_audit.json` | Leakage measurements | WORKING | Yes | None | – | Arpit | None |
| `data/reports/level1_summary.json` | Level 1 payload source | BROKEN | No | Status and decision counts included campaign results; accuracy and macro-F1 were correct | – | Arpit | Regenerated from Agents 1 to 3 |
| `data/reports/training_report.json` | Model comparison and training record | WORKING | Yes | None | – | Arpit | None |
| `docs/API.md` | API reference | PARTIALLY IMPLEMENTED | Partly | No Agents 4 or 5 | – | Arush | Updated |
| `docs/INTEGRATION_GUIDE.md` | Run and merge guide | PARTIALLY IMPLEMENTED | Partly | Hidden-set steps stale | – | Arush | Updated |
| `docs/LEVEL1_SUMMARY.md` | Level 1 text | PARTIALLY IMPLEMENTED | Partly | Counts mixed in campaign results | – | Arush | Corrected from regenerated report |
| `docs/MODULE_CONTRACTS.md` | Interface definitions | PARTIALLY IMPLEMENTED | Partly | Old status names; no Agents 4 or 5 | – | Arush | Updated |
| `docs/REFACTOR_AUDIT.md` | Audit from the earlier refactor | WORKING | Yes | Historic: superseded by this file, and says the folder is not a Git repository | – | Arush | Kept as history |
| `docs/TEAM_HANDOFF.md` | What each member reviews | PARTIALLY IMPLEMENTED | Partly | Git section stale: told Arush to create a repository that exists | – | Arush | Points to GIT_WORKFLOW.md; Agents 4 and 5 added |
| `docs/TEAM_OWNERSHIP.md` | Module ownership | PARTIALLY IMPLEMENTED | Partly | Missing new modules | – | Arush | Updated |
| `frontend/index.html` | App shell | PARTIALLY IMPLEMENTED | Partly | No favicon, so every page logged a 404 | – | Lucky | Added |
| `frontend/package-lock.json` | Locked dependencies | WORKING | Yes | None | – | Lucky | Updated with test runner |
| `frontend/package.json` | Frontend dependencies and scripts | PARTIALLY IMPLEMENTED | Partly | No typecheck or browser test script | – | Lucky | Added |
| `frontend/postcss.config.js` | PostCSS | WORKING | Yes | None | – | Lucky | None |
| `frontend/src/analytics/AnomalyAnalytics.tsx` | Agent 2 charts | WORKING | Yes | None | types, ui | Agrim | None |
| `frontend/src/analytics/ConfusionMatrix.tsx` | Confusion matrix | WORKING | Yes | None | ui | Agrim | None |
| `frontend/src/analytics/ModelMetrics.tsx` | Model Intelligence page | PARTIALLY IMPLEMENTED | Partly | No Modes A, B, C | AnomalyAnalytics, ConfusionMatrix, api, types, ui | Agrim | Added table |
| `frontend/src/analytics/ThreatAnalytics.tsx` | Attack Intelligence page | PARTIALLY IMPLEMENTED | Partly | No Agent 4 | CorrelationGroups, EvidenceGraph, api, types, ui | Agrim | Added panel |
| `frontend/src/app/App.tsx` | Root | WORKING | Yes | None | Layout, router | Lucky | None |
| `frontend/src/app/router.tsx` | Six page routes | WORKING | Yes | None | CommandCenter, DefenceAudit, InvestigationWorkbench, ModelMetrics, ReplayLab, ThreatAnalytics | Lucky | None |
| `frontend/src/audit/AuditLogs.tsx` | Audit list | WORKING | Yes | None | api, ui | Agrim | None |
| `frontend/src/audit/DecisionHistory.tsx` | Policy history | WORKING | Yes | None | api, types, ui | Agrim | None |
| `frontend/src/audit/DefenceAudit.tsx` | Defence & Audit page | PARTIALLY IMPLEMENTED | Partly | No Agent 5 | AdaptiveDefense, AuditLogs, DecisionHistory, PolicyControls, api, types, ui | Agrim | Added panel |
| `frontend/src/audit/PolicyControls.tsx` | Thresholds and what-if | WORKING | Yes | None | api, types, ui | Agrim | None |
| `frontend/src/components/AgentStatus.tsx` | Agent status cards | PARTIALLY IMPLEMENTED | Partly | Did not list Agents 3 to 5 | api, types, ui | Lucky | Added |
| `frontend/src/components/Layout.tsx` | Page frame | WORKING | Yes | None | Navbar, Sidebar, api, ui | Lucky | None |
| `frontend/src/components/Navbar.tsx` | Top bar, health | WORKING | Yes | None | api, types, ui | Lucky | None |
| `frontend/src/components/Sidebar.tsx` | Navigation | WORKING | Yes | None | None internal | Lucky | None |
| `frontend/src/components/ui.tsx` | Shared UI parts | WORKING | Yes | None | types | Lucky | None |
| `frontend/src/evidence-graph/EvidenceGraph.tsx` | React Flow graph | WORKING | Yes | None | types | Agrim | None |
| `frontend/src/investigations/HypothesisPanel.tsx` | Competing hypotheses | WORKING | Yes | None | types, ui | Agrim | None |
| `frontend/src/investigations/IncidentTimeline.tsx` | Incident list | WORKING | Yes | None | types, ui | Agrim | None |
| `frontend/src/investigations/InvestigationWorkbench.tsx` | Investigation page | PARTIALLY IMPLEMENTED | Partly | Did not show the replay action | EvidenceGraph, HypothesisPanel, api, types, ui | Agrim | Added |
| `frontend/src/main.tsx` | React mount | WORKING | Yes | None | App | Lucky | None |
| `frontend/src/pages/CommandCenter.tsx` | Command Centre page | PARTIALLY IMPLEMENTED | Partly | No Agent 5 actions | AgentStatus, IncidentTimeline, ReplayInputNotice, api, types, ui | Lucky | Added panel |
| `frontend/src/replay/LiveFlowFeed.tsx` | Live table | PARTIALLY IMPLEMENTED | Partly | No Agent 5 column | types, ui | Lucky | Added |
| `frontend/src/replay/ReplayControls.tsx` | Start, pause, resume, stop | WORKING | Yes | None | types, ui | Lucky | None |
| `frontend/src/replay/ReplayLab.tsx` | Replay Lab page | PARTIALLY IMPLEMENTED | Partly | No policy activations | LiveFlowFeed, ReplayControls, ReplayInputNotice, ReplayTimeline, api, replay, types, ui | Lucky | Added |
| `frontend/src/replay/ReplayTimeline.tsx` | Progress | WORKING | Yes | None | types, ui | Lucky | None |
| `frontend/src/services/api.ts` | API client | WORKING | Yes | None | None internal | Lucky | None |
| `frontend/src/services/replay.ts` | SSE hook | PARTIALLY IMPLEMENTED | Partly | Ignored policy events | types | Lucky | Added |
| `frontend/src/services/types.ts` | TypeScript contracts | PARTIALLY IMPLEMENTED | Partly | No Agent 4 or 5 types | None internal | Lucky | Added; sync test extended |
| `frontend/src/styles/globals.css` | Base styles | WORKING | Yes | None | – | Lucky | None |
| `frontend/tailwind.config.js` | Theme | WORKING | Yes | None | – | Lucky | None |
| `frontend/tsconfig.json` | TypeScript | WORKING | Yes | None | – | Lucky | None |
| `frontend/vite.config.ts` | Dev server and API proxy | WORKING | Yes | None | None internal | Lucky | None |
| `pytest.ini` | Test settings | WORKING | Yes | None | – | Arush | None |
| `requirements.txt` | Python dependencies | WORKING | Yes | None | – | Arush | None |
| `scripts/calibrate_fusion.py` | Thresholds on training holdout | WORKING | Yes | None | agents.fusion_agent, config, evaluation.metrics, intelligence.campaign_engine, policy.policy_engine, preprocessing.data_processor, services.model_service | Arush | None |
| `scripts/evaluate.py` | Official evaluation | PARTIALLY IMPLEMENTED | Partly | Level 1 summary mixed in campaign results; no Modes A, B, C with common measures | agents.fusion_agent, config, evaluation.metrics, intelligence.campaign_engine, investigation.audit, policy.policy_engine, preprocessing.data_processor, replay.replay_engine, services.model_service | Arpit | Repaired |
| `scripts/leakage_audit.py` | Separability audit | WORKING | Yes | None | config, preprocessing.data_processor | Arpit | None |
| `scripts/profile_dataset.py` | Safe extraction, dataset profile | PARTIALLY IMPLEMENTED | Partly | No `dataset_profile.md`; no misleading-feature list | config | Arpit | Added |
| `scripts/run_all.sh` | Full rebuild | WORKING | Yes | None | – | Arush | Added rehearsal |
| `scripts/score_records.py` | Scores any flow file | WORKING | Yes | None | investigation.audit, preprocessing.data_processor, services.model_service | Arush | None; `run_level2.py` is the Level 2 path |
| `scripts/train_models.py` | Trains Agents 1 and 2 | WORKING | Yes | None | agents.anomaly_agent, agents.threat_agent, config, evaluation.metrics, preprocessing.data_processor | Arpit | None |
| `tests/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `tests/agents/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `tests/agents/test_agents.py` | Agent 2 and contracts | WORKING | Yes | None | agents.anomaly_agent, config, schemas.contracts | Arpit | None |
| `tests/agents/test_fusion.py` | Fusion | PARTIALLY IMPLEMENTED | Partly | Did not test the five conditions | agents.fusion_agent, policy.policy_engine, schemas.contracts | Arush | Extended |
| `tests/agents/test_preprocessing.py` | Preprocessing | PARTIALLY IMPLEMENTED | Partly | No standardisation or ordering tests | preprocessing.data_processor | Arpit | Extended |
| `tests/api/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `tests/api/test_api.py` | API on real data | PARTIALLY IMPLEMENTED | Partly | No Agent 5 test | None internal | Arush | Extended |
| `tests/api/test_contract_sync.py` | Python and TypeScript contracts match | WORKING | Yes | None | config, schemas | Arush | Extended |
| `tests/api/test_submission_adapter.py` | Adapter refuses without details | WORKING | Yes | None | api | Arush | None |
| `tests/conftest.py` | Shared fixtures on real models and data | WORKING | Yes | None | agents.threat_agent, config, main, services.app_state | Arush | None |
| `tests/integration/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `tests/integration/test_pipeline_e2e.py` | Full pipeline on real eval records | WORKING | Yes | None | config, schemas.contracts | Arush | None |
| `tests/intelligence/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arnav | None |
| `tests/intelligence/test_campaign_engine.py` | Campaign engine, synthetic | WORKING | Yes | None | intelligence.campaign_engine | Arnav | None |
| `tests/investigation/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arnav | None |
| `tests/investigation/test_investigation.py` | Tools and orchestrator, synthetic | PARTIALLY IMPLEMENTED | Partly | No SQLite test | agents.anomaly_agent, agents.investigation_orchestrator, intelligence.campaign_engine, investigation.audit, investigation.registry, investigation.tools, schemas.contracts | Arnav | Extended |
| `tests/policy/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `tests/policy/test_policy.py` | Policy | WORKING | Yes | None | agents.fusion_agent, policy.policy_engine | Arush | Status rename |
| `tests/replay/__init__.py` | Package marker | NOT REQUIRED | n/a | Intentionally empty | None internal | Arush | None |
| `tests/replay/test_replay.py` | Replay lifecycle on real records | WORKING | Yes | None | main | Arush | None |
| `data/raw/cyber-pack.zip` | Official archive, 74,987,240 bytes | WORKING | Yes | None | – | Arpit | Preserved |
| `data/raw/cyber-pack/ (directory)` | An unzipped copy from before the extraction step | DUPLICATE | n/a | Same files as `data/extracted/`; ignored by Git | – | Arpit | Left alone: it is your data, and it is harmless. Safe to delete by hand |
| `data/extracted/ (directory)` | Safely extracted pack | WORKING | Yes | None | – | Arpit | None |
| `data/processed/eval_predictions.parquet` | Saved predictions from evaluation | WORKING | Yes | None | – | Arpit | Regenerated |
| `data/processed/internal_splits.npz` | Internal train/selection/calibration indexes | WORKING | Yes | None | – | Arpit | None |
| `data/processed/replay_results.parquet` | Saved replay results | PARTIALLY IMPLEMENTED | Partly | From before Agents 4 and 5 | – | Arpit | Rejected on load; replaced by the next replay |
| `data/processed/replay_state.json` | Saved replay position | PARTIALLY IMPLEMENTED | Partly | From before Agents 4 and 5 | – | Arpit | Rejected on load; replaced by the next replay |
| `data/reports/train.log` | Training console log | WORKING | Yes | None | – | Arpit | None |
| `models/threat_model/threat_agent.joblib` | Agent 1 artifact, loads and reproduces metrics | WORKING | Yes | None | – | Arpit | None |
| `models/anomaly_model/anomaly_agent.joblib` | Agent 2 artifact, loads and scores | WORKING | Yes | None | – | Arnav | None |
| `frontend/dist/ (directory)` | Build output | NOT REQUIRED | n/a | Ignored by Git | – | Lucky | None |
| `frontend/node_modules/ (directory)` | Dependencies | NOT REQUIRED | n/a | Ignored by Git | – | Lucky | None |
| `.venv/ (directory)` | Python environment | NOT REQUIRED | n/a | Ignored by Git | – | Shared | None |
