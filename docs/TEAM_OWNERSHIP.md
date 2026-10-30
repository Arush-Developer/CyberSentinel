# Team ownership

This table records who is responsible for each module, not who wrote it. The first version of this code was generated with Claude Code from the team brief. A person owns a module once they have reviewed it, can explain it, and have contributed to it. Use real commits under your own name for that work; do not attribute generated code to anyone.

| Owner | Area | Files |
|---|---|---|
| **Arush** | Architecture, orchestration, backend, submission | `backend/agents/fusion_agent.py`, `backend/agents/investigation_orchestrator.py`, `backend/pipeline.py`, `backend/policy/policy_engine.py`, `backend/replay/replay_engine.py`, `backend/api/routes.py`, `backend/services/state.py`, `backend/schemas/contracts.py`, `backend/main.py`, `backend/submission/level1_adapter.py`, `scripts/calibrate_fusion.py`, `scripts/score_records.py`, `tests/test_fusion_policy.py`, `tests/test_api_replay.py` |
| **Arpit** | Data engineering, supervised ML | `scripts/profile_dataset.py`, `backend/preprocessing/data_processor.py`, `backend/agents/threat_agent.py`, `backend/evaluation/metrics.py`, `scripts/train_models.py`, `scripts/leakage_audit.py`, `scripts/evaluate.py`, `configs/default.yaml`, `tests/test_preprocessing.py` |
| **Arnav** | Anomaly detection, campaign intelligence, investigation tools | `backend/agents/anomaly_agent.py`, `backend/intelligence/campaign_engine.py`, `backend/intelligence/evidence_engine.py`, `backend/investigation/tools.py`, `backend/investigation/registry.py`, `backend/investigation/audit.py`, `tests/test_campaign_investigation.py`, `tests/test_submission_and_agents.py` (agent parts) |
| **Lucky** | Frontend foundation | `frontend/src/app/App.tsx`, `frontend/src/components/ui.tsx`, `frontend/src/services/api.ts`, `frontend/src/index.css`, `frontend/tailwind.config.js`, `frontend/vite.config.ts`, `frontend/src/pages/CommandCentre.tsx`, `frontend/src/pages/ReplayLab.tsx` |
| **Agrim** | Frontend intelligence and visualisation | `frontend/src/pages/AttackIntelligence.tsx`, `frontend/src/pages/InvestigationWorkbench.tsx`, `frontend/src/pages/ModelIntelligence.tsx`, `frontend/src/pages/DefenceAudit.tsx`, `frontend/src/components/EvidenceGraph.tsx` |

Changes that cross a boundary go through the contracts in [MODULE_CONTRACTS.md](MODULE_CONTRACTS.md).
