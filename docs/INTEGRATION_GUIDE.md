# Integration guide

## Architecture

```
React + TypeScript + Vite        frontend/src
        │ REST and SSE (/api, proxied by Vite)
Python + FastAPI                 backend/api, backend/services/app_state.py
        │
Agent orchestration              backend/services/model_service.py, backend/agents
        │
ML models + campaign engine      models/, backend/intelligence
        │
Evidence, investigation, policy  backend/investigation, backend/policy, backend/replay
```

## Data flow

1. `scripts/profile_dataset.py` checks and extracts the ZIP into `data/extracted/` and writes `data/reports/dataset_profile.json`.
2. `scripts/train_models.py` trains on training data only, writing `models/threat_model/`, `models/anomaly_model/` and `training_report.json`.
3. `scripts/calibrate_fusion.py` sets thresholds from the internal calibration split, writing `configs/calibrated.json` and `configs/campaign_baseline.json`.
4. `scripts/evaluate.py` runs everything on the eval partition, writing the evaluation report, `level1_summary.json` and predictions.
5. `backend.main` loads the models, analyses the eval partition in a background thread, and serves the API.

A change to step 2 requires rerunning 3 and 4. `scripts/run_all.sh` runs them all, plus the leakage audit.

## Run

Backend, from the repository root:

```bash
.venv/bin/uvicorn backend.main:app --port 8000
```

Frontend, in a second terminal:

```bash
npm --prefix frontend run dev
```

Open http://localhost:5173. API docs are at http://localhost:8000/docs.

## Test

Everything (real-data tests skip if the models or dataset are absent):

```bash
.venv/bin/python -m pytest -q
```

Frontend typecheck and production build:

```bash
npm --prefix frontend run build
```

## Configuration

| Setting | Where | Default |
|---|---|---|
| Data and model paths, label mapping | `configs/default.yaml` | Relative to the repository root |
| Alternative config file | `CYBERSENTINEL_CONFIG` | `configs/default.yaml` |
| Backend address for the Vite proxy | `VITE_API_TARGET` | `http://127.0.0.1:8000` |
| Submission details | `configs/submission.yaml` (gitignored) | Absent: the adapter refuses to send |

## What is and is not committed

Committed: code, `configs/` (except `submission.yaml`), `docs/`, `tests/`, `data/reports/*.json`. Ignored: `data/raw`, `data/extracted`, `data/processed`, `models/**/*.joblib`, `.venv`, `node_modules`. Anyone cloning the repository needs the ZIP and must run `run_all.sh`.

## Adding things

- **New investigation tool:** write it in `investigation/tools.py`, add it to `registry.TOOLS` and `plan()` in the orchestrator, add a test.
- **New campaign detector:** add it to `CampaignTracker`, add its type to `COMPATIBLE_CLASSES` and `HYPOTHESES`, and test it with fixtures labelled synthetic.
- **New endpoint:** add the schema to `contracts.py`, the logic to `services/app_state.py`, the route to `api/routes.py`, the type to `frontend/src/services/types.ts`, and a row to `docs/API.md`.
- **New screen:** add it in the owning folder under `frontend/src/`, with a route in `app/router.tsx` and a nav entry in `components/Sidebar.tsx`.
- **Retraining:** do model selection and threshold work on the internal splits. Do not tune on eval.

## Merging team branches

See [TEAM_HANDOFF.md](TEAM_HANDOFF.md#git-workflow). After each merge, run the tests and the frontend build above.

## When the hidden set arrives

1. Confirm the file has the 78 feature columns, then run `scripts/score_records.py`.
2. If `source_ip`, `destination_ip` and `seq` or `timestamp` are present, the campaign engine switches to endpoint mode by itself.
3. Those detectors have only been tested on synthetic fixtures, so review the campaigns before relying on them. Column names are assumed from the pack README; if they differ, change `metadata_columns` in `configs/default.yaml` and rename at load time.
4. Replay and the dashboard read the eval partition. To show hidden data, add the partition to `load_partition` and pass it to `AppState.load`.

## Troubleshooting

- **Dashboard says backend unreachable:** start uvicorn on port 8000.
- **503 from data endpoints:** models are still loading, or `/api/health` gives the reason they failed.
- **Unstyled page:** rerun `npm --prefix frontend ci`.
- **Replay shows old progress:** it restores from `data/processed/replay_state.json`. Press Start for a fresh run, or delete that file and `replay_results.parquet` with the backend stopped.
