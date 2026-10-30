# Integration guide

## Data flow

1. `scripts/profile_dataset.py` checks and extracts the ZIP and writes `data/reports/dataset_profile.json`.
2. `scripts/train_models.py` trains on training data only and writes `models/*.joblib` and `training_report.json`.
3. `scripts/calibrate_fusion.py` sets thresholds from the internal calibration split and writes `configs/calibrated.json` and `configs/campaign_baseline.json`.
4. `scripts/evaluate.py` runs everything on the eval partition and writes the evaluation report, `level1_summary.json` and predictions.
5. `backend.main` loads the models, analyses the eval partition in a background thread, and serves the API.
6. The React app talks to `/api`, which Vite proxies to port 8000.

Order matters: a change to step 2 requires rerunning 3 and 4. `scripts/run_all.sh` runs them all, plus the leakage audit.

## What is and is not committed

Committed: code, `configs/`, `docs/`, `tests/`, `data/reports/*.json`. Ignored: `data/raw`, `data/extracted`, `data/processed`, `models/*.joblib`, `.venv`, `node_modules`. Anyone cloning the repository needs the ZIP and must run `run_all.sh`.

## Adding things

- **New investigation tool:** write it in `investigation/tools.py`, add it to `registry.TOOLS` and `plan()` in the orchestrator, add a test.
- **New campaign detector:** add it to `CampaignTracker`, add its type to `COMPATIBLE_CLASSES`, and test it with fixtures labelled synthetic.
- **New endpoint:** add the schema to `contracts.py`, the logic to `services/state.py`, the route to `api/routes.py`, the type to `frontend/src/services/api.ts`, and a row to `docs/API.md`.
- **New screen:** add a page in `frontend/src/pages/` and a route and nav entry in `app/App.tsx`.
- **Retraining:** do model selection and threshold work on the internal splits. Do not tune on eval.

## When the hidden set arrives

1. Confirm the file has the 78 feature columns, then run `scripts/score_records.py`.
2. If `source_ip`, `destination_ip` and `seq` or `timestamp` are present, the campaign engine switches to endpoint mode by itself.
3. Those detectors have only been tested on synthetic fixtures, so review the campaigns before relying on them. Column names are assumed from the pack README; if they differ, change `metadata_columns` in `configs/default.yaml` and rename at load time.
4. Replay and the dashboard read the eval partition. To show hidden data, pass `partition` through `AppState.load` and add the partition to `load_partition`.

## Level 2

The requirements have not been shared yet, so nothing assumes them. Keep the Day 1 state preserved first: see [TEAM_HANDOFF.md](TEAM_HANDOFF.md).

## Troubleshooting

- **Dashboard says backend unreachable:** start uvicorn on port 8000.
- **503 from data endpoints:** models are still loading, or `/api/health` gives the reason they failed.
- **`Unstyled page`:** rerun `npm --prefix frontend ci`; Tailwind and PostCSS configs are in `frontend/`.
- **Replay shows old progress:** it restores from `data/processed/replay_state.json`. Press Start for a fresh run, or delete that file and `replay_results.parquet`.
