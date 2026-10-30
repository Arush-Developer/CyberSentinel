#!/usr/bin/env bash
# Rebuilds every model and report from the official ZIP. Run from the repository root.
set -euo pipefail
PY="${PY:-.venv/bin/python}"
"$PY" scripts/profile_dataset.py
"$PY" scripts/train_models.py
"$PY" scripts/leakage_audit.py
"$PY" scripts/calibrate_fusion.py
"$PY" scripts/evaluate.py
