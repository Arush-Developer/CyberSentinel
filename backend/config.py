"""Loads configs/default.yaml. Paths in the config are relative to the repository root."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
# CYBERSENTINEL_CONFIG points at an alternative config file; relative paths inside it still use ROOT.
CONFIG_PATH = Path(os.environ.get("CYBERSENTINEL_CONFIG", ROOT / "configs" / "default.yaml"))


@lru_cache(maxsize=1)
def load_config() -> dict:
    return yaml.safe_load(CONFIG_PATH.read_text())


def resolve(path: str) -> Path:
    return ROOT / path
