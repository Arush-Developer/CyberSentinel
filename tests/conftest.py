"""Shared fixtures. real_data tests use the saved models and official eval records, and skip without them."""
import os

import pytest
from fastapi.testclient import TestClient

from backend.config import load_config, resolve
from backend.main import app

READY = (resolve(load_config()["models"]["threat"]).exists() and resolve(load_config()["models"]["anomaly"]).exists()
         and resolve(load_config()["data"]["eval_parquet"]).exists())


def pytest_configure(config):
    config.addinivalue_line("markers", "real_data: needs saved models and the extracted official dataset")


def pytest_collection_modifyitems(items):
    skip = pytest.mark.skip(reason="models or dataset not available")
    for item in items:
        if "real_data" in item.keywords and not READY:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def threat_agent():
    from backend.agents.threat_agent import ThreatAgent

    return ThreatAgent.load(resolve(load_config()["models"]["threat"]))


@pytest.fixture(scope="session")
def app_state():
    """Full pipeline over the real eval partition. Replay persistence is off so saved runs stay intact."""
    from backend.services.app_state import AppState

    return AppState.load(persist=False)


@pytest.fixture(scope="session")
def client(app_state):
    os.environ["CYBERSENTINEL_NO_AUTOLOAD"] = "1"
    with TestClient(app) as c:
        app.state.cs = app_state
        yield c
        app_state.replay.stop()
