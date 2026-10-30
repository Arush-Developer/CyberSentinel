"""Replay over real validation records, with persistence off. Skipped when those are absent."""
import time

import pytest

from backend.main import app

pytestmark = pytest.mark.real_data


def wait_for(client, predicate, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        status = client.get("/api/replay/status").json()
        if predicate(status):
            return status
        time.sleep(0.05)
    raise AssertionError(f"timed out; last status {status}")


def test_replay_lifecycle_and_stop_is_immediate(client):
    start = client.post("/api/replay/start", json={"speed": 2000, "batch_size": 500, "limit": 100000})
    assert start.status_code == 200
    assert client.post("/api/replay/start", json={}).status_code == 409
    wait_for(client, lambda s: s["cursor"] > 200)
    paused = client.post("/api/replay/pause").json()
    assert paused["status"] == "paused"
    time.sleep(0.3)
    held = client.get("/api/replay/status").json()["cursor"]
    time.sleep(0.3)
    assert client.get("/api/replay/status").json()["cursor"] == held
    assert client.post("/api/replay/resume").json()["status"] == "running"
    wait_for(client, lambda s: s["cursor"] > held)
    t0 = time.time()
    stopped = client.post("/api/replay/stop").json()
    assert stopped["status"] == "stopped" and time.time() - t0 < 2
    cursor = stopped["cursor"]
    time.sleep(0.3)
    assert client.get("/api/replay/status").json()["cursor"] == cursor
    assert cursor < 100000


def test_replay_matches_batch_analysis_and_emits_real_events(client):
    client.post("/api/replay/start", json={"speed": 100000, "batch_size": 500, "limit": 2000})
    done = wait_for(client, lambda s: s["status"] == "completed")
    counts = done["counts"]
    assert counts["total"] == 2000 == sum(counts["decisions"].values()) == sum(counts["classes"].values())
    flows = client.get("/api/flows", params={"scope": "replay", "limit": 500}).json()
    assert flows["total"] == 2000
    state = app.state.cs
    for item in flows["items"][:50]:
        row = state.flow_row(item["flow_id"])
        assert item["threat_class"] == state.analysis.frame["threat_class"].iat[row]
        assert abs(item["anomaly_score"] - state.analysis.frame["anomaly_score"].iat[row]) < 1e-9
    body = client.get("/api/replay/events", params={"once": True}).text
    assert "event: flows" in body


def test_replay_rejects_control_when_idle(client):
    client.post("/api/replay/stop")
    assert client.post("/api/replay/pause").status_code == 409
    assert client.post("/api/replay/resume").status_code == 409


