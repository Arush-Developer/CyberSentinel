"""Restart behaviour on real validation records. Saved state goes to a temporary folder."""
import time

import pandas as pd
import pytest

from backend.investigation.audit import AuditLog
from backend.replay import replay_engine
from backend.replay.replay_engine import ReplayEngine
from backend.services import app_state as app_state_module
from backend.services.app_state import AppState
from backend.services.model_service import Pipeline

pytestmark = pytest.mark.real_data


@pytest.fixture()
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(replay_engine, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(replay_engine, "RESULTS_FILE", str(tmp_path / "results.parquet"))
    monkeypatch.setattr(app_state_module, "AUDIT_DB", str(tmp_path / "audit.sqlite3"))
    return tmp_path


def test_replay_restores_after_restart_and_resumes_cleanly(isolated, app_state):
    engine = ReplayEngine(app_state.pipeline, app_state.analysis, AuditLog(), persist=True)
    engine.start(speed=2000, batch_size=500, limit=3000, max_investigations_per_batch=0)
    while engine.cursor < 300:
        time.sleep(0.01)
    engine.stop()
    assert 0 < engine.cursor < 3000

    restored = ReplayEngine(app_state.pipeline, app_state.analysis, AuditLog(), persist=True)
    assert restored.status == "stopped" and restored.cursor == len(restored.replayed_frame())
    assert restored.counts["total"] == restored.cursor
    restored.start(speed=100_000, batch_size=500, limit=3000, max_investigations_per_batch=0, resume_saved=True)
    restored._thread.join(timeout=30)
    frame = restored.replayed_frame()
    assert restored.status == "completed" and len(frame) == 3000 and frame["flow_id"].is_unique
    expected = app_state.analysis.partition.metadata["flow_id"].to_numpy()[restored.order[:3000]]
    assert frame["flow_id"].tolist() == expected.tolist()


def test_saved_results_from_an_older_version_are_rejected_not_mixed_in(isolated, app_state):
    engine = ReplayEngine(app_state.pipeline, app_state.analysis, AuditLog(), persist=True)
    engine.start(speed=100_000, batch_size=500, limit=1000, max_investigations_per_batch=0)
    engine._thread.join(timeout=30)
    results = isolated / "results.parquet"
    pd.read_parquet(results).drop(columns=["defense_action"]).to_parquet(results, index=False)
    audit = AuditLog()
    restored = ReplayEngine(app_state.pipeline, app_state.analysis, audit, persist=True)
    assert restored.status == "idle" and restored.cursor == 0 and not restored.results
    assert audit.list("replay_error")


def test_policy_changes_and_audit_survive_a_restart(isolated, app_state):
    first = AppState(Pipeline.load(), app_state.analysis, persist=True)
    new = {**first.pipeline.thresholds.to_dict(), "allow_benign_confidence": 0.97}
    first.configure_policy(new, "tighter for the test")
    first.audit.close()
    second = AppState(Pipeline.load(), app_state.analysis, persist=True)
    assert second.pipeline.thresholds.allow_benign_confidence == 0.97
    assert second.policy_history[-1]["reason"] == "tighter for the test"
    assert second.audit.list("policy_change")
    # The analysis frame is shared in this test, so put its decisions back for later tests.
    second._apply_thresholds(app_state.pipeline.thresholds.to_dict())
    second.audit.close()
