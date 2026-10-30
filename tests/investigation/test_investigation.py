"""SYNTHETIC flows only. These verify tool and orchestrator logic."""
import threading

import numpy as np
import pandas as pd
import pytest

from backend.agents.anomaly_agent import AnomalyAgent
from backend.agents.investigation_orchestrator import (
    TRIGGER_DISAGREEMENT, TRIGGER_HIGH_ANOMALY, VERDICT_CONFLICTING, InvestigationCancelled, Orchestrator, plan)
from backend.intelligence.campaign_engine import DOS
from backend.investigation.audit import AuditLog
from backend.investigation.registry import ToolRegistry
from backend.investigation.tools import EvidenceStore
from backend.schemas.contracts import InvestigationResult


def base_features(n, port=443.0, fwd=10.0, rate=5.0):
    return pd.DataFrame({
        "Destination Port": np.full(n, port), "Flow Packets/s": np.full(n, rate),
        "Flow Bytes/s": np.full(n, 100.0), "Total Fwd Packets": np.full(n, fwd),
        "Flow Duration": np.full(n, 1000.0), "Extra": np.arange(n, dtype=float) % 7,
    })


@pytest.fixture()
def store():
    n = 200
    features = base_features(n)
    features["Flow Packets/s"] = 5.0 + np.arange(n) % 3
    agent = AnomalyAgent.train(features, n_estimators=10, max_samples=100)
    agent.calibrate(features, 0.05)
    meta = pd.DataFrame({"flow_id": [f"C{i:05d}" for i in range(n)],
                         "destination_port": features["Destination Port"].to_numpy()})
    anomaly = np.zeros(n)
    anomaly[0] = 0.99
    cids = np.full(n, None, dtype=object)
    cids[0] = "CMP-00001"
    features.loc[0, "Flow Packets/s"] = 1e6
    return EvidenceStore(
        flow_ids=meta["flow_id"].to_numpy(), features=features, metadata=meta,
        threat_class=np.array(["BENIGN"] * n), threat_confidence=np.full(n, 0.9), anomaly_score=anomaly,
        is_anomaly=anomaly >= 0.95, flow_campaign=cids,
        campaigns={"CMP-00001": {"campaign_type": DOS, "flow_count": 10, "confidence": "low", "confidence_basis": "x"}},
        anomaly_agent=agent)


def test_tools_cite_real_values_and_refuse_absent_metadata(store):
    audit = AuditLog()
    registry = ToolRegistry(store, audit)
    deviations = registry.call("inspect_feature_deviations", "I1", flow_id="C00000")
    assert deviations["status"] == "ok"
    assert deviations["result"]["evidence"]["deviations"][0]["measured_value"] == 1e6
    source = registry.call("inspect_source_activity", "I1", flow_id="C00000")
    assert source["result"]["available"] is False and "absent" in source["result"]["summary"]
    assert len(audit.list("tool_call")) == 2
    registry.close()


def test_unknown_tool_and_failing_tool_are_contained(store):
    registry = ToolRegistry(store, AuditLog())
    with pytest.raises(KeyError):
        registry.call("drop_firewall", "I1")
    bad = registry.call("inspect_campaign_context", "I1", flow_id="NOPE")
    assert bad["status"] == "error" and bad["result"]["available"] is False
    registry.close()


def test_investigation_budget_and_audit(store):
    audit = AuditLog()
    registry = ToolRegistry(store, audit)
    result = Orchestrator(registry).investigate("C00000", [TRIGGER_DISAGREEMENT, TRIGGER_HIGH_ANOMALY])
    assert 1 <= len(result["tool_calls"]) <= 3
    assert result["planner"] == "deterministic"
    assert result["tools_selected"] == [c["tool"] for c in result["tool_calls"]]
    InvestigationResult(**result)  # Matches the shared contract.
    assert audit.list("investigation_finished")[0]["flow_id"] == "C00000"
    registry.close()


def test_investigation_cancels(store):
    registry = ToolRegistry(store, AuditLog())
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(InvestigationCancelled):
        Orchestrator(registry, cancel=cancel).investigate("C00000", [TRIGGER_DISAGREEMENT])
    registry.close()


def test_planner_prefers_available_evidence():
    assert "inspect_source_activity" not in plan([TRIGGER_DISAGREEMENT], has_endpoints=False)
    assert "inspect_source_activity" in plan([TRIGGER_DISAGREEMENT], has_endpoints=True)


def test_conclusion_records_conflict():
    calls = [
        {"tool": "t1", "result": {"available": True, "supports": "attack", "summary": "a"}},
        {"tool": "t2", "result": {"available": True, "supports": "benign", "summary": "b"}},
    ]
    out = Orchestrator._conclude("I", "F", [], calls)
    assert out["verdict"] == VERDICT_CONFLICTING
    assert out["supporting_observations"] == ["a"] and out["contradicting_observations"] == ["b"]
