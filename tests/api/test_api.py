"""API tests over the real models and real validation records. Skipped when those are absent."""
import pytest

pytestmark = pytest.mark.real_data


def test_health_and_model_status(client):
    assert client.get("/api/health").json()["status"] == "ok"
    status = client.get("/api/models/status").json()
    assert status["campaign_mode"] == "cohort"
    assert status["threat_features"] > 50 and status["llm_in_use"] is False


def test_flow_detail_has_all_agent_outputs(client):
    item = client.get("/api/flows", params={"scope": "historical", "limit": 1}).json()["items"][0]
    detail = client.get(f"/api/flows/{item['flow_id']}").json()
    assert detail["threat"]["agent"] == "threat_detection"
    assert abs(sum(detail["threat"]["probabilities"].values()) - 1) < 1e-6
    assert detail["anomaly"]["agent"] == "anomaly_detection"
    assert detail["fusion"]["final_class"] in detail["threat"]["probabilities"]
    assert detail["policy"]["decision"] in ("ALLOW", "BLOCK", "REVIEW") and detail["policy"]["simulated"]
    assert detail["evidence_graph"]["nodes"] and detail["evidence_graph"]["edges"]
    assert detail["threat"]["flow_id"] == detail["anomaly"]["flow_id"] == detail["fusion"]["flow_id"] == item["flow_id"]
    assert f"flow:{item['flow_id']}" in detail["policy"]["evidence_refs"] and detail["policy"]["policy_rule"]


def test_disagreement_triggers_a_real_investigation(client):
    item = client.get("/api/flows", params={"scope": "historical", "disagree": True, "limit": 1}).json()["items"][0]
    detail = client.get(f"/api/flows/{item['flow_id']}").json()
    inv = detail["investigation"]
    assert inv and "AGENT_DISAGREEMENT" in inv["triggers"] and 1 <= len(inv["tool_calls"]) <= 3
    assert client.get(f"/api/investigations/{inv['investigation_id']}").json()["flow_id"] == item["flow_id"]
    assert client.get("/api/audit", params={"kind": "tool_call"}).json()["items"]


def test_unknown_flow_is_404(client):
    assert client.get("/api/flows/NOPE").status_code == 404


def test_analyse_rejects_incomplete_features(client):
    assert client.post("/api/flows/analyse", json={"features": {"Flow Duration": 1.0}}).status_code == 422


def test_campaigns_disclose_limitations(client):
    body = client.get("/api/campaigns", params={"scope": "historical"}).json()
    assert body["mode"] == "cohort" and body["limitations"] and body["items"]
    assert all(c["distinct_sources"] is None for c in body["items"])


def test_policy_simulation_does_not_change_state_but_configure_does(client):
    policy = client.get("/api/policy").json()["thresholds"]
    stricter = {**policy, "allow_benign_confidence": 0.9999999}
    before = client.get("/api/policy").json()["thresholds"]
    sim = client.post("/api/policy/simulate", json={"thresholds": stricter}).json()
    assert sim["flows_evaluated"] > 100_000 and sim["previous_thresholds"] == before
    assert client.get("/api/policy").json()["thresholds"] == before
    updated = client.post("/api/policy/configure", json={"thresholds": stricter, "reason": "test"}).json()
    assert updated["history"][-1]["previous"] == before
    client.post("/api/policy/configure", json={"thresholds": before, "reason": "restore"})
    assert client.get("/api/audit", params={"kind": "policy_change"}).json()["items"]


def test_policy_rejects_out_of_range(client):
    policy = client.get("/api/policy").json()["thresholds"]
    assert client.post("/api/policy/simulate", json={"thresholds": {**policy, "allow_benign_confidence": 2}}).status_code == 422


def test_metrics_come_from_saved_reports(client):
    metrics = client.get("/api/metrics").json()
    assert metrics["evaluation_report"]["system"]["rows"] == 114185
    assert metrics["training_report"]["eval_partition_used"] is False
