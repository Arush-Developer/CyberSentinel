"""One complete run over actual official validation records, with no synthetic data."""
import numpy as np
import pytest

from backend.config import load_config, resolve
from backend.schemas.contracts import CampaignRecord, FlowDetail, InvestigationResult

pytestmark = pytest.mark.real_data
CLASSES = load_config()["labels"]["classes"]


def test_all_records_are_processed_with_valid_outputs(app_state):
    frame = app_state.analysis.frame
    assert len(frame) == 114185
    assert set(frame["final_class"]) <= set(CLASSES)
    assert set(frame["policy_decision"]) == {"ALLOW", "BLOCK", "REVIEW"}
    assert frame["anomaly_score"].between(0, 1).all()


def test_agent1_matches_saved_evaluation_report(app_state):
    labels = app_state.analysis.partition.labels.to_numpy()
    accuracy = float((app_state.analysis.frame["threat_class"].to_numpy() == labels).mean())
    report = app_state.report("evaluation_report")
    assert accuracy == pytest.approx(report["agent1"]["accuracy"], abs=1e-9)


def test_agent2_scores_do_not_depend_on_agent1(app_state):
    pipe, part = app_state.pipeline, app_state.analysis.partition
    alone = pipe.anomaly.score(part.features.iloc[:2000])
    assert np.array_equal(alone, app_state.analysis.scores[:2000])


def test_labels_never_reach_the_models(app_state):
    columns = set(app_state.pipeline.threat.pipeline.columns_) | set(app_state.pipeline.anomaly.pipeline.columns_)
    assert not columns & {"label", "record_id", "flow_id", "ground_truth_evaluation_only"}
    assert "label" not in app_state.analysis.partition.features


def test_campaign_correlation_on_real_records_matches_contract(app_state):
    campaigns = app_state.analysis.campaign.campaigns
    assert app_state.analysis.campaign.mode == "cohort" and campaigns
    for record in campaigns:
        CampaignRecord(**record)
        assert record["distinct_sources"] is None
        assert record["relationships"] and record["relationships"][0]["source"] is None
    known = set(app_state.analysis.frame["flow_id"])
    assert set(campaigns[0]["related_flow_ids"]) <= known


def test_disagreement_investigation_decision_and_audit_on_a_real_flow(app_state):
    frame = app_state.analysis.frame
    flow_id = str(frame.loc[frame["agreement"] == "DISAGREE", "flow_id"].iloc[0])
    detail = app_state.flow_detail(flow_id)
    parsed = FlowDetail(**detail)
    assert parsed.investigation is not None and parsed.fusion.agreement == "DISAGREE"
    assert parsed.fusion.investigation_refs == [parsed.investigation.investigation_id]
    assert f"investigation:{parsed.investigation.investigation_id}" in parsed.policy.evidence_refs
    assert 1 <= len(parsed.investigation.tool_calls) <= 3
    InvestigationResult(**detail["investigation"])
    events = app_state.audit.list("tool_call", limit=100)
    assert any(e["investigation_id"] == parsed.investigation.investigation_id for e in events)


def test_evaluation_reports_are_still_accessible(app_state):
    for name in ("evaluation_report", "training_report", "calibration_report", "leakage_audit", "level1_summary"):
        assert app_state.report(name), name
    assert resolve(load_config()["data"]["reports_dir"]).is_dir()
