"""Each registered tool, run through the registry against real official eval records."""
import pytest

from backend.investigation.audit import AuditLog
from backend.investigation.registry import TOOLS, ToolRegistry

pytestmark = pytest.mark.real_data
REQUIRED = {"inspect_feature_deviations", "compare_against_benign_baseline", "find_related_flows",
            "inspect_source_activity", "inspect_destination_activity", "inspect_port_distribution",
            "inspect_campaign_context", "inspect_agent_disagreement"}


def test_all_eight_required_tools_are_registered():
    assert set(TOOLS) == REQUIRED


@pytest.mark.parametrize("tool", sorted(REQUIRED))
def test_tool_executes_against_real_records(app_state, tool):
    frame = app_state.analysis.frame
    flow_id = str(frame.loc[frame["campaign_id"].notna(), "flow_id"].iloc[0])
    audit = AuditLog()
    registry = ToolRegistry(app_state.analysis.store, audit)
    try:
        call = registry.call(tool, "INV-test", flow_id=flow_id)
    finally:
        registry.close()
    assert call["status"] == "ok" and call["result"]["summary"]
    assert audit.list("tool_call")[0]["tool"] == tool
    if tool in ("inspect_source_activity", "inspect_destination_activity"):
        # The participant pack has no addresses, so these must say so, not invent an answer.
        assert call["result"]["available"] is False and "absent" in call["result"]["summary"]
    else:
        assert call["result"]["available"] is True
    if tool == "inspect_campaign_context":
        assert call["result"]["evidence"]["campaign_id"] == frame.loc[frame["flow_id"] == flow_id, "campaign_id"].iloc[0]


def test_tool_outputs_are_reproducible(app_state):
    flow_id = str(app_state.analysis.frame["flow_id"].iloc[100])
    registry = ToolRegistry(app_state.analysis.store, AuditLog())
    try:
        first = registry.call("inspect_feature_deviations", "A", flow_id=flow_id)["result"]
        second = registry.call("inspect_feature_deviations", "B", flow_id=flow_id)["result"]
    finally:
        registry.close()
    assert first == second
