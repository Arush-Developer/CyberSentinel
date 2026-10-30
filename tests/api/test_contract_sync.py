"""The TypeScript interfaces must carry the same fields as the Pydantic contracts."""
import re

import pytest

from backend.config import ROOT
from backend.schemas import contracts

TYPES = (ROOT / "frontend/src/services/types.ts").read_text()
SHARED = ["ThreatAssessment", "SupportingFeature", "AnomalyAssessment", "CampaignRelationship", "CampaignRecord",
          "ToolResult", "ToolCall", "InvestigationResult", "FusionAssessment", "PolicyOutcome", "FlowDetail",
          "Thresholds", "ReplayStatus", "ModelStatusResponse", "CorrelationEvidence", "CorrelationGroup",
          "DefensePolicy", "DefenseState", "FlowDefense"]
TS_NAME = {"ModelStatusResponse": "ModelStatus"}


def ts_fields(name: str) -> set[str]:
    match = re.search(rf"export interface {name} \{{(.*?)^\}}", TYPES, re.S | re.M)
    assert match, f"{name} is missing from types.ts"
    # Top-level members sit at two-space indentation; nested object members are deeper.
    return set(re.findall(r"^  (\w+)\??:", match.group(1), re.M))


@pytest.mark.parametrize("model", SHARED)
def test_typescript_matches_pydantic(model):
    assert ts_fields(TS_NAME.get(model, model)) == set(getattr(contracts, model).model_fields)
