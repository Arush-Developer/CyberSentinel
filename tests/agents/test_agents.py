"""Agent independence and output contracts. Synthetic data unless marked real_data."""
import ast
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from backend.agents.anomaly_agent import AnomalyAgent
from backend.config import ROOT
from backend.schemas.contracts import AnomalyAssessment, ThreatAssessment


def test_anomaly_agent_imports_nothing_from_threat_agent():
    tree = ast.parse(Path(ROOT, "backend/agents/anomaly_agent.py").read_text())
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any("threat" in name or "fusion" in name for name in imported)


def test_anomaly_scores_unusual_flow_higher_and_keeps_percentile_meaning():
    rng = np.random.default_rng(0)
    frame = pd.DataFrame(rng.normal(100, 5, size=(3000, 8)), columns=[f"f{i}" for i in range(8)])
    agent = AnomalyAgent.train(frame.iloc[:2000], n_estimators=40, max_samples=256)
    agent.calibrate(frame.iloc[2000:], target_fpr=0.05)
    unusual = pd.DataFrame([[500.0] * 8], columns=frame.columns)
    assert agent.score(unusual)[0] >= agent.threshold
    assert 0.0 <= agent.score(frame.iloc[:50]).min() and agent.score(frame.iloc[:50]).max() <= 1.0
    flagged = (agent.score(frame.iloc[2000:]) >= agent.threshold).mean()
    assert flagged <= 0.08
    evidence = agent.supporting_features(unusual)[0]
    assert evidence[0]["deviation"] == "high" and evidence[0]["measured_value"] == 500.0
    output = agent.to_output("S1", float(agent.score(unusual)[0]), evidence)
    AnomalyAssessment(**output)
    assert output["flow_id"] == "S1"
    assert "not a probability" in output["score_meaning"]


@pytest.mark.real_data
def test_saved_threat_agent_loads_and_rejects_missing_columns(threat_agent):
    agent = threat_agent
    assert "record_id" not in agent.pipeline.columns_ and "label" not in agent.pipeline.columns_
    with pytest.raises(ValueError):
        agent.predict_proba(pd.DataFrame({"Flow Duration": [1.0]}))


@pytest.mark.real_data
def test_threat_agent_output_matches_contract(threat_agent):
    row = np.array([0.1, 0.1, 0.1, 0.6, 0.1])
    output = threat_agent.to_output("C1", row)
    ThreatAssessment(**output)
    assert output["flow_id"] == "C1" and output["predicted_class"] == "DDOS" and output["confidence"] == 0.6
