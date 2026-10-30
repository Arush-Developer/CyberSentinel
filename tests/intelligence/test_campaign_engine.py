"""SYNTHETIC flows only. These verify detector logic and say nothing about the real dataset."""
import numpy as np
import pandas as pd

from backend.intelligence.campaign_engine import (
    BRUTE, DDOS, DOS, SCAN, VOLUMETRIC, CampaignConfig, CampaignEngine, detect_mode)


def base_features(n, port=443.0, fwd=10.0, rate=5.0):
    return pd.DataFrame({
        "Destination Port": np.full(n, port), "Flow Packets/s": np.full(n, rate),
        "Flow Bytes/s": np.full(n, 100.0), "Total Fwd Packets": np.full(n, fwd),
        "Flow Duration": np.full(n, 1000.0), "Extra": np.arange(n, dtype=float) % 7,
    })


def endpoint_meta(sources, destinations, ports):
    n = len(sources)
    return pd.DataFrame({"flow_id": [f"S{i:05d}" for i in range(n)], "source_ip": sources,
                         "destination_ip": destinations, "destination_port": ports, "seq": np.arange(n)})


def test_mode_selection_follows_available_metadata():
    features = base_features(5)
    assert detect_mode(endpoint_meta(["a"] * 5, ["b"] * 5, [1] * 5), features)[0] == "endpoint"
    assert detect_mode(pd.DataFrame({"flow_id": ["C1"] * 5}), features)[0] == "cohort"
    assert detect_mode(pd.DataFrame({"x": [1]}), pd.DataFrame({"y": [1]}))[0] == "disabled"


def test_ddos_needs_many_sources_and_dos_few():
    engine = CampaignEngine(CampaignConfig(window_flows=100))
    n = 100
    anomaly = np.ones(n, bool)
    ddos = engine.detect(endpoint_meta([f"10.0.0.{i % 40}" for i in range(n)], ["9.9.9.9"] * n, [80] * n),
                         base_features(n), anomaly)
    assert [c["campaign_type"] for c in ddos.campaigns] == [DDOS]
    assert ddos.campaigns[0]["distinct_sources"] == 40
    dos = engine.detect(endpoint_meta(["10.0.0.1"] * n, ["9.9.9.9"] * n, [80] * n), base_features(n), anomaly)
    assert [c["campaign_type"] for c in dos.campaigns] == [DOS]


def test_normal_traffic_makes_no_campaign():
    engine = CampaignEngine(CampaignConfig(window_flows=100))
    n = 100
    result = engine.detect(endpoint_meta(["10.0.0.1"] * n, ["9.9.9.9"] * n, [443] * n),
                           base_features(n), np.zeros(n, bool))
    assert result.campaigns == []


def test_port_scan_and_brute_force_patterns():
    engine = CampaignEngine(CampaignConfig(window_flows=100))
    scan = engine.detect(endpoint_meta(["10.0.0.5"] * 100, ["9.9.9.9"] * 100, list(range(1000, 1100))),
                         base_features(100, fwd=1.0), np.zeros(100, bool))
    assert scan.campaigns[0]["campaign_type"] == SCAN
    assert scan.campaigns[0]["supporting_evidence"][0]["distinct_destination_ports"] == 100
    brute = engine.detect(endpoint_meta(["10.0.0.5"] * 10, ["9.9.9.9"] * 10, [22] * 10),
                          base_features(10, port=22.0), np.zeros(10, bool))
    assert brute.campaigns[0]["campaign_type"] == BRUTE
    assert "behavioural indicator" in brute.campaigns[0]["confidence_basis"].lower()
    assert "no authentication events" in brute.campaigns[0]["confidence_basis"]


def test_cohort_mode_withholds_source_claims():
    engine = CampaignEngine(CampaignConfig(window_flows=100))
    meta = pd.DataFrame({"flow_id": [f"C{i:06d}" for i in range(100)]})
    result = engine.detect(meta, base_features(100, port=80.0), np.ones(100, bool))
    assert result.mode == "cohort" and result.limitations
    assert result.campaigns[0]["campaign_type"] == VOLUMETRIC
    assert result.campaigns[0]["distinct_sources"] is None


def test_adjacent_windows_merge():
    engine = CampaignEngine(CampaignConfig(window_flows=50))
    result = engine.detect(endpoint_meta(["10.0.0.1"] * 150, ["9.9.9.9"] * 150, [80] * 150),
                           base_features(150), np.ones(150, bool))
    assert len(result.campaigns) == 1
    assert result.campaigns[0]["campaign_type"] == DOS
    assert result.campaigns[0]["windows_observed"] == 3 and result.campaigns[0]["flow_count"] == 150
    assert all(cid == "CMP-00001" for cid in result.flow_campaign)


def test_signals_mark_conflicts():
    engine = CampaignEngine(CampaignConfig(window_flows=100))
    result = engine.detect(endpoint_meta(["10.0.0.1"] * 100, ["9.9.9.9"] * 100, [80] * 100),
                           base_features(100), np.ones(100, bool))
    predicted = np.array(["DOS"] * 50 + ["BENIGN"] * 25 + ["PORT_SCAN"] * 25)
    support, conflict = result.signals(predicted)
    assert support[:75].all() and conflict[75:].all() and not conflict[:75].any()


def test_campaign_records_state_relationships_and_contradictions():
    engine = CampaignEngine(CampaignConfig(window_flows=100))
    result = engine.detect(endpoint_meta(["10.0.0.1"] * 100, ["9.9.9.9"] * 100, [80] * 100),
                           base_features(100), np.array([True] * 40 + [False] * 60))
    record = result.campaigns[0] if result.campaigns else None
    assert record is not None and record["campaign_type"] == DOS and "9.9.9.9" in record["hypothesis"]
    assert record["relationships"] == [
        {"source": "10.0.0.1", "destination": "9.9.9.9", "destination_port": 80.0, "flows": 100}]
    assert any("40.0%" in text for text in record["contradicting_evidence"])
    assert not any(k.startswith("_") for k in record)
