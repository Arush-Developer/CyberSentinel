"""SYNTHETIC flows: Agents 4 and 5, including the brief's ordering rules."""
from backend.agents.defense_agent import ALLOW, BLOCK, DefenseConfig, DefenseLoop
from backend.agents.temporal_agent import TemporalConfig


def loop(**defense):
    settings = dict(min_attack_flows_multi_signal=3, min_attack_flows_classifier_only=5, min_attack_flows_converging=1,
                    min_attack_share=0.6, ttl_records=4, max_ttl_records=16, min_confidence=0.9)
    return DefenseLoop(TemporalConfig(window_records=50, converging_min_sources=3), DefenseConfig(**{**settings, **defense}))


def attack(run, i, src="1.1.1.1", dst="9.9.9.9", status="MULTI_SIGNAL_ATTACK", cls="DOS", conf=0.99, port=80.0):
    return run.step(i, f"R{i}", src, dst, port, cls, conf, 0.99, status == "MULTI_SIGNAL_ATTACK", status)


def benign(run, i, src="2.2.2.2", dst="9.9.9.8"):
    return run.step(i, f"R{i}", src, dst, 443.0, "BENIGN", 0.99, 0.2, False, "AGREED_BENIGN")


def test_policy_applies_only_to_later_flows_and_never_to_its_trigger():
    run = loop()
    assert [attack(run, i)["action"] for i in range(3)] == [ALLOW, ALLOW, ALLOW]
    policy = run.defense.policies[0]
    assert policy["activated_after_record_id"] == "R2" and policy["status"] == "ACTIVE"
    next_flow = attack(run, 3)
    assert next_flow["action"] == BLOCK and next_flow["applied_policy_id"] == policy["policy_id"]


def test_block_only_matches_the_policy_source():
    run = loop()
    for i in range(3):
        attack(run, i)
    assert benign(run, 3)["action"] == ALLOW
    assert attack(run, 4)["action"] == BLOCK


def test_policy_expires_and_records_the_last_active_record():
    run = loop()
    for i in range(3):
        attack(run, i)
    actions = [benign(run, i)["action"] for i in range(3, 7)]
    assert actions == [ALLOW] * 4
    policy = run.defense.policies[0]
    assert policy["status"] == "EXPIRED" and policy["expires_after_record_id"] == "R6"
    assert [e["event"] for e in run.defense.log] == ["ACTIVATED", "EXPIRED"]
    assert benign(run, 7, src="1.1.1.1")["action"] == ALLOW


def test_repeat_offender_gets_a_longer_policy():
    run = loop()
    for i in range(3):
        attack(run, i)
    for i in range(3, 7):
        benign(run, i)
    attack(run, 7)
    assert run.defense.policies[1]["ttl_records"] == 8


def test_classifier_only_needs_more_flows_than_multi_signal():
    run = loop()
    for i in range(4):
        assert attack(run, i, status="CLASSIFIER_ONLY")["activated_policy"] is None
    assert attack(run, 4, status="CLASSIFIER_ONLY")["activated_policy"] is not None


def test_anomaly_alone_never_creates_a_policy():
    run = loop()
    for i in range(20):
        run.step(i, f"R{i}", "1.1.1.1", "9.9.9.9", 80.0, "BENIGN", 0.99, 0.99, True, "ANOMALY_ONLY")
    assert not run.defense.policies and run.temporal.groups


def test_low_confidence_attack_calls_do_not_count():
    run = loop()
    for i in range(10):
        attack(run, i, conf=0.7, status="CLASSIFIER_ONLY")
    assert not run.defense.policies


def test_shared_source_with_mostly_benign_traffic_is_protected():
    run = loop()
    i = 0
    for _ in range(20):
        benign(run, i, src="1.1.1.1")
        i += 1
    for _ in range(5):
        attack(run, i)
        i += 1
    assert not run.defense.policies
    assert run.temporal.source_evidence("1.1.1.1")["attack_share"] < 0.6


def test_converging_sources_lower_the_bar_for_a_new_source():
    run = loop(min_attack_flows_multi_signal=100, min_attack_flows_classifier_only=100)
    results = [attack(run, i, src=f"7.7.7.{i}") for i in range(3)]
    assert results[-1]["activated_policy"] is not None and results[0]["activated_policy"] is None
    assert run.defense.policies[0]["converging_group_id"]
    destination = [g for g in run.temporal.groups if g["scope_type"] == "DESTINATION_IP"][0]
    assert destination["evidence"]["distinct_attacking_sources"] == 3
    assert destination["evidence"]["pattern"] == "many sources converging on one destination"


def test_window_forgets_old_observations_and_a_gap_opens_a_new_group():
    run = loop(min_attack_flows_multi_signal=100, min_attack_flows_classifier_only=100, min_attack_flows_converging=100)
    attack(run, 0)
    first = run.temporal.groups[0]["group_id"]
    attack(run, 100)
    groups = [g for g in run.temporal.groups if g["scope_type"] == "SOURCE_IP"]
    assert len(groups) == 2 and groups[0]["group_id"] == first
    assert run.temporal.source_evidence("1.1.1.1")["flows_in_window"] == 1


def test_port_scan_pattern_is_named_from_observed_ports():
    run = loop(min_attack_flows_multi_signal=100, min_attack_flows_classifier_only=100, min_attack_flows_converging=100)
    for i in range(25):
        attack(run, i, cls="PORT_SCAN", port=float(1000 + i))
    assert run.temporal.source_evidence("1.1.1.1")["pattern"] == "one source touching many destination ports"


def test_one_attack_call_at_a_converging_destination_is_not_enough_by_default():
    assert DefenseConfig().min_attack_flows_converging >= 2


def test_finish_closes_policies_still_active():
    run = loop(ttl_records=1000)
    for i in range(3):
        attack(run, i)
    run.finish(2, "R2")
    assert run.defense.policies[0]["expires_after_record_id"] == "R2"


def test_missing_source_addresses_are_never_grouped_or_blocked():
    run = loop()
    for i in range(20):
        result = attack(run, i, src="nan")
        assert result["action"] == ALLOW and result["activated_policy"] is None
    assert not run.defense.policies and not run.temporal.groups

