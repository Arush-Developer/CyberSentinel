"""The adapter must refuse to send anything until it has the official format."""
import pytest

from backend.api import submission_adapter as adapter


def test_adapter_refuses_without_official_config(monkeypatch, tmp_path):
    monkeypatch.setattr(adapter, "resolve", lambda _: tmp_path / "missing.yaml")
    with pytest.raises(adapter.SubmissionNotConfigured, match="official instructions"):
        adapter.load_submission_config()


def test_payload_fills_only_measured_values():
    summary = {"macro_f1": 0.5, "agent1": {"accuracy": 0.75}}
    template = {"score": "{macro_f1}", "nested": ["{agent1.accuracy}", "literal"]}
    assert adapter.build_payload(template, summary) == {"score": 0.5, "nested": [0.75, "literal"]}
    with pytest.raises(KeyError):
        adapter.build_payload({"x": "{not_measured}"}, summary)


