"""Isolated adapter for the organisers' Level 1 submission API.

The endpoint, authentication and payload format were shared only in the event WhatsApp group and
are not in this repository, so none of them are assumed here. Fill in configs/submission.yaml
(gitignored if it holds a credential) from the official instructions; until then submit() refuses.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

import yaml

from backend.config import load_config, resolve

CONFIG_PATH = "configs/submission.yaml"


class SubmissionNotConfigured(RuntimeError):
    pass


@dataclass
class SubmissionConfig:
    url: str
    method: str
    token_env: str | None
    token_header: str | None
    payload_template: dict


def load_submission_config() -> SubmissionConfig:
    path = resolve(CONFIG_PATH)
    if not path.exists():
        raise SubmissionNotConfigured(
            f"{CONFIG_PATH} is missing. Copy the endpoint, auth and payload format from the organisers' "
            "official instructions; do not guess them.")
    raw = yaml.safe_load(path.read_text())
    return SubmissionConfig(raw["url"], raw.get("method", "POST"), raw.get("token_env"),
                            raw.get("token_header"), raw["payload_template"])


def load_summary() -> dict:
    return json.loads((resolve(load_config()["data"]["reports_dir"]) / "level1_summary.json").read_text())


def build_payload(template: dict, summary: dict) -> dict:
    """Fill {dotted.path} string placeholders in the official template from the measured summary."""
    def lookup(path: str):
        value = summary
        for key in path.split("."):
            value = value[key]
        return value

    def fill(node):
        if isinstance(node, dict):
            return {k: fill(v) for k, v in node.items()}
        if isinstance(node, list):
            return [fill(v) for v in node]
        if isinstance(node, str) and node.startswith("{") and node.endswith("}"):
            return lookup(node[1:-1])
        return node

    return fill(template)


def submit(dry_run: bool = True) -> dict:
    """Build the payload, and send it only when dry_run is False."""
    import httpx

    config = load_submission_config()
    payload = build_payload(config.payload_template, load_summary())
    if dry_run:
        return {"dry_run": True, "url": config.url, "payload": payload}
    headers = {}
    if config.token_env:
        token = os.environ.get(config.token_env)
        if not token:
            raise SubmissionNotConfigured(f"environment variable {config.token_env} is not set")
        headers[config.token_header or "Authorization"] = token
    response = httpx.request(config.method, config.url, json=payload, headers=headers, timeout=30)
    return {"dry_run": False, "status_code": response.status_code, "response": response.text}
