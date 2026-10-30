"""Every backend module must import, and no module may be left empty apart from package markers."""
import importlib
import pkgutil
from pathlib import Path

import pytest

import backend
from backend.config import ROOT
from backend.main import app

MODULES = sorted(m.name for m in pkgutil.walk_packages(backend.__path__, "backend."))


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name):
    importlib.import_module(name)


def test_only_package_markers_are_empty():
    empty = [p for p in Path(ROOT, "backend").rglob("*.py") if p.stat().st_size == 0]
    assert all(p.name == "__init__.py" for p in empty)


def test_required_routes_are_registered():
    paths = {(m.upper(), path) for path, item in app.openapi()["paths"].items() for m in item}
    required = [("GET", "/api/health"), ("GET", "/api/models/status"), ("GET", "/api/metrics"), ("GET", "/api/flows"),
                ("GET", "/api/flows/{flow_id}"), ("GET", "/api/campaigns"), ("GET", "/api/incidents"),
                ("GET", "/api/incidents/{incident_id}"), ("GET", "/api/investigations/{investigation_id}"),
                ("GET", "/api/audit"), ("POST", "/api/flows/analyse"), ("POST", "/api/replay/start"),
                ("POST", "/api/replay/pause"), ("POST", "/api/replay/resume"), ("POST", "/api/replay/stop"),
                ("GET", "/api/replay/events"), ("POST", "/api/policy/configure"), ("POST", "/api/policy/simulate"),
                ("GET", "/api/defense")]
    assert not [r for r in required if r not in paths]


@pytest.mark.parametrize("script", sorted(p.stem for p in Path(ROOT, "scripts").glob("*.py")))
def test_script_imports(script):
    importlib.import_module(f"scripts.{script}")
