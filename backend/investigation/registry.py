"""Bounded tool registry. Tools run with a timeout, are logged, and cannot call back into the registry."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Callable

from backend.investigation import tools
from backend.investigation.audit import AuditLog

DEFAULT_TIMEOUT_SECONDS = 5.0

TOOLS: dict[str, Callable] = {
    fn.__name__: fn for fn in (
        tools.inspect_feature_deviations,
        tools.compare_against_benign_baseline,
        tools.find_related_flows,
        tools.inspect_source_activity,
        tools.inspect_destination_activity,
        tools.inspect_port_distribution,
        tools.inspect_campaign_context,
        tools.inspect_agent_disagreement,
    )
}


class ToolRegistry:
    def __init__(self, store: tools.EvidenceStore, audit: AuditLog, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.store = store
        self.audit = audit
        self.timeout = timeout
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="investigation-tool")
        self._local = threading.local()

    def call(self, name: str, investigation_id: str, **kwargs) -> dict:
        if name not in TOOLS:
            raise KeyError(f"unregistered tool: {name}")
        if getattr(self._local, "in_tool", False):
            raise RuntimeError("recursive tool invocation is not allowed")
        self._local.in_tool = True
        started = time.perf_counter()
        try:
            future = self._executor.submit(TOOLS[name], self.store, **kwargs)
            try:
                result = future.result(timeout=self.timeout)
                status = "ok"
            except FutureTimeout:
                future.cancel()
                result = {"available": False, "summary": f"Tool timed out after {self.timeout}s.",
                          "supports": tools.NEUTRAL, "evidence": {}}
                status = "timeout"
            except Exception as exc:  # A failing tool must not end the investigation.
                result = {"available": False, "summary": f"Tool failed: {exc}",
                          "supports": tools.NEUTRAL, "evidence": {}}
                status = "error"
        finally:
            self._local.in_tool = False
        call = {
            "tool": name, "arguments": kwargs, "status": status,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2), "result": result,
        }
        self.audit.record("tool_call", investigation_id=investigation_id, tool=name, arguments=kwargs,
                          status=status, duration_ms=call["duration_ms"], summary=result["summary"])
        return call

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
