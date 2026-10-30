"""Thread-safe, append-only audit log. Every tool call and control action lands here."""
from __future__ import annotations

import itertools
import threading
import time
from collections import deque


class AuditLog:
    def __init__(self, maxlen: int = 50_000):
        self._events: deque[dict] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._ids = itertools.count(1)

    def record(self, kind: str, **details) -> dict:
        event = {"event_id": next(self._ids), "time": time.time(), "kind": kind, **details}
        with self._lock:
            self._events.append(event)
        return event

    def list(self, kind: str | None = None, limit: int = 200) -> list[dict]:
        with self._lock:
            events = list(self._events)
        if kind:
            events = [e for e in events if e["kind"] == kind]
        return events[-limit:][::-1]

    def __len__(self) -> int:
        return len(self._events)
