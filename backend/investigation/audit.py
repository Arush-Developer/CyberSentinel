"""Thread-safe, append-only audit log. Every tool call and control action lands here.

Events are kept in memory for fast listing. Given a database path they are also written to SQLite,
so the audit trail and policy history survive a backend restart.
"""
from __future__ import annotations

import itertools
import json
import sqlite3
import threading
import time
from collections import deque
from pathlib import Path


class AuditLog:
    def __init__(self, maxlen: int = 50_000, db_path: Path | str | None = None):
        self._events: deque[dict] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        last_id = 0
        if db_path is not None:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(db_path, check_same_thread=False)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.execute("CREATE TABLE IF NOT EXISTS audit_events (event_id INTEGER PRIMARY KEY, "
                             "time REAL NOT NULL, kind TEXT NOT NULL, details TEXT NOT NULL)")
            self._db.execute("CREATE INDEX IF NOT EXISTS audit_kind ON audit_events (kind)")
            rows = self._db.execute("SELECT details FROM audit_events ORDER BY event_id DESC LIMIT ?", (maxlen,))
            self._events.extend(json.loads(row[0]) for row in reversed(rows.fetchall()))
            last_id = self._events[-1]["event_id"] if self._events else 0
        self._ids = itertools.count(last_id + 1)

    def record(self, kind: str, **details) -> dict:
        event = {"event_id": next(self._ids), "time": time.time(), "kind": kind, **details}
        with self._lock:
            self._events.append(event)
            if self._db is not None:
                self._db.execute("INSERT INTO audit_events VALUES (?, ?, ?, ?)",
                                 (event["event_id"], event["time"], kind, json.dumps(event, default=str)))
                self._db.commit()
        return event

    def list(self, kind: str | None = None, limit: int = 200) -> list[dict]:
        with self._lock:
            events = list(self._events)
        if kind:
            events = [e for e in events if e["kind"] == kind]
        return events[-limit:][::-1]

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def __len__(self) -> int:
        return len(self._events)
