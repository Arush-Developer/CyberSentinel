"""Offline traffic replay: real records, real batch inference, simulated decisions only.

Flows are scored in batches, one campaign window per batch, and then released to listeners at the
requested speed. Ground truth travels with each event for display only; no decision reads it.
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass

import numpy as np
import pandas as pd

from backend.agents.investigation_orchestrator import InvestigationCancelled, Orchestrator, triggers_for
from backend.config import resolve
from backend.intelligence.campaign_engine import CampaignEngine, CampaignResult, CampaignTracker
from backend.investigation.audit import AuditLog
from backend.investigation.registry import ToolRegistry
from backend.services.model_service import HIGH_ANOMALY, Analysis, Pipeline

STATE_FILE = "data/processed/replay_state.json"
RESULTS_FILE = "data/processed/replay_results.parquet"
MAX_FLOWS_PER_EVENT = 40
EVENT_BUFFER = 20_000

IDLE, RUNNING, PAUSED, STOPPED, COMPLETED = "idle", "running", "paused", "stopped", "completed"


@dataclass
class ReplaySettings:
    speed: float = 500.0
    batch_size: int = 500
    limit: int | None = None
    max_investigations_per_batch: int = 5


class ReplayEngine:
    def __init__(self, pipeline: Pipeline, analysis: Analysis, audit: AuditLog, persist: bool = True):
        self.pipeline = pipeline
        self.analysis = analysis
        self.audit = audit
        self.persist = persist
        partition = analysis.partition
        numeric = partition.metadata["flow_id"].astype(str).str.extract(r"(\d+)")[0].astype(np.int64).to_numpy()
        self.order = np.argsort(numeric, kind="stable")
        self.settings = ReplaySettings()
        self._lock = threading.RLock()
        self._events: deque[dict] = deque(maxlen=EVENT_BUFFER)
        self._seq = 0
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._resume = threading.Event()
        self._resume.set()
        self.status = IDLE
        self.cursor = 0
        self.started_at: float | None = None
        self.processing_seconds = 0.0
        self.counts = self._empty_counts()
        self.tracker = self._new_tracker()
        self.results: list[pd.DataFrame] = []
        self.investigations: dict[str, dict] = {}
        self.investigation_triggers = 0
        self._restore()

    def _new_tracker(self) -> CampaignTracker:
        mode = self.analysis.campaign.mode
        return CampaignTracker(mode, self.pipeline.campaign_engine.config)

    def _empty_counts(self) -> dict:
        return {
            "total": 0,
            "classes": {c: 0 for c in self.pipeline.threat.classes},
            "decisions": {"ALLOW": 0, "BLOCK": 0, "REVIEW": 0},
            "agreement": {"AGREE": 0, "DISAGREE": 0},
            "evidence": {},
        }

    # ---- Events -----------------------------------------------------------------------------
    def _emit(self, kind: str, **payload) -> None:
        with self._lock:
            self._seq += 1
            self._events.append({"seq": self._seq, "type": kind, "time": time.time(), **payload})

    def events_since(self, seq: int, limit: int = 500) -> list[dict]:
        with self._lock:
            return [e for e in self._events if e["seq"] > seq][:limit]

    # ---- Controls ---------------------------------------------------------------------------
    def start(self, speed: float = 500.0, batch_size: int = 500, limit: int | None = None,
              resume_saved: bool = False, max_investigations_per_batch: int = 5) -> dict:
        with self._lock:
            if self.status in (RUNNING, PAUSED):
                raise RuntimeError("replay is already active; stop it first")
            self.settings = ReplaySettings(speed, batch_size, limit, max_investigations_per_batch)
            if not (resume_saved and self.cursor and self.cursor < self._target()):
                self.cursor = 0
                self.counts = self._empty_counts()
                self.tracker = self._new_tracker()
                self.results = []
                self.investigations = {}
                self.investigation_triggers = 0
                self.processing_seconds = 0.0
            self._stop.clear()
            self._resume.set()
            self.status = RUNNING
            self.started_at = time.time()
            self._thread = threading.Thread(target=self._run, name="replay", daemon=True)
            self._thread.start()
        self.audit.record("replay_control", action="start", speed=speed, batch_size=batch_size,
                          limit=limit, resumed=bool(resume_saved and self.cursor))
        self._emit("state", status=RUNNING, cursor=self.cursor)
        return self.snapshot()

    def pause(self) -> dict:
        with self._lock:
            if self.status != RUNNING:
                raise RuntimeError(f"cannot pause while {self.status}")
            self._resume.clear()
            self.status = PAUSED
        self.audit.record("replay_control", action="pause", cursor=self.cursor)
        self._emit("state", status=PAUSED, cursor=self.cursor)
        self._save()
        return self.snapshot()

    def resume(self) -> dict:
        with self._lock:
            if self.status != PAUSED:
                raise RuntimeError(f"cannot resume while {self.status}")
            self.status = RUNNING
            self._resume.set()
        self.audit.record("replay_control", action="resume", cursor=self.cursor)
        self._emit("state", status=RUNNING, cursor=self.cursor)
        return self.snapshot()

    def stop(self) -> dict:
        """Global stop. Takes effect at the next flow chunk and cancels running investigations."""
        with self._lock:
            active = self.status in (RUNNING, PAUSED)
            self._stop.set()
            self._resume.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=10)
        with self._lock:
            if active:
                self.status = STOPPED
        self.audit.record("replay_control", action="stop", cursor=self.cursor, was_active=active)
        self._emit("state", status=self.status, cursor=self.cursor)
        self._save()
        return self.snapshot()

    def snapshot(self) -> dict:
        with self._lock:
            target = self._target()
            elapsed = self.processing_seconds
            return {
                "status": self.status,
                "cursor": self.cursor,
                "total": target,
                "progress": self.cursor / target if target else 0.0,
                "speed": self.settings.speed,
                "batch_size": self.settings.batch_size,
                "counts": json.loads(json.dumps(self.counts)),
                "campaigns": len(self.tracker.campaigns),
                "campaign_mode": self.analysis.campaign.mode,
                "investigations": len(self.investigations),
                "investigation_triggers": self.investigation_triggers,
                "inference_flows_per_second": round(self.cursor / elapsed, 1) if elapsed else None,
                "latest_seq": self._seq,
            }

    def _target(self) -> int:
        total = len(self.order)
        return min(self.settings.limit, total) if self.settings.limit else total

    # ---- Processing -------------------------------------------------------------------------
    def _run(self) -> None:
        try:
            while self.cursor < self._target() and not self._stop.is_set():
                self._resume.wait()
                if self._stop.is_set():
                    break
                self._process_batch()
            with self._lock:
                if not self._stop.is_set():
                    self.status = COMPLETED
            if self.status == COMPLETED:
                self.audit.record("replay_control", action="completed", cursor=self.cursor)
                self._emit("state", status=COMPLETED, cursor=self.cursor)
                self._save()
        except Exception as exc:
            with self._lock:
                self.status = STOPPED
            self.audit.record("replay_error", error=str(exc))
            self._emit("error", message=str(exc))
            self._save()

    def _process_batch(self) -> None:
        settings = self.settings
        rows = self.order[self.cursor:min(self.cursor + settings.batch_size, self._target())]
        partition = self.analysis.partition
        features = partition.features.iloc[rows].reset_index(drop=True)
        metadata = partition.metadata.iloc[rows].reset_index(drop=True)
        started = time.perf_counter()

        proba, scores = self.pipeline.score(features)
        threat_class = np.array(self.pipeline.threat.classes)[proba.argmax(axis=1)]
        is_anomaly = scores >= self.pipeline.anomaly.threshold

        known = len(self.tracker.campaigns)
        frame = CampaignEngine.prepare(metadata, features, is_anomaly)
        window = self.cursor // max(settings.batch_size, 1)
        flow_campaign = np.full(len(rows), None, dtype=object)
        for positions, cid in self.tracker.process_window(window, frame):
            flow_campaign[positions] = cid
        result = CampaignResult(self.tracker.mode, [], self.tracker.public_campaigns(), flow_campaign)
        support, conflict = result.signals(threat_class)
        fusion = self.pipeline.fuse(proba, scores, campaign_support=support, campaign_conflict=conflict)

        ids = metadata["flow_id"].to_numpy()
        triggered = self._investigate(rows, ids, fusion, scores, flow_campaign, conflict)
        out = self.pipeline.results_frame(ids, proba, fusion, flow_campaign)
        self.processing_seconds += time.perf_counter() - started

        with self._lock:
            self.results.append(out)
        campaigns = result.campaigns
        for record in campaigns[known:]:
            self._emit("campaign", action="detected", campaign=self._campaign_brief(record))
        touched = {c for c in flow_campaign if c is not None}
        for record in campaigns[:known]:
            if record["campaign_id"] in touched:
                self._emit("campaign", action="updated", campaign=self._campaign_brief(record))
        self._release(out, partition.labels.to_numpy()[rows] if partition.labels is not None else None, triggered)
        self._save()

    @staticmethod
    def _campaign_brief(record: dict) -> dict:
        return {k: record[k] for k in ("campaign_id", "campaign_type", "target", "flow_count", "confidence",
                                       "windows_observed", "traffic_intensity", "first_observed", "last_observed")}

    def _investigate(self, rows, ids, fusion, scores, flow_campaign, conflict) -> np.ndarray:
        triggers = [triggers_for(str(fusion.threat_class[i]), fusion.agreement[i] == "DISAGREE",
                                 bool(fusion.low_confidence[i]), float(scores[i]), HIGH_ANOMALY,
                                 flow_campaign[i] is not None, bool(conflict[i])) for i in range(len(rows))]
        triggered = np.array([bool(t) for t in triggers])
        self.investigation_triggers += int(triggered.sum())
        budget = self.settings.max_investigations_per_batch
        if budget <= 0 or not triggered.any():
            return triggered
        # Spend the per-batch budget on the most unusual triggered flows.
        chosen = np.flatnonzero(triggered)[np.argsort(-scores[triggered], kind="stable")[:budget]]
        registry = ToolRegistry(self.analysis.store, self.audit)
        orchestrator = Orchestrator(registry, cancel=self._stop)
        try:
            for i in chosen:
                try:
                    result = orchestrator.investigate(str(ids[i]), triggers[i])
                except InvestigationCancelled:
                    break
                with self._lock:
                    self.investigations[str(ids[i])] = result
                self._emit("investigation", flow_id=str(ids[i]), investigation_id=result["investigation_id"],
                           triggers=result["triggers"], verdict=result["verdict"],
                           tools=[c["tool"] for c in result["tool_calls"]])
        finally:
            registry.close()
        return triggered

    def _release(self, out: pd.DataFrame, truth, triggered: np.ndarray) -> None:
        """Hand results to listeners at the requested speed. Stop is honoured between chunks."""
        speed = max(self.settings.speed, 1.0)
        chunk = max(1, int(speed / 20))
        i = 0
        while i < len(out):
            if self._stop.is_set():
                return
            self._resume.wait()
            if self._stop.is_set():
                return
            part = out.iloc[i:i + chunk]
            tick = time.perf_counter()
            self._count(part)
            with self._lock:
                self.cursor += len(part)
                cursor = self.cursor
            shown = part.iloc[:MAX_FLOWS_PER_EVENT]
            flows = [{
                "flow_id": str(r.flow_id), "threat_class": r.threat_class,
                "confidence": round(float(r.threat_confidence), 4),
                "anomaly_score": round(float(r.anomaly_score), 4), "is_anomaly": bool(r.is_anomaly),
                "agreement": r.agreement, "final_class": r.final_class, "evidence_status": r.evidence_status,
                "policy_decision": r.policy_decision, "policy_rule": r.policy_rule,
                "campaign_id": r.campaign_id, "investigation_triggered": bool(triggered[i + j]),
                "ground_truth_evaluation_only": str(truth[i + j]) if truth is not None else None,
            } for j, r in enumerate(shown.itertuples(index=False))]
            self._emit("flows", cursor=cursor, total=self._target(), flows=flows, flows_in_chunk=len(part),
                       counts=self.counts)
            i += len(part)
            wait = len(part) / speed - (time.perf_counter() - tick)
            if wait > 0:
                self._stop.wait(wait)

    def _count(self, part: pd.DataFrame) -> None:
        with self._lock:
            c = self.counts
            c["total"] += len(part)
            for key, col in (("classes", "final_class"), ("decisions", "policy_decision"), ("agreement", "agreement"),
                             ("evidence", "evidence_status")):
                for name, n in part[col].value_counts().items():
                    c[key][name] = c[key].get(name, 0) + int(n)

    # ---- Results and persistence --------------------------------------------------------------
    def replayed_frame(self) -> pd.DataFrame:
        with self._lock:
            if not self.results:
                return pd.DataFrame()
            frame = pd.concat(self.results, ignore_index=True)
        return frame.iloc[:self.cursor]

    def _save(self) -> None:
        if not self.persist:
            return
        with self._lock:
            state = {
                "status": self.status, "cursor": self.cursor, "counts": self.counts,
                "settings": self.settings.__dict__, "campaigns": self.tracker.campaigns,
                "investigation_triggers": self.investigation_triggers, "saved_at": time.time(),
                "processing_seconds": self.processing_seconds,
            }
        path = resolve(STATE_FILE)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, default=str))
        tmp.replace(path)
        if self.status != RUNNING:
            frame = self.replayed_frame()
            if len(frame):
                frame.to_parquet(resolve(RESULTS_FILE), index=False)

    def _restore(self) -> None:
        if not self.persist:
            return
        path = resolve(STATE_FILE)
        if not path.exists():
            return
        try:
            state = json.loads(path.read_text())
            self.settings = ReplaySettings(**state["settings"])
            # A run that was active when the process ended comes back stopped, at its last saved batch.
            self.status = state["status"] if state["status"] in (COMPLETED, STOPPED, PAUSED) else STOPPED
            if self.status == PAUSED:
                self.status = STOPPED
            self.cursor = state["cursor"]
            self.counts = state["counts"]
            self.investigation_triggers = state.get("investigation_triggers", 0)
            self.processing_seconds = state.get("processing_seconds", 0.0)
            self.tracker.campaigns = state["campaigns"]
            self.tracker._counter = len(state["campaigns"])
            self.tracker._open = {(c["campaign_type"], c["target"]): c for c in state["campaigns"]}
            if resolve(RESULTS_FILE).exists():
                self.results = [pd.read_parquet(resolve(RESULTS_FILE))]
            self.cursor = min(self.cursor, sum(len(r) for r in self.results))
        except (KeyError, ValueError, TypeError, OSError) as exc:
            self.audit.record("replay_error", error=f"could not restore saved replay state: {exc}")
            self.status, self.cursor = IDLE, 0
