"""HTTP API for CyberSentinel X. All decisions are simulated; no endpoint touches a real network."""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from backend.schemas.contracts import (
    AnalyseFlowRequest, FlowDetail, HealthResponse, InvestigationResult, ModelStatusResponse, PolicyConfigureRequest,
    DefenseState, PolicySimulateRequest, ReplayStartRequest, ReplayStatus)

router = APIRouter(prefix="/api")
SSE_POLL_SECONDS = 0.2


def state_of(request: Request):
    state = getattr(request.app.state, "cs", None)
    if state is None:
        detail = getattr(request.app.state, "load_error", None) or "models are still loading"
        raise HTTPException(503, detail)
    return state


@router.get("/health", response_model=HealthResponse)
def health(request: Request):
    if getattr(request.app.state, "cs", None) is not None:
        return HealthResponse(status="ok")
    error = getattr(request.app.state, "load_error", None)
    return HealthResponse(status="unavailable" if error else "loading", detail=error)


@router.get("/models/status", response_model=ModelStatusResponse)
def model_status(request: Request):
    s = state_of(request)
    t, a = s.pipeline.threat, s.pipeline.anomaly
    return ModelStatusResponse(
        threat_model=t.model_version, threat_calibration=t.calibration_status,
        threat_features=len(t.pipeline.columns_), anomaly_model=a.model_version, anomaly_detector=a.detector,
        anomaly_threshold=a.threshold, anomaly_features=len(a.pipeline.columns_),
        campaign_mode=s.analysis.campaign.mode, campaign_limitations=s.analysis.campaign.limitations,
        defense_available=s.replay.defense_available, replay_input=s.replay_input)


@router.get("/metrics")
def metrics(request: Request):
    return state_of(request).metrics()


@router.get("/summary")
def summary(request: Request):
    return state_of(request).summary()


@router.get("/flows")
def flows(request: Request, scope: str | None = None, offset: int = Query(0, ge=0),
          limit: int = Query(50, ge=1, le=500), decision: str | None = None, final_class: str | None = None,
          evidence_status: str | None = None, disagree: bool | None = None, campaign_id: str | None = None,
          search: str | None = None):
    return state_of(request).list_flows(scope, offset, limit, decision, final_class, evidence_status, disagree,
                                        campaign_id, search)


@router.post("/flows/analyse")
def analyse(request: Request, body: AnalyseFlowRequest):
    try:
        return state_of(request).analyse_features(body.features)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/flows/{flow_id}", response_model=FlowDetail)
def flow(request: Request, flow_id: str):
    try:
        return state_of(request).flow_detail(flow_id)
    except KeyError as exc:
        raise HTTPException(404, f"unknown flow {flow_id}") from exc


@router.get("/campaigns")
def campaigns(request: Request, scope: str | None = None):
    return state_of(request).campaigns(scope)


@router.get("/ports")
def ports(request: Request, scope: str | None = None):
    return state_of(request).port_distribution(scope)


@router.get("/incidents")
def incidents(request: Request, scope: str | None = None, limit: int = Query(100, ge=1, le=1000)):
    return state_of(request).incidents(scope, limit)


@router.get("/incidents/{incident_id}")
def incident(request: Request, incident_id: str):
    try:
        return state_of(request).incident(incident_id)
    except KeyError as exc:
        raise HTTPException(404, f"unknown incident {incident_id}") from exc


@router.get("/investigations")
def investigations(request: Request, limit: int = Query(100, ge=1, le=500)):
    return {"items": state_of(request).investigations(limit)}


@router.get("/investigations/{investigation_id}", response_model=InvestigationResult)
def investigation(request: Request, investigation_id: str):
    try:
        return state_of(request).investigation(investigation_id)
    except KeyError as exc:
        raise HTTPException(404, f"no investigation {investigation_id}") from exc


@router.get("/audit")
def audit(request: Request, kind: str | None = None, limit: int = Query(200, ge=1, le=2000)):
    s = state_of(request)
    return {"total": len(s.audit), "items": s.audit.list(kind, limit)}


@router.get("/policy")
def policy(request: Request):
    return state_of(request).policy()


@router.post("/policy/configure")
def policy_configure(request: Request, body: PolicyConfigureRequest):
    return state_of(request).configure_policy(body.thresholds.model_dump(), body.reason)


@router.post("/policy/simulate")
def policy_simulate(request: Request, body: PolicySimulateRequest):
    return state_of(request).simulate_policy(body.thresholds.model_dump(), body.max_examples)


@router.get("/defense", response_model=DefenseState)
def defense(request: Request, member_limit: int = Query(25, ge=0, le=5000), group_limit: int = Query(200, ge=1, le=5000)):
    """Agents 4 and 5 from the current replay: correlation groups, policies, activation and expiry log."""
    return state_of(request).defense_state(member_limit, group_limit)


def _control(call):
    try:
        return call()
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/replay/start", response_model=ReplayStatus)
def replay_start(request: Request, body: ReplayStartRequest):
    replay = state_of(request).replay
    return _control(lambda: replay.start(**body.model_dump()))


@router.post("/replay/pause", response_model=ReplayStatus)
def replay_pause(request: Request):
    return _control(state_of(request).replay.pause)


@router.post("/replay/resume", response_model=ReplayStatus)
def replay_resume(request: Request):
    return _control(state_of(request).replay.resume)


@router.post("/replay/stop", response_model=ReplayStatus)
def replay_stop(request: Request):
    return _control(state_of(request).replay.stop)


@router.get("/replay/status", response_model=ReplayStatus)
def replay_status(request: Request):
    return state_of(request).replay.snapshot()


@router.get("/replay/events")
async def replay_events(request: Request, since: int = 0, once: bool = False):
    """Server-Sent Events of replay activity. once=true returns the backlog and closes."""
    replay = state_of(request).replay

    async def stream():
        seq = since
        while True:
            batch = replay.events_since(seq)
            for event in batch:
                seq = event["seq"]
                yield f"id: {seq}\nevent: {event['type']}\ndata: {json.dumps(event, default=str)}\n\n"
            if once:
                return
            if await request.is_disconnected():
                return
            if not batch:
                yield ": keepalive\n\n"
                await asyncio.sleep(SSE_POLL_SECONDS)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
