"""FastAPI entry point. Run with: .venv/bin/uvicorn backend.main:app --port 8000"""
from __future__ import annotations

import os
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes import router
from backend.services.app_state import AppState


def _load(app: FastAPI) -> None:
    try:
        app.state.cs = AppState.load()
    except Exception as exc:  # Reported through /api/health so the UI can say what is missing.
        app.state.load_error = f"could not load models or data: {exc}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.cs = None
    app.state.load_error = None
    if not os.environ.get("CYBERSENTINEL_NO_AUTOLOAD"):  # Tests install their own non-persisting state.
        threading.Thread(target=_load, args=(app,), daemon=True).start()
    yield
    if app.state.cs is not None:
        app.state.cs.replay.stop()


app = FastAPI(title="CyberSentinel X", version="0.1.0",
              description="Offline multi-agent intrusion analysis. All ALLOW/BLOCK/REVIEW decisions are simulated.",
              lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(router)
