"""FastAPI control plane. Phase 0 routes, wired to storage + the ingest pipeline.

NIST CSF: Detect + Respond (this is the operator's window into both).

Routes:
* ``GET  /health``  — liveness + version
* ``POST /events``  — ingest one Event; runs detectors, persists Event + Alerts
* ``GET  /events``  — query stored Events (filter by source/kind/src_ip)
* ``GET  /alerts``  — query stored Alerts (filter by severity)
* ``GET  /metrics`` — table counts + loaded-detector summary

Construct with :func:`create_app` (tests pass an isolated Settings); the
module-level ``app`` is what ``make run`` / uvicorn import.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI, Query, Request

from sentinel_v import __version__
from sentinel_v.config import Settings, load_settings
from sentinel_v.detection.rules import SigmaRuleDetector
from sentinel_v.models import Alert, Event, Severity
from sentinel_v.pipeline import Pipeline, build_pipeline
from sentinel_v.storage import Store


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    store = Store(settings.db_url)
    pipeline = build_pipeline(settings, store)

    app = FastAPI(title="Sentinel-V", version=__version__)
    app.state.settings = settings
    app.state.store = store
    app.state.pipeline = pipeline

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/events")
    def ingest_event(event: Event, request: Request) -> dict[str, object]:
        pl: Pipeline = request.app.state.pipeline
        stored, alerts = pl.ingest(event)
        return {"event": stored, "alerts": alerts}

    @app.get("/events")
    def list_events(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        source: str | None = None,
        kind: str | None = None,
        src_ip: str | None = None,
    ) -> list[Event]:
        st: Store = request.app.state.store
        return st.get_events(limit=limit, source=source, kind=kind, src_ip=src_ip)

    @app.get("/alerts")
    def list_alerts(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        severity: Severity | None = None,
    ) -> list[Alert]:
        st: Store = request.app.state.store
        return st.get_alerts(limit=limit, severity=severity)

    @app.get("/metrics")
    def metrics(request: Request) -> dict[str, object]:
        st: Store = request.app.state.store
        pl: Pipeline = request.app.state.pipeline
        rules_loaded = sum(
            len(d.rules) for d in pl.detectors if isinstance(d, SigmaRuleDetector)
        )
        return {
            "counts": st.counts(),
            "detectors": [d.name for d in pl.detectors],
            "rules_loaded": rules_loaded,
        }

    return app


app = create_app()
