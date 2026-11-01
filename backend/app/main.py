"""Angler API: serves the dashboard contract in docs/api-contract.md."""

import json
import os

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from . import db, fixtures
from .schemas import Actor, AttackEvent, Cve, Stats

# "fixture" serves the contract examples (Phase 0). "db" will read real pipeline data (Phase 3).
DATA_SOURCE = os.getenv("ANGLER_DATA_SOURCE", "fixture")

# Comma-separated extra origins, e.g. the frontend's Render static-site URL once it exists.
FRONTEND_ORIGINS = [o.strip().rstrip("/") for o in os.getenv("FRONTEND_ORIGINS", "").split(",") if o.strip()]

app = FastAPI(title="Angler API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET"],
    allow_headers=["*"],
    expose_headers=["X-Angler-Data-Source"],
)


@app.middleware("http")
async def tag_data_source(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["X-Angler-Data-Source"] = DATA_SOURCE
    return response


@app.get("/")
def root():
    return {"service": "angler-api", "data_source": DATA_SOURCE, "docs": "/docs"}


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/status")
def pipeline_status():
    """Read-only pipeline health: is the DB reachable, how much is in it, when did ingest last run."""
    conn = db.connect()
    try:
        last = conn.execute(
            "SELECT started_at, finished_at, since, cursor, counts_json FROM ingest_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return {
            "database": "postgres" if conn.pg else "sqlite",
            "cves": conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"],
            "kev": conn.execute("SELECT COUNT(*) AS n FROM cves WHERE kev = 1").fetchone()["n"],
            "patch_checked": conn.execute("SELECT COUNT(*) AS n FROM cves WHERE patch_checked_at IS NOT NULL").fetchone()["n"],
            "pending": conn.execute("SELECT COUNT(*) AS n FROM ingest_pending").fetchone()["n"],
            "ingest_runs": conn.execute("SELECT COUNT(*) AS n FROM ingest_runs").fetchone()["n"],
            "last_run": {**dict(last), "counts": json.loads(last["counts_json"])} if last else None,
        }
    finally:
        conn.close()


@app.get("/api/cves",response_model=list[Cve], response_model_exclude_none=True)
def list_cves():
    return fixtures.CVES


@app.get("/api/events", response_model=list[AttackEvent], response_model_exclude_none=True)
def list_events(limit: int = Query(1000, ge=1, le=5000)):
    return fixtures.EVENTS[:limit]


@app.get("/api/stats", response_model=Stats, response_model_exclude_none=True)
def get_stats(window: str = "24h"):
    return fixtures.STATS


@app.get("/api/actors", response_model=list[Actor], response_model_exclude_none=True)
def list_actors():
    return fixtures.ACTORS
