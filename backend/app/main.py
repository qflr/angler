"""Angler API: serves the dashboard contract in docs/api-contract.md from the pipeline's database.

Everything returned is real: CVEs from cvelistV5 + enrichment, hits from the honeypot. No hits yet
means empty lists and zero counts, never placeholders.
"""

import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import hmac
import ipaddress

from fastapi import Body, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from . import actors, classify, db, geoip, honeypots, triage
from .schemas import Actor, AttackEvent, Cve, Stats

# Shared secret the honeypot sensor sends in X-Ingest-Key. Unset = ingest disabled.
INGEST_KEY = os.getenv("INGEST_KEY", "")

# The deployed dashboard, plus any extra origins in FRONTEND_ORIGINS (comma-separated).
_DASHBOARD = "https://angler-gmip.onrender.com"
FRONTEND_ORIGINS = list(dict.fromkeys(
    [_DASHBOARD] + [o.strip().rstrip("/") for o in os.getenv("FRONTEND_ORIGINS", "").split(",") if o.strip()]
))

app = FastAPI(title="Angler API", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    expose_headers=["X-Angler-Data-Source"],
)


@app.on_event("startup")
def load_reference_lists() -> None:
    actors.refresh_lists_in_background()


@app.on_event("startup")
def reclassify_events() -> None:
    """Re-run the classifier over stored hits so signature updates apply to history too."""
    try:
        conn = db.connect()
    except Exception as e:  # never block startup on this
        print(f"reclassify skipped: {e}")
        return
    try:
        rows = conn.execute("SELECT id, method, path, body_preview, headers_json FROM events").fetchall()
        with conn:
            for r in rows:
                v = classify.classify(r["method"] or "", r["path"] or "", r["body_preview"] or "",
                                      json.loads(r["headers_json"] or "{}"))
                conn.execute(
                    "UPDATE events SET classification = :classification, stage = :stage, cve_id = :cve_id WHERE id = :id",
                    {**v, "id": r["id"]},
                )
        print(f"reclassified {len(rows)} events")
    finally:
        conn.close()


@app.middleware("http")
async def tag_data_source(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["X-Angler-Data-Source"] = "db"
    return response


def _cutoff(window: str) -> str:
    m = re.fullmatch(r"(\d+)([hd])", window)
    if not m:
        raise HTTPException(422, "window must look like 24h or 7d")
    hours = int(m.group(1)) * (24 if m.group(2) == "d" else 1)
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.get("/")
def root():
    return {"service": "angler-api", "data_source": "db", "docs": "/docs", "status": "/status"}


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
        count = lambda sql: conn.execute(sql).fetchone()["n"]  # noqa: E731
        return {
            "database": "postgres" if conn.pg else "sqlite",
            "cves": count("SELECT COUNT(*) AS n FROM cves"),
            "kev": count("SELECT COUNT(*) AS n FROM cves WHERE kev = 1"),
            "patch_checked": count("SELECT COUNT(*) AS n FROM cves WHERE patch_checked_at IS NOT NULL"),
            "pending": count("SELECT COUNT(*) AS n FROM ingest_pending"),
            "events": count("SELECT COUNT(*) AS n FROM events WHERE is_test = 0"),
            "ingest_runs": count("SELECT COUNT(*) AS n FROM ingest_runs"),
            "last_run": {**dict(last), "counts": json.loads(last["counts_json"])} if last else None,
        }
    finally:
        conn.close()


_STATUS_RANK = {"urgent": 0, "high": 1, "watch": 2}


@app.get("/api/cves", response_model=list[Cve], response_model_exclude_none=True)
def list_cves(limit: int = Query(500, ge=1, le=5000)):
    """Tracked CVEs, urgent first, then high, then newest."""
    conn = db.connect()
    try:
        rows = conn.execute(
            """SELECT id, title, description, vendor, product, cwes_json, date_published, cvss, severity,
                      kev, patch_status
               FROM cves WHERE state = 'PUBLISHED'"""
        ).fetchall()
    finally:
        conn.close()

    cves = []
    for r in rows:
        kev = r["kev"] == 1
        cves.append(
            {
                "id": r["id"],
                "description": triage.summary(r["title"], r["description"]),
                "severity": r["severity"] if r["severity"] in ("critical", "high", "medium", "low") else "unknown",
                "status": triage.status(kev, r["patch_status"], r["cwes_json"], r["description"], r["cvss"]),
                "kev": kev,
                "patch_status": r["patch_status"] or "unknown",
                "cvss": r["cvss"],
                "product": triage.product(r["vendor"], r["product"]),
                "published": r["date_published"],
            }
        )
    cves.sort(key=lambda c: c["published"] or "", reverse=True)
    cves.sort(key=lambda c: _STATUS_RANK[c["status"]])
    return cves[:limit]


_EVENT_FIELDS = [f for f in AttackEvent.model_fields]


@app.get("/api/events", response_model=list[AttackEvent], response_model_exclude_none=True)
def list_events(limit: int = Query(1000, ge=1, le=5000), cve_id: str | None = None):
    """Real honeypot hits, newest first. Our own test traffic (is_test) is never returned."""
    conn = db.connect()
    try:
        rows = conn.execute(
            f"SELECT {', '.join(_EVENT_FIELDS)} FROM events WHERE is_test = 0"
            + (" AND cve_id = ?" if cve_id else "")
            + " ORDER BY timestamp DESC LIMIT ?",
            (cve_id, limit) if cve_id else (limit,),
        ).fetchall()
    finally:
        conn.close()
    # AS0 is the reserved "no ASN" value (RFC 7607): used until the lookup resolves an address.
    ip_to_actor = actors.current()[0]
    return [{**dict(r), "asn": r["asn"] or 0, "actor_id": ip_to_actor.get(r["source_ip"])} for r in rows]


@app.get("/api/stats", response_model=Stats, response_model_exclude_none=True)
def get_stats(window: str = "24h", cve_id: str | None = None):
    since = _cutoff(window)
    conn = db.connect()
    try:
        changes = dict(
            (r["kind"], r["n"])
            for r in conn.execute(
                "SELECT kind, COUNT(DISTINCT cve_id) AS n FROM cve_changes WHERE at >= ? GROUP BY kind", (since,)
            )
        )
        hits = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE is_test = 0 AND timestamp >= ?" + (" AND cve_id = ?" if cve_id else ""),
            (since, cve_id) if cve_id else (since,),
        ).fetchone()["n"]
    finally:
        conn.close()
    return {
        "new_cves": changes.get("new", 0),
        "updated_cves": changes.get("updated", 0),
        "newly_patched": changes.get("patched", 0),
        "newly_kev": changes.get("kev", 0),
        "total_hits": hits,
        "window": window,
    }


@app.get("/api/actors", response_model=list[Actor], response_model_exclude_none=True)
def list_actors(cve_id: str | None = None):
    """Attacker dossiers: IPs clustered into actors by shared payloads, infrastructure and identity."""
    dossiers = actors.current()[1]
    return [a for a in dossiers if cve_id in (a.get("cves") or [])] if cve_id else dossiers


@app.post("/ingest/events")
def ingest_events(hits: list[dict] = Body(...), x_ingest_key: str = Header("")):
    """Raw hits from the honeypot sensor: classify, attribute, store. Idempotent on hit id."""
    if not INGEST_KEY or not hmac.compare_digest(x_ingest_key, INGEST_KEY):
        raise HTTPException(401, "bad ingest key")
    if len(hits) > 500:
        raise HTTPException(413, "max 500 hits per batch")

    conn = db.connect()
    try:
        for h in hits:
            # Loopback/private sources can't be internet attackers: our own tests or health checks.
            try:
                if not ipaddress.ip_address(h["source_ip"]).is_global:
                    h["is_test"] = True
            except ValueError:
                h["is_test"] = True
        geo = geoip.lookup(conn, [h["source_ip"] for h in hits if not h.get("is_test")])
        stored = 0
        with conn:
            for h in hits:
                verdict = classify.classify(h.get("method", ""), h.get("path", ""), h.get("body_preview", ""), h.get("headers"))
                g = geo.get(h["source_ip"], {})
                cur = conn.execute(
                    """INSERT INTO events (id, source_ip, asn, port, timestamp, classification, org, country,
                           country_code, region, city, lat, lng, cve_id, method, path, stage, user_agent,
                           headers_json, body_preview, is_test)
                       VALUES (:id, :source_ip, :asn, :port, :timestamp, :classification, :org, :country,
                           :country_code, :region, :city, :lat, :lng, :cve_id, :method, :path, :stage, :user_agent,
                           :headers_json, :body_preview, :is_test)
                       ON CONFLICT (id) DO NOTHING""",
                    {
                        "id": str(h["id"])[:64],
                        "source_ip": str(h["source_ip"])[:64],
                        "port": int(h["port"]),
                        "timestamp": str(h["timestamp"])[:32],
                        "method": str(h.get("method", ""))[:16],
                        "path": str(h.get("path", ""))[:2048],
                        "user_agent": str(h.get("user_agent", ""))[:512],
                        "headers_json": json.dumps(h.get("headers") or {})[:8192],
                        "body_preview": str(h.get("body_preview", ""))[:4096],
                        "is_test": 1 if h.get("is_test") else 0,
                        **verdict,
                        **{k: g.get(k) for k in ("asn", "org", "country", "country_code", "region", "city", "lat", "lng")},
                    },
                )
                stored += max(cur.rowcount, 0)
    finally:
        conn.close()
    return {"received": len(hits), "stored": stored}


# --- CVE in, honeypot out (contract: "honeypot build pipeline") --------------------------------

RENDER_API_KEY = os.getenv("RENDER_API_KEY")
WORKFLOW_SLUG = os.getenv("ANGLER_WORKFLOW_SLUG", "angler-pipeline")


def _start_build(job_id: str, cve_id: str) -> None:
    """Run build_honeypot on Render Workflows when we can, else the same task code in-process."""
    if RENDER_API_KEY:
        try:
            from render import Render

            Render().workflows.start_task(f"{WORKFLOW_SLUG}/build_honeypot", [job_id, cve_id])
            return
        except Exception as e:
            print(f"workflow start failed, running in-process: {e}")
    import asyncio
    import threading

    from .pipeline import build_honeypot
    from .run_local import LocalContext

    def run():
        try:
            asyncio.run(LocalContext().run(build_honeypot, job_id, cve_id))
        except Exception as e:
            print(f"build_honeypot {job_id} failed: {e}")

    threading.Thread(target=run, daemon=True).start()


@app.post("/api/honeypots")
def create_honeypot(payload: dict = Body(...)):
    cve_id = str(payload.get("cve_id", "")).strip().upper()
    if not honeypots.CVE_ID.match(cve_id):
        raise HTTPException(422, "cve_id must look like CVE-2024-4577")
    job = honeypots.create(cve_id)
    _start_build(job["id"], cve_id)
    return job


@app.get("/api/honeypots")
def list_honeypots():
    """Published honeypots, one per CVE (latest publish wins). The dashboard makes a tab for each."""
    return honeypots.list_published()


@app.get("/api/honeypots/{job_id}")
def get_honeypot(job_id: str):
    job = honeypots.get(job_id)
    if not job:
        raise HTTPException(404, "no such job")
    return job


@app.post("/api/honeypots/{job_id}/publish")
def publish_honeypot(job_id: str):
    try:
        job = honeypots.publish(job_id)
    except ValueError as e:
        raise HTTPException(409, str(e))
    if not job:
        raise HTTPException(404, "no such job")
    return job
