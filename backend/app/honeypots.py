"""CVE in, honeypot out: the job behind POST /api/honeypots (contract: "honeypot build pipeline").

Each stage is real work, and a job that can't honestly finish fails with the reason:

    researching  load the CVE record (pull it from cvelistV5 if we don't track it) + KEV + patch status
    building     prebuilt CVEs continue; any other CVE gets a validated Gemini profile (static paths and
                 responses, no code) that the decoy starts serving
    containing   health-check the sandboxed decoy: it answers with the vulnerable banner
    ready        waits for the user to publish
    published    returns the live decoy URL; hits for this CVE are tagged targeted
"""

import json
import os
import re
import uuid

import httpx

from . import classify, db
from .enrich import kev, patch
from .ingest import cvelist

DECOY_URL = os.getenv("DECOY_URL", "http://34.72.134.92/")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
STATUSES = ("researching", "building", "containing", "ready", "published", "failed")


def _row(conn: db.Conn, job_id: str) -> dict | None:
    r = conn.execute("SELECT * FROM honeypot_jobs WHERE id = ?", (job_id,)).fetchone()
    return dict(r) if r else None


def view(row: dict) -> dict:
    """Contract shape (HoneypotJob)."""
    return {
        "id": row["id"],
        "cve_id": row["cve_id"],
        "status": row["status"],
        "advisory": json.loads(row["advisory_json"]) if row["advisory_json"] else None,
        "url": row["url"],
        "error": row["error"],
    }


def get(job_id: str) -> dict | None:
    conn = db.connect()
    try:
        row = _row(conn, job_id)
    finally:
        conn.close()
    return view(row) if row else None


def create(cve_id: str) -> dict:
    job_id = f"hp_{uuid.uuid4().hex[:10]}"
    conn = db.connect()
    with conn:
        conn.execute(
            """INSERT INTO honeypot_jobs (id, cve_id, status, created_at, updated_at)
               VALUES (?, ?, 'researching', ?, ?)""",
            (job_id, cve_id, db.now_iso(), db.now_iso()),
        )
        row = _row(conn, job_id)
    conn.close()
    return view(row)


def _set(job_id: str, **fields) -> None:
    fields["updated_at"] = db.now_iso()
    sets = ", ".join(f"{k} = :{k}" for k in fields)
    conn = db.connect()
    with conn:
        conn.execute(f"UPDATE honeypot_jobs SET {sets} WHERE id = :id", {**fields, "id": job_id})
    conn.close()


def fail(job_id: str, error: str) -> None:
    _set(job_id, status="failed", error=error)


# --- stages (each runs as its own Workflows task) -------------------------------------------------

def research(job_id: str, cve_id: str) -> dict | None:
    conn = db.connect()
    try:
        have = conn.execute("SELECT 1 FROM cves WHERE id = ?", (cve_id,)).fetchone()
    finally:
        conn.close()
    if not have:
        from .pipeline import store_items

        store_items([{"cve_id": cve_id, "url": kev.record_url(cve_id), "date_updated": "", "feed_kind": "backfill"}])

    conn = db.connect()
    try:
        row = conn.execute(
            "SELECT id, title, description, vendor, product, cvss, kev, patch_checked_at, affected_json FROM cves WHERE id = ?",
            (cve_id,),
        ).fetchone()
        if not row:
            fail(job_id, f"{cve_id} is not a published CVE in cvelistV5")
            return None
        if row["kev"] is None:
            with conn:
                kev.apply_one(conn, cve_id, kev.fetch_catalog())
        if row["patch_checked_at"] is None:
            with conn:
                patch.apply(conn, patch.check_many([{"id": cve_id, "affected_json": row["affected_json"]}]))
        row = conn.execute(
            "SELECT title, description, vendor, product, cvss, kev FROM cves WHERE id = ?", (cve_id,)
        ).fetchone()
    finally:
        conn.close()

    from .triage import product, summary

    advisory = {
        "description": summary(row["title"], row["description"]),
        "product": product(row["vendor"], row["product"]),
        "cvss": row["cvss"],
        "kev": row["kev"] == 1,
    }
    _set(job_id, status="building", advisory_json=json.dumps(advisory))
    return advisory


def _advisory_text(job_id: str) -> str:
    conn = db.connect()
    try:
        row = _row(conn, job_id)
    finally:
        conn.close()
    if not row or not row["advisory_json"]:
        return ""
    advisory = json.loads(row["advisory_json"])
    return f"{advisory.get('product') or ''} {advisory.get('description') or ''}".strip()


def build(job_id: str, cve_id: str) -> bool:
    """Prebuilt CVEs use the hand-built profiles. Anything else gets a validated Gemini profile installed."""
    if cve_id in classify.DECOY_CVES:
        _set(job_id, status="containing")
        return True
    from . import llm

    try:
        profile = llm.propose(cve_id, _advisory_text(job_id))
    except llm.ProfileError as e:
        fail(job_id, str(e))
        return False
    save_profile(cve_id, profile)  # validated static data; the sensor picks it up within ~30 s
    _set(job_id, status="containing")
    return True


def contain(job_id: str) -> bool:
    try:
        res = httpx.get(DECOY_URL, timeout=10, headers={"X-Angler-Test": "1"})
        banner = res.headers.get("server", "")
    except httpx.HTTPError as e:
        fail(job_id, f"Decoy health check failed: {e}")
        return False
    if "Apache/2.4.49" not in banner:
        fail(job_id, f"Decoy answered with an unexpected banner: {banner or 'none'}")
        return False
    _set(job_id, status="ready")
    return True


def publish(job_id: str) -> dict | None:
    conn = db.connect()
    try:
        row = _row(conn, job_id)
    finally:
        conn.close()
    if not row:
        return None
    if row["status"] != "ready":
        raise ValueError(f"job is {row['status']}, not ready")
    _set(job_id, status="published", url=DECOY_URL)
    return get(job_id)


def list_published() -> list[dict]:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM honeypot_jobs WHERE status = 'published' ORDER BY updated_at DESC"
        ).fetchall()
    finally:
        conn.close()
    seen, out = set(), []
    for r in rows:
        if r["cve_id"] not in seen:
            seen.add(r["cve_id"])
            out.append(view(dict(r)))
    return out


def save_profile(cve_id: str, profile: dict) -> None:
    conn = db.connect()
    with conn:
        conn.execute(
            """INSERT INTO decoy_profiles (cve_id, summary, responses_json, created_at) VALUES (?, ?, ?, ?)
               ON CONFLICT (cve_id) DO UPDATE SET summary = excluded.summary,
                   responses_json = excluded.responses_json, created_at = excluded.created_at""",
            (cve_id, profile["summary"], json.dumps(profile["responses"]), db.now_iso()),
        )
    conn.close()


def active_profiles() -> list[dict]:
    conn = db.connect()
    try:
        rows = conn.execute("SELECT cve_id, summary, responses_json FROM decoy_profiles").fetchall()
    finally:
        conn.close()
    return [{"cve_id": r["cve_id"], "summary": r["summary"], "responses": json.loads(r["responses_json"])} for r in rows]
