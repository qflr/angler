"""Render Workflows tasks for the CVE ingestion spine.

Workflows has no ctx.step(); the checkpoint unit is a task. Each stage below is its own task, so
Render retries it on its own and a failed batch never re-runs the stages before it:

    ingest_cves ──► plan_cve_delta ──► ingest_cve_batch × N (parallel) ──► commit_cve_cursor

The cursor only advances after every batch has finished, and every write is an idempotent
upsert, so a crashed run is safe to replay in full.
"""

import asyncio
import json
import os

from render import Retry, TaskContext, Workflows

from . import db
from .ingest import cvelist

BATCH_SIZE = int(os.getenv("ANGLER_BATCH_SIZE", "100"))
BOOTSTRAP_HOURS = int(os.getenv("ANGLER_BOOTSTRAP_HOURS", "24"))
CURSOR_KEY = "cvelist_cursor"
MAX_PENDING_ATTEMPTS = 5

app = Workflows(default_retry=Retry(max_retries=3, wait_duration_ms=2000, backoff_scaling=2.0))


@app.task
def plan_cve_delta(ctx: TaskContext, since: str | None = None) -> dict:
    """Read the cursor and the delta log, return the deduped work list (plus retried stragglers)."""
    conn = db.connect()
    cursor = since or db.get_state(conn, CURSOR_KEY) or cvelist.bootstrap_cursor(BOOTSTRAP_HOURS)
    items, new_cursor = cvelist.plan_delta(cvelist.fetch_delta_log(), cursor)

    seen = {i["cve_id"] for i in items}
    pending = conn.execute(
        "SELECT cve_id, url, date_updated, feed_kind FROM ingest_pending WHERE attempts < ?",
        (MAX_PENDING_ATTEMPTS,),
    ).fetchall()
    items += [dict(p) for p in pending if p["cve_id"] not in seen]
    conn.close()
    return {"since": cursor, "cursor": new_cursor, "items": items}


@app.task
def ingest_cve_batch(ctx: TaskContext, items: list[dict]) -> dict:
    """Fetch, parse and upsert one batch. Failures go to ingest_pending instead of failing the run."""
    counts = {"new": 0, "updated": 0, "unchanged": 0, "stale": 0, "failed": 0}
    results = cvelist.fetch_records(items)
    conn = db.connect()
    with conn:
        for item, raw, error in results:
            if raw is not None:
                try:
                    outcome = db.upsert_cve(conn, cvelist.parse_record(raw), item["feed_kind"])
                except (KeyError, TypeError, ValueError) as e:
                    error = f"parse: {type(e).__name__}: {e}"
                else:
                    counts[outcome] += 1
                    conn.execute("DELETE FROM ingest_pending WHERE cve_id = ?", (item["cve_id"],))
                    continue
            counts["failed"] += 1
            conn.execute(
                """INSERT INTO ingest_pending (cve_id, url, date_updated, feed_kind, attempts, last_error)
                   VALUES (?, ?, ?, ?, 1, ?)
                   ON CONFLICT (cve_id) DO UPDATE SET url = excluded.url, date_updated = excluded.date_updated,
                       attempts = attempts + 1, last_error = excluded.last_error""",
                (item["cve_id"], item["url"], item["date_updated"], item["feed_kind"], error),
            )
    conn.close()
    return counts


@app.task
def commit_cve_cursor(ctx: TaskContext, since: str, cursor: str, counts: dict) -> str:
    conn = db.connect()
    with conn:
        db.set_state(conn, CURSOR_KEY, cursor)
        conn.execute(
            "INSERT INTO ingest_runs (started_at, finished_at, since, cursor, counts_json) VALUES (?, ?, ?, ?, ?)",
            (counts.pop("started_at"), db.now_iso(), since, cursor, json.dumps(counts)),
        )
    conn.close()
    return cursor


@app.task
async def ingest_cves(ctx: TaskContext, since: str | None = None) -> dict:
    """Root task: one hourly (or 15-min demo) pull of cvelistV5 changes."""
    started_at = db.now_iso()
    plan = await ctx.run(plan_cve_delta, since)
    items = plan["items"]
    batches = [items[i : i + BATCH_SIZE] for i in range(0, len(items), BATCH_SIZE)]
    results = await asyncio.gather(*(ctx.run(ingest_cve_batch, b) for b in batches))

    counts = {"items": len(items), "batches": len(batches)}
    for r in results:
        for k, v in r.items():
            counts[k] = counts.get(k, 0) + v
    await ctx.run(commit_cve_cursor, plan["since"], plan["cursor"], {**counts, "started_at": started_at})
    return {"since": plan["since"], "cursor": plan["cursor"], **counts}
