"""CISA Known Exploited Vulnerabilities: the urgent flag.

Every tracked CVE gets kev = 1/0. A 'kev' change row is logged when a CVE we track turns KEV,
dated by CISA's dateAdded, so "newly KEV in 24h" means CISA added it in the last 24h.
Recent KEV additions older than our feed window are backfilled so the urgent list isn't empty.
"""

import os
from datetime import date, timedelta

import httpx

from .. import db
from ..ingest import cvelist

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BACKFILL_DAYS = int(os.getenv("ANGLER_KEV_BACKFILL_DAYS", "30"))


def fetch_catalog() -> dict[str, dict]:
    res = httpx.get(KEV_URL, timeout=cvelist.TIMEOUT, headers=cvelist.HEADERS, follow_redirects=True)
    res.raise_for_status()
    return {v["cveID"]: v for v in res.json()["vulnerabilities"]}


def record_url(cve_id: str) -> str:
    _, year, num = cve_id.split("-")
    return f"{cvelist.RAW}/cves/{year}/{int(num) // 1000}xxx/{cve_id}.json"


def backfill_items(conn: db.Conn, catalog: dict[str, dict], days: int = BACKFILL_DAYS) -> list[dict]:
    cutoff = (date.today() - timedelta(days=days)).isoformat()
    have = {r["id"] for r in conn.execute("SELECT id FROM cves")}
    return [
        {"cve_id": cid, "url": record_url(cid), "date_updated": "", "feed_kind": "backfill"}
        for cid, v in sorted(catalog.items())
        if v["dateAdded"] >= cutoff and cid not in have
    ]


def apply_one(conn: db.Conn, cve_id: str, catalog: dict[str, dict]) -> bool:
    entry = catalog.get(cve_id)
    conn.execute(
        "UPDATE cves SET kev = ?, kev_date_added = ?, kev_checked_at = ? WHERE id = ?",
        (1 if entry else 0, entry["dateAdded"] if entry else None, db.now_iso(), cve_id),
    )
    return entry is not None


def apply(conn: db.Conn, catalog: dict[str, dict]) -> dict:
    """Set kev flags on every tracked CVE. Returns counts."""
    checked_at = db.now_iso()
    counts = {"kev": 0, "newly_kev": 0}
    rows = conn.execute("SELECT id, kev FROM cves").fetchall()
    for row in rows:
        entry = catalog.get(row["id"])
        if entry is None:
            conn.execute("UPDATE cves SET kev = 0, kev_checked_at = ? WHERE id = ?", (checked_at, row["id"]))
            continue
        counts["kev"] += 1
        conn.execute(
            "UPDATE cves SET kev = 1, kev_date_added = ?, kev_checked_at = ? WHERE id = ?",
            (entry["dateAdded"], checked_at, row["id"]),
        )
        if row["kev"] != 1:
            counts["newly_kev"] += 1
            conn.execute(
                "INSERT INTO cve_changes (cve_id, kind, at) VALUES (?, 'kev', ?)",
                (row["id"], f"{entry['dateAdded']}T00:00:00.000Z"),
            )
    return counts
