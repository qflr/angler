"""NVD severity, only for CVEs whose own record carried no CVSS score.

NVD is the laggiest source (new CVEs often wait days for analysis) and rate-limited: 5 requests per
30 s without a key, 50 with NVD_API_KEY. So this job is small, throttled, and runs last.
"""

import os
import sqlite3
import time

import httpx

from .. import db
from ..ingest import cvelist

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
DELAY = 0.7 if NVD_API_KEY else 6.5
RECHECK_HOURS = int(os.getenv("ANGLER_NVD_RECHECK_HOURS", "12"))
_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def parse(payload: dict) -> tuple[float, str] | None:
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None
    metrics = vulns[0]["cve"].get("metrics", {})
    for key in _METRIC_KEYS:
        entries = metrics.get(key) or []
        # Prefer NVD's own scoring over a CNA's when both exist.
        entries = sorted(entries, key=lambda m: m.get("type") != "Primary")
        for m in entries:
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or m.get("baseSeverity")
            if score is not None and severity:
                return float(score), severity.lower()
    return None


def due(conn: sqlite3.Connection, limit: int) -> list[str]:
    rows = conn.execute(
        """SELECT id FROM cves
           WHERE state = 'PUBLISHED' AND cvss IS NULL
             AND (nvd_checked_at IS NULL
                  OR nvd_checked_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?))
           ORDER BY kev DESC, date_published DESC
           LIMIT ?""",
        (f"-{RECHECK_HOURS} hours", limit),
    ).fetchall()
    return [r["id"] for r in rows]


def run(conn: sqlite3.Connection, cve_ids: list[str]) -> dict:
    counts = {"checked": 0, "scored": 0, "errors": 0}
    headers = {**cvelist.HEADERS, **({"apiKey": NVD_API_KEY} if NVD_API_KEY else {})}
    with httpx.Client(timeout=cvelist.TIMEOUT, headers=headers) as client:
        for i, cve_id in enumerate(cve_ids):
            if i:
                time.sleep(DELAY)
            try:
                res = client.get(NVD_URL, params={"cveId": cve_id})
                res.raise_for_status()
                found = parse(res.json())
            except (httpx.HTTPError, ValueError, KeyError):
                counts["errors"] += 1
                continue
            counts["checked"] += 1
            with conn:
                if found:
                    counts["scored"] += 1
                    conn.execute(
                        """UPDATE cves SET cvss = ?, severity = ?, severity_source = 'nvd', nvd_checked_at = ?
                           WHERE id = ? AND cvss IS NULL""",
                        (*found, db.now_iso(), cve_id),
                    )
                else:
                    conn.execute("UPDATE cves SET nvd_checked_at = ? WHERE id = ?", (db.now_iso(), cve_id))
    return counts
