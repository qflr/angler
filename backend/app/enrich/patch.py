"""Patch status: does a vendor/upstream fix exist?

Sources, first one with an answer wins:
  1. OSV.dev: the CVE's own OSV record (fix commits) plus its GHSA aliases, read through OSV's
     mirror of GitHub Advisories (ecosystem packages with fixed versions). No rate limit.
  2. GitHub Advisories API directly, only when GITHUB_TOKEN is set (unauthenticated is 60/hr).
  3. The CVE record's own affected[].versions (a lessThan bound or a change to "unaffected").

Status is patched (every affected package has a fix), partial (some do), or unpatched (a source
lists the affected packages and none has a fix). If no source knows, patch_status stays NULL;
we never report "unpatched" just because we found nothing.
"""

import json
import os
from concurrent.futures import ThreadPoolExecutor

import httpx

from .. import db
from ..ingest import cvelist

OSV_URL = "https://api.osv.dev/v1/vulns/{}"
GHSA_URL = "https://api.github.com/advisories"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# A result is (status, fixed_versions, source) or None when the source has no opinion.
Result = tuple[str, list[str], str] | None


def _status(entries: list[tuple[str, list[str]]]) -> tuple[str, list[str]] | None:
    """entries: (label, fixes) per affected package."""
    if not entries:
        return None
    with_fix = [e for e in entries if e[1]]
    fixed = sorted({f"{label}@{f}" if label else f for label, fixes in with_fix for f in fixes})
    if len(with_fix) == len(entries):
        return "patched", fixed
    return ("partial" if with_fix else "unpatched"), fixed


def from_osv_records(records: list[dict]) -> Result:
    entries = []
    for rec in records:
        for aff in rec.get("affected", []) or []:
            pkg = aff.get("package") or {}
            for rng in aff.get("ranges", []) or []:  # entries with only a version list say nothing about fixes
                label = pkg.get("name") or (rng.get("repo") or "").removeprefix("https://github.com/")
                fixes = [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
                if rng.get("type") == "GIT":
                    fixes = [f[:10] for f in fixes]
                entries.append((label, fixes))
    res = _status(entries)
    return (res[0], res[1], "osv") if res else None


def from_github_advisories(advisories: list[dict]) -> Result:
    entries = [
        ((v.get("package") or {}).get("name", ""), [v["first_patched_version"]] if v.get("first_patched_version") else [])
        for adv in advisories
        for v in adv.get("vulnerabilities", []) or []
    ]
    res = _status(entries)
    return (res[0], res[1], "ghsa") if res else None


def from_cve_record(affected_json: str | None) -> Result:
    entries = []
    for aff in json.loads(affected_json or "[]"):
        versions = aff.get("versions") or []
        # Products listed only as unaffected (e.g. "Cloud NGFW: All unaffected") need no fix.
        if not any(v.get("status") == "affected" for v in versions):
            continue
        fixes = []
        for v in versions:
            fixes += [c["at"] for c in v.get("changes", []) or [] if c.get("status") == "unaffected" and c.get("at")]
            bound = v.get("lessThan")
            if v.get("status") == "affected" and bound and bound not in ("*", "n/a") and not v.get("changes"):
                fixes.append(bound)
        entries.append((aff.get("product") or "", fixes))
    # The record alone can show a fix exists; it can't prove one doesn't, so no "unpatched" from here.
    res = _status(entries)
    if not res or res[0] == "unpatched":
        return None
    return res[0], res[1], "cve-record"


def check(client: httpx.Client, cve_id: str, affected_json: str | None) -> Result:
    res = client.get(OSV_URL.format(cve_id))
    if res.status_code == 200:
        rec = res.json()
        records = [rec]
        for alias in rec.get("aliases", []):
            if alias.startswith("GHSA-"):
                r = client.get(OSV_URL.format(alias))
                if r.status_code == 200:
                    records.append(r.json())
        found = from_osv_records(records)
        if found:
            return found
    elif res.status_code != 404:
        res.raise_for_status()

    if GITHUB_TOKEN:
        r = client.get(
            GHSA_URL,
            params={"cve_id": cve_id},
            headers={"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"},
        )
        if r.status_code == 200:
            found = from_github_advisories(r.json())
            if found:
                return found

    return from_cve_record(affected_json)


def check_many(rows: list[dict], workers: int = 16) -> list[tuple[str, Result, str | None]]:
    """rows: {id, affected_json}. Returns (cve_id, result, error)."""
    with httpx.Client(timeout=cvelist.TIMEOUT, headers=cvelist.HEADERS, follow_redirects=True) as client:

        def one(row):
            try:
                return row["id"], check(client, row["id"], row["affected_json"]), None
            except httpx.HTTPError as e:
                return row["id"], None, f"{type(e).__name__}: {e}"

        with ThreadPoolExecutor(workers) as pool:
            return list(pool.map(one, rows))


RECHECK_HOURS = int(os.getenv("ANGLER_PATCH_RECHECK_HOURS", "6"))


def due(conn: db.Conn, limit: int) -> list[dict]:
    """CVEs never checked, changed since their last check, or not yet patched and due a recheck."""
    rows = conn.execute(
        """SELECT id, affected_json FROM cves
           WHERE state = 'PUBLISHED' AND (
               patch_checked_at IS NULL
               OR last_changed_at > patch_checked_at
               OR (COALESCE(patch_status, '') != 'patched'
                   AND patch_checked_at < ?))
           ORDER BY COALESCE(kev, 0) DESC, COALESCE(date_published, '') DESC
           LIMIT ?""",
        (db.hours_ago(RECHECK_HOURS), limit),
    ).fetchall()
    return [dict(r) for r in rows]


def apply(conn: db.Conn, results: list[tuple[str, Result, str | None]]) -> dict:
    """Store results. Logs 'patched' only on an observed unpatched/partial -> patched transition."""
    at = db.now_iso()
    counts = {"checked": 0, "patched": 0, "partial": 0, "unpatched": 0, "unknown": 0, "newly_patched": 0, "errors": 0}
    for cve_id, result, error in results:
        if error:
            counts["errors"] += 1
            continue
        counts["checked"] += 1
        prev = conn.execute("SELECT patch_status FROM cves WHERE id = ?", (cve_id,)).fetchone()["patch_status"]
        if result is None:
            counts["unknown"] += 1
            conn.execute("UPDATE cves SET patch_checked_at = ? WHERE id = ?", (at, cve_id))
            continue
        status, fixed, source = result
        counts[status] += 1
        conn.execute(
            """UPDATE cves SET patch_status = ?, patch_source = ?, fixed_versions_json = ?, patch_checked_at = ?
               WHERE id = ?""",
            (status, source, json.dumps(fixed[:20]), at, cve_id),
        )
        if status == "patched" and prev in ("unpatched", "partial"):
            counts["newly_patched"] += 1
            conn.execute("INSERT INTO cve_changes (cve_id, kind, at) VALUES (?, 'patched', ?)", (cve_id, at))
    return counts
