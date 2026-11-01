"""CVEProject/cvelistV5 delta feed: what changed since a cursor, and the records themselves.

cves/deltaLog.json lists every repo update for the last ~30 days (fetchTime + new/updated CVE IDs),
so a poller can miss any number of commits and still catch up. ~2 MB gzipped.
"""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx

from ..db import record_hash

RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
DELTA_LOG_URL = f"{RAW}/cves/deltaLog.json"
TIMEOUT = httpx.Timeout(30.0)
HEADERS = {"User-Agent": "angler-cve-ingest (LarpHacks 2026)"}


def norm_ts(value: str | None) -> str | None:
    """Canonical UTC timestamp with milliseconds, so string comparison orders correctly."""
    if not value:
        return value
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def bootstrap_cursor(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def fetch_delta_log() -> list[dict]:
    res = httpx.get(DELTA_LOG_URL, timeout=TIMEOUT, headers=HEADERS, follow_redirects=True)
    res.raise_for_status()
    return res.json()


def plan_delta(delta_log: list[dict], cursor: str) -> tuple[list[dict], str]:
    """Collapse every delta entry newer than `cursor` into one item per CVE ID.

    Returns (items, new_cursor). Each item keeps the newest dateUpdated seen, and is "new" if any
    entry in the window called it new. Timestamps share one ISO format, so string compare is safe.
    """
    items: dict[str, dict] = {}
    new_cursor = cursor
    for entry in delta_log:
        fetch_time = norm_ts(entry["fetchTime"])
        if fetch_time <= cursor:
            continue
        new_cursor = max(new_cursor, fetch_time)
        for kind in ("new", "updated"):
            for c in entry.get(kind, []):
                prev = items.get(c["cveId"])
                item = {
                    "cve_id": c["cveId"],
                    "url": c["githubLink"],
                    "date_updated": norm_ts(c["dateUpdated"]),
                    "feed_kind": kind,
                }
                if prev is None:
                    items[c["cveId"]] = item
                else:
                    if item["date_updated"] > prev["date_updated"]:
                        prev.update(url=item["url"], date_updated=item["date_updated"])
                    if kind == "new":
                        prev["feed_kind"] = "new"
    return sorted(items.values(), key=lambda i: i["cve_id"]), new_cursor


def fetch_records(items: list[dict], workers: int = 16) -> list[tuple[dict, dict | None, str | None]]:
    """Fetch raw CVE JSON for each item. Returns (item, raw_or_None, error_or_None)."""
    with httpx.Client(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as client:

        def one(item: dict):
            try:
                # Query string keys the CDN cache to this revision, so we don't get a stale copy.
                res = client.get(item["url"], params={"v": item["date_updated"]})
                res.raise_for_status()
                raw = res.json()
            except (httpx.HTTPError, json.JSONDecodeError) as e:
                return item, None, f"{type(e).__name__}: {e}"
            got = norm_ts(raw.get("cveMetadata", {}).get("dateUpdated")) or ""
            if got < item["date_updated"]:
                return item, None, f"lagging copy: got {got}, feed says {item['date_updated']}"
            return item, raw, None

        with ThreadPoolExecutor(workers) as pool:
            return list(pool.map(one, items))


# --- parsing -----------------------------------------------------------------------------------

_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


def _english(entries: list[dict] | None) -> str | None:
    entries = entries or []
    for e in entries:
        if e.get("lang", "").lower().startswith("en") and e.get("value"):
            return e["value"].strip()
    return entries[0]["value"].strip() if entries and entries[0].get("value") else None


def _cvss(containers: list[dict]) -> tuple[float | None, str | None]:
    """Highest-version CVSS score present in the CNA or any ADP container."""
    for key in _CVSS_KEYS:
        for container in containers:
            for metric in container.get("metrics", []) or []:
                data = metric.get(key)
                if data and data.get("baseScore") is not None:
                    sev = data.get("baseSeverity")
                    return float(data["baseScore"]), sev.lower() if sev else None
    return None, None


def parse_record(raw: dict) -> dict:
    meta = raw["cveMetadata"]
    containers = raw.get("containers", {})
    cna = containers.get("cna", {})
    adp = containers.get("adp", []) or []

    affected = cna.get("affected", []) or []
    named = [a for a in affected if (a.get("product") or "").lower() not in ("", "n/a")]
    first = named[0] if named else {}

    cwes = sorted(
        {
            d["cweId"]
            for pt in cna.get("problemTypes", []) or []
            for d in pt.get("descriptions", []) or []
            if d.get("cweId")
        }
    )
    refs = [r["url"] for r in cna.get("references", []) or [] if r.get("url")]
    cvss, severity = _cvss([cna, *adp])

    description = _english(cna.get("descriptions")) or _english(cna.get("rejectedReasons")) or ""

    return {
        "id": meta["cveId"],
        "state": meta.get("state", "PUBLISHED"),
        "title": cna.get("title"),
        "description": description,
        "vendor": first.get("vendor"),
        "product": first.get("product"),
        "affected_json": json.dumps(
            [{"vendor": a.get("vendor"), "product": a.get("product"), "versions": a.get("versions", [])} for a in named]
        ),
        "references_json": json.dumps(refs),
        "cwes_json": json.dumps(cwes),
        "date_published": norm_ts(meta.get("datePublished")),
        "date_updated": norm_ts(meta["dateUpdated"]),
        "record_hash": record_hash(raw),
        "cvss": cvss,
        "severity": severity,
        "severity_source": "cve-record" if cvss is not None else None,
    }
