"""SQLite storage for CVEs, their change log, and pipeline state.

Plain sqlite3 so it runs anywhere. Note for deploy: Workflows task runs each get their own
compute, so a shared SQLite file only works locally. Deployed runs need Postgres (DATABASE_URL).
"""

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("ANGLER_DB", Path(__file__).resolve().parents[1] / "angler.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    id               TEXT PRIMARY KEY,
    state            TEXT NOT NULL,
    title            TEXT,
    description      TEXT,
    vendor           TEXT,
    product          TEXT,
    affected_json    TEXT,
    references_json  TEXT,
    cwes_json        TEXT,
    date_published   TEXT,
    date_updated     TEXT NOT NULL,
    record_hash      TEXT NOT NULL,
    cvss             REAL,
    severity         TEXT,
    severity_source  TEXT,
    -- enrichment (Phase 2), NULL until a job has checked
    kev              INTEGER,
    kev_date_added   TEXT,
    patch_status     TEXT,
    fixed_versions_json TEXT,
    first_ingested_at TEXT NOT NULL,
    last_changed_at  TEXT NOT NULL
);

-- One row per meaningful change; /api/stats counts these.
CREATE TABLE IF NOT EXISTS cve_changes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id  TEXT NOT NULL,
    kind    TEXT NOT NULL,  -- new | updated | patched | kev
    at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cve_changes_at ON cve_changes (at);

-- Feed items that failed to fetch or came back older than the feed promised; retried next run.
CREATE TABLE IF NOT EXISTS ingest_pending (
    cve_id       TEXT PRIMARY KEY,
    url          TEXT NOT NULL,
    date_updated TEXT NOT NULL,
    feed_kind    TEXT NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT
);

CREATE TABLE IF NOT EXISTS ingest_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    since       TEXT,
    cursor      TEXT,
    counts_json TEXT
);

CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def get_state(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def record_hash(raw: dict) -> str:
    return hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def upsert_cve(conn: sqlite3.Connection, cve: dict, feed_kind: str, at: str | None = None) -> str:
    """Store one parsed CVE. Returns new | updated | unchanged | stale.

    Dedup is by CVE ID. A record is only rewritten when its content hash changed and it is not
    older than what we hold, so replaying the same feed window is a no-op.
    """
    at = at or now_iso()
    row = conn.execute("SELECT date_updated, record_hash FROM cves WHERE id = ?", (cve["id"],)).fetchone()

    if row is None:
        conn.execute(
            """INSERT INTO cves (id, state, title, description, vendor, product, affected_json,
                   references_json, cwes_json, date_published, date_updated, record_hash, cvss, severity,
                   severity_source, first_ingested_at, last_changed_at)
               VALUES (:id, :state, :title, :description, :vendor, :product, :affected_json,
                   :references_json, :cwes_json, :date_published, :date_updated, :record_hash, :cvss,
                   :severity, :severity_source, :at, :at)""",
            {**cve, "at": at},
        )
        # First sighting of a CVE the feed calls "updated" is an old CVE that changed, not a new one.
        kind = "new" if feed_kind == "new" else "updated"
        conn.execute("INSERT INTO cve_changes (cve_id, kind, at) VALUES (?, ?, ?)", (cve["id"], kind, at))
        return kind

    if cve["date_updated"] < row["date_updated"]:
        return "stale"
    if cve["record_hash"] == row["record_hash"]:
        return "unchanged"

    conn.execute(
        """UPDATE cves SET state = :state, title = :title, description = :description, vendor = :vendor,
               product = :product, affected_json = :affected_json, references_json = :references_json,
               cwes_json = :cwes_json, date_published = :date_published, date_updated = :date_updated,
               record_hash = :record_hash,
               cvss = COALESCE(:cvss, cvss),
               severity = COALESCE(:severity, severity),
               severity_source = COALESCE(:severity_source, severity_source),
               last_changed_at = :at
           WHERE id = :id""",
        {**cve, "at": at},
    )
    conn.execute("INSERT INTO cve_changes (cve_id, kind, at) VALUES (?, 'updated', ?)", (cve["id"], at))
    return "updated"
