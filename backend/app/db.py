"""Storage for CVEs, their change log, and pipeline state.

Postgres when DATABASE_URL is set (Render: every Workflows task runs on its own compute, so they
need a shared database), otherwise a local SQLite file. Both sit behind Conn, and all SQL here and
in the jobs is written to run on both: ? and :name params, no dialect-specific functions.
"""

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATABASE_URL = os.getenv("DATABASE_URL")
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
    kev_checked_at   TEXT,
    patch_status     TEXT,     -- patched | partial | unpatched, NULL = no source knows
    patch_source     TEXT,     -- osv | ghsa | cve-record
    fixed_versions_json TEXT,
    patch_checked_at TEXT,
    nvd_checked_at   TEXT,
    first_ingested_at TEXT NOT NULL,
    last_changed_at  TEXT NOT NULL
);

-- One row per meaningful change; /api/stats counts these.
CREATE TABLE IF NOT EXISTS cve_changes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id  TEXT NOT NULL,
    kind    TEXT NOT NULL,  -- new | updated | patched | kev  (kev rows are dated by CISA dateAdded)
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


# Columns added after a DB may already exist; connect() adds any that are missing.
LATE_COLUMNS = {
    "cves": {
        "kev_checked_at": "TEXT",
        "patch_source": "TEXT",
        "patch_checked_at": "TEXT",
        "nvd_checked_at": "TEXT",
    }
}


_NAMED_PARAM = re.compile(r"(?<![:\w]):(\w+)")
_SCHEMA_LOCK = 4242  # pg advisory lock id: parallel tasks may all create the schema at once


def _pg_sql(sql: str) -> str:
    sql = sql.replace("%", "%%").replace("?", "%s")
    return _NAMED_PARAM.sub(r"%(\1)s", sql)


class Conn:
    """One interface over sqlite3 and psycopg. `with conn:` is a transaction (commit or rollback)."""

    def __init__(self, raw, pg: bool):
        self.raw = raw
        self.pg = pg

    def execute(self, sql: str, params=()):
        return self.raw.execute(_pg_sql(sql) if self.pg else sql, params)

    def commit(self) -> None:
        self.raw.commit()

    def close(self) -> None:
        self.raw.close()

    def __enter__(self) -> "Conn":
        return self

    def __exit__(self, exc_type, *_) -> None:
        if exc_type:
            self.raw.rollback()
        else:
            self.raw.commit()


def _connect_pg() -> Conn:
    import psycopg
    from psycopg.rows import dict_row

    raw = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    raw.execute("SELECT pg_advisory_lock(%s)", (_SCHEMA_LOCK,))
    raw.execute(SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY"))
    for table, cols in LATE_COLUMNS.items():
        for name, decl in cols.items():
            raw.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {name} {decl}")
    raw.execute("SELECT pg_advisory_unlock(%s)", (_SCHEMA_LOCK,))
    raw.commit()
    return Conn(raw, pg=True)


def connect(path: Path | str | None = None) -> Conn:
    """Postgres if DATABASE_URL is set and no explicit SQLite path is given, else SQLite."""
    if DATABASE_URL and path is None:
        return _connect_pg()
    raw = sqlite3.connect(path or DB_PATH, timeout=30)
    raw.row_factory = sqlite3.Row
    raw.execute("PRAGMA journal_mode=WAL")
    raw.executescript(SCHEMA)
    for table, cols in LATE_COLUMNS.items():
        have = {r["name"] for r in raw.execute(f"PRAGMA table_info({table})")}
        for name, decl in cols.items():
            if name not in have:
                raw.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    raw.commit()
    return Conn(raw, pg=False)


def hours_ago(hours: float) -> str:
    """Cutoff in the same format as now_iso(), for portable time-window queries."""
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_state(conn: Conn, key: str) -> str | None:
    row = conn.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_state(conn: Conn, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def record_hash(raw: dict) -> str:
    return hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def upsert_cve(conn: Conn, cve: dict, feed_kind: str, at: str | None = None) -> str:
    """Store one parsed CVE. Returns new | updated | unchanged | stale | backfilled.

    feed_kind "backfill" stores a CVE we pulled in for context (e.g. a recent KEV entry older than
    our feed window) without logging it as a new or updated CVE.

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
        if feed_kind == "backfill":
            return "backfilled"
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
