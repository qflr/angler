import json
import copy

import pytest

from app import db
from app.ingest import cvelist


def raw_record(cve_id="CVE-2026-0001", updated="2026-11-01T10:00:00.000Z", desc="Example bug", score=9.8):
    return {
        "dataType": "CVE_RECORD",
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "datePublished": "2026-11-01T09:00:00Z",
            "dateUpdated": updated,
        },
        "containers": {
            "cna": {
                "title": "Example",
                "descriptions": [{"lang": "en", "value": desc}],
                "affected": [{"vendor": "Acme", "product": "Widget", "versions": [{"version": "1.0", "status": "affected"}]}],
                "metrics": [{"cvssV3_1": {"baseScore": score, "baseSeverity": "CRITICAL"}}],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-78"}]}],
                "references": [{"url": "https://example.com/advisory"}],
            }
        },
    }


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "test.db")
    yield c
    c.close()


def test_norm_ts_orders_with_and_without_millis():
    assert cvelist.norm_ts("2026-11-01T10:00:00Z") == "2026-11-01T10:00:00.000Z"
    assert cvelist.norm_ts("2026-11-01T10:00:00.5Z") < cvelist.norm_ts("2026-11-01T10:00:01Z")


def test_parse_record_extracts_fields():
    cve = cvelist.parse_record(raw_record())
    assert cve["id"] == "CVE-2026-0001"
    assert (cve["vendor"], cve["product"]) == ("Acme", "Widget")
    assert (cve["cvss"], cve["severity"]) == (9.8, "critical")
    assert cve["cwes_json"] == '["CWE-78"]'


def test_upsert_dedups_by_id_and_content(conn):
    rec = cvelist.parse_record(raw_record())
    assert db.upsert_cve(conn, rec, "new") == "new"
    assert db.upsert_cve(conn, rec, "new") == "unchanged"
    assert db.upsert_cve(conn, rec, "updated") == "unchanged"

    changed = cvelist.parse_record(raw_record(updated="2026-11-01T11:00:00.000Z", desc="Now with exploit"))
    assert db.upsert_cve(conn, changed, "updated") == "updated"
    assert db.upsert_cve(conn, rec, "updated") == "stale"  # older copy never overwrites newer

    row = conn.execute("SELECT description FROM cves WHERE id = 'CVE-2026-0001'").fetchone()
    assert row["description"] == "Now with exploit"
    kinds = [r["kind"] for r in conn.execute("SELECT kind FROM cve_changes ORDER BY id")]
    assert kinds == ["new", "updated"]


def test_first_sighting_of_updated_cve_counts_as_updated(conn):
    assert db.upsert_cve(conn, cvelist.parse_record(raw_record("CVE-2019-1234")), "updated") == "updated"


def test_plan_delta_collapses_window():
    log = [
        {"fetchTime": "2026-11-01T12:00:00.000Z", "new": [], "updated": [
            {"cveId": "CVE-A", "githubLink": "u2", "dateUpdated": "2026-11-01T11:59:00.000Z"}]},
        {"fetchTime": "2026-11-01T11:00:00.000Z", "new": [
            {"cveId": "CVE-A", "githubLink": "u1", "dateUpdated": "2026-11-01T10:59:00.000Z"}], "updated": []},
        {"fetchTime": "2026-11-01T09:00:00.000Z", "new": [
            {"cveId": "CVE-OLD", "githubLink": "u0", "dateUpdated": "2026-11-01T08:59:00.000Z"}], "updated": []},
    ]
    items, cursor = cvelist.plan_delta(log, "2026-11-01T10:00:00.000Z")
    assert cursor == "2026-11-01T12:00:00.000Z"
    assert items == [{"cve_id": "CVE-A", "url": "u2", "date_updated": "2026-11-01T11:59:00.000Z", "feed_kind": "new"}]
    assert cvelist.plan_delta(log, cursor) == ([], cursor)


def test_pipeline_twice_is_idempotent(tmp_path, monkeypatch):
    from app import pipeline, run_local

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "pipe.db")
    log = [{"fetchTime": "2026-11-01T12:00:00.000Z", "updated": [], "new": [
        {"cveId": f"CVE-2026-000{i}", "githubLink": f"u{i}", "dateUpdated": "2026-11-01T10:00:00.000Z"} for i in range(5)]}]
    monkeypatch.setattr(cvelist, "fetch_delta_log", lambda: copy.deepcopy(log))
    monkeypatch.setattr(
        cvelist, "fetch_records",
        lambda items: [(i, raw_record(i["cve_id"]), None) for i in items],
    )
    monkeypatch.setattr(pipeline, "BATCH_SIZE", 2)

    first = run_local.run_once("2026-11-01T00:00:00.000Z")
    assert (first["new"], first["batches"]) == (5, 3)
    assert run_local.run_once()["items"] == 0                       # cursor advanced
    replay = run_local.run_once("2026-11-01T00:00:00.000Z")         # same window again
    assert (replay["new"], replay["updated"], replay["unchanged"]) == (0, 0, 5)


def test_patch_from_cve_record_ignores_unaffected_products():
    from app.enrich import patch

    affected = [
        {"product": "PAN-OS", "versions": [{"version": "10.2.0", "status": "affected", "lessThan": "10.2.9-h1",
                                            "changes": [{"at": "10.2.9-h1", "status": "unaffected"}]}]},
        {"product": "Cloud NGFW", "versions": [{"version": "All", "status": "unaffected"}]},
    ]
    assert patch.from_cve_record(json.dumps(affected)) == ("patched", ["PAN-OS@10.2.9-h1"], "cve-record")
    no_fix = [{"product": "X", "versions": [{"version": "1.0", "status": "affected"}]}]
    assert patch.from_cve_record(json.dumps(no_fix)) is None  # record can't prove "unpatched"


def test_patch_from_osv_partial_and_unpatched():
    from app.enrich import patch

    fixed = {"package": {"name": "a"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2"}]}]}
    open_ = {"package": {"name": "b"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}
    assert patch.from_osv_records([{"affected": [fixed]}]) == ("patched", ["a@1.2"], "osv")
    assert patch.from_osv_records([{"affected": [fixed, open_]}])[0] == "partial"
    assert patch.from_osv_records([{"affected": [open_]}])[0] == "unpatched"


def test_nvd_parse_prefers_primary():
    from app.enrich import nvd

    payload = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}},
        {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]}
    assert nvd.parse(payload) == (9.8, "critical")
    assert nvd.parse({"vulnerabilities": [{"cve": {"metrics": {}}}]}) is None


def test_pg_sql_translation():
    assert db._pg_sql("UPDATE t SET a = :a, b = ? WHERE id = :id AND x LIKE '5%'") == (
        "UPDATE t SET a = %(a)s, b = %s WHERE id = %(id)s AND x LIKE '5%%'"
    )
    assert db._pg_sql("SELECT x::text") == "SELECT x::text"


def test_every_sql_statement_translates_cleanly():
    """No sqlite-only functions slipped into the job SQL."""
    import pathlib

    src = "".join(p.read_text() for p in pathlib.Path("app").rglob("*.py") if p.name != "db.py")
    assert "strftime(" not in src.replace("datetime", "").replace(".strftime(", "")


def test_no_control_characters_in_source():
    import pathlib

    for f in pathlib.Path("app").rglob("*.py"):
        text = f.read_text(encoding="utf-8")
        assert not [c for c in text if ord(c) < 32 and c not in "\n\r\t"], f"control character in {f}"
