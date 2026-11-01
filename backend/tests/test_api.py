import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import db, triage
from app.ingest import cvelist
from app.main import app
from app.schemas import Actor, AttackEvent, Cve, Stats
from tests.test_ingest import raw_record

client = TestClient(app)
TYPES_TS = Path(__file__).resolve().parents[2] / "frontend" / "src" / "data" / "types.ts"


def ts_fields(interface: str) -> dict[str, bool]:
    """Field name -> required, parsed from an interface in frontend/src/data/types.ts."""
    body = re.search(rf"export interface {interface} \{{(.*?)\n\}}", TYPES_TS.read_text(), re.S).group(1)
    return {m.group(1): not m.group(2) for m in re.finditer(r"^\s+(\w+)(\?)?:", body, re.M)}


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "api.db")
    monkeypatch.setattr(db, "DATABASE_URL", None)
    conn = db.connect()
    with conn:
        db.upsert_cve(conn, cvelist.parse_record(raw_record("CVE-2026-0001")), "new")
        unscored = raw_record("CVE-2026-0002", score=None)
        unscored["containers"]["cna"]["metrics"] = []
        db.upsert_cve(conn, cvelist.parse_record(unscored), "updated")
        conn.execute("UPDATE cves SET kev = 1, patch_status = 'patched' WHERE id = 'CVE-2026-0001'")
        for i, (ip, test) in enumerate([("203.0.113.5", 0), ("203.0.113.6", 0), ("127.0.0.1", 1)]):
            # Same /24 and same User-Agent: the clustering should fold both IPs into one actor.
            conn.execute(
                """INSERT INTO events (id, source_ip, asn, port, timestamp, classification, user_agent, is_test)
                   VALUES (?, ?, ?, 443, ?, ?, 'botnet-x/1.0', ?)""",
                (f"h{i}", ip, 64500 if i else None, db.now_iso(), "targeted" if i == 0 else "noise", test),
            )
    conn.close()


def test_models_match_frontend_types():
    for ts_name, model in [("Cve", Cve), ("AttackEvent", AttackEvent), ("Stats", Stats), ("Actor", Actor)]:
        py = {name: f.is_required() for name, f in model.model_fields.items()}
        assert py == ts_fields(ts_name), f"{ts_name} drifted from frontend/src/data/types.ts"


def test_endpoints_return_real_rows(seeded):
    cves = client.get("/api/cves").json()
    assert [c["id"] for c in cves] == ["CVE-2026-0001", "CVE-2026-0002"]  # KEV (urgent) first
    assert cves[0]["status"] == "urgent" and cves[0]["kev"] is True
    assert (cves[1]["severity"], cves[1]["patch_status"]) == ("unknown", "unknown")

    events = client.get("/api/events").json()
    assert {e["source_ip"] for e in events} == {"203.0.113.5", "203.0.113.6"}  # test hit excluded
    assert {e["asn"] for e in events} == {0, 64500}

    stats = client.get("/api/stats").json()
    assert stats == {"new_cves": 1, "updated_cves": 1, "newly_patched": 0, "newly_kev": 0, "total_hits": 2, "window": "24h"}

    actors = client.get("/api/actors").json()
    assert len(actors) == 1 and actors[0]["hit_count"] == 2 and actors[0]["classification"] == "targeted"
    assert actors[0]["ips"] == ["203.0.113.5", "203.0.113.6"]
    assert {e["actor_id"] for e in events} == {actors[0]["id"]}  # events link to their dossier

    for path, model in [("/api/cves", Cve), ("/api/events", AttackEvent), ("/api/actors", Actor)]:
        res = client.get(path)
        assert res.headers["X-Angler-Data-Source"] == "db"
        for item in res.json():
            model.model_validate(item)


def test_empty_db_is_empty_not_fake(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "empty.db")
    monkeypatch.setattr(db, "DATABASE_URL", None)
    assert client.get("/api/cves").json() == []
    assert client.get("/api/events").json() == []
    assert client.get("/api/actors").json() == []
    assert client.get("/api/stats").json()["total_hits"] == 0


def test_bad_params(seeded):
    assert client.get("/api/events?limit=0").status_code == 422
    assert client.get("/api/stats?window=forever").status_code == 422
    assert client.get("/api/stats?window=7d").json()["window"] == "7d"


def test_cors_allows_local_dev(seeded):
    res = client.get("/api/cves", headers={"Origin": "http://localhost:5173"})
    assert res.headers["access-control-allow-origin"] == "http://localhost:5173"
    res = client.get("/api/cves", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in res.headers


def test_triage_rules():
    rce = '["CWE-78"]'
    assert triage.status(True, "patched", None, "") == "urgent"
    assert triage.status(False, "unpatched", rce, "A remote attacker can inject OS commands") == "high"
    assert triage.status(False, None, None, "Unauthenticated remote code execution via crafted request") == "high"
    assert triage.status(False, "patched", rce, "A remote attacker can inject OS commands") == "watch"
    assert triage.status(False, "unpatched", rce, "A local user can inject OS commands") == "watch"
    assert triage.status(False, "unknown", '["CWE-79","CWE-94"]', "remote XSS allows code injection", 4.8) == "watch"
    assert triage.summary("Short useful title", "Long description.") == "Short useful title"
    assert triage.summary("Security Advisory 0199", "Arista VCO auth bypass. More.") == "Arista VCO auth bypass."
    assert triage.summary(None, "First sentence. Second sentence.") == "First sentence."
    assert triage.product("Acme", "Acme Widget") == "Acme Widget"
    assert triage.product("Acme", "Widget") == "Acme Widget"
    assert triage.product("n/a", "TP-Link Archer AX21") == "TP-Link Archer AX21"
