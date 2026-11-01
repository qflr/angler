import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.schemas import Actor, AttackEvent, Cve, Stats

client = TestClient(app)
TYPES_TS = Path(__file__).resolve().parents[2] / "frontend" / "src" / "data" / "types.ts"


def ts_fields(interface: str) -> dict[str, bool]:
    """Field name -> required, parsed from an interface in frontend/src/data/types.ts."""
    body = re.search(rf"export interface {interface} \{{(.*?)\n\}}", TYPES_TS.read_text(), re.S).group(1)
    return {m.group(1): not m.group(2) for m in re.finditer(r"^\s+(\w+)(\?)?:", body, re.M)}


def test_models_match_frontend_types():
    for ts_name, model in [("Cve", Cve), ("AttackEvent", AttackEvent), ("Stats", Stats), ("Actor", Actor)]:
        py = {name: f.is_required() for name, f in model.model_fields.items()}
        assert py == ts_fields(ts_name), f"{ts_name} drifted from frontend/src/data/types.ts"


def test_endpoints_return_contract_shapes():
    for path, model, is_list in [
        ("/api/cves", Cve, True),
        ("/api/events", AttackEvent, True),
        ("/api/stats", Stats, False),
        ("/api/actors", Actor, True),
    ]:
        res = client.get(path)
        assert res.status_code == 200, path
        assert "X-Angler-Data-Source" in res.headers
        body = res.json()
        for item in body if is_list else [body]:
            model.model_validate(item)


def test_events_limit():
    assert client.get("/api/events?limit=0").status_code == 422
    assert len(client.get("/api/events?limit=1").json()) <= 1


def test_cors_allows_local_dev():
    res = client.get("/api/cves", headers={"Origin": "http://localhost:5173"})
    assert res.headers["access-control-allow-origin"] == "http://localhost:5173"
    res = client.get("/api/cves", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in res.headers
