import pytest

from app import db, honeypots, llm


def test_validate_keeps_a_static_profile():
    profile = llm.validate(
        "CVE-2024-3400",
        {
            "summary": "Pretends to be a PAN-OS GlobalProtect page.",
            "responses": [
                {"path": "/ssl-vpn/hipreport.esp", "status": 200, "content_type": "text/html", "body": "login"}
            ],
        },
    )
    assert profile["responses"][0]["path"] == "/ssl-vpn/hipreport.esp"
    assert "not installed" in llm.render("CVE-2024-3400", profile)


def test_validate_rejects_a_path_outside_the_shape():
    with pytest.raises(llm.ProfileError):
        llm.validate(
            "CVE-2024-3400",
            {
                "summary": "nope",
                "responses": [{"path": "http://evil.example/x", "status": 200, "content_type": "text/plain", "body": "x"}],
            },
        )


def test_unknown_cve_records_the_profile_and_stays_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(db, "DATABASE_URL", None)
    job = honeypots.create("CVE-2024-3400")
    monkeypatch.setattr(
        llm,
        "propose",
        lambda *args: {
            "summary": "Pretends to be a PAN-OS login.",
            "responses": [{"path": "/ssl-vpn/hipreport.esp", "status": 200, "content_type": "text/html", "body": "login"}],
        },
    )
    assert honeypots.build(job["id"], "CVE-2024-3400") is False
    got = honeypots.get(job["id"])
    assert got["status"] == "failed"
    assert got["url"] is None
    assert "/ssl-vpn/hipreport.esp" in got["error"]
    assert "not installed" in got["error"]


def test_prebuilt_cve_does_not_call_gemini(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(db, "DATABASE_URL", None)
    job = honeypots.create("CVE-2024-4577")

    def boom(*args):
        raise AssertionError("gemini should not run for a prebuilt CVE")

    monkeypatch.setattr(llm, "propose", boom)
    assert honeypots.build(job["id"], "CVE-2024-4577") is True
    assert honeypots.get(job["id"])["status"] == "containing"
