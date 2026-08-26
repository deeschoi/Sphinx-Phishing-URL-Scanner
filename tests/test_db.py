"""Scan telemetry storage and the endpoints built on it."""

from __future__ import annotations

import hashlib
import importlib

import pytest

from tests.conftest import make_client


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A fresh SQLite database per test, with module globals reset."""
    monkeypatch.setenv("PHISHING_DATABASE_URL", f"sqlite:///{tmp_path / 'scans.db'}")
    from phishing import db as db_module

    importlib.reload(db_module)
    db_module.init_db()
    return db_module


def sample_result(url: str = "https://example.com/login?token=secret") -> dict:
    return {
        "url": url,
        "verdict": "suspicious",
        "probability": 0.62,
        "model": "XGBoost",
        "coverage": {"page_fetched": True, "tls_checked": True},
        "model_quality": {"warn_threshold": 0.5, "block_threshold": 0.85},
        "features": {"having_IP_Address": 1},
        "signals": [{"feature": "SSLfinal_State", "contribution": 0.3}],
    }


def test_record_and_read_back(db):
    scan_id = db.record_scan(sample_result(), duration_ms=123)
    assert scan_id is not None

    rows = db.recent_scans()
    assert len(rows) == 1
    assert rows[0]["verdict"] == "suspicious"
    assert rows[0]["duration_ms"] == 123
    assert rows[0]["host"] == "example.com"


def test_query_string_is_not_stored(db):
    db.record_scan(sample_result("https://example.com/reset?token=hunter2"))
    stored = db.recent_scans()[0]["url"]
    assert "hunter2" not in stored
    assert stored == "https://example.com/reset"


def test_same_url_hashes_consistently(db):
    url = "https://example.com/a?x=1"
    db.record_scan(sample_result(url))
    db.record_scan(sample_result(url))
    with db.session_scope() as session:
        hashes = {row.url_hash for row in session.query(db.Scan).all()}
    assert len(hashes) == 1


def test_stats_counts_verdicts(db):
    db.record_scan(sample_result())
    phishing = sample_result("https://bad.example.org/")
    phishing["verdict"] = "phishing"
    db.record_scan(phishing)

    stats = db.scan_stats()
    assert stats["total_scans"] == 2
    assert stats["verdicts"] == {"suspicious": 1, "phishing": 1}
    assert stats["daily"][0]["scans"] == 2


def test_stats_mean_probability_ignores_unreachable(db):
    db.record_scan(sample_result())
    dead = sample_result("https://no-such-host.invalid/")
    dead["verdict"] = "unreachable"
    dead["probability"] = 0.003
    db.record_scan(dead)

    stats = db.scan_stats()
    assert stats["verdicts"]["unreachable"] == 1
    assert stats["verdicts"]["suspicious"] == 1
    assert stats["daily"][0]["scans"] == 2
    assert stats["daily"][0]["mean_probability"] == pytest.approx(0.62)


def test_record_scan_never_raises(db, monkeypatch):
    """A telemetry failure must not turn a successful scan into an error."""

    def boom():
        raise RuntimeError("database is down")

    monkeypatch.setattr(db, "session_scope", boom)
    assert db.record_scan(sample_result()) is None


def test_scans_and_stats_endpoints(db, monkeypatch):
    import api.main as api_main

    importlib.reload(api_main)
    monkeypatch.setattr(api_main, "record_scan", db.record_scan)
    monkeypatch.setattr(api_main, "recent_scans", db.recent_scans)
    monkeypatch.setattr(api_main, "scan_stats", db.scan_stats)

    db.record_scan(sample_result())

    with make_client(api_main.app) as client:
        listed = client.get("/api/scans")
        assert listed.status_code == 200
        assert len(listed.json()["scans"]) == 1

        stats = client.get("/api/stats")
        assert stats.status_code == 200
        assert stats.json()["total_scans"] == 1

        assert client.get("/api/health").json() == {"status": "ok"}


def test_numeric_otp_in_the_path_is_redacted(db):
    db.record_scan(sample_result("https://example.com/verify/482913"))
    stored = db.recent_scans()[0]["url"]
    assert "482913" not in stored
    assert stored == "https://example.com/verify/[redacted]"


def test_word_shaped_token_after_a_keyword_is_redacted(db):
    db.record_scan(sample_result("https://example.com/reset/magiclinktoken"))
    stored = db.recent_scans()[0]["url"]
    assert "magiclinktoken" not in stored
    assert stored == "https://example.com/reset/[redacted]"


def test_jwt_in_the_path_is_redacted(db):
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    db.record_scan(sample_result(f"https://example.com/session/{jwt}"))
    stored = db.recent_scans()[0]["url"]
    assert jwt not in stored
    assert stored == "https://example.com/session/[redacted]"


def test_hash_named_file_is_redacted_named_file_is_not(db):
    digest = "a" * 32
    db.record_scan(sample_result(f"https://example.com/files/{digest}.pdf"))
    assert db.recent_scans()[0]["url"] == "https://example.com/files/[redacted]"
    db.record_scan(sample_result("https://example.com/files/annual-report.pdf"))
    urls = {row["url"] for row in db.recent_scans()}
    assert "https://example.com/files/annual-report.pdf" in urls


@pytest.mark.parametrize(
    "path",
    [
        "/en-us/pricing",
        "/2024/03/hello-world",
        "/docs/getting-started",
        "/blog/black-friday-2024",
        "/assets/app.min.js",
        "/v1/users",
        "/page/2",
    ],
)
def test_readable_paths_round_trip_byte_identically(db, path):
    url = f"https://example.com{path}"
    db.record_scan(sample_result(url))
    assert db.recent_scans()[0]["url"] == url


def test_url_hash_covers_the_unredacted_url(db):
    url = "https://example.com/reset/482913?x=1"
    db.record_scan(sample_result(url))
    with db.session_scope() as session:
        row = session.query(db.Scan).one()
    assert row.url_hash == hashlib.sha256(url.encode("utf-8")).hexdigest()
    assert "482913" not in row.url


def test_scan_by_id_returns_the_row_or_none(db):
    scan_id = db.record_scan(sample_result())
    row = db.scan_by_id(scan_id)
    assert row is not None
    assert row["id"] == scan_id
    assert db.scan_by_id(scan_id + 999) is None
