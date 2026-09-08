"""Async scan jobs and batch endpoints."""

from __future__ import annotations

import importlib
import time

import pytest

from tests.conftest import make_client


@pytest.fixture
def jobs_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHING_DATABASE_URL", f"sqlite:///{tmp_path / 'scans.db'}")
    from phishing import db as db_module
    from phishing import jobs as jobs_module

    importlib.reload(db_module)
    importlib.reload(jobs_module)
    db_module.init_db()
    yield db_module, jobs_module
    jobs_module.shutdown_jobs()


def _payload(url: str = "https://example.com") -> dict:
    return {
        "url": url,
        "final_url": url,
        "verdict": "legitimate",
        "probability": 0.02,
        "model": "XGBoost",
        "coverage": {"page_fetched": True, "tls_checked": True},
        "model_quality": {"warn_threshold": 0.2, "block_threshold": 0.9},
        "features": {},
        "signals": [],
        "notes": [],
    }


def test_job_lands_done_and_records_a_scan(jobs_env, monkeypatch):
    db, jobs = jobs_env
    monkeypatch.setattr(jobs, "scan", lambda url, timeout=8: _payload(url))

    job_id = jobs.enqueue_scan_job("https://example.com")
    deadline = time.time() + 3
    payload = None
    while time.time() < deadline:
        payload = jobs.job_status(job_id)
        if payload and payload["status"] in {"done", "error"}:
            break
        time.sleep(0.02)
    assert payload is not None
    assert payload["status"] == "done"
    assert payload["result"]["verdict"] == "legitimate"
    assert payload["scan_id"] is not None
    assert db.scan_by_id(payload["scan_id"])["verdict"] == "legitimate"


def test_job_crash_lands_error_not_running(jobs_env, monkeypatch):
    _, jobs = jobs_env

    def boom(url, timeout=8):
        raise RuntimeError("nope")

    monkeypatch.setattr(jobs, "scan", boom)
    job_id = jobs.enqueue_scan_job("https://example.com")
    deadline = time.time() + 3
    payload = None
    while time.time() < deadline:
        payload = jobs.job_status(job_id)
        if payload and payload["status"] in {"done", "error"}:
            break
        time.sleep(0.02)
    assert payload is not None
    assert payload["status"] == "error"
    assert "Scan failed" in (payload["error"] or "")


def test_job_and_batch_endpoints(jobs_env, monkeypatch):
    db, jobs = jobs_env
    import api.main as api_main

    importlib.reload(api_main)
    monkeypatch.setattr(api_main, "enqueue_scan_job", jobs.enqueue_scan_job)
    monkeypatch.setattr(api_main, "job_status", jobs.job_status)
    monkeypatch.setattr(api_main, "enqueue_batch", jobs.enqueue_batch)
    monkeypatch.setattr(api_main, "batch_status", jobs.batch_status)
    monkeypatch.setattr(api_main, "scan_by_id", db.scan_by_id)
    monkeypatch.setattr(jobs, "scan", lambda url, timeout=8: _payload(url))

    with make_client(api_main.app) as client:
        created = client.post("/api/scan/jobs", json={"url": "https://example.com"})
        assert created.status_code == 202
        job_id = created.json()["job_id"]

        deadline = time.time() + 3
        body = None
        while time.time() < deadline:
            body = client.get(f"/api/scan/jobs/{job_id}").json()
            if body["status"] in {"done", "error"}:
                break
            time.sleep(0.02)
        assert body["status"] == "done"
        assert body["result"]["verdict"] == "legitimate"

        stored = client.get(f"/api/scans/{body['scan_id']}")
        assert stored.status_code == 200
        assert stored.json()["verdict"] == "legitimate"

        batched = client.post(
            "/api/scan/batch",
            json={"urls": ["https://a.example", "https://b.example"]},
        )
        assert batched.status_code == 202
        batch_id = batched.json()["batch_id"]
        assert len(batched.json()["job_ids"]) == 2

        deadline = time.time() + 3
        rollup = None
        while time.time() < deadline:
            rollup = client.get(f"/api/scan/batch/{batch_id}").json()
            if rollup["status"] in {"done", "error"}:
                break
            time.sleep(0.02)
        assert rollup["total"] == 2
        assert rollup["done"] == 2

        too_big = client.post(
            "/api/scan/batch",
            json={"urls": [f"https://x{i}.example" for i in range(30)]},
        )
        assert too_big.status_code == 400
