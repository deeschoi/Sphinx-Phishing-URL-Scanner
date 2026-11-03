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


def test_enqueue_refuses_when_the_queue_is_full(jobs_env, monkeypatch):
    import threading

    _, jobs = jobs_env
    monkeypatch.setattr(jobs, "JOB_WORKERS", 1)
    monkeypatch.setattr(jobs, "JOB_QUEUE_MAX", 1)
    started = threading.Event()
    release = threading.Event()

    def block(url, timeout=8):
        started.set()
        release.wait(3)
        return _payload(url)

    monkeypatch.setattr(jobs, "scan", block)
    try:
        jobs.enqueue_scan_job("https://example.com/1")
        assert started.wait(2)
        jobs.enqueue_scan_job("https://example.com/2")
        with pytest.raises(jobs.JobQueueFull):
            jobs.enqueue_scan_job("https://example.com/3")
    finally:
        release.set()


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


def test_qstash_enqueue_publishes_the_job_id_and_stays_queued(jobs_env, monkeypatch):
    _, jobs = jobs_env
    monkeypatch.setenv("SPHINX_JOB_BACKEND", "qstash")
    published: list[str] = []
    monkeypatch.setattr(jobs, "_publish_job", published.append)
    job_id = jobs.enqueue_scan_job("https://example.com", client_key="1.2.3.4")
    assert published == [job_id]
    assert jobs.job_status(job_id)["status"] == "queued"


def test_qstash_publish_sends_parallelism_and_only_the_job_id(jobs_env, monkeypatch):
    _, jobs = jobs_env
    monkeypatch.setenv("SPHINX_JOB_BACKEND", "qstash")
    monkeypatch.setenv("SPHINX_WORKER_URL", "https://sphinx.example/api/internal/scan-jobs/run")

    class Messages:
        kwargs: dict | None = None

        def publish_json(self, **kwargs):
            self.kwargs = kwargs

    class Client:
        def __init__(self) -> None:
            self.message = Messages()

    client = Client()
    monkeypatch.setattr(jobs, "_qstash_client", lambda: client)
    job_id = jobs.enqueue_scan_job("https://example.com")
    assert client.message.kwargs is not None
    assert client.message.kwargs["url"] == "https://sphinx.example/api/internal/scan-jobs/run"
    assert client.message.kwargs["body"] == {"job_id": job_id}
    assert client.message.kwargs["flow_control"] == {
        "key": "sphinx-scan",
        "parallelism": jobs.JOB_WORKERS,
    }
    assert client.message.kwargs["deduplication_id"] == job_id


def test_qstash_publish_failure_marks_unpublished_rows(jobs_env, monkeypatch):
    _, jobs = jobs_env
    monkeypatch.setenv("SPHINX_JOB_BACKEND", "qstash")
    calls: list[str] = []

    def publish(job_id: str) -> None:
        calls.append(job_id)
        if len(calls) == 2:
            raise RuntimeError("qstash down")

    monkeypatch.setattr(jobs, "_publish_job", publish)
    with pytest.raises(jobs.JobPublishError):
        jobs.enqueue_batch(
            ["https://a.example", "https://b.example", "https://c.example"],
            client_key="1.2.3.4",
        )
    assert jobs.job_status(calls[0])["status"] == "queued"
    assert jobs.job_status(calls[1])["status"] == "error"
    # The third row was inserted and then marked, so it has a status too.
    from phishing.db import list_batch_jobs

    # batch id is on the first job
    batch_id = jobs.job_status(calls[0])["batch_id"]
    rows = {row.id: row.status for row in list_batch_jobs(batch_id)}
    assert rows[calls[0]] == "queued"
    assert set(rows.values()) == {"queued", "error"}
    assert list(rows.values()).count("error") == 2


def test_qstash_queue_cap_counts_rows(jobs_env, monkeypatch):
    _, jobs = jobs_env
    monkeypatch.setenv("SPHINX_JOB_BACKEND", "qstash")
    monkeypatch.setattr(jobs, "JOB_WORKERS", 1)
    monkeypatch.setattr(jobs, "JOB_QUEUE_MAX", 1)
    monkeypatch.setattr(jobs, "_publish_job", lambda job_id: None)
    jobs.enqueue_scan_job("https://example.com/1")
    jobs.enqueue_scan_job("https://example.com/2")
    with pytest.raises(jobs.JobQueueFull):
        jobs.enqueue_scan_job("https://example.com/3")


def test_claim_runs_once_and_a_replay_is_ignored(jobs_env, monkeypatch):
    db, jobs = jobs_env
    monkeypatch.setattr(jobs, "scan", lambda url, timeout=8: _payload(url))
    job_id = db.create_scan_job("https://example.com", client_key="1.2.3.4")
    assert jobs.run_queued_job(job_id) == "done"
    assert jobs.run_queued_job(job_id) == "ignored"
    payload = jobs.job_status(job_id)
    assert payload["status"] == "done"
    assert payload["result"]["verdict"] == "legitimate"


def test_maintenance_times_out_a_stuck_running_job(jobs_env):
    from datetime import UTC, datetime, timedelta

    db, _jobs = jobs_env
    job_id = db.create_scan_job("https://example.com")
    assert db.claim_scan_job(job_id) is not None
    with db.session_scope() as session:
        row = session.get(db.ScanJob, job_id)
        assert row is not None
        row.started_at = datetime.now(UTC) - timedelta(minutes=10)
    assert db.fail_stale_running_jobs() == 1
    assert db.get_scan_job(job_id).status == "error"
    assert db.get_scan_job(job_id).error == "Scan timed out."
    assert db.fail_stale_running_jobs() == 0
