"""In-process async scan jobs.

A bounded worker pool (``SPHINX_JOB_WORKERS``) runs the existing ``scan()``
then ``record_scan()`` path. Status transitions always land on ``done`` or
``error`` so a crash cannot leave a row stuck at ``running``.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any

from phishing.db import (
    create_scan_job,
    get_scan_job,
    list_batch_jobs,
    record_scan,
    scan_by_id,
    update_scan_job,
)
from phishing.netguard import UnsafeTargetError
from phishing.scanner import scan
from phishing.settings import JOB_WORKERS

log = logging.getLogger(__name__)

_slots = threading.BoundedSemaphore(JOB_WORKERS)
_results: dict[str, dict[str, Any]] = {}
_results_lock = threading.Lock()


def shutdown_jobs() -> None:
    """No-op kept so tests can tear down without a leaked pool."""


def _error_message(exc: BaseException) -> str:
    if isinstance(exc, (UnsafeTargetError, ValueError, FileNotFoundError)):
        return str(exc)
    return f"Scan failed: {type(exc).__name__}"


def _run_job(job_id: str) -> None:
    try:
        row = get_scan_job(job_id)
        if row is None:
            return
        update_scan_job(job_id, status="running")
        started = time.perf_counter()
        result = scan(row.url, timeout=row.timeout)
        duration_ms = int((time.perf_counter() - started) * 1000)
        scan_id = record_scan(result, duration_ms=duration_ms)
        result["scan_id"] = scan_id
        result["duration_ms"] = duration_ms
        with _results_lock:
            _results[job_id] = result
        update_scan_job(job_id, status="done", scan_id=scan_id)
    except Exception as exc:  # noqa: BLE001 - job must never stay running
        log.exception("scan job %s failed", job_id)
        try:
            update_scan_job(job_id, status="error", error=_error_message(exc))
        except Exception:
            log.exception("scan job %s could not record its error", job_id)


def _guarded_run(job_id: str) -> None:
    _slots.acquire()
    try:
        _run_job(job_id)
    finally:
        _slots.release()


def enqueue_scan_job(
    url: str,
    *,
    timeout: int = 8,
    client_key: str = "",
    batch_id: str | None = None,
) -> str:
    job_id = create_scan_job(
        url, timeout=timeout, client_key=client_key, batch_id=batch_id
    )
    threading.Thread(
        target=_guarded_run,
        args=(job_id,),
        daemon=True,
        name=f"scan-job-{job_id[:8]}",
    ).start()
    return job_id


def enqueue_batch(
    urls: list[str],
    *,
    timeout: int = 8,
    client_key: str = "",
) -> tuple[str, list[str]]:
    batch_id = str(uuid.uuid4())
    job_ids = [
        enqueue_scan_job(url, timeout=timeout, client_key=client_key, batch_id=batch_id)
        for url in urls
    ]
    return batch_id, job_ids


def _job_payload(job_id: str) -> dict[str, Any] | None:
    row = get_scan_job(job_id)
    if row is None:
        return None
    payload = row.to_dict()
    if row.status == "done":
        result = scan_by_id(row.scan_id) if row.scan_id is not None else None
        if result is None:
            with _results_lock:
                result = _results.get(job_id)
        payload["result"] = result
    else:
        payload["result"] = None
    return payload


def job_status(job_id: str) -> dict[str, Any] | None:
    return _job_payload(job_id)


def batch_status(batch_id: str) -> dict[str, Any] | None:
    rows = list_batch_jobs(batch_id)
    if not rows:
        return None
    jobs = [job for job in (_job_payload(row.id) for row in rows) if job is not None]
    n = len(jobs)
    n_done = sum(1 for job in jobs if job["status"] == "done")
    n_error = sum(1 for job in jobs if job["status"] == "error")
    n_running = sum(1 for job in jobs if job["status"] == "running")
    n_queued = sum(1 for job in jobs if job["status"] == "queued")
    if n_error and n_done + n_error == n:
        rollup = "error"
    elif n_done == n:
        rollup = "done"
    elif n_running or n_done or n_error:
        rollup = "running"
    else:
        rollup = "queued"
    return {
        "batch_id": batch_id,
        "status": rollup,
        "total": n,
        "queued": n_queued,
        "running": n_running,
        "done": n_done,
        "error": n_error,
        "jobs": jobs,
    }
