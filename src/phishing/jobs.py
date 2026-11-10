"""Async scan jobs.

``SPHINX_JOB_BACKEND=thread`` (the default) runs a bounded worker pool in
this process. ``qstash`` writes the same rows and publishes each job id to
Upstash QStash, which calls ``/api/internal/scan-jobs/run`` under a
parallelism cap. Status transitions always land on ``done`` or ``error``.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from phishing.db import (
    claim_scan_job,
    count_open_scan_jobs,
    create_scan_job,
    fail_stale_running_jobs,
    get_scan_job,
    list_batch_jobs,
    purge_old_scan_jobs,
    record_scan,
    running_job_is_stale,
    scan_by_id,
    update_scan_job,
)
from phishing.netguard import UnsafeTargetError
from phishing.scanner import scan
from phishing.settings import JOB_QUEUE_MAX, JOB_WORKERS, env, job_backend

log = logging.getLogger(__name__)

_MAX_RESULTS = 500
_results: OrderedDict[str, dict[str, Any]] = OrderedDict()
_results_lock = threading.Lock()
_pending = 0
_pending_lock = threading.Lock()
_executor: ThreadPoolExecutor | None = None


class JobQueueFull(Exception):
    """The worker pool and its queue are both at their cap."""


class JobPublishError(Exception):
    """The durable queue did not accept every job in the request."""


class InvalidWorkerSignature(Exception):
    """A worker callback failed the QStash signature check."""


def _capacity() -> int:
    return JOB_WORKERS + JOB_QUEUE_MAX


def _reserve(count: int) -> bool:
    global _pending
    with _pending_lock:
        if _pending + count > _capacity():
            return False
        _pending += count
        return True


def _release(count: int = 1) -> None:
    global _pending
    with _pending_lock:
        _pending = max(0, _pending - count)


def _pool() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(
            max_workers=JOB_WORKERS,
            thread_name_prefix="scan-job",
        )
    return _executor


def shutdown_jobs() -> None:
    """Drop the pool so a reloaded module does not leak workers."""
    global _executor, _pending
    pool = _executor
    _executor = None
    if pool is not None:
        pool.shutdown(wait=True, cancel_futures=True)
    with _pending_lock:
        _pending = 0


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
        scan_id = record_scan(
            result, duration_ms=duration_ms, client_key=row.client_key
        )
        result["scan_id"] = scan_id
        result["duration_ms"] = duration_ms
        with _results_lock:
            _results[job_id] = result
            while len(_results) > _MAX_RESULTS:
                _results.popitem(last=False)
        update_scan_job(job_id, status="done", scan_id=scan_id)
    except Exception as exc:  # noqa: BLE001 - job must never stay running
        log.exception("scan job %s failed", job_id)
        try:
            update_scan_job(job_id, status="error", error=_error_message(exc))
        except Exception:
            log.exception("scan job %s could not record its error", job_id)


def _guarded_run(job_id: str) -> None:
    try:
        _run_job(job_id)
    finally:
        _release()


def _reap_stale_jobs() -> None:
    """Free queue slots held by workers that already died.

    Failure here must not refuse a new scan. The daily cron repeats the work.
    """
    try:
        fail_stale_running_jobs()
    except Exception:
        log.exception("could not time out stale scan jobs")


def enqueue_scan_job(
    url: str,
    *,
    timeout: int = 8,
    client_key: str = "",
    batch_id: str | None = None,
) -> str:
    # Before the cap, so a killed function does not hold a slot until cron.
    _reap_stale_jobs()
    if job_backend() == "qstash":
        _, job_ids = _enqueue_durable(
            [url], timeout=timeout, client_key=client_key, batch_id=batch_id
        )
        return job_ids[0]
    if not _reserve(1):
        raise JobQueueFull()
    job_id: str | None = None
    try:
        job_id = create_scan_job(
            url, timeout=timeout, client_key=client_key, batch_id=batch_id
        )
        _pool().submit(_guarded_run, job_id)
    except Exception:
        _release()
        if job_id is not None:
            update_scan_job(job_id, status="error", error="Could not queue scan.")
        raise
    try:
        purge_old_scan_jobs()
    except Exception:
        log.exception("could not purge old scan jobs")
    return job_id


def enqueue_batch(
    urls: list[str],
    *,
    timeout: int = 8,
    client_key: str = "",
) -> tuple[str, list[str]]:
    """Queue every URL or none of them.

    Reserving the whole batch up front means a full queue refuses the request
    instead of accepting the first few URLs and 503ing the rest.
    """
    if not urls:
        return str(uuid.uuid4()), []
    _reap_stale_jobs()
    if job_backend() == "qstash":
        return _enqueue_durable(urls, timeout=timeout, client_key=client_key)
    if not _reserve(len(urls)):
        raise JobQueueFull()
    batch_id = str(uuid.uuid4())
    job_ids: list[str] = []
    submitted = 0
    try:
        for url in urls:
            job_id = create_scan_job(
                url, timeout=timeout, client_key=client_key, batch_id=batch_id
            )
            job_ids.append(job_id)
            _pool().submit(_guarded_run, job_id)
            submitted += 1
    except Exception:
        _release(len(urls) - submitted)
        for job_id in job_ids[submitted:]:
            update_scan_job(job_id, status="error", error="Could not queue scan.")
        raise
    try:
        purge_old_scan_jobs()
    except Exception:
        log.exception("could not purge old scan jobs")
    return batch_id, job_ids


def _job_payload(job_id: str) -> dict[str, Any] | None:
    row = get_scan_job(job_id)
    if row is None:
        return None
    # One compare on the row already loaded. The table update runs only after
    # this job itself is past the timeout, not on every poll.
    if running_job_is_stale(row):
        _reap_stale_jobs()
        fresh = get_scan_job(job_id)
        if fresh is not None:
            row = fresh
    payload = row.to_dict()
    if row.status == "done":
        result = (
            scan_by_id(row.scan_id, client_key=row.client_key)
            if row.scan_id is not None
            else None
        )
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
    if any(running_job_is_stale(row) for row in rows):
        _reap_stale_jobs()
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


def worker_url() -> str:
    """Absolute URL QStash posts job ids to.

    ``VERCEL_URL`` is the deployment host, not the production alias, so a
    staged deploy publishes back to itself and not to the previous production
    deployment.
    """
    explicit = env("SPHINX_WORKER_URL", "").strip()
    if explicit:
        return explicit
    base = env("SPHINX_PUBLIC_BASE_URL", "").strip().rstrip("/")
    if not base:
        host = env("VERCEL_URL", "").strip()
        host = host.removeprefix("https://").removeprefix("http://").strip("/")
        if host:
            base = "https://" + host
    if not base:
        raise RuntimeError(
            "Set SPHINX_WORKER_URL, SPHINX_PUBLIC_BASE_URL, or VERCEL_URL "
            "when SPHINX_JOB_BACKEND=qstash."
        )
    return base + "/api/internal/scan-jobs/run"


def _qstash_client():
    from qstash import QStash

    token = env("QSTASH_TOKEN", "").strip()
    if not token:
        raise RuntimeError("QSTASH_TOKEN is required when SPHINX_JOB_BACKEND=qstash")
    return QStash(token)


def _publish_job(job_id: str) -> None:
    client = _qstash_client()
    client.message.publish_json(
        url=worker_url(),
        body={"job_id": job_id},
        # QStash delivers at most JOB_WORKERS scans at once. Sync scans use
        # the separate Redis in-flight cap, so the outbound ceiling stays
        # SCAN_MAX_CONCURRENT + JOB_WORKERS.
        flow_control={"key": "sphinx-scan", "parallelism": max(1, JOB_WORKERS)},
        retries=3,
        timeout="55s",
        deduplication_id=job_id,
    )


def _enqueue_durable(
    urls: list[str],
    *,
    timeout: int,
    client_key: str,
    batch_id: str | None = None,
) -> tuple[str | None, list[str]]:
    """Insert every row, then publish. A failed publish marks the rest error."""
    if count_open_scan_jobs() + len(urls) > _capacity():
        raise JobQueueFull()
    own_batch = batch_id
    if own_batch is None and len(urls) > 1:
        own_batch = str(uuid.uuid4())
    job_ids: list[str] = []
    for url in urls:
        job_ids.append(
            create_scan_job(
                url, timeout=timeout, client_key=client_key, batch_id=own_batch
            )
        )
    published = 0
    try:
        for job_id in job_ids:
            _publish_job(job_id)
            published += 1
    except Exception as exc:
        log.exception("could not publish scan job")
        for job_id in job_ids[published:]:
            try:
                update_scan_job(job_id, status="error", error="Could not queue scan.")
            except Exception:
                log.exception("could not mark unpublished job %s as error", job_id)
        raise JobPublishError("Could not queue scan.") from exc
    try:
        purge_old_scan_jobs()
    except Exception:
        log.exception("could not purge old scan jobs")
    return own_batch, job_ids


def verify_worker_signature(body: bytes, signature: str) -> None:
    """Reject anything QStash did not sign with the current or next key.

    The body is only a job id. The URL to scan is read from that row, so a
    replay cannot choose a new target. ``url`` is the address we published,
    which is the subject QStash signed.
    """
    current = env("QSTASH_CURRENT_SIGNING_KEY", "").strip()
    nxt = env("QSTASH_NEXT_SIGNING_KEY", "").strip()
    if not current or not nxt or not signature.strip():
        raise InvalidWorkerSignature("missing signing key or signature")
    try:
        url = worker_url()
        text = body.decode("utf-8")
    except (RuntimeError, UnicodeError) as exc:
        raise InvalidWorkerSignature("worker URL or body is not usable") from exc
    from qstash import Receiver
    from qstash.errors import SignatureError

    receiver = Receiver(current_signing_key=current, next_signing_key=nxt)
    try:
        receiver.verify(signature=signature.strip(), body=text, url=url, clock_tolerance=60)
    except SignatureError as exc:
        raise InvalidWorkerSignature("invalid signature") from exc


def run_queued_job(job_id: str) -> str:
    """Claim a queued row and run it. A second delivery returns ``ignored``.

    Scan failures are recorded on the row and still return ``error`` rather
    than raising, so QStash does not fetch the target again.
    """
    if claim_scan_job(job_id) is None:
        return "ignored"
    _run_job(job_id)
    row = get_scan_job(job_id)
    if row is None:
        return "ignored"
    return row.status
