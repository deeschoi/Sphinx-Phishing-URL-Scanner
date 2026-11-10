#!/usr/bin/env python3
"""Smoke-test a staged Vercel deploy before it takes production traffic.

The checks match the Docker smoke test, plus the serverless controls: shared
rate limit, QStash jobs, the worker signature, and the CDN security headers.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

SSRF_TARGETS = (
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
)


def _headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    headers: dict[str, str] = {}
    bypass = os.environ.get("VERCEL_AUTOMATION_BYPASS_SECRET", "").strip()
    if bypass:
        headers["x-vercel-protection-bypass"] = bypass
    if extra:
        headers.update(extra)
    return headers


def request(
    method: str,
    url: str,
    body: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 90,
) -> tuple[int, dict[str, str], bytes]:
    data = None if body is None else json.dumps(body).encode()
    merged = _headers(headers)
    if data is not None:
        merged.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=merged, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # Status 0: no HTTP answer. A burst thread must not crash the script.
        return 0, {}, repr(exc).encode()


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def header(headers: dict[str, str], name: str) -> str:
    folded = name.casefold()
    for key, value in headers.items():
        if key.casefold() == folded:
            return value
    return ""


def require_csp(base: str, path: str) -> None:
    status, headers, _body = request("GET", base + path, timeout=30)
    if status != 200:
        fail(f"{path} returned {status}")
    policy = header(headers, "Content-Security-Policy")
    if "default-src" not in policy:
        fail(f"{path} is missing the Content-Security-Policy header")


def wait_until(url: str, label: str) -> dict:
    deadline = time.monotonic() + 120
    last = ""
    raw = b""
    while time.monotonic() < deadline:
        status, _headers, raw = request("GET", url, timeout=30)
        if status != 200:
            fail(f"{label} poll returned {status}: {raw[:300]!r}")
        payload = json.loads(raw)
        last = str(payload.get("status"))
        if last in {"done", "error"}:
            if last != "done":
                fail(f"{label} finished as {last}: {raw[:500]!r}")
            return payload
        time.sleep(2)
    hint = (
        " QStash never reached the worker: check the signing keys and the"
        " QStash console logs/DLQ."
        if last == "queued"
        else ""
    )
    fail(f"{label} still {last} after 120s: {raw[:500]!r}.{hint}")
    return {}


def burst(base: str, count: int, forwarded: str | None = None) -> list[int]:
    extra = {"X-Forwarded-For": forwarded} if forwarded else None

    def once() -> int:
        status, _headers, _raw = request(
            "POST",
            base + "/api/scan",
            {"url": "https://example.com"},
            headers=extra,
            timeout=90,
        )
        return status

    with ThreadPoolExecutor(max_workers=min(count, 40)) as pool:
        return list(pool.map(lambda _n: once(), range(count)))


def main() -> int:
    if len(sys.argv) != 2:
        fail("usage: python scripts/smoke_vercel.py https://deployment.vercel.app")
    base = sys.argv[1].rstrip("/")

    status, _headers, raw = request("GET", base + "/api/ready", timeout=120)
    if status != 200:
        fail(f"/api/ready returned {status}: {raw[:400]!r}")
    ready = json.loads(raw)
    if ready.get("rate_limit") != "redis" or ready.get("jobs") != "qstash":
        fail(f"/api/ready is not on the serverless backends: {ready}")
    if ready.get("jobs_config") != "ok":
        fail(f"/api/ready jobs_config is {ready.get('jobs_config')!r}: {ready}")
    staged_host = base.split("://", 1)[-1]
    if ready.get("worker_host") != staged_host:
        # QStash would deliver this deploy's jobs to another deployment, and
        # the job checks below would test the old build.
        fail(
            f"QStash worker host is {ready.get('worker_host')!r}, not {staged_host!r}."
            " Unset SPHINX_WORKER_URL and SPHINX_PUBLIC_BASE_URL in Production."
        )
    rate = int(ready.get("scan_rate_per_minute") or 0)
    if rate < 4:
        fail(f"scan_rate_per_minute={rate} leaves no room for the batch check")
    print(
        "ready", ready.get("status"), ready.get("rate_limit"), ready.get("jobs"),
        "qstash", ready.get("qstash_host"), "rate", rate,
    )

    require_csp(base, "/")
    require_csp(base, "/api/health")
    print("csp ok")

    status, _headers, raw = request(
        "POST",
        base + "/api/internal/scan-jobs/run",
        {"job_id": "00000000-0000-4000-8000-000000000000"},
        timeout=30,
    )
    if status != 401:
        fail(f"unsigned worker returned {status}: {raw[:200]!r}")
    print("unsigned worker 401")

    for target in SSRF_TARGETS:
        status, _headers, raw = request(
            "POST", base + "/api/scan", {"url": target}, timeout=30
        )
        if status != 403:
            fail(f"SSRF guard did not refuse {target} (got {status})")
    print("ssrf 403")

    status, _headers, raw = request(
        "POST", base + "/api/scan", {"url": "https://example.com"}, timeout=90
    )
    if status != 200 or b'"verdict"' not in raw:
        fail(f"example.com scan returned {status}: {raw[:300]!r}")
    print("example.com verdict")

    status, _headers, raw = request(
        "POST", base + "/api/scan/jobs", {"url": "https://example.org"}, timeout=30
    )
    if status != 202:
        reason = header(_headers, "X-Sphinx-Queue-Error")
        fail(
            f"job enqueue returned {status} (queue error: {reason or 'n/a'}):"
            f" {raw[:300]!r}. Search the function logs for 'could not publish scan job'."
        )
    job_id = json.loads(raw)["job_id"]
    wait_until(base + f"/api/scan/jobs/{job_id}", "job")
    print("job done", job_id)

    status, _headers, raw = request(
        "POST",
        base + "/api/scan/batch",
        {
            "urls": [
                "https://example.com",
                "https://example.org",
                "https://example.net",
            ]
        },
        timeout=30,
    )
    if status != 202:
        reason = header(_headers, "X-Sphinx-Queue-Error")
        fail(f"batch enqueue returned {status} (queue error: {reason or 'n/a'}): {raw[:300]!r}")
    batch_id = json.loads(raw)["batch_id"]
    wait_until(base + f"/api/scan/batch/{batch_id}", "batch")
    print("batch done", batch_id)

    # One past the per-minute rate trips the limiter however many earlier
    # requests have already aged out of the window.
    codes = burst(base, rate + 1)
    if 429 not in codes:
        fail(f"rate limit did not return 429: {codes}")
    spoofed = burst(base, 1, forwarded="203.0.113.50")
    if spoofed != [429]:
        fail(f"spoofed X-Forwarded-For got a fresh budget: {spoofed}")
    print("rate limit 429, spoof still 429")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
