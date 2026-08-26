"""Request-level guards for the scan API: rate limits, concurrency, optional auth.

The scanner makes outbound HTTP requests on behalf of whoever calls it, so an
open ``POST /api/scan`` is both a denial-of-service target and an outbound proxy
for someone else. These are process-local limits — good enough for a single
container, and the right shape to swap for Redis if this is ever replicated.
"""

from __future__ import annotations

import hmac
import ipaddress
import threading
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request

from phishing.settings import (
    CHAT_MAX_CONCURRENT,
    CHAT_RATE_PER_MINUTE,
    READ_RATE_PER_MINUTE,
    SCAN_MAX_CONCURRENT,
    SCAN_RATE_PER_MINUTE,
    allow_anonymous,
    api_key,
)

WINDOW_SECONDS = 60.0
_MAX_TRACKED_CLIENTS = 10_000
_EVICT_BATCH = 5_000
_OPEN_ANONYMOUS = frozenset({"1", "true", "all", "yes", "on"})
_NEVER_ANONYMOUS = frozenset({"0", "never", "false", "off", "no"})


class RateLimiter:
    """Sliding-window counter keyed by client, with a global in-flight cap."""

    def __init__(
        self,
        per_minute: int,
        max_concurrent: int,
        *,
        busy_detail: str = "Too many scans in flight. Try again in a moment.",
    ) -> None:
        self.per_minute = max(0, per_minute)
        self.max_concurrent = max(1, max_concurrent)
        self.busy_detail = busy_detail
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(self.max_concurrent)

    def check(self, client: str, now: float | None = None) -> None:
        """Raise 429 when ``client`` has spent its per-minute budget."""
        if self.per_minute <= 0:
            return
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits[client]
            cutoff = now - WINDOW_SECONDS
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self.per_minute:
                retry_after = max(1, int(WINDOW_SECONDS - (now - hits[0])))
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"Rate limit reached: {self.per_minute} requests per minute. "
                        f"Try again in {retry_after}s."
                    ),
                    headers={"Retry-After": str(retry_after)},
                )
            hits.append(now)
            self._evict(now)

    def _evict(self, now: float) -> None:
        """Drop idle keys, then the oldest half if the table is still huge.

        An IPv6 /64 still yields 2^64 keys even after IP validation, so this is
        load-bearing: empty-deque sweeps never fire under an active spray,
        because a deque is emptied only by a later ``check`` for that same key.
        """
        cutoff = now - WINDOW_SECONDS
        stale = [
            key
            for key, hits in self._hits.items()
            if not hits or hits[-1] < cutoff
        ]
        for key in stale:
            del self._hits[key]
        if len(self._hits) <= _MAX_TRACKED_CLIENTS:
            return
        oldest = sorted(
            self._hits,
            key=lambda key: self._hits[key][-1] if self._hits[key] else 0.0,
        )
        for key in oldest[:_EVICT_BATCH]:
            del self._hits[key]

    def slot(self) -> _Slot:
        return _Slot(self._slots, self.busy_detail)


class _Slot:
    """Context manager that refuses rather than queues when the pool is full."""

    def __init__(self, semaphore: threading.BoundedSemaphore, busy_detail: str) -> None:
        self._semaphore = semaphore
        self._busy_detail = busy_detail
        self._held = False

    def __enter__(self) -> _Slot:
        if not self._semaphore.acquire(blocking=False):
            raise HTTPException(
                status_code=503,
                detail=self._busy_detail,
                headers={"Retry-After": "5"},
            )
        self._held = True
        return self

    def __exit__(self, *exc) -> None:
        if self._held:
            self._semaphore.release()
            self._held = False


scan_limiter = RateLimiter(SCAN_RATE_PER_MINUTE, SCAN_MAX_CONCURRENT)
chat_limiter = RateLimiter(
    CHAT_RATE_PER_MINUTE,
    CHAT_MAX_CONCURRENT,
    busy_detail="Too many chat requests in flight. Try again in a moment.",
)
read_limiter = RateLimiter(
    READ_RATE_PER_MINUTE,
    max_concurrent=8,
    busy_detail="Too many history requests in flight. Try again in a moment.",
)


def _normalise_ip(raw: str) -> str | None:
    """Collapse ``1.2.3.004`` / ``[::1]:port`` forms to a canonical address."""
    text = raw.strip().lower()
    if not text:
        return None
    if text.startswith("[") and "]" in text:
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        text = text.rsplit(":", 1)[0]
    if text.count(".") == 3 and ":" not in text:
        try:
            text = ".".join(str(int(part)) for part in text.split("."))
        except ValueError:
            return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def client_key(request: Request) -> str:
    """Identify the caller for rate-limiting.

    ``X-Forwarded-For`` is honoured only when a trusted proxy is declared,
    because a client can otherwise set it to anything and get a fresh budget
    per request. When it is honoured, the right-most trusted hop is used —
    the value the outermost proxy appended — not the client-supplied left-most
    entry.
    """
    from phishing.settings import env_bool, env_int

    if env_bool("SPHINX_TRUST_PROXY_HEADERS"):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            hops = max(1, min(8, env_int("SPHINX_TRUSTED_PROXY_HOPS", 1)))
            parts = [part.strip() for part in forwarded.split(",") if part.strip()]
            if len(parts) >= hops:
                parsed = _normalise_ip(parts[-hops])
                if parsed is not None:
                    return parsed
    return request.client.host if request.client else "unknown"


def _peer_is_local(request: Request, mode: str) -> bool:
    """Whether the TCP peer may call a guarded route with no API key.

    Deliberately ignores ``X-Forwarded-For`` even when proxy trust is on:
    behind a proxy real visitors are non-loopback, so an XFF-aware check
    would still refuse them. The proxied case is the explicit opt-in.
    """
    host = request.client.host if request.client else ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    if mode == "private":
        return bool(ip.is_private or ip.is_link_local)
    return False


def require_api_key(
    request: Request, x_api_key: str | None = Header(default=None)
) -> None:
    """Guard scan/chat/history/stats when the caller is not a local demo.

    ``SPHINX_API_KEY``, when set, always wins: ``X-API-Key`` must match
    (constant-time) and the anonymous-access setting is not consulted. When
    no key is configured, anonymous callers are allowed only according to
    ``SPHINX_ALLOW_ANONYMOUS`` (default ``loopback``).
    """
    expected = api_key()
    if expected:
        if not x_api_key or not hmac.compare_digest(x_api_key, expected):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid X-API-Key.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return
    mode = allow_anonymous()
    if mode in _OPEN_ANONYMOUS:
        return
    if mode not in _NEVER_ANONYMOUS and _peer_is_local(request, mode):
        return
    raise HTTPException(
        status_code=401,
        detail=(
            "This endpoint is reachable from outside localhost with no "
            "SPHINX_API_KEY set. Set SPHINX_API_KEY, or set "
            "SPHINX_ALLOW_ANONYMOUS=1 if this service is intentionally public."
        ),
        headers={"WWW-Authenticate": "ApiKey"},
    )
