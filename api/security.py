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
    env,
    lease_ttl_seconds,
    rate_limit_backend,
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

    def check(self, client: str, now: float | None = None, cost: int = 1) -> None:
        """Raise 429 when ``client`` has spent its per-minute budget.

        ``cost`` charges more than one slot (a batch of N URLs spends N).
        """
        if self.per_minute <= 0:
            return
        cost = max(1, int(cost))
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits[client]
            cutoff = now - WINDOW_SECONDS
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) + cost > self.per_minute:
                oldest = hits[0] if hits else now
                retry_after = max(1, int(WINDOW_SECONDS - (now - oldest)))
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"Rate limit reached: {self.per_minute} requests per minute. "
                        f"Try again in {retry_after}s."
                    ),
                    headers={"Retry-After": str(retry_after)},
                )
            for _ in range(cost):
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


# Sliding window. ARGV: now, window seconds, limit, cost, unique member prefix.
# Returns {1, 0} when the cost fits, else {0, retry_after_seconds}. The cost
# is all or nothing: a batch that does not fit adds nothing.
_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local member_prefix = ARGV[5]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if (count + cost) > limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry = math.ceil(window)
  if oldest[2] ~= nil then
    retry = math.ceil(window - (now - tonumber(oldest[2])))
  end
  if retry < 1 then
    retry = 1
  end
  return {0, retry}
end
for i = 1, cost do
  redis.call('ZADD', key, now, member_prefix .. ':' .. i)
end
redis.call('PEXPIRE', key, math.ceil(window * 1000))
return {1, 0}
"""

# In-flight leases. ARGV: now_ms, ttl_ms, max, lease id. Returns 1 or 0.
# Each lease's score is its expiry, so a killed instance frees the slot
# when maxDuration elapses even if it never decrements.
_LEASE_ACQUIRE_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local maxc = tonumber(ARGV[3])
local lease = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
local count = redis.call('ZCARD', key)
if count >= maxc then
  return 0
end
redis.call('ZADD', key, now + ttl, lease)
local key_ttl = redis.call('PTTL', key)
if key_ttl < ttl then
  redis.call('PEXPIRE', key, ttl)
end
return 1
"""

_LEASE_RELEASE_LUA = """
redis.call('ZREM', KEYS[1], ARGV[1])
return 1
"""

_redis_client = None


def redis_client():
    """Shared Redis connection for the rate limiters, or None on the memory backend."""
    global _redis_client
    if rate_limit_backend() != "redis":
        return None
    if _redis_client is None:
        import redis

        url = env("REDIS_URL", "").strip()
        if not url:
            raise RuntimeError(
                "REDIS_URL is required when SPHINX_RATE_LIMIT_BACKEND=redis"
            )
        _redis_client = redis.Redis.from_url(
            url,
            decode_responses=True,
            socket_timeout=2.0,
            socket_connect_timeout=2.0,
        )
    return _redis_client


class RedisRateLimiter:
    """Sliding-window counter and in-flight leases stored in Redis.

    ``fail_closed`` is for scan and chat: if Redis is down, those routes
    503. A public demo's rate limit is the only abuse control, so failing
    open would remove it. Reads fail open so a Redis blip does not blank
    History while a scan is already running.
    """

    def __init__(
        self,
        per_minute: int,
        max_concurrent: int,
        *,
        client,
        prefix: str,
        fail_closed: bool,
        lease_ttl_seconds: int = 60,
        busy_detail: str = "Too many scans in flight. Try again in a moment.",
    ) -> None:
        self.per_minute = max(0, per_minute)
        self.max_concurrent = max(1, max_concurrent)
        self.client = client
        self.prefix = prefix
        self.fail_closed = fail_closed
        self.lease_ttl_seconds = max(1, lease_ttl_seconds)
        self.busy_detail = busy_detail

    def check(self, client: str, now: float | None = None, cost: int = 1) -> None:
        if self.per_minute <= 0:
            return
        cost = max(1, int(cost))
        # Wall clock, not monotonic: every instance has to agree on the window.
        now = time.time() if now is None else now
        try:
            allowed, retry_after = self._window(client, now, cost)
        except Exception as exc:
            if _is_redis_error(exc) and not self.fail_closed:
                return
            if _is_redis_error(exc):
                raise _limiter_unavailable() from exc
            raise
        if allowed:
            return
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit reached: {self.per_minute} requests per minute. "
                f"Try again in {retry_after}s."
            ),
            headers={"Retry-After": str(retry_after)},
        )

    def _window(self, client: str, now: float, cost: int) -> tuple[bool, int]:
        member = f"{now:.6f}:{uuid_hex()}"
        result = self.client.eval(
            _WINDOW_LUA,
            1,
            f"sphinx:rl:{self.prefix}:{client}",
            now,
            WINDOW_SECONDS,
            self.per_minute,
            cost,
            member,
        )
        allowed = int(result[0]) == 1
        retry_after = max(1, int(result[1]))
        return allowed, retry_after

    def slot(self) -> _RedisSlot:
        return _RedisSlot(self)


class _RedisSlot:
    def __init__(self, limiter: RedisRateLimiter) -> None:
        self._limiter = limiter
        self._lease: str | None = None

    def __enter__(self) -> _RedisSlot:
        lease = uuid_hex()
        now_ms = int(time.time() * 1000)
        ttl_ms = self._limiter.lease_ttl_seconds * 1000
        try:
            acquired = self._limiter.client.eval(
                _LEASE_ACQUIRE_LUA,
                1,
                f"sphinx:inflight:{self._limiter.prefix}",
                now_ms,
                ttl_ms,
                self._limiter.max_concurrent,
                lease,
            )
        except Exception as exc:
            if _is_redis_error(exc) and not self._limiter.fail_closed:
                return self
            if _is_redis_error(exc):
                raise _limiter_unavailable() from exc
            raise
        if int(acquired) != 1:
            raise HTTPException(
                status_code=503,
                detail=self._limiter.busy_detail,
                headers={"Retry-After": "5"},
            )
        self._lease = lease
        return self

    def __exit__(self, *exc) -> None:
        if self._lease is None:
            return
        try:
            self._limiter.client.eval(
                _LEASE_RELEASE_LUA,
                1,
                f"sphinx:inflight:{self._limiter.prefix}",
                self._lease,
            )
        except Exception as err:
            if not _is_redis_error(err):
                raise
            # The lease score expires on its own.
        finally:
            self._lease = None


def _is_redis_error(exc: BaseException) -> bool:
    try:
        from redis.exceptions import RedisError
    except ImportError:
        return False
    return isinstance(exc, RedisError)


def _limiter_unavailable() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="Rate limiter unavailable. Try again in a moment.",
        headers={"Retry-After": "5"},
    )


def uuid_hex() -> str:
    import uuid

    return uuid.uuid4().hex


def _build_limiter(
    per_minute: int,
    max_concurrent: int,
    *,
    name: str,
    fail_closed: bool,
    busy_detail: str,
) -> RateLimiter | RedisRateLimiter:
    if rate_limit_backend() == "redis":
        return RedisRateLimiter(
            per_minute,
            max_concurrent,
            client=redis_client(),
            prefix=name,
            fail_closed=fail_closed,
            lease_ttl_seconds=lease_ttl_seconds(),
            busy_detail=busy_detail,
        )
    return RateLimiter(per_minute, max_concurrent, busy_detail=busy_detail)


scan_limiter = _build_limiter(
    SCAN_RATE_PER_MINUTE,
    SCAN_MAX_CONCURRENT,
    name="scan",
    fail_closed=True,
    busy_detail="Too many scans in flight. Try again in a moment.",
)
chat_limiter = _build_limiter(
    CHAT_RATE_PER_MINUTE,
    CHAT_MAX_CONCURRENT,
    name="chat",
    fail_closed=True,
    busy_detail="Too many chat requests in flight. Try again in a moment.",
)
read_limiter = _build_limiter(
    READ_RATE_PER_MINUTE,
    max_concurrent=8,
    name="read",
    fail_closed=False,
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
