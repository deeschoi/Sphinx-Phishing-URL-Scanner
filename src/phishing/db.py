"""Scan telemetry storage.

Runtime scan history lives here so the API can report what it has seen and how
its score distribution moves over time. Research outputs stay as files in
``reports/`` — they are static artifacts of a pipeline run, not telemetry.

SQLite by default so the app runs with no extra services; point
``PHISHING_DATABASE_URL`` at Postgres in a deployment.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse, urlunparse

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    case,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from phishing.config import PROJECT_ROOT
from phishing.features.reachability import LIVE_RISK_VERDICTS
from phishing.netguard import strip_userinfo

DEFAULT_DATABASE_URL = f"sqlite:///{PROJECT_ROOT / 'data' / 'scans.db'}"


def database_url() -> str:
    return os.environ.get("PHISHING_DATABASE_URL", DEFAULT_DATABASE_URL)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    """One scored URL.

    Query strings are dropped before storage: they routinely carry session
    tokens, password-reset links, and other credentials, and the model never
    reads them anyway. Path segments that look like secrets are redacted
    best-effort — a readable slug that is itself a secret is kept, and the
    keyword list is not exhaustive. ``url_hash`` covers the full URL so
    repeat scans of the same link can still be counted without retaining
    the sensitive part.
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    url: Mapped[str] = mapped_column(Text)
    url_hash: Mapped[str] = mapped_column(String(64), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    probability: Mapped[float] = mapped_column(Float)
    model_name: Mapped[str] = mapped_column(String(64))
    warn_threshold: Mapped[float] = mapped_column(Float)
    block_threshold: Mapped[float] = mapped_column(Float)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    page_fetched: Mapped[bool] = mapped_column(default=False)
    tls_checked: Mapped[bool] = mapped_column(default=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    signals: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    # Full scan payload stored so the analyst can bind to server-truth instead
    # of the browser-echoed copy. Nullable so older rows (and the migration
    # down-path) stay valid.
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True, default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "url": self.url,
            "host": self.host,
            "verdict": self.verdict,
            "probability": self.probability,
            "model": self.model_name,
            "duration_ms": self.duration_ms,
            "page_fetched": self.page_fetched,
            "tls_checked": self.tls_checked,
        }

    def to_full_dict(self) -> dict[str, Any]:
        """Full scan payload for the analyst, falling back to the slim row.

        Always injects ``id``, ``created_at``, and ``duration_ms`` from the
        authoritative row columns so callers can rely on those being present
        regardless of what was stored in result_json.
        """
        if self.result_json:
            out = dict(self.result_json)
            out["id"] = self.id
            out["created_at"] = self.created_at.isoformat() if self.created_at else None
            out.setdefault("duration_ms", self.duration_ms)
            return out
        return self.to_dict()


_engine = None
_Session: sessionmaker[Session] | None = None


def get_engine():
    global _engine, _Session
    if _engine is None:
        url = database_url()
        if url.startswith("sqlite:///"):
            path = url.removeprefix("sqlite:///")
            if path and path != ":memory:":
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        is_sqlite = url.startswith("sqlite")
        # check_same_thread=False: FastAPI serves requests on a threadpool.
        # timeout: without it SQLite fails immediately on a locked database, and
        # record_scan swallows the error, so history silently drops under load.
        connect_args = {"check_same_thread": False, "timeout": 15} if is_sqlite else {}
        _engine = create_engine(url, future=True, connect_args=connect_args)
        if is_sqlite:
            _enable_sqlite_wal(_engine)
        _Session = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def _enable_sqlite_wal(engine) -> None:
    """Write-ahead logging so a reader does not block the writer.

    The default rollback journal serialises every reader against the writer,
    which shows up as dropped telemetry the moment two scans overlap.
    """
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_connection, _record):  # pragma: no cover - driver callback
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=15000")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()


def init_db() -> None:
    Base.metadata.create_all(get_engine())


@contextmanager
def session_scope() -> Iterator[Session]:
    get_engine()
    assert _Session is not None
    session = _Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


_SECRET_SEGMENTS = frozenset(
    {
        "reset",
        "verify",
        "confirm",
        "activate",
        "invite",
        "token",
        "magic",
        "auth",
        "session",
        "sso",
        "oauth",
        "unsubscribe",
        "password",
        "recover",
        "otp",
        "code",
        "key",
        "secret",
        "signin",
        "signout",
        "signup",
        "callback",
        "jwt",
        "nonce",
        "csrf",
        "saml",
        "magiclink",
        "redeem",
        "unlock",
    }
)
_OTP = re.compile(r"^\d{6,}$")
_JWT = re.compile(r"^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(\.[A-Za-z0-9_-]*)?$")
_HEX_TOKEN = re.compile(r"^[A-Fa-f0-9]{24,}$")
_TOKEN_CHARS = re.compile(r"^[A-Za-z0-9_-]+$")
_FILENAME_EXT = re.compile(r"^(.+)\.([A-Za-z0-9]{1,5})$")


def _looks_random(segment: str) -> bool:
    """Context-free token test: mixed, long enough, and high-entropy.

    Hyphenated slugs like ``black-friday-2024`` fail this on purpose so the
    length floor can sit at 12 without eating readable paths. Mixed-case
    tokens (an uppercase run plus a digit) skip the entropy gate.
    """
    if len(segment) < 12 or not _TOKEN_CHARS.fullmatch(segment):
        return False
    has_lower = any(char.islower() for char in segment)
    has_upper = any(char.isupper() for char in segment)
    has_digit = any(char.isdigit() for char in segment)
    if not has_digit or (has_lower + has_upper + has_digit) < 2:
        return False
    if re.search(r"[A-Z]{2,}", segment):
        return True
    if "-" in segment:
        return False
    n = len(segment)
    counts = Counter(segment)
    entropy = -sum((count / n) * math.log2(count / n) for count in counts.values())
    return entropy / math.log2(64) > 0.55


def _part_is_token(part: str) -> bool:
    """Whether one dot-separated piece independently looks like a secret."""
    return bool(part) and (
        bool(_HEX_TOKEN.match(part)) or bool(_OTP.match(part)) or _looks_random(part)
    )


def _segment_is_token(segment: str) -> bool:
    if not segment:
        return False
    if _JWT.match(segment) or _HEX_TOKEN.match(segment) or _OTP.match(segment):
        return True
    if "." in segment:
        if any(_part_is_token(part) for part in segment.split(".")):
            return True
        match = _FILENAME_EXT.match(segment)
        return bool(match) and _segment_is_token(match.group(1))
    return _looks_random(segment)


def _redact_path(path: str) -> str:
    """Replace token-shaped path segments with a placeholder.

    Dropping the query string is necessary but not sufficient: password resets
    and magic links routinely put the secret in the path
    (``/reset/9f3c1a...``), and scan history is not the place for it.

    Rules, in order: a segment after a well-known secret keyword is redacted
    regardless of shape; 6+ digit OTP-shaped segments; JWTs and dotted
    segments whose parts fail the entropy test; filename stems with a short
    extension; then a context-free mixed-alnum / long-hex test.

    Two limits are kept on purpose. A readable slug that *is* a secret is not
    caught, and the keyword list is not exhaustive. Only opaque-token-shaped
    segments are touched, so ``/en-us/pricing`` survives intact.
    """
    if not path:
        return path
    parts: list[str] = []
    previous = ""
    for segment in path.split("/"):
        redact = False
        if segment:
            if (
                previous.lower() in _SECRET_SEGMENTS
                and segment.lower() not in _SECRET_SEGMENTS
            ):
                redact = True
            elif _segment_is_token(segment):
                redact = True
        parts.append("[redacted]" if redact else segment)
        previous = segment
    return "/".join(parts)


def strip_query(url: str) -> str:
    """Canonical stored form: no credentials, no query, no fragment, no path tokens."""
    parsed = urlparse(strip_userinfo(url))
    return urlunparse(parsed._replace(path=_redact_path(parsed.path), query="", fragment=""))


def record_scan(result: dict[str, Any], duration_ms: int = 0) -> int | None:
    """Persist a scan result. Returns the row id, or None if storage failed.

    Telemetry must never turn a successful scan into a failed request, so all
    database errors are swallowed here and surfaced only in the logs.
    """
    try:
        url = str(result.get("url", ""))
        coverage = result.get("coverage") or {}
        quality = result.get("model_quality") or {}
        with session_scope() as session:
            row = Scan(
                url=strip_query(url),
                url_hash=hashlib.sha256(url.encode("utf-8")).hexdigest(),
                host=(urlparse(url).hostname or "")[:255],
                verdict=str(result.get("verdict", "unknown")),
                probability=float(result.get("probability", 0.0)),
                model_name=str(result.get("model", "unknown")),
                warn_threshold=float(quality.get("warn_threshold", 0.0)),
                block_threshold=float(quality.get("block_threshold", 0.0)),
                duration_ms=int(duration_ms),
                page_fetched=bool(coverage.get("page_fetched", False)),
                tls_checked=bool(coverage.get("tls_checked", False)),
                features=result.get("features") or {},
                signals=result.get("signals") or [],
                result_json=dict(result),
            )
            session.add(row)
            session.flush()
            return row.id
    except Exception:  # noqa: BLE001 - logging telemetry must not break scanning
        import logging

        logging.getLogger(__name__).exception("Failed to record scan")
        return None


def recent_scans(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    with session_scope() as session:
        rows = session.scalars(
            select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
        ).all()
        return [row.to_dict() for row in rows]


def scans_for_host(host: str, limit: int = 10) -> list[dict[str, Any]]:
    """Prior verdicts for one hostname — how a host has scored over time."""
    host = (host or "").lower().strip().rstrip(".")[:255]
    if not host:
        return []
    with session_scope() as session:
        rows = session.scalars(
            select(Scan)
            .where(Scan.host == host)
            .order_by(Scan.created_at.desc())
            .limit(max(1, min(limit, 50)))
        ).all()
        return [row.to_dict() for row in rows]


def scan_by_id(scan_id: int) -> dict[str, Any] | None:
    """Full stored scan payload by primary key, or ``None`` if missing.

    Returns ``result_json`` when present (rows written after the schema
    migration), otherwise falls back to the slim ``to_dict`` row (older rows
    that pre-date the column).  The analyst uses this to bind tools to
    server-truth rather than the browser-echoed copy.
    """
    with session_scope() as session:
        row = session.get(Scan, int(scan_id))
        return row.to_full_dict() if row else None


def scan_stats(days: int = 30) -> dict[str, Any]:
    """Verdict mix and mean score per day — the drift signal for the deployed model.

    Every aggregate is filtered to the window. ``total_scans`` and the verdict
    mix used to be all-time while ``daily`` returned the last N *populated* day
    buckets, so a UI captioned "over the last 30 days" mixed three different
    time ranges, none of which was the last 30 days.
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    with session_scope() as session:
        window = Scan.created_at >= cutoff
        total = session.scalar(select(func.count(Scan.id)).where(window)) or 0
        all_time = session.scalar(select(func.count(Scan.id))) or 0

        verdicts = session.execute(
            select(Scan.verdict, func.count(Scan.id)).where(window).group_by(Scan.verdict)
        ).all()

        day = func.date(Scan.created_at)
        live_probability = case(
            (Scan.verdict.in_(LIVE_RISK_VERDICTS), Scan.probability),
        )
        daily = session.execute(
            select(day, func.count(Scan.id), func.avg(live_probability))
            .where(window)
            .group_by(day)
            .order_by(day.desc())
        ).all()

        return {
            "days": int(days),
            "since": cutoff.isoformat(),
            "total_scans": int(total),
            "total_scans_all_time": int(all_time),
            "verdicts": {str(v): int(c) for v, c in verdicts},
            "daily": [
                {"date": str(d), "scans": int(c), "mean_probability": float(p or 0.0)}
                for d, c, p in daily
            ],
        }
