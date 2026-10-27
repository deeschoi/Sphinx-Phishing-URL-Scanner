"""Hardened HTTP fetch for hostile pages. HTML is parsed; JavaScript is never run."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from requests.exceptions import TooManyRedirects

from phishing.features.reachability import classify_network_error
from phishing.netguard import (
    UnsafeTargetError,
    assert_public_url,
    guarded_session,
    strip_userinfo,
)

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 8
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 8
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class FetchDeadline(TimeoutError):
    """The wall-clock budget for the whole fetch was spent.

    ``requests`` resets its read timeout on every body chunk, so a target that
    drips one byte forever would otherwise hold a scan slot until the process
    restarts. The deadline is checked between chunks and between redirects.
    """


@dataclass
class FetchResult:
    url: str
    final_url: str
    ok: bool
    status_code: int | None
    html: str
    soup: BeautifulSoup | None
    n_redirects: int
    history_urls: list[str] = field(default_factory=list)
    error: str | None = None
    error_kind: str | None = None
    content_type: str = ""
    truncated: bool = False


def _read_capped(response, max_bytes: int, deadline: float) -> tuple[bytes, bool]:
    """Read at most ``max_bytes``, and never past ``deadline``."""
    chunks: list[bytes] = []
    size = 0
    truncated = False
    for chunk in response.iter_content(chunk_size=8192):
        if time.monotonic() >= deadline:
            raise FetchDeadline("fetch exceeded the time budget")
        if not chunk:
            continue
        size += len(chunk)
        if size > max_bytes:
            truncated = True
            break
        chunks.append(chunk)
    return b"".join(chunks), truncated


def fetch_page(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_BYTES,
) -> FetchResult:
    """GET ``url`` with a short timeout, size cap, and redirect accounting.

    Redirects are followed by hand rather than by ``requests``: every hop is
    re-validated against the SSRF guard before it is followed, because the whole
    point of an open redirect is that hop *n+1* is chosen by the target, not by
    us. The connection itself is made through a guarded adapter, so a hop that
    passes the URL check and then rebinds to loopback still fails.

    ``ok`` requires a 2xx response. A 404, a 503, or a WAF interstitial is not a
    measurement of the page the user asked about; scoring that markup produced
    verdicts on content the target never served. Those fall back to URL-only.

    JavaScript is not executed. Features that depend on runtime JS (status-bar
    spoofing, right-click handlers) are approximated from source text.
    """
    start_url = strip_userinfo(url)
    session = guarded_session()
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    history: list[str] = []
    current = start_url
    budget = max(float(timeout), 0.1)
    deadline = time.monotonic() + budget
    try:
        for _ in range(MAX_REDIRECTS + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FetchDeadline("fetch exceeded the time budget")
            assert_public_url(current)
            hop = min(budget, remaining)
            resp = session.get(
                current,
                headers=headers,
                timeout=(hop, hop),
                allow_redirects=False,
                stream=True,
            )
            location = resp.headers.get("Location")
            if resp.status_code in REDIRECT_CODES and location:
                resp.close()
                history.append(current)
                nxt = strip_userinfo(urljoin(current, location.strip()))
                if urlparse(nxt).scheme.lower() not in {"http", "https"}:
                    raise UnsafeTargetError(
                        f"Refusing to follow a redirect to {urlparse(nxt).scheme!r}."
                    )
                current = nxt
                continue

            raw, truncated = _read_capped(resp, max_bytes, deadline)
            content_type = resp.headers.get("Content-Type", "")
            html = raw.decode(resp.encoding or "utf-8", errors="replace")
            ok = 200 <= resp.status_code < 300
            soup = BeautifulSoup(html, "lxml") if ok else None
            return FetchResult(
                url=start_url,
                final_url=current,
                ok=ok,
                status_code=resp.status_code,
                html=html if ok else "",
                soup=soup,
                n_redirects=len(history),
                history_urls=list(history),
                content_type=content_type,
                truncated=truncated,
                error=None if ok else f"HTTP {resp.status_code}",
                error_kind=None if ok else "http",
            )

        raise TooManyRedirects(f"Exceeded {MAX_REDIRECTS} redirects")
    except UnsafeTargetError:
        raise
    except Exception as exc:  # noqa: BLE001 — extractor must never raise
        return FetchResult(
            url=start_url,
            final_url=current,
            ok=False,
            status_code=None,
            html="",
            soup=None,
            n_redirects=len(history),
            history_urls=list(history),
            error=f"{type(exc).__name__}: {exc}",
            error_kind=classify_network_error(exc),
        )
    finally:
        session.close()
