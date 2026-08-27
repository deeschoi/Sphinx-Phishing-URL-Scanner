"""Runtime configuration read from the environment, with a ``.env`` fallback.

Secrets do not belong in ``config.py`` next to feature lists, and they must not
be committed. ``.env`` at the repo root is gitignored and loaded here without a
dependency on python-dotenv; real environment variables always win, so a
container's own settings are never overridden by a stray checkout file.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from phishing.config import PROJECT_ROOT


@lru_cache(maxsize=1)
def load_dotenv(path: Path | None = None) -> dict[str, str]:
    """Parse ``KEY=value`` lines from ``.env`` into ``os.environ`` if absent."""
    target = path or PROJECT_ROOT / ".env"
    loaded: dict[str, str] = {}
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return loaded
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        loaded[key] = value
        os.environ.setdefault(key, value)
    return loaded


def env(name: str, default: str = "") -> str:
    load_dotenv()
    return os.environ.get(name, default)


def env_int(name: str, default: int) -> int:
    try:
        return int(env(name, str(default)))
    except ValueError:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    value = env(name, "1" if default else "0").strip().lower()
    return value in {"1", "true", "yes", "on"}


# --- Scan API limits ---------------------------------------------------------
# Every scan costs a DNS lookup, an HTTP fetch of up to 20s, an HTML parse, and
# two model passes on the request threadpool. Without a cap, an unauthenticated
# caller can exhaust sockets and use the service as an outbound proxy.
SCAN_RATE_PER_MINUTE = env_int("SPHINX_SCAN_RATE_PER_MINUTE", 20)
SCAN_MAX_CONCURRENT = env_int("SPHINX_SCAN_MAX_CONCURRENT", 4)
# Chat is a separate budget so a public demo cannot be used as a Groq proxy.
# Local defaults are generous; a hosted demo should set 5 / 1.
CHAT_RATE_PER_MINUTE = env_int("SPHINX_CHAT_RATE_PER_MINUTE", 30)
CHAT_MAX_CONCURRENT = env_int("SPHINX_CHAT_MAX_CONCURRENT", 1)
READ_RATE_PER_MINUTE = env_int("SPHINX_READ_RATE_PER_MINUTE", 60)


def api_key() -> str:
    """Shared secret required on mutating/telemetry routes, or "" to leave open.

    Unset by default so the local demo keeps working. Set ``SPHINX_API_KEY``
    before binding this service to anything but localhost: with no key, anyone
    who can reach the port can force outbound fetches and read scan history.
    """
    return env("SPHINX_API_KEY", "").strip()


def allow_anonymous() -> str:
    """Who may call guarded routes when ``SPHINX_API_KEY`` is unset.

    ``loopback`` (default) keeps the localhost demo open. ``private`` also
    allows RFC1918 / ULA / link-local. ``1`` / ``true`` / ``all`` is the
    explicit public-demo opt-in. ``0`` / ``never`` refuses everyone.

    Render injects ``RENDER=true`` and the TCP peer is the proxy, not
    loopback. Leaving the mode unset there 401s every visitor scan, so
    Render defaults to the public-demo opt-in. An explicit value always
    wins, including ``loopback`` if you really want that on a public host.
    """
    configured = env("SPHINX_ALLOW_ANONYMOUS", "").strip().lower()
    if configured:
        return configured
    if env_bool("RENDER"):
        return "1"
    return "loopback"


# --- Groq-backed analyst chat ------------------------------------------------
# Optional local/operator fallback. A public demo should omit this so Groq
# bills the visitor who pasted X-Groq-Api-Key, not the person hosting Sphinx.
def groq_api_key() -> str:
    return env("GROQ_API_KEY", "").strip()


GROQ_BASE_URL = env("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_MODEL = env("GROQ_MODEL", "openai/gpt-oss-120b")
GROQ_TIMEOUT = env_int("GROQ_TIMEOUT", 45)
GROQ_MAX_TOOL_STEPS = env_int("GROQ_MAX_TOOL_STEPS", 5)
