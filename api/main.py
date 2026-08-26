"""FastAPI service for the phishing scanner."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.security import (
    chat_limiter,
    client_key,
    read_limiter,
    require_api_key,
    scan_limiter,
)
from phishing.agent import AgentUnavailableError
from phishing.agent import answer as agent_answer
from phishing.db import init_db, recent_scans, record_scan, scan_stats
from phishing.netguard import UnsafeTargetError
from phishing.scanner import available_models, research_findings, scan
from phishing.settings import GROQ_MODEL, groq_api_key

ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = ROOT / "web" / "dist"
_RESERVED_FRONTEND = {"api", "docs", "redoc", "openapi.json"}

MISSING_FRONTEND = """<!doctype html>
<title>Frontend not built</title>
<p>The React UI has not been built. From the repo root:</p>
<pre>cd web &amp;&amp; npm install &amp;&amp; npm run build</pre>
<p>Or run the Vite dev server on port 5173 while this API is on 8000.</p>
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(
    title="Sphinx",
    description="URL phishing guardian: explained phishing verdicts from a "
                "model trained on the PhiUSIIL 2023 URL dataset.",
    version="1.1.0",
    lifespan=lifespan,
)


class ScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan", max_length=2048)
    timeout: int = Field(8, ge=2, le=20, description="Per-request timeout in seconds")


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(..., max_length=4000)


_VERDICTS = frozenset(
    {"legitimate", "probably safe", "suspicious", "phishing", "unreachable", "not_probed"}
)
_RISKS = frozenset({"legitimate", "probably safe", "suspicious", "phishing"})
_REACHABILITY = frozenset({"resolved", "unreachable", "fetch_failed", "not_probed"})


def _clip(value: object, limit: int) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


def _as_float(value: object) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if number != number or number in {float("inf"), float("-inf")}:
        return None
    return number


def _unit_interval(value: object) -> float | None:
    number = _as_float(value)
    if number is None or number < 0 or number > 1:
        return None
    return number


def _as_int(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _as_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in {"true", "false", "1", "0", "yes", "no"}:
        return value.lower() in {"true", "1", "yes"}
    return default


def _vocab(value: object, allowed: frozenset[str]) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text in allowed else None


class SignalPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    feature: str | None = None
    label: str | None = None
    value_meaning: str | None = None
    evidence: str | None = None
    contribution: float | None = None
    measured: bool | None = None

    @field_validator("feature", "label", mode="before")
    @classmethod
    def _clip_label(cls, value: object) -> str | None:
        return _clip(value, 200)

    @field_validator("value_meaning", "evidence", mode="before")
    @classmethod
    def _clip_value(cls, value: object) -> str | None:
        return _clip(value, 400)

    @field_validator("contribution", mode="before")
    @classmethod
    def _contrib(cls, value: object) -> float | None:
        return _as_float(value)

    @field_validator("measured", mode="before")
    @classmethod
    def _measured(cls, value: object) -> bool | None:
        if value is None:
            return None
        return _as_bool(value)


class WarningPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    feature: str | None = None
    message: str | None = None
    fallback: float | None = None

    @field_validator("feature", mode="before")
    @classmethod
    def _clip_feature(cls, value: object) -> str | None:
        return _clip(value, 64)

    @field_validator("message", mode="before")
    @classmethod
    def _clip_message(cls, value: object) -> str | None:
        return _clip(value, 400)

    @field_validator("fallback", mode="before")
    @classmethod
    def _fallback(cls, value: object) -> float | None:
        return _as_float(value)


class CoveragePayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    reachability: str | None = None
    dns_ok: bool | None = None
    page_fetched: bool | None = None
    https: bool | None = None
    tls_checked: bool | None = None
    http_status: int | None = None
    redirects: int | None = None
    truncated: bool | None = None
    features_used: int | None = None
    features_in_dataset: int | None = None

    @field_validator("reachability", mode="before")
    @classmethod
    def _reach(cls, value: object) -> str | None:
        return _vocab(value, _REACHABILITY)

    @field_validator("dns_ok", "page_fetched", "https", "tls_checked", "truncated", mode="before")
    @classmethod
    def _flag(cls, value: object) -> bool | None:
        if value is None:
            return None
        return _as_bool(value)

    @field_validator(
        "http_status", "redirects", "features_used", "features_in_dataset", mode="before"
    )
    @classmethod
    def _count(cls, value: object) -> int | None:
        return _as_int(value)


class LiveSamplePayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    accuracy: float | None = None
    recall: float | None = None
    false_positive_rate: float | None = None
    precision: float | None = None
    n_per_class: int | None = None
    unrated_hosts: int | None = None
    seed: int | None = None
    note: str | None = None

    @field_validator(
        "accuracy", "recall", "false_positive_rate", "precision", mode="before"
    )
    @classmethod
    def _rate(cls, value: object) -> float | None:
        return _as_float(value)

    @field_validator("n_per_class", "unrated_hosts", "seed", mode="before")
    @classmethod
    def _count(cls, value: object) -> int | None:
        return _as_int(value)

    @field_validator("note", mode="before")
    @classmethod
    def _note(cls, value: object) -> str | None:
        return _clip(value, 400)


class ModelQualityPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    accuracy: float | None = None
    auroc: float | None = None
    recall_at_warn: float | None = None
    false_positive_rate_at_warn: float | None = None
    warn_threshold: float | None = None
    block_threshold: float | None = None
    measured_on: str | None = None
    live_sample: LiveSamplePayload | None = None

    @field_validator(
        "accuracy",
        "auroc",
        "recall_at_warn",
        "false_positive_rate_at_warn",
        "warn_threshold",
        "block_threshold",
        mode="before",
    )
    @classmethod
    def _metric(cls, value: object) -> float | None:
        return _as_float(value)

    @field_validator("measured_on", mode="before")
    @classmethod
    def _measured_on(cls, value: object) -> str | None:
        return _clip(value, 200)

    @field_validator("live_sample", mode="before")
    @classmethod
    def _live(cls, value: object) -> object:
        return value if isinstance(value, dict) else None


class ScanPayload(BaseModel):
    """Lenient scan body: unknown keys dropped, out-of-range values coerced.

    A strict model would 422 payloads the current frontend (and the sparse
    ``CHAT`` fixture) still send. Validators clip, map to vocabularies, or
    drop rather than raise, so currently-valid requests keep working.
    """

    model_config = ConfigDict(extra="ignore")

    url: str | None = None
    final_url: str | None = None
    verdict: str | None = None
    risk: str | None = None
    url_pattern_risk: str | None = None
    probability: float | None = None
    page_probability: float | None = None
    url_probability: float | None = None
    url_only: bool = False
    url_disagreement: bool = False
    model: str | None = None
    rationale: str | None = None
    notes: list[str] = Field(default_factory=list)
    signals: list[SignalPayload] = Field(default_factory=list)
    features: dict[str, float] = Field(default_factory=dict)
    warnings: list[WarningPayload] = Field(default_factory=list)
    coverage: CoveragePayload | None = None
    model_quality: ModelQualityPayload | None = None
    scan_id: int | None = None

    @field_validator("url", "final_url", mode="before")
    @classmethod
    def _clip_url(cls, value: object) -> str | None:
        return _clip(value, 2048)

    @field_validator("verdict", mode="before")
    @classmethod
    def _verdict(cls, value: object) -> str | None:
        return _vocab(value, _VERDICTS)

    @field_validator("risk", "url_pattern_risk", mode="before")
    @classmethod
    def _risk(cls, value: object) -> str | None:
        return _vocab(value, _RISKS)

    @field_validator("probability", "page_probability", "url_probability", mode="before")
    @classmethod
    def _prob(cls, value: object) -> float | None:
        return _unit_interval(value)

    @field_validator("url_only", "url_disagreement", mode="before")
    @classmethod
    def _flag(cls, value: object) -> bool:
        return _as_bool(value)

    @field_validator("model", mode="before")
    @classmethod
    def _model(cls, value: object) -> str | None:
        return _clip(value, 64)

    @field_validator("rationale", mode="before")
    @classmethod
    def _rationale(cls, value: object) -> str | None:
        return _clip(value, 2000)

    @field_validator("notes", mode="before")
    @classmethod
    def _notes(cls, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item)[:400] for item in value[:10]]

    @field_validator("signals", mode="before")
    @classmethod
    def _signals(cls, value: object) -> object:
        if not isinstance(value, list):
            return []
        return [item for item in value[:48] if isinstance(item, dict)]

    @field_validator("features", mode="before")
    @classmethod
    def _features(cls, value: object) -> dict[str, float]:
        if not isinstance(value, dict):
            return {}
        out: dict[str, float] = {}
        for key, raw in value.items():
            if len(out) >= 48:
                break
            number = _as_float(raw)
            if number is None:
                continue
            out[str(key)[:64]] = number
        return out

    @field_validator("warnings", mode="before")
    @classmethod
    def _warnings(cls, value: object) -> object:
        if not isinstance(value, list):
            return []
        return [item for item in value[:48] if isinstance(item, dict)]

    @field_validator("coverage", "model_quality", mode="before")
    @classmethod
    def _nested(cls, value: object) -> object:
        return value if isinstance(value, dict) else None

    @field_validator("scan_id", mode="before")
    @classmethod
    def _scan_id(cls, value: object) -> int | None:
        return _as_int(value)


class ChatRequest(BaseModel):
    """A question about a scan the caller already ran.

    ``scan`` is that scan's response payload, echoed back. Schema validation,
    quoting, and a ``scan_id`` cross-check against stored telemetry enforce
    that it is grounding data, never instructions: unknown keys are ignored
    and out-of-range values are coerced, so currently-valid requests keep
    working. The system prompt is server-side and the model can only reach
    real evidence through tools.
    """

    scan: ScanPayload = Field(..., description="The /api/scan response being discussed")
    messages: list[ChatMessage] = Field(..., min_length=1, max_length=24)


@app.post("/api/scan", dependencies=[Depends(require_api_key)])
def scan_url(request: ScanRequest, http_request: Request) -> dict:
    # A scan is a DNS lookup, an outbound fetch of up to 20s, an HTML parse and
    # two model passes, all on the request threadpool. Both limits are load
    # bearing: the per-caller budget stops one client monopolising the service,
    # and the in-flight cap stops many clients exhausting sockets together.
    scan_limiter.check(client_key(http_request))
    try:
        with scan_limiter.slot():
            started = time.perf_counter()
            result = scan(request.url, timeout=request.timeout)
            duration_ms = int((time.perf_counter() - started) * 1000)
        result["scan_id"] = record_scan(result, duration_ms=duration_ms)
        result["duration_ms"] = duration_ms
        return result
    except HTTPException:
        raise
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Scan failed: {type(exc).__name__}"
        ) from exc


@app.get("/api/agent")
def agent_status() -> dict:
    """Whether chat needs a visitor-supplied Groq key.

    The panel is always offered. Scans do not need a key. Chat does, from the
    browser (``X-Groq-Api-Key``) or from optional server ``GROQ_API_KEY``.
    """
    server_key = bool(groq_api_key())
    return {
        "enabled": True,
        "requires_user_key": not server_key,
        "model": GROQ_MODEL,
        "detail": (
            None
            if server_key
            else (
                "Scans work without a key. Chat needs a Groq API key from you "
                "(https://console.groq.com/keys). The key is sent only with "
                "chat requests and is not stored on the server."
            )
        ),
    }


@app.post("/api/chat", dependencies=[Depends(require_api_key)])
def chat(
    request: ChatRequest,
    http_request: Request,
    x_groq_api_key: str | None = Header(default=None),
) -> dict:
    """Answer a question about a scan, grounded in that scan's evidence.

    ``X-Groq-Api-Key`` is optional when the server has ``GROQ_API_KEY``. The
    header is never logged and is not accepted on ``/api/scan``.
    """
    chat_limiter.check(client_key(http_request))
    # Header wins; env is fallback only. Do not interpolate the value anywhere.
    key = (x_groq_api_key or "").strip() or groq_api_key()
    try:
        with chat_limiter.slot():
            return agent_answer(
                request.scan.model_dump(),
                [message.model_dump() for message in request.messages],
                api_key=key,
            )
    except AgentUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Chat failed: {type(exc).__name__}"
        ) from exc


@app.get("/api/model")
def model_info() -> dict:
    models = available_models()
    return {
        name: {
            "features": bundle["features"],
            "accuracy": bundle["metrics"]["accuracy"],
            "auroc": bundle["metrics"]["auroc"],
            "dataset": bundle.get("dataset", ""),
            # The held-out numbers above are the frozen 2023 dataset columns.
            # This is the same model measured over the live network, which is
            # what a scan of a real URL gets.
            "live_sample": bundle.get("live_sample") or {},
            "thresholds": bundle["thresholds"],
            "url_only": bundle.get("url_only") or {},
        }
        for name, bundle in models.items()
    }


@app.get("/api/findings")
def findings() -> dict:
    """Headline results from the analysis, surfaced alongside the scanner."""
    return research_findings()


@app.get("/api/scans", dependencies=[Depends(require_api_key)])
def scans(
    http_request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict:
    """Recent scan history. URLs are stored without credentials or query strings;
    path segments that look like secrets are redacted best-effort.
    """
    read_limiter.check(client_key(http_request))
    return {"scans": recent_scans(limit=limit, offset=offset)}


@app.get("/api/stats", dependencies=[Depends(require_api_key)])
def stats(http_request: Request, days: int = Query(30, ge=1, le=365)) -> dict:
    """Verdict mix and mean score per day, for spotting score drift."""
    read_limiter.check(client_key(http_request))
    return scan_stats(days=days)


@app.get("/api/health")
def health() -> dict:
    """Liveness only: the process is up and serving. Never touches the model or DB."""
    return {"status": "ok"}


@app.get("/api/ready")
def ready() -> dict:
    """Readiness: can this instance actually serve a scan?

    ``/api/health`` returning ok while ``artifacts/model.joblib`` is missing
    meant an orchestrator kept routing traffic to an instance that answered
    every scan with a 503.
    """
    checks: dict[str, object] = {}
    ok = True

    try:
        models = available_models()
        checks["model"] = next(iter(models)) if models else None
        if not models:
            ok = False
            checks["model_error"] = "No trained model artifact. Run: phishing train"
    except Exception as exc:  # noqa: BLE001 — readiness reports, never raises
        ok = False
        checks["model_error"] = f"{type(exc).__name__}: {exc}"

    try:
        from sqlalchemy import text

        from phishing.db import session_scope

        with session_scope() as session:
            session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001 — readiness reports, never raises
        ok = False
        checks["database"] = f"{type(exc).__name__}: {exc}"

    checks["frontend"] = "built" if (DIST_DIR / "index.html").is_file() else "not built"
    checks["analyst"] = "server_key" if groq_api_key() else "byok"
    if not ok:
        raise HTTPException(status_code=503, detail={"status": "not ready", **checks})
    return {"status": "ready", **checks}


def _frontend_file(relative: str) -> Path | None:
    if not relative:
        return None
    candidate = (DIST_DIR / relative).resolve()
    try:
        candidate.relative_to(DIST_DIR.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _frontend_index():
    index_path = DIST_DIR / "index.html"
    if index_path.is_file():
        return FileResponse(index_path)
    return HTMLResponse(MISSING_FRONTEND, status_code=503)


@app.get("/")
def index():
    """Serve the built React app, or a short how-to if it has not been built."""
    return _frontend_index()


@app.get("/{full_path:path}")
def spa(full_path: str):
    """Client-side routes (/history, /stats, /findings) all share index.html."""
    first = full_path.split("/", 1)[0]
    if first in _RESERVED_FRONTEND:
        raise HTTPException(status_code=404, detail="Not found")
    direct = _frontend_file(full_path)
    if direct is not None:
        return FileResponse(direct)
    return _frontend_index()


_assets = DIST_DIR / "assets"
if _assets.is_dir():
    app.mount("/assets", StaticFiles(directory=_assets), name="assets")
