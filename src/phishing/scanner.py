"""Score a live URL and return the payload the web UI renders."""

from __future__ import annotations

from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

import pandas as pd

from phishing.config import (
    ARTIFACTS_DIR,
    DEAD_FEATURE_REASON,
    FEATURE_LABELS,
    PHIUSIIL_MODEL_FEATURES,
    PHIUSIIL_URL_FEATURES,
    REPORTS_DIR,
    REVERSED_FEATURES,
    UNAVAILABLE_2026,
    VALUE_MEANING,
)
from phishing.features.extractor import url_to_phiusiil_features
from phishing.features.phiusiil_url import is_free_hosting_platform, is_kit_shaped_path
from phishing.features.reachability import LiveProbe
from phishing.io import load_json, to_jsonable
from phishing.netguard import (
    BLOCKED_SCHEMES,
    UnsafeTargetError,
    assert_public_url,
    strip_userinfo,
)
from phishing.schema import FeatureWarning, ModelArtifact
from phishing.tuning import load_payload

__all__ = [
    "UnsafeTargetError",
    "available_models",
    "research_findings",
    "scan",
]


def _clean_json(value: Any) -> Any:
    return to_jsonable(value)


def _normalise_url(url: str) -> str:
    """Canonicalise the input, refusing anything that is not a fetchable web URL.

    ``user:password@host`` is dropped here rather than at fetch time so the
    credentials never reach the request, the response payload, or scan history.
    """
    text = url.strip()
    if not text:
        raise ValueError("URL is empty.")
    lowered = text.lower()
    for scheme in BLOCKED_SCHEMES:
        if lowered.startswith(f"{scheme}:") or lowered.startswith(f"{scheme}://"):
            raise ValueError(f"Scheme {scheme!r} is not allowed.")
    if "://" not in text:
        text = "https://" + text
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError("URL must use http or https.")
    if not parsed.hostname:
        raise ValueError("URL has no host.")
    return strip_userinfo(text)


@lru_cache(maxsize=1)
def _loaded_payload() -> dict[str, Any]:
    path = ARTIFACTS_DIR / "model.joblib"
    if not path.exists():
        raise FileNotFoundError(
            f"No trained model at {path}. From the repo root run: phishing train"
        )
    return load_payload(path)


def _loaded_model() -> tuple[Any, ModelArtifact]:
    payload = _loaded_payload()
    return payload["estimator"], payload["artifact"]


def _operating_point(
    artifact: ModelArtifact, name: str, threshold: float, prefix: str = ""
) -> dict[str, float]:
    """Recall/FPR measured *at this cut*, not the warn-point numbers reused.

    ``fit`` searches each operating point separately and stores the full
    threshold report, so the block row does not have to borrow warn's metrics.
    """
    points = artifact.extra.get(f"{prefix}operating_points") or {}
    report = points.get(name) or {}
    metrics = artifact.extra.get("url_metrics") if prefix else artifact.metrics
    metrics = metrics or {}
    return {
        "threshold": float(report.get("threshold", threshold)),
        "recall": float(report.get("recall", metrics.get("recall", 0.0))),
        "false_positive_rate": float(report.get("fpr", metrics.get("fpr", 0.0))),
    }


def available_models() -> dict[str, dict[str, Any]]:
    try:
        _, artifact = _loaded_model()
    except FileNotFoundError:
        return {}
    metrics = artifact.metrics
    warn = float(artifact.threshold)
    block = float(artifact.extra.get("fpr_threshold", max(warn, 0.85)))
    url_warn = float(artifact.extra.get("url_threshold", warn))
    url_block = float(artifact.extra.get("url_fpr_threshold", max(url_warn, 0.85)))
    return {
        artifact.model_name: {
            "features": list(artifact.feature_names),
            "metrics": metrics,
            "dataset": artifact.extra.get("dataset", ""),
            "live_sample": artifact.extra.get("live_sample") or {},
            "thresholds": {
                "warn": _operating_point(artifact, "warn", warn),
                "block": _operating_point(artifact, "block", block),
            },
            "url_only": {
                "features": list(artifact.extra.get("url_features") or PHIUSIIL_URL_FEATURES),
                "metrics": artifact.extra.get("url_metrics") or {},
                "thresholds": {
                    "warn": _operating_point(artifact, "warn", url_warn, prefix="url_"),
                    "block": _operating_point(artifact, "block", url_block, prefix="url_"),
                },
            },
        }
    }


# "probably safe" used to be pinned at 0.25, above the served warn cut of
# 0.205, so the band could never be emitted: anything below warn was already
# "legitimate". The bands are now derived from the cut the model actually
# ships with, which keeps all four reachable at any threshold.
def _risk(probability: float, warn: float, block: float) -> str:
    if probability >= block:
        return "phishing"
    if probability >= warn:
        return "suspicious"
    if probability >= warn / 2:
        return "probably safe"
    return "legitimate"


def _withhold_risk(probe: LiveProbe) -> bool:
    # DNS failure and offline scans are not live-site judgments. A fetch
    # timeout still has a fully measured URL string (scheme, host, path).
    return probe.status in {"unreachable", "not_probed"}


def _html_measured(probe: LiveProbe) -> bool:
    return bool(probe.page_fetched)


def _format_feature_value(feature: str, encoded: object) -> str:
    meanings = VALUE_MEANING.get(feature)
    try:
        as_int = int(encoded)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        as_int = None
    if (
        meanings is not None
        and as_int is not None
        and as_int in meanings
        and float(encoded) == as_int  # type: ignore[arg-type]
    ):
        return meanings[as_int]
    if isinstance(encoded, float) and not encoded.is_integer():
        return f"{encoded:.3f}"
    if isinstance(encoded, (int, float)):
        return str(int(encoded))
    return str(encoded)


def _warning_by_feature(warnings: list[FeatureWarning]) -> dict[str, FeatureWarning]:
    return {w.feature: w for w in warnings}


def _measured(feature: str, warning_map: dict[str, FeatureWarning]) -> bool:
    warning = warning_map.get(feature)
    if warning is None:
        return True
    message = warning.message.lower()
    return not any(
        token in message
        for token in ("skipped", "failed", "retired", "not queried", "unmeasured")
    )


def _signals(
    feature_names: list[str],
    shap_row,
    feature_row: pd.Series,
    warning_map: dict[str, FeatureWarning],
    k: int = 12,
) -> list[dict[str, Any]]:
    import numpy as np

    order = np.argsort(-np.abs(shap_row))[:k]
    out = []
    for i in order:
        name = feature_names[i]
        contribution = float(shap_row[i])
        encoded = feature_row[name]
        warning = warning_map.get(name)
        measured = _measured(name, warning_map)
        toward = "phishing" if contribution >= 0 else "legitimate"
        meaning = _format_feature_value(name, encoded)
        out.append(
            {
                "feature": name,
                "label": FEATURE_LABELS.get(name, name),
                "contribution": contribution,
                "measured": measured,
                "value_meaning": meaning,
                "encoding_unreliable": name in REVERSED_FEATURES,
                "evidence": (
                    warning.message
                    if warning and not measured
                    else meaning
                ),
                "direction": f"pushed toward {toward}",
            }
        )
    return out


def _url_pattern_phrase(url_pattern_risk: str | None) -> str:
    if url_pattern_risk == "phishing":
        return " The URL pattern itself looks like phishing."
    if url_pattern_risk == "suspicious":
        return " The URL pattern itself looks suspicious."
    if url_pattern_risk == "legitimate":
        return " The URL pattern itself does not look like phishing."
    # Withheld scans with a clean origin: do not call that "not phishing".
    if url_pattern_risk is None:
        return (
            " A clean-looking origin is not a finding that the site is safe."
        )
    return ""


def _rationale(
    verdict: str,
    signals: list[dict[str, Any]],
    probe: LiveProbe,
    url_pattern_risk: str | None = None,
) -> str:
    if probe.status == "unreachable":
        return (
            "The hostname does not resolve, so this is not a live-site judgment. "
            "DNS, TLS, and page fetch all failed; the score below is from the URL "
            "string and placeholders only." + _url_pattern_phrase(url_pattern_risk)
        )
    if probe.status == "not_probed":
        return (
            "The page was not fetched. Risk is withheld; the score below is from "
            "the URL string only." + _url_pattern_phrase(url_pattern_risk)
        )
    if verdict in {"phishing", "suspicious"}:
        top = [
            s["label"]
            for s in signals
            if s.get("label") and float(s.get("contribution", 0)) >= 0
        ][:2]
    else:
        top = [
            s["label"]
            for s in signals
            if s.get("label") and float(s.get("contribution", 0)) < 0
        ][:2]
    joined = " and ".join(top) if top else "the extracted URL features"
    if verdict == "phishing":
        text = f"This looks like phishing mainly because of {joined}."
    elif verdict == "suspicious":
        text = f"This is in the warning band; {joined} moved the score toward phishing."
    else:
        text = f"This looks legitimate; {joined} pulled the score toward the safe side."
    if probe.status == "fetch_failed":
        text += (
            " The page could not be fetched, so this is a URL-string score, not a "
            "live-page judgment."
        )
    return text


def _coverage(probe: LiveProbe, n_model_features: int) -> dict[str, Any]:
    return {
        "reachability": probe.status,
        "dns_ok": probe.dns_ok,
        "page_fetched": probe.page_fetched,
        # HTTPS on the landing page, from the scheme. No handshake is made and
        # no certificate is parsed, so this is not "certificate inspected".
        "https": probe.tls_inspected,
        "tls_checked": probe.tls_inspected,
        "http_status": probe.status_code,
        "redirects": probe.n_redirects,
        "truncated": probe.truncated,
        "features_used": n_model_features,
        "features_in_dataset": len(PHIUSIIL_MODEL_FEATURES),
    }


_PLAIN_NOTES = (
    (
        "javascript shell",
        "This page is mostly JavaScript with almost no static links. Those "
        "missing links were not counted as a phishing signal.",
    ),
)


def _notes(warnings: list[FeatureWarning]) -> list[str]:
    notes = []
    seen = set()
    for warning in warnings:
        if warning.feature in UNAVAILABLE_2026:
            continue
        low = warning.message.lower()
        if "skipped" in low:
            continue
        if "page fetch failed" in low or "content parse failed" in low:
            continue
        # Minified HTML is the common case for 2026 sites; keep the fill, skip the note.
        if "minified html" in low:
            continue
        text = None
        for needle, plain in _PLAIN_NOTES:
            if needle in low:
                text = plain
                break
        if text is None:
            text = f"{FEATURE_LABELS.get(warning.feature, warning.feature)}: {warning.message}"
        if text in seen:
            continue
        seen.add(text)
        notes.append(text)
    return notes[:8]


def scan(
    url: str,
    timeout: int = 8,
    *,
    tier: str = "full",
    fetch=None,
) -> dict[str, Any]:
    """Extract features, score with the deployable model, and explain the verdict."""
    normalised = _normalise_url(url)
    assert_public_url(normalised)
    payload = _loaded_payload()
    estimator, artifact = payload["estimator"], payload["artifact"]
    url_estimator = payload.get("url_estimator")
    tld_prob = artifact.extra.get("tld_legit_prob") or {}
    html_fill = artifact.extra.get("html_fill") or {}
    features, warnings, probe = url_to_phiusiil_features(
        normalised,
        tier=tier,  # type: ignore[arg-type]
        timeout=timeout,
        fetch=fetch,
        tld_prob=tld_prob,
        html_fill=html_fill,
    )
    # The page that was actually scored, which is not always the one pasted:
    # a 302 to another host is exactly what redirect-based phishing does.
    final_url = strip_userinfo(probe.final_url or normalised)
    withheld = _withhold_risk(probe)
    use_url_only = withheld or not _html_measured(probe)
    if use_url_only and url_estimator is not None:
        feature_names = list(artifact.extra.get("url_features") or PHIUSIIL_URL_FEATURES)
        scorer = url_estimator
        warn = float(artifact.extra.get("url_threshold", artifact.threshold))
        block = float(artifact.extra.get("url_fpr_threshold", max(warn, 0.85)))
        model_label = f"{artifact.model_name} (URL-only)"
        metrics = artifact.extra.get("url_metrics") or artifact.metrics
    else:
        feature_names = list(artifact.feature_names)
        scorer = estimator
        warn = float(artifact.threshold)
        block = float(artifact.extra.get("fpr_threshold", max(warn, 0.85)))
        model_label = artifact.model_name
        metrics = artifact.metrics

    X = features[feature_names].to_frame().T
    probability = float(scorer.predict_proba(X)[:, 1][0])

    # Score the URL string on its own regardless of which model is serving.
    # It backs the disagreement rule below and the qualified verdict the UI
    # shows when the host never resolved.
    url_warn = float(artifact.extra.get("url_threshold", artifact.threshold))
    url_block = float(artifact.extra.get("url_fpr_threshold", max(url_warn, 0.85)))
    url_feature_names = list(artifact.extra.get("url_features") or PHIUSIIL_URL_FEATURES)
    page_probability: float | None = None
    url_probability: float | None = None
    if url_estimator is not None:
        if use_url_only:
            url_probability = probability
        else:
            page_probability = probability
            url_row = features[url_feature_names].to_frame().T
            url_probability = float(url_estimator.predict_proba(url_row)[:, 1][0])

    url_pattern_risk = (
        _risk(url_probability, url_warn, url_block) if url_probability is not None else None
    )

    # Withheld scans never get a live risk band. The URL-pattern chip is the
    # only string judgment the UI shows, so a kit-shaped path (ignored by the
    # origin-only model) still has to surface, and a clean origin must not be
    # rendered as "legitimate".
    kit_path = is_kit_shaped_path(normalised)
    if withheld:
        if kit_path:
            url_pattern_risk = "phishing"
        elif url_pattern_risk in {"legitimate", "probably safe"}:
            url_pattern_risk = None

    # The page model's top weights (NoOfExternalRef 57%, LineOfCode 10%,
    # NoOfSelfRef 9%) are exactly the columns that moved between the 2023 crawl
    # and 2026 markup, so a rich modern homepage can pin at p ≈ 1.0. When the
    # URL string looks clean, that disagreement is drift, not evidence.
    #
    # Gated on the free-hosting hint: a kit on firebaseapp.com has a clean-
    # looking URL by construction, and must not be talked down this way.
    disagreement = False
    if (
        not use_url_only
        and page_probability is not None
        and url_probability is not None
        and page_probability >= block
        and url_probability < url_warn
        and not is_free_hosting_platform(normalised)
    ):
        disagreement = True
        probability = url_probability
        model_label = f"{artifact.model_name} (URL disagreement)"

    risk = _risk(probability, warn, block)
    verdict = probe.status if withheld else risk
    warning_map = _warning_by_feature(warnings)

    # SHAP must explain the number on screen. Before the disagreement rule
    # switched the scorer, explanations were still computed on the page
    # estimator, so the bars cited page-richness while the gauge showed a
    # URL-string probability.
    if disagreement:
        explained_estimator = url_estimator
        explained_names = url_feature_names
    else:
        explained_estimator = scorer
        explained_names = feature_names
    explained_X = features[explained_names].to_frame().T

    signals: list[dict[str, Any]] = []
    try:
        from phishing.explain import shap_values

        _, values = shap_values(explained_estimator, explained_X, background=explained_X)
        signals = _signals(explained_names, values[0], features, warning_map)
    except Exception as exc:  # noqa: BLE001
        signals = []
        shap_error = f"SHAP unavailable: {exc}"
    else:
        shap_error = None

    notes = _notes(warnings)
    if shap_error:
        notes.insert(0, shap_error)
    if disagreement:
        notes.insert(
            0,
            "The page-content model scored this as phishing, but the URL string "
            "on its own looks clean. That pattern is usually 2023-vs-2026 drift "
            "in the page-richness features rather than evidence, so the score "
            "shown is the URL-string score.",
        )
    if withheld and kit_path:
        notes.insert(
            0,
            "The URL path looks like a phishing kit (a landing file such as "
            ".html or .php). The origin-only model does not count the path, so "
            "the string is flagged from that path rather than from the host alone.",
        )
    if use_url_only:
        if probe.status == "fetch_failed":
            status_code = probe.status_code
            if status_code is not None and not (200 <= status_code < 300):
                fetch_note = (
                    f"The server answered HTTP {status_code}, so no page from this "
                    "URL was measured. An error, parking, or block page is not the "
                    "site being judged. This score is from the URL string only."
                )
            else:
                fetch_note = (
                    "The page could not be fetched. This score is from the URL string only."
                )
            if normalised.lower().startswith("http://"):
                fetch_note += (
                    " This dataset has no legitimate HTTP pages, so plain HTTP "
                    "scores as phishing."
                )
            notes.insert(0, fetch_note)
        else:
            notes.insert(
                0,
                "Page HTML was not measured; this probability comes from the URL-only model.",
            )
    if probe.truncated:
        notes.insert(
            0,
            "The page exceeded the 2 MB download cap, so HTML counts below are "
            "measured on a partial document.",
        )
    if final_url != normalised:
        notes.insert(
            0,
            f"This URL redirected {probe.n_redirects} time"
            f"{'' if probe.n_redirects == 1 else 's'} and the page scored was "
            f"{final_url}.",
        )

    payload_out = {
        "url": normalised,
        "final_url": final_url,
        "redirect_chain": list(probe.redirect_chain),
        "http_status": probe.status_code,
        "reachability": probe.to_dict(),
        "risk": None if withheld else risk,
        "verdict": verdict,
        "url_only": use_url_only,
        "probability": probability,
        "page_probability": page_probability,
        "url_probability": url_probability,
        "url_pattern_risk": url_pattern_risk,
        "url_disagreement": disagreement,
        "rationale": _rationale(verdict, signals, probe, url_pattern_risk),
        "notes": notes,
        "error": None,
        "signals": signals,
        "coverage": _coverage(probe, len(feature_names)),
        "model": model_label,
        # Two different measurements, labelled as such. The holdout numbers are
        # the frozen 2023 CSV columns; the live-sample numbers are the same
        # model re-extracting features over the network, which is what a user
        # of this scanner actually gets. Showing only the first read as 99.95%
        # accuracy on live 2026 pages, which is not true.
        "model_quality": {
            "accuracy": float(metrics.get("accuracy", 0.0)),
            "auroc": float(metrics.get("auroc", 0.0)),
            "recall_at_warn": float(metrics.get("recall", 0.0)),
            "false_positive_rate_at_warn": float(metrics.get("fpr", 0.0)),
            "warn_threshold": warn,
            "block_threshold": block,
            "measured_on": "grouped holdout of the frozen 2023 dataset columns",
            "live_sample": artifact.extra.get("live_sample") or None,
        },
        "prediction": (
            None if withheld else ("phishing" if probability >= warn else "legitimate")
        ),
        "threshold": warn,
        "warnings": [w.to_dict() for w in warnings],
        "features": features.to_dict(),
    }
    return _clean_json(payload_out)


def research_findings() -> dict[str, Any]:
    """Headline numbers for the Research findings tab."""

    leakage = load_json(REPORTS_DIR / "01_grouped_evaluation.json")
    shap_res = load_json(REPORTS_DIR / "03_shap.json")
    obsolescence = load_json(REPORTS_DIR / "04_obsolescence.json")
    minimal = load_json(REPORTS_DIR / "05_minimal_features.json")
    payload = {
        "leakage": leakage.get("leakage", {}),
        "models": leakage.get("results", []),
        "reversed_features": shap_res.get("reversed_features", []),
        "no_signal_features": shap_res.get("no_signal_features", []),
        "encoding_audit": shap_res.get("encoding_audit", []),
        "top_interactions": shap_res.get("interactions", [])[:6],
        "scenarios": obsolescence.get("scenarios", []),
        "minimal_feature_set": minimal.get("minimal_feature_set", []),
        "unavailable_features": [
            {"feature": f, "reason": DEAD_FEATURE_REASON[f]} for f in UNAVAILABLE_2026
        ],
    }
    return _clean_json(payload)
