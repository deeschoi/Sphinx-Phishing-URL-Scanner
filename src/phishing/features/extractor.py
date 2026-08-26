"""Assemble a feature vector from a raw URL, with per-feature fallbacks."""

from __future__ import annotations

from typing import Literal

import pandas as pd

from phishing.config import (
    FEATURE_COLUMNS,
    PHIUSIIL_HTML_FEATURES,
    PHIUSIIL_MINIFIED_LINE_CHARS,
    PHIUSIIL_MODEL_FEATURES,
    PHIUSIIL_SPA_LINK_FEATURES,
    PHIUSIIL_URL_FEATURES,
    TIER_A,
    TIER_B,
    TIER_C,
)
from phishing.features.content_features import extract_content_features, redirect_feature
from phishing.features.fetch import FetchResult, fetch_page
from phishing.features.infra_features import extract_infra_features, unavailable_features
from phishing.features.phiusiil_content import extract_phiusiil_content_features
from phishing.features.phiusiil_url import extract_phiusiil_url_features
from phishing.features.reachability import LiveProbe, assess_reachability
from phishing.features.url_features import extract_url_features
from phishing.schema import FeatureWarning

Tier = Literal["A", "B", "full"]


def _neutral_fill(
    missing: list[str], reason: str, warnings: list[FeatureWarning]
) -> dict[str, float]:
    values = {}
    for name in missing:
        values[name] = 0
        warnings.append(FeatureWarning(name, reason, 0))
    return values


def _looks_like_js_shell(values: dict[str, float]) -> bool:
    """True when markup is script-heavy but almost has no crawlable links.

    Deliberately narrow. Widening this to fire on "self-refs low relative to
    script/CSS volume" was measured on the seed-42 live sample and cost 5.1
    points of recall for no FPR gain: a phishing kit is *also* a thin page
    behind a few scripts, so the ratio catches the kits along with the
    CDN-heavy legitimate pages it was meant for. See scripts/07_live_sample_eval.py.
    """
    links = float(values.get("NoOfExternalRef", 0)) + float(values.get("NoOfSelfRef", 0))
    scripts = float(values.get("NoOfJS", 0))
    loc = float(values.get("LineOfCode", 0))
    return links < 10 and (scripts >= 5 or loc >= 40)


def _impute_js_shell_links(
    values: dict[str, float],
    fill: dict[str, float],
    warnings: list[FeatureWarning],
) -> None:
    """Impute only the link-shaped columns, never the whole HTML block.

    Filling all of PHIUSIIL_HTML_FEATURES here was measured on the seed-42
    live sample and cost 10.3 points of recall: HasPasswordField, Bank, Pay
    and the rest are genuinely measured on a kit's login page, and replacing
    them with legitimate-class medians erases the evidence. See scripts/07_live_sample_eval.py.
    """
    if not fill or not _looks_like_js_shell(values):
        return
    for name in PHIUSIIL_SPA_LINK_FEATURES:
        if name not in fill:
            continue
        values[name] = float(fill[name])
        warnings.append(
            FeatureWarning(
                name,
                "JavaScript shell: static page-structure counts are unmeasured; "
                "filled with the legitimate-class median",
                float(fill[name]),
            )
        )


def _impute_minified_line_length(
    values: dict[str, float],
    fill: dict[str, float],
    warnings: list[FeatureWarning],
) -> None:
    if "LargestLineLength" not in fill:
        return
    if float(values.get("LargestLineLength", 0)) < PHIUSIIL_MINIFIED_LINE_CHARS:
        return
    values["LargestLineLength"] = float(fill["LargestLineLength"])
    warnings.append(
        FeatureWarning(
            "LargestLineLength",
            "Minified HTML: longest-line length is unmeasured against the "
            "pretty-printed training pages; filled with the legitimate-class median",
            float(fill["LargestLineLength"]),
        )
    )


def url_to_features(
    url: str,
    tier: Tier = "full",
    fetch: FetchResult | None = None,
    timeout: int | None = None,
) -> tuple[pd.Series, list[FeatureWarning], LiveProbe]:
    """Extract features in CSV column order.

    ``tier='A'`` is offline URL parsing only. ``tier='B'`` adds a page fetch.
    ``tier='full'`` adds TLS/WHOIS/DNS. Features that cannot be computed are
    filled with 0 (suspicious / unknown) and a warning is recorded. This
    function never raises on extraction failure.

    The third return value is whether the host was actually observed. The
    model still scores placeholder features; callers must not treat that
    score as a live-site verdict when the probe is ``unreachable``.
    """
    warnings: list[FeatureWarning] = []
    values: dict[str, int] = {c: 0 for c in FEATURE_COLUMNS}

    try:
        values.update(extract_url_features(url))
    except Exception as exc:  # noqa: BLE001
        values.update(_neutral_fill(TIER_A, f"URL parse failed: {exc}", warnings))

    probed = False
    page_fetched = False
    tls_inspected = False
    dns_ok: bool | None = None

    if tier in ("B", "full"):
        probed = True
        if fetch is not None:
            result = fetch
        elif timeout is not None:
            result = fetch_page(url, timeout=timeout)
        else:
            result = fetch_page(url)
        page_url = result.final_url or url
        if result.ok and result.soup is not None:
            page_fetched = True
            dns_ok = True
            try:
                values.update(extract_content_features(result, page_url))
            except Exception as exc:  # noqa: BLE001
                values.update(
                    _neutral_fill(TIER_B, f"content parse failed: {exc}", warnings)
                )
        else:
            if result.error_kind == "dns":
                dns_ok = False
            elif result.error_kind is not None:
                dns_ok = True
            values.update(
                _neutral_fill(
                    TIER_B,
                    f"page fetch failed: {result.error or 'no HTML'}",
                    warnings,
                )
            )
        values["Redirect"] = redirect_feature(result.n_redirects)

    if tier == "full":
        probed = True
        try:
            infra, infra_warnings, infra_dns_ok, tls_inspected = extract_infra_features(
                url
            )
            values.update(infra)
            warnings.extend(infra_warnings)
            if infra_dns_ok:
                dns_ok = True
            elif dns_ok is None:
                dns_ok = False
        except Exception as exc:  # noqa: BLE001
            values.update(_neutral_fill(TIER_C, f"infra lookup failed: {exc}", warnings))
            dead, dead_w = unavailable_features()
            values.update(dead)
            warnings.extend(dead_w)
            tls_inspected = False
            if dns_ok is None:
                dns_ok = False
    else:
        # Even in cheaper tiers, document that reputation features are unused.
        dead, dead_w = unavailable_features()
        values.update(dead)
        warnings.extend(dead_w)
        if tier == "A":
            values.update(_neutral_fill(TIER_B + TIER_C, "skipped (tier A)", warnings))
        elif tier == "B":
            values.update(_neutral_fill(TIER_C, "skipped (tier B)", warnings))

    probe = assess_reachability(
        probed=probed,
        dns_ok=dns_ok,
        page_fetched=page_fetched,
        tls_inspected=tls_inspected,
    )
    series = pd.Series({c: int(values[c]) for c in FEATURE_COLUMNS}, dtype="int64")
    return series, warnings, probe


def url_to_phiusiil_features(
    url: str,
    tier: Tier = "full",
    fetch: FetchResult | None = None,
    timeout: int | None = None,
    tld_prob: dict[str, float] | None = None,
    html_fill: dict[str, float] | None = None,
) -> tuple[pd.Series, list[FeatureWarning], LiveProbe]:
    """Extract the 48-feature PhiUSIIL vector the served model was trained on.

    ``tier='A'`` is URL parsing only. ``tier='B'`` and ``tier='full'`` fetch HTML.
    There is no TLS/WHOIS pass: HTTPS is the scheme bit, and page-quality
    features replace the retired reputation APIs.

    HTML that was not measured is filled with legitimate-class medians from
    training (not zeros). The scanner must still score those rows with the
    URL-only model; zeros here would be the phishing prototype, so ``html_fill``
    is required and a caller that omits it gets a ``ValueError`` rather than a
    quietly phishing-shaped row.
    """
    warnings: list[FeatureWarning] = []
    values: dict[str, float] = {c: 0.0 for c in PHIUSIIL_MODEL_FEATURES}
    # Fail closed rather than defaulting to zeros. All-zero HTML *is* the
    # phishing prototype in this table, so a caller without the trained fills
    # would silently score every unfetched page as a kit.
    missing_fill = [name for name in PHIUSIIL_HTML_FEATURES if name not in (html_fill or {})]
    if missing_fill:
        raise ValueError(
            "html_fill is required: scoring unmeasured HTML as zeros is the "
            f"phishing prototype. Missing {len(missing_fill)} of "
            f"{len(PHIUSIIL_HTML_FEATURES)} legitimate-class medians "
            "(artifact.extra['html_fill'])."
        )
    fill = {name: float(html_fill[name]) for name in PHIUSIIL_HTML_FEATURES}

    try:
        values.update(extract_phiusiil_url_features(url, tld_prob=tld_prob))
    except Exception as exc:  # noqa: BLE001
        values.update(_neutral_fill(PHIUSIIL_URL_FEATURES, f"URL parse failed: {exc}", warnings))

    probed = False
    page_fetched = False
    tls_inspected = False
    dns_ok: bool | None = None
    observed: dict[str, object] = {}

    def _fill_html(reason: str) -> None:
        for name in PHIUSIIL_HTML_FEATURES:
            values[name] = fill[name]
            warnings.append(FeatureWarning(name, reason, fill[name]))

    if tier in ("B", "full"):
        probed = True
        if fetch is not None:
            result = fetch
        elif timeout is not None:
            result = fetch_page(url, timeout=timeout)
        else:
            result = fetch_page(url)
        page_url = result.final_url or url
        observed = {
            "final_url": page_url,
            "status_code": result.status_code,
            "n_redirects": int(result.n_redirects or 0),
            "redirect_chain": tuple(result.history_urls or ()),
            "truncated": bool(getattr(result, "truncated", False)),
        }
        if result.ok and result.soup is not None:
            page_fetched = True
            dns_ok = True
            tls_inspected = page_url.lower().startswith("https://")
            try:
                values.update(extract_phiusiil_content_features(result, page_url))
                fill_src = html_fill or {}
                _impute_js_shell_links(values, fill_src, warnings)
                _impute_minified_line_length(values, fill_src, warnings)
            except Exception as exc:  # noqa: BLE001
                _fill_html(f"content parse failed: {exc}")
        else:
            if result.error_kind == "dns":
                dns_ok = False
            elif result.error_kind is not None:
                dns_ok = True
            _fill_html(f"page fetch failed: {result.error or 'no HTML'}")
    else:
        _fill_html("skipped (tier A)")

    probe = assess_reachability(
        probed=probed,
        dns_ok=dns_ok,
        page_fetched=page_fetched,
        tls_inspected=tls_inspected,
        **observed,
    )
    series = pd.Series({c: float(values[c]) for c in PHIUSIIL_MODEL_FEATURES}, dtype="float64")
    return series, warnings, probe
