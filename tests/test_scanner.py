"""Scanner helpers used by the FastAPI app."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from phishing.config import PHIUSIIL_MODEL_FEATURES
from phishing.features.reachability import LiveProbe
from phishing.scanner import UnsafeTargetError, research_findings, scan
from phishing.schema import ModelArtifact


def test_scan_rejects_loopback():
    with pytest.raises(UnsafeTargetError):
        scan("http://127.0.0.1/")
    with pytest.raises(UnsafeTargetError):
        scan("http://localhost:8000/")


def test_scan_rejects_empty_and_non_http():
    with pytest.raises(ValueError, match="empty"):
        scan("   ")
    with pytest.raises(ValueError, match="javascript"):
        scan("javascript:alert(1)")


def test_missing_model_message(tmp_path, monkeypatch):
    from phishing import scanner

    monkeypatch.setattr(scanner, "ARTIFACTS_DIR", tmp_path)
    scanner._loaded_payload.cache_clear()
    with pytest.raises(FileNotFoundError, match="train"):
        scanner._loaded_payload()
    scanner._loaded_payload.cache_clear()


def test_research_findings_has_ui_keys():
    data = research_findings()
    assert "leakage" in data
    assert "models" in data
    assert "unavailable_features" in data
    reasons = {row["feature"] for row in data["unavailable_features"]}
    assert reasons == {
        "web_traffic",
        "Page_Rank",
        "Google_Index",
        "Links_pointing_to_page",
        "Statistical_report",
    }
    if data["models"]:
        row = data["models"][0]
        assert "random_accuracy" in row
        assert "grouped_accuracy" in row


def test_api_module_imports():
    from api.main import app

    routes = {getattr(route, "path", None) for route in app.routes}
    assert "/" in routes
    assert "/api/scan" in routes
    assert "/api/scan/jobs" in routes
    assert "/api/scan/batch" in routes
    assert "/api/scans/{scan_id}" in routes
    assert "/api/findings" in routes
    assert "/api/health" in routes


def test_unicode_host_and_shortener_hops():
    from phishing.scanner import _redirect_hops, _unicode_host

    assert _unicode_host("https://example.com") is None
    decoded = _unicode_host("https://xn--e1afmkfd.xn--p1ai/")
    assert decoded == "пример.рф"
    hops = _redirect_hops(["https://bit.ly/abc", "https://phish.example/login"])
    assert hops[0]["shortener"] is True
    assert hops[1]["shortener"] is False


def _fake_model(probability: float = 0.003):
    class Est:
        def predict_proba(self, X):
            return np.array([[1.0 - probability, probability]] * len(X))

    artifact = ModelArtifact(
        model_name="Fake",
        feature_names=list(PHIUSIIL_MODEL_FEATURES),
        threshold=0.38,
        metrics={"accuracy": 0.9, "auroc": 0.99, "recall": 0.9, "fpr": 0.01},
        trained_at="test",
        extra={"fpr_threshold": 0.85, "url_threshold": 0.5, "url_fpr_threshold": 0.85},
    )
    return Est(), artifact


def _patch_scan(
    monkeypatch,
    probe: LiveProbe,
    probability: float = 0.003,
    url_probability: float = 0.12,
):
    from phishing import scanner
    from phishing.config import PHIUSIIL_URL_FEATURES

    features = pd.Series({c: 1.0 for c in PHIUSIIL_MODEL_FEATURES}, dtype="float64")
    monkeypatch.setattr(
        scanner, "url_to_phiusiil_features", lambda *a, **k: (features, [], probe)
    )
    full_est, artifact = _fake_model(probability)
    artifact.extra["url_features"] = list(PHIUSIIL_URL_FEATURES)
    url_est, _ = _fake_model(url_probability)
    monkeypatch.setattr(
        scanner,
        "_loaded_payload",
        lambda: {
            "estimator": full_est,
            "artifact": artifact,
            "url_estimator": url_est,
        },
    )

    def _skip_shap(*_a, **_k):
        raise RuntimeError("shap skipped in test")

    monkeypatch.setattr("phishing.explain.shap_values", _skip_shap)


def test_unresolved_host_is_not_legitimate(monkeypatch):
    _patch_scan(
        monkeypatch,
        LiveProbe(
            status="unreachable",
            dns_ok=False,
            page_fetched=False,
            tls_inspected=False,
        ),
        probability=0.003,
    )
    result = scan("https://iqospots.com")
    assert result["verdict"] == "unreachable"
    assert result["risk"] is None
    assert result["url_only"] is True
    assert result["prediction"] is None
    assert result["probability"] == pytest.approx(0.12)
    assert "URL-only" in result["model"] or result["url_only"] is True
    assert "does not resolve" in result["rationale"]
    assert result["reachability"]["status"] == "unreachable"
    assert result["coverage"]["page_fetched"] is False
    assert result["coverage"]["tls_checked"] is False


def test_fetch_failed_uses_url_model_as_verdict(monkeypatch):
    _patch_scan(
        monkeypatch,
        LiveProbe(
            status="fetch_failed",
            dns_ok=True,
            page_fetched=False,
            tls_inspected=False,
        ),
    )
    result = scan("https://example.com")
    assert result["verdict"] != "fetch_failed"
    assert result["risk"] is not None
    assert result["url_only"] is True
    assert "Risk is withheld" not in result["rationale"]
    assert "could not be fetched" in result["rationale"]
    assert result["probability"] == pytest.approx(0.12)
    assert result["url_only"] is True
    assert any("could not be fetched" in n for n in result["notes"])


def test_not_probed_withholds_and_uses_url_model(monkeypatch):
    _patch_scan(
        monkeypatch,
        LiveProbe(
            status="not_probed",
            dns_ok=None,
            page_fetched=False,
            tls_inspected=False,
        ),
        probability=0.99,
        url_probability=0.12,
    )
    result = scan("https://github.com")
    assert result["verdict"] == "not_probed"
    assert result["risk"] is None
    assert result["url_only"] is True
    assert result["probability"] == pytest.approx(0.12)
    assert result["probability"] < 0.5
    assert "not fetched" in result["rationale"]
    assert "URL string only" in result["rationale"]


def test_resolved_host_uses_probability_bands(monkeypatch):
    _patch_scan(
        monkeypatch,
        LiveProbe(
            status="resolved",
            dns_ok=True,
            page_fetched=True,
            tls_inspected=True,
        ),
        probability=0.003,
    )
    result = scan("https://example.com")
    assert result["verdict"] == "legitimate"
    assert result["risk"] == "legitimate"
    assert result["url_only"] is False
    assert result["prediction"] == "legitimate"


def test_rationale_cites_only_features_that_support_the_verdict():
    from phishing.scanner import _rationale

    probe = LiveProbe(
        status="resolved",
        dns_ok=True,
        page_fetched=True,
        tls_inspected=True,
    )
    signals = [
        {"label": "Longest HTML line", "contribution": 11.5},
        {"label": "Domain appears in the title", "contribution": -1.4},
    ]
    text = _rationale("phishing", signals, probe)
    assert "Longest HTML line" in text
    assert "Domain appears in the title" not in text


def test_plain_http_is_phishing_when_fetch_times_out():
    """neverssl.com is the HTTP demo chip. PhiUSIIL has no legitimate HTTP rows."""
    from phishing.features.fetch import FetchResult
    from phishing.tuning import load_payload

    try:
        payload = load_payload()
    except FileNotFoundError:
        pytest.skip("no trained model")
    if payload["artifact"].extra.get("dataset", "").find("PhiUSIIL") < 0:
        pytest.skip("served model is not PhiUSIIL")

    failed = FetchResult(
        url="http://neverssl.com",
        final_url="http://neverssl.com",
        ok=False,
        status_code=None,
        html="",
        soup=None,
        n_redirects=0,
        error="ReadTimeout: read timed out",
        error_kind="timeout",
    )
    result = scan("http://neverssl.com", tier="B", fetch=failed)
    assert result["url_only"] is True
    assert result["verdict"] == "phishing"
    assert result["risk"] == "phishing"
    assert result["probability"] > 0.9
    assert "fetch_failed" not in result["verdict"]
    notes = " ".join(result.get("notes") or [])
    assert "could not be fetched" in notes
    assert "plain HTTP" in notes
    assert "ReadTimeout" not in notes
