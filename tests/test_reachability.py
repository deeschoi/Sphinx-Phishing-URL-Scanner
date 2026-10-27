"""Reachability is classified from probe flags and exception types, not warning text."""

from __future__ import annotations

import socket
import time

import requests

from phishing.config import FEATURE_COLUMNS
from phishing.features.extractor import url_to_features
from phishing.features.fetch import FetchResult, fetch_page
from phishing.features.infra_features import unavailable_features
from phishing.features.reachability import (
    assess_reachability,
    classify_network_error,
)
from phishing.schema import FeatureWarning


def test_assess_resolved_when_page_or_tls_seen():
    page = assess_reachability(
        probed=True, dns_ok=True, page_fetched=True, tls_inspected=False
    )
    assert page.status == "resolved"
    tls = assess_reachability(
        probed=True, dns_ok=True, page_fetched=False, tls_inspected=True
    )
    assert tls.status == "resolved"
    assert tls.dns_ok is True


def test_assess_unreachable_when_dns_fails_and_host_unseen():
    probe = assess_reachability(
        probed=True, dns_ok=False, page_fetched=False, tls_inspected=False
    )
    assert probe.status == "unreachable"
    assert probe.dns_ok is False


def test_assess_fetch_failed_when_name_resolves_but_nothing_is_inspected():
    probe = assess_reachability(
        probed=True, dns_ok=True, page_fetched=False, tls_inspected=False
    )
    assert probe.status == "fetch_failed"
    assert probe.dns_ok is True


def test_assess_not_probed_for_offline_tier():
    probe = assess_reachability(
        probed=False, dns_ok=None, page_fetched=False, tls_inspected=False
    )
    assert probe.status == "not_probed"
    assert probe.dns_ok is None


def test_classify_gaierror_wrapped_in_connection_error():
    inner = socket.gaierror(8, "nodename nor servname provided, or not known")
    outer = requests.exceptions.ConnectionError(inner)
    assert classify_network_error(outer) == "dns"
    assert classify_network_error(inner) == "dns"


def test_classify_timeout_before_generic_connection_error():
    exc = requests.exceptions.ConnectTimeout("timed out")
    assert classify_network_error(exc) == "timeout"


def test_fetch_page_records_dns_error_kind(monkeypatch):
    class BoomSession:
        max_redirects = 8

        def get(self, *args, **kwargs):
            raise requests.exceptions.ConnectionError(
                socket.gaierror(8, "nodename nor servname provided, or not known")
            )

        def close(self):
            pass

    monkeypatch.setattr("phishing.features.fetch.guarded_session", BoomSession)
    result = fetch_page("https://no-such-host.invalid/")
    assert result.ok is False
    assert result.error_kind == "dns"


def test_fetch_page_reports_non_2xx_as_a_failed_fetch(monkeypatch):
    """A 404 or a WAF interstitial is not the page the user asked about."""

    class Resp:
        status_code = 503
        headers = {"Content-Type": "text/html"}
        encoding = "utf-8"

        def iter_content(self, chunk_size=8192):
            yield b"<html><title>Service unavailable</title></html>"

        def close(self):
            pass

    class Session:
        def get(self, *args, **kwargs):
            return Resp()

        def close(self):
            pass

    monkeypatch.setattr("phishing.features.fetch.guarded_session", Session)
    result = fetch_page("https://example.com/")
    assert result.ok is False
    assert result.status_code == 503
    assert result.soup is None
    assert result.html == ""
    assert result.error_kind == "http"


def test_fetch_page_aborts_a_slow_drip(monkeypatch):
    """A body that never ends must not hold the scan past the wall-clock budget."""

    class Resp:
        status_code = 200
        headers = {"Content-Type": "text/html"}
        encoding = "utf-8"

        def iter_content(self, chunk_size=8192):
            while True:
                time.sleep(0.05)
                yield b"x"

        def close(self):
            pass

    class Session:
        def get(self, *args, **kwargs):
            return Resp()

        def close(self):
            pass

    monkeypatch.setattr("phishing.features.fetch.assert_public_url", lambda url: None)
    monkeypatch.setattr("phishing.features.fetch.guarded_session", Session)
    started = time.monotonic()
    result = fetch_page("https://example.com/", timeout=1)
    assert time.monotonic() - started < 2
    assert result.ok is False
    assert result.error_kind == "timeout"


def _failed_fetch(kind: str) -> FetchResult:
    return FetchResult(
        url="https://no-such-host.invalid/",
        final_url="https://no-such-host.invalid/",
        ok=False,
        status_code=None,
        html="",
        soup=None,
        n_redirects=0,
        error="ConnectionError: failed",
        error_kind=kind,
    )


def _infra(dns_ok: bool, tls_inspected: bool):
    dead, dead_w = unavailable_features()
    values = {
        "SSLfinal_State": -1,
        "Domain_registeration_length": 0,
        "port": 1,
        "Abnormal_URL": 0,
        "age_of_domain": 0,
        "DNSRecord": 1 if dns_ok else -1,
    }
    values.update(dead)
    warnings = [
        FeatureWarning("SSLfinal_State", "TLS handshake failed: test", -1),
        FeatureWarning("DNSRecord", "DNS lookup failed: test", -1),
    ]
    if dns_ok:
        warnings = warnings[:1]
    return values, warnings + dead_w, dns_ok, tls_inspected


def test_extractor_unreachable_when_dns_and_fetch_fail(monkeypatch):
    monkeypatch.setattr(
        "phishing.features.extractor.fetch_page", lambda *a, **k: _failed_fetch("dns")
    )
    monkeypatch.setattr(
        "phishing.features.extractor.extract_infra_features",
        lambda url: _infra(dns_ok=False, tls_inspected=False),
    )
    series, _warnings, probe = url_to_features(
        "https://no-such-host.invalid/", tier="full"
    )
    assert list(series.index) == FEATURE_COLUMNS
    assert probe.status == "unreachable"
    assert probe.dns_ok is False
    assert probe.page_fetched is False
    assert probe.tls_inspected is False


def test_extractor_fetch_failed_when_dns_works(monkeypatch):
    monkeypatch.setattr(
        "phishing.features.extractor.fetch_page",
        lambda *a, **k: _failed_fetch("timeout"),
    )
    monkeypatch.setattr(
        "phishing.features.extractor.extract_infra_features",
        lambda url: _infra(dns_ok=True, tls_inspected=False),
    )
    _series, _warnings, probe = url_to_features("https://example.com/", tier="full")
    assert probe.status == "fetch_failed"
    assert probe.dns_ok is True
