"""SSRF guards. The scanner fetches URLs a stranger typed, so these are load-bearing."""

from __future__ import annotations

import http.server
import ipaddress
import threading

import pytest

from phishing import netguard
from phishing.features.fetch import fetch_page
from phishing.netguard import (
    UnsafeTargetError,
    assert_public_url,
    is_unsafe_ip,
    strip_userinfo,
)

PRIVATE = [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",  # cloud metadata
    "169.254.170.2",  # ECS task metadata
    "100.64.0.1",  # CGNAT: is_private False *and* is_global False
    "100.100.100.200",  # Alibaba metadata
    "0.0.0.0",
    "224.0.0.1",  # multicast is is_global True on IPv4
    "240.0.0.1",  # reserved
    "::1",
    "fd00:ec2::254",  # AWS metadata over IPv6
    "fc00::1",  # unique local
    "::ffff:127.0.0.1",  # IPv4-mapped loopback
]

PUBLIC = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]


@pytest.mark.parametrize("address", PRIVATE)
def test_non_public_addresses_are_unsafe(address):
    assert is_unsafe_ip(ipaddress.ip_address(address)) is True


@pytest.mark.parametrize("address", PUBLIC)
def test_public_addresses_are_allowed(address):
    assert is_unsafe_ip(ipaddress.ip_address(address)) is False


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://[::1]/",
        "https://localhost/",
        "https://LOCALHOST./",
        "https://api.localhost/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.64.0.1/",
        "https://printer.local/",
        "https://db.internal/",
        "ftp://example.com/",
    ],
)
def test_assert_public_url_rejects_local_targets(url):
    with pytest.raises(UnsafeTargetError):
        assert_public_url(url)


def test_assert_public_url_allows_a_normal_site():
    assert_public_url("https://example.com/login")


def test_a_name_with_one_private_record_is_rejected(monkeypatch):
    """Which A record the connection uses is not ours to choose."""
    monkeypatch.setattr(
        netguard,
        "resolve_host",
        lambda host: [
            ipaddress.ip_address("93.184.216.34"),
            ipaddress.ip_address("127.0.0.1"),
        ],
    )
    with pytest.raises(UnsafeTargetError):
        assert_public_url("https://split-horizon.example/")


def test_unresolvable_name_is_not_an_ssrf_risk(monkeypatch):
    """NXDOMAIN fails at fetch time and is reported as unreachable, not as unsafe."""
    monkeypatch.setattr(netguard, "resolve_host", lambda host: [])
    assert_public_url("https://no-such-host.invalid/")


def test_strip_userinfo_removes_credentials():
    assert (
        strip_userinfo("https://alice:hunter2@bank.example/account?tab=1")
        == "https://bank.example/account?tab=1"
    )
    assert strip_userinfo("https://bank.example:8443/x") == "https://bank.example:8443/x"
    assert strip_userinfo("https://bob@bank.example/") == "https://bank.example/"


class _LocalServer:
    """A real HTTP server on loopback, so the guards are exercised end to end."""

    def __init__(self):
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler API
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{parent.port}/secret")
                    self.end_headers()
                    return
                if self.path == "/metadata":
                    self.send_response(302)
                    self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                    self.end_headers()
                    return
                body = b"<html><title>internal</title></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"


def test_fetch_page_refuses_loopback():
    with _LocalServer() as server:
        with pytest.raises(UnsafeTargetError):
            fetch_page(server.url("/secret"), timeout=4)


def test_fetch_page_refuses_a_redirect_into_private_space():
    """requests follows redirects without re-checking; this loop does not."""
    with _LocalServer() as server:
        for path in ("/redirect", "/metadata"):
            with pytest.raises(UnsafeTargetError):
                fetch_page(server.url(path), timeout=4)


def test_socket_guard_catches_a_rebind_after_the_url_check(monkeypatch):
    """Time-of-check/time-of-use: DNS can flip between the check and the connect.

    Neutering the URL check simulates a short-TTL name that answered with a
    public address a moment ago. The connection must still be dropped, because
    the guard validates the peer the socket actually reached.
    """
    monkeypatch.setattr("phishing.features.fetch.assert_public_url", lambda url: None)
    with _LocalServer() as server:
        with pytest.raises(UnsafeTargetError):
            fetch_page(server.url("/secret"), timeout=4)


def test_legacy_tls_probe_does_not_dial_loopback_or_odd_ports(monkeypatch):
    from phishing.config import PHISHING
    from phishing.features.infra_features import ssl_final_state

    def boom(*_args, **_kwargs):
        raise AssertionError("socket opened")

    monkeypatch.setattr(
        "phishing.features.infra_features.socket.create_connection", boom
    )
    warnings: list = []
    value, inspected = ssl_final_state("https://127.0.0.1/", warnings)
    assert value == PHISHING
    assert inspected is False

    warnings.clear()
    value, inspected = ssl_final_state("https://example.com:22/", warnings)
    assert value == PHISHING
    assert inspected is False
    assert any("port 22" in warning.message for warning in warnings)
