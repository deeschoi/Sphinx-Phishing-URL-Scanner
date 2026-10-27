"""Tier C: TLS / WHOIS / DNS / port. Failures return a neutral value plus a warning."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

import tldextract

from phishing.config import LEGITIMATE, PHISHING, SUSPICIOUS, UNAVAILABLE_2026
from phishing.schema import FeatureWarning

# Original 2012 paper list plus CAs that actually issue certificates in 2026.
TRUSTED_ISSUERS = (
    "geotrust",
    "godaddy",
    "network solutions",
    "thawte",
    "comodo",
    "doster",
    "verisign",
    "let's encrypt",
    "lets encrypt",
    "digicert",
    "sectigo",
    "globalsign",
    "amazon",
    "google trust",
    "gts ",
    "microsoft",
    "entrust",
    "usertrust",
    "starfield",
    "rapidssl",
    "ssl.com",
    "cisc",
    "apple",
    "cloudflare",
)

PREFERRED_CLOSED_PORTS = {21, 22, 23, 445, 1433, 1521, 3306, 3389}
PREFERRED_OPEN_PORTS = {80, 443}
# The legacy TLS probe opens its own socket, outside the guarded HTTP adapter.
# Keep it on the ports a certificate check is actually for.
_TLS_PORTS = frozenset({443, 8443})


def _host_port(url: str) -> tuple[str, int | None, str]:
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
    port = parsed.port
    scheme = (parsed.scheme or "http").lower()
    return host, port, scheme


def _registered(url: str) -> str:
    ext = tldextract.extract(url)
    if not ext.domain:
        return ""
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()


def ssl_final_state(url: str, warnings: list[FeatureWarning]) -> tuple[int, bool]:
    """Return ``(encoding, inspected)``. ``inspected`` is True only after a handshake."""

    host, port, scheme = _host_port(url)
    if scheme != "https":
        return PHISHING, False
    port = port or 443
    if port not in _TLS_PORTS:
        warnings.append(
            FeatureWarning(
                "SSLfinal_State",
                f"refusing TLS probe to port {port}",
                PHISHING,
            )
        )
        return PHISHING, False
    from phishing.netguard import UnsafeTargetError, _assert_public_peer, assert_public_url

    literal_host = f"[{host}]" if ":" in host else host
    try:
        assert_public_url(f"https://{literal_host}:{port}/")
    except UnsafeTargetError as exc:
        warnings.append(FeatureWarning("SSLfinal_State", str(exc), PHISHING))
        return PHISHING, False
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            _assert_public_peer(sock)
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except UnsafeTargetError as exc:
        warnings.append(FeatureWarning("SSLfinal_State", str(exc), PHISHING))
        return PHISHING, False
    except Exception as exc:  # noqa: BLE001
        warnings.append(
            FeatureWarning("SSLfinal_State", f"TLS handshake failed: {exc}", PHISHING)
        )
        return PHISHING, False
    if not cert:
        return PHISHING, True
    issuer_parts = []
    for rdn in cert.get("issuer", ()):
        for _key, value in rdn:
            issuer_parts.append(str(value))
    issuer = " ".join(issuer_parts).lower()
    trusted = any(token in issuer for token in TRUSTED_ISSUERS)
    not_before = cert.get("notBefore")
    age_ok = False
    if not_before:
        try:
            start = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=UTC
            )
            age_ok = (datetime.now(UTC) - start).days >= 365
        except ValueError:
            age_ok = False
    if trusted and age_ok:
        return LEGITIMATE, True
    if scheme == "https":
        return SUSPICIOUS, True
    return PHISHING, True


def _whois_record(url: str):
    import whois as whois_mod

    return whois_mod.whois(_registered(url))


def domain_registration_length(
    url: str, warnings: list[FeatureWarning], record=None
) -> int:
    if record is None:
        return 0
    try:
        exp = record.expiration_date
        if isinstance(exp, list):
            exp = exp[0] if exp else None
        if exp is None:
            warnings.append(
                FeatureWarning("Domain_registeration_length", "no expiration in WHOIS", PHISHING)
            )
            return PHISHING
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        remaining = (exp - datetime.now(UTC)).days
        return PHISHING if remaining <= 365 else LEGITIMATE
    except Exception as exc:  # noqa: BLE001
        warnings.append(
            FeatureWarning("Domain_registeration_length", f"WHOIS failed: {exc}", 0)
        )
        return 0


def age_of_domain(url: str, warnings: list[FeatureWarning], record=None) -> int:
    if record is None:
        return 0
    try:
        created = record.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if created is None:
            warnings.append(FeatureWarning("age_of_domain", "no creation date in WHOIS", PHISHING))
            return PHISHING
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        age_days = (datetime.now(UTC) - created).days
        return LEGITIMATE if age_days >= 180 else PHISHING
    except Exception as exc:  # noqa: BLE001
        warnings.append(FeatureWarning("age_of_domain", f"WHOIS failed: {exc}", 0))
        return 0


def dns_record(url: str, warnings: list[FeatureWarning]) -> int:
    host, _, _ = _host_port(url)
    if not host:
        return PHISHING
    try:
        import dns.resolver

        dns.resolver.resolve(host, "A")
        return LEGITIMATE
    except Exception:
        try:
            socket.getaddrinfo(host, None)
            return LEGITIMATE
        except Exception as exc:  # noqa: BLE001
            warnings.append(FeatureWarning("DNSRecord", f"DNS lookup failed: {exc}", PHISHING))
            return PHISHING


def abnormal_url(url: str, warnings: list[FeatureWarning], record=None) -> int:
    """Hostname should appear in the WHOIS record of a legitimate site."""
    host, _, _ = _host_port(url)
    domain = _registered(url)
    if record is None:
        return 0
    try:
        blob = str(record).lower()
        token = (domain or host).lower()
        if token and token in blob:
            return LEGITIMATE
        return PHISHING
    except Exception as exc:  # noqa: BLE001
        warnings.append(FeatureWarning("Abnormal_URL", f"WHOIS failed: {exc}", 0))
        return 0


def port_feature(url: str) -> int:
    _, port, scheme = _host_port(url)
    if port is None:
        return LEGITIMATE
    if port in PREFERRED_CLOSED_PORTS:
        return PHISHING
    if port in PREFERRED_OPEN_PORTS:
        return LEGITIMATE
    return PHISHING


def unavailable_features() -> tuple[dict[str, int], list[FeatureWarning]]:
    values = {name: 0 for name in UNAVAILABLE_2026}
    warnings = [
        FeatureWarning(
            name,
            "Original 2012 data source is retired or not queried (Alexa/PageRank/"
            "Google Index/backlink counts/2012 blocklists).",
            0,
        )
        for name in UNAVAILABLE_2026
    ]
    return values, warnings


def extract_infra_features(
    url: str,
) -> tuple[dict[str, int], list[FeatureWarning], bool, bool]:
    warnings: list[FeatureWarning] = []
    record = None
    try:
        record = _whois_record(url)
    except Exception as exc:  # noqa: BLE001
        warnings.append(FeatureWarning("WHOIS", f"WHOIS lookup failed: {exc}", 0))
    ssl_encoding, tls_inspected = ssl_final_state(url, warnings)
    dns_encoding = dns_record(url, warnings)
    values = {
        "SSLfinal_State": ssl_encoding,
        "Domain_registeration_length": domain_registration_length(
            url, warnings, record=record
        ),
        "port": port_feature(url),
        "Abnormal_URL": abnormal_url(url, warnings, record=record),
        "age_of_domain": age_of_domain(url, warnings, record=record),
        "DNSRecord": dns_encoding,
    }
    dead, dead_warnings = unavailable_features()
    values.update(dead)
    warnings.extend(dead_warnings)
    return values, warnings, dns_encoding == LEGITIMATE, tls_inspected
