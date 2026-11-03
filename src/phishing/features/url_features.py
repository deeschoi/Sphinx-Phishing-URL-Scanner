"""Tier A: URL-string features. Pure parsing, no network."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from phishing.config import LEGITIMATE, PHISHING, SUSPICIOUS
from phishing.features.public_suffix import extract as suffix_extract

SHORTENERS = {
    "bit.ly",
    "goo.gl",
    "tinyurl.com",
    "ow.ly",
    "t.co",
    "bit.do",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "is.gd",
    "cli.gs",
    "yfrog.com",
    "migre.me",
    "ff.im",
    "url4.eu",
    "twit.ac",
    "su.pr",
    "twurl.nl",
    "snipurl.com",
    "short.to",
    "budurl.com",
    "ping.fm",
    "post.ly",
    "just.as",
    "bkite.com",
    "snipr.com",
    "fic.kr",
    "loopt.us",
    "doiop.com",
    "htxt.it",
    "alturl.com",
    "om.ly",
    "tr.im",
    "sn.im",
    "short.ie",
    "x.co",
    "tiny.pl",
    "rb.gy",
    "buff.ly",
    "adf.ly",
    "bc.ly",
    "bitly.com",
    "lnkd.in",
    "db.tt",
    "qr.ae",
    "cur.lv",
    "ity.im",
    "q.gs",
    "po.st",
    "bc.vc",
    "u.to",
    "j.mp",
    "buzurl.com",
    "cutt.us",
    "u.bb",
    "yourls.org",
    "prettylinkpro.com",
    "scrnch.me",
    "filoops.info",
    "vzturl.com",
    "qr.net",
    "1url.com",
    "tweez.me",
    "v.gd",
    "link.zip.net",
}

_HEX_IP = re.compile(
    r"^(?:0x[0-9a-f]+(?:\.0x[0-9a-f]+){3})$",
    re.IGNORECASE,
)
_DECIMAL_IP = re.compile(r"^\d{8,10}$")


def _hostname(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


def having_ip_address(url: str) -> int:
    host = _hostname(url)
    if not host:
        return PHISHING
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return PHISHING
    except ValueError:
        pass
    if _HEX_IP.match(candidate) or _DECIMAL_IP.match(candidate):
        return PHISHING
    return LEGITIMATE


def url_length(url: str) -> int:
    n = len(url)
    if n < 54:
        return LEGITIMATE
    if n <= 75:
        return SUSPICIOUS
    return PHISHING


def shortening_service(url: str) -> int:
    host = _hostname(url)
    if host in SHORTENERS or any(host.endswith("." + s) for s in SHORTENERS):
        return PHISHING
    return LEGITIMATE


def having_at_symbol(url: str) -> int:
    return PHISHING if "@" in url else LEGITIMATE


def double_slash_redirecting(url: str) -> int:
    """Last '//' past the scheme separator is a phishing indicator.

    The paper uses 1-based positions: the scheme '//' of http:// sits at
    position 6, https:// at 7. Anything later is a redirect in the path.
    """
    pos = url.rfind("//")
    if pos < 0:
        return LEGITIMATE
    return PHISHING if (pos + 1) > 7 else LEGITIMATE


def prefix_suffix(url: str) -> int:
    ext = suffix_extract(url)
    domain = ext.domain or ""
    return PHISHING if "-" in domain else LEGITIMATE


def having_sub_domain(url: str) -> int:
    """Dots remaining after stripping www and the registered suffix.

    0 extra labels → legitimate, 1 → suspicious, 2+ → phishing.
    """
    ext = suffix_extract(url)
    sub = ext.subdomain.lower()
    labels = [p for p in sub.split(".") if p and p != "www"]
    if len(labels) == 0:
        return LEGITIMATE
    if len(labels) == 1:
        return SUSPICIOUS
    return PHISHING


def https_token(url: str) -> int:
    ext = suffix_extract(url)
    host_labels = ".".join(
        p for p in (ext.subdomain, ext.domain) if p
    ).lower()
    return PHISHING if "https" in host_labels else LEGITIMATE


def extract_url_features(url: str) -> dict[str, int]:
    return {
        "having_IP_Address": having_ip_address(url),
        "URL_Length": url_length(url),
        "Shortining_Service": shortening_service(url),
        "having_At_Symbol": having_at_symbol(url),
        "double_slash_redirecting": double_slash_redirecting(url),
        "Prefix_Suffix": prefix_suffix(url),
        "having_Sub_Domain": having_sub_domain(url),
        "HTTPS_token": https_token(url),
    }
