"""PhiUSIIL URL-string features. Pure parsing, no network.

IsHTTPS is the scheme bit. It is not the 2012 SSLfinal_State encoding
(trusted CA + certificate at least a year old).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlparse

from phishing.config import PHIUSIIL_PLATFORM_SUFFIXES

_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")


def _parsed(url: str):
    return urlparse(url if "://" in url else "http://" + url)


def _host(url: str) -> str:
    return (_parsed(url).hostname or "").lower().rstrip(".")


def is_domain_ip(url: str) -> int:
    host = _host(url).strip("[]")
    if not host:
        return 0
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def _tld(host: str) -> str:
    if not host or is_domain_ip("http://" + host):
        return ""
    return host.rsplit(".", 1)[-1]


def char_continuation_rate(host: str, tld: str) -> float:
    """Longest alphanumeric run in the hostname after stripping www and the TLD.

    Hyphens and extra dots lower the score; a single clean label is 1.0.
    """
    core = host
    if core.startswith("www."):
        core = core[4:]
    if tld and core.endswith("." + tld):
        core = core[: -(len(tld) + 1)]
    if not core:
        return 1.0
    runs = _ALNUM_RUN.findall(core)
    longest = max((len(run) for run in runs), default=0)
    return longest / len(core)


def platform_suffix(host: str) -> str:
    """Longest free-hosting suffix the hostname sits under, or "".

    Longest wins so a nested suffix cannot be shadowed by a shorter one.
    """
    host = (host or "").lower().rstrip(".")
    matches = [
        suffix
        for suffix in PHIUSIIL_PLATFORM_SUFFIXES
        if host == suffix or host.endswith("." + suffix)
    ]
    return max(matches, key=len) if matches else ""


def is_free_hosting_platform(url: str) -> int:
    """1 when the hostname is published under shared free hosting.

    A scanner routing hint, never a model feature — see the note on
    ``PHIUSIIL_PLATFORM_SUFFIXES``. Subdomain depth is deliberately *not*
    counted against these suffixes either; both were measured and rejected
    in scripts/07_live_sample_eval.py.
    """
    return 1 if platform_suffix(_host(url)) else 0


# Landing-file suffixes typical of phishing kits. Locale and app paths
# (/en-us, /python/cpython) do not match, which is the point: counting any
# path in the URL-only model re-leaked those into the phishing class.
_KIT_PATH_SUFFIXES = (".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".cgi")


def is_kit_shaped_path(url: str) -> bool:
    """True when the path looks like a phishing-kit landing file.

    A scanner routing hint, never a model feature. PhiUSIIL legitimate rows
    have no paths, so putting path length into the URL-only model made
    ``/en-us`` look like a kit. File suffixes are precise enough to flag
    ``/wetj/famt.html`` without touching homepages or locale paths.
    """
    path = (_parsed(url).path or "").rstrip("/")
    if not path:
        return False
    last = path.rsplit("/", 1)[-1].lower()
    return any(last.endswith(suffix) for suffix in _KIT_PATH_SUFFIXES)


def _url_for_char_counts(url: str, host: str) -> str:
    """Count letters / length / specials on the www-stripped origin.

    PhiUSIIL legitimate rows are homepage-shaped: every one has ``www.``, and
    none has a path or trailing slash. Counting those extras made
    ``https://github.com/`` and ``https://www.visa.com/en-us`` look like the
    phishing class (any slash/path is a leak). The origin keeps host signals
    (HTTPS, TLD, hyphens, IP) without that homepage-shape leak.
    """
    parsed = _parsed(url)
    scheme = (parsed.scheme or "http").lower()
    host_core = host[4:] if host.startswith("www.") else host
    if not host_core:
        host_core = host
    netloc = host_core
    if parsed.port:
        netloc = f"{host_core}:{parsed.port}"
    if host_core and ":" in host_core and not host_core.startswith("["):
        # IPv6 hostname from urlparse has no brackets.
        try:
            ipaddress.IPv6Address(host_core)
            netloc = f"[{host_core}]"
            if parsed.port:
                netloc = f"[{host_core}]:{parsed.port}"
        except ValueError:
            pass
    return f"{scheme}://{netloc}"


def extract_phiusiil_url_features(
    url: str, tld_prob: dict[str, float] | None = None
) -> dict[str, float]:
    parsed = _parsed(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    tld = _tld(host)
    # PhiUSIIL legitimate rows all include a leading "www.", so treating www as
    # a subdomain makes github.com / ramp.com look like the phishing class.
    labels = [p for p in host.split(".") if p and p != "www"]
    n_labels = len(labels)
    ip = is_domain_ip(url)

    host_core = host[4:] if host.startswith("www.") else host
    count_url = _url_for_char_counts(url, host)
    # Every character count reads the same origin string. Counting =?&% on the
    # full URL while length/letters/specials used the origin was the same
    # homepage-shape leak in a different column: no legitimate PhiUSIIL row has
    # a query, so a legitimate deep link like /search?q=1 still scored as a kit.
    encoded = _PERCENT.findall(count_url)
    n_obf = len(encoded)
    length = max(len(count_url), 1)
    letters = sum(c.isalpha() for c in count_url)
    digits = sum(c.isdigit() for c in count_url)
    n_eq = count_url.count("=")
    n_qm = count_url.count("?")
    n_amp = count_url.count("&")
    # Specials on the origin only. Path/query punctuation is a class leak:
    # no legitimate PhiUSIIL row has a path, so /en-us looked like a kit.
    other_special = sum(
        (not c.isalnum()) and c not in {":", "/", "=", "?", "&", "%"} for c in count_url
    )

    return {
        "URLLength": float(len(count_url)),
        "DomainLength": float(len(host_core)),
        "IsDomainIP": float(ip),
        "TLDLength": float(len(tld)),
        "NoOfSubDomain": float(max(0, n_labels - 2) if not ip else 0),
        "HasObfuscation": float(1 if n_obf else 0),
        "NoOfObfuscatedChar": float(n_obf),
        "ObfuscationRatio": float(n_obf / length),
        "NoOfLettersInURL": float(letters),
        "LetterRatioInURL": float(letters / length),
        "NoOfDegitsInURL": float(digits),
        "DegitRatioInURL": float(digits / length),
        "NoOfEqualsInURL": float(n_eq),
        "NoOfQMarkInURL": float(n_qm),
        "NoOfAmpersandInURL": float(n_amp),
        "NoOfOtherSpecialCharsInURL": float(other_special),
        "SpacialCharRatioInURL": float(other_special / length),
        "IsHTTPS": float(1 if parsed.scheme.lower() == "https" else 0),
        "CharContinuationRate": float(char_continuation_rate(host, tld)),
        "TLDLegitimateProb": float((tld_prob or {}).get(tld, 0.0)),
    }


def decode_obfuscation_hint(url: str) -> str:
    """Human-readable note when the URL uses percent-encoding."""
    if "%" not in url:
        return ""
    try:
        return unquote(url)
    except Exception:  # noqa: BLE001
        return ""
