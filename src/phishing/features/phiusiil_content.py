"""PhiUSIIL HTML features from fetched markup. JavaScript is never executed.

These columns are the living stand-in for the retired Alexa / PageRank /
inbound-link features: a real site has social links, a copyright line, scripts,
and a title that matches its domain. A phishing kit is usually a thin shell.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from phishing.features.fetch import FetchResult
from phishing.features.public_suffix import extract as suffix_extract

_POPUP = re.compile(r"window\.open\s*\(", re.I)
_EMPTY_HREF = re.compile(r"^(#|javascript:|)$", re.I)
_COPYRIGHT = re.compile(r"copyright|&copy;|©", re.I)

SOCIAL_HOSTS = {
    "facebook.com",
    "fb.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "linkedin.com",
    "youtube.com",
    "youtu.be",
    "pinterest.com",
    "tiktok.com",
    "reddit.com",
    "whatsapp.com",
    "t.me",
    "telegram.me",
}

BANK_WORDS = re.compile(
    r"\b(bank|banking|creditunion|credit-union|iban|swift|account number)\b", re.I
)
PAY_WORDS = re.compile(
    r"\b(pay|payment|paypal|stripe|checkout|billing|invoice|purchase)\b", re.I
)
CRYPTO_WORDS = re.compile(
    r"\b(bitcoin|btc|ethereum|crypto|wallet|blockchain|metamask|nft)\b", re.I
)


def _registered(url: str) -> str:
    ext = suffix_extract(url)
    if not ext.domain:
        return ""
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower().rstrip(".")


def _is_social_host(host: str) -> bool:
    """Whole-label host match, so ``notx.com`` and ``x.com.evil.io`` do not count."""
    host = (host or "").lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in SOCIAL_HOSTS)


def _is_external(href: str, page_url: str) -> bool:
    if not href or href.startswith("data:"):
        return False
    absolute = urljoin(page_url, href)
    dest = _registered(absolute)
    src = _registered(page_url)
    return bool(dest) and dest != src


def _title_text(soup: BeautifulSoup) -> str:
    tag = soup.find("title")
    return tag.get_text(" ", strip=True) if tag else ""


def _domain_core(page_url: str) -> str:
    """The registrable label — ``bbc`` for ``bbc.co.uk``, not ``co``.

    Splitting on the last two labels treats every multi-label public suffix as
    the brand: ``bbc.co.uk`` returned ``co``, and a two-character needle matches
    almost any title, so DomainTitleMatchScore came back a false 100%.
    The offline public-suffix snapshot knows multi-label suffixes, so the
    label it reports is the one a person would call the domain name.
    """
    ext = suffix_extract(page_url)
    if ext.domain:
        return ext.domain.lower()
    host = _host(page_url)
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in host.split(".") if p]
    return parts[0] if parts else ""


def _match_score(needle: str, haystack: str) -> float:
    """Percent of ``needle`` characters that appear, in order, in ``haystack``."""
    n = re.sub(r"[^a-z0-9]", "", needle.lower())
    h = re.sub(r"[^a-z0-9]", "", haystack.lower())
    if not n:
        return 0.0
    i = 0
    for ch in h:
        if i < len(n) and ch == n[i]:
            i += 1
    return 100.0 * i / len(n)


def extract_phiusiil_content_features(fetch: FetchResult, page_url: str) -> dict[str, float]:
    soup = fetch.soup or BeautifulSoup("", "lxml")
    html = fetch.html or ""
    title = _title_text(soup)
    core = _domain_core(page_url)
    host = _host(page_url)

    # PhiUSIIL crawled pretty-printed HTML. Live pages are often one minified
    # line; counting tags keeps LineOfCode in the same ballpark as "how much
    # markup is here" instead of collapsing to 1.
    n_lines = len(html.splitlines()) if html else 0
    n_tags = html.count("<")
    line_of_code = max(n_lines, n_tags, 1 if html else 0)
    lines = html.splitlines() or [html]
    images = soup.find_all("img")
    css = []
    for t in soup.find_all("link"):
        rel = t.get("rel") or []
        rel_s = " ".join(rel) if isinstance(rel, list) else str(rel)
        if "stylesheet" in rel_s.lower():
            css.append(t)
    scripts = soup.find_all("script")
    anchors = soup.find_all("a")

    n_self = n_empty = n_ext = 0
    social = False
    href_tags = list(anchors) + soup.find_all("area")
    for tag in href_tags:
        href = (tag.get("href") or "").strip()
        if _EMPTY_HREF.match(href):
            n_empty += 1
            continue
        absolute = urljoin(page_url, href)
        dest_host = _host(absolute)
        dest_reg = _registered(absolute)
        if _is_social_host(dest_host) or dest_reg in SOCIAL_HOSTS:
            social = True
        if _is_external(href, page_url):
            n_ext += 1
        else:
            n_self += 1
    if not social:
        # Substring-matching the whole document was the old fallback and it
        # fired on any CDN path containing "x.com" or "t.me". Only real link
        # and script targets count, matched on the host, not on the text.
        for tag in soup.find_all(["script", "iframe", "link"]):
            candidate = (tag.get("src") or tag.get("href") or "").strip()
            if not candidate:
                continue
            if _is_social_host(_host(urljoin(page_url, candidate))):
                social = True
                break

    forms = soup.find_all("form")
    external_submit = 0
    for form in forms:
        action = (form.get("action") or "").strip()
        if action and _is_external(action, page_url):
            external_submit = 1
            break

    # The URL used to be part of the keyword haystack, which set Pay=1 for any
    # host called pay.* or any /checkout path — including paypal.com itself.
    # These columns describe what the *page* is about, so only markup is read.
    haystack = html
    favicon = soup.find("link", rel=lambda v: v and "icon" in str(v).lower())
    robots = soup.find("meta", attrs={"name": re.compile(r"robots", re.I)})
    viewport = soup.find("meta", attrs={"name": re.compile(r"viewport", re.I)})
    description = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
    password = soup.find("input", attrs={"type": re.compile(r"password", re.I)})
    submit = soup.find("button", attrs={"type": re.compile(r"submit", re.I)}) or soup.find(
        "input", attrs={"type": re.compile(r"submit", re.I)}
    )
    hidden = soup.find("input", attrs={"type": re.compile(r"hidden", re.I)})

    self_redirects = 0
    page_reg = _registered(page_url)
    for hop in fetch.history_urls or []:
        if _registered(hop) == page_reg:
            self_redirects += 1

    return {
        "LineOfCode": float(line_of_code),
        "LargestLineLength": float(max((len(line) for line in lines), default=0)),
        "HasTitle": float(1 if title else 0),
        "DomainTitleMatchScore": float(_match_score(core, title) if title else 0.0),
        "URLTitleMatchScore": float(_match_score(host, title) if title else 0.0),
        "HasFavicon": float(1 if favicon else 0),
        "Robots": float(1 if robots else 0),
        "IsResponsive": float(1 if viewport else 0),
        "NoOfURLRedirect": float(fetch.n_redirects),
        "NoOfSelfRedirect": float(self_redirects),
        "HasDescription": float(1 if description and description.get("content") else 0),
        "NoOfPopup": float(len(_POPUP.findall(html))),
        "NoOfiFrame": float(len(soup.find_all("iframe"))),
        "HasExternalFormSubmit": float(external_submit),
        "HasSocialNet": float(1 if social else 0),
        "HasSubmitButton": float(1 if submit else 0),
        "HasHiddenFields": float(1 if hidden else 0),
        "HasPasswordField": float(1 if password else 0),
        "Bank": float(1 if BANK_WORDS.search(haystack) else 0),
        "Pay": float(1 if PAY_WORDS.search(haystack) else 0),
        "Crypto": float(1 if CRYPTO_WORDS.search(haystack) else 0),
        "HasCopyrightInfo": float(1 if _COPYRIGHT.search(html) else 0),
        "NoOfImage": float(len(images)),
        "NoOfCSS": float(len(css)),
        "NoOfJS": float(len(scripts)),
        "NoOfSelfRef": float(n_self),
        "NoOfEmptyRef": float(n_empty),
        "NoOfExternalRef": float(n_ext),
    }
