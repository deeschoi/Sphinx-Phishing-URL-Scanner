"""Tier B: HTML/JavaScript features from fetched markup. JS is never executed."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from phishing.config import LEGITIMATE, PHISHING, SUSPICIOUS
from phishing.features.fetch import FetchResult
from phishing.features.public_suffix import extract as suffix_extract

_MAILTO = re.compile(r"mailto:", re.I)
_MAIL_FN = re.compile(r"\bmail\s*\(", re.I)
_STATUS_BAR = re.compile(r"onmouseover\s*=", re.I)
_WINDOW_STATUS = re.compile(r"window\.status|status\s*=", re.I)
_RIGHT_CLICK = re.compile(r"event\.button\s*==\s*2|oncontextmenu|button\s*==\s*2", re.I)
_POPUP = re.compile(r"window\.open\s*\(", re.I)
_EMPTY_ANCHOR = re.compile(r"^(#|javascript:|)$", re.I)


def _registered(url: str) -> str:
    ext = suffix_extract(url)
    if not ext.domain:
        return ""
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()


def _is_external(src: str, page_url: str) -> bool:
    if not src or src.startswith("data:"):
        return False
    absolute = urljoin(page_url, src)
    return _registered(absolute) != _registered(page_url) and bool(_registered(absolute))


def _ratio_to_code(ratio: float, low: float, high: float) -> int:
    pct = ratio * 100
    if pct < low:
        return LEGITIMATE
    if pct <= high:
        return SUSPICIOUS
    return PHISHING


def request_url(soup: BeautifulSoup, page_url: str) -> int:
    tags = soup.find_all(["img", "audio", "embed", "video", "source"])
    if not tags:
        return LEGITIMATE
    external = 0
    total = 0
    for tag in tags:
        src = tag.get("src") or tag.get("data-src")
        if not src:
            continue
        total += 1
        if _is_external(src, page_url):
            external += 1
    if total == 0:
        return LEGITIMATE
    # CSV is binary for this column; collapse the paper's middle bin into phishing.
    return LEGITIMATE if (external / total) * 100 < 22 else PHISHING


def url_of_anchor(soup: BeautifulSoup, page_url: str) -> int:
    anchors = soup.find_all("a")
    if not anchors:
        return LEGITIMATE
    bad = 0
    for a in anchors:
        href = (a.get("href") or "").strip()
        if _EMPTY_ANCHOR.match(href) or _is_external(href, page_url):
            bad += 1
    return _ratio_to_code(bad / len(anchors), 31, 67)


def links_in_tags(soup: BeautifulSoup, page_url: str) -> int:
    tags = soup.find_all(["meta", "script", "link"])
    if not tags:
        return LEGITIMATE
    external = 0
    total = 0
    for tag in tags:
        src = tag.get("href") or tag.get("src") or tag.get("content")
        if not src or not isinstance(src, str):
            continue
        if not src.startswith(("http://", "https://", "//", "/")):
            continue
        total += 1
        if _is_external(src, page_url):
            external += 1
    if total == 0:
        return LEGITIMATE
    return _ratio_to_code(external / total, 17, 81)


def sfh(soup: BeautifulSoup, page_url: str) -> int:
    forms = soup.find_all("form")
    if not forms:
        return LEGITIMATE
    worst = LEGITIMATE
    for form in forms:
        action = (form.get("action") or "").strip()
        if action == "" or action.lower() == "about:blank":
            return PHISHING
        if _is_external(action, page_url):
            worst = SUSPICIOUS
    return worst


def submitting_to_email(html: str, soup: BeautifulSoup) -> int:
    if _MAILTO.search(html) or _MAIL_FN.search(html):
        return PHISHING
    for form in soup.find_all("form"):
        action = (form.get("action") or "")
        if _MAILTO.search(action):
            return PHISHING
    return LEGITIMATE


def favicon(soup: BeautifulSoup, page_url: str) -> int:
    icons = soup.find_all("link", rel=lambda v: v and "icon" in str(v).lower())
    for icon in icons:
        href = icon.get("href") or ""
        if href and _is_external(href, page_url):
            return PHISHING
    return LEGITIMATE


def redirect_feature(n_redirects: int) -> int:
    """Match the CSV's {0, 1} encoding, not the paper's three-valued rule.

    0 = at most one hop (typical legitimate), 1 = two or more hops.
    """
    return 0 if n_redirects <= 1 else 1


def on_mouseover(html: str) -> int:
    if _STATUS_BAR.search(html) and _WINDOW_STATUS.search(html):
        return PHISHING
    if re.search(r"onmouseover\s*=\s*[\"'].*status", html, re.I):
        return PHISHING
    return LEGITIMATE


def right_click(html: str) -> int:
    return PHISHING if _RIGHT_CLICK.search(html) else LEGITIMATE


def popup_window(html: str, soup: BeautifulSoup) -> int:
    if not _POPUP.search(html):
        return LEGITIMATE
    if soup.find("input") or re.search(r"prompt\s*\(", html, re.I):
        return PHISHING
    return LEGITIMATE


def iframe(soup: BeautifulSoup) -> int:
    return PHISHING if soup.find("iframe") else LEGITIMATE


def extract_content_features(fetch: FetchResult, page_url: str) -> dict[str, int]:
    soup = fetch.soup or BeautifulSoup("", "lxml")
    html = fetch.html or ""
    return {
        "Favicon": favicon(soup, page_url),
        "Request_URL": request_url(soup, page_url),
        "URL_of_Anchor": url_of_anchor(soup, page_url),
        "Links_in_tags": links_in_tags(soup, page_url),
        "SFH": sfh(soup, page_url),
        "Submitting_to_email": submitting_to_email(html, soup),
        "Redirect": redirect_feature(fetch.n_redirects),
        "on_mouseover": on_mouseover(html),
        "RightClick": right_click(html),
        "popUpWidnow": popup_window(html, soup),
        "Iframe": iframe(soup),
    }
