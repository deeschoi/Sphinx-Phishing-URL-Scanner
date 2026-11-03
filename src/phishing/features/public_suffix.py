"""Offline public-suffix parsing.

tldextract's default extractor fetches the public suffix list and writes
``~/.cache`` on first use. The function filesystem is read-only, so every
call site uses the snapshot shipped inside the package.
"""

from __future__ import annotations

import tldextract
from tldextract.tldextract import ExtractResult

EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


def extract(url: str) -> ExtractResult:
    return EXTRACTOR(url)
