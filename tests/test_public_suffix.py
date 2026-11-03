"""The suffix parser must not fetch or write a cache on import."""

from phishing.features.public_suffix import EXTRACTOR, extract


def test_multi_label_suffix_comes_from_the_bundled_snapshot():
    parsed = extract("https://www.bbc.co.uk/news")
    assert parsed.domain == "bbc"
    assert parsed.suffix == "co.uk"
    assert parsed.subdomain == "www"


def test_extractor_does_not_fetch_the_public_suffix_list():
    assert EXTRACTOR.suffix_list_urls == ()
    assert EXTRACTOR._cache.enabled is False
