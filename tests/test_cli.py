"""CLI scan output: human by default, JSON behind --json."""

from __future__ import annotations

from phishing.cli import render_scan


def test_render_scan_shows_verdict_signals_and_coverage():
    text = render_scan(
        {
            "verdict": "phishing",
            "probability": 0.991,
            "model": "XGBoost (URL disagreement)",
            "rationale": "This looks like phishing.",
            "signals": [
                {
                    "label": "Off-domain links",
                    "contribution": 2.1,
                }
            ],
            "notes": ["Platform HTML looks rich by construction."],
            "coverage": {
                "reachability": "resolved",
                "page_fetched": True,
                "redirects": 1,
                "redirect_hops": [
                    {"url": "https://bit.ly/abc", "host": "bit.ly", "shortener": True}
                ],
            },
            "host_unicode": "пример.рф",
        }
    )
    assert "phishing  p=0.991" in text
    assert "Top signals" in text
    assert "Off-domain links" in text
    assert "Platform HTML" in text
    assert "bit.ly/abc (shortener)" in text
    assert "unicode host: пример.рф" in text


def test_cmd_scan_json_flag(monkeypatch, capsys):
    from phishing import cli

    payload = {"verdict": "legitimate", "probability": 0.02, "signals": [], "notes": []}
    monkeypatch.setattr("phishing.scanner.scan", lambda url, tier="full": payload)

    class Args:
        url = "https://example.com"
        tier = "full"
        json = True

    assert cli.cmd_scan(Args()) == 0
    out = capsys.readouterr().out
    assert '"verdict": "legitimate"' in out


def test_cmd_scan_human_default(monkeypatch, capsys):
    from phishing import cli

    payload = {
        "verdict": "legitimate",
        "probability": 0.02,
        "model": "XGBoost",
        "rationale": "Looks fine.",
        "signals": [],
        "notes": [],
        "coverage": {"reachability": "resolved", "page_fetched": True, "redirects": 0},
    }
    monkeypatch.setattr("phishing.scanner.scan", lambda url, tier="full": payload)

    class Args:
        url = "https://example.com"
        tier = "full"
        json = False

    assert cli.cmd_scan(Args()) == 0
    out = capsys.readouterr().out
    assert "legitimate  p=0.020" in out
    assert '"verdict"' not in out
