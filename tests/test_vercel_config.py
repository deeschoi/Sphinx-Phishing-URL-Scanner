"""The CDN config has to match the headers the API sets itself."""

from __future__ import annotations

import json
from pathlib import Path

from api.main import _SECURITY_CSP

ROOT = Path(__file__).resolve().parent.parent


def test_cdn_policy_matches_the_api_and_deploys_only_from_ci():
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    headers = {
        item["key"]: item["value"] for item in config["headers"][0]["headers"]
    }
    assert headers["Content-Security-Policy"] == _SECURITY_CSP
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "camera=()" in headers["Permissions-Policy"]
    assert headers["Strict-Transport-Security"].startswith("max-age=")
    assert config["git"]["deploymentEnabled"] is False
    assert config["functions"]["app.py"]["maxDuration"] == 60
    assert "artifacts/**" in config["functions"]["app.py"]["includeFiles"]
    assert config["crons"][0]["path"] == "/api/internal/maintenance"
    assert config["crons"][0]["schedule"] == "0 8 * * *"
    sources = [rule["source"] for rule in config["rewrites"]]
    assert any("api" in source for source in sources)


def test_vercel_entrypoint_is_the_root_app():
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'entrypoint = "app:app"' in project
    import app

    assert app.app.title
