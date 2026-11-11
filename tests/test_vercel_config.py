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
    # The function serves the UI itself: CLI 65 routes the SPA rewrite to the
    # app, so a function without web/dist answers "/" with its 503 page.
    assert "web/dist/**" in config["functions"]["app.py"]["includeFiles"]
    assert "web/dist/**" not in config["functions"]["app.py"]["excludeFiles"]
    assert config["crons"][0]["path"] == "/api/internal/maintenance"
    assert config["crons"][0]["schedule"] == "0 8 * * *"
    # No SPA rewrite. CLI 65 hands a backend project's rewrite to the app as
    # the destination path, so "/assets/index-*.js" reached FastAPI as
    # "/index.html", the browser got HTML for its module script, and the UI
    # rendered blank. Unmatched paths already reach the app, whose catch-all
    # serves web/dist files and falls back to index.html.
    for rule in config.get("rewrites", []):
        assert "index.html" not in rule.get("destination", ""), rule


def test_vercel_entrypoint_is_the_root_app():
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'entrypoint = "app:app"' in project
    import app

    assert app.app.title


def test_function_installs_from_uv_lock_not_a_custom_command():
    """A custom Install Command fills a local venv that large functions never
    ship: the deploy built, uploaded 3.8 MB, and crashed on import."""
    import tomllib

    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    assert "installCommand" not in config

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = project["tool"]["setuptools"]["dynamic"]["dependencies"]["file"]
    assert deps == ["requirements-serve.txt"]


def test_bundle_check_accepts_the_committed_lock():
    """uv.lock must install the project and the serve stack, never NCCL."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_function_bundle", ROOT / "scripts" / "check_function_bundle.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.lock_errors() == []
    assert module.install_command_errors() == []


def test_bundle_check_requires_the_frontend_in_the_function():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_function_bundle", ROOT / "scripts" / "check_function_bundle.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors = module.frontend_errors()
    # web/dist exists only after a frontend build; the config half must pass.
    assert not any("vercel.json" in error for error in errors)
