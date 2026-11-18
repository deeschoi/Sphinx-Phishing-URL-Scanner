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
    # The CDN serves the UI (app.frontend promotion). web/dist stays in the
    # function too, so a missed promotion degrades to slow, not blank.
    assert "web/dist/**" in config["functions"]["app.py"]["includeFiles"]
    assert "web/dist/**" not in config["functions"]["app.py"]["excludeFiles"]
    assert config["crons"][0]["path"] == "/api/internal/maintenance"
    assert config["crons"][0]["schedule"] == "0 8 * * *"
    # No SPA rewrite. CLI 65 hands a backend project's rewrite to the app as
    # the destination path, so "/assets/index-*.js" reached FastAPI as
    # "/index.html", the browser got HTML for its module script, and the UI
    # rendered blank. app.frontend() handles client routes instead.
    for rule in config.get("rewrites", []):
        assert "index.html" not in rule.get("destination", ""), rule
    # public/ was a copy of web/dist that Vercel never served for this preset.
    assert "public" not in config["buildCommand"]


def _header_rules(config: dict) -> dict[str, dict[str, str]]:
    return {
        rule["source"]: {item["key"]: item["value"] for item in rule["headers"]}
        for rule in config["headers"]
    }


def test_hashed_assets_are_immutable_and_findings_are_cacheable():
    import re

    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    rules = _header_rules(config)
    for source in ("/assets/(.*)", "/fonts/(.*)"):
        assert "immutable" in rules[source]["Cache-Control"], source
    no_store = [s for s, h in rules.items() if h.get("Cache-Control") == "no-store"]
    assert len(no_store) == 1
    # Vercel matches the source against the whole path.
    pattern = re.compile("^" + no_store[0] + "$")
    for path in ("/api/scan", "/api/scan/jobs/x", "/api/chat", "/api/scans", "/api/warm"):
        assert pattern.match(path), path
    for path in ("/api/findings", "/api/agent"):
        assert not pattern.match(path), path


def test_ui_is_promoted_to_the_cdn():
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["vercel"]["fastapi"]["static"]["cdn"] is True
    source = (ROOT / "api" / "main.py").read_text(encoding="utf-8")
    assert "app.frontend(" in source
    # The builder skips promotion entirely unless this is set at build time.
    build = (ROOT / "scripts" / "vercel_build.sh").read_text(encoding="utf-8")
    assert "export VERCEL_FASTAPI_STATIC_CDN=1" in build
    assert "StaticFiles" not in source


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


def test_the_page_loads_nothing_the_csp_blocks():
    """The CSP allows 'self' only, so a Google Fonts link silently never loads.

    Fonts are self-hosted from web/public/fonts and served immutable, so a
    changed file needs a new name (the upstream version is in it).
    """
    import re

    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "web" / "src" / "styles.css").read_text(encoding="utf-8")
    external = re.findall(r'(?:href|src)="(https?://[^"]+)"', html)
    assert not external, f"index.html loads from another origin: {external}"
    assert "fonts.googleapis" not in css and "fonts.gstatic" not in css
    fonts = ROOT / "web" / "public" / "fonts"
    for name in re.findall(r'url\("/fonts/([^"]+)"\)', css):
        assert (fonts / name).is_file(), name
        assert re.search(r"-v\d+-", name), f"{name} has no version: it is cached immutable"
    for name in re.findall(r'href="/fonts/([^"]+)"', html):
        assert (fonts / name).is_file(), name
