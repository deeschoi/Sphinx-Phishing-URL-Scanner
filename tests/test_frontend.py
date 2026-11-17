"""Serving the built React UI from FastAPI.

The frontend routes are registered when ``api.main`` is imported, so each
test reloads the module against its own ``SPHINX_DIST_DIR`` and restores the
real one afterwards.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

BROWSER = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}


@pytest.fixture
def app_with_dist(monkeypatch):
    import api.main as api_main

    def build(dist):
        monkeypatch.setenv("SPHINX_DIST_DIR", str(dist))
        return importlib.reload(api_main).app

    yield build
    monkeypatch.delenv("SPHINX_DIST_DIR", raising=False)
    importlib.reload(api_main)


@pytest.fixture
def dist(tmp_path):
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><title>Sphinx</title>")
    (root / "favicon.ico").write_bytes(b"ico")
    (root / "assets" / "index-abc123.js").write_text("console.log(1)")
    return root


def test_index_without_build(app_with_dist, tmp_path):
    app = app_with_dist(tmp_path / "missing")
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 503
        assert "Frontend not built" in response.text
        assert client.get("/api/health").json() == {"status": "ok"}


def test_index_and_client_routes_from_dist(app_with_dist, dist):
    with TestClient(app_with_dist(dist)) as client:
        home = client.get("/", headers=BROWSER)
        assert home.status_code == 200
        assert "Sphinx" in home.text

        # Client-side route: a browser navigation falls back to index.html.
        history = client.get("/history", headers=BROWSER)
        assert history.status_code == 200
        assert "Sphinx" in history.text

        assert client.get("/favicon.ico").status_code == 200

        listed = client.get("/api/health")
        assert listed.status_code == 200
        assert listed.json() == {"status": "ok"}


def test_assets_are_javascript_and_immutable(app_with_dist, dist):
    with TestClient(app_with_dist(dist)) as client:
        asset = client.get("/assets/index-abc123.js")
        assert asset.status_code == 200
        assert "javascript" in asset.headers["content-type"]
        assert "immutable" in asset.headers["cache-control"]

        # A missing bundle must 404, not come back as index.html: the browser
        # refuses an HTML module script and renders a blank page.
        missing = client.get("/assets/nope.js")
        assert missing.status_code == 404
        assert "text/html" not in missing.headers.get("content-type", "")


def test_spa_does_not_swallow_missing_api_routes(app_with_dist, dist):
    with TestClient(app_with_dist(dist)) as client:
        for headers in ({}, BROWSER):
            response = client.get("/api/does-not-exist", headers=headers)
            assert response.status_code == 404
            assert response.headers["content-type"].startswith("application/json")
        posted = client.post("/api/does-not-exist", json={})
        assert posted.status_code == 404


def test_docs_paths_are_not_the_spa_when_disabled(app_with_dist, dist, monkeypatch):
    monkeypatch.delenv("SPHINX_ENABLE_DOCS", raising=False)
    with TestClient(app_with_dist(dist)) as client:
        for path in ("/openapi.json", "/docs", "/redoc"):
            response = client.get(path, headers=BROWSER)
            assert response.status_code == 404, path
            assert "text/html" not in response.headers["content-type"], path


def test_read_only_api_answers_are_edge_cacheable(app_with_dist, dist):
    with TestClient(app_with_dist(dist)) as client:
        for path in ("/api/findings", "/api/agent"):
            response = client.get(path)
            assert response.status_code == 200, path
            assert "s-maxage=" in response.headers["cache-control"], path
        assert "s-maxage" not in client.get("/api/health").headers.get("cache-control", "")
