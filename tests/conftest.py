"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from phishing.data import load_raw, load_xy


@pytest.fixture(scope="session")
def raw_df():
    return load_raw()


@pytest.fixture(scope="session")
def xy():
    return load_xy()


def make_client(app, *, host: str = "127.0.0.1", port: int = 12345) -> TestClient:
    """TestClient whose ASGI peer is a real IP.

    Starlette 0.41 hardcodes ``client`` to the hostname ``testclient``, which
    is not a parseable address. The anonymous-access guard fails closed on
    that, so every guarded route would 401. Wrap the app and stamp a loopback
    (or caller-chosen) peer onto each HTTP scope.
    """

    async def with_peer(scope, receive, send):
        if scope.get("type") in {"http", "websocket"}:
            scope = {**scope, "client": (host, port)}
        await app(scope, receive, send)

    return TestClient(with_peer)
