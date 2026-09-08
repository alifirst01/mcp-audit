"""Shared fixtures: a mock Authorization Server + MCP server (httpx.MockTransport,
no real network) and a fake "browser" that completes the loopback redirect
without launching anything.
"""
from __future__ import annotations

import threading
import urllib.parse
import urllib.request
from urllib.parse import parse_qsl, urlparse

import httpx
import pytest

AS_ISSUER = "https://as.example.test"
AS_METADATA = {
    "issuer": AS_ISSUER,
    "authorization_endpoint": f"{AS_ISSUER}/authorize",
    "token_endpoint": f"{AS_ISSUER}/token",
    "registration_endpoint": f"{AS_ISSUER}/register",
    "code_challenge_methods_supported": ["S256"],
}
MCP_URL = "https://mcp.example.test/mcp"

# The three secret values under test. Chosen distinctive so a false-positive
# substring match elsewhere in the fixtures is implausible.
ACCESS_TOKEN = "fixture-access-token-abc123"
REFRESH_TOKEN = "fixture-refresh-token-def456"
CLIENT_SECRET = "fixture-client-secret-ghi789"


def _token_response(access_token=ACCESS_TOKEN, refresh_token=REFRESH_TOKEN):
    return httpx.Response(200, json={
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read",
    })


class MockServer:
    """Mock AS + MCP server. `.requests` records every request seen, so a
    test can positively confirm a secret was actually sent over the wire —
    not just that it's absent from evidence, which would be vacuously true
    if the flow never ran."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = request.url
        if url.host == "as.example.test" and url.path == "/register" and request.method == "POST":
            return httpx.Response(201, json={
                "client_id": "fixture-client-id",
                "client_secret": CLIENT_SECRET,
            })
        if url.host == "as.example.test" and url.path == "/token" and request.method == "POST":
            params = dict(parse_qsl(request.content.decode()))
            if params.get("grant_type") == "refresh_token":
                return _token_response(
                    access_token=ACCESS_TOKEN + "-rotated",
                    refresh_token=REFRESH_TOKEN + "-rotated",
                )
            return _token_response()
        if url.host == "mcp.example.test" and url.path == "/mcp":
            auth = request.headers.get("authorization", "")
            if auth == f"Bearer {ACCESS_TOKEN}":
                return httpx.Response(200, json={
                    "jsonrpc": "2.0", "id": 1,
                    "result": {"tools": [{
                        "name": "read_thing",
                        "description": "Reads a thing.",
                        "inputSchema": {"type": "object", "properties": {}},
                    }]},
                })
            return httpx.Response(401, json={"error": "invalid_token"})
        return httpx.Response(404, json={"error": "not_found", "path": url.path})


@pytest.fixture
def mock_server() -> MockServer:
    return MockServer()


@pytest.fixture
def fake_browser(monkeypatch):
    """Patch oauth.webbrowser.open so authenticate()'s loopback flow
    completes without a real browser: parses the authorize URL for
    redirect_uri/state, then hits the (real, localhost-only) loopback
    listener with a fake authorization code in a background thread."""
    import mcp_audit.core.oauth as oauth_module

    def fake_open(authorize_url: str) -> bool:
        qs = dict(parse_qsl(urlparse(authorize_url).query))
        redirect_uri = qs["redirect_uri"]
        state = qs["state"]
        callback_url = (
            f"{redirect_uri}?code=fixture-auth-code"
            f"&state={urllib.parse.quote(state)}"
            f"&iss={urllib.parse.quote(AS_ISSUER, safe='')}"
        )

        def hit():
            urllib.request.urlopen(callback_url, timeout=5)

        threading.Thread(target=hit, daemon=True).start()
        return True

    monkeypatch.setattr(oauth_module.webbrowser, "open", fake_open)
