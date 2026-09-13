"""Minimal-scope OAuth requests (--scopes), requested/granted scope evidence,
and honest degradation of the tool-surface checks (TS-01/02/03) when
tools/list comes back empty or refused under a minimal grant.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlparse

import httpx
import pytest

from mcp_audit.core import oauth
from mcp_audit.core.models import Target, Transport
from mcp_audit.core.oauth import AuthInput, build_authorize_url
from mcp_audit.core.probe import AuthSession, ProbeContext

from conftest import AS_ISSUER, AS_METADATA, MCP_URL

AS_META_MIN = {"authorization_endpoint": "https://as.test/authorize", "issuer": "https://as.test"}


# --- build_authorize_url: no scope by default, exact scope when given ------

def test_build_authorize_url_omits_scope_by_default():
    url = build_authorize_url(AS_META_MIN, "cid", "http://127.0.0.1/cb", "st", "chal", "https://rs.test/mcp")
    assert "scope=" not in url


def test_build_authorize_url_sends_exact_scope_when_given():
    url = build_authorize_url(
        AS_META_MIN, "cid", "http://127.0.0.1/cb", "st", "chal", "https://rs.test/mcp",
        scope="read:user",
    )
    qs = dict(parse_qsl(urlparse(url).query))
    assert qs["scope"] == "read:user"


# --- end-to-end: authenticate() requests no scope unless --scopes ----------

def _capture_authorize_url(monkeypatch, mock_server):
    """Like the `fake_browser` fixture, but records the authorize URL it saw
    instead of discarding it."""
    import threading
    import urllib.parse
    import urllib.request

    captured = {}

    def fake_open(authorize_url: str) -> bool:
        captured["url"] = authorize_url
        qs = dict(parse_qsl(urlparse(authorize_url).query))
        callback_url = (
            f"{qs['redirect_uri']}?code=fixture-auth-code"
            f"&state={urllib.parse.quote(qs['state'])}"
            f"&iss={urllib.parse.quote(AS_ISSUER, safe='')}"
        )
        threading.Thread(target=lambda: urllib.request.urlopen(callback_url, timeout=5), daemon=True).start()
        return True

    monkeypatch.setattr(oauth.webbrowser, "open", fake_open)
    return captured


def _target() -> Target:
    t = Target(name="fixture", url=MCP_URL, transport=Transport.HTTP)
    t.context["as_metadata"] = dict(AS_METADATA)
    t.context["prm_doc"] = {"scopes_supported": ["read", "write", "admin"]}
    return t


def test_default_auth_input_requests_no_scope_end_to_end(mock_server, monkeypatch):
    captured = _capture_authorize_url(monkeypatch, mock_server)
    ctx = ProbeContext(transport=mock_server.transport)
    target = _target()

    oauth.authenticate(target, ctx, auth_input=AuthInput())

    assert ctx.auth_failure is None
    assert "scope=" not in captured["url"]
    assert ctx.auth_session.requested_scope is None
    ctx.close()


def test_scopes_flag_sends_exactly_that_value_end_to_end(mock_server, monkeypatch):
    captured = _capture_authorize_url(monkeypatch, mock_server)
    ctx = ProbeContext(transport=mock_server.transport)
    target = _target()

    oauth.authenticate(target, ctx, auth_input=AuthInput(scopes="read:user"))

    assert ctx.auth_failure is None
    qs = dict(parse_qsl(urlparse(captured["url"]).query))
    assert qs["scope"] == "read:user"
    assert ctx.auth_session.requested_scope == "read:user"
    ctx.close()


def test_scope_evidence_records_requested_vs_granted(mock_server, monkeypatch):
    from mcp_audit.checks.server._helpers import scope_evidence

    _capture_authorize_url(monkeypatch, mock_server)
    ctx = ProbeContext(transport=mock_server.transport)
    target = _target()

    oauth.authenticate(target, ctx, auth_input=AuthInput(scopes="read:user"))

    # MockServer's /token always grants "read" (conftest._token_response),
    # independent of what was requested — exactly the case worth recording.
    assert scope_evidence(ctx) == {"requested_scopes": ["read:user"], "granted_scopes": ["read"]}
    ctx.close()


def test_no_scopes_requested_means_empty_evidence_lists():
    ctx = ProbeContext()
    ctx.auth_session = AuthSession(access_token="AT", token_type="Bearer")
    from mcp_audit.checks.server._helpers import scope_evidence
    assert scope_evidence(ctx) == {"requested_scopes": [], "granted_scopes": []}
    ctx.close()


# --- TS-01/02/03 degrade honestly under a minimal/default grant ------------

def _tools_server(tools_status: int, tools_body: dict | None = None):
    """initialize succeeds normally; tools/list returns whatever the test
    wants to simulate a minimal-grant server."""
    def handle(request: httpx.Request) -> httpx.Response:
        try:
            method = json.loads(request.content.decode()).get("method", "")
        except Exception:
            method = ""
        if method == "initialize":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": 0,
                "result": {"protocolVersion": "2026-07-28", "capabilities": {}},
            })
        if method == "notifications/initialized":
            return httpx.Response(202, text="")
        if method == "tools/list":
            if tools_body is not None:
                return httpx.Response(tools_status, json=tools_body)
            return httpx.Response(tools_status, json={"error": "denied"})
        return httpx.Response(404, json={"error": "not_found"})
    return httpx.MockTransport(handle)


def _authed_target_ctx(transport) -> tuple[Target, ProbeContext]:
    target = Target(name="t", url="https://mcp.test/mcp", transport=Transport.HTTP)
    ctx = ProbeContext(transport=transport)
    ctx.auth_session = AuthSession(
        access_token="AT", token_type="Bearer",
        probe_evidence={"auth_mode": "auto"},   # a real OAuth flow ran
    )
    return target, ctx


@pytest.mark.parametrize("check_cls", [
    "ToolBlastRadius", "ToolRwSeparation", "ToolInjectionSurface",
])
def test_ts_checks_na_not_pass_on_403_under_minimal_grant(check_cls):
    from mcp_audit.checks.server import tool_safety
    from mcp_audit.core.models import Rating

    transport = _tools_server(403, {"jsonrpc": "2.0", "id": 1,
                                    "error": {"code": -32003, "message": "insufficient scope"}})
    target, ctx = _authed_target_ctx(transport)

    result = getattr(tool_safety, check_cls)().run(target, ctx)

    assert result.rating == Rating.NA
    assert "scope" in result.detail.lower()
    assert "--scopes" in result.detail
    ctx.close()


@pytest.mark.parametrize("check_cls", [
    "ToolBlastRadius", "ToolRwSeparation", "ToolInjectionSurface",
])
def test_ts_checks_na_not_pass_on_empty_list_under_minimal_grant(check_cls):
    from mcp_audit.checks.server import tool_safety
    from mcp_audit.core.models import Rating

    transport = _tools_server(200, {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
    target, ctx = _authed_target_ctx(transport)

    result = getattr(tool_safety, check_cls)().run(target, ctx)

    assert result.rating == Rating.NA
    assert result.rating != Rating.PASS
    assert "--scopes" in result.detail
    ctx.close()


def test_ts_check_still_errors_on_non_scope_refusal():
    """A 500 (or any non-401/403 refusal) is not a scope story — stays ERROR,
    not silently downgraded to n/a."""
    from mcp_audit.checks.server.tool_safety import ToolBlastRadius
    from mcp_audit.core.models import Rating

    transport = _tools_server(500, {"error": "internal"})
    target, ctx = _authed_target_ctx(transport)

    result = ToolBlastRadius().run(target, ctx)

    assert result.rating == Rating.ERROR
    ctx.close()


def test_static_token_empty_tools_does_not_blame_scope():
    """A static --token's permissions aren't ours to widen with --scopes, so
    an empty tool list there keeps the generic message, not the --scopes hint."""
    from mcp_audit.checks.server.tool_safety import ToolBlastRadius
    from mcp_audit.core.models import Rating

    transport = _tools_server(200, {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
    target = Target(name="t", url="https://mcp.test/mcp", transport=Transport.HTTP)
    ctx = ProbeContext(transport=transport)
    ctx.auth_session = AuthSession(access_token="AT", token_type="Bearer",
                                   probe_evidence={"auth_mode": "supplied-token"})

    result = ToolBlastRadius().run(target, ctx)

    assert result.rating == Rating.NA
    assert "--scopes" not in result.detail
    ctx.close()
