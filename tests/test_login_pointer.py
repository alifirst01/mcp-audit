"""CD-05 (LoginPointer): when the 401 carries no in-band WWW-Authenticate
pointer, the finding must reflect whether the well-known fallback (CD-02)
actually resolves — not assume the worst case regardless.
"""
from __future__ import annotations

import httpx

from mcp_audit.checks.server.connection_discovery import LoginPointer
from mcp_audit.core.models import Rating, Target, Transport
from mcp_audit.core.probe import ProbeContext

MCP_URL = "https://mcp.test/mcp"
WELL_KNOWN_URL = "https://mcp.test/.well-known/oauth-protected-resource/mcp"


def _target() -> Target:
    return Target(name="t", url=MCP_URL, transport=Transport.HTTP)


def _transport(mcp_response: httpx.Response, well_known_response: httpx.Response | None):
    def handle(request: httpx.Request) -> httpx.Response:
        if str(request.url) == MCP_URL:
            return mcp_response
        if well_known_response is not None:
            return well_known_response
        return httpx.Response(404, json={"error": "not_found"})
    return httpx.MockTransport(handle)


def test_no_header_but_well_known_resolves_is_warn_with_fallback_wording():
    """The exact contradiction being fixed: no WWW-Authenticate, but the
    well-known path does resolve — the detail must say so, not claim the
    agent would have to guess."""
    transport = _transport(
        httpx.Response(401, json={"error": "unauthorized"}),
        httpx.Response(200, json={"authorization_servers": ["https://as.test"]}),
    )
    ctx = ProbeContext(transport=transport)
    result = LoginPointer().run(_target(), ctx)

    assert result.rating == Rating.WARN
    assert "must fall back to probing the well-known path" in result.detail
    assert "did resolve" in result.detail
    assert "would have to guess" not in result.detail
    assert result.evidence["well_known_resolved"] is True
    assert result.evidence["well_known_url"] == WELL_KNOWN_URL
    ctx.close()


def test_no_header_and_well_known_also_fails_uses_strong_wording():
    transport = _transport(httpx.Response(401, json={"error": "unauthorized"}), None)
    ctx = ProbeContext(transport=transport)
    result = LoginPointer().run(_target(), ctx)

    assert result.rating == Rating.WARN
    assert "would have to guess or consult documentation" in result.detail
    assert result.evidence["well_known_resolved"] is False
    assert result.evidence["well_known_url"] is None
    ctx.close()


def test_header_with_resource_metadata_is_unaffected():
    wa = f'Bearer resource_metadata="{WELL_KNOWN_URL}"'
    transport = _transport(
        httpx.Response(401, headers={"WWW-Authenticate": wa}, json={"error": "unauthorized"}),
        httpx.Response(200, json={"authorization_servers": ["https://as.test"]}),
    )
    ctx = ProbeContext(transport=transport)
    result = LoginPointer().run(_target(), ctx)

    assert result.rating == Rating.PASS
    ctx.close()


def test_header_without_resource_metadata_pointer_is_unaffected():
    transport = _transport(
        httpx.Response(401, headers={"WWW-Authenticate": "Bearer"}, json={"error": "unauthorized"}),
        None,
    )
    ctx = ProbeContext(transport=transport)
    result = LoginPointer().run(_target(), ctx)

    assert result.rating == Rating.WARN
    assert "no resource_metadata pointer" in result.detail
    ctx.close()
