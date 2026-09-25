"""CD-06 (DualDiscoveryPath) regression cover after refactoring its
well-known/header-pointer probing onto the shared _helpers.fetch_prm_doc /
well_known_prm_candidates — behavior must be unchanged.
"""
from __future__ import annotations

import httpx

from mcp_audit.checks.server.connection_discovery import DualDiscoveryPath
from mcp_audit.core.models import Rating, Target, Transport
from mcp_audit.core.probe import ProbeContext

MCP_URL = "https://mcp.test/mcp"
WELL_KNOWN_URL = "https://mcp.test/.well-known/oauth-protected-resource/mcp"
HEADER_PRM_URL = "https://mcp.test/custom-prm-location"


def _target(prm_url_from_header=None) -> Target:
    t = Target(name="t", url=MCP_URL, transport=Transport.HTTP)
    if prm_url_from_header:
        t.context["prm_url"] = prm_url_from_header
    return t


def _transport(routes: dict[str, httpx.Response]):
    def handle(request: httpx.Request) -> httpx.Response:
        return routes.get(str(request.url), httpx.Response(404, json={"error": "not_found"}))
    return httpx.MockTransport(handle)


_PRM_OK = httpx.Response(200, json={"authorization_servers": ["https://as.test"]})


def test_both_paths_reachable_is_pass():
    ctx = ProbeContext(transport=_transport({WELL_KNOWN_URL: _PRM_OK, HEADER_PRM_URL: _PRM_OK}))
    result = DualDiscoveryPath().run(_target(HEADER_PRM_URL), ctx)
    assert result.rating == Rating.PASS
    ctx.close()


def test_only_header_pointer_reachable_is_warn():
    ctx = ProbeContext(transport=_transport({HEADER_PRM_URL: _PRM_OK}))
    result = DualDiscoveryPath().run(_target(HEADER_PRM_URL), ctx)
    assert result.rating == Rating.WARN
    assert "well-known" in result.detail.lower()
    ctx.close()


def test_only_well_known_reachable_is_warn():
    ctx = ProbeContext(transport=_transport({WELL_KNOWN_URL: _PRM_OK}))
    result = DualDiscoveryPath().run(_target(), ctx)
    assert result.rating == Rating.WARN
    assert "WWW-Authenticate" in result.detail
    ctx.close()


def test_neither_reachable_is_fail():
    ctx = ProbeContext(transport=_transport({}))
    result = DualDiscoveryPath().run(_target(), ctx)
    assert result.rating == Rating.FAIL
    ctx.close()
