"""TS-03 (tool-injection-surface): the desc_match phrase set must not
over-match ordinary first-party tool descriptions, while still catching
genuine external-content fetchers.

Regression cover for: bare tokens like "search"/"web" in the description
match flagging first-party search tools (search_docs, search_issues,
search_stripe_documentation) as an injection surface.
"""
from __future__ import annotations

import json

import httpx
import pytest

from mcp_audit.core.probe import AuthSession, ProbeContext
from mcp_audit.core.models import Target, Transport
from mcp_audit.checks.server.tool_safety import ToolInjectionSurface


def _server(tools: list[dict]) -> httpx.MockTransport:
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
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": 1, "result": {"tools": tools},
            })
        return httpx.Response(404, json={"error": "not_found"})
    return httpx.MockTransport(handle)


def _run(tools: list[dict]):
    ctx = ProbeContext(transport=_server(tools))
    ctx.auth_session = AuthSession(access_token="tok", token_type="Bearer")
    target = Target(name="t", url="https://mcp.example.test/mcp", transport=Transport.HTTP)
    target.context = {}
    try:
        return ToolInjectionSurface().run(target, ctx)
    finally:
        ctx.close()


# --- the three named first-party search tools must not flag ---------------

_FIRST_PARTY_SEARCH_TOOLS = [
    {"name": "search_docs",
     "description": "Search across all organizations, projects, and branches "
                     "by keyword. Returns matching items with id, title, and URL.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
    {"name": "search_stripe_documentation",
     "description": "Search the Stripe documentation and knowledge base for "
                     "guides and API reference relevant to a query.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
    {"name": "search_issues",
     "description": "Search issues in the workspace by title, description, or "
                     "label, returning matching issue records.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
]


@pytest.mark.parametrize("tool", _FIRST_PARTY_SEARCH_TOOLS, ids=lambda t: t["name"])
def test_first_party_search_tools_do_not_flag(tool):
    result = _run([tool])
    assert result.rating.value == "pass"
    assert result.evidence["injection_surface_tools"] == []


def test_first_party_search_tools_do_not_flag_together():
    result = _run(_FIRST_PARTY_SEARCH_TOOLS)
    assert result.rating.value == "pass"
    assert result.evidence["injection_surface_tools"] == []


# --- genuine external-content tools must still flag ------------------------

@pytest.mark.parametrize("tool", [
    {"name": "web_search", "description": "Search the web for a query.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
    {"name": "browse", "description": "Open a web page and return its content.",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},
    {"name": "fetch_url", "description": "Fetch the contents of any URL.",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},
], ids=lambda t: t["name"])
def test_genuine_external_fetch_tools_still_flag(tool):
    result = _run([tool])
    assert result.rating.value == "warn"
    flagged_names = [f["name"] for f in result.evidence["injection_surface_tools"]]
    assert tool["name"] in flagged_names


def test_param_plus_desc_match_requires_the_new_narrower_phrases():
    # A url-shaped param alone isn't enough; the description must name an
    # untrusted external boundary, not just contain "url" as in "an issue URL".
    benign = {"name": "link_issue_to_pr",
              "description": "Link an issue to a pull request by URL.",
              "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}}
    result = _run([benign])
    assert result.rating.value == "pass"

    flagged = {"name": "open_external_page",
               "description": "Open an arbitrary URL on the web and return its text.",
               "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}}
    result2 = _run([flagged])
    assert result2.rating.value == "warn"
