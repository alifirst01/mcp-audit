"""Shared constants and helpers for MCP server checks.

"""
from __future__ import annotations

MCP_VERSION = "2026-07-28"


def mcp_post_headers(version: str = MCP_VERSION, method: str = "tools/list") -> dict:
    """Standard HTTP headers for an MCP POST request. Default method is
    tools/list — the one JSON-RPC method every check in this project has
    proven works against real servers (see tools_list_body's docstring).
    Every transport check builds its own headers from this plus a body from
    tools_list_body(), never a hand-assembled minimal request."""
    return {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": version,
        "Mcp-Method": method,
    }


def maybe_authed_headers(ctx, headers: dict) -> tuple[dict, bool]:
    """Merge in the Authorization header from ctx.auth_session if a completed
    --auth session exists, so a probe can see past a server's
    401-before-transport-validation ordering instead of only reporting an
    inconclusive WARN. Returns (headers, used_auth) so the caller can phrase
    its result around whether credentials were sent."""
    if ctx.auth_session:
        return {**headers, **ctx.authed_headers()}, True
    return headers, False


def probe_reaches_property_stage(response) -> bool:
    """True if `response` indicates the request was structurally valid
    enough to reach past body/header validation — 200, 401, 403, whatever —
    and False only for HTTP 400, which on an otherwise-correct request means
    the server rejected it at an earlier validation stage unrelated to the
    property under test. A network error also fails this.

    Guard behind every baseline-vs-mutated differential check: if the
    baseline itself doesn't pass this, the check cannot draw a conclusion
    and must report ERROR/not-tested instead."""
    return not response.error and response.status != 400


def redact_headers(headers: dict) -> dict:
    """Headers dict safe to place in evidence/JSON output. The Authorization
    value (a live bearer token) is replaced with a marker so findings stay
    reproducible — a reader knows a token was sent and in what scheme —
    without the secret itself landing in a report that might be shared or
    published."""
    out = dict(headers)
    auth = out.get("Authorization")
    if auth:
        scheme = auth.split(" ", 1)[0] if " " in auth else "Bearer"
        out["Authorization"] = f"{scheme} <redacted>"
    return out


def request_evidence(method: str, url: str, headers: dict, body, response) -> dict:
    """Full request/response evidence for one probe, with any bearer token
    redacted, so a check's finding can be hand-verified by re-sending the
    exact same request. Used by every baseline-vs-mutated differential check —
    see probe_reaches_property_stage's docstring."""
    return {
        "request_method": method,
        "request_url": url,
        "request_headers": redact_headers(headers),
        "request_body": body,
        "response_status": response.status,
        "response_body": (response.text or "")[:500],
    }


def extract_jsonrpc_error(text: str) -> dict | None:
    """Parse the error object from a JSON-RPC response body, or return None."""
    import json
    try:
        doc = json.loads(text)
        return doc.get("error")
    except Exception:
        return None


def base_url(url: str) -> str:
    """Return scheme://netloc with no path component."""
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def tools_list_body(version: str = MCP_VERSION) -> dict:
    """JSON-RPC body for a tools/list request — the same shape
    fetch_tools/fetch_tools_authed use to successfully call real servers.
    Recommended baseline body for any differential check that mutates
    exactly one property: confirm this succeeds, then change only the one
    thing under test. Never hand-assemble a bespoke minimal body."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }


def fetch_tools(target, ctx):
    """Send tools/list and return (tools, err). err is one of None,
    'stdio-no-http', 'auth-required', 'request-error:...', 'unexpected-status:N',
    'parse-error:...'. Shared by every check that needs the live tool list."""
    from ...core.models import Transport
    if target.transport == Transport.STDIO or not target.url:
        return None, "stdio-no-http"

    headers = mcp_post_headers(method="tools/list")
    r = ctx.post(target.url, json_body=tools_list_body(), headers=headers)

    if r.error:
        return None, f"request-error:{r.error}"
    if r.status == 401:
        return None, "auth-required"
    if r.status != 200:
        return None, f"unexpected-status:{r.status}"

    try:
        doc = r.json()
        tools = doc.get("result", {}).get("tools") or doc.get("tools", [])
        return tools, None
    except Exception as exc:
        return None, f"parse-error:{exc}"


def fetch_tools_authed(target, ctx):
    """Like fetch_tools, but sends the Authorization header from ctx.auth_session.
    Falls through to the unauthenticated fetch_tools if no session exists."""
    from ...core.models import Transport
    if target.transport == Transport.STDIO or not target.url:
        return None, "stdio-no-http"
    if not ctx.auth_session:
        return fetch_tools(target, ctx)

    headers = mcp_post_headers(method="tools/list")
    headers.update(ctx.authed_headers())
    r = ctx.post(target.url, json_body=tools_list_body(), headers=headers)

    if r.error:
        return None, f"request-error:{r.error}"
    if r.status != 200:
        return None, f"unexpected-status:{r.status}"
    try:
        doc = r.json()
        tools = doc.get("result", {}).get("tools") or doc.get("tools", [])
        return tools, None
    except Exception as exc:
        return None, f"parse-error:{exc}"


def obtained_without_auth_note(ctx) -> str:
    """Detail-text suffix for a check tagged Method: Auth whose data this run
    happened to obtain without a completed --auth session. Empty string when
    a session was actually used."""
    return "" if ctx.auth_session else " (obtained without authentication)"


def decode_jwt_payload(token: str) -> dict | None:
    """Best-effort, unverified decode of a JWT's payload segment — used only
    to read informational claims like `aud`. Returns None for an opaque
    (non-JWT) token; never used to make a trust decision."""
    import json as _json
    from joserfc.jws import extract_compact
    try:
        return _json.loads(extract_compact(token.encode()).payload)
    except Exception:
        return None


def expected_issuer_from_well_known(well_known_url: str) -> str:
    """
    Derive the expected OAuth issuer identifier from a well-known metadata URL.

    Per RFC 8414 §3.1 and OIDC Discovery §4.1, the issuer is obtained by
    stripping the well-known suffix (and any path that precedes it in the
    path-insertion variant) from the URL.

    Examples:
      https://auth.example.com/.well-known/oauth-authorization-server
        → https://auth.example.com
      https://auth.example.com/.well-known/oauth-authorization-server/tenant1
        → https://auth.example.com/tenant1
      https://auth.example.com/tenant1/.well-known/openid-configuration
        → https://auth.example.com/tenant1
    """
    _SUFFIXES = (
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    )
    for suffix in _SUFFIXES:
        idx = well_known_url.find(suffix)
        if idx != -1:
            tail = well_known_url[idx + len(suffix):]   # "" or "/tenant"
            return well_known_url[:idx] + tail
    return well_known_url
