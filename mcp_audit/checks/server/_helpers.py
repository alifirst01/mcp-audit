"""Shared constants and helpers for MCP server checks.

"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlunparse

from ...core.probe import debug_log, debug_tokens_enabled

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
    see Check.baseline_gate, which gates a conclusion on the baseline here
    reaching a 2xx."""
    return {
        "request_method": method,
        "request_url": url,
        "request_headers": redact_headers(headers),
        "request_body": body,
        "response_status": response.status,
        "response_body": (response.text or "")[:500],
    }


def parse_jsonrpc_message(text: str) -> dict | None:
    """Parse one JSON-RPC object from an MCP POST response body, whether the
    server replied with `application/json` (the body *is* the object) or
    `text/event-stream` (the object is the `data:` payload of an SSE
    `message` event — MCP Streamable HTTP lets a server answer a POST with
    either, and we send `Accept: application/json, text/event-stream`).
    Returns the last JSON object found, or None."""
    import json
    if not text:
        return None
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            doc = json.loads(text)
            return doc if isinstance(doc, dict) else None
        except Exception:
            return None
    # SSE framing: gather consecutive `data:` lines per event; keep the last
    # payload that parses to a JSON object. `event:` / `id:` / `:comment`
    # lines are ignored.
    last: dict | None = None
    buf: list[str] = []
    for raw in text.splitlines() + [""]:
        line = raw.rstrip("\r")
        if line.startswith("data:"):
            buf.append(line[5:].lstrip(" "))
        elif not line:
            if buf:
                try:
                    doc = json.loads("\n".join(buf))
                    if isinstance(doc, dict):
                        last = doc
                except Exception:
                    pass
            buf = []
    return last


def extract_jsonrpc_error(text: str) -> dict | None:
    """The JSON-RPC `error` object (a dict with `code`/`message`) from a
    response body — plain JSON or SSE-framed — or None. A body like
    `{"error": "invalid_token"}` (OAuth-style, `error` is a bare string) is
    not a JSON-RPC error object and yields None."""
    msg = parse_jsonrpc_message(text)
    err = msg.get("error") if msg else None
    return err if isinstance(err, dict) else None


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


_INIT_METHOD = "initialize"


def initialize_body(version: str = MCP_VERSION) -> dict:
    """JSON-RPC body for the MCP `initialize` handshake. Sent before
    tools/list (and the transport probes) because spec-strict servers
    (Linear, Sentry, Stripe, Neon) reject a bare tools/list until initialize
    has completed.

    `method` and `params.protocolVersion` here MUST match the Mcp-Method and
    MCP-Protocol-Version headers that `_initialize_headers(ctx, version)`
    builds for the same `version` — a request whose mirrored headers disagree
    with its body is rejected with `400` (`-32020 HeaderMismatch` or
    `-32602`). Both sides are derived from `version` so they cannot drift."""
    return {
        "jsonrpc": "2.0",
        "id": 0,
        "method": _INIT_METHOD,
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "mcp-audit", "version": "0.1"},
        },
    }


def _initialize_headers(ctx, version: str = MCP_VERSION) -> tuple[dict, bool]:
    """Headers for the `initialize` POST: the standard MCP POST headers for
    `version` + method `initialize` — so the `MCP-Protocol-Version` and
    `Mcp-Method` headers mirror `initialize_body(version)`'s `protocolVersion`
    and `method` exactly — plus the bearer token. Neon enforces that these
    mirrored headers are present and consistent with the body and returns
    `400` otherwise (Linear/Sentry tolerate their absence, but matching
    headers satisfy all three). Returns (headers, authorization_sent)."""
    headers = mcp_post_headers(version=version, method=_INIT_METHOD)
    if ctx.auth_session:
        headers.update(ctx.authed_headers())
        return headers, True
    return headers, False


@dataclass
class McpSession:
    """Everything a JSON-RPC POST to this target needs beyond a token:
      - ``message_url``: where POSTs go — not the configured URL when that URL
        is an HTTP+SSE stream (then it's the endpoint the stream announces);
      - ``protocol_version``: the version ``initialize`` negotiated, to send in
        the MCP-Protocol-Version header (and mirror in the body) on every
        later request so header and body stay consistent;
      - ``session_headers``: any ``Mcp-Session-Id`` ``initialize`` returned
        that the server expects echoed on every subsequent request;
      - ``sse``: True when the message endpoint was resolved from an SSE
        ``endpoint`` event — replies then arrive asynchronously on that
        stream and a bare POST returns ``202 Accepted``.

    Resolved once per target and cached on ``target.context['mcp_session']``."""
    message_url: str
    protocol_version: str = MCP_VERSION
    session_headers: dict = field(default_factory=dict)
    sse: bool = False
    initialized: bool = False
    accepted_async: bool = False
    error: Optional[str] = None
    evidence: dict = field(default_factory=dict)


def _is_sse_endpoint(url: str) -> bool:
    return urlparse(url).path.rstrip("/").endswith("/sse")


def _streamable_http_guess(url: str) -> str:
    """Best-effort Streamable-HTTP URL for a server configured with an
    HTTP+SSE stream URL: swap a trailing `/sse` for `/mcp`."""
    p = urlparse(url)
    return urlunparse(p._replace(path=re.sub(r"/sse/?$", "/mcp", p.path)))


def _resolve_message_url(target, ctx) -> tuple[str, Optional[str], bool]:
    """Where JSON-RPC POSTs for this target go, and whether that endpoint is a
    true HTTP+SSE message endpoint (async replies). For a normal
    Streamable-HTTP endpoint it's the configured URL, replying synchronously.
    For an `…/sse` endpoint the real message endpoint is announced in the
    stream's first `endpoint` event; if that handshake can't be completed
    (e.g. the stream itself needs a token this run doesn't have) fall back to
    the conventional Streamable-HTTP path. Returns
    (url, note, via_sse_handshake)."""
    url = target.url
    if not _is_sse_endpoint(url):
        return url, None, False
    headers, _ = maybe_authed_headers(ctx, {})
    resolved, err = ctx.resolve_sse_endpoint(url, headers)
    if resolved:
        return resolved, f"resolved via SSE endpoint event from {url}", True
    guess = _streamable_http_guess(url)
    return (guess,
            f"SSE handshake with {url} failed ({err}); using Streamable-HTTP path {guess}",
            False)


_VERSION_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _server_supported_version(jerr: dict) -> Optional[str]:
    """From an `initialize` JSON-RPC error, return the newest protocol version
    the server says it supports, or None. Servers put the list in different
    places — `data.supported`, `data.supportedVersions`, `data.versions`,
    `data` as a bare list — and some only name it in the message text
    (Neon's -32000 "Unsupported protocol version" carries the list in
    `data`). Version strings are ISO dates, so lexicographic max == newest."""
    if not isinstance(jerr, dict):
        return None
    data = jerr.get("data")
    cands: list = []
    if isinstance(data, list):
        cands = data
    elif isinstance(data, dict):
        for k in ("supported", "supportedVersions", "supported_versions", "versions"):
            v = data.get(k)
            if isinstance(v, list):
                cands = v
                break
        else:
            if isinstance(data.get("protocolVersion"), str):
                cands = [data["protocolVersion"]]
    if not cands:
        cands = _VERSION_RE.findall(jerr.get("message") or "")
    versions = sorted({v for v in cands if isinstance(v, str) and _VERSION_RE.fullmatch(v)})
    return versions[-1] if versions else None


def _record_initialize_failure(evidence: dict, r, headers: dict, body: dict) -> tuple[str, Optional[str]]:
    """Populate `evidence` from a rejected `initialize` (HTTP error, or HTTP
    200 carrying a JSON-RPC error) and return (err_tag, best_supported_version).
    `request_evidence` truncates the body to 500 chars; keep the full thing
    (bounded) and surface the JSON-RPC error so it's diagnosable from the
    report alone."""
    evidence["response_body_full"] = (r.text or "")[:4000]
    jerr = extract_jsonrpc_error(r.text)
    if not jerr:
        return f"initialize-status:{r.status}", None
    code = jerr.get("code")
    evidence["jsonrpc_error"] = {"code": code, "message": jerr.get("message"),
                                "data": jerr.get("data")}
    best = _server_supported_version(jerr)
    if code in (-32000, -32020, -32602) or best:
        evidence["initialize_request_rejected"] = (
            f"Server rejected initialize with JSON-RPC {code} "
            f"({jerr.get('message')!r}). Sent MCP-Protocol-Version="
            f"{headers.get('MCP-Protocol-Version')!r}, Mcp-Method="
            f"{headers.get('Mcp-Method')!r}; body method={body['method']!r}, "
            f"params.protocolVersion={body['params'].get('protocolVersion')!r}."
            + (f" Server supports {best!r} — adopted for later requests." if best else "")
        )
    return f"initialize-jsonrpc-error:{code}", best


def mcp_session(target, ctx) -> McpSession:
    """Resolve this target's message endpoint and run the MCP initialize
    handshake (with the bearer token when --auth completed), negotiating the
    protocol version from the server's response and capturing any
    Mcp-Session-Id. Cached per target — the handshake runs at most once."""
    cached = target.context.get("mcp_session")
    if cached is not None:
        return cached

    message_url, resolve_note, via_sse = _resolve_message_url(target, ctx)

    # Negotiate the protocol version. Send our preferred one; if initialize
    # comes back with a JSON-RPC error naming the server's supported versions
    # (Neon answers -32000 "Unsupported protocol version" with the list),
    # retry once with the newest version the server actually supports. Header
    # and body are always built from the same `init_version`, so the mirrored
    # MCP-Protocol-Version / Mcp-Method headers agree with the body.
    init_version = MCP_VERSION
    negotiation: list[dict] = []
    r = headers = body = None
    auth_sent = False
    for attempt in range(2):
        headers, auth_sent = _initialize_headers(ctx, init_version)
        body = initialize_body(init_version)
        r = ctx.post(message_url, json_body=body, headers=headers)
        jerr = None if r.error else extract_jsonrpc_error(r.text)
        negotiation.append({
            "sent_version": init_version,
            "http_status": r.status,
            "jsonrpc_error_code": (jerr or {}).get("code"),
        })
        if r.error or attempt == 1 or not jerr:
            break
        better = _server_supported_version(jerr)
        if not better or better == init_version:
            break
        debug_log(f"initialize: server rejected protocolVersion {init_version!r}; "
                  f"retrying with server-supported {better!r}")
        init_version = better

    evidence = request_evidence("POST", message_url, headers, body, r)
    evidence["authorization_sent"] = auth_sent
    evidence["protocol_negotiation"] = negotiation
    if resolve_note:
        evidence["endpoint_resolution"] = resolve_note

    # Local, unredacted dump of the initialize exchange (full body, both
    # verbs) for diagnosing a rejected handshake — only when the operator
    # sets MCP_AUDIT_DEBUG_TOKENS. Nothing here touches the on-disk evidence.
    if debug_tokens_enabled() and ctx.auth_session:
        g = ctx.get(message_url, headers=ctx.authed_headers(
            {"Accept": "application/json, text/event-stream"}))
        debug_log(f"initialize POST  {message_url} -> {r.status}  "
                  f"headers sent: MCP-Protocol-Version={headers.get('MCP-Protocol-Version')!r} "
                  f"Mcp-Method={headers.get('Mcp-Method')!r}  "
                  f"body: method={body['method']!r} "
                  f"protocolVersion={body['params'].get('protocolVersion')!r}")
        debug_log(f"initialize POST  full response body: {r.text!r}")
        debug_log(f"plain authed GET {message_url} -> {g.status} {(g.text or '')[:200]!r}")
        debug_log("EXPECT: authed GET is non-401 once the token is valid; "
                  "if both are 401 the issued token itself is being rejected.")

    session_headers: dict = {}
    sid = None if r.error else r.headers.get("mcp-session-id")
    if sid:
        session_headers["Mcp-Session-Id"] = sid

    # Default to the last version we actually sent: MCP_VERSION when no
    # negotiation happened, or the server's own supported version when we
    # retried with it. A clean initialize may narrow it further via
    # result.protocolVersion.
    protocol_version = init_version
    initialized = False
    accepted_async = False
    err: Optional[str] = None

    if r.error:
        err = f"initialize-request-error:{r.error}"
    elif r.status == 202:
        # Old HTTP+SSE transport: the server accepted the request and will
        # deliver the InitializeResult on the SSE stream, which this probe
        # does not hold open across the POST. "Accepted, reply not captured" —
        # not a failure.
        accepted_async = True
        initialized = True
        err = "initialize-accepted-async-202"
    elif 200 <= r.status < 300:
        jerr = extract_jsonrpc_error(r.text)
        if jerr:
            # HTTP 200 carrying a JSON-RPC error body — e.g. a -32000 version
            # rejection returned inside a 200 rather than as an HTTP error.
            err, best = _record_initialize_failure(evidence, r, headers, body)
            if best:
                protocol_version = best
            debug_log(f"initialize {message_url} -> 200 + JSON-RPC error; body: {r.text!r}")
        else:
            initialized = True
            # The InitializeResult may arrive as plain JSON or SSE-framed
            # (text/event-stream) — parse both, so the negotiated version is
            # actually captured and not silently dropped.
            doc = parse_jsonrpc_message(r.text)
            negotiated = ((doc or {}).get("result") or {}).get("protocolVersion")
            if isinstance(negotiated, str) and negotiated:
                protocol_version = negotiated
                evidence["negotiated_protocol_version"] = negotiated
            else:
                evidence["negotiated_protocol_version"] = None
                evidence["initialize_result_unparsed"] = (r.text or "")[:500]
    elif r.status == 401 and not ctx.auth_session:
        err = "initialize-no-auth-session"
        evidence["note"] = (
            "No completed --auth session, so the initialize POST carried no "
            "bearer token — this 401 is expected. Re-run with --auth."
        )
    elif r.status == 401:
        # The token that GET-based checks accept was rejected on this POST.
        # Capture a same-token GET beside the POST so the difference is in
        # evidence (header format / content negotiation / session).
        err = "initialize-status:401"
        get_headers = {**ctx.authed_headers(),
                       "Accept": "application/json, text/event-stream"}
        g = ctx.get(message_url, headers=get_headers)
        evidence["reference_get"] = {
            "request_headers": redact_headers(get_headers),
            "response_status": g.status,
            "response_body": (g.text or "")[:300],
        }
        evidence["post_vs_get"] = (
            f"POST {message_url} with the bearer token -> {r.status} "
            f"({(r.text or '')[:120]!r}); GET the same URL with the same token "
            f"-> {g.status}"
        )
    else:
        err, best = _record_initialize_failure(evidence, r, headers, body)
        if best:
            protocol_version = best
        debug_log(f"initialize {message_url} -> {r.status}; full body: {r.text!r}")

    if initialized and not accepted_async:
        # Spec: the client MUST send notifications/initialized before issuing
        # any other request. Best-effort — the response is not needed.
        note_headers = mcp_post_headers(version=protocol_version,
                                        method="notifications/initialized")
        note_headers, _ = maybe_authed_headers(ctx, note_headers)
        note_headers.update(session_headers)
        ctx.post(
            message_url,
            json_body={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=note_headers,
        )

    session = McpSession(
        message_url=message_url,
        protocol_version=protocol_version,
        session_headers=session_headers,
        sse=via_sse,
        initialized=initialized,
        accepted_async=accepted_async,
        error=err,
        evidence=evidence,
    )
    target.context["mcp_session"] = session
    return session


def mcp_message_target(target, ctx, method: str = "tools/list") -> tuple[str, dict, bool, McpSession]:
    """(url, headers, used_auth, session) for a JSON-RPC POST probe: the
    resolved message endpoint, MCP POST headers carrying the **negotiated**
    protocol version, the Mcp-Session-Id from the initialize handshake, and
    the bearer token when --auth completed. Every JSON-RPC probe in this
    project routes through here so SSE endpoints, session ids and the
    negotiated version are handled in one place. Callers that also send a
    body must build it with `session.protocol_version` so header and body
    agree."""
    session = mcp_session(target, ctx)
    headers = mcp_post_headers(version=session.protocol_version, method=method)
    headers.update(session.session_headers)
    headers, used_auth = maybe_authed_headers(ctx, headers)
    return session.message_url, headers, used_auth, session


def accepted_async(*responses) -> bool:
    """True if any probe response is HTTP 202 — the server took the request
    and the JSON-RPC reply is on a separate SSE stream this probe does not
    consume. Callers must treat this as inconclusive (n/a), never fail."""
    return any(getattr(r, "status", None) == 202 for r in responses)


def sse_async_na(check, evidence: dict):
    """The standard n/a result for `accepted_async`: never an error or fail."""
    from ...core.models import Rating
    return check._result(
        Rating.NA,
        "The server accepted the probe with HTTP 202 and delivers the JSON-RPC "
        "response on a separate SSE stream, which this probe does not consume. "
        "SSE async response not captured.",
        evidence,
    )


def _tools_from_response(r):
    """(tools, err) from a tools/list HTTP 200 — body may be plain JSON or
    SSE-framed. A JSON-RPC error in the body (e.g. -32000) is surfaced, not
    swallowed as an empty tool list."""
    doc = parse_jsonrpc_message(r.text)
    if doc is None:
        return None, f"parse-error:unparseable response body ({(r.text or '')[:120]!r})"
    err = doc.get("error")
    if isinstance(err, dict):
        return None, f"jsonrpc-error:{err.get('code')}:{err.get('message')}"
    tools = (doc.get("result") or {}).get("tools") or doc.get("tools") or []
    return tools, None


def fetch_tools(target, ctx):
    """Send tools/list and return (tools, err). err is one of None,
    'stdio-no-http', 'auth-required', 'request-error:...', 'unexpected-status:N',
    'parse-error:...', 'jsonrpc-error:...'. Shared by every check that needs
    the live tool list."""
    from ...core.models import Transport
    if target.transport == Transport.STDIO or not target.url:
        return None, "stdio-no-http"

    url, headers, _used_auth, session = mcp_message_target(target, ctx, method="tools/list")
    body = tools_list_body(version=session.protocol_version)
    r = ctx.post(url, json_body=body, headers=headers)
    ctx.last_tools_list_evidence = request_evidence("POST", url, headers, body, r)
    if session.evidence:
        ctx.last_tools_list_evidence["initialize"] = session.evidence

    if r.error:
        return None, f"request-error:{r.error}"
    if r.status == 202:
        return None, "sse-async-not-captured"
    if r.status == 401:
        return None, "auth-required"
    if r.status != 200:
        return None, f"unexpected-status:{r.status}"
    return _tools_from_response(r)


def fetch_tools_authed(target, ctx):
    """Like fetch_tools, but sends the Authorization header from ctx.auth_session.
    Falls through to the unauthenticated fetch_tools if no session exists."""
    from ...core.models import Transport
    if target.transport == Transport.STDIO or not target.url:
        return None, "stdio-no-http"
    if not ctx.auth_session:
        return fetch_tools(target, ctx)

    # mcp_message_target already merges the bearer token via maybe_authed_headers
    # (ctx.auth_session is set here), plus the Mcp-Session-Id from initialize.
    url, headers, _used_auth, session = mcp_message_target(target, ctx, method="tools/list")
    body = tools_list_body(version=session.protocol_version)
    r = ctx.post(url, json_body=body, headers=headers)
    ctx.last_tools_list_evidence = request_evidence("POST", url, headers, body, r)
    if session.evidence:
        ctx.last_tools_list_evidence["initialize"] = session.evidence

    if r.error:
        return None, f"request-error:{r.error}"
    if r.status == 202:
        return None, "sse-async-not-captured"
    if r.status != 200:
        return None, f"unexpected-status:{r.status}"
    return _tools_from_response(r)


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
