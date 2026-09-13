"""Shared constants and helpers for MCP server checks."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlunparse

from ...core.base import EVIDENCE_NOTE
from ...core.probe import debug_log, debug_tokens_enabled

MCP_VERSION = "2026-07-28"


def mcp_post_headers(version: str = MCP_VERSION, method: str = "tools/list") -> dict:
    """The HTTP headers for an MCP JSON-RPC POST. The `Mcp-Method` and
    `MCP-Protocol-Version` headers mirror the request body and must agree with
    it; keep the `version`/`method` passed here in sync with the body."""
    return {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": version,
        "Mcp-Method": method,
    }


def maybe_authed_headers(ctx, headers: dict) -> tuple[dict, bool]:
    """Add the bearer token when a completed `--auth` session exists, so a
    probe can get past servers that reject on auth before validating the
    property under test. Returns (headers, used_auth)."""
    if ctx.auth_session:
        return {**headers, **ctx.authed_headers()}, True
    return headers, False


def redact_headers(headers: dict) -> dict:
    """A copy of `headers` safe for evidence output: the `Authorization` value
    is replaced with `<scheme> <redacted>` so a reader can see a token was
    sent, and in what scheme, without the secret itself."""
    out = dict(headers)
    auth = out.get("Authorization")
    if auth:
        scheme = auth.split(" ", 1)[0] if " " in auth else "Bearer"
        out["Authorization"] = f"{scheme} <redacted>"
    return out


def request_evidence(method: str, url: str, headers: dict, body, response) -> dict:
    """A request/response record (bearer token redacted) that lets a finding
    be reproduced by re-sending the same request. Response body is truncated;
    callers needing the whole thing capture it separately."""
    return {
        "request_method": method,
        "request_url": url,
        "request_headers": redact_headers(headers),
        "request_body": body,
        "response_status": response.status,
        "response_body": (response.text or "")[:500],
    }


def parse_jsonrpc_message(text: str) -> dict | None:
    """The JSON-RPC object from an MCP POST response, or None. A server may
    answer a POST with `application/json` (the body is the object) or
    `text/event-stream` (the object is the `data:` payload of an SSE event),
    since we send `Accept: application/json, text/event-stream`. For an SSE
    body the last object seen is returned."""
    if not text:
        return None
    if text.lstrip()[:1] in "{[":
        try:
            doc = json.loads(text)
            return doc if isinstance(doc, dict) else None
        except Exception:
            return None
    # SSE: join each event's `data:` lines; keep the last that parses.
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
    """`scheme://netloc` with no path."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def tools_list_body(version: str = MCP_VERSION) -> dict:
    """JSON-RPC body for a tools/list request. `version` sets the protocol
    version in `params._meta`; it must match the `MCP-Protocol-Version`
    header (see `mcp_post_headers`)."""
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
    """JSON-RPC body for the MCP `initialize` handshake. Some servers reject a
    tools/list issued before initialize completes.

    `method` and `params.protocolVersion` must match the `Mcp-Method` and
    `MCP-Protocol-Version` headers from `_initialize_headers(ctx, version)`;
    a mismatch is rejected with `400` (`-32020`/`-32602`). Both sides derive
    from `version`."""
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
    """Headers for the `initialize` POST — the standard MCP POST headers for
    `version` and method `initialize`, plus the bearer token. Some servers
    require the mirrored `MCP-Protocol-Version` / `Mcp-Method` headers to be
    present and to match the body. Returns (headers, authorization_sent)."""
    headers = mcp_post_headers(version=version, method=_INIT_METHOD)
    if ctx.auth_session:
        headers.update(ctx.authed_headers())
        return headers, True
    return headers, False


@dataclass
class McpSession:
    """What a JSON-RPC POST to this target needs beyond a token, established by
    the `initialize` handshake and cached on `target.context['mcp_session']`.

    - `message_url`: where POSTs go. Differs from the configured URL only when
      that URL is an HTTP+SSE stream, whose first `endpoint` event names the
      real POST target.
    - `protocol_version`: the version `initialize` negotiated. Goes in the
      `MCP-Protocol-Version` header and the body `_meta` of every later
      request, which must agree.
    - `session_headers`: an `Mcp-Session-Id` to echo on later requests, if the
      server issued one.
    - `sse`: the message endpoint was resolved from an SSE `endpoint` event,
      so it replies asynchronously and a bare POST returns `202`.
    """
    message_url: str
    protocol_version: str = MCP_VERSION
    session_headers: dict = field(default_factory=dict)
    sse: bool = False
    initialized: bool = False
    accepted_async: bool = False
    error: Optional[str] = None
    evidence: dict = field(default_factory=dict)
    auth_method: str = "none"
    requested_scopes: list = field(default_factory=list)
    granted_scopes: list = field(default_factory=list)

    def summary(self) -> dict:
        """The subset of session state a check puts in its evidence."""
        return {"message_url": self.message_url, "initialized": self.initialized,
                "protocol_version": self.protocol_version, "error": self.error,
                "auth_method": self.auth_method,
                "requested_scopes": self.requested_scopes,
                "granted_scopes": self.granted_scopes}


def _is_sse_endpoint(url: str) -> bool:
    return urlparse(url).path.rstrip("/").endswith("/sse")


def _streamable_http_guess(url: str) -> str:
    """Best-effort Streamable-HTTP URL for a server configured with an
    HTTP+SSE stream URL: swap a trailing `/sse` for `/mcp`."""
    p = urlparse(url)
    return urlunparse(p._replace(path=re.sub(r"/sse/?$", "/mcp", p.path)))


def _resolve_message_url(target, ctx) -> tuple[str, Optional[str], bool]:
    """(url, note, via_sse_handshake) — where JSON-RPC POSTs for this target
    go. A Streamable-HTTP endpoint is used as-is. For an `…/sse` endpoint the
    real POST target comes from the stream's first `endpoint` event; if that
    handshake can't complete (e.g. the stream itself needs a token), fall back
    to the conventional `/mcp` path."""
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
    """The newest protocol version an `initialize` JSON-RPC error says the
    server supports, or None. The list may be under `data.supported`,
    `data.supportedVersions`, `data.versions`, `data` itself, or only in the
    message text. Versions are ISO dates, so the lexicographic max is newest."""
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
    """Record a rejected `initialize` (an HTTP error, or an HTTP 200 whose
    body carries a JSON-RPC error) into `evidence` and return
    (err_tag, best_supported_version). Keeps the full response body so the
    rejection is diagnosable from the report alone."""
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

    # Negotiate the protocol version: send the preferred one, and if the
    # server rejects it with an error naming the versions it supports, retry
    # once with the newest of those. Header and body are rebuilt together from
    # `init_version` each attempt so their versions stay in agreement.
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
    evidence["auth_method"] = auth_method_label(ctx)
    evidence.update(scope_evidence(ctx))
    evidence["protocol_negotiation"] = negotiation
    if resolve_note:
        evidence["endpoint_resolution"] = resolve_note

    # Unredacted dump of the initialize exchange to stderr for debugging a
    # rejected handshake; gated on MCP_AUDIT_DEBUG_TOKENS, never in evidence.
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

    # The last version actually sent; a successful initialize below replaces
    # it with the server's negotiated `result.protocolVersion`.
    protocol_version = init_version
    initialized = False
    accepted_async = False
    err: Optional[str] = None

    if r.error:
        err = f"initialize-request-error:{r.error}"
    elif r.status == 202:
        # HTTP+SSE transport: the reply is delivered on the SSE stream, which
        # this probe does not hold open across the POST. Accepted, not failed.
        accepted_async = True
        initialized = True
        err = "initialize-accepted-async-202"
    elif 200 <= r.status < 300:
        jerr = extract_jsonrpc_error(r.text)
        if jerr:
            # A JSON-RPC error carried inside a 200 rather than an HTTP error.
            err, best = _record_initialize_failure(evidence, r, headers, body)
            if best:
                protocol_version = best
            debug_log(f"initialize {message_url} -> 200 + JSON-RPC error; body: {r.text!r}")
        else:
            initialized = True
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
        # A session exists but the POST was still refused. Capture a GET with
        # the same token so the report shows whether it's the verb, headers,
        # or the token itself that the server rejects.
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
        # The spec requires notifications/initialized before any other request.
        note_headers = mcp_post_headers(version=protocol_version,
                                        method="notifications/initialized")
        note_headers, _ = maybe_authed_headers(ctx, note_headers)
        note_headers.update(session_headers)
        ctx.post(
            message_url,
            json_body={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=note_headers,
        )

    scopes = scope_evidence(ctx)
    session = McpSession(
        message_url=message_url,
        protocol_version=protocol_version,
        session_headers=session_headers,
        sse=via_sse,
        initialized=initialized,
        accepted_async=accepted_async,
        error=err,
        evidence=evidence,
        auth_method=auth_method_label(ctx),
        requested_scopes=scopes["requested_scopes"],
        granted_scopes=scopes["granted_scopes"],
    )
    target.context["mcp_session"] = session
    return session


def mcp_message_target(target, ctx, method: str = "tools/list") -> tuple[str, dict, bool, McpSession]:
    """(url, headers, used_auth, session) for a JSON-RPC POST probe: the
    resolved endpoint, POST headers at the negotiated protocol version, the
    `Mcp-Session-Id`, and the bearer token when `--auth` completed. Every
    JSON-RPC probe routes through here. A caller that also sends a body must
    build it with `session.protocol_version` so header and body agree."""
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


def differential_guard(check, evidence: dict, baseline, *mutated):
    """Shared early-exit for a differential check: a network failure -> ERROR,
    a 202 on any probe -> n/a (reply on an SSE stream), a non-2xx baseline ->
    n/a (never reached the tested behavior). Returns a CheckResult to return
    immediately, or None to proceed with the comparison."""
    from ...core.models import Rating
    if any(r.error for r in (baseline, *mutated)):
        return check._result(
            Rating.ERROR,
            "The baseline or mutated probe failed at the network level. "
            + EVIDENCE_NOTE,
            evidence,
        )
    if accepted_async(baseline, *mutated):
        return sse_async_na(check, evidence)
    return check.baseline_gate(baseline, evidence)


def _tools_from_response(r):
    """(tools, err) from a tools/list HTTP 200. A JSON-RPC error in the body
    is surfaced rather than passed off as an empty tool list."""
    doc = parse_jsonrpc_message(r.text)
    if doc is None:
        return None, f"parse-error:unparseable response body ({(r.text or '')[:120]!r})"
    err = doc.get("error")
    if isinstance(err, dict):
        return None, f"jsonrpc-error:{err.get('code')}:{err.get('message')}"
    tools = (doc.get("result") or {}).get("tools") or doc.get("tools") or []
    return tools, None


def _tools_list_request(target, ctx):
    """POST tools/list to the resolved endpoint at the negotiated version,
    record evidence, and return the Response."""
    url, headers, _used_auth, session = mcp_message_target(target, ctx, method="tools/list")
    body = tools_list_body(version=session.protocol_version)
    r = ctx.post(url, json_body=body, headers=headers)
    ctx.last_tools_list_evidence = request_evidence("POST", url, headers, body, r)
    if session.evidence:
        ctx.last_tools_list_evidence["initialize"] = session.evidence
    return r


def fetch_tools(target, ctx):
    """Send tools/list and return (tools, err). err is one of None,
    'stdio-no-http', 'auth-required', 'request-error:...', 'unexpected-status:N',
    'parse-error:...', 'jsonrpc-error:...', 'sse-async-not-captured'."""
    from ...core.models import Transport
    if target.transport == Transport.STDIO or not target.url:
        return None, "stdio-no-http"

    r = _tools_list_request(target, ctx)
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
    """Like fetch_tools, but with the bearer token attached. Falls back to the
    unauthenticated path when no session exists. A 401 here means a session
    was sent and refused — reported as 'unexpected-status:401', not
    'auth-required'."""
    from ...core.models import Transport
    if target.transport == Transport.STDIO or not target.url:
        return None, "stdio-no-http"
    if not ctx.auth_session:
        return fetch_tools(target, ctx)

    r = _tools_list_request(target, ctx)
    if r.error:
        return None, f"request-error:{r.error}"
    if r.status == 202:
        return None, "sse-async-not-captured"
    if r.status != 200:
        return None, f"unexpected-status:{r.status}"
    return _tools_from_response(r)


def obtained_without_auth_note(ctx) -> str:
    """Detail-text suffix for an Auth-method check whose data was obtained
    without a completed `--auth` session; empty when a session was used."""
    return "" if ctx.auth_session else " (obtained without authentication)"


def auth_method_label(ctx) -> str:
    """How the current session's token was obtained, for evidence:
    'static-token' (--token, no OAuth flow ran), 'preconfigured-client' (a
    real authorization-code flow, but against a pre-registered client_id
    the operator supplied instead of self-registering), 'dcr' (a real flow
    with a self-registered client — CIMD or Dynamic Client Registration),
    or 'none' (no session)."""
    if not ctx.auth_session:
        return "none"
    auth_mode = ctx.auth_session.probe_evidence.get("auth_mode")
    if auth_mode == "supplied-token":
        return "static-token"
    if auth_mode == "supplied-credentials":
        return "preconfigured-client"
    return "dcr"


def scope_evidence(ctx) -> dict:
    """`requested_scopes`/`granted_scopes` for a check's evidence, split from
    the session's space-separated scope strings into lists. Both are `[]`
    when there's no session, or when nothing was requested/granted — which
    is the default: mcp-audit requests no scope unless --scopes supplied
    one (see core/oauth.authenticate)."""
    session = ctx.auth_session
    requested = session.requested_scope.split() if session and session.requested_scope else []
    granted = session.scope.split() if session and session.scope else []
    return {"requested_scopes": requested, "granted_scopes": granted}


def decode_jwt_payload(token: str) -> dict | None:
    """Unverified decode of a JWT payload, to read informational claims like
    `aud`. Returns None for an opaque token; never used for a trust decision."""
    from joserfc.jws import extract_compact
    try:
        return json.loads(extract_compact(token.encode()).payload)
    except Exception:
        return None


def expected_issuer_from_well_known(well_known_url: str) -> str:
    """The OAuth issuer identifier for a well-known metadata URL: per RFC 8414
    §3.1 and OIDC Discovery §4.1, strip the well-known suffix and, in the
    path-insertion variant, keep the tenant path that followed it.

      https://as.example/.well-known/oauth-authorization-server         -> https://as.example
      https://as.example/.well-known/oauth-authorization-server/tenant1 -> https://as.example/tenant1
      https://as.example/tenant1/.well-known/openid-configuration       -> https://as.example/tenant1
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
