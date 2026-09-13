"""OAuth 2.1 + PKCE(S256) authorization-code flow, plus two faster paths.

Entry point `authenticate(target, ctx, auth_input=None)`. `AuthInput.mode()`
picks a path in priority order:

  1. supplied-token (`--token`): no OAuth flow; the token is used directly.
     Checks that exercise the authorization flow itself report `n/a`.
  2. supplied-credentials (`--client-id`/`--client-secret` or
     `--client-metadata-url`): the full interactive flow with a
     pre-registered client, for servers without DCR or CIMD.
  3. auto (bare `--auth`): self-register via CIMD (preferred) or DCR, then
     run the interactive flow.

On success it sets `ctx.auth_session`; on failure it sets `ctx.auth_failure`
with a reason (never raises) that downstream checks and the CLI surface.

For the two paths that run a real authorization request (2 and 3), the
`scope` parameter is omitted by default — mcp-audit requests no scope at
all unless `--scopes` supplies one, so the AS applies its own default grant.
This is a minimal-privilege default.

Secrets never reach evidence, the console, or JSON output — only the
resulting `access_token` is held in memory (tests/test_oauth_no_secret_leak.py).
Prefer `MCP_AUDIT_CLIENT_SECRET` / `MCP_AUDIT_TOKEN` over the CLI flags, which
are visible via `ps` and shell history.
"""
from __future__ import annotations

import http.server
import json as _json
import secrets
import threading
import urllib.parse
import webbrowser
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs

from authlib.common.security import generate_token
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.rfc6749.parameters import prepare_token_request
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from .probe import AuthFailure, AuthSession, ProbeContext, debug_log, debug_tokens_enabled

LOOPBACK_TIMEOUT_SECONDS = 120


def _debug_token_response(stage: str, endpoint: str, doc, chosen: str) -> None:
    """Unredacted dump of a token-endpoint response to stderr, gated on
    MCP_AUDIT_DEBUG_TOKENS. Never reaches evidence or report files."""
    if not debug_tokens_enabled():
        return
    keys = sorted(doc) if isinstance(doc, dict) else f"<not a JSON object: {type(doc).__name__}>"
    debug_log(f"{stage}: {endpoint}")
    debug_log(f"{stage}: response keys = {keys}")
    debug_log(f"{stage}: full response JSON = {_json.dumps(doc) if isinstance(doc, dict) else doc!r}")
    debug_log(f"{stage}: bearer=access_token value={chosen!r} len={len(chosen)}")


# RFC 7636 requires the code verifier to be 43-128 characters.
_PKCE_VERIFIER_LENGTH = 48


# ---------------------------------------------------------------------------
# Credential input (priority-ordered)
# ---------------------------------------------------------------------------

@dataclass
class AuthInput:
    """Credential material the operator supplied via the CLI for --auth.

    `mode()` picks the path: a supplied token, supplied client credentials,
    or (neither) the fully-automatic path. A token and client credentials
    together are mutually exclusive — they authenticate a run in
    fundamentally different ways (skip the flow entirely vs. run it with a
    pre-registered client) — so the CLI (`_build_auth_input`) rejects that
    combination outright rather than silently picking one.
    """
    token: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    client_metadata_url: Optional[str] = None
    # Fixed port for the OAuth loopback listener (see LoopbackServer). None
    # (the default) keeps the OS-assigned ephemeral port, unchanged.
    redirect_port: Optional[int] = None
    # Space-separated scope string for the authorization request (--scopes).
    # None (the default) requests no scope at all — the AS applies its own
    # default grant
    scopes: Optional[str] = None

    def mode(self) -> str:
        if self.token:
            return "supplied-token"
        if self.client_id or self.client_metadata_url:
            return "supplied-credentials"
        return "auto"


# ---------------------------------------------------------------------------
# PKCE
# ---------------------------------------------------------------------------

def pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) per RFC 7636, S256 method."""
    verifier = generate_token(_PKCE_VERIFIER_LENGTH)
    challenge = create_s256_code_challenge(verifier)
    return verifier, challenge


# ---------------------------------------------------------------------------
# Client registration
# ---------------------------------------------------------------------------

@dataclass
class ClientCredentials:
    client_id: str
    client_secret: Optional[str] = None
    mechanism: str = ""  # "dcr", "cimd", or "supplied"


def register_client(
    ctx: ProbeContext,
    as_metadata: dict,
    redirect_uri: str,
    client_metadata_url: Optional[str] = None,
) -> ClientCredentials:
    """Self-register a client_id (the "auto" path — see AuthInput.mode()).

    Preference order:
      1. CIMD, if the operator supplied a self-hosted --client-metadata-url and the
         AS advertises client_id_metadata_document_supported.
      2. Dynamic Client Registration (RFC 7591) against registration_endpoint.
    Raises RuntimeError with an explanatory message if neither is available —
    in that case the operator needs the supplied-credentials path instead.
    """
    if client_metadata_url and as_metadata.get("client_id_metadata_document_supported"):
        return ClientCredentials(client_id=client_metadata_url, mechanism="cimd")

    reg_endpoint = as_metadata.get("registration_endpoint")
    if not reg_endpoint:
        if client_metadata_url:
            raise RuntimeError(
                "AS does not advertise client_id_metadata_document_supported, so the "
                "provided --client-metadata-url cannot be used, and no "
                "registration_endpoint (DCR) is advertised either."
            )
        raise RuntimeError(
            "Authorization Server advertises neither a registration_endpoint (Dynamic "
            "Client Registration) nor client_id_metadata_document_supported (Client ID "
            "Metadata Documents), so mcp-audit cannot self-register a client. This "
            "server needs pre-registered credentials — pre-register an OAuth app "
            "yourself and re-run with --client-id (and --client-secret if the app "
            "is confidential), or --client-metadata-url if you host a Client ID "
            "Metadata Document."
        )

    body = {
        "client_name": "mcp-audit",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",  # public client (loopback, PKCE)
    }
    r = ctx.post(reg_endpoint, json_body=body, headers={"Accept": "application/json"})
    if r.error or r.status not in (200, 201):
        raise RuntimeError(
            f"Dynamic Client Registration failed: POST {reg_endpoint} -> "
            f"{r.status or r.error}"
        )
    doc = r.json()
    client_id = doc.get("client_id")
    if not client_id:
        raise RuntimeError(
            f"Dynamic Client Registration response from {reg_endpoint} carried no client_id."
        )
    return ClientCredentials(
        client_id=client_id,
        client_secret=doc.get("client_secret"),
        mechanism="dcr",
    )


# ---------------------------------------------------------------------------
# Loopback redirect listener
# ---------------------------------------------------------------------------

class LoopbackServer:
    """A one-shot HTTP server on 127.0.0.1 that captures the authorization
    callback's query string, then shuts itself down.

    `port=0` (the default) binds an OS-assigned ephemeral port, so the
    redirect URI's port varies between runs — fine for servers that honor
    RFC 8252's loopback-any-port matching. A fixed `port` gives a stable
    redirect URI (`http://127.0.0.1:<port>/callback`) across runs, for
    providers that require an exact pre-registered redirect URI and don't
    treat a varying port as a match (e.g. GitHub OAuth Apps). If that fixed
    port is already in use, this raises immediately rather than silently
    falling back to a random one — a silent fallback would register one
    redirect_uri and then send the browser to a different one, a mismatch
    the operator would otherwise have to debug blind."""

    def __init__(self, port: int = 0):
        self.result: Optional[dict] = None
        self._event = threading.Event()
        handler = self._make_handler()
        try:
            self._httpd = http.server.HTTPServer(("127.0.0.1", port), handler)
        except OSError as e:
            if port:
                raise RuntimeError(
                    f"Could not bind the OAuth loopback listener to "
                    f"127.0.0.1:{port} (--redirect-port {port}): {e}. Free "
                    f"that port, choose a different --redirect-port, or omit "
                    f"the flag to use an OS-assigned port."
                ) from e
            raise
        self.port = self._httpd.server_address[1]
        self.redirect_uri = f"http://127.0.0.1:{self.port}/callback"

    def _make_handler(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urlparse(self.path)
                outer.result = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h3>mcp-audit</h3>"
                    b"<p>Authorization received. You can close this tab and return "
                    b"to the terminal.</p></body></html>"
                )
                outer._event.set()

            def log_message(self, *args):
                pass  # silence default stderr logging

        return Handler

    def wait_for_callback(self, timeout: float = LOOPBACK_TIMEOUT_SECONDS) -> Optional[dict]:
        thread = threading.Thread(target=self._httpd.handle_request, daemon=True)
        thread.start()
        got_it = self._event.wait(timeout)
        try:
            self._httpd.server_close()
        except Exception:
            pass
        return self.result if got_it else None


# ---------------------------------------------------------------------------
# Authorize URL
# ---------------------------------------------------------------------------

def build_authorize_url(
    as_metadata: dict,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    resource: str,
    scope: Optional[str] = None,
) -> str:
    endpoint = as_metadata["authorization_endpoint"]
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        # RFC 8707 — sent unconditionally per MCP Auth spec, regardless of
        # whether the AS advertises support for it.
        "resource": resource,
    }
    if scope:
        params["scope"] = scope
    return f"{endpoint}?{urlencode(params)}"


def _client_auth(client: ClientCredentials, method: str) -> ClientAuth:
    """RFC 6749 §2.3 client authentication for the token endpoint, under one
    specific method: `client_secret_basic` (HTTP Basic), `client_secret_post`
    (secret in the form body), or `none` (client_id in the body only, for a
    public client)."""
    return ClientAuth(client.client_id, client.client_secret, auth_method=method)


def _token_request(ctx: ProbeContext, token_endpoint: str, client: ClientCredentials, body: str):
    """POST a prepared token-request `body`, authenticating as `client`.

    A public client (no secret) just sends client_id in the body. A
    confidential client tries HTTP Basic first — RFC 6749 §2.3.1's preferred
    method — then, if the AS rejects it, retries once with the secret in the
    form body instead: some ASes only accept one or the other, and neither
    the spec nor discovery metadata reliably says which in advance. `body`
    is a plain query string (untouched by either attempt), so reusing it
    across both attempts is safe.
    """
    if not client.client_secret:
        uri, headers, form = _client_auth(client, "none").prepare(
            "POST", token_endpoint, {"Accept": "application/json"}, body)
        return ctx.post_form(uri, data=form, headers=headers)

    uri, basic_headers, basic_body = _client_auth(client, "client_secret_basic").prepare(
        "POST", token_endpoint, {"Accept": "application/json"}, body)
    r = ctx.post_form(uri, data=basic_body, headers=basic_headers)
    if not r.error and r.status == 200:
        return r

    uri, post_headers, post_body = _client_auth(client, "client_secret_post").prepare(
        "POST", token_endpoint, {"Accept": "application/json"}, body)
    r2 = ctx.post_form(uri, data=post_body, headers=post_headers)
    if not r2.error and r2.status == 200:
        return r2
    # Neither worked — surface whichever response is more informative (a
    # real HTTP response over a transport-level error).
    return r if not r.error else r2


# ---------------------------------------------------------------------------
# Token exchange / refresh
# ---------------------------------------------------------------------------

def exchange_code(
    ctx: ProbeContext,
    as_metadata: dict,
    client: ClientCredentials,
    code: str,
    verifier: str,
    redirect_uri: str,
    resource: str,
    requested_scope: Optional[str],
    issuer_from_callback: Optional[str],
) -> AuthSession:
    token_endpoint = as_metadata["token_endpoint"]
    body = prepare_token_request(
        "authorization_code",
        code=code,
        redirect_uri=redirect_uri,
        code_verifier=verifier,
        resource=resource,
    )
    r = _token_request(ctx, token_endpoint, client, body)
    if r.error or r.status != 200:
        raise RuntimeError(
            f"Token exchange failed: POST {token_endpoint} -> "
            f"{r.status or r.error}: {r.text[:300]}"
        )
    doc = r.json()
    # The bearer is the `access_token` field only — never id_token or
    # refresh_token. Strip any surrounding whitespace.
    access_token = (doc.get("access_token") or "").strip() if isinstance(doc, dict) else ""
    _debug_token_response("token-exchange", token_endpoint, doc, access_token)
    if not access_token:
        present = sorted(doc) if isinstance(doc, dict) else type(doc).__name__
        raise RuntimeError(
            f"Token response from {token_endpoint} has no usable 'access_token' "
            f"(fields present: {present}). mcp-audit will not fall back to "
            f"id_token or refresh_token."
        )
    return AuthSession(
        access_token=access_token,
        token_type=(doc.get("token_type") or "Bearer"),
        refresh_token=doc.get("refresh_token") or None,
        expires_in=doc.get("expires_in"),
        scope=doc.get("scope"),
        requested_scope=requested_scope,
        issuer=issuer_from_callback or as_metadata.get("issuer"),
        resource=resource,
        client_secret=client.client_secret,
    )


def refresh(ctx: ProbeContext, as_metadata: dict, client: ClientCredentials,
            session: AuthSession) -> AuthSession:
    if not session.refresh_token:
        raise RuntimeError("No refresh_token on the current session.")
    token_endpoint = as_metadata["token_endpoint"]
    body = prepare_token_request(
        "refresh_token",
        refresh_token=session.refresh_token,
        resource=session.resource,
    )
    r = _token_request(ctx, token_endpoint, client, body)
    if r.error or r.status != 200:
        raise RuntimeError(
            f"Refresh failed: POST {token_endpoint} -> {r.status or r.error}: {r.text[:300]}"
        )
    doc = r.json()
    # Fall back to the current values with `or`, not `dict.get(k, default)`:
    # a response with an explicit `"access_token": ""` must not overwrite a
    # still-valid token with an empty one.
    new_access = (doc.get("access_token") or "").strip() if isinstance(doc, dict) else ""
    new_refresh = (doc.get("refresh_token") or "") or None
    _debug_token_response("token-refresh", token_endpoint, doc, new_access)
    rotated = bool(new_refresh) and new_refresh != session.refresh_token
    return AuthSession(
        access_token=new_access or session.access_token,
        token_type=(doc.get("token_type") or session.token_type),
        refresh_token=new_refresh or session.refresh_token,
        expires_in=doc.get("expires_in"),
        scope=(doc.get("scope") or session.scope),
        requested_scope=session.requested_scope,
        issuer=session.issuer,
        resource=session.resource,
        client_secret=session.client_secret,
        probe_evidence={
            **session.probe_evidence,
            "refresh_rotated_token": rotated,
            "refresh_returned_new_access_token": bool(new_access),
        },
    )


# ---------------------------------------------------------------------------
# Path 1: supplied token — no flow, no network calls
# ---------------------------------------------------------------------------

def _authenticate_with_supplied_token(target, ctx: ProbeContext, auth_input: AuthInput) -> None:
    session = AuthSession(
        access_token=auth_input.token,
        token_type="Bearer",
        resource=target.url.rstrip("/") if target.url else None,
        probe_evidence={"auth_mode": "supplied-token"},
    )
    ctx.auth_session = session
    print(
        "\n  Using the supplied --token directly — no OAuth flow was run. "
        "Checks that test the authorization flow itself (client "
        "registration, PKCE enforcement, redirect-URI validation, issuer "
        "validation) will report n/a; checks about the token and the "
        "server's tools will run normally.\n"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def authenticate(target, ctx: ProbeContext, auth_input: Optional[AuthInput] = None) -> None:
    """Run the appropriate credential path and set ctx.auth_session or
    ctx.auth_failure. Never raises."""
    auth_input = auth_input or AuthInput()
    mode = auth_input.mode()

    if mode == "supplied-token":
        _authenticate_with_supplied_token(target, ctx, auth_input)
        return

    as_metadata = target.context.get("as_metadata")
    if not as_metadata:
        ctx.auth_failure = AuthFailure(
            reason="No Authorization Server metadata discovered — the discovery "
                   "checks (CD-01..CD-07) did not find a usable AS, so there is "
                   "nothing to authorize against.",
            stage="discovery",
        )
        return
    if "authorization_endpoint" not in as_metadata or "token_endpoint" not in as_metadata:
        ctx.auth_failure = AuthFailure(
            reason="Authorization Server metadata is missing authorization_endpoint "
                   "or token_endpoint.",
            stage="discovery",
        )
        return

    try:
        loopback = LoopbackServer(port=auth_input.redirect_port or 0)
    except RuntimeError as e:
        ctx.auth_failure = AuthFailure(reason=str(e), stage="redirect-port")
        return

    print(
        f"\n  Redirect URI: {loopback.redirect_uri}"
        + f" (fixed via --redirect-port {auth_input.redirect_port})"
    )

    try:
        if mode == "supplied-credentials":
            client_id = auth_input.client_id or auth_input.client_metadata_url
            client = ClientCredentials(
                client_id=client_id,
                client_secret=auth_input.client_secret,
                mechanism="supplied",
            )
        else:
            client = register_client(
                ctx, as_metadata, loopback.redirect_uri, auth_input.client_metadata_url
            )

        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(16)
        resource = target.url.rstrip("/") if target.url else ""
        # Minimal by default: request no scope at all unless the operator
        # opts in with --scopes. The AS then applies its own default grant.
        # Applies uniformly to both the DCR and preconfigured-client paths —
        # this is their one shared code path below.
        requested_scope = auth_input.scopes or None

        authorize_url = build_authorize_url(
            as_metadata, client.client_id, loopback.redirect_uri, state, challenge,
            resource, requested_scope,
        )

        print(f"\n  Opening browser to authorize against "
              f"{as_metadata.get('issuer', urllib.parse.urlparse(as_metadata['authorization_endpoint']).netloc)} "
              f"({'using the supplied client credentials' if mode == 'supplied-credentials' else 'self-registering a client'}) ...")
        print(f"  If it doesn't open automatically, visit:\n  {authorize_url}")
        print(f"  Waiting on {loopback.redirect_uri} (timeout {LOOPBACK_TIMEOUT_SECONDS}s)...")
        webbrowser.open(authorize_url)

        callback = loopback.wait_for_callback()
        if callback is None:
            ctx.auth_failure = AuthFailure(
                reason=f"Timed out after {LOOPBACK_TIMEOUT_SECONDS}s waiting for the "
                       f"browser to redirect back to {loopback.redirect_uri}.",
                stage="consent",
            )
            return
        if "error" in callback:
            ctx.auth_failure = AuthFailure(
                reason=f"Authorization Server returned an error: "
                       f"{callback.get('error')} — {callback.get('error_description', '')}",
                stage="authorize",
            )
            return
        if callback.get("state") != state:
            ctx.auth_failure = AuthFailure(
                reason="Callback 'state' did not match the value sent in the "
                       "authorization request — possible CSRF/mix-up, aborting.",
                stage="authorize",
            )
            return
        code = callback.get("code")
        if not code:
            ctx.auth_failure = AuthFailure(
                reason="Callback carried no authorization code.",
                stage="authorize",
            )
            return

        session = exchange_code(
            ctx, as_metadata, client, code, verifier, loopback.redirect_uri,
            resource, requested_scope, callback.get("iss"),
        )
        session.probe_evidence["callback_iss"] = callback.get("iss")
        session.probe_evidence["client_mechanism"] = client.mechanism
        session.probe_evidence["client_id"] = client.client_id
        session.probe_evidence["auth_mode"] = mode
        # Kept so AA-02/AA-03 can build a real baseline authorization request
        # (same client, registered redirect, valid challenge) to mutate.
        session.probe_evidence["registered_redirect_uri"] = loopback.redirect_uri
        session.probe_evidence["pkce_challenge"] = challenge
        ctx.auth_session = session
        print("  Authorized.\n")
        _debug_fresh_token_sanity_get(ctx, target)

    except Exception as e:
        ctx.auth_failure = AuthFailure(reason=str(e), stage="flow")


def _debug_fresh_token_sanity_get(ctx: ProbeContext, target) -> None:
    """One authenticated GET with the just-issued token, logged to stderr
    (gated on MCP_AUDIT_DEBUG_TOKENS). Distinguishes a token that is bad at
    issuance from one a later probe invalidates."""
    if not debug_tokens_enabled() or not target.url:
        return
    try:
        g = ctx.get(target.url, headers=ctx.authed_headers(
            {"Accept": "application/json, text/event-stream"}))
        debug_log(f"fresh-token sanity GET {target.url} -> {g.status} {(g.text or '')[:200]!r}")
    except Exception as e:
        debug_log(f"fresh-token sanity GET raised: {e!r}")
