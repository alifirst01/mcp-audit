"""A real OAuth 2.1 + PKCE(S256) authorization-code flow — plus two faster
paths for servers that don't support self-registration or when the operator
already has credentials.

PKCE, token exchange, refresh, and JWT decoding use Authlib. MCP discovery,
DCR/CIMD registration, and the loopback listener are implemented here.

Entry point: `authenticate(target, ctx, auth_input=None)`. `auth_input` is an
`AuthInput` describing what credential material the operator supplied via the
CLI (`--token`, `--client-id`/`--client-secret`/`--client-metadata-url`, or
none). `AuthInput.mode()` resolves which of the three paths applies, checked
in priority order:

  1. **supplied-token** (`--token`): skip the OAuth flow entirely. The
     supplied token is used directly for every token-dependent check.
     Checks that test the interactive authorization flow itself (client
     registration, PKCE enforcement, redirect-URI validation, issuer
     validation) have nothing to test and report `n/a`.
  2. **supplied-credentials** (`--client-id`[/`--client-secret`] or
     `--client-metadata-url`): skip self-registration, run the full
     interactive flow with the given client identity. For servers that
     require pre-registration (e.g. GitHub) and don't support Dynamic
     Client Registration or Client ID Metadata Documents.
  3. **auto** (bare `--auth`): self-register via Client ID Metadata
     Documents (preferred) or Dynamic Client Registration (deprecated
     fallback), then run the full interactive flow.

On success `authenticate()` sets `ctx.auth_session`; on failure it sets
`ctx.auth_failure` with a human-readable reason so downstream checks can
report `ERROR` with that reason, and so the CLI can print the reason up
front — see `core/engine.py` and `cli.py`.

Secrets (`--client-secret`, `--token`) are never written into `evidence`
dicts, printed to the console, or included in JSON output — only the
resulting `access_token` is held in memory for the duration of the run
(tested in tests/test_oauth_no_secret_leak.py). Prefer the
`MCP_AUDIT_CLIENT_SECRET` / `MCP_AUDIT_TOKEN` environment variables over the
CLI flags where possible: command-line arguments are visible to other
processes on the same machine (e.g. via `ps`) and are recorded in shell
history.

See docs/METHODOLOGY.md "How the OAuth flow works" for the full writeup.
"""
from __future__ import annotations

import http.server
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

from .probe import AuthFailure, AuthSession, ProbeContext

LOOPBACK_TIMEOUT_SECONDS = 120

# RFC 7636 requires 43-128 characters; comfortably within range.
_PKCE_VERIFIER_LENGTH = 48


# ---------------------------------------------------------------------------
# Credential input (priority-ordered)
# ---------------------------------------------------------------------------

@dataclass
class AuthInput:
    """Credential material the operator supplied via the CLI for --auth.

    Fields are checked in priority order by `mode()`: a supplied token wins
    over supplied client credentials, which win over the fully-automatic
    path. Supplying more than one is not an error — the higher-priority
    input is used and the rest are ignored (the CLI warns about this).
    """
    token: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    client_metadata_url: Optional[str] = None

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
    callback's query string, then shuts itself down."""

    def __init__(self):
        self.result: Optional[dict] = None
        self._event = threading.Event()
        handler = self._make_handler()
        self._httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
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


def _client_auth(client: ClientCredentials) -> ClientAuth:
    """RFC 6749 §2.3 client authentication for the token endpoint: HTTP
    Basic when a client_secret is present (confidential client), otherwise
    client_id in the body only (public client)."""
    method = "client_secret_basic" if client.client_secret else "none"
    return ClientAuth(client.client_id, client.client_secret, auth_method=method)


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
    headers = {"Accept": "application/json"}
    uri, headers, body = _client_auth(client).prepare("POST", token_endpoint, headers, body)
    r = ctx.post_form(uri, data=body, headers=headers)
    if r.error or r.status != 200:
        raise RuntimeError(
            f"Token exchange failed: POST {token_endpoint} -> "
            f"{r.status or r.error}: {r.text[:300]}"
        )
    doc = r.json()
    access_token = doc.get("access_token")
    if not access_token:
        raise RuntimeError(f"Token response from {token_endpoint} carried no access_token.")
    return AuthSession(
        access_token=access_token,
        token_type=doc.get("token_type", "Bearer"),
        refresh_token=doc.get("refresh_token"),
        expires_in=doc.get("expires_in"),
        scope=doc.get("scope"),
        requested_scope=requested_scope,
        issuer=issuer_from_callback or as_metadata.get("issuer"),
        resource=resource,
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
    headers = {"Accept": "application/json"}
    uri, headers, body = _client_auth(client).prepare("POST", token_endpoint, headers, body)
    r = ctx.post_form(uri, data=body, headers=headers)
    if r.error or r.status != 200:
        raise RuntimeError(
            f"Refresh failed: POST {token_endpoint} -> {r.status or r.error}: {r.text[:300]}"
        )
    doc = r.json()
    return AuthSession(
        access_token=doc.get("access_token", session.access_token),
        token_type=doc.get("token_type", session.token_type),
        refresh_token=doc.get("refresh_token", session.refresh_token),
        expires_in=doc.get("expires_in"),
        scope=doc.get("scope", session.scope),
        requested_scope=session.requested_scope,
        issuer=session.issuer,
        resource=session.resource,
        probe_evidence={**session.probe_evidence, "refresh_rotated_token": doc.get("refresh_token") != session.refresh_token},
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
    prm_doc = target.context.get("prm_doc")
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
        loopback = LoopbackServer()

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
        requested_scope = " ".join((prm_doc or {}).get("scopes_supported", [])) or None

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
        # Kept for downstream checks to build a genuine baseline authorization
        # request from — same client, same registered redirect, a valid
        # code_challenge — rather than a bare crafted one.
        session.probe_evidence["registered_redirect_uri"] = loopback.redirect_uri
        session.probe_evidence["pkce_challenge"] = challenge
        ctx.auth_session = session
        print(f"  Authorized.\n")

    except Exception as e:
        ctx.auth_failure = AuthFailure(reason=str(e), stage="flow")
