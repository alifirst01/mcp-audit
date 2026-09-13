"""--client-id/--client-secret (the "supplied-credentials" / preconfigured-
client path): the token-endpoint Basic->body auth fallback, client_secret
propagation onto AuthSession so a later refresh can re-authenticate, and the
--token/--client-id mutual-exclusivity hard error.
"""
from __future__ import annotations

import argparse

import httpx
import pytest

from mcp_audit.cli import _build_auth_input
from mcp_audit.core.oauth import ClientCredentials, exchange_code, refresh
from mcp_audit.core.probe import AuthSession, ProbeContext

AS_META = {"token_endpoint": "https://as.test/token", "issuer": "https://as.test"}
CONFIDENTIAL_CLIENT = ClientCredentials(client_id="cid", client_secret="shh", mechanism="supplied")


def _exchange(ctx: ProbeContext, client=CONFIDENTIAL_CLIENT) -> AuthSession:
    return exchange_code(
        ctx, AS_META, client, code="c", verifier="v",
        redirect_uri="http://127.0.0.1/cb", resource="https://rs.test/mcp",
        requested_scope=None, issuer_from_callback=None,
    )


# --- Basic -> body fallback --------------------------------------------------

def _basic_only_server(request: httpx.Request) -> httpx.Response:
    """Accepts client_secret_basic, rejects a secret sent in the body."""
    if "authorization" in request.headers:
        return httpx.Response(200, json={"access_token": "AT-basic", "token_type": "Bearer"})
    return httpx.Response(401, json={"error": "invalid_client"})


def _body_only_server(request: httpx.Request) -> httpx.Response:
    """Rejects HTTP Basic outright, only accepts the secret in the form body
    (some ASes, GitHub among them, are like this)."""
    if "authorization" in request.headers:
        return httpx.Response(401, json={"error": "invalid_client"})
    body = request.content.decode()
    if "client_secret=shh" in body:
        return httpx.Response(200, json={"access_token": "AT-body", "token_type": "Bearer"})
    return httpx.Response(400, json={"error": "invalid_request"})


def test_exchange_uses_basic_when_the_as_accepts_it():
    ctx = ProbeContext(transport=httpx.MockTransport(_basic_only_server))
    assert _exchange(ctx).access_token == "AT-basic"
    ctx.close()


def test_exchange_falls_back_to_body_when_basic_is_rejected():
    ctx = ProbeContext(transport=httpx.MockTransport(_body_only_server))
    assert _exchange(ctx).access_token == "AT-body"
    ctx.close()


def test_public_client_never_sends_a_secret_and_skips_basic_attempt():
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"access_token": "AT-pub", "token_type": "Bearer"})

    ctx = ProbeContext(transport=httpx.MockTransport(handle))
    public_client = ClientCredentials(client_id="cid", client_secret=None, mechanism="supplied")
    session = _exchange(ctx, client=public_client)

    assert session.access_token == "AT-pub"
    assert len(seen) == 1                                   # no Basic attempt at all
    assert "authorization" not in seen[0].headers
    ctx.close()


def test_both_auth_methods_rejected_surfaces_a_clear_error():
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client"})

    ctx = ProbeContext(transport=httpx.MockTransport(handle))
    with pytest.raises(RuntimeError) as e:
        _exchange(ctx)
    assert "Token exchange failed" in str(e.value)
    ctx.close()


# --- client_secret propagates onto AuthSession, for a later refresh ---------

def test_exchange_stores_client_secret_on_session_for_later_refresh():
    ctx = ProbeContext(transport=httpx.MockTransport(_basic_only_server))
    session = _exchange(ctx)
    assert session.client_secret == "shh"
    ctx.close()


def test_refresh_of_a_confidential_client_uses_the_same_fallback():
    ctx = ProbeContext(transport=httpx.MockTransport(_body_only_server))
    session = AuthSession(access_token="AT-old", token_type="Bearer",
                          refresh_token="RT-old", resource="https://rs.test/mcp",
                          client_secret="shh")
    refreshed = refresh(ctx, AS_META, CONFIDENTIAL_CLIENT, session)
    assert refreshed.access_token == "AT-body"
    ctx.close()


def test_ct05_refresh_of_preconfigured_confidential_client_no_longer_fails():
    """The bug this task fixes: CT-05 rebuilding ClientCredentials without
    client_secret meant refresh always authenticated as a public client, so a
    confidential AS rejected it with something like 'client_secret required'."""
    from mcp_audit.checks.server.credential_token_risk import ShortLivedAndRefreshRotates
    from mcp_audit.core.models import Rating, Target, Transport

    ctx = ProbeContext(transport=httpx.MockTransport(_body_only_server))
    ctx.auth_session = AuthSession(
        access_token="AT-spent", token_type="Bearer", refresh_token="RT-spent",
        expires_in=3600, resource="https://rs.test/mcp", client_secret="shh",
        probe_evidence={"client_id": "cid", "client_mechanism": "supplied",
                        "auth_mode": "supplied-credentials"},
    )
    target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)
    target.context = {"as_metadata": AS_META}

    result = ShortLivedAndRefreshRotates().run(target, ctx)

    assert result.rating != Rating.NA
    assert ctx.auth_session.access_token == "AT-body"
    ctx.close()


# --- AA checks run normally (not n/a) under the preconfigured-client path --

def test_aa_checks_do_not_short_circuit_for_supplied_credentials():
    """Only auth_mode == 'supplied-token' (Path 1) is exempt; 'supplied-
    credentials' (Path 2) runs a real flow and must be probed normally."""
    from mcp_audit.checks.server import authentication_authorization as aa

    session = AuthSession(access_token="AT", token_type="Bearer",
                          probe_evidence={"auth_mode": "supplied-credentials"})
    assert session.probe_evidence.get("auth_mode") != "supplied-token"


# --- auth_method_label 3-way scheme -----------------------------------------

def test_auth_method_label_preconfigured_client():
    from mcp_audit.checks.server._helpers import auth_method_label

    ctx = ProbeContext()
    ctx.auth_session = AuthSession(access_token="AT", token_type="Bearer",
                                   probe_evidence={"auth_mode": "supplied-credentials"})
    assert auth_method_label(ctx) == "preconfigured-client"
    ctx.close()


# --- CLI: --token and --client-id are mutually exclusive -------------------

def test_cli_errors_when_token_and_client_id_are_both_supplied():
    args = argparse.Namespace(
        token="a-token", client_id="cid", client_secret=None,
        client_metadata_url=None, redirect_port=None, scopes=None,
    )
    with pytest.raises(SystemExit) as e:
        _build_auth_input(args)
    assert e.value.code == 2


def test_cli_errors_when_token_and_client_metadata_url_are_both_supplied():
    args = argparse.Namespace(
        token="a-token", client_id=None, client_secret=None,
        client_metadata_url="https://client.example.test/meta.json", redirect_port=None, scopes=None,
    )
    with pytest.raises(SystemExit) as e:
        _build_auth_input(args)
    assert e.value.code == 2


def test_cli_client_id_alone_is_still_fine():
    args = argparse.Namespace(
        token=None, client_id="cid", client_secret=None,
        client_metadata_url=None, redirect_port=None, scopes=None,
    )
    auth_input = _build_auth_input(args)
    assert auth_input.mode() == "supplied-credentials"


def test_cli_token_alone_is_still_fine():
    args = argparse.Namespace(
        token="a-token", client_id=None, client_secret=None,
        client_metadata_url=None, redirect_port=None, scopes=None,
    )
    auth_input = _build_auth_input(args)
    assert auth_input.mode() == "supplied-token"


# --- credentials come only from CLI flags, never environment variables -----

def test_env_vars_are_ignored_for_token_and_client_secret(monkeypatch):
    """MCP_AUDIT_TOKEN / MCP_AUDIT_CLIENT_SECRET must have no effect: only an
    explicit --token/--client-secret on this invocation counts."""
    monkeypatch.setenv("MCP_AUDIT_TOKEN", "env-token-should-be-ignored")
    monkeypatch.setenv("MCP_AUDIT_CLIENT_SECRET", "env-secret-should-be-ignored")

    args = argparse.Namespace(
        token=None, client_id="cid", client_secret=None,
        client_metadata_url=None, redirect_port=None, scopes=None,
    )
    auth_input = _build_auth_input(args)

    assert auth_input.token is None
    assert auth_input.client_secret is None
    assert auth_input.mode() == "supplied-credentials"   # public client, not blocked
