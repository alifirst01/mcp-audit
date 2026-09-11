"""Token-endpoint response parsing (core/oauth.exchange_code / refresh) and
the empty-bearer guard (core/probe.authed_headers).

Regression cover for: an issued token being rejected because the parser
stored the wrong field, an empty value, or a refresh response poisoned the
session.
"""
from __future__ import annotations

import httpx
import pytest

from mcp_audit.core import oauth
from mcp_audit.core.oauth import ClientCredentials, exchange_code, refresh
from mcp_audit.core.probe import AuthSession, ProbeContext

AS_META = {"token_endpoint": "https://as.test/token", "issuer": "https://as.test"}
CLIENT = ClientCredentials(client_id="cid", client_secret=None, mechanism="dcr")


def _ctx(token_json: dict, status: int = 200) -> ProbeContext:
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=token_json)
    return ProbeContext(transport=httpx.MockTransport(handle))


def _exchange(ctx: ProbeContext) -> AuthSession:
    return exchange_code(
        ctx, AS_META, CLIENT, code="c", verifier="v",
        redirect_uri="http://127.0.0.1/cb", resource="https://rs.test/mcp",
        requested_scope=None, issuer_from_callback=None,
    )


# --- exchange_code -----------------------------------------------------------

def test_exchange_uses_access_token_field_only():
    ctx = _ctx({"access_token": "AT-good", "id_token": "ID-nope",
                "refresh_token": "RT", "token_type": "Bearer"})
    s = _exchange(ctx)
    assert s.access_token == "AT-good"          # not id_token, not refresh_token
    assert s.refresh_token == "RT"


def test_exchange_strips_whitespace_from_token():
    ctx = _ctx({"access_token": "  AT-padded\n", "token_type": "Bearer"})
    assert _exchange(ctx).access_token == "AT-padded"


def test_exchange_rejects_response_with_no_access_token():
    ctx = _ctx({"id_token": "ID", "token_type": "Bearer"})
    with pytest.raises(RuntimeError) as e:
        _exchange(ctx)
    assert "access_token" in str(e.value) and "id_token" in str(e.value)


def test_exchange_rejects_empty_access_token():
    ctx = _ctx({"access_token": "   ", "token_type": "Bearer"})
    with pytest.raises(RuntimeError):
        _exchange(ctx)


# --- refresh ---------------------------------------------------------------

def _session() -> AuthSession:
    return AuthSession(access_token="AT-old", token_type="Bearer",
                       refresh_token="RT-old", resource="https://rs.test/mcp")


def test_refresh_adopts_new_access_token_and_flags_it():
    ctx = _ctx({"access_token": "AT-new", "refresh_token": "RT-new", "token_type": "Bearer"})
    s = refresh(ctx, AS_META, CLIENT, _session())
    assert s.access_token == "AT-new"
    assert s.refresh_token == "RT-new"
    assert s.probe_evidence["refresh_rotated_token"] is True
    assert s.probe_evidence["refresh_returned_new_access_token"] is True


def test_refresh_with_empty_access_token_does_not_poison_session():
    # A response that rotates only the refresh token and returns "" for the
    # access token must NOT overwrite the still-valid current access token.
    ctx = _ctx({"access_token": "", "refresh_token": "RT-new", "token_type": "Bearer"})
    s = refresh(ctx, AS_META, CLIENT, _session())
    assert s.access_token == "AT-old"
    assert s.refresh_token == "RT-new"
    assert s.probe_evidence["refresh_returned_new_access_token"] is False


def test_refresh_missing_access_token_key_falls_back():
    ctx = _ctx({"refresh_token": "RT-new"})
    s = refresh(ctx, AS_META, CLIENT, _session())
    assert s.access_token == "AT-old"


# --- authed_headers empty-bearer guard -----------------------------------

def test_authed_headers_refuses_empty_bearer():
    ctx = ProbeContext()
    ctx.auth_session = AuthSession(access_token="   ", token_type="Bearer")
    with pytest.raises(RuntimeError) as e:
        ctx.authed_headers()
    assert "empty" in str(e.value).lower()
    ctx.close()


def test_authed_headers_emits_bearer_with_token():
    ctx = ProbeContext()
    ctx.auth_session = AuthSession(access_token="AT-xyz", token_type="bearer")
    assert ctx.authed_headers()["Authorization"] == "Bearer AT-xyz"
    ctx.close()


# --- CT-05 must not leave the run holding a spent token -------------------

def test_ct05_adopts_refreshed_session_so_later_checks_use_the_live_token():
    """On strict-rotation servers (Neon/Stripe) using the refresh token
    invalidates the access token it replaces. CT-05 must swap ctx.auth_session
    to the freshly-issued one so initialize / tools/list / transport probes
    that run afterwards don't send a dead token."""
    from mcp_audit.checks.server.credential_token_risk import ShortLivedAndRefreshRotates
    from mcp_audit.core.models import Target, Transport

    ctx = _ctx({"access_token": "AT-fresh", "refresh_token": "RT-fresh", "token_type": "Bearer"})
    ctx.auth_session = AuthSession(
        access_token="AT-spent", token_type="Bearer", refresh_token="RT-spent",
        expires_in=3600, resource="https://rs.test/mcp",
        probe_evidence={"client_id": "cid", "client_mechanism": "dcr", "auth_mode": "auto"},
    )
    target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)
    target.context = {"as_metadata": AS_META}

    result = ShortLivedAndRefreshRotates().run(target, ctx)

    assert ctx.auth_session.access_token == "AT-fresh"     # adopted
    assert ctx.auth_session.refresh_token == "RT-fresh"
    assert result.evidence.get("session_adopted_refreshed_token") is True
    ctx.close()


# --- static token (--token): no OAuth lifecycle to test on CT-05 ---------

def test_ct05_static_token_reports_na_not_warn_or_manual():
    from mcp_audit.checks.server.credential_token_risk import ShortLivedAndRefreshRotates
    from mcp_audit.core.models import Rating, Target, Transport

    ctx = ProbeContext()
    ctx.auth_session = AuthSession(access_token="napi_realkey", token_type="Bearer",
                                    probe_evidence={"auth_mode": "supplied-token"})
    target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)
    target.context = {}

    result = ShortLivedAndRefreshRotates().run(target, ctx)

    assert result.rating == Rating.NA
    assert "no OAuth token lifecycle" in result.detail
    assert result.evidence["auth_method"] == "static-token"
    ctx.close()
