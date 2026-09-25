"""Resource/audience canonicalization (RFC 8707 guidance): CD-02's declared
PRM resource vs the endpoint it describes, and CT-01's token aud vs the
requested resource, must compare canonical forms — not raw strings — so a
trailing slash, scheme/host case, or explicit default port doesn't produce
a false mismatch (or hide a real one).
"""
from __future__ import annotations

import base64
import json

import httpx

from mcp_audit.checks.server._helpers import canonicalize_resource, resources_match
from mcp_audit.checks.server.connection_discovery import DiscoversAuthorizationServer
from mcp_audit.checks.server.credential_token_risk import ResourceBoundToken
from mcp_audit.core.models import Rating, Target, Transport
from mcp_audit.core.probe import AuthSession, ProbeContext


# --- canonicalize_resource / resources_match --------------------------------

def test_canonicalize_strips_default_port_and_lowercases():
    assert canonicalize_resource("HTTPS://Example.COM:443/mcp") == "https://example.com/mcp"
    assert canonicalize_resource("http://Example.com:80/mcp") == "http://example.com/mcp"


def test_canonicalize_keeps_non_default_port():
    assert canonicalize_resource("https://example.com:8443/mcp") == "https://example.com:8443/mcp"


def test_canonicalize_strips_trailing_slash_on_non_root_path():
    assert canonicalize_resource("https://example.com/mcp/") == "https://example.com/mcp"


def test_canonicalize_normalizes_empty_path_to_root():
    assert canonicalize_resource("https://example.com") == "https://example.com/"


def test_canonicalize_empty_input_is_empty_string():
    assert canonicalize_resource("") == ""
    assert canonicalize_resource(None) == ""


def test_resources_match_true_for_case_port_slash_variants():
    assert resources_match("https://Example.com:443/mcp/", "https://example.com/mcp")


def test_resources_match_false_for_genuinely_different_hosts():
    assert not resources_match("https://example.com/mcp", "https://evil.example.com/mcp")


def test_resources_match_origin_prefix_still_matches():
    assert resources_match("https://example.com", "https://example.com/mcp")


def test_resources_match_both_empty_is_not_a_match():
    assert not resources_match("", "")


# --- CD-02: declared PRM resource vs the endpoint it describes -------------

def _prm_server(declared_resource):
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "resource": declared_resource,
            "authorization_servers": ["https://as.test"],
        })
    return httpx.MockTransport(handle)


def test_cd02_pass_when_declared_resource_canonicalizes_equal_despite_slash_case():
    target = Target(name="t", url="https://Mcp.Test/mcp", transport=Transport.HTTP)
    ctx = ProbeContext(transport=_prm_server("https://mcp.test:443/mcp/"))

    result = DiscoversAuthorizationServer().run(target, ctx)

    assert result.rating == Rating.PASS
    assert result.evidence["declared_resource_canonical"] == result.evidence["endpoint_canonical"]
    ctx.close()


def test_cd02_warn_when_declared_resource_genuinely_differs():
    target = Target(name="t", url="https://mcp.test/mcp", transport=Transport.HTTP)
    ctx = ProbeContext(transport=_prm_server("https://other.test/mcp"))

    result = DiscoversAuthorizationServer().run(target, ctx)

    assert result.rating == Rating.WARN
    assert "does not canonicalize" in result.detail
    assert result.evidence["declared_resource_canonical"] != result.evidence["endpoint_canonical"]
    ctx.close()


def test_cd02_no_resource_field_is_still_pass():
    """`resource` is RECOMMENDED by the spec text mcp-audit quotes but not
    universally present; its absence is not itself a mismatch."""
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"authorization_servers": ["https://as.test"]})

    target = Target(name="t", url="https://mcp.test/mcp", transport=Transport.HTTP)
    ctx = ProbeContext(transport=httpx.MockTransport(handle))

    result = DiscoversAuthorizationServer().run(target, ctx)

    assert result.rating == Rating.PASS
    assert result.evidence["declared_resource"] is None
    ctx.close()


# --- CT-01: token aud vs the requested resource -----------------------------

def _jwt_with_aud(aud) -> str:
    def b64u(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")
    header = b64u(json.dumps({"alg": "none"}).encode())
    payload = b64u(json.dumps({"aud": aud}).encode())
    sig = b64u(b"x")
    return (header + b"." + payload + b"." + sig).decode()


def test_ct01_pass_when_aud_canonicalizes_equal_despite_port_and_slash():
    token = _jwt_with_aud("https://mcp.test:443/mcp/")
    ctx = ProbeContext()
    ctx.auth_session = AuthSession(access_token=token, token_type="Bearer",
                                   resource="https://mcp.test/mcp")
    target = Target(name="t", url="https://mcp.test/mcp", transport=Transport.HTTP)

    result = ResourceBoundToken().run(target, ctx)

    assert result.rating == Rating.PASS
    assert result.evidence["resource_requested_canonical"] in result.evidence["aud_claim_canonical"]
    ctx.close()


def test_ct01_warn_when_aud_genuinely_different_resource():
    token = _jwt_with_aud("https://other.test/mcp")
    ctx = ProbeContext()
    ctx.auth_session = AuthSession(access_token=token, token_type="Bearer",
                                   resource="https://mcp.test/mcp")
    target = Target(name="t", url="https://mcp.test/mcp", transport=Transport.HTTP)

    result = ResourceBoundToken().run(target, ctx)

    assert result.rating == Rating.WARN
    ctx.close()


def test_ct01_pass_when_aud_is_origin_prefix_of_resource():
    token = _jwt_with_aud("https://mcp.test")
    ctx = ProbeContext()
    ctx.auth_session = AuthSession(access_token=token, token_type="Bearer",
                                   resource="https://mcp.test/mcp")
    target = Target(name="t", url="https://mcp.test/mcp", transport=Transport.HTTP)

    result = ResourceBoundToken().run(target, ctx)

    assert result.rating == Rating.PASS
    ctx.close()


def test_ct01_opaque_token_records_canonical_form_in_evidence():
    ctx = ProbeContext()
    ctx.auth_session = AuthSession(access_token="opaque-not-a-jwt", token_type="Bearer",
                                   resource="https://mcp.test/mcp/")
    target = Target(name="t", url="https://mcp.test/mcp", transport=Transport.HTTP)

    result = ResourceBoundToken().run(target, ctx)

    assert result.rating == Rating.MANUAL
    assert result.evidence["resource_requested_canonical"] == "https://mcp.test/mcp"
    ctx.close()
