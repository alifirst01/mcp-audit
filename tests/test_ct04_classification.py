"""CT-04 classifies a bad-token rejection by *why* it happened, not just its
HTTP status code: a rejection naming a token/credential problem is PASS, an
envelope/shape/routing/server rejection is n/a (inconclusive, never FAIL),
and only an actually-honored request is FAIL.
"""
from __future__ import annotations

import httpx
import pytest

from mcp_audit.checks.server.credential_token_risk import TokenCheckedEveryRequest
from mcp_audit.core.models import Rating, Target, Transport
from mcp_audit.core.probe import AuthSession, ProbeContext


def _ctx_and_target(status: int, json_body: dict | None = None, text: str | None = None):
    def handle(request: httpx.Request) -> httpx.Response:
        if json_body is not None:
            return httpx.Response(status, json=json_body)
        return httpx.Response(status, text=text or "")

    ctx = ProbeContext(transport=httpx.MockTransport(handle))
    ctx.auth_session = AuthSession(access_token="AT-real", token_type="Bearer")
    target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)
    return target, ctx


def test_401_with_invalid_token_body_is_pass():
    target, ctx = _ctx_and_target(401, json_body={"error": "invalid_token"})
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.PASS
    assert result.evidence["rejection_classification"] == "pass"
    ctx.close()


def test_401_with_empty_body_is_still_pass():
    """401 means "lacked valid credentials" by definition (RFC 7235) even
    with no explanatory body."""
    target, ctx = _ctx_and_target(401, text="")
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.PASS
    ctx.close()


def test_jsonrpc_error_inside_200_for_envelope_reason_is_na_not_fail():
    """A JSON-RPC error delivered inside an HTTP 200 (the MCP idiom) that
    names an envelope problem, not the token, must not be scored as PASS or
    FAIL."""
    target, ctx = _ctx_and_target(200, json_body={
        "jsonrpc": "2.0", "id": 1,
        "error": {"code": -32600, "message": "Invalid Request"},
    })
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.NA
    assert result.evidence["rejection_classification"] == "na"
    assert "401" not in result.detail or result.rating == Rating.NA
    ctx.close()


def test_404_not_found_is_na_not_fail():
    target, ctx = _ctx_and_target(404, text="Not Found")
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.NA
    ctx.close()


def test_406_not_acceptable_empty_body_is_na():
    """A bare status-based envelope rejection (e.g. missing the SSE Accept
    header) with no informative body must still classify as n/a via the
    status-code fallback, not FAIL."""
    target, ctx = _ctx_and_target(406, text="")
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.NA
    ctx.close()


def test_500_internal_server_error_is_na():
    target, ctx = _ctx_and_target(500, text="Internal Server Error")
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.NA
    ctx.close()


def test_honored_200_with_real_result_is_fail():
    target, ctx = _ctx_and_target(200, json_body={
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": [{"name": "read_thing"}]},
    })
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.FAIL
    assert result.evidence["rejection_classification"] == "fail"
    ctx.close()


def test_ambiguous_403_with_uninformative_body_defaults_to_na_not_fail():
    """No token/credential wording, no envelope wording, status not in the
    known envelope set — genuinely ambiguous. Must default to inconclusive,
    never FAIL."""
    target, ctx = _ctx_and_target(403, text="Forbidden")
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.NA
    ctx.close()


def test_403_naming_unauthorized_is_pass():
    target, ctx = _ctx_and_target(403, json_body={"error": "unauthorized_client",
                                                    "error_description": "bearer token rejected"})
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.PASS
    ctx.close()


def test_request_error_stays_error():
    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    ctx = ProbeContext(transport=httpx.MockTransport(handle))
    ctx.auth_session = AuthSession(access_token="AT-real", token_type="Bearer")
    target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)

    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.ERROR
    ctx.close()


def test_evidence_records_status_and_reason_for_na():
    target, ctx = _ctx_and_target(404, text="Not Found")
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert "404" in result.evidence["rejection_reason"]
    assert result.evidence["response_status"] == 404 or "404" in str(result.evidence)
    ctx.close()


# --- regression: GitHub's actual response was misclassified as n/a --------

def test_github_authorization_header_badly_formatted_is_pass_not_na():
    """The exact regression this fix addresses: GitHub returns HTTP 400
    with body 'bad request: Authorization header is badly formatted' —
    a token/credential rejection, but 'bad request' alone would also match
    the envelope hint list. The token hint ("authorization header") must
    win."""
    target, ctx = _ctx_and_target(400, text="bad request: Authorization header is badly formatted\n")
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.PASS
    assert result.evidence["rejection_classification"] == "pass"
    ctx.close()


def test_body_token_hint_wins_over_envelope_status_precedence():
    """A status that's ALSO in the envelope status-code set (400) must
    still classify as PASS when the body names the token/credential —
    body reason wins over status code, not the other way around."""
    target, ctx = _ctx_and_target(400, text="malformed authorization: credential rejected")
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.PASS
    ctx.close()


def test_jsonrpc_envelope_code_32020_is_na():
    target, ctx = _ctx_and_target(400, json_body={
        "jsonrpc": "2.0", "id": 0,
        "error": {"code": -32020, "message": "HeaderMismatch"},
    })
    result = TokenCheckedEveryRequest().run(target, ctx)
    assert result.rating == Rating.NA
    ctx.close()


# --- CT-04 sends a structurally valid (same-shape) invalid token ----------

def test_ct04_sends_same_shape_token_not_a_garbage_string():
    """The probe token must be the same length/shape as the real one (not
    an arbitrary literal), so a rejection proves token validation, not
    header-parsing rejection of an obviously-malformed value."""
    real_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYmMifQ.sig-part-here"
    sent_headers = {}

    def handle(request: httpx.Request) -> httpx.Response:
        sent_headers["Authorization"] = request.headers.get("authorization", "")
        return httpx.Response(401, json={"error": "invalid_token"})

    ctx = ProbeContext(transport=httpx.MockTransport(handle))
    ctx.auth_session = AuthSession(access_token=real_token, token_type="Bearer")
    target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)

    TokenCheckedEveryRequest().run(target, ctx)

    sent_token = sent_headers["Authorization"].removeprefix("Bearer ")
    assert sent_token != real_token                     # never issued
    assert len(sent_token) == len(real_token)            # same shape/length
    assert sent_token.count(".") == real_token.count(".")  # segment structure preserved
    ctx.close()


def test_fabricate_invalid_token_differs_and_preserves_punctuation():
    from mcp_audit.checks.server.credential_token_risk import _fabricate_invalid_token

    real = "ghu_ABC123xyz.mid.tail"
    fabricated = _fabricate_invalid_token(real)
    assert fabricated != real
    assert len(fabricated) == len(real)
    # Punctuation (underscore, dots) preserved exactly at the same positions.
    assert [c for c in fabricated if not c.isalnum()] == [c for c in real if not c.isalnum()]
