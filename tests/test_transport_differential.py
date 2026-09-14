"""TR-01/04/05/08: the shared differential-rejection rule (_helpers.
differential_bucket / differential_status_evidence) — FAIL only when a
mutation isn't rejected at all (same status as baseline); a rejection with
the wrong status/error code is WARN, never FAIL. Also covers the structured
baseline_status/mutation_status/mutation_error_code evidence fields.
"""
from __future__ import annotations

import json

import httpx
import pytest

from mcp_audit.checks.server._helpers import differential_bucket, differential_status_evidence
from mcp_audit.checks.server.transport_protocol import (
    ForeignOriginRejected,
    HeaderBodyConsistency,
    UnsupportedVersionError,
    VersionHeaderEnforced,
)
from mcp_audit.core.models import Rating, Target, Transport
from mcp_audit.core.probe import ProbeContext


# --- unit tests: the shared helpers -----------------------------------------

class _FakeResponse:
    def __init__(self, status, text=""):
        self.status = status
        self.text = text


def test_differential_bucket_pass_when_matched():
    assert differential_bucket(True, _FakeResponse(200), _FakeResponse(400)) == Rating.PASS


def test_differential_bucket_fail_only_when_not_rejected_at_all():
    baseline = _FakeResponse(200)
    honored_mutation = _FakeResponse(200)
    assert differential_bucket(False, baseline, honored_mutation) == Rating.FAIL


def test_differential_bucket_warn_when_rejected_with_wrong_code():
    baseline = _FakeResponse(200)
    wrong_code_rejection = _FakeResponse(400)
    assert differential_bucket(False, baseline, wrong_code_rejection) == Rating.WARN


def test_differential_status_evidence_flat_fields():
    baseline = _FakeResponse(200, text='{"jsonrpc":"2.0","result":{}}')
    mutated = _FakeResponse(400, text='{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request"}}')
    ev = differential_status_evidence(baseline, mutated)
    assert ev["baseline_status"] == 200
    assert ev["mutation_status"] == 400
    assert ev["mutation_error_code"] == -32000
    assert "Bad Request" in ev["mutation_response_body"]


# --- integration: a mock MCP server exercising TR-04/05/08 end to end ------

def _body_method(request: httpx.Request) -> dict:
    try:
        return json.loads(request.content.decode())
    except Exception:
        return {}


def _mcp_server(tools_list_handler):
    """initialize succeeds normally; tools_list_handler(request) -> httpx.Response
    decides the tools/list reply so a test can simulate a real rejection
    (wrong error code, same status as baseline, ...)."""
    def handle(request: httpx.Request) -> httpx.Response:
        body = _body_method(request)
        method = body.get("method", "")
        if method == "initialize":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": 0,
                "result": {"protocolVersion": "2026-07-28", "capabilities": {}},
            })
        if method == "notifications/initialized":
            return httpx.Response(202, text="")
        if method == "tools/list":
            return tools_list_handler(request)
        return httpx.Response(404, json={"error": "not_found"})
    return httpx.MockTransport(handle)


def _target_and_ctx(transport):
    target = Target(name="t", url="https://mcp.test/mcp", transport=Transport.HTTP)
    ctx = ProbeContext(transport=transport)
    return target, ctx


def test_tr04_rejected_with_wrong_code_is_warn_not_fail():
    """The exact Neon shape: mismatched-version request gets HTTP 400 with
    a JSON-RPC error, but not code -32020 — must be WARN."""
    def handler(request):
        body = _body_method(request)
        version = request.headers.get("mcp-protocol-version")
        if version == VersionHeaderEnforced._MISMATCHED_VERSION:
            return httpx.Response(400, json={
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32000, "message": "Bad Request: Unsupported protocol version"},
            })
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    target, ctx = _target_and_ctx(_mcp_server(handler))
    result = VersionHeaderEnforced().run(target, ctx)

    assert result.rating == Rating.WARN
    assert result.evidence["baseline_status"] == 200
    assert result.evidence["mutation_status"] == 400
    assert result.evidence["mutation_error_code"] == -32000
    ctx.close()


def test_tr04_correct_code_is_pass():
    def handler(request):
        version = request.headers.get("mcp-protocol-version")
        if version == VersionHeaderEnforced._MISMATCHED_VERSION:
            return httpx.Response(400, json={
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32020, "message": "HeaderMismatch"},
            })
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    target, ctx = _target_and_ctx(_mcp_server(handler))
    result = VersionHeaderEnforced().run(target, ctx)
    assert result.rating == Rating.PASS
    ctx.close()


def test_tr04_not_rejected_at_all_is_fail():
    def handler(request):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    target, ctx = _target_and_ctx(_mcp_server(handler))
    result = VersionHeaderEnforced().run(target, ctx)
    assert result.rating == Rating.FAIL
    assert result.evidence["baseline_status"] == result.evidence["mutation_status"] == 200
    ctx.close()


def test_tr05_neon_shape_not_rejected_at_all_is_correctly_fail_not_artifact():
    """Regression for the exact Neon TR-05 case: the mutated request (real,
    distinct Mcp-Method header) gets served identically to the baseline —
    genuinely not rejected, so FAIL is correct, not a probe artifact."""
    seen_headers = []

    def handler(request):
        seen_headers.append(request.headers.get("mcp-method"))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                          "result": {"tools": [{"name": "list_organizations"}]}})

    target, ctx = _target_and_ctx(_mcp_server(handler))
    result = HeaderBodyConsistency().run(target, ctx)

    assert result.rating == Rating.FAIL
    assert "tools/list" in seen_headers            # baseline's Mcp-Method
    assert HeaderBodyConsistency._MISMATCHED_METHOD in seen_headers   # mutation really sent
    assert result.evidence["baseline_status"] == 200
    assert result.evidence["mutation_status"] == 200
    ctx.close()


def test_tr05_rejected_with_wrong_code_is_warn():
    def handler(request):
        if request.headers.get("mcp-method") == HeaderBodyConsistency._MISMATCHED_METHOD:
            return httpx.Response(400, json={
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32602, "message": "Invalid params"},
            })
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    target, ctx = _target_and_ctx(_mcp_server(handler))
    result = HeaderBodyConsistency().run(target, ctx)
    assert result.rating == Rating.WARN
    ctx.close()


def test_tr08_rejected_with_wrong_code_is_warn_not_fail():
    def handler(request):
        body = _body_method(request)
        if body.get("params", {}).get("_meta", {}).get(
                "io.modelcontextprotocol/protocolVersion") == UnsupportedVersionError._BOGUS_VERSION:
            return httpx.Response(400, json={
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32000, "message": "Bad Request: Unsupported protocol version"},
            })
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    target, ctx = _target_and_ctx(_mcp_server(handler))
    result = UnsupportedVersionError().run(target, ctx)
    assert result.rating == Rating.WARN
    ctx.close()


def test_tr08_correct_code_missing_supported_is_warn_not_pass_or_fail():
    def handler(request):
        body = _body_method(request)
        if body.get("params", {}).get("_meta", {}).get(
                "io.modelcontextprotocol/protocolVersion") == UnsupportedVersionError._BOGUS_VERSION:
            return httpx.Response(400, json={
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32022, "message": "Unsupported protocol version"},
            })
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    target, ctx = _target_and_ctx(_mcp_server(handler))
    result = UnsupportedVersionError().run(target, ctx)
    assert result.rating == Rating.WARN
    ctx.close()


def test_tr08_not_rejected_at_all_is_fail():
    def handler(request):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    target, ctx = _target_and_ctx(_mcp_server(handler))
    result = UnsupportedVersionError().run(target, ctx)
    assert result.rating == Rating.FAIL
    ctx.close()


# --- TR-01 (Origin): different shape, same shared rule ---------------------

def test_tr01_rejected_with_wrong_status_is_warn():
    def handle(request: httpx.Request) -> httpx.Response:
        body = _body_method(request)
        method = body.get("method", "")
        if method == "initialize":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": 0,
                "result": {"protocolVersion": "2026-07-28", "capabilities": {}},
            })
        if method == "notifications/initialized":
            return httpx.Response(202, text="")
        if method == "tools/list":
            origin = request.headers.get("origin")
            if origin == "http://evil.attacker.example.com":
                return httpx.Response(451, json={"error": "blocked"})
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
        return httpx.Response(404, json={"error": "not_found"})

    target, ctx = _target_and_ctx(httpx.MockTransport(handle))
    result = ForeignOriginRejected().run(target, ctx)
    assert result.rating == Rating.WARN
    assert result.evidence["mutation_status"] == 451
    ctx.close()


def test_tr01_not_rejected_at_all_is_fail():
    def handle(request: httpx.Request) -> httpx.Response:
        body = _body_method(request)
        method = body.get("method", "")
        if method == "initialize":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": 0,
                "result": {"protocolVersion": "2026-07-28", "capabilities": {}},
            })
        if method == "notifications/initialized":
            return httpx.Response(202, text="")
        if method == "tools/list":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
        return httpx.Response(404, json={"error": "not_found"})

    target, ctx = _target_and_ctx(httpx.MockTransport(handle))
    result = ForeignOriginRejected().run(target, ctx)
    assert result.rating == Rating.FAIL
    ctx.close()
