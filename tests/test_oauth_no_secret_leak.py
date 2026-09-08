"""The trust guarantee in core/oauth.py's docstring, made a tested
invariant: secrets (access_token, refresh_token, client_secret) must never
appear in a CheckResult's evidence, in ctx.auth_session.probe_evidence, or
in the serialized TargetReport JSON that --out writes — for all three
--auth credential paths.

Runs entirely against the mock fixtures in conftest.py; no live network,
no real browser.
"""
from __future__ import annotations

import base64
import dataclasses
import json

from mcp_audit.core import oauth
from mcp_audit.core.models import Target, TargetReport, Transport
from mcp_audit.core.probe import ProbeContext
from mcp_audit.checks.server.credential_token_risk import (
    ResourceBoundToken,
    ShortLivedAndRefreshRotates,
    TokenCheckedEveryRequest,
    TokenIntegrityVerified,
)
from mcp_audit.checks.server.tool_safety import ToolBlastRadius

from conftest import AS_METADATA, CLIENT_SECRET, MCP_URL, REFRESH_TOKEN

_SAMPLE_CHECKS = [
    ResourceBoundToken(), TokenIntegrityVerified(), TokenCheckedEveryRequest(),
    ShortLivedAndRefreshRotates(), ToolBlastRadius(),
]


def _target() -> Target:
    t = Target(name="fixture", url=MCP_URL, transport=Transport.HTTP)
    t.context["as_metadata"] = dict(AS_METADATA)
    t.context["prm_doc"] = {"scopes_supported": ["read"]}
    return t


def _run_sample_checks(target: Target, ctx: ProbeContext) -> list:
    return [check.run(target, ctx) for check in _SAMPLE_CHECKS]


def _assert_absent(secret: str, *objects) -> None:
    """Assert `secret` appears nowhere in the JSON serialization of any of
    `objects` — the exact shape written to --out and shown in evidence."""
    for obj in objects:
        text = json.dumps(obj, default=str)
        assert secret not in text, f"secret leaked into output: {text}"


def _report_dict(target: Target, results: list) -> dict:
    report = TargetReport(target=target, results=results)
    return report.to_dict()


def test_auto_flow_no_secret_leak(mock_server, fake_browser):
    """Path 3 (auto): self-registration (DCR) + full interactive flow."""
    target = _target()
    ctx = ProbeContext(transport=mock_server.transport)

    oauth.authenticate(target, ctx, auth_input=oauth.AuthInput())

    assert ctx.auth_failure is None
    assert ctx.auth_session is not None
    assert ctx.auth_session.access_token == "fixture-access-token-abc123"
    assert ctx.auth_session.refresh_token == REFRESH_TOKEN

    # Sanity: the client_secret DCR handed back was actually used (Basic
    # auth) at the token endpoint — otherwise this test would trivially
    # pass just because the secret was never touched.
    token_requests = [r for r in mock_server.requests if r.url.path == "/token"]
    assert token_requests, "token endpoint was never called"
    basic = base64.b64encode(f"fixture-client-id:{CLIENT_SECRET}".encode()).decode()
    assert any(
        r.headers.get("authorization") == f"Basic {basic}" for r in token_requests
    ), "client_secret was never sent — leak-absence check would be vacuous"

    _assert_absent(CLIENT_SECRET, dataclasses.asdict(ctx.auth_session)["probe_evidence"])

    results = _run_sample_checks(target, ctx)
    report_dict = _report_dict(target, results)
    for secret in (ctx.auth_session.access_token, ctx.auth_session.refresh_token, CLIENT_SECRET):
        _assert_absent(secret, ctx.auth_session.probe_evidence, *[r.to_dict() for r in results], report_dict)


def test_supplied_token_no_secret_leak(mock_server):
    """Path 1 (supplied-token): no flow, no network call to obtain it."""
    target = _target()
    ctx = ProbeContext(transport=mock_server.transport)
    supplied = "fixture-supplied-token-999"

    oauth.authenticate(target, ctx, auth_input=oauth.AuthInput(token=supplied))

    assert ctx.auth_failure is None
    assert ctx.auth_session.access_token == supplied

    results = _run_sample_checks(target, ctx)
    report_dict = _report_dict(target, results)
    _assert_absent(supplied, ctx.auth_session.probe_evidence, *[r.to_dict() for r in results], report_dict)


def test_supplied_credentials_no_secret_leak(mock_server, fake_browser):
    """Path 2 (supplied-credentials): skip registration, run the full
    interactive flow with an operator-supplied client_id/client_secret."""
    target = _target()
    ctx = ProbeContext(transport=mock_server.transport)
    supplied_secret = "fixture-supplied-client-secret-321"

    oauth.authenticate(
        target, ctx,
        auth_input=oauth.AuthInput(client_id="supplied-client-id", client_secret=supplied_secret),
    )

    assert ctx.auth_failure is None
    assert ctx.auth_session is not None

    token_requests = [r for r in mock_server.requests if r.url.path == "/token"]
    assert token_requests, "token endpoint was never called"
    basic = base64.b64encode(f"supplied-client-id:{supplied_secret}".encode()).decode()
    assert any(
        r.headers.get("authorization") == f"Basic {basic}" for r in token_requests
    ), "client_secret was never sent — leak-absence check would be vacuous"

    results = _run_sample_checks(target, ctx)
    report_dict = _report_dict(target, results)
    for secret in (ctx.auth_session.access_token, ctx.auth_session.refresh_token, supplied_secret):
        _assert_absent(secret, ctx.auth_session.probe_evidence, *[r.to_dict() for r in results], report_dict)
