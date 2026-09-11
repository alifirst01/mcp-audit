"""--redirect-port: a fixed OAuth loopback port for providers (GitHub OAuth
Apps) whose registered redirect URI must match exactly, port included.

Default behavior (OS-assigned ephemeral port) must be unchanged; a fixed
port must be stable across runs and fail loudly — never silently fall back
to a random port — when already in use.
"""
from __future__ import annotations

import argparse
import socket

import pytest

from mcp_audit.cli import _build_auth_input
from mcp_audit.core.oauth import AuthFailure, LoopbackServer
from mcp_audit.core.probe import ProbeContext
from mcp_audit.core import oauth as oauth_module


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- LoopbackServer ----------------------------------------------------

def test_default_port_zero_is_unchanged_and_varies():
    a = LoopbackServer()
    b = LoopbackServer()
    try:
        assert a.port != 0 and b.port != 0
        assert a.redirect_uri == f"http://127.0.0.1:{a.port}/callback"
        # Overwhelmingly likely to differ; this is the whole point of port 0.
        assert a.port != b.port
    finally:
        a._httpd.server_close()
        b._httpd.server_close()


def test_fixed_port_is_stable_across_two_consecutive_runs():
    port = _free_port()
    first = LoopbackServer(port=port)
    try:
        assert first.redirect_uri == f"http://127.0.0.1:{port}/callback"
    finally:
        first._httpd.server_close()

    # A second, independent "run" against the same requested port.
    second = LoopbackServer(port=port)
    try:
        assert second.redirect_uri == f"http://127.0.0.1:{port}/callback"
        assert second.redirect_uri == first.redirect_uri
    finally:
        second._httpd.server_close()


def test_fixed_port_already_in_use_raises_clearly_not_silently():
    port = _free_port()
    occupier = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupier.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    occupier.bind(("127.0.0.1", port))
    occupier.listen(1)
    try:
        with pytest.raises(RuntimeError) as e:
            LoopbackServer(port=port)
        assert str(port) in str(e.value)
        assert "--redirect-port" in str(e.value)
    finally:
        occupier.close()


# --- authenticate() surfaces the failure via ctx.auth_failure, no fallback --

def test_authenticate_reports_redirect_port_failure_without_falling_back(monkeypatch):
    from mcp_audit.core.oauth import AuthInput, authenticate
    from mcp_audit.core.models import Target, Transport

    port = _free_port()
    occupier = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupier.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    occupier.bind(("127.0.0.1", port))
    occupier.listen(1)
    try:
        ctx = ProbeContext()
        target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)
        target.context = {"as_metadata": {
            "authorization_endpoint": "https://as.test/authorize",
            "token_endpoint": "https://as.test/token",
        }}
        monkeypatch.setattr(oauth_module.webbrowser, "open", lambda url: pytest.fail(
            "must not proceed to opening the browser on a redirect-port failure"))

        authenticate(target, ctx, auth_input=AuthInput(client_id="cid", redirect_port=port))

        assert ctx.auth_session is None
        assert isinstance(ctx.auth_failure, AuthFailure)
        assert ctx.auth_failure.stage == "redirect-port"
        assert str(port) in ctx.auth_failure.reason
        ctx.close()
    finally:
        occupier.close()


# --- CLI wiring ----------------------------------------------------------

def test_cli_threads_redirect_port_into_auth_input():
    args = argparse.Namespace(
        token=None, client_id="cid", client_secret=None, client_metadata_url=None,
        redirect_port=8765,
    )
    auth_input = _build_auth_input(args)
    assert auth_input.redirect_port == 8765


def test_cli_redirect_port_defaults_to_none():
    args = argparse.Namespace(
        token=None, client_id=None, client_secret=None, client_metadata_url=None,
        redirect_port=None,
    )
    assert _build_auth_input(args).redirect_port is None
