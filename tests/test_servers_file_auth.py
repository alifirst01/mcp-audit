"""Bulk (eval-file) credential resolution: a servers.yaml/json entry can
carry its own token/client_id/client_secret/client_metadata_url/
redirect_port/scopes, overriding the eval-file CLI flags field-by-field for
that server only.
"""
from __future__ import annotations

import argparse

import pytest

from mcp_audit import cli
from mcp_audit.core.loader import load_targets
from mcp_audit.core.models import Target, Transport


def _args(**overrides):
    defaults = dict(
        token=None, client_id=None, client_secret=None, client_metadata_url=None,
        redirect_port=None, scopes=None, out=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# --- loader: per-entry auth fields land in target.context ------------------

def test_loader_reads_per_server_auth_fields(tmp_path):
    servers_yaml = tmp_path / "servers.yaml"
    servers_yaml.write_text(
        "- name: GitHub\n"
        "  url: https://api.githubcopilot.com/mcp\n"
        "  client_id: cid-123\n"
        "  client_secret: shh\n"
        "  redirect_port: 8765\n"
        "- name: Neon\n"
        "  url: https://mcp.neon.tech/mcp\n"
        "  token: napi_xyz\n"
        "- name: Plain\n"
        "  url: https://plain.test/mcp\n"
    )
    targets = load_targets(str(servers_yaml))
    by_name = {t.name: t for t in targets}

    assert by_name["GitHub"].context["auth_overrides"] == {
        "client_id": "cid-123", "client_secret": "shh", "redirect_port": 8765,
    }
    assert by_name["Neon"].context["auth_overrides"] == {"token": "napi_xyz"}
    assert "auth_overrides" not in by_name["Plain"].context


# --- _target_auth_input: field-level override, not whole-group swap -------

def test_target_with_no_overrides_falls_back_to_cli_flags():
    target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)
    args = _args(token="cli-token")

    auth_input = cli._target_auth_input(target, args)

    assert auth_input.token == "cli-token"
    assert auth_input.mode() == "supplied-token"


def test_target_own_token_overrides_cli_token():
    target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)
    target.context["auth_overrides"] = {"token": "server-token"}
    args = _args(token="cli-token")

    auth_input = cli._target_auth_input(target, args)

    assert auth_input.token == "server-token"


def test_target_own_client_id_used_when_cli_gives_nothing():
    target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)
    target.context["auth_overrides"] = {"client_id": "cid", "client_secret": "sec",
                                        "redirect_port": 8765}
    args = _args()

    auth_input = cli._target_auth_input(target, args)

    assert auth_input.client_id == "cid"
    assert auth_input.client_secret == "sec"
    assert auth_input.redirect_port == 8765
    assert auth_input.mode() == "supplied-credentials"


def test_target_scopes_override_and_fallback():
    with_override = Target(name="a", url="https://a.test/mcp", transport=Transport.HTTP)
    with_override.context["auth_overrides"] = {"scopes": "read:user"}
    without_override = Target(name="b", url="https://b.test/mcp", transport=Transport.HTTP)
    args = _args(scopes="global:scope")

    assert cli._target_auth_input(with_override, args).scopes == "read:user"
    assert cli._target_auth_input(without_override, args).scopes == "global:scope"


# --- mutual exclusivity is validated per target, naming the server --------

def test_conflicting_server_override_errors_naming_the_server():
    target = Target(name="Bad Server", url="https://rs.test/mcp", transport=Transport.HTTP)
    target.context["auth_overrides"] = {"client_id": "cid"}
    args = _args(token="cli-token")   # CLI token + this server's own client_id

    with pytest.raises(SystemExit) as e:
        cli._target_auth_input(target, args)
    assert e.value.code == 2


def test_server_client_secret_without_client_id_errors():
    target = Target(name="t", url="https://rs.test/mcp", transport=Transport.HTTP)
    target.context["auth_overrides"] = {"client_secret": "shh"}
    args = _args()

    with pytest.raises(SystemExit):
        cli._target_auth_input(target, args)


# --- eval-file: each target evaluated with its own resolved auth_input ----

def test_eval_file_uses_each_targets_own_auth_input(monkeypatch, tmp_path):
    calls = []

    def fake_evaluate(target, include_auth=False, auth_input=None, on_result=None):
        calls.append((target.name, include_auth, auth_input))
        class _Report:
            def to_dict(self_):
                return {}
        return _Report()

    monkeypatch.setattr(cli, "evaluate", fake_evaluate)
    monkeypatch.setattr(cli, "_print_report", lambda report: None)
    monkeypatch.setattr(cli, "_print_server_separator", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_confirm_auth", lambda name: pytest.fail(
        "must not prompt when every target has its own or the global credential"))

    servers_yaml = tmp_path / "servers.yaml"
    servers_yaml.write_text(
        "- name: HasOwnToken\n  url: https://a.test/mcp\n  token: own-token\n"
        "- name: UsesGlobal\n  url: https://b.test/mcp\n"
    )

    cli._cmd_eval_file(_args(path=str(servers_yaml), token="global-token"))

    by_name = {name: (include_auth, auth_input) for name, include_auth, auth_input in calls}
    assert by_name["HasOwnToken"][1].token == "own-token"
    assert by_name["UsesGlobal"][1].token == "global-token"
    assert all(include_auth for include_auth, _ in by_name.values())


def test_eval_file_bad_server_entry_fails_before_any_evaluation(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(cli, "evaluate", lambda *a, **k: calls.append(1))

    servers_yaml = tmp_path / "servers.yaml"
    servers_yaml.write_text(
        "- name: Good\n  url: https://a.test/mcp\n"
        "- name: Bad\n  url: https://b.test/mcp\n  client_id: cid\n"
    )

    with pytest.raises(SystemExit):
        cli._cmd_eval_file(_args(path=str(servers_yaml), token="global-token"))

    assert calls == []   # aborted before evaluating "Good"
