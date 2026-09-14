"""CLI wiring: supplying a credential (--token/--client-id/--client-metadata-url)
must authenticate on its own, without also requiring --auth, and without
eval-file's interactive per-target prompt.
"""
from __future__ import annotations

import argparse

from mcp_audit import cli
from mcp_audit.core.oauth import AuthInput


def _args(**overrides):
    defaults = dict(
        url="https://mcp.example.test/mcp", name=None, auth=False,
        token=None, client_id=None, client_secret=None, client_metadata_url=None,
        redirect_port=None, scopes=None, out=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _capture_evaluate(monkeypatch, calls):
    def fake_evaluate(target, include_auth=False, auth_input=None, on_result=None):
        calls.append({"include_auth": include_auth, "auth_input": auth_input})
        class _Report:
            def to_dict(self_):
                return {}
            def to_summary_dict(self_):
                return {}
        return _Report()
    monkeypatch.setattr(cli, "evaluate", fake_evaluate)
    monkeypatch.setattr(cli, "_print_report", lambda report: None)


def test_eval_token_alone_authenticates_without_auth_flag(monkeypatch):
    calls = []
    _capture_evaluate(monkeypatch, calls)

    cli._cmd_eval(_args(token="napi_realkey"))

    assert len(calls) == 1
    assert calls[0]["include_auth"] is True
    assert calls[0]["auth_input"].mode() == "supplied-token"


def test_eval_no_credential_and_no_auth_flag_stays_unauthenticated(monkeypatch):
    calls = []
    _capture_evaluate(monkeypatch, calls)

    cli._cmd_eval(_args())

    assert calls[0]["include_auth"] is False


def test_eval_bare_auth_flag_still_works(monkeypatch):
    calls = []
    _capture_evaluate(monkeypatch, calls)

    cli._cmd_eval(_args(auth=True))

    assert calls[0]["include_auth"] is True
    assert calls[0]["auth_input"].mode() == "auto"


def test_eval_file_token_alone_skips_the_confirm_prompt(monkeypatch, tmp_path):
    calls = []
    _capture_evaluate(monkeypatch, calls)
    prompted = []
    monkeypatch.setattr(cli, "_confirm_auth", lambda name: prompted.append(name) or False)
    monkeypatch.setattr(cli, "_print_server_separator", lambda *a, **k: None)

    servers_yaml = tmp_path / "servers.yaml"
    servers_yaml.write_text(
        "- name: One\n  url: https://a.test/mcp\n"
        "- name: Two\n  url: https://b.test/mcp\n"
    )

    cli._cmd_eval_file(_args(path=str(servers_yaml), token="napi_realkey"))

    assert prompted == []                      # never asked, credential was enough
    assert len(calls) == 2
    assert all(c["include_auth"] is True for c in calls)
    assert all(c["auth_input"].mode() == "supplied-token" for c in calls)


def test_eval_file_no_credential_falls_back_to_prompt(monkeypatch, tmp_path):
    calls = []
    _capture_evaluate(monkeypatch, calls)
    monkeypatch.setattr(cli, "_confirm_auth", lambda name: False)
    monkeypatch.setattr(cli, "_print_server_separator", lambda *a, **k: None)

    servers_yaml = tmp_path / "servers.yaml"
    servers_yaml.write_text("- name: One\n  url: https://a.test/mcp\n")

    cli._cmd_eval_file(_args(path=str(servers_yaml)))

    assert calls[0]["include_auth"] is False
