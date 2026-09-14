"""Load targets from a file for bulk evaluation.

Supported formats: YAML or JSON, a list of entries like:

  - name: GitHub MCP (remote)
    url: https://api.githubcopilot.com/mcp
    client_id: Ov23liXXXXXXXXXXXX
    client_secret: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    redirect_port: 8765
  - name: Neon MCP (remote)
    url: https://mcp.neon.tech/mcp
    token: napi_XXXXXXXXXXXXXXXXXXXXXXXXXXXX
  - name: Supabase MCP (remote)
    repo: https://mcp.supabase.com/mcp

`token`, `client_id`, `client_secret`, `client_metadata_url`, `redirect_port`,
and `scopes` mirror the `eval` CLI flags of the same name, applying to this
server only; see `cli._resolve_auth_input`. Any left unset fall back to the
matching `--` flag on the `eval-file` invocation itself.
"""
from __future__ import annotations

import json
import pathlib

from .models import Target, Transport

_AUTH_FIELDS = ("token", "client_id", "client_secret", "client_metadata_url",
                "redirect_port", "scopes")


def _to_target(entry: dict) -> Target:
    t = entry.get("transport")
    if t:
        try:
            transport = Transport(t.lower())
        except ValueError:
            transport = Transport.UNKNOWN
    else:
        transport = Transport.HTTP if entry.get("url") else Transport.UNKNOWN
    target = Target(
        name=entry["name"],
        url=entry.get("url"),
        repo=entry.get("repo"),
        transport=transport,
        category=entry.get("category"),
        notes=entry.get("notes"),
    )
    auth_overrides = {k: entry[k] for k in _AUTH_FIELDS if k in entry}
    if auth_overrides:
        target.context["auth_overrides"] = auth_overrides
    return target


def load_targets(path: str) -> list[Target]:
    p = pathlib.Path(path)
    raw = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        import yaml
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    if isinstance(data, dict) and "servers" in data:
        data = data["servers"]
    return [_to_target(e) for e in data]
