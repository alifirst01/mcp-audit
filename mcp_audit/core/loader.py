"""Load targets from a file for bulk evaluation.

Supported formats: YAML or JSON, a list of entries like:

  - name: GitHub MCP (remote)
    url: https://api.githubcopilot.com/mcp
    client_id: ${GITHUB_CLIENT_ID}
    client_secret: ${GITHUB_CLIENT_SECRET}
    redirect_port: 8765
  - name: Neon MCP (remote)
    url: https://mcp.neon.tech/mcp
    token: ${NEON_TOKEN}
  - name: Supabase MCP (remote)
    repo: https://mcp.supabase.com/mcp

`token`, `client_id`, `client_secret`, `client_metadata_url`, `redirect_port`,
and `scopes` mirror the `eval` CLI flags of the same name, applying to this
server only; see `cli._resolve_auth_input`. Any left unset fall back to the
matching `--` flag on the `eval-file` invocation itself.

A `${VAR_NAME}` anywhere in any field's value is substituted from a
secrets file — `.secrets.yaml`/`.secrets.yml`/`.secrets.json`, whichever
exists first, in the *same directory* as the servers file — so real
credentials never need to sit in the (typically version-controlled)
servers file itself; only the placeholder does. That secrets file is a
flat `VAR_NAME: value` mapping and is expected to be gitignored. A
reference to a variable the secrets file doesn't define is an error naming
the server and variable, not a silent literal `${VAR_NAME}` sent as a
credential.
"""
from __future__ import annotations

import json
import pathlib
import re

from .models import Target, Transport

_SECRETS_FILENAMES = (".secrets.yaml", ".secrets.yml", ".secrets.json")
_VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Canonical field name each accepted YAML/JSON key maps to. Both the
# underscore form (matching AuthInput's own field names) and the hyphenated
# form (matching how the equivalent CLI flag reads, e.g. --client-id) are
# accepted, since a servers file is edited by hand.
_AUTH_FIELD_ALIASES = {
    "token": "token",
    "client_id": "client_id", "client-id": "client_id",
    "client_secret": "client_secret", "client-secret": "client_secret",
    "client_metadata_url": "client_metadata_url",
    "client-metadata-url": "client_metadata_url",
    "redirect_port": "redirect_port", "redirect-port": "redirect_port",
    "scopes": "scopes",
}


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
    auth_overrides = {
        canonical: entry[key]
        for key, canonical in _AUTH_FIELD_ALIASES.items()
        if key in entry
    }
    if auth_overrides:
        target.context["auth_overrides"] = auth_overrides
    return target


def _load_secrets(servers_path: pathlib.Path) -> dict[str, str]:
    """The flat VAR_NAME: value mapping from the first
    .secrets.yaml/.secrets.yml/.secrets.json found next to `servers_path`,
    or {} if none exists."""
    for name in _SECRETS_FILENAMES:
        candidate = servers_path.parent / name
        if not candidate.exists():
            continue
        text = candidate.read_text()
        if candidate.suffix == ".json":
            data = json.loads(text)
        else:
            import yaml
            data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{candidate} must be a flat mapping of VAR_NAME: value.")
        return {str(k): str(v) for k, v in data.items()}
    return {}


def _interpolate(value, secrets: dict[str, str], where: str):
    """Substitute every ${VAR_NAME} in `value` (recursively through
    dicts/lists) from `secrets`. Raises clearly, naming `where` and the
    variable, rather than sending a literal ${VAR_NAME} as a credential."""
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            var = m.group(1)
            if var not in secrets:
                raise ValueError(
                    f"{where} references ${{{var}}}, but no such variable is "
                    f"defined in a secrets file ({'/'.join(_SECRETS_FILENAMES)} "
                    f"next to the servers file)."
                )
            return secrets[var]
        return _VAR_REF.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate(v, secrets, f"{where}.{k}") for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v, secrets, f"{where}[{i}]") for i, v in enumerate(value)]
    return value


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
    secrets = _load_secrets(p)
    data = [
        _interpolate(entry, secrets, entry.get("name") or f"servers[{i}]")
        for i, entry in enumerate(data)
    ]
    return [_to_target(e) for e in data]
