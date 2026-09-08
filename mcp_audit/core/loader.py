"""Load targets from a file for bulk evaluation.

Supported formats: YAML or JSON, a list of entries like:

  - name: GitHub MCP (remote)
    url: https://api.githubcopilot.com/mcp
  - name: Supabase MCP (remote)
    repo: https://mcp.supabase.com/mcp
"""
from __future__ import annotations

import json
import pathlib

from .models import Target, Transport


def _to_target(entry: dict) -> Target:
    t = entry.get("transport")
    if t:
        try:
            transport = Transport(t.lower())
        except ValueError:
            transport = Transport.UNKNOWN
    else:
        transport = Transport.HTTP if entry.get("url") else Transport.UNKNOWN
    return Target(
        name=entry["name"],
        url=entry.get("url"),
        repo=entry.get("repo"),
        transport=transport,
        category=entry.get("category"),
        notes=entry.get("notes"),
    )


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
