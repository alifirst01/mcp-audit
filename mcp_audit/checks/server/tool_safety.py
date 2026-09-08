"""Tool Safety & Blast Radius — how much can this server's tools do?

Once a client can see the server's tools, what could go wrong if an agent
uses them unsupervised or is fed adversarial input? Covers unrestricted
capability, the read/write distinction an agent needs to reason about risk,
and tools whose input can carry untrusted external content into the
agent's context.

Each check sends a tools/list JSON-RPC request via `_helpers.fetch_tools_authed`,
using a completed --auth session when one exists. Tagged Method: Auth
because most servers require a session for tools/list (Supabase does, for
example) — but these checks don't `requires_auth`-gate: on a server that
serves tools/list unauthenticated, the check still runs and its evidence
records "obtained without authentication" rather than the Method tag
changing per-server. If tools/list genuinely requires a session and none is
available, the check reports `n/a`.

Spec source: modelcontextprotocol.io/specification/draft/server/tools
"""
from __future__ import annotations

from ...core.base import Check, register
from ...core.models import Rating, SpecLevel
from ...core.probe import ProbeContext
from ._helpers import fetch_tools_authed as fetch_tools, obtained_without_auth_note

_SECTION = "Tool Safety & Blast Radius"

_SPEC_TOOLS = (
    "https://modelcontextprotocol.io/specification/draft/server/tools"
)

# Tool names / descriptions that suggest dangerously broad access.
_BLAST_PATTERNS = (
    "execute", "shell", "bash", "powershell", "cmd", "run_command",
    "arbitrary", "raw_sql", "eval", "admin", "superuser", "sudo",
    "any_query", "full_access",
)

# Parameter names that often carry untrusted external content.
_INJECTION_PARAM_PATTERNS = (
    "url", "uri", "href", "query", "content", "html", "body",
    "text", "input", "prompt", "message", "instructions",
)

# Tool names suggesting they fetch untrusted external data.
_INJECTION_TOOL_PATTERNS = (
    "web_search", "search", "fetch_url", "read_url", "browse",
    "http_get", "scrape", "crawl",
)


def _fetch_error_result(check: Check, err: str):
    if err == "stdio-no-http":
        return check._result(
            Rating.NA,
            "Cannot probe a stdio server without an HTTP endpoint; connect in "
            "--auth mode to inspect its tools.",
        )
    if err == "auth-required":
        return check._result(
            Rating.NA,
            "tools/list requires authentication; re-run with --auth to inspect it.",
        )
    return check._result(Rating.NA, f"tools/list was unavailable ({err}).")


# ---------------------------------------------------------------------------
# TS-01  Tool blast radius
# ---------------------------------------------------------------------------

@register
class ToolBlastRadius(Check):
    id = "tool-blast-radius"
    rubric_id = "TS-01"
    section = _SECTION
    display_order = 401
    method = "Auth"
    order = 801
    title = "No unrestricted-access tools are present"
    spec_level = SpecLevel.SHOULD
    spec_ref = (
        "Least Privilege: tools SHOULD be narrowly scoped; catch-all tools "
        "(raw SQL execution, arbitrary shell, unrestricted HTTP) are flagged "
        "as high blast-radius."
    )

    def run(self, target, ctx: ProbeContext):
        tools, err = fetch_tools(target, ctx)
        if err:
            return _fetch_error_result(self, err)
        if not tools:
            return self._result(Rating.NA, "tools/list returned an empty tool list.")

        auth_note = obtained_without_auth_note(ctx)
        flagged = []
        for t in tools:
            name = (t.get("name") or "").lower()
            desc = (t.get("description") or "").lower()
            combined = name + " " + desc
            if any(p in combined for p in _BLAST_PATTERNS):
                flagged.append(t.get("name", "?"))

        evidence = {
            "total_tools": len(tools),
            "flagged_tools": flagged,
            "authenticated": bool(ctx.auth_session),
            "endpoint": target.url,
        }

        if flagged:
            return self._result(
                Rating.WARN,
                f"{len(flagged)} of {len(tools)} tool(s) look like they carry "
                f"broad or dangerous access by name/description: {flagged}. "
                f"Review whether this access is actually required.{auth_note}",
                evidence,
            )

        return self._result(
            Rating.PASS,
            f"None of the {len(tools)} tool(s) look like a catch-all or "
            f"dangerously broad tool by name/description.{auth_note}",
            evidence,
        )


# ---------------------------------------------------------------------------
# TS-02  Read / write separation
# ---------------------------------------------------------------------------

@register
class ToolRwSeparation(Check):
    id = "tool-rw-separation"
    rubric_id = "TS-02"
    section = _SECTION
    display_order = 402
    method = "Auth"
    order = 802
    title = "Read and write operations are distinguishable"
    spec_level = SpecLevel.SHOULD
    spec_ref = (
        "Least Privilege: write/destructive tools SHOULD be clearly distinguished "
        "from read-only tools, either via naming convention, annotation "
        "(readOnlyHint), or separate toolsets."
    )

    _WRITE_PATTERNS = (
        "create", "write", "update", "delete", "remove", "modify",
        "insert", "upsert", "patch", "put", "post", "send", "push",
        "edit", "set", "add",
    )
    _READ_PATTERNS = ("read", "get", "list", "fetch", "search", "query", "find", "show")

    def run(self, target, ctx: ProbeContext):
        tools, err = fetch_tools(target, ctx)
        if err:
            return _fetch_error_result(self, err)
        if not tools:
            return self._result(Rating.NA, "tools/list returned an empty tool list.")

        auth_note = obtained_without_auth_note(ctx)
        write_tools, read_tools, readonly_annotated = [], [], []
        for t in tools:
            name = (t.get("name") or "").lower()
            annotations = t.get("annotations") or {}
            if annotations.get("readOnlyHint") is True:
                readonly_annotated.append(t.get("name"))
            elif any(p in name for p in self._WRITE_PATTERNS):
                write_tools.append(t.get("name"))
            elif any(p in name for p in self._READ_PATTERNS):
                read_tools.append(t.get("name"))

        evidence = {
            "total": len(tools),
            "write_tools": write_tools,
            "read_tools": read_tools,
            "readonly_annotated": readonly_annotated,
            "authenticated": bool(ctx.auth_session),
            "endpoint": target.url,
        }

        total_read = len(read_tools) + len(readonly_annotated)

        if not write_tools:
            return self._result(
                Rating.PASS,
                f"No write/destructive tools were detected among {len(tools)} "
                f"tool(s).{auth_note}",
                evidence,
            )

        if readonly_annotated or (read_tools and write_tools):
            # Report every bucket, not just the naming-convention one — a
            # server that annotates every read tool with readOnlyHint would
            # otherwise look like it has zero read tools.
            breakdown = []
            if readonly_annotated:
                breakdown.append(f"{len(readonly_annotated)} via readOnlyHint annotation")
            if read_tools:
                breakdown.append(f"{len(read_tools)} via naming convention")
            return self._result(
                Rating.PASS,
                f"{len(write_tools)} write tool(s) and {total_read} read "
                f"tool(s) ({'; '.join(breakdown)}) are distinguishable from "
                f"each other.{auth_note}",
                evidence,
            )

        return self._result(
            Rating.WARN,
            f"{len(write_tools)} of {len(tools)} tool(s) look potentially "
            f"destructive by name, with no readOnlyHint annotation and no "
            f"read-named tools to contrast them against: {write_tools[:4]}. "
            f"An agent (or a human skimming the tool list) can't tell these "
            f"apart from read-only tools at a glance.{auth_note}",
            evidence,
        )


# ---------------------------------------------------------------------------
# TS-03  Injection surface
# ---------------------------------------------------------------------------

@register
class ToolInjectionSurface(Check):
    id = "tool-injection-surface"
    rubric_id = "TS-03"
    section = _SECTION
    display_order = 403
    method = "Auth"
    order = 803
    title = "Tools with an external-content injection surface are identifiable"
    spec_level = SpecLevel.SHOULD
    spec_ref = (
        "Prompt-Injection Blast Radius: tools that fetch untrusted external content "
        "(web pages, user-supplied URLs, external queries) SHOULD be identified and "
        "their injection surface documented."
    )

    def run(self, target, ctx: ProbeContext):
        tools, err = fetch_tools(target, ctx)
        if err:
            return _fetch_error_result(self, err)
        if not tools:
            return self._result(Rating.NA, "tools/list returned an empty tool list.")

        auth_note = obtained_without_auth_note(ctx)
        flagged = []
        for t in tools:
            name = (t.get("name") or "").lower()
            desc = (t.get("description") or "").lower()
            schema_props = list((t.get("inputSchema") or {}).get("properties", {}).keys())
            props_lower = [p.lower() for p in schema_props]

            name_match = any(p in name for p in _INJECTION_TOOL_PATTERNS)
            param_match = any(p in props_lower for p in _INJECTION_PARAM_PATTERNS)
            desc_match = any(p in desc for p in ("url", "web", "search", "external", "browse"))

            if name_match or (param_match and desc_match):
                flagged.append({
                    "name": t.get("name"),
                    "reason": "tool name suggests fetching external content" if name_match
                              else f"input parameters {schema_props[:3]} plus a description "
                                   f"mentioning web/external content",
                })

        evidence = {
            "total_tools": len(tools),
            "injection_surface_tools": flagged,
            "authenticated": bool(ctx.auth_session),
            "endpoint": target.url,
        }

        if flagged:
            names = [f["name"] for f in flagged]
            return self._result(
                Rating.WARN,
                f"{len(flagged)} of {len(tools)} tool(s) appear to pull in "
                f"untrusted external content that could inject instructions "
                f"into the agent's context: {names}. Review and document this "
                f"injection surface.{auth_note}",
                evidence,
            )

        return self._result(
            Rating.PASS,
            f"No obvious untrusted-content injection surface was detected "
            f"among {len(tools)} tool(s).{auth_note}",
            evidence,
        )
