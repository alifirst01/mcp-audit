"""Tool Safety & Blast Radius — what could go wrong if an agent uses this
server's tools unsupervised or on adversarial input. Covers unrestricted
capability, read/write separation, and external-content injection surface.

Each check reads the tool list via `_helpers.fetch_tools_authed`. They are
tagged Method: Auth but not `requires_auth`-gated: a server that serves
tools/list unauthenticated is still evaluated, with the evidence noting the
data was obtained without authentication. tools/list unavailable with no
session -> n/a; refused despite a session -> error with the request/response.

Spec source: modelcontextprotocol.io/specification/draft/server/tools
"""
from __future__ import annotations

from typing import Optional

from ...core.base import Check, EVIDENCE_NOTE, register
from ...core.models import Rating, SpecLevel
from ...core.probe import ProbeContext
from ._helpers import (
    auth_method_label, fetch_tools_authed as fetch_tools, obtained_without_auth_note,
    scope_evidence,
)

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
_INJECTION_PARAM_PATTERNS = ("url", "uri", "href", "link", "endpoint")

# Tool names suggesting they fetch untrusted external data.
_INJECTION_TOOL_PATTERNS = (
    "web_search", "fetch_url", "read_url", "browse",
    "http_get", "scrape", "crawl", "open_url",
)


_SCOPE_LIMITED_REASON = (
    "tool list unavailable — server may require a scope to enumerate tools; "
    "re-run with --scopes."
)


def _scope_limited_reason(ctx: ProbeContext) -> Optional[str]:
    """None for a static --token: its permissions aren't ours to widen with
    --scopes, so blaming scope there would be misleading."""
    session = ctx.auth_session
    if not session or session.probe_evidence.get("auth_mode") == "supplied-token":
        return None
    return _SCOPE_LIMITED_REASON


def _looks_scope_related(err: str) -> bool:
    if err.startswith("unexpected-status:401") or err.startswith("unexpected-status:403"):
        return True
    return err.startswith("jsonrpc-error:") and "scope" in err.lower()


def _fetch_error_result(check: Check, err: str, ctx: ProbeContext):
    """Map a `fetch_tools` error string to a CheckResult. A refusal with an
    active session is an error (the tool list should have been reachable);
    everything else is n/a."""
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

    evidence = ctx.last_tools_list_evidence or {}
    if err == "sse-async-not-captured":
        return check._result(
            Rating.NA,
            "The server accepted the tools/list request with HTTP 202 and "
            "returns the result on a separate SSE stream, which this probe "
            "does not consume. SSE async response not captured.",
            evidence,
        )
    if _looks_scope_related(err):
        reason = _scope_limited_reason(ctx)
        if reason:
            return check._result(Rating.NA, reason, evidence)
    if ctx.auth_session:
        return check._result(
            Rating.ERROR,
            f"tools/list was rejected ({err}) even though an authenticated "
            f"session is available, so the tool list could not be inspected. "
            + EVIDENCE_NOTE,
            evidence,
        )
    return check._result(
        Rating.NA, f"tools/list was unavailable ({err}).", evidence
    )


@register
class ToolBlastRadius(Check):
    """TS-01: no catch-all tool (raw SQL, arbitrary shell, unrestricted HTTP)
    is exposed. Least Privilege — tools SHOULD be narrowly scoped."""

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
            return _fetch_error_result(self, err, ctx)
        if not tools:
            return self._result(
                Rating.NA,
                _scope_limited_reason(ctx) or "tools/list returned an empty tool list.",
            )

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
            "auth_method": auth_method_label(ctx),
            **scope_evidence(ctx),
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


@register
class ToolRwSeparation(Check):
    """TS-02: write/destructive tools are distinguishable from read-only ones
    by naming, a `readOnlyHint` annotation, or separate toolsets. Least
    Privilege SHOULD."""

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
            return _fetch_error_result(self, err, ctx)
        if not tools:
            return self._result(
                Rating.NA,
                _scope_limited_reason(ctx) or "tools/list returned an empty tool list.",
            )

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
            "auth_method": auth_method_label(ctx),
            **scope_evidence(ctx),
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
            # Count both buckets: a server that annotates every read tool with
            # readOnlyHint would otherwise appear to have no read tools.
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


@register
class ToolInjectionSurface(Check):
    """TS-03: tools that pull in untrusted external content (web pages,
    arbitrary/user-supplied URLs, open-web search) are identifiable so their
    prompt-injection surface can be documented. SHOULD.

    Scope: this is a name/description/schema heuristic and only covers the
    clearly-external case — a tool that fetches an arbitrary URL or crawls
    the open web. Second-order injection via attacker-planted first-party
    content (a prompt injection hidden in an issue body, comment, or email
    that a benign-looking tool like `get_issue` reads back) is not
    detectable this way and is out of scope for automated detection; it
    requires manual review of what each tool's response actually returns.
    """

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
            return _fetch_error_result(self, err, ctx)
        if not tools:
            return self._result(
                Rating.NA,
                _scope_limited_reason(ctx) or "tools/list returned an empty tool list.",
            )

        auth_note = obtained_without_auth_note(ctx)
        flagged = []
        for t in tools:
            name = (t.get("name") or "").lower()
            desc = (t.get("description") or "").lower()
            schema_props = list((t.get("inputSchema") or {}).get("properties", {}).keys())
            props_lower = [p.lower() for p in schema_props]

            name_match = any(p in name for p in _INJECTION_TOOL_PATTERNS)
            param_match = any(p in props_lower for p in _INJECTION_PARAM_PATTERNS)
            desc_match = any(p in desc for p in (
                "arbitrary url", "any url", "web page", "webpage", "the web",
                "external website", "third-party", "internet", "crawl",
            ))

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
            "auth_method": auth_method_label(ctx),
            **scope_evidence(ctx),
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
