"""Command-line interface.

    # evaluate one server
    mcp-audit eval --url https://api.githubcopilot.com/mcp --name "GitHub"

    # evaluate a whole list (prompts per-server whether to authenticate)
    mcp-audit eval-file servers/servers.yaml --out results/

    # list every check and the spec clause it enforces
    mcp-audit rubric
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from collections import defaultdict
from contextlib import contextmanager

from .core.base import all_checks
from .core.engine import evaluate
from .core.loader import load_targets
from .core.models import Rating, Target, Transport
from .core.oauth import AuthInput

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box as _box

    _console = Console()
    _RICH = True
except Exception:
    _RICH = False

# ---------------------------------------------------------------------------
# Section metadata: (section_name, display_title, description, methodology_anchor)
# Must match docs/RUBRIC.md's section names/order. A section with no results
# is simply skipped when rendering.
# ---------------------------------------------------------------------------

_SECTIONS = [
    (
        "Connection & Discovery",
        "1 · Connection & Discovery",
        "Will the client connect, and how? Can a client with no prior "
        "knowledge of this server learn that login is required, discover "
        "its Authorization Server, and determine how it can register as a "
        "client?",
        "#1-connection--discovery",
    ),
    (
        "Authentication & Authorization",
        "2 · Authentication & Authorization",
        "How does the client prove identity, and what does the token "
        "permit? Covers the authorization-code flow, PKCE, redirect-URI "
        "and issuer validation, and scope minimization.",
        "#2-authentication--authorization",
    ),
    (
        "Credential & Token Risk",
        "3 · Credential & Token Risk",
        "What credential does the client end up holding, and how exposed "
        "is it? Covers audience binding, transmission, integrity, "
        "per-request validation, and lifetime/refresh rotation.",
        "#3-credential--token-risk",
    ),
    (
        "Tool Safety & Blast Radius",
        "4 · Tool Safety & Blast Radius",
        "How much can this server's tools do? Covers unrestricted "
        "capability, read/write separation, and external-content "
        "injection surface.",
        "#4-tool-safety--blast-radius",
    ),
    (
        "Response Quality & Consistency",
        "5 · Response Quality & Consistency",
        "Can the client reliably parse and act on responses? Covers tool "
        "metadata clarity, structured output, response-shape consistency, "
        "error format, and descriptiveness.",
        "#5-response-quality--consistency",
    ),
    (
        "API / Surface Fidelity",
        "6 · API / Surface Fidelity",
        "Does the MCP tool surface match the server's underlying product "
        "API? Requires the vendor's own API reference as an independent "
        "source of truth.",
        "#6-api--surface-fidelity",
    ),
    (
        "Transport & Protocol Plumbing",
        "7 · Transport & Protocol Plumbing",
        "Is the underlying transport sound? Covers transport encryption, "
        "DNS-rebinding defense, and protocol-version/header consistency "
        "enforcement.",
        "#7-transport--protocol-plumbing",
    ),
]

# ---------------------------------------------------------------------------
# Rating / spec-level / method display helpers
# ---------------------------------------------------------------------------

_BADGE = {
    Rating.PASS: "[green]✓ PASS[/green]",
    Rating.WARN: "[yellow]⚠ WARN[/yellow]",
    Rating.FAIL: "[bold red]✗ FAIL[/bold red]",
    Rating.NA: "[dim]○ n/a[/dim]",
    Rating.MANUAL: "[cyan]⊙ MANUAL[/cyan]",
    Rating.ERROR: "[magenta]⚡ ERROR[/magenta]",
}
_BADGE_PLAIN = {
    Rating.PASS: "PASS",
    Rating.WARN: "WARN",
    Rating.FAIL: "FAIL",
    Rating.NA: "n/a",
    Rating.MANUAL: "MANUAL",
    Rating.ERROR: "ERROR",
}

_METHOD_COLOR = {
    "Probe": "Probe",
    "Auth": "[dim]Auth[/dim]",
    "Doc": "[dim italic]Doc[/dim italic]",
}


def _badge(rating: Rating, rich: bool = True) -> str:
    return _BADGE.get(rating, rating.value) if rich else _BADGE_PLAIN.get(rating, rating.value)


def _method(m: str, rich: bool = True) -> str:
    return _METHOD_COLOR.get(m, f"[dim]{m}[/dim]") if rich else m


def _strip_rubric_id(title: str) -> str:
    """Strip a trailing '(XX-00)' rubric ID from a check title."""
    return re.sub(r"\s+\([A-Z]+-\d+\)$", "", title)


def _count_ratings(results) -> dict:
    counts: dict[Rating, int] = {r: 0 for r in Rating}
    for r in results:
        counts[r.rating] += 1
    return counts


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------

def _print_report_rich(report) -> None:
    results = report.results
    counts = _count_ratings(results)

    # ── Header panel ─────────────────────────────────────────────────────────
    transport = report.target.transport.value
    url_line = f"[dim]{report.target.url}[/dim]  " if report.target.url else ""
    stats = (
        f"[green]{counts[Rating.PASS]} pass[/green]  "
        f"[yellow]{counts[Rating.WARN]} warn[/yellow]  "
        f"[bold red]{counts[Rating.FAIL]} fail[/bold red]  "
        f"[magenta]{counts[Rating.ERROR]} error[/magenta]  "
        f"[dim]{counts[Rating.NA]} n/a  "
        f"{counts[Rating.MANUAL]} manual[/dim]"
        f"[dim]  ({len(results)} checks)[/dim]"
    )
    _console.print()
    _console.print(
        Panel(
            f"[bold]{report.target.name}[/bold]  [dim]\\[{transport}][/dim]\n"
            f"{url_line}\n"
            f"{stats}",
            border_style="dim",
            padding=(0, 1),
        )
    )

    if report.auth_failure:
        _console.print(
            Panel(
                f"[bold yellow]⚠ Authentication did not complete[/bold yellow]\n"
                f"{report.auth_failure}\n"
                f"[dim]Checks requiring a completed session are marked ERROR below.[/dim]",
                border_style="yellow",
                padding=(0, 1),
            )
        )

    # ── Group results by section ──────────────────────────────────────────────
    section_map: dict[str, list] = defaultdict(list)
    orphans = []
    for r in results:
        if r.section:
            section_map[r.section].append(r)
        else:
            orphans.append(r)
    for section in section_map:
        section_map[section].sort(key=lambda r: r.display_order)

    # ── Render each section ───────────────────────────────────────────────────
    for section_name, display_title, description, anchor in _SECTIONS:
        section_results = section_map.get(section_name, [])
        if not section_results:
            continue

        _console.print()
        _console.rule(f"[bold]{display_title}[/bold]", align="left")
        _console.print(f"[dim]{description}[/dim]")
        _console.print(f"[dim]→ METHODOLOGY.md{anchor}[/dim]")
        _console.print()

        tbl = Table(
            box=_box.SIMPLE_HEAD,
            padding=(0, 1),
            show_header=True,
            header_style="bold dim",
            expand=True,
        )
        tbl.add_column("ID", min_width=6, no_wrap=True, ratio=1)
        tbl.add_column("Meth", min_width=8, no_wrap=True, ratio=1)
        tbl.add_column("Check  ·  Result", ratio=8)

        for r in section_results:
            title = _strip_rubric_id(r.title)
            detail = r.detail or ""
            badge = _badge(r.rating)
            combined = (
                f"[bold]{title}[/bold]\n{badge}  [dim]{detail}[/dim]"
                if detail
                else f"[bold]{title}[/bold]\n{badge}"
            )
            tbl.add_row(
                r.rubric_id or r.check_id,
                _method(r.method),
                combined,
            )

        _console.print(tbl)

    # ── Results with no section set ──────────────────────────────────────────
    if orphans:
        _console.print()
        _console.rule("[bold dim]Other checks[/bold dim]", align="left")
        tbl = Table(box=_box.SIMPLE_HEAD, padding=(0, 1), header_style="bold dim")
        tbl.add_column("ID", min_width=40)
        tbl.add_column("Result", min_width=42)
        for r in orphans:
            tbl.add_row(r.check_id, _badge(r.rating))
        _console.print(tbl)


# ---------------------------------------------------------------------------
# Plain-text fallback
# ---------------------------------------------------------------------------

def _print_report_plain(report) -> None:
    results = report.results
    counts = _count_ratings(results)
    t = report.target
    print(f"\n=== {t.name} [{t.transport.value}] ===")
    if t.url:
        print(f"    {t.url}")
    print(
        f"    pass={counts[Rating.PASS]}  warn={counts[Rating.WARN]}  "
        f"fail={counts[Rating.FAIL]}  error={counts[Rating.ERROR]}  "
        f"n/a={counts[Rating.NA]}  manual={counts[Rating.MANUAL]}  "
        f"({len(results)} checks)"
    )

    if report.auth_failure:
        print(f"\n!! Authentication did not complete: {report.auth_failure}")
        print("   Checks requiring a completed session are marked ERROR below.")

    section_map: dict[str, list] = defaultdict(list)
    orphans = []
    for r in results:
        if r.section:
            section_map[r.section].append(r)
        else:
            orphans.append(r)
    for section in section_map:
        section_map[section].sort(key=lambda r: r.display_order)

    for section_name, display_title, description, anchor in _SECTIONS:
        section_results = section_map.get(section_name, [])
        if not section_results:
            continue
        print(f"\n── {display_title} ──")
        print(f"   {description}")
        print(f"   See METHODOLOGY.md{anchor}")
        for r in section_results:
            rating_str = _BADGE_PLAIN.get(r.rating, r.rating.value)
            title = _strip_rubric_id(r.title)
            rid = r.rubric_id or r.check_id
            print(f"\n  {rid}  [{rating_str}]  {title}  [{r.method}]")
            if r.detail:
                print(f"          {r.detail}")

    if orphans:
        print("\n── Other ──")
        for r in orphans:
            rating_str = _BADGE_PLAIN.get(r.rating, r.rating.value)
            print(f"  {r.check_id}  [{rating_str}]  {r.title}")
            if r.detail:
                print(f"          {r.detail}")


def _print_report(report) -> None:
    if _RICH:
        _print_report_rich(report)
    else:
        _print_report_plain(report)


def _print_server_separator(target, index: int | None = None, total: int | None = None) -> None:
    """Full-width divider + bold name/URL header printed before each server's
    report in a multi-server run, with blank space above it, so it's obvious
    at a glance where one server's block ends and the next begins."""
    label = target.name or target.url or "unnamed"
    if index is not None and total is not None:
        label = f"{label}  ·  {index}/{total}"

    if _RICH:
        _console.print()
        _console.print()
        _console.rule(f"[bold]{label}[/bold]", style="bold cyan")
        if target.url:
            _console.print(f"[bold cyan]{target.url}[/bold cyan]")
    else:
        import shutil
        width = shutil.get_terminal_size((100, 20)).columns
        print("\n")
        print("=" * width)
        print(f"  {label}")
        if target.url:
            print(f"  {target.url}")
        print("=" * width)


# ---------------------------------------------------------------------------
# Rubric listing (section-grouped)
# ---------------------------------------------------------------------------

def _cmd_rubric(args):
    """Print every check in rubric order with its spec clause."""
    checks = [c() for c in all_checks()]
    section_map: dict[str, list] = defaultdict(list)
    orphans = []
    for c in checks:
        if c.section:
            section_map[c.section].append(c)
        else:
            orphans.append(c)
    for s in section_map:
        section_map[s].sort(key=lambda c: c.display_order)

    if _RICH:
        _console.print()
        _console.print("[bold]MCP Audit Rubric[/bold]  [dim](spec-aligned, rubric order)[/dim]")
        for section_name, display_title, description, anchor in _SECTIONS:
            checks_in = section_map.get(section_name, [])
            if not checks_in:
                continue
            _console.print()
            _console.rule(f"[bold]{display_title}[/bold]", align="left")
            tbl = Table(
                box=_box.SIMPLE_HEAD, padding=(0, 1),
                show_header=True, header_style="bold dim",
                expand=True,
            )
            tbl.add_column("ID", min_width=6, no_wrap=True, ratio=1)
            tbl.add_column("Meth", min_width=8, no_wrap=True, ratio=1)
            tbl.add_column("Check  ·  Spec reference", ratio=8)
            for c in checks_in:
                tbl.add_row(
                    c.rubric_id or c.id,
                    _method(c.method),
                    f"[bold]{_strip_rubric_id(c.title)}[/bold]\n[dim]{c.spec_ref}[/dim]",
                )
            _console.print(tbl)
        if orphans:
            _console.print()
            _console.rule("[bold dim]Other[/bold dim]", align="left")
            for c in orphans:
                _console.print(f"  [dim]{c.id}[/dim]  {c.title}")
    else:
        print("\nMCP Audit Rubric (rubric order)\n")
        for section_name, display_title, description, anchor in _SECTIONS:
            checks_in = section_map.get(section_name, [])
            if not checks_in:
                continue
            print(f"\n── {display_title} ──")
            for c in checks_in:
                print(f"  {c.rubric_id or c.id}  [{c.method}]  {_strip_rubric_id(c.title)}")
                print(f"       {c.spec_ref}\n")


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _build_auth_input(args) -> AuthInput:
    """Resolve --auth credential material: supplied token > supplied client
    credentials > fully-automatic. When both a flag and its env var are set,
    the flag wins — it's the more specific signal for this invocation."""
    token = args.token or os.environ.get("MCP_AUDIT_TOKEN")
    client_id = args.client_id
    client_secret = args.client_secret or os.environ.get("MCP_AUDIT_CLIENT_SECRET")
    client_metadata_url = args.client_metadata_url
    redirect_port = args.redirect_port

    if client_secret and not client_id:
        print("mcp-audit: --client-secret (or MCP_AUDIT_CLIENT_SECRET) requires --client-id",
              file=sys.stderr)
        sys.exit(2)
    if client_id and client_metadata_url:
        print("mcp-audit: pass either --client-id or --client-metadata-url, not both",
              file=sys.stderr)
        sys.exit(2)
    if token and (client_id or client_metadata_url):
        ignored = "--client-id/--client-secret" if client_id else "--client-metadata-url"
        print(f"mcp-audit: --token (or MCP_AUDIT_TOKEN) takes priority over "
              f"{ignored} for authentication; ignoring the latter.", file=sys.stderr)

    return AuthInput(
        token=token,
        client_id=client_id,
        client_secret=client_secret,
        client_metadata_url=client_metadata_url,
        redirect_port=redirect_port,
    )


def _confirm_auth(name: str) -> bool:
    """Ask, per target, whether to run the auth flow before evaluating it.
    Defaults to no on a non-interactive stdin (CI, piped input) instead of
    blocking on a prompt no one can answer."""
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(f"Authenticate with \"{name}\"? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


@contextmanager
def _progress(target_name: str):
    """Yield an on_result callback for evaluate() that renders a single-line,
    live-updating progress indicator while checks run. Rich renders an actual
    bar; the plain fallback overwrites one line with \\r."""
    if _RICH:
        from rich.progress import BarColumn, Progress, TextColumn
        with Progress(
            TextColumn("[dim]{task.fields[label]}[/dim]"),
            BarColumn(),
            TextColumn("[dim]{task.completed}/{task.total} checks[/dim]"),
            console=_console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("eval", total=1, label=f"{target_name} · starting")

            def on_result(result, completed, total):
                id_ = result.rubric_id or result.check_id
                label = (
                    f"{target_name} · checks complete"
                    if completed == total
                    else f"{target_name} {id_}"
                )
                progress.update(task_id, completed=completed, total=total, label=label)

            yield on_result
    else:
        def on_result(result, completed, total):
            id_ = result.rubric_id or result.check_id
            status = "checks complete" if completed == total else f"checking {id_}"
            line = f"\r[{completed}/{total} checks] {target_name} · {status}"
            print(line.ljust(100), end="", flush=True)
            if completed == total:
                print()

        yield on_result


def _cmd_eval(args):
    # v1 only evaluates remote HTTP servers (see docs/RUBRIC.md's "Version"
    # section) — there's no stdio execution path to choose between.
    target = Target(
        name=args.name or args.url or "unnamed",
        url=args.url,
        transport=Transport.HTTP if args.url else Transport.UNKNOWN,
    )
    auth_input = _build_auth_input(args)
    # Supplying a credential (--token, --client-id, --client-metadata-url) is
    # itself a request to authenticate — --auth is only needed to trigger the
    # zero-credential, fully-automatic self-registration path.
    include_auth = args.auth or auth_input.mode() != "auto"
    with _progress(target.name) as on_result:
        report = evaluate(target, include_auth=include_auth,
                           auth_input=auth_input, on_result=on_result)
    _print_report(report)
    if args.out:
        _write_json(report, args.out)
        print(f"\nWrote the full report, including every check's evidence, to {args.out}")


def _cmd_eval_file(args):
    targets = load_targets(args.path)
    outdir = pathlib.Path(args.out) if args.out else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
    auth_input = _build_auth_input(args)
    # A supplied credential applies to every target without prompting —
    # only the no-credential case falls back to asking per target.
    has_supplied_credential = auth_input.mode() != "auto"
    summary = []
    total = len(targets)
    for i, target in enumerate(targets, start=1):
        include_auth = has_supplied_credential or _confirm_auth(target.name)
        with _progress(target.name) as on_result:
            report = evaluate(target, include_auth=include_auth, auth_input=auth_input,
                               on_result=on_result)
        _print_server_separator(target, index=i, total=total)
        _print_report(report)
        summary.append(report.to_dict())
        if outdir:
            _write_json(report, str(outdir / f"{_slug(target.name)}.json"))
    if outdir:
        (outdir / "summary.json").write_text(json.dumps(summary, indent=2))
        print(
            f"\nWrote {len(summary)} per-server report(s) and summary.json "
            f"(all servers, evidence included) to {outdir}/"
        )


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _write_json(report, path: str):
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(path).write_text(json.dumps(report.to_dict(), indent=2))


def main(argv=None):
    from .core.engine import _autoload_checks
    _autoload_checks()

    p = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Spec-aligned security evaluator for MCP servers.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("eval", help="Evaluate a single MCP server.")
    pe.add_argument("--url", help="Remote MCP endpoint URL.")
    pe.add_argument("--name", help="Display name.")
    pe.add_argument("--auth", action="store_true",
                    help="Authenticate before running the checks that need a "
                         "completed session. Only needed for the fully-automatic, "
                         "zero-credential self-registration path — supplying "
                         "--token, --client-id, or --client-metadata-url already "
                         "authenticates on its own. See docs/METHODOLOGY.md "
                         "'How the OAuth flow works'.")
    pe.add_argument(
        "--token",
        help="Priority 1: use this access token/PAT/API key directly as "
             "'Authorization: Bearer <value>' and skip the OAuth flow entirely "
             "(no --auth needed) — only checks that need a token mcp-audit "
             "itself issued (the interactive flow, refresh rotation) report "
             "n/a; everything else, including initialize and tools/list, runs "
             "normally. Prefer the MCP_AUDIT_TOKEN environment variable over "
             "this flag: command-line arguments are visible to other processes "
             "(e.g. `ps`) and land in shell history.",
    )
    pe.add_argument(
        "--client-id",
        help="Priority 2: run the full interactive login flow using this "
             "pre-registered client ID instead of self-registering one. For "
             "servers that require manual app registration (e.g. GitHub) and "
             "don't support Dynamic Client Registration or Client ID Metadata "
             "Documents. Pair with --client-secret if the app is confidential; "
             "mutually exclusive with --client-metadata-url.",
    )
    pe.add_argument(
        "--client-secret",
        help="Optional secret for a confidential --client-id app, sent via HTTP "
             "Basic auth at the token endpoint. Prefer the "
             "MCP_AUDIT_CLIENT_SECRET environment variable over this flag for "
             "the same reason as --token.",
    )
    pe.add_argument(
        "--client-metadata-url",
        help="Priority 2 (alternative to --client-id): URL of a self-hosted "
             "Client ID Metadata Document to authorize with directly, instead "
             "of self-registering. Requires the Authorization Server to "
             "support Client ID Metadata Documents. Mutually exclusive with "
             "--client-id.",
    )
    pe.add_argument(
        "--redirect-port",
        type=int,
        help="Bind the OAuth loopback listener to this fixed port instead of "
             "an OS-assigned one, so the redirect URI "
             "(http://127.0.0.1:<port>/callback) is stable across runs. Needed "
             "for providers whose registered redirect URI must match exactly, "
             "port included (e.g. GitHub OAuth Apps) — pair with --client-id "
             "using this same port in the app's callback URL. Omit to keep the "
             "default OS-assigned ephemeral port. Fails clearly if the port is "
             "already in use, rather than silently picking another one.",
    )
    pe.add_argument("--out", help="Write the JSON report to this path — the only place each "
                                   "check's full evidence (exact requests/responses) is saved; "
                                   "the console shows only the summary line.")
    pe.set_defaults(func=_cmd_eval)

    pf = sub.add_parser("eval-file", help="Bulk-evaluate servers from a YAML/JSON file.")
    pf.add_argument("path", help="Path to servers.yaml / servers.json.")
    pf.add_argument("--token", help="Credential to use if you confirm auth for a "
                                     "target at its prompt. See `eval --help`. Also "
                                     "MCP_AUDIT_TOKEN.")
    pf.add_argument("--client-id", help="See `eval --help`.")
    pf.add_argument("--client-secret",
                    help="See `eval --help`. Also MCP_AUDIT_CLIENT_SECRET.")
    pf.add_argument("--client-metadata-url", help="See `eval --help`.")
    pf.add_argument("--redirect-port", type=int, help="See `eval --help`.")
    pf.add_argument("--out", help="Directory to write one JSON report per server plus "
                                   "summary.json (all servers, one file) — the only place each "
                                   "check's full evidence is saved; the console shows only the "
                                   "summary line.")
    pf.set_defaults(func=_cmd_eval_file)

    pr = sub.add_parser("rubric", help="Print the spec-aligned rubric in section order.")
    pr.set_defaults(func=_cmd_rubric)

    args = p.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
