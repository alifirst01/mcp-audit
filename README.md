# mcp-audit

A **customer-focused security and usability evaluator for MCP servers.** Point it
at a Model Context Protocol server and it answers the questions that actually
matter to someone deciding whether to connect an agent to it: can the agent
discover what this server does, can it actually use the responses it gets back,
how does login work and is the resulting token protected, and can the agent get
at credentials it shouldn't be able to.

It runs unauthenticated by default — observing the server the way a new client
would (the 401 challenge, the public discovery documents) — and never sends
destructive or exploit-shaped requests. Pass `--auth` and it runs a full
OAuth 2.1 + PKCE browser login flow to unlock the checks that need a
completed session, under a conservative policy that never calls a
write/destructive tool. See [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

This is not a protocol conformance tester (see the official
[conformance suite](https://github.com/modelcontextprotocol/conformance) for that).
It answers a different question: **not "does this server work," but "is it safe
and usable to give an agent."**

## Install

```bash
pip install -e .            # from a clone
# or, once published:
# pip install mcp-audit
```

## Quickstart

```bash
# Evaluate one remote server, unauthenticated
mcp-audit eval --url https://api.githubcopilot.com/mcp --name "GitHub"

# Same, authenticated — see "Authenticating" below for which flags to add
mcp-audit eval --url https://api.githubcopilot.com/mcp --name "GitHub" --auth

# Evaluate a whole list (bulk)
mcp-audit eval-file servers/servers.yaml --out results/

# Print the rubric: every check and the customer-focus / spec reference it maps to
mcp-audit rubric
```

## Authenticating (`--auth`, or just a credential flag)

Authenticating unlocks §2–3 (Authentication & Authorization, Credential &
Token Risk) and the Auth-tagged checks in §4 (Tool Safety & Blast Radius).
Not every server can be driven the same way, so there are three credential
paths. Add flags to tell it which one to use; **if you supply more than one,
this priority order decides which wins** (mcp-audit prints a warning and
ignores the rest). Supplying a credential (`--token`, `--client-id`, or
`--client-metadata-url`) is itself enough to authenticate — `--auth` on its
own is only needed to trigger Path 3, the zero-credential automatic path:

| Priority | Path | Flags | Use when |
|---|---|---|---|
| 1 | **Static token** | `--token` (or `MCP_AUDIT_TOKEN`) | You already have an access token, PAT, or API key for this server. Skips the OAuth flow entirely — the tool goes straight to the `initialize` handshake with `Authorization: Bearer <token>`, no browser, no registration. Checks that specifically test the OAuth flow itself (PKCE, redirect-URI/issuer validation, refresh rotation) report `n/a` — there's no flow or token lifecycle to probe. |
| 2 | **Supplied client credentials** | `--client-id` (+ optional `--client-secret` / `MCP_AUDIT_CLIENT_SECRET`), or `--client-metadata-url` | The server requires pre-registration and doesn't support self-registration — e.g. **GitHub**, where you create an OAuth App by hand first. Runs the real interactive login flow, skipping only the registration step. |
| 3 | **Auto** | `--auth`, nothing else | The server supports self-registration: Client ID Metadata Documents or Dynamic Client Registration. Works out of the box against **Supabase's default auth**, and against **WorkOS, Stytch, Keycloak, or Auth0** deployments with DCR enabled. |

```bash
# Path 1 — paste a token/API key you already have (fastest; no browser, no --auth needed)
export MCP_AUDIT_TOKEN=napi_your_existing_api_key
mcp-audit eval --url https://mcp.neon.tech/mcp

# Path 2 — pre-registered app (GitHub requires this; DCR/CIMD aren't available)
#   1. Create an OAuth App in GitHub settings, note its client ID (and secret,
#      if confidential), and set its callback URL to http://127.0.0.1:*/callback
#      (or the specific loopback port mcp-audit prints when it starts the flow).
#   2. Run:
mcp-audit eval --url https://api.githubcopilot.com/mcp \
  --client-id YOUR_CLIENT_ID
# add --client-secret (or MCP_AUDIT_CLIENT_SECRET) if the app is confidential

# Path 3 — auto self-registration (Supabase default / WorkOS / Stytch /
# Keycloak / Auth0 with DCR enabled) — needs --auth since no credential is given
mcp-audit eval --url https://your-supabase-project.mcp.example.com/mcp --auth
```

**Security note:** prefer the `MCP_AUDIT_TOKEN` / `MCP_AUDIT_CLIENT_SECRET`
environment variables over the `--token` / `--client-secret` flags where you
can. Command-line arguments are visible to other processes on the same
machine (e.g. via `ps`) and get recorded in shell history; environment
variables set in the calling shell are not. mcp-audit never writes either
value — nor the access token obtained via `--auth` — into the console
output or the JSON report saved by `--out`: only the resulting evidence
(status codes, header values, claims), never the raw token or secret. See
"Where evidence lives" below for exactly which file that ends up in.

**Where evidence lives:** the console only ever prints each check's
human-readable summary line — it never prints the underlying request/
response evidence. That evidence exists only in memory unless you pass
`--out`, in which case it's written to disk: `eval --out report.json`
writes one file at that path; `eval-file --out results/` writes one file
per server into the `results/` directory *plus* `results/summary.json`,
which holds every server's full report (evidence included) in one file.
Without `--out`, evidence is generated during the run but never saved
anywhere.

**If authentication doesn't complete** — the server needs a path you didn't
supply, a supplied client ID is invalid, the browser never redirected back,
etc. — mcp-audit prints the specific reason in a banner at the top of the
report, before the per-check results, and marks every check that needed the
session `ERROR` with the same reason rather than silently producing
misleading `n/a`s.

Whichever path completes, checks that specifically test the *interactive
authorization flow* (PKCE enforcement, redirect-URI validation, issuer
validation — the parts of §2 Authentication & Authorization that need a
live flow to probe) report `n/a` under the static-token path, since no flow
ran to test. Refresh-token rotation (CT-05, §3) is `n/a` for the same
reason — a static token has no OAuth token response to check the lifetime
or rotation of. Everything else about the token and the server's tools
(audience binding, transmission, integrity, tools/list, transport) runs
normally under all three paths, and reports which path was used as
`auth_method` (`static-token` or `oauth`) in its evidence.

## What it checks

Sections are grouped by the question a developer needs answered at each
stage of an MCP client (agent) calling an MCP server — not by MCP spec
section number. All seven sections always appear in the rubric; only a
defined subset of checks is live in v1 (25 of 44 — scoped to remote HTTP
servers, using the Probe and Auth methods only), the rest are `planned`. Run
`mcp-audit rubric` for the full, always-current list, or read
[docs/RUBRIC.md](docs/RUBRIC.md) for the detailed breakdown, including the
live/planned status and method for every check.

| # | Section | Question |
|---|---|---|
| 1 | Connection & Discovery | Will the client connect, and how? |
| 2 | Authentication & Authorization | How does the client prove identity, and what does the token permit? |
| 3 | Credential & Token Risk | What credential does the client end up holding, and how exposed is it? |
| 4 | Tool Safety & Blast Radius | How much can this server's tools do? |
| 5 | Response Quality & Consistency | Can the client reliably parse and act on responses? |
| 6 | API / Surface Fidelity | Does the MCP tool surface match the server's underlying product API? |
| 7 | Transport & Protocol Plumbing | Is the underlying transport sound? |

Sections 5 and 6 are entirely `planned` in v1 — no checks are registered
for them in the committed tree yet.

Ratings: **PASS** (meets it) · **WARN** (partial / SHOULD unmet / deviation) ·
**FAIL** (violates a MUST) · **n/a** (doesn't apply, e.g. an OAuth check on a stdio
server) · **MANUAL** (needs a documentation/source review) · **ERROR** (couldn't
evaluate, e.g. the `--auth` flow didn't complete).

## Transports

The MCP auth spec applies to **HTTP** transports. **stdio** servers explicitly retrieve
credentials from the environment instead, so HTTP-only checks are marked `n/a` for them
and their evaluation focuses on documented credential handling. Set `transport:` per
server in your list.

## Add a check (the whole extensibility story)

**A live (v1) check** gets its own `@register`-decorated class in one of the
files under `mcp_audit/checks/server/` (grouped by section — e.g.
`connection_discovery.py`, `tool_safety.py`):

```python
from mcp_audit.core.base import Check, register
from mcp_audit.core.models import Rating, SpecLevel

@register
class MyCheck(Check):
    id = "my-check"
    rubric_id = "CD-09"                    # next free ID in its section — see docs/RUBRIC.md
    section = "Connection & Discovery"     # must match an entry in cli.py's _SECTIONS
    display_order = 109
    title = "Human-readable title, in plain language — no bare acronyms"
    spec_level = SpecLevel.SHOULD
    spec_ref = "MCP Auth §X.Y: the exact clause, or a Customer Focus criterion"
    method = "Probe"               # Probe / Auth / Doc — see docs/METHODOLOGY.md
    requires_http = True           # skip on stdio targets
    requires_auth = False          # True if it needs a completed --auth session
    order = 50                     # lower runs first; discovery checks use low numbers,
                                    # anything needing ctx.auth_session must be >= 400
                                    # (see core/engine.py's lazy auth trigger)

    def run(self, target, ctx):
        r = ctx.get(target.url)   # cached, shared HTTP
        if ...:
            return self._result(Rating.PASS, "why it passed — name the actual value seen")
        return self._result(Rating.WARN, "what was off", {"evidence": r.status})
```

The engine auto-discovers it — `core/engine.py`'s `_autoload_checks()` walks
every module under `mcp_audit.checks`, so dropping the file in is enough.
Nothing else changes. See `docs/METHODOLOGY.md` for the writing-style rule
every check's `detail` text follows.

**A `planned` check** (a rubric entry not yet in v1's live scope) goes in
the mirrored path under `admin/` instead — e.g.
`admin/checks/server/response_quality.py` — which is git-ignored and never
imported by `_autoload_checks()`, since it only walks `mcp_audit.checks`.
To promote a planned check to live: update its status in `docs/RUBRIC.md`
(the source of truth), then move its file (and any check-only helper it
needs from `admin/checks/server/_helpers_planned.py`) into the matching
path under `mcp_audit/checks/server/` — the relative imports in the admin
files already point at the right place once moved.

## Roadmap

Priority and ordering of `planned` work is intentionally left unstated in
`docs/RUBRIC.md` — see its "Status" tag definition — so this list is
illustrative, not a commitment or a sequence:

- **Automated API-parity diff (SF-01):** `Target.openapi_ref` / `--openapi-ref` is
  already wired as an extension point; today it's a pointer for the manual
  review in `admin/checks/server/api_surface_fidelity.py`, not an automated
  diff against `tools/list`.
- **Cross-audience token rejection (CT-03) against a genuine second resource
  server:** today's check is a best-effort substitute (a tampered copy of the
  real token, which proves integrity verification but not audience-specific
  rejection) since a single-target run has no second resource server to mint
  a cross-audience token against.
- **Local/stdio evaluation:** the `Server: Local` and `Server: Remote & Local`
  checks across §3–5 (see `admin/checks/server/`) are structured but not yet
  wired up to actually run against stdio targets.
- **Client evaluation**: a parallel `checks/client/` suite reusing the same engine.

## License

MIT
