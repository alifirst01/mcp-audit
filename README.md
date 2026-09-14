# mcp-audit

A security posture evaluator for remote [Model Context Protocol](https://modelcontextprotocol.io) servers. It connects to an MCP server the way a real client would, runs a set of spec-referenced checks against its authorization, transport, token, and tool-exposure behavior, and reports each result with the evidence behind it.

It is **read-only and non-destructive**. It sends the requests a conforming client sends, plus a small set of deliberately malformed variants used to test whether the server rejects them. It never fuzzes, floods, or attempts exploitation.

---

## What it checks

25 checks across five areas. Each check maps to a clause in the MCP authorization/transport spec or to an established security practice (least privilege, OWASP NHI). Full text and spec references: [`docs/RUBRIC.md`](docs/RUBRIC.md).

| Area | Checks | Examples |
|------|--------|----------|
| Connection & Discovery | CD-01…CD-07 | 401 on unauthenticated request; Protected Resource Metadata (RFC 9728); Authorization Server metadata (RFC 8414); registration-mechanism classification |
| Authentication & Authorization | AA-01…AA-05 | PKCE advertised and enforced; redirect-URI validation; issuer validation; scope minimization |
| Credential & Token Risk | CT-01…CT-05 | bearer-in-header only; audience binding; tampered-token rejection; invalid-token rejection; short-lived tokens with refresh rotation |
| Transport & Protocol | TR-01…TR-08 | HTTPS everywhere; `Origin` validation (DNS-rebinding); protocol-version enforcement; header/body consistency |
| Tool Safety & Blast Radius | TS-01…TS-03 | unrestricted-access tools; read/write separation; external-content injection surface |

Each check is evaluated one of three ways, shown in its output as a **method**:

| Method | Meaning |
|--------|---------|
| `Probe` | Determined from an unauthenticated request or public metadata. No credentials needed. |
| `Auth`  | Requires a completed authenticated session (see [Authentication](#authentication)). |
| `Doc`   | Assessed from documentation; reported as a finding, not an automated pass/fail. |

### Ratings: 
- `pass`
- `warn` (a SHOULD is unmet, or a MUST is met imprecisely)
- `fail` (a MUST is violated)
- `na` (not applicable)
- `manual` (needs server-side confirmation) · `error` (could not evaluate).

---

## Install

```bash
git clone <repo-url> && cd mcp-audit
pip install -e .
```

Requires Python 3.10+.

---

## Usage

Every example writes full evidence with `--out`. Without `--out`, the console shows only each check's summary line and no evidence is saved.

### Evaluate one server

Probe-only — no credentials. Runs every `Probe` check; `Auth` checks report `na`:

```bash
mcp-audit eval --url https://mcp.sentry.dev/mcp --out sentry.json
```

### Evaluate a list of servers

`--out` here is a **directory**: one JSON report per server plus a combined `summary.json`.

```bash
mcp-audit eval-file servers.yaml --out results/
```

### Print the rubric

```bash
mcp-audit rubric
```

---

## Authentication

`Auth`-method checks (audience binding, PKCE enforcement, token/redirect validation, tool-surface) need a completed session. There are three ways to authenticate; pick the one that matches how the server registers clients. All work on both `eval` and `eval-file`.

| Mode | Flags | When to use |
|------|-------|-------------|
| **Self-registration (DCR)** | `--auth` | Server's authorization server supports Dynamic Client Registration. The tool registers itself and opens a browser to log in. This is the only mode that needs `--auth`. |
| **Preconfigured app** | `--client-id <id>` (+ `--client-secret`, `--redirect-port`) | Server needs a manually registered OAuth app and doesn't support DCR (e.g. GitHub). |
| **Static token** | `--token <value>` | You already hold an API key / PAT. Sent as `Authorization: Bearer <value>`, skipping OAuth. |

`--token` and `--client-id` are mutually exclusive — each authenticates a run a different way, and neither needs `--auth`.

**DCR (self-registration):**
```bash
mcp-audit eval --url https://mcp.sentry.dev/mcp --auth --out sentry.json
```

**Static token** — checks that need a tool-issued token (interactive flow, refresh rotation) report `na`; everything else, including `tools/list`, runs normally:
```bash
mcp-audit eval --url https://mcp.neon.tech/mcp --token "$NEON_API_KEY" --out neon.json
```

**Preconfigured client** — register the app's callback as `http://127.0.0.1:8765/callback` and pass the same port:
```bash
mcp-audit eval --url https://api.githubcopilot.com/mcp \
  --client-id "$GH_ID" --client-secret "$GH_SECRET" --redirect-port 8765 --out github.json
```

### CLI arguments

| Argument | Applies to | Purpose |
|----------|-----------|---------|
| `--url` | `eval` | Remote MCP endpoint URL. |
| `--name` | `eval` | Display name for the report. |
| `--auth` | both | Authenticate via self-registration (DCR). Not needed when a credential flag is supplied. |
| `--token` | both | Use this token/PAT/API key directly as a bearer credential; skips OAuth. |
| `--client-id` | both | Run the login flow with a pre-registered client ID instead of self-registering. |
| `--client-secret` | both | Secret for a confidential `--client-id` app (HTTP Basic, falling back to form body). |
| `--redirect-port` | both | Bind the OAuth loopback to a fixed port so the redirect URI is stable (needed with `--client-id` on providers requiring exact-match callbacks). |
| `--scopes` | both | Space-separated scopes to request (DCR and preconfigured flows only). Omitted by default — the server applies its own minimal default grant; never auto-widened. |
| `--out` | both | `eval`: file path for the JSON report. `eval-file`: directory for per-server reports + `summary.json`. The only place full evidence is written. |

---

### Scopes

By default the tool requests **no scopes**, letting each server apply its own minimal default grant rather than guessing at scope strings that could fail with `invalid_scope`. Scopes are never auto-widened. When a server needs a specific scope to expose functionality (e.g. an empty tool list under the default grant), request it explicitly — requested and granted scopes are recorded in the evidence:

```bash
mcp-audit eval --url https://mcp.example.com/mcp --auth --scopes "read:user read:org" --out example.json
```

---

## Input: server list

`eval-file` reads a YAML or JSON list of servers:

```yaml
- name: Sentry MCP
  url: https://mcp.sentry.dev/mcp
- name: Asana MCP
  url: https://mcp.asana.com/sse
- name: Neon MCP
  url: https://mcp.neon.tech/mcp
  token: <value>
- name: Github MCP
  url: https://api.githubcopilot.com/mcp
  redirect_port: 8765
  client-id: <value>
  client-secret: <value>
```

## Methodology & limitations

- **Observed behavior** A `pass` means the server's observable behavior or metadata meets the clause — not that the implementation is bug-free. Properties that can't be confirmed from outside (e.g. audience binding on an opaque token) are reported `manual`.
- **Differential testing.** Checks that mutate a request to test rejection (TR-01/04/05/08, AA-02/03) first establish a valid baseline, mutate exactly one property, and rate by comparing the two. A mutation that reaches the *same* status as the baseline is a `fail` (the server never distinguished them); a mutation that is rejected but not in the exact way the spec requires is a `warn`; `pass` needs the required rejection shape. If the baseline itself never reaches the validation stage, the check reports `not-tested` rather than guessing.
- **Heuristics are flagged.** Scope, tool-blast-radius, and injection-surface checks use keyword heuristics and say so — review flagged items individually; a `pass` means none were found by name/schema, not that none exist.
- **Minimal scopes.** Runs request no scopes by default; the server applies its own default grant. Scope-related `na` is a deliberate least-privilege choice, not a defect.
- **Token safety.** In auth mode the access token is held in memory only, never written to disk, never logged, and never placed in evidence or `--out` reports.

Every result records the exact requests and responses behind it (bearer tokens redacted) as part of the evidence saved in `--out` dir, so findings are independently reproducible. Full method, per-check evidence, and spec references: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## License

MIT