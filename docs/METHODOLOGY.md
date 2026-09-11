# MCP Audit — Methodology

This document defines the evaluation method, evidence collected, and known
limitations for each check in `docs/RUBRIC.md`.

## Method reference

| Method | Definition |
|--------|---------------|
| **Probe** | An unauthenticated HTTP request; no credentials required. |
| **Auth** | Requires a completed OAuth 2.1 session (`--auth`). mcp-audit executes a full authorization-code flow with PKCE — see "How the OAuth flow works" below. |
| **Doc** | Assessed from documentation, source, configuration, or comparison against an external reference not obtainable from MCP traffic alone, such as the vendor's published API reference. |

## Status reference

| Status | Meaning                                      |
|--------|----------------------------------------------|
| **live** | Implemented and evaluated today.             |
| **planned** | Not yet implemented. Displayed as "Planned." |


## Differential-testing requirement

Every Probe or Auth check that mutates a request to test rejection — a
spoofed header, an omitted parameter, an unregistered value — follows the
same mandatory pattern:

1. Establish a valid baseline by sending a request built from the exact shape a
   real client would successfully send.
2. Mutate exactly one property under test, leaving everything else in
   the baseline unchanged.
3. Confirm the baseline itself reaches the property's validation stage
   before drawing any conclusion. If the baseline does not succeed — it
   cannot be confirmed to have reached the validation stage for the
   property under test.
4. Rate by comparing the mutated response to the baseline response. A mutated request that reaches
   the *identical* outcome as the baseline means the mutation changed
   nothing — that is a `FAIL`, regardless of what status code it is,
   because an absolute-status check would have missed that the server never
   distinguished the two requests at all.
5. Record the exact baseline and mutated request/response — see
   "Evidence requirement" below.


**Worked example — TR-01 (foreign `Origin` header).** The baseline is a
`tools/list` request with no `Origin` header (or same-origin), sent using
the exact request shape a real client uses to list tools successfully. The
mutation is the identical request with `Origin: http://evil.attacker.example.com`
added. The check compares the two: if the baseline succeeds and the
mutated request is rejected specifically because of the Origin header, that
is `PASS`. If the baseline itself fails to reach the Origin-validation stage
— for instance if the server rejects it for an unrelated reason — the check
reports `not-tested`, because a mutated-request rejection in that case
proves nothing about Origin handling specifically. This is why the check
never sends a bare, hand-built Origin probe in isolation: without a
confirmed-successful baseline, a rejected mutation is ambiguous evidence.

## Evidence requirement

Every check result records the exact request(s) sent and response(s)
received (method, URL, headers with bearer tokens redacted, body, status,
a response-body snippet) for both the baseline and the mutation, so any
finding is independently reproducible.

The console only prints a check's details and results, never its `evidence`
object. Evidence is exported to a JSON file when `--out` is passed:

- `mcp-audit eval --url https://mcp.example.com/mcp --name "My Server" --auth --out report.json
` writes the evidence file at `report.json`
- `mcp-audit eval-file servers/servers.yaml --out results/` writes one evidence file per server into `results/` plus
`results/summary.json`.

---

## Auth-mode

Every `Auth`-method check completes a real OAuth 2.1 authorization-code
flow and handles a real user access token.

- The access token (and refresh token, if
  issued) is held only in memory, on the run's `AuthSession`/`ProbeContext`,
  for the duration of that run. It is not written to disk.
- The raw token value is never placed in a log line.
- The raw token value is never placed
  in a check's `evidence` dict, so it never appears in the JSON `--out`
  report or in console output.

---

## How the OAuth flow works

Three credential paths, via `AuthInput` (`mcp_audit/core/oauth.py`),
resolved in priority order. Supplying a credential (`--token`, `--client-id`,
`--client-metadata-url`) authenticates on its own; bare `--auth` is only
needed to select Path 3, the zero-credential automatic path.

### Path 1 — static token (`--token` / `MCP_AUDIT_TOKEN`)

Highest priority. If a token is supplied, `_authenticate_with_supplied_token()`
builds an `AuthSession` directly from it — no discovery requirement, no
network calls, no browser, no `--auth` flag needed. The session's `resource`
is set to the target URL for the checks that compare it against a claim,
and `probe_evidence["auth_mode"] = "supplied-token"` marks it so later
checks can tell (surfaced in evidence as `auth_method: "static-token"`,
vs. `"oauth"` for the other two paths).

The token is used as-is for the `initialize` handshake and every
authenticated request after it (tools/list, transport probes, CT-01/03/04)
exactly like an OAuth-obtained token. Only checks that need a token
mcp-audit itself issued report `n/a` instead of running: AA-02/03/04 (no
interactive flow occurred to probe PKCE/redirect-URI/issuer handling) and
CT-05 (no OAuth token response exists to check `expires_in` or test
refresh rotation against).

### Path 2 — supplied client credentials (`--client-id`/`--client-secret`, or `--client-metadata-url`)

For servers that require pre-registration and don't support self-registration. The operator pre-registers an OAuth app by hand, then
supplies its identity. This runs the **full interactive flow** — PKCE,
loopback listener, browser consent, token exchange — identically to Path 3,
except client registration is skipped: `ClientCredentials` is built directly
from the supplied `--client-id`/`--client-secret` (or `--client-metadata-url`,
used as the `client_id` value.

The loopback listener (`LoopbackServer`, `core/oauth.py`) binds
`("127.0.0.1", 0)` by default, so its redirect URI's port is OS-assigned and
different every run — fine for an AS that treats any loopback port as a
match (RFC 8252 §7.3), but not for a provider whose pre-registered redirect
URI must match exactly, port included (GitHub OAuth Apps do exact matching
on the whole URL). `--redirect-port <port>` binds that fixed port instead,
so `redirect_uri` is `http://127.0.0.1:<port>/callback` on every run and can
be registered once. If the port is already bound by something else,
`LoopbackServer` raises immediately naming the port — it never silently
falls back to a random one, which would otherwise send the AS to a
different redirect_uri than the one registered and fail well downstream
with no obvious cause.

### Path 3 — auto (bare `--auth`, nothing else supplied)

The zero-config path: `register_client()` self-registers via Client
ID Metadata Documents or, failing
that, Dynamic Client Registration (RFC 7591, a POST to
`registration_endpoint` — the MCP specification's deprecated fallback,
kept for Authorization Servers that don't yet support Client ID Metadata
Documents). If the Authorization Server advertises neither, `register_client()`
raises, which surfaces as an `AuthFailure` telling the operator to retry with
Path 2 instead.

---

## 1. Connection & Discovery

A client with no prior knowledge of the server can learn that login
is required, discover its Authorization Server, and determine how it can
register as a client.

**MCP specification:** [Discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery), [Client Registration](https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration)

All checks in this section require a live HTTP endpoint and are not
applicable to stdio-only targets.

### CD-01 — Unauthenticated requests are rejected (`discovery-login-required`)

Sends an unauthenticated GET to the configured MCP endpoint.

**Evidence:** HTTP status, endpoint URL.

### CD-02 — Protected Resource Metadata is published (`discovery-authorization-server`)

Fetches the Protected Resource Metadata document, trying, in
order: 
- the URL from header pointer
- `/.well-known/oauth-protected-resource<path>` (path-specific, RFC 9728 §4.2)
- `/.well-known/oauth-protected-resource` (root)

**Evidence:** Document contents, URL retrieved, Authorization Server(s)
listed, advertised scopes.

### CD-03 — Authorization Server metadata is published (`discovery-as-config`)

Reads `authorization_servers[0]` from the Protected Resource
Metadata. Tries RFC 8414 path-insertion, OIDC path-insertion, and OIDC
path-appending, in MCP specification priority order.

**Evidence:** Metadata URL, variant used, PKCE methods advertised,
registration endpoint, Client ID Metadata Document support flag.

### CD-04 — Client registration mechanism is classified (`registration-priority`)

Reads `client_id_metadata_document_supported` and
`registration_endpoint` from `as_metadata`.

**Evidence:** Both field values.

**Rating logic:** `PASS` if `client_id_metadata_document_supported` is true
— whether or not `registration_endpoint` is also present, since the 
MCP specification explicitly permits an Authorization Server to support both
(Dynamic Client Registration remains available "for backwards compatibility
with authorization servers that do not support Client ID Metadata
Documents"). `WARN` if only `registration_endpoint` is present: the
Authorization Server relies solely on the deprecated mechanism. `WARN` if
neither is present (pre-registration-only or undetected).

### CD-05 — 401 response includes a resource-metadata pointer (`discovery-login-pointer`)

Reads `WWW-Authenticate` from the CD-01 response (cached; no
additional request). Extracts the `resource_metadata="<URL>"` parameter.

**Evidence:** Header value, extracted URL.

### CD-06 — Metadata is reachable via both discovery paths (`discovery-dual-path`)

Verifies the header-pointer path and the well-known path
independently resolve to a valid document. Passes only if both resolve.

**Evidence:** Which path(s) resolved, URLs tried.

### CD-07 — Authorization Server metadata issuer is self-consistent (`discovery-as-config-consistent`)

Compares `as_metadata["issuer"]` against the issuer implied by
the well-known URL it was fetched from (RFC 8414 §3.3 / OIDC §4.1).


**Evidence:** Both issuer values, discovery URL.

### CD-08 — SSRF protections for Client ID Metadata Document retrieval are documented (`registration-ssrf-protection`)

Per the MCP specification's Authorization Server Abuse Protection guidance: an
Authorization Server fetching a client's Client ID Metadata Document (a
client-supplied URL) SHOULD mitigate Server-Side Request Forgery risk
(allowlisting, blocking internal network addresses, timeouts and
response-size limits). Not verifiable by black-box probing.

---

## 2. Authentication & Authorization

How the client proves identity, and what the resulting token permits: whether
it can complete an authorization-code flow safely, and whether the resulting
grant is appropriately scoped.

**MCP specification:** [Security Considerations](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations), [Auth Overview](https://modelcontextprotocol.io/specification/draft/basic/authorization)

All `Auth`-method checks require a completed `--auth` session (see "How the
OAuth flow works" above).

### AA-01 — PKCE (S256) is advertised (`oauth-pkce-advertised`)

Reads `code_challenge_methods_supported`
from `as_metadata`.

### AA-02 — Unregistered redirect URIs are rejected (`oauth-redirect-uri-rejected`)

Differential test: baseline is a direct GET to `authorization_endpoint` using the
client identifier, *registered* redirect URI, and PKCE `code_challenge` the
completed flow just used successfully
(`session.probe_evidence["registered_redirect_uri"]` / `["pkce_challenge"]`,
stashed by `core/oauth.py`). Mutated is the identical request with only
`redirect_uri` changed to `https://evil.attacker.example/callback`. Using
the *real* registered redirect URI in the baseline matters — a throwaway,
never-registered redirect URI even for the baseline side of the comparison
would let a server that validates redirect URIs before PKCE reject the
probe for the wrong reason and still look like a PASS.

**Rating logic:** `FAIL` if the mutated request redirects straight to the
attacker-controlled address. `PASS` if the mutated request reaches a
different status than the baseline (and doesn't redirect to the attacker
address). `WARN` if baseline and mutated reach the identical status —
Authorization Servers that only validate redirect URIs after an active
login session can produce this even when validation is real. `ERROR` ("not
tested") if the baseline itself gets a generic-rejection status (400 or
422 — see `_AS_GENERIC_REJECTION_STATUSES`) rather than reaching the
redirect-URI validation stage.

**Evidence:** Full request/response for both the baseline and mutated probe.


### AA-03 — PKCE is enforced (`oauth-pkce-enforced`)

Differential test: baseline is a direct GET to
`authorization_endpoint` with the registered redirect URI and a valid
`code_challenge` (same stashed values as AA-02). Mutated is the identical
request with `code_challenge` omitted entirely.

**Rating logic:** `FAIL` if the mutated request is issued an authorization
code (`code=` present in the redirect). `PASS` if the mutated request
reaches a different status than the baseline, or carries an explicit
`error` parameter. `WARN` if baseline and mutated reach the identical
status with no error indicator and no issued code — some Authorization
Servers require an active browser session before validating the request,
and this probe carries no session cookies, so PKCE enforcement can't be
conclusively confirmed from a bare request in that case. `ERROR` ("not
tested") if the baseline itself gets a generic-rejection status.

**Evidence:** Full request/response for both probes.

### AA-04 — Authorization response issuer is validated (`oauth-issuer-response-valid`)


Compares the `iss` value from the
redirect callback (RFC 9207) against `as_metadata["issuer"]`. Reported as
`WARN`, not `FAIL`, if `iss` is absent — mcp-audit proceeds to gather other
evidence, but a conforming client should refuse to use the code.


### AA-05 — Advertised scopes are narrowly defined (least privilege) (`oauth-scope-surface`)

Matches `scopes_supported` against a
keyword list associated with broad access (`repo`, `admin`, `write`,
`delete`, `*`, and similar).

**Limitation:** A keyword heuristic; review flagged scopes individually.

---

## 3. Credential & Token Risk

The credential the client ends up holding, and its exposure if it leaks: how
long it lives, how it's transmitted, whether it's verified on every request,
and whether the agent's own runtime context can expose it.


**MCP specification:** 
- [Security Considerations](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations) (CT-01–CT-08)
- OWASP Non-Human Identity (NHI) Top 10 and credential-handling practice (CT-09–CT-15)

### CT-01 — Access token is bound to this resource (audience binding) (`oauth-resource-bound`)

If the access token is a JWT, decodes its payload (unverified
— used only to read the claim, not to establish trust) and compares `aud`
against the requested `resource`.

**Limitation:** Reported as `MANUAL` for opaque (non-JWT) tokens, which are
common — GitHub's tokens, for example, are not JWTs. Audience binding for an
opaque token requires server-side confirmation (introspection or vendor
documentation).

### CT-02 — Access token is transmitted via the Authorization header only (`oauth-bearer-header-only`)

Checks `bearer_methods_supported` in
the Protected Resource Metadata, falling back to the `WWW-Authenticate`
scheme. Fails if `"query"` is an accepted method.

### CT-03 — Token integrity is verified (tampered-token rejection) (`oauth-token-integrity`)

Sends a modified copy of the valid access token (the final
four characters altered) to the MCP endpoint. Expects HTTP 401.

**What this does and does not prove:** rejecting a tampered token
demonstrates the server verifies token integrity (e.g. signature
validation) — it does **not** demonstrate audience validation. Those are
distinct properties: a server can verify a token's signature perfectly and
still fail to check which resource the token was issued for. CT-01 checks
audience binding directly (via the `aud` claim); CT-03 does not stand in for
it.

**Limitation:** A genuine cross-audience test would require a token minted
by a second resource server, which a single-target run does not have. This
check confirms the server verifies tokens at all, using a tampered copy of
the real token as the closest available substitute.

### CT-04 — Invalid or expired tokens are rejected on every request (`oauth-token-checked-every-request`)

Sends an invalid bearer token to the
MCP endpoint. Expects HTTP 401. No known limitation.

### CT-05 — Access tokens are short-lived and refresh tokens rotate (`oauth-short-lived-refresh`)

Reads `expires_in` from the token response. If a
`refresh_token` was issued, calls `oauth.refresh()` and checks whether the
returned `refresh_token` differs from the one submitted.

**Evidence:** `expires_in`, whether rotation was observed.

**On the lifetime threshold:** the MCP specification says access tokens SHOULD
be short-lived but names no exact duration. mcp-audit uses a rough
operational heuristic — roughly an hour (3600 seconds) or less — to render
a PASS/WARN judgment, but that number is mcp-audit's own choice, not a 
MCP specification requirement. The rotation half of this check (refresh tokens
SHOULD rotate on each use for public clients) is a direct, unambiguous 
MCP specification statement with no heuristic involved.

**Limitation:** Reported as `MANUAL`/`WARN` if no refresh token was issued.
**Under Path 1 (static token):** reports `n/a` immediately — "Static token
supplied; no OAuth token lifecycle to test" — rather than evaluating
`expires_in`/refresh at all: a supplied API key has no OAuth token response
whose lifetime or rotation could be measured, so there is nothing here to
grade as MANUAL or WARN.

### CT-06 — Granted scope does not exceed the requested scope (`oauth-scope-not-overgranted`)

Compares the token response's `scope` field against the scope requested. Reported as
`MANUAL` if the token response omits `scope` entirely, which some servers
do when granted scope equals requested scope.

**Under Path 1 (supplied token):** mcp-audit never requested a scope, so
there is nothing to compare against — always `MANUAL` with that explanation
rather than the generic "no scope field" message.

### CT-07 — Access token is not present in tool responses (`oauth-token-not-reflected`)

Invokes up to two eligible tools and checks each raw response body for the literal
access-token value. Fails on any match.

**Limitation:** Checks only the responses sampled during this run — not a
guarantee across every tool, code path, or server-side log.

### CT-08 — Server does not forward the client's token upstream (`oauth-no-passthrough`)

Not verifiable by black-box probing; requires reading documentation or
source to confirm the server obtains its own upstream credentials.

### CT-09 through CT-15 — Config-file / static-credential handling

All apply to every server type (`Server: Remote & Local`, except
CT-14 which is `Server: Local`).

| ID | Review criterion |
|----|--------------------------------------------------|
| CT-09 | Does setup documentation recommend OAuth or a short-lived token over a static API key or personal access token? |
| CT-10 | If the connected agent has filesystem or shell tool access, can it read the configuration file containing this server's credential? Does documentation direct the credential to a keychain, secrets manager, or environment variable instead? |
| CT-11 | Are credentials short-lived or rotatable, rather than static and non-expiring? |
| CT-12 | Is a credential rotation/revocation procedure documented? |
| CT-13 | Is a read-only mode, tool allow-list, or scoped credential option available? |
| CT-14 | For stdio: does documentation state that any local process able to spawn the server can invoke every tool it exposes? |
| CT-15 | Does the distributed package contain no hardcoded API key, client secret, or other embedded credential? |

For **CT-15**, search the package or source repository for patterns such as
`sk-`, `Bearer `, `api_key=`, `token=`, `password=` in non-test code, and
confirm any `.env.example` file contains only placeholder values.

---

## 4. Tool Safety & Blast Radius

How much the server's tools can do, and what could go wrong if an agent
uses them unsupervised or is fed adversarial input.


**MCP specification:** Not spec-defined; based on least-privilege and prompt-injection blast-radius practice.

All checks send `tools/list` via `_helpers.fetch_tools_authed`, using a
`--auth` session in the same run when one exists. These checks are tagged
`Auth`: most servers require a completed session to serve `tools/list`
(Supabase does, for example). On a server that happens to serve it
unauthenticated, the check still runs and simply records "obtained without
authentication" in its evidence — the Method tag itself doesn't change
per-server. If the server requires authentication and none is available,
checks return `n/a`. For local targets, all checks currently return `n/a`
— the underlying question is server-agnostic (see `docs/RUBRIC.md`'s
Version section), but local evaluation is not yet wired up.

### TS-01 — No unrestricted-access tools are present (`tool-blast-radius`)


Matches tool names and
descriptions against a keyword list (`execute`, `shell`, `bash`,
`raw_sql`, `admin`, and similar).

**Limitation:** A keyword heuristic; review flagged tools individually.

### TS-02 — Read and write operations are distinguishable (`tool-rw-separation`)


Prefers the `readOnlyHint`
annotation where present; falls back to substring name matching
(`create`/`delete`/`update`/... for write, `get`/`list`/`read`/... for
read) only for tools without the annotation.

**Reported counts include both read-detection paths.** A server that
correctly annotates every read tool with `readOnlyHint` will show 0 tools
matched by the naming heuristic — that's the annotation doing its job, not
a missed detection. The result text reports both buckets explicitly ("N
read tool(s) (M via readOnlyHint annotation, K via naming convention)")
rather than only the naming-heuristic count, so a fully-annotated server
doesn't misleadingly read as "0 read tools detected."

### TS-03 — Tools with an external-content injection surface are identifiable (`tool-injection-surface`)

Flags tools matching fetch/browse/crawl name patterns (`web_search`,
`fetch_url`, `scrape`) or whose input schema includes a parameter commonly
carrying external content (`url`, `uri`, `href`, `link`, `endpoint`)
combined with a description that names an untrusted external boundary
("arbitrary url", "web page", "the web", "third-party", "internet", …).

**Scope:** this is a name/description/schema keyword heuristic, and by
design only covers the clearly-external case — a tool that fetches an
arbitrary or user-supplied URL, or crawls/searches the open web.
Second-order prompt injection via attacker-planted *first-party* content
(a malicious instruction hidden inside an issue body, comment, or email
that a benign-looking tool like `get_issue` reads back into the agent's
context) cannot be detected this way, since nothing about that tool's
name, description, or schema looks external. That case is out of scope
for automated detection and needs manual review of what each tool's
response actually contains.

**Limitation:** A keyword heuristic; confirm manually whether a flagged
tool's input can actually carry content into the agent's context, and
don't rely on a PASS here to mean the server has no injection surface at
all — only that no *clearly-external* one was found by name/schema.

---

## 5. Response Quality & Consistency

A client can reliably build software around a tool's response —
typed enough to parse, consistent enough to reuse one code path across
tools, and informative enough on both success and failure to act on.


**MCP specification:** [Tools](https://modelcontextprotocol.io/specification/draft/server/tools) (RQ-01, RQ-02); RQ-03–05 are not spec-defined.

All checks in this section are `planned`. RQ-03 through RQ-05 additionally
invoke live tools under the invocation policy described above and require
`--auth`.

### RQ-01 — Tool metadata is complete and typed (`discovery-tool-metadata-clarity`)




Sends `tools/list`. If the unauthenticated request returns
401 and a `--auth` session exists in the same run, retries authenticated —
if it instead succeeds unauthenticated, evidence notes "obtained without
authentication" (see the §4 note above; the same policy applies here).
Checks each tool for a non-empty `description` and an `inputSchema` with
typed properties.

**Evidence:** Total tool count, tools missing a description or typed schema.

### RQ-02 — Tools declare structured output (`response-structured-output`)




Checks each tool in `tools/list` for a non-empty
`outputSchema`.

**Evidence:** Tools with and without a declared output schema.

### RQ-03 — Response structure is consistent across tools (`response-shape-consistency`)




Selects up to two tools eligible under the invocation policy,
invokes each, and compares the top-level key set of the `result` object (or
its type, if not an object).

**Evidence:** Tool names invoked, top-level structure of successful
responses, and a `failed_calls` map for any that didn't return one.

**A failed call is not a "consistent shape."** If a sampled call errors
(non-200, or a body that doesn't parse), it has no top-level shape to
compare — two tools that both errored with the same status are evidence
that neither call produced a real response, not evidence of a unified
format. Reported as `MANUAL` whenever any call fails, rather than treating
matching failure strings as a passing comparison.

**Limitation:** Reported as `MANUAL` if fewer than two eligible tools exist.

### RQ-04 — Errors are reported in a consistent format (`response-error-format`)




Invokes one eligible tool with a deliberately invalid
argument (an incorrect type on a required field, or an unrecognized
parameter if the tool has no required fields) and inspects how the failure
is reported: a JSON-RPC `error` object with a `message` field, or a result
with `isError: true` and text content — either is reported as `PASS`;
neither is `WARN`.

**Evidence:** Tool invoked, arguments sent, error format detected.

### RQ-05 — Responses contain sufficient content to act on (`response-descriptive`)




Invokes one eligible tool with valid synthesized arguments and
measures the returned text length and presence of `structuredContent`.

**Evidence:** Tool invoked, content length, presence of structured content.

**Limitation:** Uses a length threshold (40 characters) as a proxy for
sufficiency; review results near the threshold manually.

---

## 6. API / Surface Fidelity

The set of operations exposed as MCP tools accurately represents
what the underlying product can do — no silently missing capability, no
undocumented surface area.


**MCP specification:** Not spec-defined.

### SF-01 — MCP tool surface corresponds to the underlying API (`discovery-api-parity-gap`)




List every tool name from `tools/list` (RQ-01). Compare
against the vendor's published REST or GraphQL API reference. Record each
operation present in the underlying API with no corresponding MCP tool (a
capability the agent cannot reach through MCP), and each MCP tool with no
corresponding documented API operation (surface area outside the vendor's
documented behavior, versioning, and support guarantees).

**Rationale:** An MCP server built on top of an existing API can under- or
over-expose that API's capability surface without any protocol-level
violation. Neither case is detectable from MCP traffic alone; both require
the vendor's API reference as an independent source of truth, which is why
this is a `Doc` check rather than a `Probe` or `Auth` one — it can't be
answered by talking to the target server alone.

---

## 7. Transport & Protocol Plumbing

The wire-level soundness of the transport itself — the checks that apply to
the literal first request a client makes and to every request thereafter.


**MCP specification:** [Streamable HTTP](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http)

All checks require a live HTTP endpoint and are not applicable to
stdio-only targets (except TR-07, which is about how a local server binds
its own HTTP listener).

### TR-01 — Requests with a foreign Origin header are rejected (`transport-foreign-origin-rejected`)




Sends the baseline `tools/list` request three ways: with no
`Origin` header, with a same-origin `Origin` (the target's own
scheme+host), and with `Origin: http://evil.attacker.example.com`. The
first of the two non-hostile variants that reaches past body/header
validation (see the differential-testing note above) becomes the reference
point.

**Rating logic:** `PASS` if the foreign-Origin request gets HTTP 403.
`FAIL` if it reaches the exact same status as the reference. `WARN` if it's
rejected but not with 403. `ERROR` ("not tested") if even both non-hostile
variants fail to reach the validation stage.

**Evidence:** Full request/response for all three variants.

### TR-02 — Every evaluated endpoint uses HTTPS (`transport-https`)




Checks the configured MCP endpoint's scheme, then, if
Authorization Server metadata was discovered (CD-03), checks the scheme of
every endpoint it lists (`authorization_endpoint`, `token_endpoint`,
`registration_endpoint`, `revocation_endpoint`, `introspection_endpoint`,
`jwks_uri`, `issuer`). A single check covering every endpoint involved in
the evaluation, rather than separate checks per endpoint category.

**Evidence:** Scheme of each endpoint checked.

**Limitation:** Checks only the URLs present in the configured target and
discovered metadata, not HTTP-to-HTTPS redirects or split-traffic
configurations.

### TR-04 — Mismatched protocol-version header is rejected (`transport-version-header-enforced`)




Baseline: the `tools/list` request with a matching, correct
`MCP-Protocol-Version` header. Mutated: the identical request with the
header changed to `2099-01-01` — the body's declared version is left
alone, so this isolates header/body *version* consistency specifically.

**Rating logic:** `PASS` if the mutated request gets `400` with JSON-RPC
error `-32020` (`HeaderMismatch`). `FAIL` if it reaches the identical
status as the baseline. `WARN` for a `400` with a different error code, or
any other status. `ERROR` ("not tested") if the baseline itself doesn't
reach the validation stage.

**Evidence:** Full request/response for both the baseline and the mutated probe.

### TR-05 — Header/body mismatches are rejected (`transport-header-body-consistency`)




Baseline: the `tools/list` request with `Mcp-Method:
tools/list` matching the body. Mutated: the identical request with
`Mcp-Method: resources/read` — a real, different MCP method — while the
body still declares `tools/list`.

**Rating logic:** Same PASS/FAIL/WARN/ERROR structure as TR-04, expecting
`400` + `-32020` on the mutated request.

**Evidence:** Full request/response for both probes.

### TR-07 — Local servers bind to localhost only (`transport-localhost-binding`)



Reviewed from startup flags or documentation for the default bind address.

### TR-08 — Unsupported protocol versions are rejected with a supported-version list (`transport-unsupported-version-error`)




Baseline: the `tools/list` request with the real, current
protocol version consistently in both header and body. Mutated: the
identical request with the version changed to `1900-01-01` — consistently,
in *both* header and body, so this isolates version *negotiation* rather
than re-testing TR-05's header/body *consistency*.

**Rating logic:** `PASS` if the mutated request gets JSON-RPC error
`-32022` (`UnsupportedProtocolVersionError`) with `data.supported` listing
real versions. `FAIL` if it reaches the identical status as the baseline.
`WARN` for `-32022` with no `data.supported`, or any other mismatch.
`ERROR` ("not tested") if the baseline itself doesn't reach the validation
stage.

**Evidence:** Full request/response for both probes.

