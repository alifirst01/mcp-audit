# MCP Audit — Methodology

Evaluation method, evidence collected, and known limitations for each check in `docs/RUBRIC.md`.

## Methods and statuses

| Method | Definition |
|--------|------------|
| **Probe** | An unauthenticated HTTP request; no credentials required. |
| **Auth** | Requires a completed OAuth 2.1 session (`--auth`) — a full authorization-code flow with PKCE (see [How the OAuth flow works](#how-the-oauth-flow-works)). |
| **Doc** | Assessed from documentation, source, config, or an external reference (e.g. the vendor's API docs) not obtainable from MCP traffic alone. |

| Status | Meaning |
|--------|---------|
| **live** | Implemented and evaluated today. |
| **planned** | Not yet implemented. |

## Differential testing

Every Probe/Auth check that mutates a request to test rejection (spoofed header, omitted parameter, unregistered value) follows one pattern, shared via `_helpers.differential_bucket` so the rule can't drift between checks:

1. Establish a valid baseline using the exact request shape a real client uses successfully.
2. Mutate exactly one property; leave everything else identical.
3. Confirm the baseline itself reaches the property's validation stage. If it doesn't, the check reports **not-tested** — a mutated-request rejection proves nothing if the baseline never got that far.
4. Rate by comparing mutated vs baseline response:
   - **FAIL** — mutated reaches the *identical* status as baseline: the server never distinguished the two requests (true regardless of status code).
   - **WARN** — mutated *was* rejected, but not in the exact spec-required way (wrong status or JSON-RPC error code).
   - **PASS** — rejection matches the required shape exactly.
5. Record the baseline and mutated request/response (see [Evidence](#evidence)).

## Evidence

Every result records the exact request(s) and response(s) — method, URL, headers (bearer tokens redacted), body, status, body snippet — for both baseline and mutation, so any finding is reproducible. Differential checks (TR-01/04/05/08) additionally record flat `baseline_status` / `mutation_status` / `mutation_error_code` / `mutation_response_body` fields, so narrated statuses are machine-checkable without parsing nested blocks.

The console prints only details and results, never `evidence`. Evidence is written to disk with `--out`:

- `eval --out report.json` — one self-contained file: server name, URL, `tool_version`, run `timestamp`, and every check's full evidence.
- `eval-file --out results/` — one self-contained file per server, plus a thin `results/summary.json` (per check: `rubric_id`/`rating`/`title`/`method`/`detail`, no evidence, plus a `report_file` pointer).

## Auth-mode token safety

Every `Auth` check completes a real OAuth 2.1 authorization-code flow and handles a real access token. The token (and refresh token, if issued) is held in memory only for the run's duration — never written to disk, never logged, never placed in any check's `evidence`, so it appears in neither `--out` reports nor console output.

## How the OAuth flow works

Three credential paths via `AuthInput` (`core/oauth.py`). A supplied token and supplied client credentials are mutually exclusive (`cli._build_auth_input()` errors if both are given). Supplying either authenticates on its own; bare `--auth` selects only Path 3.

**Path 1 — static token (`--token`).**
- Builds an `AuthSession` directly from the supplied value — no discovery, no network calls, no browser.
- Used as-is for `initialize` and every authenticated request (tools/list, transport probes, CT-01/03/04), exactly like an OAuth token. Surfaced as `auth_method: static-token`.
- Only checks needing a token mcp-audit itself issued report `n/a`: AA-02/03/04 (no interactive flow to probe) and CT-05 (no token response to inspect).

**Path 2 — supplied client credentials (`--client-id`/`--client-secret`).**
- For servers requiring pre-registration. Runs the full interactive flow (PKCE, loopback listener, browser consent, token exchange) identically to Path 3, but skips client registration — `ClientCredentials` is built from the supplied values. Surfaced as `preconfigured-client`.
- Because a real token is obtained via a real flow, AA-02/03/04 and CT-05 run normally.
- **Redirect port:** `LoopbackServer` binds `("127.0.0.1", 0)` by default (OS-assigned port). That suits an AS treating any loopback port as a match (RFC 8252 §7.3), but not one requiring exact redirect-URI match including port (GitHub OAuth Apps). `--redirect-port <port>` binds a fixed port so `redirect_uri` is stable and can be registered once. If the port is taken, it raises immediately naming the port rather than silently picking another (which would fail downstream with no obvious cause).
- **Confidential client:** with `--client-secret`, `_token_request()` authenticates at the token endpoint via HTTP Basic first (`client_secret_basic`), falling back once to the form body (`client_secret_post`) if Basic is rejected — some ASes accept only one and metadata doesn't say which. The same helper backs the initial exchange and CT-05's refresh.

**Path 3 — auto (bare `--auth`).**
- `register_client()` self-registers via Client ID Metadata Documents, or failing that Dynamic Client Registration (RFC 7591, the spec's deprecated fallback).
- If the AS advertises neither, it raises an `AuthFailure` telling the operator to use Path 2.

---

## 1. Connection & Discovery

A client with no prior knowledge can learn that login is required, discover its Authorization Server, and determine how to register.
**Spec:** [Discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery), [Client Registration](https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration). All require a live HTTP endpoint (n/a for stdio).

**CD-01 — Unauthenticated requests are rejected.**
- **Sends:** an unauthenticated GET to the MCP endpoint.
- **Evidence:** status, URL.

**CD-02 — Protected Resource Metadata is published.**
- **Sends:** fetches PRM, trying in order — the header-pointer URL, `/.well-known/oauth-protected-resource<path>` (RFC 9728 §4.2), then root.
- **Verifies:** the document's own `resource` field (RFC 9728 §2) canonicalizes (`_helpers.canonicalize_resource` — lowercase scheme/host, default port stripped, no trailing slash) to the same value as the endpoint it describes; WARN on a genuine mismatch, not a formatting difference.
- **Evidence:** contents, URL, Authorization Server(s), advertised scopes, `declared_resource`/`declared_resource_canonical`, `endpoint_canonical`.

**CD-03 — Authorization Server metadata is published.**
- **Sends:** reads `authorization_servers[0]` from PRM; tries RFC 8414 path-insertion, OIDC path-insertion, and OIDC path-appending in spec priority.
- **Evidence:** URL, variant used, PKCE methods, registration endpoint, CIMD support flag.

**CD-04 — Client registration mechanism is classified.**
- **Reads:** `client_id_metadata_document_supported` and `registration_endpoint`.
- **Rates:** PASS if CIMD supported (whether or not DCR is too — the spec permits both); WARN if only `registration_endpoint` (relies solely on the deprecated mechanism); WARN if neither (pre-registration-only or undetected).

**CD-05 — 401 includes a resource-metadata pointer.**
- **Reads:** `WWW-Authenticate` from the cached CD-01 response; extracts `resource_metadata`.
- **When the header is missing:** WARN either way, but the wording reflects whether the well-known fallback (CD-02) actually resolves — probed here directly (`_helpers.well_known_prm_candidates`/`fetch_prm_doc`, cached so CD-02 doesn't re-fetch) rather than assumed. If it resolves, the detail says discovery still succeeds via the fallback, just without the in-band shortcut; only when the fallback *also* fails does it say the agent would have to guess or consult documentation.
- **Evidence:** header value, extracted URL, `well_known_tried`/`well_known_resolved`/`well_known_url`.

**CD-06 — Metadata reachable via both discovery paths.**
- **Verifies:** the header-pointer path and the well-known path independently resolve; passes only if both do.
- **Evidence:** which path(s) resolved, URLs tried.

**CD-07 — AS metadata issuer is self-consistent.**
- **Compares:** `as_metadata["issuer"]` against the issuer implied by the fetch URL (RFC 8414 §3.3 / OIDC §4.1).
- **Evidence:** both issuer values, discovery URL.

**CD-08 — SSRF protection for CIMD retrieval is documented.** *Doc.*
- Per the spec's abuse-protection guidance, an AS fetching a client-supplied CIMD URL SHOULD mitigate SSRF (allowlisting, blocking internal addresses, timeouts, size limits).
- **Limitation:** not verifiable by black-box probing.

## 2. Authentication & Authorization

How the client proves identity and whether the resulting grant is safely scoped.
**Spec:** [Security Considerations](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations), [Auth Overview](https://modelcontextprotocol.io/specification/draft/basic/authorization). Auth checks require a completed `--auth` session.

**AA-01 — PKCE (S256) advertised.**
- **Reads:** `code_challenge_methods_supported` from AS metadata.

**AA-02 — Unregistered redirect URIs rejected.** *Differential.*
- **Baseline:** GET to `authorization_endpoint` with the client ID, the *registered* redirect URI, and the PKCE challenge the flow just used successfully.
- **Mutated:** identical request with only `redirect_uri` changed to an attacker address. Using the real registered URI in the baseline matters — a never-registered baseline URI could be rejected for the wrong reason and still look like PASS.
- **Rates:** FAIL if mutated redirects to the attacker address; PASS if mutated reaches a different status (and doesn't redirect there); WARN if identical status (ASes validating redirect URIs only after login produce this); not-tested if the baseline gets a generic rejection (400/422) before reaching validation.
- **Evidence:** full request/response for both probes.

**AA-03 — PKCE enforced.** *Differential.*
- **Baseline:** as AA-02.
- **Mutated:** identical request with `code_challenge` omitted.
- **Rates:** FAIL if mutated is issued a code; PASS if different status or explicit `error`; WARN if identical status with no error/code (the probe carries no session cookies, so enforcement can't be confirmed); not-tested on a generic-rejection baseline.
- **Evidence:** full request/response for both probes.

**AA-04 — Authorization response issuer validated.**
- **Compares:** callback `iss` (RFC 9207) against `as_metadata["issuer"]`.
- **Rates:** WARN (not FAIL) if `iss` is absent — a conforming client should refuse the code.

**AA-05 — Advertised scopes narrowly defined.**
- **Matches:** `scopes_supported` against broad-access keywords (`repo`, `admin`, `write`, `delete`, `*`, …).
- **Limitation:** keyword heuristic; review flagged scopes individually.

## 3. Credential & Token Risk

The credential the client holds and its exposure if it leaks.
**Spec:** [Security Considerations](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations) (CT-01–08); OWASP NHI Top 10 and credential practice (CT-09–15).

**CT-01 — Access token bound to this resource (audience).**
- **Checks:** if the token is a JWT, decodes the payload (unverified, read-only) and compares `aud` to the requested `resource`, canonicalized (`_helpers.resources_match`) — an `aud`/resource pair differing only by trailing slash, scheme/host case, or an explicit default port still matches; an `aud` naming an origin that's a canonical prefix of the resource (e.g. `https://api.example.com` vs `.../mcp`) also matches.
- **Evidence:** both raw and canonical forms (`resource_requested`/`_canonical`, `aud_claim`/`_canonical`).
- **Limitation:** MANUAL for opaque tokens (common — e.g. GitHub's), which need introspection or vendor docs to confirm.

**CT-02 — Token transmitted via Authorization header only.**
- **Checks:** `bearer_methods_supported` (falling back to the `WWW-Authenticate` scheme).
- **Rates:** fails if `query` is an accepted method.

**CT-03 — Token integrity verified (tampered-token rejection).**
- **Sends:** the real token with its last four characters altered; expects 401.
- **Proves:** the server verifies integrity (e.g. signature) — **not** audience validation (a distinct property CT-01 covers).
- **Limitation:** a true cross-audience test needs a token from a second resource server, which a single-target run lacks.

**CT-04 — Invalid/expired tokens rejected on every request.**
- **Sends:** a token shaped exactly like the real one (same length/segment structure) but with every letter and digit substituted (`_fabricate_invalid_token`) — a rejection proves content validation, not mere header parsing. Distinct from CT-03 (whole value differs, never issued).
- **Classifies by *why* it was rejected** (`_classify_rejection`), with the body checked before the status:
  - **PASS** — rejected over the credential: HTTP 401 (RFC 7235: lacked valid credentials), or any status whose body names a token problem (`invalid_token`, `unauthorized`, `bearer`, `expired`, `authorization header`, `badly formatted`, …). Checked first, so GitHub's `HTTP 400: "Authorization header is badly formatted"` is PASS despite the 400.
  - **n/a (inconclusive)** — rejected for an envelope/routing/server reason that would reject any request (malformed request, wrong method/`Accept`, unknown route, envelope JSON-RPC codes `-32600`/`-32700`/`-32020`, `5xx`); the token was never evaluated. A JSON-RPC `error` inside an HTTP 2xx body is treated the same.
  - **FAIL** — not rejected: a 2xx with no error — the protected resource was served despite the bad token.
- **Limitation:** hint lists are heuristic; unrecognized phrasing falls back to n/a, never FAIL.

**CT-05 — Tokens short-lived and refresh tokens rotate.**
- **Reads:** `expires_in`; if a refresh token was issued, calls `oauth.refresh()` and checks whether the returned refresh token differs.
- **On thresholds:** the ~3600s lifetime cutoff is mcp-audit's own operational heuristic, **not** a spec figure; the rotation half (public clients SHOULD rotate) is a direct spec statement.
- **Limitation:** MANUAL/WARN if no refresh token. Path 1 (static token): `n/a` — no OAuth response to measure.

**CT-06 — Granted scope ≤ requested scope.**
- **Compares:** the token response `scope` against the requested scope.
- **Limitation:** MANUAL if `scope` is omitted (some servers omit it when granted = requested). Path 1: always MANUAL (no scope was requested).

**CT-07 — Access token not present in tool responses.**
- **Sends:** invokes up to two eligible tools; fails if any raw response contains the token value.
- **Limitation:** only samples the responses seen this run.

**CT-08 — Server does not forward the client's token upstream.** *Doc.*
- **Limitation:** not black-box verifiable; needs docs/source.

**CT-09–15 — Config-file / static-credential handling.** *Doc.* All server types (CT-14 is local-only):

| ID | Criterion |
|----|-----------|
| CT-09 | Docs recommend OAuth or a short-lived token over a static API key/PAT? |
| CT-10 | If the agent has filesystem/shell access, can it read the config file holding this credential? Do docs direct it to a keychain/secrets manager/env var? |
| CT-11 | Credentials short-lived or rotatable, not static and non-expiring? |
| CT-12 | Rotation/revocation procedure documented? |
| CT-13 | Read-only mode, tool allow-list, or scoped-credential option available? |
| CT-14 | (stdio) Do docs state any local process able to spawn the server can invoke every tool? |
| CT-15 | Distributed package contains no hardcoded key/secret/embedded credential? |

- For CT-15, search source for `sk-`, `Bearer `, `api_key=`, `token=`, `password=` in non-test code, and confirm `.env.example` holds only placeholders.

## 4. Tool Safety & Blast Radius

How much the tools can do, and what could go wrong under adversarial input.
**Spec:** not spec-defined; least-privilege and prompt-injection practice. All send `tools/list` via `_helpers.fetch_tools_authed` using the run's `--auth` session; tagged `Auth` because most servers require a session to serve it. If served unauthenticated, the check runs and notes "obtained without authentication." If auth is required and absent, returns `n/a`. Local targets: `n/a` (not yet wired).

**TS-01 — No unrestricted-access tools.**
- **Matches:** tool names/descriptions against keywords (`execute`, `shell`, `bash`, `raw_sql`, `admin`, …).
- **Limitation:** keyword heuristic; review flagged tools individually.

**TS-02 — Read/write operations distinguishable.**
- **Prefers:** the `readOnlyHint` annotation; falls back to name matching (`create`/`delete`/`update` vs `get`/`list`/`read`) only for unannotated tools.
- **Reports:** both buckets ("N read tools (M via annotation, K via naming)") so a fully-annotated server doesn't read as "0 read tools."

**TS-03 — External-content injection surface identifiable.**
- **Flags:** fetch/browse/crawl names (`web_search`, `fetch_url`, `scrape`), or an external-content parameter (`url`, `uri`, `href`, `link`, `endpoint`) combined with a description naming an untrusted boundary ("arbitrary url", "web page", "the web", "third-party", "internet", …).
- **Scope:** covers only the clearly-external case. Second-order injection via attacker-planted *first-party* content (a malicious instruction in an issue body that a benign `get_issue` reads back) is out of scope — nothing about the tool looks external.
- **Limitation:** keyword heuristic; a PASS means no clearly-external surface was found by name/schema, not that none exists.

## 5. Response Quality & Consistency — *planned*

A client can reliably build on a tool's response.
**Spec:** [Tools](https://modelcontextprotocol.io/specification/draft/server/tools) (RQ-01/02); RQ-03–05 not spec-defined. All `planned`; RQ-03–05 invoke live tools and require `--auth`.

**RQ-01 — Tool metadata complete and typed.**
- **Sends:** `tools/list` (retries authenticated on 401 if a session exists); checks each tool for a non-empty `description` and a typed `inputSchema`.

**RQ-02 — Tools declare structured output.**
- **Checks:** each tool for a non-empty `outputSchema`.

**RQ-03 — Response structure consistent across tools.**
- **Sends:** invokes up to two eligible tools; compares the top-level key set of `result`.
- **Limitation:** a failed call has no shape to compare — MANUAL if any call fails (matching failures are not a "consistent shape"), or if fewer than two eligible tools exist.

**RQ-04 — Errors reported in a consistent format.**
- **Sends:** invokes one tool with a deliberately invalid argument.
- **Rates:** PASS for a JSON-RPC `error` with `message`, or a result with `isError: true` + text; else WARN.

**RQ-05 — Responses contain sufficient content.**
- **Sends:** invokes one tool with valid synthesized arguments; measures text length and `structuredContent` presence.
- **Limitation:** 40-char length proxy; review near-threshold results.

## 6. API / Surface Fidelity — *planned*

The MCP tool surface accurately represents the underlying product.
**Spec:** not spec-defined.

**SF-01 — Tool surface corresponds to the underlying API.** *Doc.*
- **Compares:** tool names (from RQ-01) against the vendor's published REST/GraphQL reference, recording API operations with no MCP tool (unreachable capability) and MCP tools with no documented operation (undocumented surface).
- **Why Doc:** requires the vendor's API reference as an independent source of truth, so it can't be answered from MCP traffic alone.

## 7. Transport & Protocol Plumbing

Wire-level soundness of the transport — the first request and every one after.
**Spec:** [Streamable HTTP](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http). All require a live HTTP endpoint (n/a for stdio), except TR-07.

**TR-01 — Foreign `Origin` rejected.** *Differential.*
- **Sends:** baseline `tools/list` three ways — no `Origin`, same-origin, and `Origin: http://evil.attacker.example.com`. The first non-hostile variant to pass body/header validation is the reference.
- **Rates:** PASS if the foreign request gets 403; FAIL if it reaches the reference's exact status; WARN if rejected but not with 403; not-tested if neither non-hostile variant reaches validation.
- **Evidence:** full request/response for all three variants.

**TR-02 — Every evaluated endpoint uses HTTPS.**
- **Checks:** the MCP endpoint's scheme, plus every endpoint in discovered AS metadata (`authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `introspection_endpoint`, `jwks_uri`, `issuer`).
- **Limitation:** checks only URLs present in target/metadata, not redirects or split-traffic configs.

**TR-04 — Mismatched protocol-version header rejected.** *Differential.*
- **Baseline:** correct `MCP-Protocol-Version`.
- **Mutated:** header changed to `2099-01-01`, body version left alone (isolates header/body version consistency).
- **Rates:** PASS for `400` + `-32020` (`HeaderMismatch`); FAIL if identical status; WARN for `400` with a different code or any other status; not-tested on a failed baseline.
- **Evidence:** full request/response for both probes.

**TR-05 — Header/body mismatches rejected.** *Differential.*
- **Baseline:** `Mcp-Method: tools/list` matching the body.
- **Mutated:** `Mcp-Method: resources/read` while the body still says `tools/list`.
- **Rates:** same PASS/FAIL/WARN/not-tested structure as TR-04, expecting `400` + `-32020`.
- **Evidence:** full request/response for both probes.

**TR-07 — Local servers bind to localhost only.** *Doc.*
- **Reviewed:** from startup flags or docs for the default bind address.

**TR-08 — Unsupported protocol versions rejected with a supported-version list.** *Differential.*
- **Baseline:** real version consistently in header and body.
- **Mutated:** version changed to `1900-01-01` consistently in *both* header and body (isolates version negotiation, not TR-05's consistency).
- **Rates:** PASS for JSON-RPC `-32022` (`UnsupportedProtocolVersionError`) with `data.supported` listing real versions; FAIL if identical status; WARN for `-32022` without `data.supported` or any other mismatch; not-tested on a failed baseline.
- **Evidence:** full request/response for both probes.