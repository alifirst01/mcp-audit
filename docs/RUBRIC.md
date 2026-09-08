# MCP Audit — Rubric

This rubric defines the criteria mcp-audit evaluates for a Model Context
Protocol (MCP) server. `docs/METHODOLOGY.md` defines the evaluation method,
evidence collected, and known limitations for each check.

**Specification Target:** (2026-07-28+)

## Per-check tags

Every check carries three tags:

**Method** — how the check is evaluated:
- **Probe** — an unauthenticated request to the live server.
- **Auth** — requires a completed OAuth 2.1 session (`--auth`). mcp-audit
  executes a full authorization-code flow with PKCE — see "How the OAuth
  flow works" in `docs/METHODOLOGY.md`.
- **Doc** — assessed from published documentation, source, configuration,
  or comparison against an external reference such as the vendor's own API
  reference; not verifiable by black-box probing of the target alone.
  Displayed as `MANUAL`.

**Status** — publication state, not priority or scheduling:
- **live** — implemented and evaluated today.
- **planned** — Not yet implemented; planned for future release.

**Server** — which server type the check is about: **Remote**, **Local**,
or **Remote & Local**.

---

## 1. Connection & Discovery

A client with no prior knowledge of the server can learn that login
is required, discover its Authorization Server, and determine how it can
register as a client. Covers the first HTTP exchange, the 401 challenge,
and the standard discovery documents that point a client to its
Authorization Server.

| ID | Criteria | Method | Status | Server | Validation Check | Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CD-01** | Unauthenticated requests are rejected | Probe | 🟢 Live | Remote | A request to the MCP endpoint without credentials returns HTTP 401 Unauthorized. | [Auth Overview](https://modelcontextprotocol.io/specification/draft/basic/authorization) |
| **CD-02** | Protected Resource Metadata is published | Probe | 🟢 Live | Remote | The server publishes RFC 9728 Protected Resource Metadata that includes an `authorization_servers` field listing at least one authorization server, along with its supported scopes. | [Discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery) |
| **CD-03** | Authorization Server metadata is published | Probe | 🟢 Live | Remote | The Authorization Server referenced in the Protected Resource Metadata publishes its metadata at a standard well-known URI, discoverable via RFC 8414 (OAuth 2.0 Authorization Server Metadata) or OpenID Connect Discovery 1.0. | [Discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery) |
| **CD-04** | Client registration mechanism is classified | Probe | 🟢 Live | Remote | Classifies how a client obtains credentials: Client ID Metadata Documents (CIMD, the specification's preferred mechanism), Dynamic Client Registration (DCR, a deprecated fallback), pre-registration-only (neither is advertised — an operator must register out of band), or none detected. Supporting both CIMD and DCR is not a deficiency; DCR exists as backwards compatibility for Authorization Servers that don't yet support CIMD. | [Registration](https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration) |
| **CD-05** | 401 response includes a resource-metadata pointer | Probe | 🟢 Live | Remote | The `WWW-Authenticate` header on the 401 response includes a `resource_metadata` parameter pointing to the Protected Resource Metadata URL. | [Discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery) |
| **CD-06** | Metadata is reachable via both discovery paths | Probe | 🟢 Live | Remote | The Protected Resource Metadata document resolves both via the `WWW-Authenticate` header pointer and via the `.well-known/oauth-protected-resource` path. | [Discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery) |
| **CD-07** | Authorization Server metadata issuer is self-consistent | Probe | 🟢 Live | Remote | The `issuer` value in the Authorization Server metadata matches the issuer identifier implied by the well-known URL it was fetched from (RFC 8414 §3.3 / OIDC §4.1). | [Discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery) |
| **CD-08** | SSRF protections for Client ID Metadata Document retrieval are documented | Doc | ⚪ Planned | Remote | Documentation or source confirms the Authorization Server mitigates Server-Side Request Forgery risk when fetching a client-supplied Client ID Metadata Document URL. | [Registration §Authorization Server Abuse Protection](https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration) |

---

## 2. Authentication & Authorization

How the client proves identity, and what the resulting token permits:
whether it can complete an authorization-code flow safely, and whether the
resulting grant is appropriately scoped. `--auth` executes a complete OAuth
2.1 authorization-code flow with PKCE — see `docs/METHODOLOGY.md`. Every
`Auth`-method check below executes against the resulting session.


| ID | Criteria | Method | Status | Server | Validation Check | Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AA-01** | PKCE (S256) is advertised | Probe | 🟢 Live | Remote | The Authorization Server's metadata lists `S256` in `code_challenge_methods_supported`. | [Security](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations) |
| **AA-02** | Unregistered redirect URIs are rejected | Auth | 🟢 Live | Remote | An authorization request specifying a redirect URI that was not registered for the client is rejected rather than redirected to. | [Registration](https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration) |
| **AA-03** | PKCE is enforced | Auth | 🟢 Live | Remote | An authorization request omitting `code_challenge` is rejected rather than processed. | [Security](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations) |
| **AA-04** | Authorization response issuer is validated | Auth | 🟢 Live | Remote | The authorization redirect includes an `iss` parameter (RFC 9207) matching the Authorization Server's issuer, confirming the authorization code originated from the expected server before it is used. | [Auth Overview](https://modelcontextprotocol.io/specification/draft/basic/authorization) |
| **AA-05** | Advertised scopes are narrowly defined (least privilege) | Probe | 🟢 Live | Remote | Advertised scopes are granular and operation-specific rather than broad administrative or write-capable grants. | [Security](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations) |

---

## 3. Credential & Token Risk

The credential the client ends up holding, and its exposure if it leaks:
how long it lives, how it's transmitted, whether it's verified on every
request, and whether the agent's own runtime context can expose it. Covers
both remote-token risk and local/config
credential hygiene.

| ID | Criteria | Method | Status | Server | Validation Check | Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CT-01** | Access token is bound to this resource (audience binding) | Auth | 🟢 Live | Remote | The issued access token's audience claim, where readable, matches the resource URI specified via the `resource` parameter (RFC 8707). | [Security](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations) |
| **CT-02** | Access token is transmitted via the Authorization header only | Probe | 🟢 Live | Remote | The server accepts bearer tokens only via the `Authorization` header; transmission via the URI query string, which intermediaries commonly log, is rejected. | [Auth Overview](https://modelcontextprotocol.io/specification/draft/basic/authorization) |
| **CT-03** | Token integrity is verified (tampered-token rejection) | Auth | 🟢 Live | Remote | A modified copy of a valid access token is rejected. Confirms integrity/signature verification only — it does not substitute for audience validation (CT-01), which is checked separately. | [Auth Overview](https://modelcontextprotocol.io/specification/draft/basic/authorization) |
| **CT-04** | Invalid or expired tokens are rejected on every request | Auth | 🟢 Live | Remote | A request to the MCP endpoint bearing an invalid bearer token returns HTTP 401. | [Auth Overview](https://modelcontextprotocol.io/specification/draft/basic/authorization) |
| **CT-05** | Access tokens are short-lived and refresh tokens rotate | Auth | 🟢 Live | Remote | The access token's lifetime is short (mcp-audit uses roughly an hour or less as its own operational heuristic, not a specification value), and using the refresh token issues a new refresh token that invalidates the previous one. | [Security](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations) |
| **CT-06** | Granted scope does not exceed the requested scope | Auth | ⚪ Planned | Remote | The scope returned in the token response is a subset of the scope requested during authorization. | *`docs/MCP Validation.md`* |
| **CT-07** | Access token is not present in tool responses | Auth | ⚪ Planned | Remote | Sampled tool responses do not contain the literal access-token value; its presence would make the token readable by any process with access to the agent's context. | *`docs/MCP Validation.md`* |
| **CT-08** | Server does not forward the client's token upstream | Doc | ⚪ Planned | Remote | Documentation or source confirms the server obtains its own credentials for upstream services rather than forwarding the client's access token. | [Security](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations) |
| **CT-09** | OAuth is preferred over a static credential | Doc | ⚪ Planned | Remote & Local | Setup documentation recommends OAuth or a short-lived token over a static API key or personal access token in a configuration file. | *OWASP NHI Top 10* |
| **CT-10** | Credential is not exposed to the agent via the filesystem | Doc | ⚪ Planned | Remote & Local | Documentation directs the credential to an OS keychain, secrets manager, or environment variable rather than a plaintext configuration file readable by any process with filesystem access, including the connected agent. | *OWASP NHI Top 10* |
| **CT-11** | Credentials expire or are rotatable | Doc | ⚪ Planned | Remote & Local | Credentials are short-lived or rotatable rather than static and non-expiring. | *OWASP NHI Top 10* |
| **CT-12** | Rotation and revocation are documented | Doc | ⚪ Planned | Remote & Local | Documentation describes the procedure for rotating or revoking a credential. | *OWASP NHI Top 10* |
| **CT-13** | A least-privilege mode is available | Doc | ⚪ Planned | Remote & Local | A read-only mode, tool allow-list, or scoped credential option is documented. | *Least Privilege* |
| **CT-14** | Caller-trust model is disclosed (stdio) | Doc | ⚪ Planned | Local | Documentation states that any local process able to spawn the server can invoke every tool it exposes, since stdio provides no per-caller authentication. | *Resource-Server Model* |
| **CT-15** | No vendor credential is embedded in the distributed package | Doc | ⚪ Planned | Remote & Local | The distributed server contains no hardcoded API key or embedded client secret. | *Secret-vs-Identity* |

---

## 4. Tool Safety & Blast Radius

How much the server's tools can do, and what could go wrong if an agent
uses them unsupervised or is fed adversarial input. Covers unrestricted
capability, the read/write distinction an agent needs to reason about risk,
and tools whose input can carry untrusted external content into the
agent's context.

| ID | Criteria | Method | Status | Server         | Validation Check | Reference |
| :--- | :--- | :--- | :--- |:---------------| :--- | :--- |
| **TS-01** | No unrestricted-access tools are present | Auth | 🟢 Live | Remote         | No tool name or description indicates unrestricted shell, SQL, or HTTP execution. | *Least Privilege* |
| **TS-02** | Read and write operations are distinguishable | Auth | 🟢 Live | Remote | Destructive or write-capable tools are distinguishable from read-only tools, by naming convention or the `readOnlyHint` annotation. | *Least Privilege* |
| **TS-03** | Tools with an external-content injection surface are identifiable | Auth | 🟢 Live | Remote | Tools that retrieve untrusted external content (web search, URL fetch) are identifiable from their name, description, or input schema. | *Prompt-Injection Blast Radius* |

---

## 5. Response Quality & Consistency

A client can reliably build software around a tool's response —
typed enough to parse, consistent enough to reuse one code path across
tools, and informative enough on both success and failure to act on. This
section is entirely `planned`.

| ID | Criteria | Method | Status | Server | Validation Check | Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RQ-01** | Tool metadata is complete and typed | Auth | ⚪ Planned | Remote & Local | Every tool returned by `tools/list` has a non-empty description and an `inputSchema` with typed properties. | [Tools](https://modelcontextprotocol.io/specification/draft/server/tools) |
| **RQ-02** | Tools declare structured output | Auth | ⚪ Planned | Remote & Local | Each tool definition includes an `outputSchema`, so responses can be parsed as typed data rather than unstructured text. | [Tools](https://modelcontextprotocol.io/specification/draft/server/tools) |
| **RQ-03** | Response structure is consistent across tools | Auth | ⚪ Planned | Remote & Local | Invoking two independent read-only tools returns responses with the same top-level structure, allowing a single parsing implementation to be reused across tools. | *`docs/MCP Validation.md`* |
| **RQ-04** | Errors are reported in a consistent format | Auth | ⚪ Planned | Remote & Local | A tool invocation with an invalid argument returns a recognizable error — a JSON-RPC error object or a result with `isError: true` — rather than an ambiguous or empty response. | *`docs/MCP Validation.md`* |
| **RQ-05** | Responses contain sufficient content to act on | Auth | ⚪ Planned | Remote & Local | A tool invoked with valid arguments returns structured content or text of sufficient length to be actionable, rather than an empty result. | *`docs/MCP Validation.md`* |

---

## 6. API / Surface Fidelity

The set of operations exposed as MCP tools accurately represents
what the underlying product can do — no silently missing capability, no
undocumented surface area. Requires the vendor's own API reference as an
independent source of truth, so every check here uses the `Doc` method.
This section is entirely `planned`.

| ID | Criteria | Method | Status | Server | Validation Check | Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SF-01** | MCP tool surface corresponds to the underlying API | Doc | ⚪ Planned | Remote & Local | Every operation in the vendor's published REST or GraphQL API reference has a corresponding MCP tool, and every MCP tool corresponds to a documented API operation — flagging capability the agent cannot reach via MCP, and surface area outside the vendor's documented behavior, versioning, and support guarantees. | *`docs/MCP Validation.md`* |

---

## 7. Transport & Protocol Plumbing

The wire-level soundness of the transport itself — the checks that apply
to the literal first request a client makes and to every request
thereafter: transport encryption, DNS-rebinding defense, and
protocol-version/header consistency enforcement.

| ID | Criteria | Method | Status | Server | Validation Check | Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TR-01** | Requests with a foreign `Origin` header are rejected | Probe | 🟢 Live | Remote | A request with a spoofed `Origin` header, characteristic of a DNS-rebinding attack, is rejected relative to a same-origin/no-origin baseline. Evaluated by the differential-testing method — see `docs/METHODOLOGY.md`. | [Streamable HTTP](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http) |
| **TR-02** | Every evaluated endpoint uses HTTPS | Probe | 🟢 Live | Remote | The MCP endpoint, and every Authorization Server endpoint discovered in §1, use the `https` scheme. | *Security Best Practice* |
| **TR-04** | Mismatched protocol-version header is rejected | Probe | 🟢 Live | Remote | A request whose `MCP-Protocol-Version` header disagrees with the body's declared version is rejected (differential-testing method). | [Streamable HTTP](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http) |
| **TR-05** | Header/body mismatches are rejected | Probe | 🟢 Live | Remote | A request whose mirrored `Mcp-Method` header disagrees with its JSON-RPC body method is rejected (differential-testing method). | [Streamable HTTP](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http) |
| **TR-07** | Local servers bind to localhost only | Doc | ⚪ Planned | Local | A locally run server's default bind address is `127.0.0.1`, not `0.0.0.0`. | [Streamable HTTP](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http) |
| **TR-08** | Unsupported protocol versions are rejected with a supported-version list | Probe | 🟢 Live | Remote | A request specifying an unsupported protocol version is rejected with a supported-versions list in the error data (differential-testing method). | [Versioning](https://modelcontextprotocol.io/specification/draft/basic/versioning) |

---

## Version

This is rubric **v1**. v1 evaluates remote (HTTP) MCP servers only, using
the Probe and Auth methods — checks determinable by connecting to a live
server and observing its behavior.
