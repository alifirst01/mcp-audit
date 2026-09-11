"""Connection & Discovery — can a client with no prior knowledge of this
server learn that login is required, discover its Authorization Server, and
determine how to register as a client?

Spec sources:
  modelcontextprotocol.io/specification/draft/basic/authorization
  modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery
  modelcontextprotocol.io/specification/draft/basic/authorization/client-registration
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ...core.base import Check, register
from ...core.models import Rating, SpecLevel
from ...core.probe import ProbeContext
from ._helpers import base_url, expected_issuer_from_well_known

_SECTION = "Connection & Discovery"

_SPEC_AUTH = (
    "https://modelcontextprotocol.io/specification/draft/basic/authorization"
)
_SPEC_DISC = (
    "https://modelcontextprotocol.io/specification/draft/basic/authorization"
    "/authorization-server-discovery"
)
_SPEC_REG = (
    "https://modelcontextprotocol.io/specification/draft/basic/authorization"
    "/client-registration"
)


@register
class LoginRequired(Check):
    """CD-01: an unauthenticated request is rejected with 401. MCP Auth
    §Overview MUST (403 is the wrong signal for 'not logged in yet')."""

    id = "discovery-login-required"
    rubric_id = "CD-01"
    section = _SECTION
    display_order = 101
    method = "Probe"
    order = 10
    title = "Unauthenticated requests are rejected"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth §Overview: servers MUST respond with HTTP 401 Unauthorized "
        f"when a protected request lacks a valid token — {_SPEC_AUTH}"
    )
    requires_http = True

    def run(self, target, ctx: ProbeContext):
        if not target.url:
            return self._result(Rating.NA, "No URL to test.")
        r = ctx.get(target.url)
        if r.error:
            return self._result(Rating.ERROR, f"Request to {target.url} failed: {r.error}")
        target.context["mcp_get_status"] = r.status
        target.context["mcp_get_headers"] = r.headers
        if r.status == 401:
            return self._result(
                Rating.PASS,
                f"Sent an unauthenticated request to the configured MCP endpoint "
                f"({target.url}) and got HTTP 401 Unauthorized, as an agent would "
                f"expect before it has logged in.",
                {"status": r.status, "endpoint_tested": target.url},
            )
        if r.status == 403:
            return self._result(
                Rating.WARN,
                f"{target.url} returned HTTP 403 Forbidden instead of 401 "
                f"Unauthorized. 403 is meant for 'logged in but not allowed'; "
                f"401 is the correct signal for 'not logged in yet'.",
                {"status": r.status, "endpoint_tested": target.url},
            )
        if r.status in (200, 405, 400):
            return self._result(
                Rating.WARN,
                f"An unauthenticated GET to {target.url} returned HTTP {r.status}, "
                f"not 401 — either this server doesn't require login on this "
                f"endpoint, or it expects a POST body before it will check "
                f"credentials. Inspect manually.",
                {"status": r.status, "endpoint_tested": target.url},
            )
        return self._result(
            Rating.WARN,
            f"An unauthenticated GET to {target.url} returned an unexpected "
            f"HTTP {r.status}.",
            {"status": r.status, "endpoint_tested": target.url},
        )


@register
class DiscoversAuthorizationServer(Check):
    """CD-02: the server publishes RFC 9728 Protected Resource Metadata with
    an `authorization_servers` array. MCP Auth Discovery MUST."""

    id = "discovery-authorization-server"
    rubric_id = "CD-02"
    section = _SECTION
    display_order = 102
    method = "Probe"
    order = 20
    title = "Protected Resource Metadata is published"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth Discovery: servers MUST implement RFC 9728 Protected Resource "
        f"Metadata with an authorization_servers array — {_SPEC_DISC}"
    )
    requires_http = True

    def run(self, target, ctx: ProbeContext):
        if not target.url:
            return self._result(Rating.NA, "No URL to test.")

        prm_url = target.context.get("prm_url")
        parsed = urlparse(target.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        candidates = []
        if prm_url:
            candidates.append(prm_url)
        if parsed.path and parsed.path not in ("/", ""):
            candidates.append(
                f"{origin}/.well-known/oauth-protected-resource{parsed.path}"
            )
        candidates.append(f"{origin}/.well-known/oauth-protected-resource")

        for cand in candidates:
            r = ctx.get(cand)
            if r.status == 200:
                try:
                    doc = r.json()
                except Exception:
                    continue
                if "authorization_servers" not in doc:
                    continue
                target.context["prm_doc"] = doc
                target.context["prm_doc_url"] = cand
                auth_servers = doc.get("authorization_servers", [])
                scopes = doc.get("scopes_supported", [])
                scope_note = (
                    f"{len(scopes)} permission scope(s) advertised: {', '.join(scopes[:6])}"
                    + ("..." if len(scopes) > 6 else "")
                    if scopes else "no permission scopes listed"
                )
                return self._result(
                    Rating.PASS,
                    f"Found a Protected Resource Metadata document at {cand} — it "
                    f"names {len(auth_servers)} Authorization Server(s) "
                    f"({', '.join(auth_servers[:3])}) and {scope_note}. A scope is "
                    f"a named permission an agent can be granted (e.g. "
                    f"'read:issues') — the fewer and narrower the scopes, the less "
                    f"an agent can do if its token leaks.",
                    {
                        "url": cand,
                        "authorization_servers": auth_servers,
                        "scopes_supported": scopes,
                        "bearer_methods_supported": doc.get("bearer_methods_supported"),
                    },
                )

        return self._result(
            Rating.FAIL,
            f"No Protected Resource Metadata document was found at any of the "
            f"standard locations tried ({'; '.join(candidates)}). An agent with no "
            f"prior knowledge of this server has no standards-based way to find "
            f"out which Authorization Server (the service that actually issues "
            f"login tokens) to use.",
            {"tried": candidates},
        )


@register
class AuthorizationServerConfig(Check):
    """CD-03: the Authorization Server publishes RFC 8414 or OpenID Connect
    Discovery metadata. MCP Auth Discovery §AS Metadata Discovery MUST."""

    id = "discovery-as-config"
    rubric_id = "CD-03"
    section = _SECTION
    display_order = 103
    method = "Probe"
    order = 30
    title = "Authorization Server metadata is published"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth Discovery §AS Metadata Discovery: the authorization server MUST "
        f"provide RFC 8414 or OpenID Connect Discovery metadata — {_SPEC_DISC}"
    )
    requires_http = True

    def run(self, target, ctx: ProbeContext):
        prm = target.context.get("prm_doc")
        if not prm:
            return self._result(
                Rating.NA,
                "No Protected Resource Metadata (CD-02) was found, so there is no "
                "login server address to check.",
            )
        auth_servers = prm.get("authorization_servers", [])
        if not auth_servers:
            return self._result(
                Rating.WARN,
                "The Protected Resource Metadata document lists no "
                "authorization_servers.",
            )

        as_issuer_url = auth_servers[0]
        as_base = base_url(as_issuer_url)
        parsed = urlparse(as_issuer_url)
        as_path = parsed.path.rstrip("/")

        candidates: list[tuple[str, str]] = []
        if as_path:
            candidates += [
                (f"{as_base}/.well-known/oauth-authorization-server{as_path}",
                 "OAuth Authorization Server Metadata (RFC 8414), path-insertion"),
                (f"{as_base}/.well-known/openid-configuration{as_path}",
                 "OpenID Connect Discovery, path-insertion"),
                (f"{as_issuer_url.rstrip('/')}/.well-known/openid-configuration",
                 "OpenID Connect Discovery, path-appending"),
            ]
        else:
            candidates += [
                (f"{as_base}/.well-known/oauth-authorization-server",
                 "OAuth Authorization Server Metadata (RFC 8414)"),
                (f"{as_base}/.well-known/openid-configuration",
                 "OpenID Connect Discovery"),
            ]

        for url, variant in candidates:
            r = ctx.get(url)
            if r.status == 200:
                try:
                    doc = r.json()
                except Exception:
                    continue
                target.context["as_metadata"] = doc
                target.context["as_discovery_url"] = url
                target.context["as_expected_issuer"] = expected_issuer_from_well_known(url)
                return self._result(
                    Rating.PASS,
                    f"The login server at {as_base} publishes its configuration "
                    f"via {variant}, fetched from {url}.",
                    {
                        "url": url,
                        "variant": variant,
                        "pkce_methods": doc.get("code_challenge_methods_supported"),
                        "registration_endpoint": doc.get("registration_endpoint"),
                        "cimd_supported": doc.get("client_id_metadata_document_supported"),
                    },
                )

        return self._result(
            Rating.WARN,
            f"The login server at {as_base} publishes no standard configuration "
            f"document at any of the locations tried "
            f"({', '.join(u for u, _ in candidates)}). Compliant agent clients "
            f"would need this server hardcoded rather than discovered.",
            {"authorization_server": as_base, "tried": [u for u, _ in candidates]},
        )


@register
class RegistrationPriority(Check):
    """CD-04: classify how a new client can register. MCP Auth Registration
    prefers Client ID Metadata Documents; Dynamic Client Registration is
    deprecated and kept only for backwards compatibility, so advertising both
    is fine — it is the *absence* of CIMD support that this flags."""

    id = "registration-priority"
    rubric_id = "CD-04"
    section = _SECTION
    display_order = 104
    method = "Probe"
    order = 32
    title = "Client registration mechanism is classified"
    spec_level = SpecLevel.SHOULD
    spec_ref = (
        f"MCP Auth Registration: Client ID Metadata Documents are the "
        f"preferred registration mechanism. Dynamic Client Registration is "
        f"deprecated and remains available only for backwards compatibility "
        f"with authorization servers that do not yet support Client ID "
        f"Metadata Documents — {_SPEC_REG}"
    )
    requires_http = True

    def run(self, target, ctx: ProbeContext):
        asm = target.context.get("as_metadata")
        if not asm:
            return self._result(
                Rating.NA,
                "No login-server configuration document was found (CD-03), so "
                "there is no registration mechanism to check.",
            )

        cimd = asm.get("client_id_metadata_document_supported", False)
        dcr_endpoint = asm.get("registration_endpoint")
        evidence = {
            "client_id_metadata_document_supported": cimd,
            "registration_endpoint": dcr_endpoint,
        }

        if cimd:
            detail = (
                "The login server advertises Client ID Metadata Document "
                "support — a new agent can identify itself with a "
                "self-hosted JSON document rather than pre-registering, "
                "using the mechanism the specification prefers."
            )
            if dcr_endpoint:
                detail += (
                    f" It also exposes a Dynamic Client Registration "
                    f"endpoint ({dcr_endpoint}); the specification permits "
                    f"this as a backwards-compatibility fallback for "
                    f"authorization servers that don't yet support Client "
                    f"ID Metadata Documents — supporting both is not a "
                    f"deficiency."
                )
            return self._result(Rating.PASS, detail, evidence)

        if dcr_endpoint:
            return self._result(
                Rating.WARN,
                f"Only Dynamic Client Registration is advertised, at "
                f"{dcr_endpoint}. The MCP specification deprecates Dynamic "
                f"Client Registration in favor of Client ID Metadata "
                f"Documents, which this login server does not advertise — "
                f"a new agent can still register, but only through the "
                f"deprecated path.",
                evidence,
            )

        return self._result(
            Rating.WARN,
            "No registration mechanism is advertised at all. A brand-new agent "
            "cannot obtain credentials on its own — it needs a client_id issued "
            "out-of-band by whoever operates this server.",
            evidence,
        )


@register
class LoginPointer(Check):
    """CD-05: the 401 carries a `resource_metadata` link in WWW-Authenticate
    so discovery can bootstrap in-band. MCP Auth Discovery SHOULD."""

    id = "discovery-login-pointer"
    rubric_id = "CD-05"
    section = _SECTION
    display_order = 105
    method = "Probe"
    order = 11
    title = "401 response includes a resource-metadata pointer"
    spec_level = SpecLevel.SHOULD
    spec_ref = (
        f"MCP Auth Discovery §Protected Resource Metadata: the 401/403 response "
        f"SHOULD include a resource_metadata link in WWW-Authenticate to bootstrap "
        f"discovery — {_SPEC_DISC}"
    )
    requires_http = True

    def run(self, target, ctx: ProbeContext):
        if not target.url:
            return self._result(Rating.NA, "No URL to test.")
        r = ctx.get(target.url)
        wa = r.headers.get("www-authenticate", "")
        if not wa:
            return self._result(
                Rating.WARN,
                f"{target.url} carries no WWW-Authenticate header on its 401 "
                f"response, so an agent has no in-band pointer to where it should "
                f"log in — it would have to guess or consult documentation.",
                {"endpoint_tested": target.url},
            )
        m = re.search(r'resource_metadata="([^"]+)"', wa)
        if m:
            target.context["prm_url"] = m.group(1)
            return self._result(
                Rating.PASS,
                f"The WWW-Authenticate header on {target.url} points to a resource "
                f"metadata document at {m.group(1)} — an agent can follow this link "
                f"to find out how to log in, with no prior knowledge of the server.",
                {"resource_metadata": m.group(1), "www_authenticate": wa},
            )
        return self._result(
            Rating.WARN,
            f"{target.url} sends a WWW-Authenticate header ({wa!r}) but it carries "
            f"no resource_metadata pointer, so it doesn't actually tell the agent "
            f"where to go next.",
            {"www_authenticate": wa},
        )


@register
class DualDiscoveryPath(Check):
    """CD-06: the Protected Resource Metadata is reachable both via the
    WWW-Authenticate pointer and via the well-known path. MCP Auth Discovery
    SHOULD (clients may use either)."""

    id = "discovery-dual-path"
    rubric_id = "CD-06"
    section = _SECTION
    display_order = 106
    method = "Probe"
    order = 22
    title = "Metadata is reachable via both discovery paths"
    spec_level = SpecLevel.SHOULD
    spec_ref = (
        f"MCP Auth Discovery: clients MUST support both discovery paths; servers "
        f"SHOULD implement both for maximum client compatibility — {_SPEC_DISC}"
    )
    requires_http = True

    def run(self, target, ctx: ProbeContext):
        if not target.url:
            return self._result(Rating.NA, "No URL to test.")

        prm_url_from_header = target.context.get("prm_url")
        parsed = urlparse(target.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        well_known_candidates = []
        if parsed.path and parsed.path not in ("/", ""):
            well_known_candidates.append(
                f"{origin}/.well-known/oauth-protected-resource{parsed.path}"
            )
        well_known_candidates.append(f"{origin}/.well-known/oauth-protected-resource")

        well_known_ok = False
        well_known_url = None
        for cand in well_known_candidates:
            r = ctx.get(cand)
            if r.status == 200:
                try:
                    doc = r.json()
                    if "authorization_servers" in doc:
                        well_known_ok = True
                        well_known_url = cand
                        break
                except Exception:
                    pass

        header_ok = False
        if prm_url_from_header:
            r = ctx.get(prm_url_from_header)
            if r.status == 200:
                try:
                    doc = r.json()
                    header_ok = "authorization_servers" in doc
                except Exception:
                    pass

        evidence = {
            "prm_url_from_www_authenticate_header": prm_url_from_header,
            "reachable_via_header_pointer": header_ok,
            "well_known_url_tried": well_known_url or well_known_candidates[-1],
            "reachable_via_well_known_path": well_known_ok,
        }

        if header_ok and well_known_ok:
            return self._result(
                Rating.PASS,
                "The login-server pointer is reachable both ways: via the "
                "WWW-Authenticate header pointer and via the standard "
                "/.well-known/oauth-protected-resource path.",
                evidence,
            )
        if header_ok and not well_known_ok:
            return self._result(
                Rating.WARN,
                "Only the WWW-Authenticate header pointer works; the "
                "/.well-known/oauth-protected-resource fallback path is not "
                "reachable. An agent that skips straight to the well-known path "
                "(a common client shortcut) would fail to discover login.",
                evidence,
            )
        if not header_ok and well_known_ok:
            reason = (
                "the 401 response carried no resource_metadata pointer"
                if not prm_url_from_header
                else f"the pointer URL ({prm_url_from_header}) was not reachable"
            )
            return self._result(
                Rating.WARN,
                f"Only the /.well-known/oauth-protected-resource path works; the "
                f"WWW-Authenticate header pointer does not, because {reason}.",
                evidence,
            )
        return self._result(
            Rating.FAIL,
            "The login-server pointer is not reachable via either standard path.",
            evidence,
        )


@register
class AuthorizationServerConsistent(Check):
    """CD-07: the `issuer` in the AS metadata equals the identifier the
    well-known URL was built from. RFC 8414 §3.3 / OIDC §4.3 MUST — a
    mismatch is the shape of an AS mix-up/impersonation."""

    id = "discovery-as-config-consistent"
    rubric_id = "CD-07"
    section = _SECTION
    display_order = 107
    method = "Probe"
    order = 31
    title = "Authorization Server metadata issuer is self-consistent"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth Discovery §AS Metadata (RFC 8414 §3.3 / OIDC §4.3): the issuer "
        f"in AS metadata MUST equal the issuer identifier used to construct the "
        f"well-known URL — {_SPEC_DISC}"
    )
    requires_http = True

    def run(self, target, ctx: ProbeContext):
        asm = target.context.get("as_metadata")
        expected = target.context.get("as_expected_issuer")

        if not asm or not expected:
            return self._result(
                Rating.NA,
                "No login-server configuration document was found (CD-03), so "
                "there is nothing to cross-check.",
            )

        actual = asm.get("issuer", "")
        evidence = {
            "expected_issuer": expected,
            "actual_issuer": actual,
            "discovery_url": target.context.get("as_discovery_url"),
        }

        if not actual:
            return self._result(
                Rating.WARN,
                "The login server's configuration document has no 'issuer' field "
                "to cross-check at all.",
                evidence,
            )
        if actual == expected:
            return self._result(
                Rating.PASS,
                f"The 'issuer' field in the login server's configuration document "
                f"({actual!r}) exactly matches the address it was fetched from, "
                f"confirming it's the genuine document for this server and not a "
                f"mismatched copy served from elsewhere.",
                evidence,
            )
        return self._result(
            Rating.FAIL,
            f"Issuer mismatch: the configuration document declares "
            f"issuer={actual!r} but it was fetched from a URL implying "
            f"issuer={expected!r}. A compliant agent MUST reject this document — "
            f"a mismatch like this is exactly the shape of a mix-up/impersonation "
            f"attack between authorization servers.",
            evidence,
        )
