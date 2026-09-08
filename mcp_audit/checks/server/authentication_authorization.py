"""Authentication & Authorization — how does the client prove identity, and
what does the token permit?

Once a client knows how to register, can it complete an authorization-code
flow safely, and is the resulting grant appropriately scoped? `--auth`
executes a complete OAuth 2.1 authorization-code flow with PKCE — see
docs/METHODOLOGY.md.

`--auth` triggers core/oauth.py's real flow (client registration, a local
loopback redirect listener, PKCE S256, browser consent). If that flow doesn't
complete, the engine reports the Auth-method checks here as ERROR with the
failure reason instead of running them — see core/engine.py.

Spec sources:
  modelcontextprotocol.io/specification/draft/basic/authorization
  modelcontextprotocol.io/specification/draft/basic/authorization/client-registration
  modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations
"""
from __future__ import annotations

import secrets
from urllib.parse import urlencode, urlparse, parse_qs

from ...core.base import Check, register
from ...core.models import Rating, SpecLevel
from ...core.probe import ProbeContext

_SECTION = "Authentication & Authorization"

_SPEC_AUTH = (
    "https://modelcontextprotocol.io/specification/draft/basic/authorization"
)
_SPEC_REG = (
    "https://modelcontextprotocol.io/specification/draft/basic/authorization"
    "/client-registration"
)
_SPEC_SEC = (
    "https://modelcontextprotocol.io/specification/draft/basic/authorization"
    "/security-considerations"
)

# Status codes observed in the wild for "this authorization request is
# malformed," independent of vendor — used to detect an inconclusive
# baseline. Not a JSON-RPC 400; authorization endpoints aren't JSON-RPC, and
# vendors vary (Supabase's AS uses 422 for a generically malformed request).
_AS_GENERIC_REJECTION_STATUSES = (400, 422)


def _authorize_probe_evidence(url: str, r) -> dict:
    return {
        "request_method": "GET",
        "request_url": url,
        "response_status": r.status,
        "response_location": r.headers.get("location"),
        "response_body": (r.text or "")[:300],
    }


# ---------------------------------------------------------------------------
# AA-01  PKCE advertised
# ---------------------------------------------------------------------------

@register
class PkceAdvertised(Check):
    id = "oauth-pkce-advertised"
    rubric_id = "AA-01"
    section = _SECTION
    display_order = 201
    method = "Probe"
    order = 41
    title = "PKCE (S256) is advertised"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth Security §Authorization Code Protection: PKCE with S256 is "
        f"REQUIRED; code_challenge_methods_supported MUST include S256 — {_SPEC_SEC}"
    )
    requires_http = True

    def run(self, target, ctx: ProbeContext):
        asm = target.context.get("as_metadata")
        if not asm:
            return self._result(
                Rating.NA,
                "No login-server configuration document was found (CD-03).",
            )
        methods = asm.get("code_challenge_methods_supported", [])
        if "S256" in methods:
            return self._result(
                Rating.PASS,
                f"The login server advertises PKCE with method S256 (methods "
                f"advertised: {methods}). PKCE (Proof Key for Code Exchange) stops "
                f"a stolen authorization code from being redeemed by anyone but "
                f"the agent that started the login.",
                {"methods": methods},
            )
        if methods:
            return self._result(
                Rating.WARN,
                f"The login server advertises PKCE methods {methods!r} but not "
                f"S256 (only the weaker 'plain' method, or something "
                f"nonstandard). Agents following the MCP spec MUST refuse to "
                f"proceed without S256 support.",
                {"methods": methods},
            )
        return self._result(
            Rating.FAIL,
            "The login server's configuration advertises no PKCE support at "
            "all (no code_challenge_methods_supported field). Agents following "
            "the MCP spec MUST refuse to authorize against this server.",
            {"methods": methods},
        )


# ---------------------------------------------------------------------------
# AA-02  Redirect URI validation
#
# Baseline-vs-mutated pattern: a bare crafted authorization request has no
# baseline to compare against — a generic rejection (many Authorization
# Servers return the same 4xx for any malformed request) can look identical
# to a genuine redirect-URI rejection, misattributing the cause. Instead:
# send a baseline request with the SAME client_id and code_challenge the
# real flow just used successfully, and the registered redirect URI. Confirm
# it reaches past generic request validation, then change ONLY the
# redirect_uri and compare.
# ---------------------------------------------------------------------------

@register
class RedirectUriRejected(Check):
    id = "oauth-redirect-uri-rejected"
    rubric_id = "AA-02"
    section = _SECTION
    display_order = 202
    method = "Auth"
    order = 402
    title = "Unregistered redirect URIs are rejected"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth Registration: the AS MUST validate exact redirect URIs, "
        f"restricting them to localhost/127.0.0.1 or HTTPS, and reject foreign/"
        f"open-redirect targets — {_SPEC_REG}"
    )
    requires_http = True
    requires_auth = True

    _EVIL_REDIRECT = "https://evil.attacker.example/callback"

    def run(self, target, ctx: ProbeContext):
        asm = target.context.get("as_metadata")
        session = ctx.auth_session
        if session and session.probe_evidence.get("auth_mode") == "supplied-token":
            return self._result(
                Rating.NA,
                "A token was supplied directly (--token), so no interactive "
                "authorization flow ran for this check to probe.",
            )
        client_id = session.probe_evidence.get("client_id") if session else None
        registered_redirect = session.probe_evidence.get("registered_redirect_uri") if session else None
        challenge = session.probe_evidence.get("pkce_challenge") if session else None
        if not asm or not client_id or not registered_redirect or not challenge:
            return self._result(Rating.NA, "No completed login session to build this probe from.")

        def build_url(redirect_uri: str, state: str) -> str:
            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": session.resource,
            }
            return f"{asm['authorization_endpoint']}?{urlencode(params)}"

        baseline_url = build_url(registered_redirect, secrets.token_urlsafe(8))
        mutated_url = build_url(self._EVIL_REDIRECT, secrets.token_urlsafe(8))

        r_baseline = ctx.get(baseline_url)
        r_mutated = ctx.get(mutated_url)

        evidence = {
            "baseline": _authorize_probe_evidence(baseline_url, r_baseline),
            "mutated": _authorize_probe_evidence(mutated_url, r_mutated),
        }

        if r_baseline.error or r_mutated.error:
            return self._result(
                Rating.ERROR,
                "The baseline or mutated probe failed at the network level; "
                "see evidence for which.",
                evidence,
            )

        if r_baseline.status in _AS_GENERIC_REJECTION_STATUSES:
            return self._result(
                Rating.ERROR,
                f"The baseline authorization request — the same client_id "
                f"and code_challenge the real login flow just used "
                f"successfully, with the registered redirect_uri "
                f"({registered_redirect}) — itself got HTTP "
                f"{r_baseline.status}, so redirect-URI validation can't be "
                f"isolated from this earlier rejection. Not tested; see "
                f"evidence.",
                evidence,
            )

        mutated_location = r_mutated.headers.get("location", "")
        if r_mutated.status in (301, 302, 303, 307, 308) and mutated_location.startswith(self._EVIL_REDIRECT):
            return self._result(
                Rating.FAIL,
                f"A baseline request with the registered redirect_uri "
                f"reached HTTP {r_baseline.status}; the identical request "
                f"with an unregistered redirect_uri "
                f"({self._EVIL_REDIRECT}) redirected straight to that "
                f"attacker-controlled address — an open redirect that "
                f"could hand an authorization code to whoever controls it.",
                evidence,
            )

        if r_mutated.status != r_baseline.status:
            return self._result(
                Rating.PASS,
                f"A baseline request with the registered redirect_uri "
                f"reached HTTP {r_baseline.status}; the identical request "
                f"with an unregistered redirect_uri "
                f"({self._EVIL_REDIRECT}) reached a different status (HTTP "
                f"{r_mutated.status}) rather than redirecting to it — the "
                f"login server treats the unregistered redirect target "
                f"differently.",
                evidence,
            )

        return self._result(
            Rating.WARN,
            f"A baseline request with the registered redirect_uri and the "
            f"identical request with an unregistered redirect_uri "
            f"({self._EVIL_REDIRECT}) both reached the exact same status "
            f"(HTTP {r_baseline.status}), and neither redirected to the "
            f"unregistered address. Redirect-URI validation could not be "
            f"confirmed from a bare, non-interactive request — some "
            f"Authorization Servers only validate the redirect target "
            f"after an active login session. Verify manually.",
            evidence,
        )


# ---------------------------------------------------------------------------
# AA-03  PKCE enforced
# ---------------------------------------------------------------------------

@register
class PkceEnforced(Check):
    id = "oauth-pkce-enforced"
    rubric_id = "AA-03"
    section = _SECTION
    display_order = 203
    method = "Auth"
    order = 403
    title = "PKCE is enforced"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth Security §Authorization Code Protection: PKCE MUST be enforced; "
        f"an auth request with no valid code_challenge MUST be rejected — {_SPEC_SEC}"
    )
    requires_http = True
    requires_auth = True

    def run(self, target, ctx: ProbeContext):
        asm = target.context.get("as_metadata")
        session = ctx.auth_session
        if session and session.probe_evidence.get("auth_mode") == "supplied-token":
            return self._result(
                Rating.NA,
                "A token was supplied directly (--token), so no interactive "
                "authorization flow ran for this check to probe.",
            )
        client_id = session.probe_evidence.get("client_id") if session else None
        registered_redirect = session.probe_evidence.get("registered_redirect_uri") if session else None
        challenge = session.probe_evidence.get("pkce_challenge") if session else None
        if not asm or not client_id or not registered_redirect or not challenge:
            return self._result(Rating.NA, "No completed login session to build this probe from.")

        # Baseline: the same registered redirect_uri the real flow just
        # used successfully, WITH a valid code_challenge. Mutated: the
        # identical request with code_challenge removed. Using the real
        # registered redirect_uri (not a throwaway one) matters — a bare
        # unregistered redirect_uri could get rejected by AA-02's property
        # (redirect-URI validation) rather than this check's property
        # (PKCE), producing exactly the wrong-reason-for-rejection bug this
        # pattern exists to prevent.
        base_params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": registered_redirect,
            "resource": session.resource,
        }
        baseline_params = {**base_params, "state": secrets.token_urlsafe(8),
                            "code_challenge": challenge, "code_challenge_method": "S256"}
        mutated_params = {**base_params, "state": secrets.token_urlsafe(8)}  # no code_challenge at all

        baseline_url = f"{asm['authorization_endpoint']}?{urlencode(baseline_params)}"
        mutated_url = f"{asm['authorization_endpoint']}?{urlencode(mutated_params)}"

        r_baseline = ctx.get(baseline_url)
        r_mutated = ctx.get(mutated_url)

        evidence = {
            "baseline": _authorize_probe_evidence(baseline_url, r_baseline),
            "mutated": _authorize_probe_evidence(mutated_url, r_mutated),
        }

        if r_baseline.error or r_mutated.error:
            return self._result(
                Rating.ERROR,
                "The baseline or mutated probe failed at the network level; "
                "see evidence for which.",
                evidence,
            )

        if r_baseline.status in _AS_GENERIC_REJECTION_STATUSES:
            return self._result(
                Rating.ERROR,
                f"The baseline authorization request — the registered "
                f"redirect_uri and a valid code_challenge, the same client "
                f"the real login flow just used successfully — itself got "
                f"HTTP {r_baseline.status}, so PKCE-enforcement behavior "
                f"can't be isolated from this earlier rejection. Not "
                f"tested; see evidence.",
                evidence,
            )

        mutated_location = r_mutated.headers.get("location", "")
        mutated_qs = parse_qs(urlparse(mutated_location).query) if mutated_location else {}

        if mutated_location and "code=" in mutated_location:
            return self._result(
                Rating.FAIL,
                f"A baseline request (with a valid code_challenge) reached "
                f"HTTP {r_baseline.status}; the identical request with no "
                f"code_challenge at all was not rejected — it was issued an "
                f"authorization code directly. PKCE does not appear to be "
                f"enforced.",
                evidence,
            )
        if r_mutated.status != r_baseline.status or mutated_qs.get("error"):
            return self._result(
                Rating.PASS,
                f"A baseline request (with a valid code_challenge) reached "
                f"HTTP {r_baseline.status}; the identical request with no "
                f"code_challenge reached a different outcome"
                f"{' (error=' + mutated_qs['error'][0] + ')' if mutated_qs.get('error') else f' (HTTP {r_mutated.status})'} "
                f"— confirming PKCE is enforced rather than optional.",
                evidence,
            )
        return self._result(
            Rating.WARN,
            f"A baseline request (with a valid code_challenge) and the "
            f"identical request with no code_challenge both reached the "
            f"exact same status (HTTP {r_baseline.status}), with no error "
            f"indicator and no issued code. This login server may require "
            f"an active browser session before validating the request "
            f"(this probe sends no cookies), so PKCE enforcement could not "
            f"be conclusively confirmed from a bare request — verify "
            f"manually.",
            evidence,
        )


# ---------------------------------------------------------------------------
# AA-04  Issuer response validation (RFC 9207)
# ---------------------------------------------------------------------------

@register
class IssuerResponseValid(Check):
    id = "oauth-issuer-response-valid"
    rubric_id = "AA-04"
    section = _SECTION
    display_order = 204
    method = "Auth"
    order = 406
    title = "Authorization response issuer is validated"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth §Overview / RFC 9207: the authorization response MUST carry "
        f"iss; it MUST match the AS issuer before the code is exchanged — {_SPEC_AUTH}"
    )
    requires_http = True
    requires_auth = True

    def run(self, target, ctx: ProbeContext):
        session = ctx.auth_session
        asm = target.context.get("as_metadata") or {}
        if not session:
            return self._result(Rating.NA, "No completed login session.")
        if session.probe_evidence.get("auth_mode") == "supplied-token":
            return self._result(
                Rating.NA,
                "A token was supplied directly (--token), so no authorization "
                "redirect occurred for this check to inspect.",
            )
        callback_iss = session.probe_evidence.get("callback_iss")
        expected = asm.get("issuer")
        evidence = {"callback_iss": callback_iss, "expected_issuer": expected}

        if not callback_iss:
            return self._result(
                Rating.WARN,
                "The redirect back from login carried no 'iss' parameter, so "
                "there's no RFC 9207 issuer confirmation to check before the "
                "authorization code is used. mcp-audit proceeded to exchange "
                "the code anyway for evaluation purposes; a strict client "
                "SHOULD refuse to.",
                evidence,
            )
        if callback_iss == expected:
            return self._result(
                Rating.PASS,
                f"The redirect back from login carried iss={callback_iss!r}, "
                f"matching the login server's own issuer identifier — confirms "
                f"the code actually came from the expected login server before "
                f"it was used.",
                evidence,
            )
        return self._result(
            Rating.FAIL,
            f"The redirect's iss={callback_iss!r} does not match the login "
            f"server's own issuer identifier ({expected!r}). A compliant client "
            f"MUST refuse to use this authorization code.",
            evidence,
        )


# ---------------------------------------------------------------------------
# AA-05  Advertised scope surface is bounded
# ---------------------------------------------------------------------------

@register
class ScopeSurface(Check):
    id = "oauth-scope-surface"
    rubric_id = "AA-05"
    section = _SECTION
    display_order = 205
    method = "Probe"
    order = 42
    title = "Advertised scopes are narrowly defined (least privilege)"
    spec_level = SpecLevel.SHOULD
    spec_ref = (
        f"MCP Auth Security §Scope Minimization: scopes SHOULD be granular and "
        f"operation-specific; overly broad scopes raise blast radius — {_SPEC_SEC}"
    )
    requires_http = True

    _BROAD = {
        "repo", "admin", "write", "workflow", "write:org", "admin:org",
        "write:packages", "delete", "*", "full_access", "sysadmin",
    }

    def run(self, target, ctx: ProbeContext):
        prm = target.context.get("prm_doc")
        if not prm:
            return self._result(
                Rating.NA,
                "No Protected Resource Metadata was found (CD-02), so there is no "
                "scope list to assess.",
            )
        scopes = prm.get("scopes_supported", [])
        if not scopes:
            return self._result(
                Rating.WARN,
                "The Protected Resource Metadata lists no scopes_supported at "
                "all, so it's not possible to tell whether logging in grants "
                "broad or narrow access from this document alone.",
            )
        broad = [s for s in scopes if any(b in s.lower() for b in self._BROAD)]
        if broad:
            return self._result(
                Rating.WARN,
                f"{len(broad)} of {len(scopes)} advertised permission scope(s) "
                f"look broad or write-capable: {', '.join(broad)}. If an agent "
                f"requests the full advertised set, its access could exceed what "
                f"it actually needs to do its job.",
                {"broad_scopes": broad, "all_scopes": scopes},
            )
        return self._result(
            Rating.PASS,
            f"All {len(scopes)} advertised permission scope(s) look narrow and "
            f"specific: {', '.join(scopes)}.",
            {"all_scopes": scopes},
        )
