"""Credential & Token Risk — what credential does the client end up
holding, and how exposed is it?

Once login completes, is the resulting access token protected — how long
does it live, how is it transmitted, is it verified on every use, and can
the agent's own runtime context expose it? Audience binding (CT-01) and
token integrity (CT-03) are related but distinct properties — a server can
verify a token's signature correctly while still failing to check which
resource it was issued for — so they are checked and reported separately
rather than one standing in for the other.

CT-06 through CT-15 are planned, not implemented here — see
admin/checks/server/credential_token_risk_planned.py.

`--auth` triggers core/oauth.py's real flow. If that flow doesn't complete,
the engine reports the Auth-method checks here as ERROR with the failure
reason instead of running them — see core/engine.py.

Spec sources:
  modelcontextprotocol.io/specification/draft/basic/authorization
  modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations
"""
from __future__ import annotations

from ...core.base import Check, register
from ...core.models import Rating, SpecLevel
from ...core.probe import ProbeContext
from ...core import oauth as oauth_module
from ._helpers import decode_jwt_payload, request_evidence

_SECTION = "Credential & Token Risk"

_SPEC_AUTH = (
    "https://modelcontextprotocol.io/specification/draft/basic/authorization"
)
_SPEC_SEC = (
    "https://modelcontextprotocol.io/specification/draft/basic/authorization"
    "/security-considerations"
)


# ---------------------------------------------------------------------------
# CT-01  Resource parameter honored — token bound to this server
# ---------------------------------------------------------------------------

@register
class ResourceBoundToken(Check):
    id = "oauth-resource-bound"
    rubric_id = "CT-01"
    section = _SECTION
    display_order = 301
    method = "Auth"
    order = 405
    title = "Access token is bound to this resource (audience binding)"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth Security: servers MUST support the resource parameter (RFC "
        f"8707) and issue tokens whose audience is bound to the canonical server "
        f"URI — {_SPEC_SEC}"
    )
    requires_http = True
    requires_auth = True

    def run(self, target, ctx: ProbeContext):
        session = ctx.auth_session
        if not session:
            return self._result(Rating.NA, "No completed login session.")
        claims = decode_jwt_payload(session.access_token)
        if claims is None:
            return self._result(
                Rating.MANUAL,
                "The access token is opaque (not a JWT), so its audience claim "
                "can't be read client-side. This was requested with "
                f"resource={session.resource!r} (RFC 8707) — confirm audience "
                "binding server-side, e.g. via token introspection.",
                {"resource_requested": session.resource},
            )
        aud = claims.get("aud")
        aud_list = aud if isinstance(aud, list) else [aud] if aud else []
        evidence = {"resource_requested": session.resource, "aud_claim": aud}
        matches = any(session.resource and (a == session.resource or session.resource.startswith(a)) for a in aud_list if a)
        if matches:
            return self._result(
                Rating.PASS,
                f"The access token's 'aud' claim ({aud!r}) matches the resource "
                f"that was requested ({session.resource!r}) — this token is "
                f"bound to this server and shouldn't be usable elsewhere.",
                evidence,
            )
        return self._result(
            Rating.WARN,
            f"The access token's 'aud' claim is {aud!r}, which does not "
            f"obviously match the requested resource ({session.resource!r}). "
            f"Either the resource parameter isn't being honored, or the audience "
            f"is expressed in a form this check doesn't recognize — verify "
            f"manually.",
            evidence,
        )


# ---------------------------------------------------------------------------
# CT-02  Bearer token delivered via Authorization header, never a query string
# ---------------------------------------------------------------------------

@register
class BearerHeaderOnly(Check):
    id = "oauth-bearer-header-only"
    rubric_id = "CT-02"
    section = _SECTION
    display_order = 302
    method = "Probe"
    order = 26
    title = "Access token is transmitted via the Authorization header only"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth §Access Token Usage: tokens MUST be sent in the "
        f"Authorization: Bearer header and MUST NOT appear in the URI query "
        f"string — {_SPEC_AUTH}"
    )
    requires_http = True

    def run(self, target, ctx: ProbeContext):
        prm = target.context.get("prm_doc")
        if not prm:
            wa = target.context.get("mcp_get_headers", {}).get("www-authenticate", "")
            if not wa:
                return self._result(
                    Rating.NA,
                    "No Protected Resource Metadata or WWW-Authenticate header "
                    "was available to check.",
                )
            if wa.lower().startswith("bearer"):
                return self._result(
                    Rating.PASS,
                    f"The WWW-Authenticate header uses the Bearer scheme "
                    f"({wa!r}), meaning the token is expected in the "
                    f"Authorization header.",
                    {"www_authenticate": wa},
                )
            return self._result(
                Rating.WARN,
                f"The WWW-Authenticate header's scheme is not 'Bearer': {wa!r}.",
                {"www_authenticate": wa},
            )

        bearer_methods = prm.get("bearer_methods_supported", [])
        evidence = {"bearer_methods_supported": bearer_methods}

        if bearer_methods:
            if "query" in bearer_methods:
                return self._result(
                    Rating.FAIL,
                    f"The Protected Resource Metadata lists 'query' among "
                    f"bearer_methods_supported ({bearer_methods}) — meaning this "
                    f"server is willing to accept the login token as a URL query "
                    f"parameter. Query strings routinely end up in server access "
                    f"logs, browser history, and proxy logs, so this is a "
                    f"meaningful exfiltration risk the MCP spec forbids.",
                    evidence,
                )
            if "header" in bearer_methods:
                return self._result(
                    Rating.PASS,
                    f"The Protected Resource Metadata advertises 'header' as the "
                    f"only accepted way to send the token "
                    f"(bearer_methods_supported: {bearer_methods}).",
                    evidence,
                )
            return self._result(
                Rating.WARN,
                f"bearer_methods_supported is {bearer_methods!r}; expected it to "
                f"contain 'header'.",
                evidence,
            )

        wa = target.context.get("mcp_get_headers", {}).get("www-authenticate", "")
        if wa.lower().startswith("bearer"):
            return self._result(
                Rating.PASS,
                f"The Protected Resource Metadata has no "
                f"bearer_methods_supported field, but the WWW-Authenticate "
                f"header uses the Bearer scheme ({wa!r}).",
                {**evidence, "www_authenticate": wa},
            )

        return self._result(
            Rating.WARN,
            "The Protected Resource Metadata does not advertise "
            "bearer_methods_supported, so it can't be confirmed from documents "
            "alone that the token must go in the Authorization header rather "
            "than a query string.",
            evidence,
        )


# ---------------------------------------------------------------------------
# CT-03  Token integrity is verified
# ---------------------------------------------------------------------------

@register
class TokenIntegrityVerified(Check):
    id = "oauth-token-integrity"
    rubric_id = "CT-03"
    section = _SECTION
    display_order = 303
    method = "Auth"
    order = 410
    title = "Token integrity is verified (tampered-token rejection)"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth §Overview: servers MUST validate access tokens on every "
        f"request; a token that fails verification MUST be rejected — {_SPEC_AUTH}"
    )
    requires_http = True
    requires_auth = True

    def run(self, target, ctx: ProbeContext):
        session = ctx.auth_session
        if not session:
            return self._result(Rating.NA, "No completed login session.")
        # Tampering the token's final segment proves integrity verification,
        # not audience binding — a server can verify signatures correctly
        # while still not checking which resource a token was issued for.
        tampered = session.access_token[:-4] + ("0000" if session.access_token[-4:] != "0000" else "1111")
        # tampered is a real token with only the last 4 chars changed;
        # redact_headers() replaces the whole Authorization value so it
        # never lands in evidence.
        r = ctx.get(target.url, headers={"Authorization": f"Bearer {tampered}"})
        evidence = request_evidence(
            "GET", target.url, {"Authorization": f"Bearer {tampered}"}, None, r
        )

        if r.status == 401:
            return self._result(
                Rating.PASS,
                "A tampered copy of the real access token (final segment "
                "altered) was rejected with HTTP 401 — the server verifies "
                "token integrity rather than accepting any bearer-shaped "
                "string. This confirms integrity verification only, not "
                "audience binding (a server could verify signatures "
                "correctly and still not check the token's intended "
                "audience — see CT-01 for that check).",
                evidence,
            )
        return self._result(
            Rating.FAIL if r.status == 200 else Rating.WARN,
            f"A tampered copy of the real access token got HTTP {r.status} "
            f"instead of 401. " + (
                "The server may not be verifying token integrity at all."
                if r.status == 200 else
                "Inconclusive — review manually."
            ),
            evidence,
        )


# ---------------------------------------------------------------------------
# CT-04  Token validated on every request
# ---------------------------------------------------------------------------

@register
class TokenCheckedEveryRequest(Check):
    id = "oauth-token-checked-every-request"
    rubric_id = "CT-04"
    section = _SECTION
    display_order = 304
    method = "Auth"
    order = 411
    title = "Invalid or expired tokens are rejected on every request"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth §Overview: invalid or expired tokens MUST receive HTTP 401; "
        f"no protected resource is served without a verified token — {_SPEC_AUTH}"
    )
    requires_http = True
    requires_auth = True

    def run(self, target, ctx: ProbeContext):
        headers = {"Authorization": "Bearer not-a-real-token-000"}
        r = ctx.get(target.url, headers=headers)
        evidence = request_evidence("GET", target.url, headers, None, r)
        if r.error:
            return self._result(Rating.ERROR, f"Request failed: {r.error}")
        if r.status == 401:
            return self._result(
                Rating.PASS,
                f"A request to {target.url} with an obviously invalid bearer "
                f"token was rejected with HTTP 401, as expected.",
                evidence,
            )
        return self._result(
            Rating.FAIL,
            f"A request to {target.url} with an obviously invalid bearer token "
            f"got HTTP {r.status} instead of 401 — this server may be "
            f"processing protected requests without actually verifying the "
            f"token.",
            evidence,
        )


# ---------------------------------------------------------------------------
# CT-05  Short-lived tokens & refresh rotation
# ---------------------------------------------------------------------------

@register
class ShortLivedAndRefreshRotates(Check):
    id = "oauth-short-lived-refresh"
    rubric_id = "CT-05"
    section = _SECTION
    display_order = 305
    method = "Auth"
    order = 412
    title = "Access tokens are short-lived and refresh tokens rotate"
    spec_level = SpecLevel.SHOULD
    spec_ref = (
        f"MCP Auth Security §Token Lifetime: access tokens SHOULD be "
        f"short-lived (the specification does not name an exact duration); "
        f"refresh tokens SHOULD rotate on each use for public clients — {_SPEC_SEC}"
    )
    requires_http = True
    requires_auth = True

    # mcp-audit's own heuristic for "short-lived," not a specification value.
    _HEURISTIC_CEILING_SECONDS = 3600

    def run(self, target, ctx: ProbeContext):
        session = ctx.auth_session
        if not session:
            return self._result(Rating.NA, "No completed login session.")

        notes = []
        evidence = {"expires_in": session.expires_in, "has_refresh_token": bool(session.refresh_token)}

        if session.expires_in is None:
            notes.append("the token response carried no expires_in — lifetime unknown")
            lifetime_ok = None
        elif session.expires_in <= self._HEURISTIC_CEILING_SECONDS:
            notes.append(
                f"access token expires in {session.expires_in}s, which mcp-audit "
                f"treats as short-lived under its own rough heuristic (roughly "
                f"an hour or less — the specification names no exact threshold)"
            )
            lifetime_ok = True
        else:
            notes.append(
                f"access token expires in {session.expires_in}s, longer than "
                f"mcp-audit's rough short-lived heuristic (roughly an hour); "
                f"the specification does not set an exact ceiling, so this is "
                f"a judgment call worth reviewing rather than a clear violation"
            )
            lifetime_ok = False

        if not session.refresh_token:
            if session.probe_evidence.get("auth_mode") == "supplied-token":
                notes.append(
                    "a token was supplied directly (--token) with no associated "
                    "refresh token, so rotation can't be tested"
                )
            else:
                notes.append("no refresh_token was issued, so rotation can't be tested")
            return self._result(
                Rating.WARN if lifetime_ok is False else Rating.MANUAL,
                "; ".join(notes) + ".",
                evidence,
            )

        try:
            client = oauth_module.ClientCredentials(
                client_id=session.probe_evidence.get("client_id", ""),
                mechanism=session.probe_evidence.get("client_mechanism", ""),
            )
            refreshed = oauth_module.refresh(ctx, target.context.get("as_metadata", {}), client, session)
            rotated = refreshed.probe_evidence.get("refresh_rotated_token")
            evidence["refresh_rotated_token"] = rotated
            # Spending the refresh token can invalidate the access token it
            # replaces on servers with strict rotation (observed on Neon and
            # Stripe; not on Linear/Sentry). Adopt the freshly-issued session
            # so every later Auth-method check (initialize, tools/list, the
            # transport probes) uses the token the AS now considers active —
            # otherwise this probe silently breaks auth for the rest of the run.
            if refreshed.probe_evidence.get("refresh_returned_new_access_token"):
                ctx.auth_session = refreshed
                evidence["session_adopted_refreshed_token"] = True
            notes.append(
                "the refresh token rotated to a new value on use" if rotated
                else "the SAME refresh token was returned again after use (no rotation)"
            )
            if lifetime_ok and rotated:
                return self._result(Rating.PASS, "; ".join(notes) + ".", evidence)
            return self._result(Rating.WARN, "; ".join(notes) + ".", evidence)
        except Exception as e:
            notes.append(f"attempting to refresh failed: {e}")
            return self._result(Rating.WARN, "; ".join(notes) + ".", evidence)
