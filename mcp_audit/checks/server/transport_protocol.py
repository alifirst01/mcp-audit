"""Transport & Protocol Plumbing — is the underlying transport sound?

The wire-level checks that apply to the literal first request a client
makes and to every request thereafter: transport encryption, DNS-rebinding
defense, and protocol-version/header consistency enforcement.

TR-07 is planned, not implemented here — see
admin/checks/server/transport_protocol_planned.py. TR-03 and TR-06 were cut
from the rubric entirely; their code lives in admin/checks/server/retired.py
for reference only — see docs/RUBRIC.md's "Retired checks" note.

TR-01, TR-04, TR-05, and TR-08 use the differential-testing method — see
docs/METHODOLOGY.md.

Spec sources:
  modelcontextprotocol.io/specification/draft/basic/transports/streamable-http
  modelcontextprotocol.io/specification/draft/basic/versioning
"""
from __future__ import annotations

from urllib.parse import urlparse

from ...core.base import Check, register
from ...core.models import Rating, SpecLevel
from ...core.probe import ProbeContext
from ._helpers import (
    base_url,
    extract_jsonrpc_error,
    maybe_authed_headers,
    mcp_post_headers,
    probe_reaches_property_stage,
    request_evidence,
    tools_list_body,
)

_SECTION = "Transport & Protocol Plumbing"

_SPEC_HTTP = (
    "https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http"
)
_SPEC_VERSIONING = (
    "https://modelcontextprotocol.io/specification/draft/basic/versioning"
)


# ---------------------------------------------------------------------------
# TR-01  DNS rebinding / Origin header validation
# ---------------------------------------------------------------------------

@register
class ForeignOriginRejected(Check):
    id = "transport-foreign-origin-rejected"
    rubric_id = "TR-01"
    section = _SECTION
    display_order = 701
    method = "Probe"
    # Runs after the engine's lazy --auth trigger, so if --auth succeeded
    # this probe can carry a real token past a server that checks auth
    # before Origin instead of only reporting an inconclusive WARN on 401.
    order = 460
    title = "Requests with a foreign `Origin` header are rejected"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Streamable HTTP §Security: servers MUST validate the Origin header "
        f"on all incoming connections; invalid origins MUST receive HTTP 403 — {_SPEC_HTTP}"
    )
    requires_http = True

    _EVIL_ORIGIN = "http://evil.attacker.example.com"

    def run(self, target, ctx: ProbeContext):
        if not target.url:
            return self._result(Rating.NA, "No URL to test.")

        body = tools_list_body()
        base_headers, used_auth = maybe_authed_headers(ctx, mcp_post_headers(method="tools/list"))
        legit_origin = base_url(target.url)
        evil_headers = {**base_headers, "Origin": self._EVIL_ORIGIN}
        legit_headers = {**base_headers, "Origin": legit_origin}

        r_no_origin = ctx.post(target.url, json_body=body, headers=base_headers)
        r_legit = ctx.post(target.url, json_body=body, headers=legit_headers)
        r_evil = ctx.post(target.url, json_body=body, headers=evil_headers)

        evidence = {
            "used_auth": used_auth,
            "baseline_no_origin": request_evidence("POST", target.url, base_headers, body, r_no_origin),
            "baseline_legit_origin": request_evidence("POST", target.url, legit_headers, body, r_legit),
            "mutated_foreign_origin": request_evidence("POST", target.url, evil_headers, body, r_evil),
        }

        if r_no_origin.error or r_legit.error or r_evil.error:
            return self._result(
                Rating.ERROR,
                "One or more of the three Origin probes failed at the "
                "network level; see evidence for which.",
                evidence,
            )

        reference, reference_label = None, None
        for candidate, label in ((r_no_origin, "no Origin header"), (r_legit, f"Origin: {legit_origin}")):
            if probe_reaches_property_stage(candidate):
                reference, reference_label = candidate, label
                break

        if reference is None:
            return self._result(
                Rating.ERROR,
                f"Even a request with no hostile Origin header was rejected "
                f"at the request-validation stage (HTTP 400 for both a "
                f"missing Origin and Origin: {legit_origin}), using the "
                f"exact tools/list request shape proven to work elsewhere "
                f"in this run — so Origin behavior can't be isolated from "
                f"this earlier rejection. Not tested; see evidence for the "
                f"full requests and responses.",
                evidence,
            )

        na = self.baseline_gate(reference, evidence)
        if na:
            return na

        if r_evil.status == 403:
            return self._result(
                Rating.PASS,
                f"A baseline request ({reference_label}) reached HTTP "
                f"{reference.status}; the identical request with "
                f"Origin: {self._EVIL_ORIGIN} was rejected with HTTP 403 — "
                f"Origin is validated.",
                evidence,
            )
        if r_evil.status == reference.status:
            return self._result(
                Rating.FAIL,
                f"A baseline request ({reference_label}) reached HTTP "
                f"{reference.status}; the identical request with "
                f"Origin: {self._EVIL_ORIGIN} reached the exact same "
                f"status — Origin does not appear to be validated.",
                evidence,
            )
        return self._result(
            Rating.WARN,
            f"A baseline request ({reference_label}) reached HTTP "
            f"{reference.status}; the foreign-Origin variant reached HTTP "
            f"{r_evil.status} instead of the expected 403 — rejected, but "
            f"not with the status the spec calls for. Review manually.",
            evidence,
        )


# ---------------------------------------------------------------------------
# TR-02  Transport encryption (TLS) — every endpoint involved in this
# evaluation, not just the MCP endpoint itself.
# ---------------------------------------------------------------------------

@register
class HttpsRequired(Check):
    id = "transport-https"
    rubric_id = "TR-02"
    section = _SECTION
    display_order = 702
    method = "Probe"
    order = 36
    title = "Every evaluated endpoint uses HTTPS"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Auth §Communication Security: remote MCP endpoints and "
        f"Authorization Server endpoints MUST use TLS — {_SPEC_HTTP}"
    )
    requires_http = True

    _AS_ENDPOINT_KEYS = (
        "authorization_endpoint",
        "token_endpoint",
        "registration_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
        "jwks_uri",
        "issuer",
    )

    def run(self, target, ctx: ProbeContext):
        if not target.url:
            return self._result(Rating.NA, "No URL to test.")

        checked: dict[str, str] = {"mcp_endpoint": target.url}
        non_https: dict[str, str] = {}
        if urlparse(target.url).scheme != "https":
            non_https["mcp_endpoint"] = target.url

        asm = target.context.get("as_metadata")
        if asm:
            for key in self._AS_ENDPOINT_KEYS:
                val = asm.get(key)
                if not val:
                    continue
                checked[key] = val
                if urlparse(val).scheme != "https":
                    non_https[key] = val

        if non_https:
            listing = ", ".join(f"{k}={v}" for k, v in non_https.items())
            return self._result(
                Rating.FAIL,
                f"{len(non_https)} of {len(checked)} checked endpoint(s) are "
                f"not served over HTTPS: {listing}. Traffic to a plaintext "
                f"endpoint — including any bearer token — can be read or "
                f"altered by anyone on the network path.",
                {"non_https_endpoints": non_https, "checked_endpoints": checked},
            )

        return self._result(
            Rating.PASS,
            f"All {len(checked)} checked endpoint(s) use HTTPS "
            f"({', '.join(checked.keys())}).",
            {"checked_endpoints": checked},
        )


# ---------------------------------------------------------------------------
# TR-04  MCP-Protocol-Version header/body mismatch
#
# Tests a header that disagrees with the body's declared version, not a
# header that's simply absent. The specification allows a server supporting
# pre-2025-06-18 clients to treat a genuinely MISSING MCP-Protocol-Version
# header as defaulting to protocol version 2025-03-26, for backward
# compatibility — so a bare-missing header is not a universal MUST-reject
# case, and probing it would produce a false FAIL against a legitimately
# backward-compatible server. A header that IS present but disagrees with
# the body's declared version is the unambiguous case: header/body
# consistency is a separate MUST regardless of backward-compatibility mode.
# ---------------------------------------------------------------------------

@register
class VersionHeaderEnforced(Check):
    id = "transport-version-header-enforced"
    rubric_id = "TR-04"
    section = _SECTION
    display_order = 704
    method = "Probe"
    # See TR-01's comment: runs after the lazy --auth trigger so this can
    # retry authenticated instead of only ever seeing the 401 challenge.
    order = 462
    title = "Mismatched protocol-version header is rejected"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Streamable HTTP §Protocol Version Header: a MCP-Protocol-Version "
        f"header that disagrees with the body's declared version MUST yield "
        f"400 Bad Request + HeaderMismatch (-32020). (A header that is simply "
        f"absent may be tolerated for backward compatibility with "
        f"pre-2025-06-18 clients — that case is intentionally not tested "
        f"here.) — {_SPEC_HTTP}"
    )
    requires_http = True

    _MISMATCHED_VERSION = "2099-01-01"

    def run(self, target, ctx: ProbeContext):
        if not target.url:
            return self._result(Rating.NA, "No URL to test.")

        body = tools_list_body()
        base_headers, used_auth = maybe_authed_headers(ctx, mcp_post_headers(method="tools/list"))
        mutated_headers = {**base_headers, "MCP-Protocol-Version": self._MISMATCHED_VERSION}

        r_baseline = ctx.post(target.url, json_body=body, headers=base_headers)
        r_mutated = ctx.post(target.url, json_body=body, headers=mutated_headers)

        evidence = {
            "used_auth": used_auth,
            "baseline": request_evidence("POST", target.url, base_headers, body, r_baseline),
            "mutated": request_evidence("POST", target.url, mutated_headers, body, r_mutated),
        }

        if r_baseline.error or r_mutated.error:
            return self._result(
                Rating.ERROR,
                "The baseline or mutated probe failed at the network level; "
                "see evidence for which.",
                evidence,
            )

        if not probe_reaches_property_stage(r_baseline):
            return self._result(
                Rating.ERROR,
                f"The baseline request — a matching MCP-Protocol-Version "
                f"header and body, using the exact tools/list shape proven "
                f"to work elsewhere in this run — itself got HTTP 400, so "
                f"header/body version-mismatch behavior can't be isolated "
                f"from this earlier rejection. Not tested; see evidence.",
                evidence,
            )

        na = self.baseline_gate(r_baseline, evidence)
        if na:
            return na

        if r_mutated.status == 400:
            err = extract_jsonrpc_error(r_mutated.text)
            code = err.get("code") if err else None
            if code == -32020:
                return self._result(
                    Rating.PASS,
                    f"A baseline request (matching header/body version) "
                    f"reached HTTP {r_baseline.status}; the identical "
                    f"request with a mismatched MCP-Protocol-Version header "
                    f"({self._MISMATCHED_VERSION}) was rejected: HTTP 400 "
                    f"with JSON-RPC error code -32020 (HeaderMismatch).",
                    evidence,
                )
            return self._result(
                Rating.WARN,
                f"The mismatched-header request got HTTP 400 (baseline "
                f"reached HTTP {r_baseline.status}), but the JSON-RPC error "
                f"code was {code!r}, not the expected -32020 (HeaderMismatch).",
                evidence,
            )
        if r_mutated.status == r_baseline.status:
            return self._result(
                Rating.FAIL,
                f"A baseline request (matching header/body version) "
                f"reached HTTP {r_baseline.status}; the identical request "
                f"with a mismatched MCP-Protocol-Version header "
                f"({self._MISMATCHED_VERSION}) reached the exact same "
                f"status — header/body consistency does not appear to be "
                f"enforced for the protocol-version header.",
                evidence,
            )
        return self._result(
            Rating.WARN,
            f"The mismatched-header request got HTTP {r_mutated.status} "
            f"(baseline reached HTTP {r_baseline.status}) — different from "
            f"the baseline, but not the expected 400 with -32020. Review "
            f"manually.",
            evidence,
        )


# ---------------------------------------------------------------------------
# TR-05  Header–body consistency
# ---------------------------------------------------------------------------

@register
class HeaderBodyConsistency(Check):
    id = "transport-header-body-consistency"
    rubric_id = "TR-05"
    section = _SECTION
    display_order = 705
    method = "Probe"
    # See TR-01's comment: runs after the lazy --auth trigger so this can
    # retry authenticated instead of only ever seeing the 401 challenge.
    order = 463
    title = "Header/body mismatches are rejected"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Streamable HTTP §Server Validation: header/body mismatch MUST "
        f"yield 400 Bad Request + HeaderMismatch (-32020) — {_SPEC_HTTP}"
    )
    requires_http = True

    _MISMATCHED_METHOD = "resources/read"  # a real, different MCP method than the body's

    def run(self, target, ctx: ProbeContext):
        if not target.url:
            return self._result(Rating.NA, "No URL to test.")

        body = tools_list_body()
        base_headers, used_auth = maybe_authed_headers(ctx, mcp_post_headers(method="tools/list"))
        mutated_headers = {**base_headers, "Mcp-Method": self._MISMATCHED_METHOD}

        r_baseline = ctx.post(target.url, json_body=body, headers=base_headers)
        r_mutated = ctx.post(target.url, json_body=body, headers=mutated_headers)

        evidence = {
            "used_auth": used_auth,
            "baseline": request_evidence("POST", target.url, base_headers, body, r_baseline),
            "mutated": request_evidence("POST", target.url, mutated_headers, body, r_mutated),
        }

        if r_baseline.error or r_mutated.error:
            return self._result(
                Rating.ERROR,
                "The baseline or mutated probe failed at the network level; "
                "see evidence for which.",
                evidence,
            )

        if not probe_reaches_property_stage(r_baseline):
            return self._result(
                Rating.ERROR,
                f"The baseline request — Mcp-Method: tools/list matching a "
                f"tools/list body, the exact shape proven to work elsewhere "
                f"in this run — itself got HTTP 400, so header/body "
                f"method-mismatch behavior can't be isolated from this "
                f"earlier rejection. Not tested; see evidence.",
                evidence,
            )

        na = self.baseline_gate(r_baseline, evidence)
        if na:
            return na

        if r_mutated.status == 400:
            err = extract_jsonrpc_error(r_mutated.text)
            code = err.get("code") if err else None
            if code == -32020:
                return self._result(
                    Rating.PASS,
                    f"A baseline request (Mcp-Method matching the body) "
                    f"reached HTTP {r_baseline.status}; the identical "
                    f"request with Mcp-Method: {self._MISMATCHED_METHOD} "
                    f"(body still declaring tools/list) was rejected: HTTP "
                    f"400 with error code -32020 (HeaderMismatch).",
                    evidence,
                )
            return self._result(
                Rating.WARN,
                f"The mismatched-header request got HTTP 400 (baseline "
                f"reached HTTP {r_baseline.status}), but the error code was "
                f"{code!r}, not the expected -32020.",
                evidence,
            )
        if r_mutated.status == r_baseline.status:
            return self._result(
                Rating.FAIL,
                f"A baseline request (Mcp-Method matching the body) reached "
                f"HTTP {r_baseline.status}; the identical request with "
                f"Mcp-Method: {self._MISMATCHED_METHOD} (body still "
                f"declaring tools/list) reached the exact same status — a "
                f"proxy trusting the header and a backend trusting the body "
                f"could be routed to two different operations for the same "
                f"request.",
                evidence,
            )
        return self._result(
            Rating.WARN,
            f"The mismatched-header request got HTTP {r_mutated.status} "
            f"(baseline reached HTTP {r_baseline.status}) — different from "
            f"the baseline, but not the expected 400 with -32020. Review "
            f"manually.",
            evidence,
        )


# ---------------------------------------------------------------------------
# TR-08  Unsupported protocol versions
#
# Header and body both get the bogus version, consistently — this isolates
# version *negotiation*, not header/body *consistency* (TR-05's job).
# ---------------------------------------------------------------------------

@register
class UnsupportedVersionError(Check):
    id = "transport-unsupported-version-error"
    rubric_id = "TR-08"
    section = _SECTION
    display_order = 708
    method = "Probe"
    # See TR-01's comment: runs after the lazy --auth trigger so this can
    # retry authenticated instead of only ever seeing the 401 challenge.
    order = 465
    title = "Unsupported protocol versions are rejected with a supported-version list"
    spec_level = SpecLevel.MUST
    spec_ref = (
        f"MCP Versioning §Protocol Version Negotiation: if the server does not "
        f"implement the requested version it MUST respond with "
        f"UnsupportedProtocolVersionError (-32022) listing supported versions in "
        f"data.supported — {_SPEC_VERSIONING}"
    )
    requires_http = True

    _BOGUS_VERSION = "1900-01-01"

    def run(self, target, ctx: ProbeContext):
        if not target.url:
            return self._result(Rating.NA, "No URL to test.")

        real_body = tools_list_body()
        base_headers, used_auth = maybe_authed_headers(ctx, mcp_post_headers(method="tools/list"))
        r_baseline = ctx.post(target.url, json_body=real_body, headers=base_headers)

        bogus_body = tools_list_body(version=self._BOGUS_VERSION)
        bogus_headers = {**base_headers, "MCP-Protocol-Version": self._BOGUS_VERSION}
        r_mutated = ctx.post(target.url, json_body=bogus_body, headers=bogus_headers)

        evidence = {
            "used_auth": used_auth,
            "baseline": request_evidence("POST", target.url, base_headers, real_body, r_baseline),
            "mutated": request_evidence("POST", target.url, bogus_headers, bogus_body, r_mutated),
        }

        if r_baseline.error or r_mutated.error:
            return self._result(
                Rating.ERROR,
                "The baseline or mutated probe failed at the network level; "
                "see evidence for which.",
                evidence,
            )

        if not probe_reaches_property_stage(r_baseline):
            return self._result(
                Rating.ERROR,
                f"The baseline request — the real, current protocol version "
                f"consistently in both header and body, using the exact "
                f"tools/list shape proven to work elsewhere in this run — "
                f"itself got HTTP 400, so version-negotiation behavior "
                f"can't be isolated from this earlier rejection. Not "
                f"tested; see evidence.",
                evidence,
            )

        na = self.baseline_gate(r_baseline, evidence)
        if na:
            return na

        err = extract_jsonrpc_error(r_mutated.text)
        code = err.get("code") if err else None
        supported = (err or {}).get("data", {}).get("supported") if err else None

        if code == -32022:
            if supported:
                return self._result(
                    Rating.PASS,
                    f"A baseline request (real protocol version) reached "
                    f"HTTP {r_baseline.status}; the identical request with "
                    f"version {self._BOGUS_VERSION} consistently in header "
                    f"and body got JSON-RPC error -32022 "
                    f"(UnsupportedProtocolVersionError) listing the "
                    f"versions this server does support: {supported}.",
                    evidence,
                )
            return self._result(
                Rating.WARN,
                f"The bogus-version request got error -32022 (baseline "
                f"reached HTTP {r_baseline.status}), but the error "
                f"payload's data.supported list was empty or missing — an "
                f"agent has no way to learn which version would actually "
                f"work.",
                evidence,
            )

        if r_mutated.status == r_baseline.status:
            return self._result(
                Rating.FAIL,
                f"A baseline request (real protocol version) reached HTTP "
                f"{r_baseline.status}; the identical request with version "
                f"{self._BOGUS_VERSION} (which should not exist) reached "
                f"the exact same status — version negotiation does not "
                f"appear to reject unsupported versions.",
                evidence,
            )

        if r_mutated.status == 400 and code is not None:
            return self._result(
                Rating.WARN,
                f"The bogus-version request got HTTP 400 with error code "
                f"{code!r} (baseline reached HTTP {r_baseline.status}), "
                f"not the expected -32022 (UnsupportedProtocolVersionError).",
                evidence,
            )

        return self._result(
            Rating.WARN,
            f"The bogus-version request got HTTP {r_mutated.status} / "
            f"error code {code!r} (baseline reached HTTP "
            f"{r_baseline.status}) — different from the baseline, but not "
            f"the expected -32022. Review manually.",
            evidence,
        )
