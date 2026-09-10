"""MCP initialize handshake + SSE endpoint resolution (_helpers.mcp_session).

No real network: an httpx.MockTransport stands in for the server and records
every request so a test can assert what actually went over the wire — which
endpoint the JSON-RPC POST hit, which headers it carried, and whether the
Mcp-Session-Id / negotiated protocol version from initialize were echoed on
subsequent requests.
"""
from __future__ import annotations

import json

import httpx
import pytest

from mcp_audit.checks.server._helpers import (
    _server_supported_version,
    _streamable_http_guess,
    accepted_async,
    fetch_tools_authed,
    mcp_message_target,
    mcp_session,
    parse_jsonrpc_message,
)
from mcp_audit.core.probe import AuthSession, ProbeContext
from mcp_audit.core.models import Target, Transport

SID = "sess-abc-123"


def _body_method(request: httpx.Request) -> str:
    try:
        return json.loads(request.content.decode()).get("method", "")
    except Exception:
        return ""


def _body(request: httpx.Request) -> dict:
    try:
        return json.loads(request.content.decode())
    except Exception:
        return {}


def _sse(obj: dict) -> httpx.Response:
    """A JSON-RPC object delivered SSE-framed, the way Neon answers a POST."""
    return httpx.Response(
        200,
        text=f"event: message\r\ndata: {json.dumps(obj)}\r\n\r\n",
        headers={"content-type": "text/event-stream", "Mcp-Session-Id": SID},
    )


class FakeServer:
    """Streamable-HTTP at /mcp that demands the initialize handshake, plus an
    HTTP+SSE stream at /sse that announces /messages/xyz as its endpoint."""

    def __init__(self, *, sse_endpoint_event: bool = True, require_session_id: bool = True,
                 init_status: int = 200, init_protocol_version: str = "2026-07-28",
                 get_status: int = 200, init_error_code: int = -32020,
                 enforce_header_body_consistency: bool = True,
                 supported_versions: list | None = None,
                 version_reject_via_200: bool = False,
                 sse_replies: bool = False,
                 tools_accept_version: str | None = None):
        self.requests: list[httpx.Request] = []
        self.transport = httpx.MockTransport(self._handle)
        self._sse_endpoint_event = sse_endpoint_event
        self._require_session_id = require_session_id
        self._init_status = init_status
        self._init_pv = init_protocol_version
        self._get_status = get_status
        self._init_error_code = init_error_code
        self._strict = enforce_header_body_consistency
        # When set, initialize with a protocolVersion not in this list is
        # rejected with -32000 + data.supported (Neon behaviour).
        self._supported = supported_versions
        self._version_reject_via_200 = version_reject_via_200
        # Neon answers POSTs with text/event-stream, not application/json.
        self._sse_replies = sse_replies
        # When set, tools/list must carry exactly this version in header + body
        # _meta, else -32000 (Neon rejects the hardcoded version this way).
        self._tools_accept_version = tools_accept_version

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        method = _body_method(request)

        if request.method == "GET" and path in ("/sse", "/mcp", "/messages/xyz"):
            if path == "/sse" and not self._sse_endpoint_event:
                return httpx.Response(200, text="event: ping\r\ndata: {}\r\n\r\n",
                                      headers={"content-type": "text/event-stream"})
            if path == "/sse":
                return httpx.Response(
                    200,
                    text="event: endpoint\r\ndata: /messages/xyz\r\n\r\n",
                    headers={"content-type": "text/event-stream"},
                )
            # reference GET used by mcp_session when initialize POST 401s
            return httpx.Response(self._get_status, json={"ok": self._get_status == 200})

        if request.method == "POST" and path in ("/mcp", "/messages/xyz"):
            b = _body(request)
            if method == "initialize":
                if self._init_status == 202:
                    return httpx.Response(202, text="")
                if self._init_status == 401:
                    return httpx.Response(401, json={"error": "No authorization provided"})
                if self._init_status == 400:
                    return httpx.Response(400, json={
                        "jsonrpc": "2.0", "id": 0,
                        "error": {"code": self._init_error_code, "message": "bad request"}})
                # Neon-style: the mirrored headers must agree with the body.
                if self._strict:
                    if (request.headers.get("mcp-protocol-version") != b["params"].get("protocolVersion")
                            or request.headers.get("mcp-method") != b.get("method")):
                        return httpx.Response(400, json={
                            "jsonrpc": "2.0", "id": 0,
                            "error": {"code": -32020, "message": "HeaderMismatch"}})
                # Neon-style: reject an unsupported protocolVersion with -32000
                # and the supported list, either as an HTTP 400 or inside a 200.
                if self._supported is not None and b["params"].get("protocolVersion") not in self._supported:
                    err = {"jsonrpc": "2.0", "id": 0, "error": {
                        "code": -32000, "message": "Unsupported protocol version",
                        "data": {"supported": self._supported}}}
                    if self._sse_replies:
                        return _sse(err)
                    return httpx.Response(200 if self._version_reject_via_200 else 400, json=err)
                result_pv = (b["params"].get("protocolVersion")
                             if self._supported is not None else self._init_pv)
                ok = {"jsonrpc": "2.0", "id": 0,
                      "result": {"protocolVersion": result_pv, "capabilities": {}}}
                if self._sse_replies:
                    return _sse(ok)
                return httpx.Response(200, json=ok, headers={"Mcp-Session-Id": SID})
            if method == "notifications/initialized":
                return httpx.Response(202, text="")
            if method == "tools/list":
                if self._init_status == 202:
                    # SSE async server: the reply comes on the stream, not here.
                    return httpx.Response(202, text="")
                if self._require_session_id and request.headers.get("mcp-session-id") != SID:
                    return httpx.Response(401, json={"error": "No authorization provided"})
                if self._tools_accept_version is not None:
                    want = self._tools_accept_version
                    meta_v = ((b.get("params") or {}).get("_meta") or {}).get(
                        "io.modelcontextprotocol/protocolVersion")
                    if request.headers.get("mcp-protocol-version") != want or meta_v != want:
                        err = {"jsonrpc": "2.0", "id": 1, "error": {
                            "code": -32000, "message": "Unsupported protocol version"}}
                        return _sse(err) if self._sse_replies else httpx.Response(400, json=err)
                ok = {"jsonrpc": "2.0", "id": 1,
                      "result": {"tools": [{"name": "read_thing", "description": "Reads."}]}}
                return _sse(ok) if self._sse_replies else httpx.Response(200, json=ok)

        return httpx.Response(404, json={"error": "not_found", "path": path})


def _ctx(server: FakeServer, *, authed: bool = True) -> ProbeContext:
    ctx = ProbeContext(transport=server.transport)
    if authed:
        ctx.auth_session = AuthSession(access_token="tok", token_type="Bearer")
    return ctx


def _target(url: str) -> Target:
    return Target(name="t", url=url, transport=Transport.HTTP)


# ---------------------------------------------------------------------------

def test_initialize_runs_and_session_id_is_captured():
    server = FakeServer()
    session = mcp_session(_target("https://mcp.example.test/mcp"), _ctx(server))

    assert session.initialized is True
    assert session.session_headers == {"Mcp-Session-Id": SID}
    methods = [_body_method(r) for r in server.requests if r.method == "POST"]
    assert methods[0] == "initialize"
    assert "notifications/initialized" in methods


def test_initialize_request_headers_mirror_the_body():
    """Neon rejects initialize with 400 -32020 unless the MCP-Protocol-Version
    and Mcp-Method headers are present AND equal to the body's protocolVersion
    and method. FakeServer enforces the same rule, so a passing handshake
    proves consistency."""
    server = FakeServer()  # enforce_header_body_consistency=True
    session = mcp_session(_target("https://mcp.example.test/mcp"), _ctx(server))
    assert session.initialized is True and session.error is None

    init = next(r for r in server.requests if _body_method(r) == "initialize")
    b = _body(init)
    assert init.headers.get("mcp-protocol-version") == b["params"]["protocolVersion"]
    assert init.headers.get("mcp-method") == b["method"] == "initialize"
    assert init.headers.get("accept") == "application/json, text/event-stream"


def test_negotiated_protocol_version_flows_to_later_requests():
    server = FakeServer(init_protocol_version="2025-06-18", require_session_id=False)
    target = _target("https://mcp.example.test/mcp")
    ctx = _ctx(server)

    session = mcp_session(target, ctx)
    assert session.protocol_version == "2025-06-18"

    url, headers, _used, _s = mcp_message_target(target, ctx)
    assert headers["MCP-Protocol-Version"] == "2025-06-18"

    fetch_tools_authed(target, ctx)
    tl = [r for r in server.requests if _body_method(r) == "tools/list"][-1]
    assert tl.headers.get("mcp-protocol-version") == "2025-06-18"
    body = _body(tl)
    assert body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2025-06-18"


@pytest.mark.parametrize("via_200", [False, True])
def test_unsupported_version_is_renegotiated_from_error_list(via_200):
    """Neon rejects 2026-07-28 with -32000 + data.supported. The client must
    retry once with the newest supported version, then use it everywhere."""
    server = FakeServer(supported_versions=["2024-11-05", "2025-11-25"],
                        version_reject_via_200=via_200, require_session_id=False)
    target = _target("https://mcp.example.test/mcp")
    ctx = _ctx(server)

    tools, err = fetch_tools_authed(target, ctx)

    assert err is None and [t["name"] for t in tools] == ["read_thing"]
    session = target.context["mcp_session"]
    assert session.protocol_version == "2025-11-25"     # newest the server named
    assert session.initialized is True

    inits = [_body(r) for r in server.requests if _body_method(r) == "initialize"]
    assert [b["params"]["protocolVersion"] for b in inits] == ["2026-07-28", "2025-11-25"]
    assert session.evidence["protocol_negotiation"][0]["jsonrpc_error_code"] == -32000

    tl = [r for r in server.requests if _body_method(r) == "tools/list"][-1]
    assert tl.headers.get("mcp-protocol-version") == "2025-11-25"
    assert _body(tl)["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2025-11-25"


def test_sse_framed_initialize_result_is_parsed_and_version_adopted():
    """Neon answers the initialize POST with text/event-stream, not JSON.
    The negotiated protocolVersion must still be extracted (was silently
    dropped by r.json(), leaving the hardcoded version in every later
    request)."""
    server = FakeServer(sse_replies=True, init_protocol_version="2025-11-25",
                        tools_accept_version="2025-11-25", require_session_id=False)
    target = _target("https://mcp.example.test/mcp")
    ctx = _ctx(server)

    tools, err = fetch_tools_authed(target, ctx)

    assert err is None and [t["name"] for t in tools] == ["read_thing"]
    session = target.context["mcp_session"]
    assert session.initialized is True
    assert session.protocol_version == "2025-11-25"           # from the SSE frame
    assert session.evidence["negotiated_protocol_version"] == "2025-11-25"

    tl = [r for r in server.requests if _body_method(r) == "tools/list"][-1]
    assert tl.headers.get("mcp-protocol-version") == "2025-11-25"
    assert _body(tl)["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2025-11-25"


def test_sse_framed_unsupported_version_error_is_renegotiated():
    server = FakeServer(sse_replies=True, supported_versions=["2024-11-05", "2025-11-25"],
                        require_session_id=False)
    target = _target("https://mcp.example.test/mcp")
    ctx = _ctx(server)

    tools, err = fetch_tools_authed(target, ctx)

    assert err is None and [t["name"] for t in tools] == ["read_thing"]
    assert target.context["mcp_session"].protocol_version == "2025-11-25"


def test_parse_jsonrpc_message_json_and_sse():
    assert parse_jsonrpc_message('{"jsonrpc":"2.0","id":1,"result":{"x":1}}')["result"] == {"x": 1}
    assert parse_jsonrpc_message(
        'event: message\r\ndata: {"jsonrpc":"2.0","id":1,"result":{"x":2}}\r\n\r\n'
    )["result"] == {"x": 2}
    # multiple events: last object wins
    two = ("data: {\"id\":1,\"result\":{\"a\":1}}\n\n"
           "event: message\ndata: {\"id\":2,\"result\":{\"b\":2}}\n\n")
    assert parse_jsonrpc_message(two)["result"] == {"b": 2}
    # data split across lines is joined
    assert parse_jsonrpc_message('data: {"id":1,\ndata: "result":{"c":3}}\n\n')["result"] == {"c": 3}
    assert parse_jsonrpc_message("not json, no sse") is None
    assert parse_jsonrpc_message("") is None


def test_renegotiation_only_retries_once():
    # Server never accepts anything -> exactly two initialize attempts, no loop.
    server = FakeServer(supported_versions=["9999-99-99"], require_session_id=False)
    target = _target("https://mcp.example.test/mcp")
    mcp_session(target, _ctx(server))

    assert sum(1 for r in server.requests if _body_method(r) == "initialize") == 2


def test_server_supported_version_picks_newest_from_various_shapes():
    f = _server_supported_version
    assert f({"data": {"supported": ["2024-11-05", "2025-11-25", "2025-06-18"]}}) == "2025-11-25"
    assert f({"data": {"supportedVersions": ["2025-03-26"]}}) == "2025-03-26"
    assert f({"data": ["2024-11-05", "2026-07-28"]}) == "2026-07-28"
    assert f({"message": "Unsupported; try 2025-11-25 or 2024-11-05"}) == "2025-11-25"
    assert f({"data": {"protocolVersion": "2025-11-25"}}) == "2025-11-25"
    assert f({"code": -32000}) is None
    assert f("not a dict") is None


def test_tr04_mutation_keeps_bad_version_baseline_uses_negotiated():
    """The nuance: TR-04's mutated request keeps its deliberately-bad version;
    its baseline (and everything else) uses the negotiated one."""
    from mcp_audit.checks.server.transport_protocol import VersionHeaderEnforced

    server = FakeServer(supported_versions=["2025-11-25"], require_session_id=False)
    target = _target("https://mcp.example.test/mcp")
    target.context = {}
    ctx = _ctx(server)

    VersionHeaderEnforced().run(target, ctx)

    posts = [r for r in server.requests if _body_method(r) == "tools/list"]
    versions = {r.headers.get("mcp-protocol-version") for r in posts}
    assert "2025-11-25" in versions                       # baseline: negotiated
    assert VersionHeaderEnforced._MISMATCHED_VERSION in versions   # mutation: bad, unchanged
    assert "2026-07-28" not in versions                   # hardcoded default not used


def test_session_id_is_echoed_on_tools_list():
    server = FakeServer(require_session_id=True)
    target = _target("https://mcp.example.test/mcp")

    tools, err = fetch_tools_authed(target, _ctx(server))

    assert err is None
    assert [t["name"] for t in tools] == ["read_thing"]
    tl = [r for r in server.requests if _body_method(r) == "tools/list"][-1]
    assert tl.headers.get("mcp-session-id") == SID
    assert tl.headers.get("authorization") == "Bearer tok"


def test_sse_url_resolves_to_message_endpoint():
    server = FakeServer()
    target = _target("https://mcp.example.test/sse")

    tools, err = fetch_tools_authed(target, _ctx(server))

    assert err is None
    session = target.context["mcp_session"]
    assert session.message_url == "https://mcp.example.test/messages/xyz"
    assert session.sse is True
    assert all(r.url.path != "/sse" for r in server.requests if r.method == "POST")


def test_sse_handshake_failure_falls_back_to_streamable_path():
    server = FakeServer(sse_endpoint_event=False)
    session = mcp_session(_target("https://mcp.example.test/sse"), _ctx(server))

    assert session.message_url == "https://mcp.example.test/mcp"
    assert session.sse is False
    assert "SSE handshake" in session.evidence.get("endpoint_resolution", "")


def test_initialize_202_is_accepted_async_not_error():
    server = FakeServer(init_status=202)
    target = _target("https://mcp.example.test/sse")   # resolves to /messages/xyz
    ctx = _ctx(server)

    session = mcp_session(target, ctx)
    assert session.accepted_async is True
    assert session.initialized is True          # accepted, not failed
    assert session.error == "initialize-accepted-async-202"
    # notifications/initialized is NOT sent when we couldn't read InitializeResult
    assert not any(_body_method(r) == "notifications/initialized" for r in server.requests)

    tools, err = fetch_tools_authed(target, ctx)
    assert tools is None
    assert err == "sse-async-not-captured"


def test_initialize_401_with_session_captures_post_vs_get():
    server = FakeServer(init_status=401, get_status=200)
    ctx = _ctx(server)
    session = mcp_session(_target("https://mcp.example.test/mcp"), ctx)

    assert session.error == "initialize-status:401"
    assert "post_vs_get" in session.evidence
    assert session.evidence["reference_get"]["response_status"] == 200
    # the reference GET carried the same bearer token, redacted in evidence
    assert session.evidence["reference_get"]["request_headers"]["Authorization"] == "Bearer <redacted>"


def test_initialize_401_without_session_is_flagged_expected():
    server = FakeServer(init_status=401)
    session = mcp_session(_target("https://mcp.example.test/mcp"), _ctx(server, authed=False))

    assert session.error == "initialize-no-auth-session"
    assert "Re-run with --auth" in session.evidence.get("note", "")
    assert "post_vs_get" not in session.evidence


@pytest.mark.parametrize("code", [-32020, -32602])
def test_initialize_400_captures_full_body_and_jsonrpc_error(code):
    server = FakeServer(init_status=400, init_error_code=code)
    session = mcp_session(_target("https://mcp.example.test/mcp"), _ctx(server))

    assert session.error == f"initialize-jsonrpc-error:{code}"
    assert session.evidence["jsonrpc_error"]["code"] == code
    assert session.evidence["response_body_full"]                 # full body kept
    assert "initialize_request_rejected" in session.evidence       # both -32020 and -32602
    assert "MCP-Protocol-Version" in session.evidence["initialize_request_rejected"]


def test_initialize_succeeds_and_tools_list_works_when_headers_mirror_body():
    """End to end against a Neon-style strict server: consistent mirrored
    headers -> initialize 200 -> Mcp-Session-Id captured -> tools/list works."""
    server = FakeServer()
    target = _target("https://mcp.example.test/mcp")
    ctx = _ctx(server)

    tools, err = fetch_tools_authed(target, ctx)

    assert err is None and [t["name"] for t in tools] == ["read_thing"]
    assert target.context["mcp_session"].session_headers == {"Mcp-Session-Id": SID}


def test_mcp_session_is_cached_handshake_runs_once():
    server = FakeServer()
    target = _target("https://mcp.example.test/mcp")
    ctx = _ctx(server)

    assert mcp_session(target, ctx) is mcp_session(target, ctx)
    assert sum(1 for r in server.requests if _body_method(r) == "initialize") == 1


def test_streamable_http_guess():
    assert _streamable_http_guess("https://mcp.asana.com/sse") == "https://mcp.asana.com/mcp"
    assert _streamable_http_guess("https://x.test/sse/") == "https://x.test/mcp"


def test_accepted_async_predicate():
    class R:
        def __init__(self, s): self.status = s
    assert accepted_async(R(200), R(202)) is True
    assert accepted_async(R(200), R(401)) is False


@pytest.mark.parametrize("authed", [True, False])
def test_initialize_carries_token_only_when_available(authed):
    server = FakeServer(require_session_id=False)
    ctx = _ctx(server, authed=authed)
    mcp_session(_target("https://mcp.example.test/mcp"), ctx)

    init_req = next(r for r in server.requests if _body_method(r) == "initialize")
    if authed:
        assert init_req.headers.get("authorization") == "Bearer tok"
    else:
        assert "authorization" not in init_req.headers
