"""ProbeContext — the shared HTTP layer.

All check network I/O flows through here so redirect policy, TLS, timeouts,
and the GET cache are consistent, and so `--auth` credentials are applied in
one place.
"""
from __future__ import annotations

import json as _json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx


def debug_tokens_enabled() -> bool:
    """True when MCP_AUDIT_DEBUG_TOKENS is set: enables unredacted stderr
    logging of token responses and Authorization headers for diagnosis. Never
    affects evidence written to disk."""
    return os.environ.get("MCP_AUDIT_DEBUG_TOKENS", "").strip().lower() in ("1", "true", "yes", "on")


def debug_log(msg: str) -> None:
    if debug_tokens_enabled():
        print(f"[MCP_AUDIT_DEBUG_TOKENS] {msg}", file=sys.stderr, flush=True)


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    text: str
    url: str
    error: Optional[str] = None

    def json(self):
        return _json.loads(self.text)

    @classmethod
    def from_httpx(cls, r: httpx.Response) -> "Response":
        return cls(
            status=r.status_code,
            headers={k.lower(): v for k, v in r.headers.items()},
            text=r.text,
            url=str(r.url),
        )


@dataclass
class AuthSession:
    """A completed OAuth 2.1 authorization-code flow (see core/oauth.py),
    stashed on `ProbeContext.auth_session` so Auth-method checks share one
    session instead of re-running the flow."""
    access_token: str
    token_type: str = "Bearer"
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    scope: Optional[str] = None
    requested_scope: Optional[str] = None
    issuer: Optional[str] = None
    resource: Optional[str] = None
    obtained_at: float = field(default_factory=time.time)
    # A confidential client's secret, kept only so a later refresh() can
    # re-authenticate at the token endpoint the same way the initial exchange
    # did. Same handling as access_token/refresh_token: held in memory for
    # the run, never copied into probe_evidence or any check's evidence.
    client_secret: Optional[str] = None
    # Flow request/response details for checks that show their work.
    probe_evidence: dict = field(default_factory=dict)

    def expires_at(self) -> Optional[float]:
        if self.expires_in is None:
            return None
        return self.obtained_at + self.expires_in


@dataclass
class AuthFailure:
    reason: str
    stage: str = ""


@dataclass
class ProbeContext:
    """Per-target network context with a small GET response cache."""
    timeout: float = 15.0
    auth_session: Optional[AuthSession] = None
    auth_failure: Optional[AuthFailure] = None
    transport: Optional[httpx.BaseTransport] = None
    # The most recent tools/list request/response, so a check that only
    # receives an error string can still show it in evidence.
    last_tools_list_evidence: Optional[dict] = None
    _cache: dict[str, Response] = field(default_factory=dict)
    _client: Optional[httpx.Client] = None

    def __post_init__(self):
        self._client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=False,
            headers={"User-Agent": "mcp-audit/0.1 (+https://github.com/your-org/mcp-audit)"},
            transport=self.transport,
        )

    def authed_headers(self, extra: Optional[dict] = None) -> dict:
        """`extra` plus `Authorization: Bearer <token>`. Raises if there is no
        auth session, or if the token is blank (a bare `Bearer ` reads to the
        server as no credential at all)."""
        if not self.auth_session:
            raise RuntimeError("authed_headers() called with no active auth_session")
        token = (self.auth_session.access_token or "").strip()
        if not token:
            raise RuntimeError("auth_session.access_token is empty/blank")
        # RFC 6750 §2.1: the scheme name is "Bearer". Some ASes return
        # `token_type` lowercase; strict resource servers then 401. Normalize.
        token_type = (self.auth_session.token_type or "Bearer").strip()
        if token_type.lower() == "bearer":
            token_type = "Bearer"
        h = dict(extra or {})
        h["Authorization"] = f"{token_type} {token}"
        debug_log(f"outgoing Authorization: {token_type} {token!r} (len={len(token)})")
        return h

    def _send(self, url: str, call) -> Response:
        try:
            return Response.from_httpx(call())
        except Exception as e:
            return Response(status=0, headers={}, text="", url=url, error=str(e))

    def get(self, url: str, headers: Optional[dict] = None) -> Response:
        key = f"GET {url} {sorted((headers or {}).items())}"
        if key not in self._cache:
            self._cache[key] = self._send(url, lambda: self._client.get(url, headers=headers or {}))
        return self._cache[key]

    def post(self, url: str, json_body: Optional[dict] = None,
             headers: Optional[dict] = None) -> Response:
        """POST. Content-Type defaults to application/json when `json_body` is
        given and the caller didn't set one in `headers`."""
        h: dict[str, str] = {}
        if json_body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        body_bytes = _json.dumps(json_body).encode() if json_body is not None else None
        return self._send(url, lambda: self._client.post(url, content=body_bytes, headers=h))

    def post_form(self, url: str, data, headers: Optional[dict] = None) -> Response:
        """`application/x-www-form-urlencoded` POST — the body shape OAuth
        token requests use (RFC 6749). `data` is a dict or a pre-encoded
        query string."""
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(headers or {})
        if isinstance(data, (str, bytes)):
            return self._send(url, lambda: self._client.post(url, content=data, headers=h))
        return self._send(url, lambda: self._client.post(url, data=data, headers=h))

    def request(self, method: str, url: str,
                headers: Optional[dict] = None) -> Response:
        """An arbitrary method (DELETE, OPTIONS, ...)."""
        return self._send(url, lambda: self._client.request(method.upper(), url, headers=headers or {}))

    def resolve_sse_endpoint(self, url: str, headers: Optional[dict] = None,
                             max_wait: float = 6.0) -> tuple[Optional[str], Optional[str]]:
        """(message_endpoint_url, None) from the first `endpoint` event of the
        HTTP+SSE stream at `url` — the URL that JSON-RPC POSTs go to under that
        transport — or (None, reason). The stream is closed as soon as the
        endpoint is known."""
        from urllib.parse import urljoin
        h = {"Accept": "text/event-stream"}
        h.update(headers or {})
        try:
            with self._client.stream("GET", url, headers=h, timeout=max_wait) as r:
                if r.status_code != 200:
                    return None, f"status:{r.status_code}"
                event: Optional[str] = None
                for line in r.iter_lines():
                    if not isinstance(line, str):
                        line = line.decode("utf-8", "replace")
                    line = line.rstrip("\r")
                    if line == "":
                        event = None
                        continue
                    if line.startswith(":"):
                        continue
                    if line.startswith("event:"):
                        event = line.split(":", 1)[1].strip()
                    elif line.startswith("data:"):
                        data = line.split(":", 1)[1].strip()
                        if event in ("endpoint", None) and (data.startswith("/") or data.startswith("http")):
                            return urljoin(url, data), None
                return None, "stream-ended-without-endpoint-event"
        except Exception as e:
            return None, f"error:{type(e).__name__}"

    def close(self):
        if self._client:
            self._client.close()
        self.auth_session = None
