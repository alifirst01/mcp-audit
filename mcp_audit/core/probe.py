"""ProbeContext — the shared HTTP layer.

All network I/O for checks flows through here so that:
  - identical requests are fetched only once per run (cache)
  - timeouts, TLS, and redirect behaviour are consistent

Unauthenticated GETs, targeted POST probes, and — once `--auth` completes —
authenticated requests all flow through this shared client.
"""
from __future__ import annotations

import json as _json
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    text: str
    url: str
    error: Optional[str] = None

    def json(self):
        return _json.loads(self.text)


@dataclass
class AuthSession:
    """The result of a completed OAuth 2.1 authorization-code flow (see core/oauth.py).

    Populated by `oauth.authenticate()` and stashed on `ProbeContext.auth_session` so
    every downstream Auth-method check can make authenticated requests without
    re-running the flow.
    """
    access_token: str
    token_type: str = "Bearer"
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    scope: Optional[str] = None
    requested_scope: Optional[str] = None
    issuer: Optional[str] = None
    resource: Optional[str] = None
    obtained_at: float = field(default_factory=time.time)
    # Full request/response evidence for checks that need to show their work.
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
    """Per-target network context with a small response cache."""
    timeout: float = 15.0
    auth_session: Optional[AuthSession] = None
    auth_failure: Optional[AuthFailure] = None
    transport: Optional[httpx.BaseTransport] = None
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
        """Merge `Authorization: Bearer <token>` into a headers dict. Raises if no
        auth session is present — callers must check `self.auth_session` first."""
        if not self.auth_session:
            raise RuntimeError("authed_headers() called with no active auth_session")
        h = dict(extra or {})
        h["Authorization"] = f"{self.auth_session.token_type} {self.auth_session.access_token}"
        return h

    def get(self, url: str, headers: Optional[dict] = None) -> Response:
        key = f"GET {url} {sorted((headers or {}).items())}"
        if key in self._cache:
            return self._cache[key]
        try:
            r = self._client.get(url, headers=headers or {})
            resp = Response(
                status=r.status_code,
                headers={k.lower(): v for k, v in r.headers.items()},
                text=r.text,
                url=str(r.url),
            )
        except Exception as e:
            resp = Response(status=0, headers={}, text="", url=url, error=str(e))
        self._cache[key] = resp
        return resp

    def post(self, url: str, json_body: Optional[dict] = None,
             headers: Optional[dict] = None) -> Response:
        """Send an HTTP POST. Callers own the Content-Type via `headers`; a
        default of application/json is set automatically when json_body is
        provided and no explicit Content-Type is in headers."""
        h: dict[str, str] = {}
        if json_body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        body_bytes = _json.dumps(json_body).encode() if json_body is not None else None
        try:
            r = self._client.post(url, content=body_bytes, headers=h)
            return Response(
                status=r.status_code,
                headers={k.lower(): v for k, v in r.headers.items()},
                text=r.text,
                url=str(r.url),
            )
        except Exception as e:
            return Response(status=0, headers={}, text="", url=url, error=str(e))

    def post_form(self, url: str, data, headers: Optional[dict] = None) -> Response:
        """Send an application/x-www-form-urlencoded POST — the body shape
        OAuth token/refresh requests use per RFC 6749, not JSON. Same
        governed client as every other method (timeout, TLS, redirect
        policy). `data` may be a dict (form-encoded by httpx) or a
        pre-encoded query string"""
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(headers or {})
        try:
            if isinstance(data, (str, bytes)):
                r = self._client.post(url, content=data, headers=h)
            else:
                r = self._client.post(url, data=data, headers=h)
            return Response(
                status=r.status_code,
                headers={k.lower(): v for k, v in r.headers.items()},
                text=r.text,
                url=str(r.url),
            )
        except Exception as e:
            return Response(status=0, headers={}, text="", url=url, error=str(e))

    def request(self, method: str, url: str,
                headers: Optional[dict] = None) -> Response:
        """Send an arbitrary HTTP request (e.g. DELETE, OPTIONS)"""
        try:
            r = self._client.request(method.upper(), url, headers=headers or {})
            return Response(
                status=r.status_code,
                headers={k.lower(): v for k, v in r.headers.items()},
                text=r.text,
                url=str(r.url),
            )
        except Exception as e:
            return Response(status=0, headers={}, text="", url=url, error=str(e))

    def close(self):
        if self._client:
            self._client.close()
        self.auth_session = None
