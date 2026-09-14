"""Core data models for the MCP audit tool."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from .. import __version__


class Rating(str, Enum):
    """Traffic-light rating for a single check.

    PASS   = meets the spec requirement / good hygiene
    WARN   = partial, deviation, or a SHOULD that isn't met
    FAIL   = violates a MUST / clear bad hygiene
    NA     = not applicable to this target (wrong transport, needs --auth, etc.)
    MANUAL = applicable but requires human / documentation review to assess
    ERROR  = the check could not be evaluated (network error, etc.)
    """
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    NA = "na"
    MANUAL = "manual"
    ERROR = "error"


class SpecLevel(str, Enum):
    """How strong the underlying requirement is, per the MCP spec / RFCs."""
    MUST = "MUST"
    SHOULD = "SHOULD"
    MAY = "MAY"
    HYGIENE = "HYGIENE"


class Transport(str, Enum):
    HTTP = "http"
    STDIO = "stdio"
    UNKNOWN = "unknown"


@dataclass
class Target:
    """A single MCP server under evaluation."""
    name: str
    url: Optional[str] = None
    repo: Optional[str] = None
    transport: Transport = Transport.UNKNOWN
    category: Optional[str] = None
    notes: Optional[str] = None
    openapi_ref: Optional[str] = None
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    """The outcome of one check against one target."""
    check_id: str
    title: str
    rating: Rating
    spec_level: SpecLevel
    spec_ref: str
    rubric_id: str = ""
    section: str = ""
    display_order: int = 999
    method: str = "Probe"
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "rubric_id": self.rubric_id,
            "section": self.section,
            "display_order": self.display_order,
            "method": self.method,
            "title": self.title,
            "rating": self.rating.value,
            "spec_ref": self.spec_ref,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class TargetReport:
    """All check results for one target, plus the target itself."""
    target: Target
    results: list[CheckResult] = field(default_factory=list)
    # Set when --auth was requested but the credential flow did not complete
    auth_failure: Optional[str] = None
    # When this run happened, so a report file is dateable without relying
    # on filesystem metadata (which doesn't survive being copied/emailed).
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Full report, evidence included — written for `eval --out` and for
        each server's own file under `eval-file --out`. Self-contained: name,
        URL, tool version, and run timestamp travel with it, so the file is
        verifiable without the run that produced it."""
        return {
            "name": self.target.name,
            "url": self.target.url,
            "repo": self.target.repo,
            "transport": self.target.transport.value,
            "category": self.target.category,
            "auth_failure": self.auth_failure,
            "tool_version": __version__,
            "timestamp": self.timestamp,
            "results": [r.to_dict() for r in self.results],
        }

    def to_summary_dict(self) -> dict[str, Any]:
        """Thin roll-up for `eval-file`'s summary.json: identifying fields
        plus, per check, only rubric_id/rating/title/method/detail — no
        evidence. Full evidence lives in this server's own per-server file."""
        return {
            "name": self.target.name,
            "url": self.target.url,
            "transport": self.target.transport.value,
            "auth_failure": self.auth_failure,
            "results": [
                {
                    "rubric_id": r.rubric_id or r.check_id,
                    "rating": r.rating.value,
                    "title": r.title,
                    "method": r.method,
                    "detail": r.detail,
                }
                for r in self.results
            ],
        }
