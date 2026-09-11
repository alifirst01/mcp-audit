"""Base Check class + registry."""
from __future__ import annotations

from abc import ABC, abstractmethod

from .models import CheckResult, Rating, SpecLevel, Target
from .probe import ProbeContext

# Console output shows only a result's `detail` line; the full evidence dict
# (exact requests/responses) is written to disk only when a run is passed
# --out (`eval --out report.json`, or `eval-file --out results/` — which
# writes both a per-server results/<name>.json and results/summary.json).
# See docs/METHODOLOGY.md "Evidence requirement".
EVIDENCE_NOTE = "See this check's evidence (saved to the JSON report with --out) for the exact request/response."

_REGISTRY: list[type["Check"]] = []


def register(cls: type["Check"]) -> type["Check"]:
    _REGISTRY.append(cls)
    return cls


def all_checks() -> list[type["Check"]]:
    return list(_REGISTRY)


class Check(ABC):
    """A single evaluation. Subclass, set the metadata, implement run()."""

    id: str = ""
    title: str = ""
    spec_level: SpecLevel = SpecLevel.HYGIENE
    spec_ref: str = ""

    rubric_id: str = ""
    section: str = ""
    display_order: int = 999
    method: str = "Probe"

    requires_http: bool = False
    requires_auth: bool = False

    # Lower runs first. Discovery checks that populate target.context are
    # ordered ahead of the checks that read it.
    order: int = 100

    def applicable(self, target: Target) -> bool:
        from .models import Transport
        if self.requires_http and target.transport == Transport.STDIO:
            return False
        return True

    @abstractmethod
    def run(self, target: Target, ctx: "ProbeContext") -> CheckResult:
        raise NotImplementedError

    def baseline_gate(self, response, evidence: dict) -> CheckResult | None:
        """Guard for differential (baseline-vs-mutation) checks. Returns None
        to proceed only when the baseline reached the behavior under test — a
        2xx with a body. For any other status (auth challenge, wrong
        route/method, malformed, redirect, or a 202 whose reply is on an SSE
        stream) the mutation has nothing to be compared against, so this
        returns an NA result naming the status. Network failures are the
        caller's to handle via `response.error` first."""
        if 200 <= response.status < 300 and response.status != 202:
            return None
        if response.status == 202:
            tail = (
                " The response is delivered on a separate SSE stream this "
                "probe does not consume. SSE async response not captured."
            )
        elif response.status in (401, 403):
            tail = " Re-run with --auth."
        else:
            tail = " " + EVIDENCE_NOTE
        return self._result(
            Rating.NA,
            f"The baseline request did not reach a usable 2xx success status "
            f"(HTTP {response.status}), so it never reached the behavior this "
            f"check tests and there is nothing for the mutation to be compared "
            f"against. Not tested." + tail,
            evidence,
        )

    def _result(self, rating, detail="", evidence=None) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            title=self.title,
            rating=rating,
            spec_level=self.spec_level,
            spec_ref=self.spec_ref,
            rubric_id=self.rubric_id,
            section=self.section,
            display_order=self.display_order,
            method=self.method,
            detail=detail,
            evidence=evidence or {},
        )
