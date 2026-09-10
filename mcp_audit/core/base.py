"""Base Check class + registry."""
from __future__ import annotations

from abc import ABC, abstractmethod

from .models import CheckResult, Rating, SpecLevel, Target
from .probe import ProbeContext

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

    # Lower order runs first; discovery checks that populate context come first
    # so dependent checks can read target.context.
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
        """Guard for differential (baseline-vs-mutation) checks: the mutation
        comparison only means something if the baseline request actually
        reached the behavior under test, and that means a 2xx success.

        Any non-2xx baseline — a 401/403 auth challenge, a 404/405 wrong
        route or method, a 400 malformed request, a 3xx redirect — means the
        request was turned away at an earlier stage, so a mutation that
        reaches the same status proves nothing. A 202 is 2xx but carries no
        response body (the reply is on a separate SSE stream), so it can't be
        compared either. In any of these cases this returns an NA result
        naming the actual baseline status; it returns None (proceed to
        compare) only for a 2xx-with-body success. Network-level failures are
        the caller's to handle via `response.error` before calling this."""
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
            tail = " See evidence for the full request and response."
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
