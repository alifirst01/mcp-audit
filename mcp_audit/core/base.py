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
        """Guard for differential (baseline-vs-mutation) checks: if the
        baseline itself was rejected at the auth layer (401/403), the auth
        gate fired before the logic under test ever ran, so a mutation that
        gets the same status proves nothing. Returns an NA result in that
        case; returns None when the baseline reached the tested logic and
        the check should proceed to compare baseline vs. mutation."""
        if response.status in (401, 403):
            return self._result(
                Rating.NA,
                f"The baseline request was rejected at the auth layer (HTTP "
                f"{response.status}) before reaching the logic this check "
                f"tests, so there is nothing to compare the mutation "
                f"against. Re-run with --auth.",
                evidence,
            )
        return None

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
