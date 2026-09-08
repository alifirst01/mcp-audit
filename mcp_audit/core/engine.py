"""The evaluation engine.

Loads every registered check, runs the applicable ones against a target,
and returns a TargetReport. All intelligence lives in the individual checks;
extending the tool never requires touching this file.
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import Callable, Optional

from . import oauth
from .base import all_checks
from .models import CheckResult, Rating, Target, Transport, TargetReport
from .probe import ProbeContext


def _autoload_checks() -> None:
    """Import every module under mcp_audit.checks so @register fires."""
    from .. import checks
    for _, modname, ispkg in pkgutil.walk_packages(
        checks.__path__, prefix="mcp_audit.checks."
    ):
        if not ispkg:
            importlib.import_module(modname)


def evaluate(target: Target, include_auth: bool = False,
             auth_input: oauth.AuthInput | None = None,
             on_result: Optional[Callable[[CheckResult, int, int], None]] = None) -> TargetReport:
    """Run all applicable checks against a single target.

    Args:
        target:        The MCP server to evaluate.
        include_auth:  Run checks that require a completed authenticated session.
                       The credential flow (core/oauth.py) is triggered lazily,
                       right before the first requires_auth check runs — by then
                       every lower-`order` Connection & Discovery check has
                       already populated target.context with AS/PRM metadata.
        auth_input:    Credential material for --auth, checked in priority
                       order by `AuthInput.mode()`: a supplied token, then
                       supplied client credentials, then fully-automatic
                       self-registration. See core/oauth.py's module
                       docstring for the full priority rationale.
        on_result:     Optional callback fired after each result is recorded,
                       as (result, completed_count, total_count) — e.g. for a
                       progress bar.
    """
    _autoload_checks()
    ctx = ProbeContext()
    report = TargetReport(target=target)
    ordered = sorted((c() for c in all_checks()), key=lambda c: c.order)
    total = len(ordered)
    auth_attempted = False

    def record(result: CheckResult) -> None:
        report.results.append(result)
        if on_result:
            on_result(result, len(report.results), total)

    try:
        for check in ordered:
            if check.requires_auth and not include_auth:
                record(check._result(
                    Rating.NA,
                    "Requires an authenticated session; re-run with --auth.",
                ))
                continue
            if check.requires_auth and include_auth and not auth_attempted:
                auth_attempted = True
                if target.transport == Transport.HTTP and target.url:
                    oauth.authenticate(target, ctx, auth_input=auth_input)
                else:
                    from .probe import AuthFailure
                    ctx.auth_failure = AuthFailure(
                        reason="OAuth applies to HTTP targets only; this target has "
                               "no HTTP URL.",
                        stage="applicability",
                    )
            if not check.applicable(target):
                record(check._result(Rating.NA, "Not applicable to this target."))
                continue
            if check.requires_auth and not ctx.auth_session:
                reason = ctx.auth_failure.reason if ctx.auth_failure else (
                    "Authentication did not complete."
                )
                record(check._result(Rating.ERROR, f"OAuth flow did not complete: {reason}"))
                continue
            try:
                record(check.run(target, ctx))
            except Exception as e:
                record(check._result(Rating.ERROR, f"Check raised: {e}"))
    finally:
        if ctx.auth_failure:
            report.auth_failure = ctx.auth_failure.reason
        ctx.close()
    return report
