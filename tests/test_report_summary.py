"""TargetReport.to_dict (full, self-contained) vs to_summary_dict (thin
roll-up for eval-file's summary.json) — and the CLI's auth-incomplete
annotation on a report's pass/fail counts.
"""
from __future__ import annotations

from mcp_audit import __version__
from mcp_audit.core.models import CheckResult, Rating, SpecLevel, Target, TargetReport, Transport


def _result(rubric_id: str, rating: Rating, evidence=None) -> CheckResult:
    return CheckResult(
        check_id=f"check-{rubric_id.lower()}",
        title=f"Title for {rubric_id}",
        rating=rating,
        spec_level=SpecLevel.MUST,
        spec_ref="https://example.test/spec",
        rubric_id=rubric_id,
        section="Some Section",
        method="Probe",
        detail=f"detail for {rubric_id}",
        evidence=evidence or {"big": "blob" * 1000},
    )


def _report(auth_failure=None) -> TargetReport:
    target = Target(name="Acme MCP", url="https://acme.test/mcp", transport=Transport.HTTP)
    results = [_result("CD-01", Rating.PASS), _result("TR-02", Rating.FAIL)]
    return TargetReport(target=target, results=results, auth_failure=auth_failure)


# --- full to_dict(): self-contained, evidence included ----------------------

def test_to_dict_is_self_contained_with_version_and_timestamp():
    d = _report().to_dict()
    assert d["name"] == "Acme MCP"
    assert d["url"] == "https://acme.test/mcp"
    assert d["tool_version"] == __version__
    assert d["timestamp"]                       # non-empty ISO string
    assert "T" in d["timestamp"]


def test_to_dict_keeps_full_evidence():
    d = _report().to_dict()
    assert d["results"][0]["evidence"]["big"]


# --- thin to_summary_dict(): no evidence, only the essentials --------------

def test_summary_dict_drops_evidence():
    d = _report().to_summary_dict()
    for r in d["results"]:
        assert "evidence" not in r


def test_summary_dict_keeps_rubric_id_rating_title_method_detail():
    d = _report().to_summary_dict()
    r = d["results"][0]
    assert set(r) == {"rubric_id", "rating", "title", "method", "detail"}
    assert r["rubric_id"] == "CD-01"
    assert r["rating"] == "pass"
    assert r["title"] == "Title for CD-01"
    assert r["method"] == "Probe"
    assert r["detail"] == "detail for CD-01"


def test_summary_dict_keeps_server_identity_and_auth_failure():
    d = _report(auth_failure="DCR failed").to_summary_dict()
    assert d["name"] == "Acme MCP"
    assert d["url"] == "https://acme.test/mcp"
    assert d["auth_failure"] == "DCR failed"


def test_summary_dict_much_smaller_than_full_dict():
    report = _report()
    import json
    full_size = len(json.dumps(report.to_dict()))
    thin_size = len(json.dumps(report.to_summary_dict()))
    assert thin_size < full_size / 10


# --- CLI: auth-incomplete annotation on the stats line ----------------------

def test_plain_printer_flags_auth_incomplete_on_the_stats_line(capsys):
    from mcp_audit import cli
    cli._print_report_plain(_report(auth_failure="registration_endpoint missing"))
    out = capsys.readouterr().out
    stats_line = [l for l in out.splitlines() if "pass=" in l][0]
    assert "auth incomplete" in stats_line


def test_plain_printer_does_not_flag_when_auth_succeeded_or_unattempted(capsys):
    from mcp_audit import cli
    cli._print_report_plain(_report(auth_failure=None))
    out = capsys.readouterr().out
    stats_line = [l for l in out.splitlines() if "pass=" in l][0]
    assert "auth incomplete" not in stats_line
