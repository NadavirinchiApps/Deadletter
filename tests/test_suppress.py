"""Suppression is an escape hatch, not a way to hide.

Every test here is about the second half of that sentence: an entry only takes
effect when it is complete, current, and explained, and what it waives stays
visible in the report either way.
"""

from __future__ import annotations

import json
from datetime import date

from deadletter import build, load
from deadletter.cli import main
from deadletter.report import render_sarif, render_text, summary
from deadletter.rules import run
from deadletter.suppress import collect

from conftest import FIXTURES

TEMPLATE = FIXTURES / "suppression" / "template.yaml"
TODAY = date(2026, 9, 4)


def findings_for(rule_id: str = "EDA001"):
    graph = build(load(TEMPLATE))
    return [f for f in run(graph, [rule_id], today=TODAY) if f.rule_id == rule_id]


def test_a_complete_and_current_suppression_is_honoured():
    suppressed = [f for f in findings_for() if f.suppressed]

    assert [f.resources[0] for f in suppressed] == ["OrdersQueue"]
    assert "ADR-114" in suppressed[0].suppression


def test_an_expired_suppression_lets_the_finding_come_back():
    """The point of an expiry date is that it arrives."""
    shipping = [f for f in findings_for() if "ShippingQueue" in f.resources]

    assert shipping and not shipping[0].suppressed


def test_a_suppression_without_a_reason_is_not_applied():
    billing = [f for f in findings_for() if "BillingQueue" in f.resources]

    assert billing and not billing[0].suppressed


def test_an_unreadable_expiry_is_not_treated_as_no_expiry():
    """Failing open here would turn a typo into a permanent waiver."""
    audit = [f for f in findings_for() if "AuditQueue" in f.resources]

    assert audit and not audit[0].suppressed


def test_the_malformed_entries_are_reported_rather_than_swallowed():
    _, problems = collect(load(TEMPLATE))

    assert len(problems) == 2
    assert any("BillingQueue" in p and "no reason" in p for p in problems)
    assert any("AuditQueue" in p and "expires" in p for p in problems)


def test_suppressed_findings_are_counted_separately_not_deleted():
    findings = findings_for()
    counts = summary(findings)

    assert counts["suppressed"] == 1
    assert counts["BLOCK"] == 3
    assert len(findings) == 4  # nothing was dropped


def test_text_output_hides_suppressed_findings_but_says_how_many():
    findings = findings_for()

    hidden = render_text(findings)
    shown = render_text(findings, show_suppressed=True)

    assert "OrdersQueue" not in hidden
    assert "1 suppressed finding hidden" in hidden
    assert "SUPPRESSED" in shown and "ADR-114" in shown


def test_sarif_marks_suppression_natively_so_code_scanning_greys_it_out():
    report = json.loads(render_sarif(findings_for()))
    results = report["runs"][0]["results"]

    suppressed = [r for r in results if "suppressions" in r]
    assert len(suppressed) == 1
    assert suppressed[0]["suppressions"][0]["kind"] == "inSource"
    assert "ADR-114" in suppressed[0]["suppressions"][0]["justification"]


def test_a_suppressed_finding_does_not_fail_the_build(capsys):
    """The whole point: the gate stays in the pipeline."""
    exit_code = main([str(TEMPLATE), "--rule", "EDA001", "--format", "json"])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 1  # three unsuppressed findings still block
    assert report["summary"]["suppressed"] == 1


def test_malformed_suppressions_warn_on_stderr(capsys):
    main([str(TEMPLATE), "--rule", "EDA001", "--fail-on", "none"])

    stderr = capsys.readouterr().err
    assert "WARNING" in stderr
    assert "BillingQueue" in stderr and "AuditQueue" in stderr
