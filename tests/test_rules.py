"""One test per BLOCK rule, plus the numbers each message must quote."""

from __future__ import annotations

from deadletter import build, load
from deadletter.findings import Severity
from deadletter.rules import all_rules, run

from conftest import FIXTURES, assert_rule


def test_five_block_rules_registered():
    ids = [r.id for r in all_rules()]
    assert ids == ["EDA001", "EDA002", "EDA003", "EDA004", "EDA005"]


def test_eda001_computes_the_required_minimum():
    finding = assert_rule("EDA001")[0]
    # 6 x 30s timeout + 10s batching window
    assert finding.evidence["required_minimum"] == 190
    assert "60s" in finding.message and "190s" in finding.message
    assert finding.severity is Severity.BLOCK
    assert "VisibilityTimeout: 190" in finding.patch_hint


def test_eda002_catches_both_the_queue_and_the_async_target():
    findings = assert_rule("EDA002", expected=2)
    named = {r for f in findings for r in f.resources}
    assert "InvoiceQueue" in named and "LedgerFunction" in named


def test_eda003_names_how_many_records_get_replayed():
    finding = assert_rule("EDA003")[0]
    assert finding.evidence["EDA003 BatchSize" if False else "ShipFunction#FromQueue.BatchSize"] == 10
    assert "up to 9 records" in finding.message


def test_eda004_blocks_an_unfiltered_loop():
    finding = assert_rule("EDA004")[0]
    assert finding.severity is Severity.BLOCK
    assert finding.evidence["hub"] == "AuditBus"
    assert finding.inferred is True


def test_eda004_downgrades_a_filtered_loop_rather_than_crying_wolf():
    """The orders workload has a real cycle, but the rule pattern filters on
    detail-type — unprovable, so WARN. A false BLOCK costs more than a miss."""
    findings = [f for f in run(build(load(FIXTURES / "orders" / "template.yaml"))) if f.rule_id == "EDA004"]
    assert findings and all(f.severity is Severity.WARN for f in findings)
    assert "detail-type" in findings[0].evidence["pattern_filters"]


def test_eda005_ignores_sqs_and_fires_on_streams():
    finding = assert_rule("EDA005")[0]
    assert finding.evidence["source_kind"] == "stream"
    assert "click-stream" in finding.message or "ClickStream" in finding.message


def test_orders_workload_produces_the_findings_the_example_report_needs(orders):
    findings = run(orders)
    by_rule = {f.rule_id for f in findings}
    assert {"EDA001", "EDA003", "EDA005"} <= by_rule
    assert all(f.evidence for f in findings)
    assert all(f.resources for f in findings)
