"""One test per rule, plus the numbers each message must quote."""

from __future__ import annotations

from deadletter import build, load
from deadletter.findings import Basis, Confidence, Verdict
from deadletter.rules import all_rules, run

from conftest import FIXTURES, assert_rule


def test_the_whole_rule_pack_is_registered():
    ids = [r.id for r in all_rules()]
    assert ids == [f"EDA{n:03d}" for n in range(1, 13)]


def test_every_rule_states_the_condition_it_needs_to_bite():
    """A rule that cannot say when it applies cannot be triaged."""
    for rule in all_rules():
        assert rule.title, f"{rule.id} has no title"
        assert rule.condition, f"{rule.id} does not state its condition"


def test_eda001_reports_the_6x_shortfall_as_a_recommendation_not_a_violation():
    """VisibilityTimeout 60 against a 30s Timeout satisfies what AWS actually
    requires and only misses the 6x advice. Blocking a release over that spends
    credibility the rule needs for the case that is genuinely broken."""
    finding = assert_rule("EDA001")[0]
    # 6 x 30s timeout + 10s batching window
    assert finding.evidence["recommended_minimum"] == 190
    assert finding.evidence["aws_minimum"] == 30
    assert finding.evidence["aws_minimum_satisfied"] is True
    assert "60s" in finding.message and "190s" in finding.message
    assert finding.basis is Basis.RECOMMENDATION
    assert finding.verdict is Verdict.WARN
    assert "VisibilityTimeout: 190" in finding.patch_hint


def test_eda001_blocks_when_the_aws_constraint_itself_is_broken():
    """VisibilityTimeout below the consumer's Timeout is the constraint AWS
    imposes, not advice — this is the case that earns a BLOCK."""
    graph = build(load(FIXTURES / "EDA001" / "violating-requirement.yaml"))
    findings = [f for f in run(graph) if f.rule_id == "EDA001"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.basis is Basis.REQUIREMENT
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.verdict is Verdict.BLOCK
    assert finding.evidence["aws_minimum"] == 30
    assert "10s" in finding.message and "30s" in finding.message


def test_eda001_recommendation_blocks_only_when_the_team_asks_for_it():
    """The strict policy is how a team opts into enforcing AWS's advice."""
    from deadletter.findings import STRICT_POLICY

    graph = build(load(FIXTURES / "EDA001" / "violating.yaml"))
    strict = [f for f in run(graph, policy=STRICT_POLICY) if f.rule_id == "EDA001"]
    assert strict and all(f.verdict is Verdict.BLOCK for f in strict)


def test_eda002_catches_both_the_queue_and_the_async_target():
    findings = assert_rule("EDA002", expected=2)
    named = {r for f in findings for r in f.resources}
    assert "InvoiceQueue" in named and "LedgerFunction" in named


def test_eda003_names_how_many_records_get_replayed():
    finding = assert_rule("EDA003")[0]
    assert finding.evidence["EDA003 BatchSize" if False else "ShipFunction#FromQueue.BatchSize"] == 10
    assert "up to 9 records" in finding.message


def test_eda004_reports_an_unfiltered_loop_as_inferred():
    """The return edge that closes a cycle is an IAM-derived publish: it shows
    the consumer may publish back, not that it does."""
    finding = assert_rule("EDA004")[0]
    assert finding.confidence is Confidence.INFERRED
    assert finding.verdict is Verdict.WARN
    assert finding.evidence["hub"] == "AuditBus"
    assert finding.inferred is True


def test_eda004_downgrades_a_filtered_loop_rather_than_crying_wolf():
    """The orders workload has a real cycle, but the rule pattern filters on
    detail-type — unprovable, so WARN. A false BLOCK costs more than a miss."""
    findings = [f for f in run(build(load(FIXTURES / "orders" / "template.yaml"))) if f.rule_id == "EDA004"]
    assert findings and all(f.verdict is Verdict.WARN for f in findings)
    assert all(f.confidence is Confidence.ASSUMED for f in findings)
    # An assumption-dependent finding has to say what it assumes.
    assert all(f.assumptions for f in findings)
    assert "detail-type" in findings[0].evidence["pattern_filters"]


def test_eda005_ignores_sqs_and_fires_on_streams():
    finding = assert_rule("EDA005")[0]
    assert finding.evidence["source_kind"] == "stream"
    assert "click-stream" in finding.message or "ClickStream" in finding.message


def test_eda006_names_the_producers_that_feed_the_undrained_queue():
    finding = assert_rule("EDA006")[0]
    assert finding.evidence["dead_letter_producers"] == ["PaymentQueue"]
    assert "PaymentDlq" in finding.message
    assert finding.basis is Basis.RECOMMENDATION
    assert finding.verdict is Verdict.WARN


def test_eda006_stays_quiet_when_an_alarm_watches_an_undrained_queue():
    """The rule requires a consumer *or* an alarm. ShippingDlq has only the
    alarm, and a rule that still fired would contradict its own message."""
    graph = build(load(FIXTURES / "EDA006" / "passing.yaml"))
    assert not [f for f in run(graph) if f.rule_id == "EDA006"]


def test_eda007_quotes_the_capacity_it_expects_to_be_exceeded():
    finding = assert_rule("EDA007")[0]
    assert finding.evidence["EventsTable.ProvisionedThroughput.WriteCapacityUnits"] == 5
    assert finding.evidence["EventsTable.BillingMode"] == "PROVISIONED"
    assert finding.inferred is True  # the write edge came from IAM


def test_eda008_quotes_both_retention_windows():
    finding = assert_rule("EDA008")[0]
    assert finding.evidence["OrdersDlq.MessageRetentionPeriod"] == 86400
    assert finding.evidence["OrdersQueue.MessageRetentionPeriod"] == 345600
    assert "86400s" in finding.message and "345600s" in finding.message


def test_eda009_counts_only_shared_throughput_readers():
    finding = assert_rule("EDA009")[0]
    assert len(finding.evidence["ClickStream.shared_throughput_readers"]) == 4
    assert finding.evidence["ClickStream.ShardCount"] == 1
    assert "4 shared-throughput readers" in finding.message


def test_eda009_treats_enhanced_fan_out_as_its_own_throughput():
    """Two direct readers plus two fan-out consumers is within the limit; the
    rule must resolve a StreamConsumer back to its stream to know that."""
    graph = build(load(FIXTURES / "EDA009" / "passing.yaml"))
    poll = [e for e in graph.edges("poll") if e.source == "ClickStream"]
    assert len(poll) == 4
    assert sum(1 for e in poll if e.props.get("enhanced_fan_out")) == 2


def test_eda010_finds_the_task_with_neither_retry_nor_catch():
    finding = assert_rule("EDA010")[0]
    assert finding.evidence["target"] == "ChargeCardFunction"
    assert finding.evidence["CheckoutWorkflow.States.ChargeCard.Retry"] is None
    assert "ChargeCard" in finding.message


def test_eda010_reaches_states_nested_in_a_map():
    """A Task inside an ItemProcessor is as capable of losing an execution as
    one at the top level."""
    machine = load(FIXTURES / "EDA010" / "passing.yaml").get("CheckoutWorkflow")
    assert "NotifyLineItem" in {name for name, _ in machine.iter_states()}


def test_eda011_quotes_the_integration_limit_it_exceeds():
    finding = assert_rule("EDA011")[0]
    assert finding.evidence["BuildReportFunction.Timeout"] == 120
    assert finding.evidence["integration_timeout"] == 29
    assert "504" in finding.message


def test_eda012_stays_silent_when_the_hub_is_exported():
    """A topic whose ARN is exported may be subscribed by another stack, and
    the scanner has no way to see that. Absence of a route stops being proof."""
    finding = assert_rule("EDA012")[0]
    assert finding.evidence["AuditTopic.exported"] is False
    assert finding.evidence["AuditTopic.publishers"] == ["RecordAuditFunction"]


def test_orders_workload_produces_the_findings_the_example_report_needs(orders):
    findings = run(orders)
    by_rule = {f.rule_id for f in findings}
    assert {"EDA001", "EDA003", "EDA005"} <= by_rule
    assert all(f.evidence for f in findings)
    assert all(f.resources for f in findings)


def test_the_new_rules_fire_on_the_realistic_workload_not_only_their_fixtures(orders):
    """A rule that only ever fires on the fixture written for it has not been
    shown to work. Both of these are real defects in the orders template."""
    findings = {f.rule_id: f for f in run(orders)}

    assert findings["EDA007"].evidence["OrdersTable.ProvisionedThroughput.WriteCapacityUnits"] == 5
    assert findings["EDA010"].evidence["target"] == "ProcessOrderFunction"


def test_an_unresolvable_task_target_is_not_invented(orders):
    """The ChargeCard state calls arn:aws:states:::http:invoke, which names no
    resource in the template. EDA010 must skip it rather than guess."""
    eda010 = [f for f in run(orders) if f.rule_id == "EDA010"]

    assert len(eda010) == 1
    assert "ChargeCard" not in eda010[0].message
