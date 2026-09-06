"""Regressions for the findings that were not trustworthy.

Each test here is a counterexample an external reviewer built against the
scanner and got the wrong answer for. They are kept together because they share
a failure shape rather than a code path: in every case the scanner treated the
*existence* of a control as evidence the control works, or presented a
prediction with the confidence of a measurement.

A rule that blocks a release has to survive these. One bad block costs the
installation, and the installation is the product.
"""

from __future__ import annotations

from deadletter import build, load
from deadletter.findings import (
    ADVISORY_POLICY,
    DEFAULT_POLICY,
    STRICT_POLICY,
    Basis,
    Confidence,
    Impact,
    Verdict,
)
from deadletter.model import Kind
from deadletter.rules import run

from conftest import FIXTURES, graph_for


def _eda(rule_id: str, path, **kwargs):
    return [f for f in run(build(load(path)), **kwargs) if f.rule_id == rule_id]


# --------------------------------------------------------------------------
# EDA006: an alarm that names the queue but cannot tell anybody
# --------------------------------------------------------------------------

def test_an_alarm_that_cannot_notify_is_not_dlq_coverage():
    """Dimension matching alone accepted an alarm on an unrelated metric, with
    ActionsEnabled false and no AlarmActions. Three DLQs, three useless alarms,
    and the scan came back clean."""
    findings = _eda("EDA006", FIXTURES / "EDA006" / "degraded-alarm.yaml")
    queues = {r for f in findings for r in f.resources}

    assert len(findings) == 3
    assert {"WrongMetricDlq", "DisabledDlq", "NoActionDlq"} <= queues


def test_the_finding_names_the_alarm_and_why_it_cannot_fire():
    """"No alarm" and "an alarm somebody trusts that does nothing" are
    different problems, and the second is worse. The message has to say which."""
    findings = _eda("EDA006", FIXTURES / "EDA006" / "degraded-alarm.yaml")
    by_queue = {f.resources[0]: f for f in findings}

    wrong = by_queue["WrongMetricDlq"]
    assert "WrongMetricAlarm" in wrong.message
    assert "NumberOfEmptyReceives" in wrong.message
    assert wrong.evidence["alarms_that_can_notify"] == []
    assert "WrongMetricAlarm" in wrong.evidence["alarm_defects"]

    disabled = by_queue["DisabledDlq"]
    assert "ActionsEnabled" in disabled.message

    no_action = by_queue["NoActionDlq"]
    assert "notifies nobody" in no_action.message


def test_a_working_alarm_is_still_accepted():
    """The fix must not turn into "no alarm is ever good enough"."""
    assert not _eda("EDA006", FIXTURES / "EDA006" / "passing.yaml")


def test_a_high_alarm_threshold_is_reported_as_an_assumption_not_a_defect():
    """Whether a threshold is too high depends on message volume, which no
    template states. That makes it an assumption, and it must carry one."""
    findings = _eda("EDA006", FIXTURES / "EDA006" / "high-threshold.yaml")
    assert len(findings) == 1
    finding = findings[0]

    assert finding.confidence is Confidence.ASSUMED
    assert finding.verdict is not Verdict.BLOCK
    assert finding.assumptions and "5000" in finding.assumptions[0]
    assert finding.evidence["ShippingDlqDepthAlarm.Threshold"] == 5000


# --------------------------------------------------------------------------
# EDA007: a cap that exists but does not protect anything
# --------------------------------------------------------------------------

def test_a_concurrency_cap_far_above_the_table_capacity_still_fires():
    """ReservedConcurrentExecutions: 1000 against a 5-WCU table silenced the
    rule entirely. The cap existed; it protected nothing."""
    graph = graph_for("EDA007", "violating.yaml")
    template = graph.template
    function = next(
        r for r in template if r.cfn_type.endswith("Function") and "Ingest" in r.logical_id
    )
    function.props["ReservedConcurrentExecutions"] = 1000

    findings = [f for f in run(graph) if f.rule_id == "EDA007"]
    assert len(findings) == 1
    assert findings[0].evidence["concurrency_ceiling"] == 1000
    assert "1000" in findings[0].message


def test_a_cap_at_or_below_capacity_is_accepted():
    graph = graph_for("EDA007", "violating.yaml")
    capacity = next(
        r for r in graph.template if r.cfn_type == "AWS::DynamoDB::Table"
    ).write_capacity
    function = next(
        r for r in graph.template if r.cfn_type.endswith("Function") and "Ingest" in r.logical_id
    )
    function.props["ReservedConcurrentExecutions"] = capacity

    assert not [f for f in run(graph) if f.rule_id == "EDA007"]


def test_capacity_findings_state_their_workload_assumptions():
    """The scanner cannot know writes per event, item size or duration. It has
    to say so, or the reader cannot argue with the finding."""
    findings = _eda("EDA007", FIXTURES / "EDA007" / "violating.yaml")
    assert findings
    finding = findings[0]

    assert finding.confidence is Confidence.ASSUMED
    assert len(finding.assumptions) >= 3
    assert any("KB" in a for a in finding.assumptions)
    assert any("IAM policy" in a for a in finding.assumptions)
    # ASSUMED never blocks by default: the assumptions might not hold.
    assert finding.verdict is Verdict.WARN


def test_an_autoscaling_target_no_longer_silences_the_rule():
    """Autoscaling reacts over minutes and stops at MaxCapacity, so it does not
    absorb a burst that arrives in seconds. It belongs in the assumptions, not
    in an early return."""
    findings = _eda("EDA007", FIXTURES / "EDA007" / "autoscaled.yaml")
    assert findings
    assert any("Auto Scaling" in a for a in findings[0].assumptions)
    assert findings[0].evidence["autoscaling_targets"]


# --------------------------------------------------------------------------
# EDA012: an export is not proof of anything
# --------------------------------------------------------------------------

def test_the_unrouted_hub_message_does_not_claim_nothing_can_reach_it():
    """A subscription in another stack can use the topic ARN directly; no
    CloudFormation export is required. The old message asserted the opposite."""
    findings = _eda("EDA012", FIXTURES / "EDA012" / "violating.yaml")
    assert findings
    message = findings[0].message

    assert "nothing outside this template can reach it" not in message
    assert "subscribes using the ARN directly" in message
    assert findings[0].evidence["external_subscribers_visible_to_this_scan"] is False


def test_a_publish_edge_from_iam_is_not_confirmed_behaviour():
    """Permission establishes capability. It does not establish that the
    application publishes, so this cannot block on its own."""
    findings = _eda("EDA012", FIXTURES / "EDA012" / "violating.yaml")
    assert findings
    assert findings[0].confidence is Confidence.INFERRED
    assert findings[0].verdict is Verdict.WARN


# --------------------------------------------------------------------------
# Blocking on a value the author never wrote
#
# From a scan of 683 templates in aws-samples/serverless-patterns,
# aws/aws-sam-cli-app-templates and aws-serverless-ecommerce-platform: 63 of
# 160 blocks rested on an AWS default nobody had typed. The analysis was right
# — the deployed system really behaves that way — but an engineer who opens the
# file, finds nothing matching the finding, and concludes the tool is wrong is
# an engineer who uninstalls it. See docs/field-scan.md.
# --------------------------------------------------------------------------

def test_an_inherited_default_does_not_stop_a_build():
    """EDA003 fired on a DynamoDB stream consumer whose BatchSize of 100 came
    from AWS, not the template, and blocked the release over it."""
    graph = graph_for("EDA003", "violating.yaml")
    esm = next(r for r in graph.template if r.kind is Kind.ESM)
    esm.props.pop("BatchSize", None)
    if esm.raw_props is not None:
        esm.raw_props.pop("BatchSize", None)

    findings = [f for f in run(graph) if f.rule_id == "EDA003"]
    assert findings, "the defect is still real; it just must not block"
    finding = findings[0]

    assert finding.defaults_relied_on
    assert finding.verdict is not Verdict.BLOCK
    assert "unset, so AWS applies its default" in finding.message


def test_a_value_the_author_wrote_still_blocks_under_strict():
    """The finding does not disappear — a team can still choose to enforce it."""
    graph = graph_for("EDA003", "violating.yaml")
    strict = [f for f in run(graph, policy=STRICT_POLICY) if f.rule_id == "EDA003"]
    assert strict and all(f.verdict is Verdict.BLOCK for f in strict)


def test_the_report_says_which_values_it_inherited():
    """So nobody goes looking in the template for a line that was never there."""
    from deadletter.report import render_text

    finding = _stub(defaults_relied_on=["Q.VisibilityTimeout"])
    finding.verdict = Verdict.WARN
    text = render_text([finding])
    assert "rests on AWS defaults you did not set" in text
    assert "Q.VisibilityTimeout" in text


def test_only_the_decisive_side_of_a_comparison_counts_as_inherited():
    """EDA008 compares two retentions. If the author wrote a short one on the
    dead-letter queue, the source sitting at its AWS default does not excuse
    it — over-crediting defaults silences findings that should block."""
    findings = _eda("EDA008", FIXTURES / "EDA008" / "violating.yaml")
    assert findings
    assert findings[0].defaults_relied_on == []
    assert findings[0].verdict is Verdict.BLOCK


# --------------------------------------------------------------------------
# EDA011: a timeout is a ceiling, not a duration
# --------------------------------------------------------------------------

def test_a_timeout_ceiling_is_not_evidence_the_handler_runs_that_long():
    """50 blocks in the field scan, 19 of them a one-second overshoot. Timeout
    is the longest the handler *may* run, not how long it does."""
    findings = _eda("EDA011", FIXTURES / "EDA011" / "violating.yaml")
    assert findings
    finding = findings[0]

    assert finding.confidence is Confidence.ASSUMED
    assert finding.verdict is not Verdict.BLOCK
    assert any("ceiling, not a duration" in a for a in finding.assumptions)
    assert finding.evidence["seconds_beyond_integration_timeout"] > 0


# --------------------------------------------------------------------------
# EDA005: do not demand what is already configured
# --------------------------------------------------------------------------

def test_no_demand_for_an_on_failure_destination_that_already_exists():
    """The unbounded retry is the defect. Asking for a destination the reader
    can see in front of them discredits the rest of the finding."""
    graph = graph_for("EDA005", "violating.yaml")
    esm = next(r for r in graph.template if r.kind is Kind.ESM)
    esm.props["DestinationConfig"] = {"OnFailure": {"Destination": "arn:aws:sqs:::already-there"}}

    findings = [f for f in run(graph) if f.rule_id == "EDA005"]
    assert findings, "unbounded retries are still a defect"
    finding = findings[0]

    assert "plus an OnFailure destination" not in finding.message
    assert "already set" in finding.message
    assert all("OnFailure" not in fix.path for fix in finding.remediations)


# --------------------------------------------------------------------------
# The axes themselves
# --------------------------------------------------------------------------

def test_policy_decides_the_verdict_and_rules_never_do():
    """The same finding is a block, a warning or a note depending only on the
    policy the customer chose."""
    path = FIXTURES / "EDA001" / "violating.yaml"  # below the 6x recommendation

    assert all(f.verdict is Verdict.WARN for f in _eda("EDA001", path))
    assert all(
        f.verdict is Verdict.BLOCK for f in _eda("EDA001", path, policy=STRICT_POLICY)
    )
    assert all(
        f.verdict is not Verdict.BLOCK
        for f in _eda("EDA001", path, policy=ADVISORY_POLICY)
    )


def test_only_confirmed_requirement_findings_block_by_default():
    """The default policy's whole job: a severe possible outcome does not make
    the evidence certain, and advice is not a violation."""
    for confidence in Confidence:
        for basis in Basis:
            for impact in Impact:
                blocks = DEFAULT_POLICY.verdict(
                    _stub(impact=impact, confidence=confidence, basis=basis)
                ) is Verdict.BLOCK
                expected = (
                    confidence is Confidence.CONFIRMED
                    and basis is Basis.REQUIREMENT
                    and impact is not Impact.DEGRADED
                )
                assert blocks is expected, (impact, confidence, basis)


def test_an_assumed_finding_must_carry_its_assumptions():
    """Enforced at construction: a risk whose assumptions are not stated cannot
    be argued with, and so cannot be trusted."""
    import pytest

    with pytest.raises(ValueError, match="assumptions"):
        _stub(confidence=Confidence.ASSUMED, assumptions=[])


def test_a_rule_cannot_hardcode_a_verdict_into_its_message():
    """Messages used to start with "BLOCK:", which meant the verdict was baked
    in before policy ran."""
    import pytest

    with pytest.raises(ValueError, match="verdict"):
        _stub(message="BLOCK: something is wrong")


def test_no_shipped_rule_hardcodes_a_verdict_prefix():
    for path in (FIXTURES.parent.parent / "src" / "deadletter" / "rules").glob("eda0*.py"):
        text = path.read_text(encoding="utf-8")
        for prefix in ('f"BLOCK: ', 'f"WARN: ', '"BLOCK: ', '"WARN: '):
            assert prefix not in text, f"{path.name} hardcodes {prefix!r}"


def _stub(**kwargs):
    from deadletter.findings import Finding

    defaults = dict(
        rule_id="TEST",
        title="t",
        message="a thing is inconsistent with another thing",
        impact=Impact.LOSS,
        confidence=Confidence.CONFIRMED,
        basis=Basis.REQUIREMENT,
        resources=["A"],
        evidence={"A.Prop": 1},
    )
    defaults.update(kwargs)
    if defaults["confidence"] is Confidence.ASSUMED and "assumptions" not in kwargs:
        defaults["assumptions"] = ["a stated workload assumption"]
    return Finding(**defaults)
