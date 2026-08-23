from __future__ import annotations

import pytest

from deadletter import loads
from deadletter.intrinsics import name_from_arn, referenced_ids, resolve
from deadletter.model import Function, Kind, Queue
from deadletter.parse import load

from conftest import FIXTURES


@pytest.fixture
def template():
    return load(FIXTURES / "orders" / "template.yaml")


def test_short_form_intrinsics_survive(template):
    """!Ref and !GetAtt must resolve, or every cross-resource rule is blind."""
    queue = template.get("OrdersQueue")
    assert isinstance(queue, Queue)
    assert queue.redrive_target.logical_id == "OrdersDlq"


def test_globals_apply_when_function_is_silent(template):
    """Globals: Function: Timeout: 30 is how real templates set this."""
    notify = template.get("NotifyCustomerFunction")
    create = template.get("CreateOrderFunction")
    assert create.timeout == 30      # inherited from Globals
    assert notify.timeout == 10      # explicit property wins


def test_lambda_default_timeout_when_nothing_says(template):
    fn = loads(
        """
        Resources:
          Bare:
            Type: AWS::Lambda::Function
            Properties: {Handler: app.handler}
        """
    ).get("Bare")
    assert fn.timeout == 3
    assert fn.timeout_declared is False


def test_sam_sqs_event_becomes_an_event_source_mapping(template):
    esm = template.get("ProcessOrderFunction#FromQueue")
    assert esm is not None and esm.kind is Kind.ESM
    assert esm.synthetic is True
    assert esm.source.logical_id == "OrdersQueue"
    assert esm.target.logical_id == "ProcessOrderFunction"
    assert esm.batch_size == 10
    assert esm.batching_window == 10
    assert esm.reports_batch_item_failures is False


def test_handwritten_event_source_mapping_parses_the_same_way(template):
    esm = template.get("AnalyticsMapping")
    assert esm.source.logical_id == "OrderEventsStream"
    assert esm.target.logical_id == "AnalyticsFunction"
    assert esm.synthetic is False
    assert esm.bisect_on_error is False
    assert esm.maximum_retry_attempts is None


def test_sqs_visibility_timeout_and_its_default(template):
    assert template.get("OrdersQueue").visibility_timeout == 60
    assert template.get("OrdersDlq").visibility_timeout == 30  # AWS default


def test_subscription_and_rule_targets_resolve(template):
    subscription = template.get("NotifySubscription")
    assert subscription.topic.logical_id == "OrderEventsTopic"
    assert subscription.endpoint.logical_id == "NotifyCustomerFunction"

    rule = template.get("OrderPlacedRule")
    assert rule.bus.logical_id == "OrdersBus"
    assert resolve(rule.targets[0]["Arn"]).logical_id == "OrdersQueue"


def test_role_policies_are_reachable_for_iam_rules(template):
    role = template.get("AnalyticsRole")
    actions = [s.get("Action") for s in role.policy_statements]
    assert "kinesis:*" in actions


def test_json_templates_parse_too():
    template = loads(
        '{"Resources": {"Q": {"Type": "AWS::SQS::Queue", '
        '"Properties": {"VisibilityTimeout": 120}}}}'
    )
    assert template.get("Q").visibility_timeout == 120


def test_sub_and_arn_helpers():
    assert resolve({"Fn::Sub": "${OrdersQueue.Arn}"}).logical_id == "OrdersQueue"
    assert "AWS::Region" not in resolve({"Fn::Sub": "${AWS::Region}-${Bus}"}).logical_ids
    assert resolve({"Fn::ImportValue": "other-stack"}).unresolved is True
    assert name_from_arn("arn:aws:sqs:eu-west-1:123456789012:orders-queue") == "orders-queue"
    assert referenced_ids({"a": [{"Ref": "X"}, {"Fn::GetAtt": ["Y", "Arn"]}]}) == {"X", "Y"}
