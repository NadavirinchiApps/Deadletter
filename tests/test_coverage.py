"""A report has to state the scope it was produced from.

"No findings" reads as "your system is sound". It often means "the part that
matters was not visible to this scan". These tests hold the report to saying
which.
"""

from __future__ import annotations

import json

from deadletter import build, load
from deadletter.cli import main
from deadletter.coverage import COVERED_KINDS, collect
from deadletter.report import render_text

from conftest import FIXTURES

OPEN_STACK = """
AWSTemplateFormatVersion: "2010-09-09"
Transform: AWS::Serverless-2016-10-31
Parameters:
  HandlerTimeout:
    Type: Number
Resources:
  SharedQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: shared
      VisibilityTimeout: !ImportValue platform-visibility-timeout
      RedrivePolicy:
        deadLetterTargetArn: !ImportValue platform-dlq-arn
        maxReceiveCount: 5
  Worker:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.work
      Runtime: python3.12
      Timeout: !Ref HandlerTimeout
      Events:
        FromQueue:
          Type: SQS
          Properties:
            Queue: !GetAtt SharedQueue.Arn
            BatchSize: 1
  PublicTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: public
Outputs:
  TopicArn:
    Value: !Ref PublicTopic
    Export:
      Name: public-topic-arn
"""


def _coverage_for(path, rules=("EDA001",)):
    return collect([build(load(path))], rules_run=rules)


def test_a_clean_scan_still_reports_its_scope():
    """The failure mode this exists to prevent: a green report that is green
    because nothing was looked at."""
    coverage = _coverage_for(FIXTURES / "EDA004" / "passing.yaml", rules=("EDA004",))
    text = render_text([], coverage=coverage)

    assert text.startswith("No findings.")
    assert "Coverage:" in text
    assert "template(s)" in text and "resource(s)" in text


def test_a_complete_scan_says_so_explicitly(tmp_path):
    coverage = _coverage_for(FIXTURES / "EDA004" / "passing.yaml", rules=("EDA004",))
    assert coverage.complete
    assert coverage.limits() == []
    assert "Nothing limited this scan." in render_text([], coverage=coverage)


def test_cross_stack_imports_are_reported_as_unanalysed(tmp_path):
    path = tmp_path / "stack.yaml"
    path.write_text(OPEN_STACK, encoding="utf-8")

    coverage = _coverage_for(path)

    assert not coverage.complete
    assert any("SharedQueue.VisibilityTimeout" in ref for ref in coverage.cross_stack_imports)
    assert any("import" in limit for limit in coverage.limits())


def test_exports_are_reported_because_consumers_may_be_elsewhere(tmp_path):
    path = tmp_path / "stack.yaml"
    path.write_text(OPEN_STACK, encoding="utf-8")

    coverage = _coverage_for(path)

    assert any("PublicTopic" in ref for ref in coverage.cross_stack_exports)
    assert any("exported" in limit for limit in coverage.limits())


def test_unresolved_load_bearing_values_are_reported(tmp_path):
    """A parameter with no default means every check reading it was answered on
    a value nobody has."""
    path = tmp_path / "stack.yaml"
    path.write_text(OPEN_STACK, encoding="utf-8")

    coverage = _coverage_for(path)

    assert any("Worker.Timeout" in ref for ref in coverage.unresolved_values)
    assert any("could not be resolved" in limit for limit in coverage.limits())


def test_out_of_scope_infrastructure_next_to_the_templates_is_reported(tmp_path):
    """Terraform or synthesized CDK beside the templates usually means the event
    flow continues somewhere this scan cannot follow."""
    (tmp_path / "stack.yaml").write_text(OPEN_STACK, encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "aws_sqs_queue" "q" {}', encoding="utf-8")
    (tmp_path / "cdk.out").mkdir()
    (tmp_path / "cdk.out" / "App.template.json").write_text("{}", encoding="utf-8")

    coverage = collect(
        [build(load(tmp_path / "stack.yaml"))], rules_run=["EDA001"], roots=[tmp_path]
    )

    assert coverage.out_of_scope_infrastructure.get("Terraform") == 1
    assert coverage.out_of_scope_infrastructure.get("synthesized CDK output") == 1
    assert any("does not read" in limit for limit in coverage.limits())


def test_coverage_reaches_the_json_report(capsys, tmp_path):
    path = tmp_path / "stack.yaml"
    path.write_text(OPEN_STACK, encoding="utf-8")

    main([str(path), "--format", "json", "--fail-on", "none"])
    report = json.loads(capsys.readouterr().out)

    assert report["coverage"]["complete"] is False
    assert report["coverage"]["limits"]
    assert report["coverage"]["rules_run"]
    assert report["coverage"]["resources_by_kind"]


def test_every_covered_kind_is_reachable_by_a_rule():
    """COVERED_KINDS is a claim about the rule pack. If it drifts, the coverage
    report starts lying in the one direction that matters."""
    from deadletter.model import Kind

    assert COVERED_KINDS <= set(Kind)
    assert Kind.QUEUE in COVERED_KINDS and Kind.FUNCTION in COVERED_KINDS
