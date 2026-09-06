"""Regression coverage for AWS representations seen in real templates."""

from __future__ import annotations

from deadletter import build, loads
from deadletter.model import Kind
from deadletter.rules import get_rule, run


def findings(rule_id: str, template: str):
    rule = get_rule(rule_id)
    assert rule is not None
    return list(rule.check(build(loads(template))))


def test_eda003_uses_the_sqs_default_batch_size_when_omitted():
    found = findings(
        "EDA003",
        """
        Resources:
          Queue:
            Type: AWS::SQS::Queue
          Consumer:
            Type: AWS::Serverless::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
              Events:
                Work:
                  Type: SQS
                  Properties:
                    Queue: !GetAtt Queue.Arn
        """,
    )

    assert len(found) == 1
    assert found[0].evidence["Consumer#Work.BatchSize"] == 10
    assert found[0].evidence["batch_size_declared"] is False


def test_eda002_accepts_an_sns_subscription_redrive_policy():
    found = findings(
        "EDA002",
        """
        Resources:
          Topic:
            Type: AWS::SNS::Topic
          DeliveryDlq:
            Type: AWS::SQS::Queue
          Consumer:
            Type: AWS::Lambda::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
          Subscription:
            Type: AWS::SNS::Subscription
            Properties:
              TopicArn: !Ref Topic
              Protocol: lambda
              Endpoint: !GetAtt Consumer.Arn
              RedrivePolicy:
                deadLetterTargetArn: !GetAtt DeliveryDlq.Arn
        """,
    )

    assert found and all(str(finding.verdict) != "BLOCK" for finding in found)


def test_eda002_accepts_native_lambda_event_invoke_config():
    found = findings(
        "EDA002",
        """
        Resources:
          Topic:
            Type: AWS::SNS::Topic
          DeliveryDlq:
            Type: AWS::SQS::Queue
          Consumer:
            Type: AWS::Lambda::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
          Subscription:
            Type: AWS::SNS::Subscription
            Properties:
              TopicArn: !Ref Topic
              Protocol: lambda
              Endpoint: !GetAtt Consumer.Arn
          AsyncFailureConfig:
            Type: AWS::Lambda::EventInvokeConfig
            Properties:
              FunctionName: !Ref Consumer
              Qualifier: live
              DestinationConfig:
                OnFailure:
                  Destination: !GetAtt DeliveryDlq.Arn
        """,
    )

    assert found and all(str(finding.verdict) != "BLOCK" for finding in found)


def test_eda002_treats_a_cross_stack_dlq_as_configured_not_absent():
    found = findings(
        "EDA002",
        """
        Resources:
          Queue:
            Type: AWS::SQS::Queue
            Properties:
              RedrivePolicy:
                deadLetterTargetArn:
                  Fn::ImportValue: shared-dlq-arn
                maxReceiveCount: 5
          Consumer:
            Type: AWS::Serverless::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
              Events:
                Work:
                  Type: SQS
                  Properties:
                    Queue: !GetAtt Queue.Arn
                    BatchSize: 1
        """,
    )

    assert found == []


def test_parameter_defaults_are_used_for_numeric_rule_inputs():
    graph = build(
        loads(
            """
            Parameters:
              FunctionTimeout:
                Type: Number
                Default: 60
              QueueVisibility:
                Type: Number
                Default: 30
            Resources:
              Queue:
                Type: AWS::SQS::Queue
                Properties:
                  VisibilityTimeout: !Ref QueueVisibility
              Consumer:
                Type: AWS::Serverless::Function
                Properties:
                  Handler: app.handler
                  Runtime: python3.12
                  Timeout: !Ref FunctionTimeout
                  Events:
                    Work:
                      Type: SQS
                      Properties:
                        Queue: !GetAtt Queue.Arn
                        BatchSize: 1
            """
        )
    )

    assert graph.node("Queue").visibility_timeout == 30
    assert graph.node("Consumer").timeout == 60
    found = list(get_rule("EDA001").check(graph))
    assert len(found) == 1
    assert found[0].evidence["recommended_minimum"] == 360


def test_unresolved_numeric_input_is_reported_as_uncertain_not_blocked():
    found = findings(
        "EDA001",
        """
        Parameters:
          FunctionTimeout:
            Type: Number
        Resources:
          Queue:
            Type: AWS::SQS::Queue
            Properties:
              VisibilityTimeout: 30
          Consumer:
            Type: AWS::Serverless::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
              Timeout: !Ref FunctionTimeout
              Events:
                Work:
                  Type: SQS
                  Properties:
                    Queue: !GetAtt Queue.Arn
                    BatchSize: 1
        """,
    )

    assert len(found) == 1
    assert str(found[0].verdict) == "WARN"
    assert "cannot verify" in found[0].message


def test_sam_globals_merge_nested_maps_and_prepend_lists():
    template = loads(
        """
        Globals:
          Function:
            Environment:
              Variables:
                STAGE: prod
                TABLE_NAME: global-table
            Policies:
              - AWSLambdaBasicExecutionRole
        Resources:
          Consumer:
            Type: AWS::Serverless::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
              Environment:
                Variables:
                  TABLE_NAME: local-table
                  FEATURE: enabled
              Policies:
                - AWSXRayDaemonWriteAccess
        """
    )

    function = template.get("Consumer")
    assert function.prop("Environment")["Variables"] == {
        "STAGE": "prod",
        "TABLE_NAME": "local-table",
        "FEATURE": "enabled",
    }
    assert function.prop("Policies") == ["AWSLambdaBasicExecutionRole", "AWSXRayDaemonWriteAccess"]


def test_anything_but_on_an_unknown_emitted_field_does_not_suppress_a_loop():
    found = findings(
        "EDA004",
        """
        Resources:
          AuditBus:
            Type: AWS::Events::EventBus
            Properties: {Name: audit}
          PublisherRole:
            Type: AWS::IAM::Role
            Properties:
              Policies:
                - PolicyName: publish
                  PolicyDocument:
                    Statement:
                      - Effect: Allow
                        Action: events:PutEvents
                        Resource: !GetAtt AuditBus.Arn
          Consumer:
            Type: AWS::Lambda::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
              Role: !GetAtt PublisherRole.Arn
          Route:
            Type: AWS::Events::Rule
            Properties:
              EventBusName: !Ref AuditBus
              EventPattern:
                detail:
                  status:
                    - anything-but: ignored-status
              Targets:
                - Id: consumer
                  Arn: !GetAtt Consumer.Arn
        """,
    )

    assert len(found) == 1
    assert str(found[0].verdict) == "WARN"


def test_iam_actions_and_resources_are_scoped_to_the_same_statement():
    graph = build(
        loads(
            """
            Resources:
              AllowedBus:
                Type: AWS::Events::EventBus
              MentionedBus:
                Type: AWS::Events::EventBus
              Role:
                Type: AWS::IAM::Role
                Properties:
                  Policies:
                    - PolicyName: mixed
                      PolicyDocument:
                        Statement:
                          - Effect: Allow
                            Action: events:PutEvents
                            Resource: !GetAtt AllowedBus.Arn
                          - Effect: Allow
                            Action: events:DescribeRule
                            Resource: !GetAtt MentionedBus.Arn
              Function:
                Type: AWS::Lambda::Function
                Properties:
                  Handler: app.handler
                  Runtime: python3.12
                  Role: !GetAtt Role.Arn
            """
        )
    )

    publishes = {(edge.source, edge.target) for edge in graph.edges("publish")}
    assert publishes == {("Function", "AllowedBus")}


def test_read_only_dynamodb_permission_is_not_a_write_edge():
    graph = build(
        loads(
            """
            Resources:
              Table:
                Type: AWS::DynamoDB::Table
              Function:
                Type: AWS::Lambda::Function
                Properties:
                  Handler: app.handler
                  Runtime: python3.12
                  Policies:
                    - Version: "2012-10-17"
                      Statement:
                        - Effect: Allow
                          Action: dynamodb:GetItem
                          Resource: !GetAtt Table.Arn
            """
        )
    )

    assert list(graph.edges("writes")) == []


def test_sns_publish_permissions_participate_in_loop_detection():
    found = findings(
        "EDA004",
        """
        Resources:
          Topic:
            Type: AWS::SNS::Topic
          Role:
            Type: AWS::IAM::Role
            Properties:
              Policies:
                - PolicyName: publish
                  PolicyDocument:
                    Statement:
                      - Effect: Allow
                        Action: sns:Publish
                        Resource: !Ref Topic
          Function:
            Type: AWS::Lambda::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
              Role: !GetAtt Role.Arn
          Subscription:
            Type: AWS::SNS::Subscription
            Properties:
              TopicArn: !Ref Topic
              Protocol: lambda
              Endpoint: !GetAtt Function.Arn
        """,
    )

    assert len(found) == 1
    assert str(found[0].verdict) == "WARN"
    assert found[0].inferred is True


def test_api_events_connect_to_their_function_regardless_of_event_name():
    graph = build(
        loads(
            """
            Resources:
              Api:
                Type: AWS::Serverless::HttpApi
              Function:
                Type: AWS::Serverless::Function
                Properties:
                  Handler: app.handler
                  Runtime: python3.12
                  Events:
                    CreateOrder:
                      Type: HttpApi
                      Properties:
                        ApiId: !Ref Api
                        Path: /orders
                        Method: POST
            """
        )
    )

    invokes = {(edge.source, edge.target, edge.via) for edge in graph.edges("invoke")}
    assert invokes == {("Api", "Function", "Function#CreateOrder")}


def test_fn_sub_variable_maps_resolve_the_underlying_resource():
    template = loads(
        """
        Resources:
          Queue:
            Type: AWS::SQS::Queue
          Function:
            Type: AWS::Lambda::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
          Mapping:
            Type: AWS::Lambda::EventSourceMapping
            Properties:
              EventSourceArn: !Sub
                - "${QueueArn}"
                - QueueArn: !GetAtt Queue.Arn
              FunctionName: !Ref Function
        """
    )

    graph = build(template)
    assert {(edge.source, edge.target) for edge in graph.edges("poll")} == {("Queue", "Function")}


def test_maximum_record_age_bounds_stream_blocking_but_requires_recovery():
    found = findings(
        "EDA005",
        """
        Resources:
          Stream:
            Type: AWS::Kinesis::Stream
          Consumer:
            Type: AWS::Lambda::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
          Mapping:
            Type: AWS::Lambda::EventSourceMapping
            Properties:
              EventSourceArn: !GetAtt Stream.Arn
              FunctionName: !Ref Consumer
              StartingPosition: LATEST
              MaximumRecordAgeInSeconds: 3600
        """,
    )

    assert len(found) == 1
    assert str(found[0].verdict) == "WARN"
    assert "discarded" in found[0].message


def test_false_resource_condition_removes_the_inactive_delivery_path():
    graph = build(
        loads(
            """
            Parameters:
              EnableConsumer:
                Type: String
                Default: "false"
            Conditions:
              ConsumerEnabled: !Equals [!Ref EnableConsumer, "true"]
            Resources:
              Queue:
                Type: AWS::SQS::Queue
              Consumer:
                Type: AWS::Serverless::Function
                Condition: ConsumerEnabled
                Properties:
                  Handler: app.handler
                  Runtime: python3.12
                  Events:
                    Work:
                      Type: SQS
                      Properties:
                        Queue: !GetAtt Queue.Arn
            """
        )
    )

    assert graph.template.get("Consumer") is None
    assert list(graph.edges("poll")) == []


def test_unknown_resource_condition_downgrades_a_block_to_warn():
    graph = build(
        loads(
            """
            Parameters:
              EnableConsumer:
                Type: String
            Conditions:
              ConsumerEnabled: !Equals [!Ref EnableConsumer, "true"]
            Resources:
              Queue:
                Type: AWS::SQS::Queue
                Properties:
                  VisibilityTimeout: 30
              Consumer:
                Type: AWS::Serverless::Function
                Condition: ConsumerEnabled
                Properties:
                  Handler: app.handler
                  Runtime: python3.12
                  Timeout: 60
                  Events:
                    Work:
                      Type: SQS
                      Properties:
                        Queue: !GetAtt Queue.Arn
                        BatchSize: 1
            """
        )
    )

    found = [finding for finding in run(graph) if finding.rule_id == "EDA001"]
    assert len(found) == 1
    assert str(found[0].verdict) == "WARN"
    assert "Consumer" in found[0].evidence["conditional_resources"]


def test_default_event_bus_is_represented_for_loop_detection():
    found = findings(
        "EDA004",
        """
        Resources:
          Consumer:
            Type: AWS::Serverless::Function
            Properties:
              Handler: app.handler
              Runtime: python3.12
              Policies:
                - EventBridgePutEventsPolicy:
                    EventBusName: default
          Route:
            Type: AWS::Events::Rule
            Properties:
              EventPattern: {}
              Targets:
                - Id: consumer
                  Arn: !GetAtt Consumer.Arn
        """,
    )

    assert len(found) == 1
    assert str(found[0].verdict) == "WARN"
    assert found[0].inferred is True


def test_source_aware_remediation_has_yaml_line_and_real_sam_path():
    template = """Resources:
  Queue:
    Type: AWS::SQS::Queue
  Consumer:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.handler
      Runtime: python3.12
      Events:
        Work:
          Type: SQS
          Properties:
            Queue: !GetAtt Queue.Arn
"""

    found = findings("EDA003", template)

    assert found[0].remediations[0].path == (
        "/Resources/Consumer/Properties/Events/Work/Properties/FunctionResponseTypes"
    )
    assert found[0].remediations[0].location.line == 12
