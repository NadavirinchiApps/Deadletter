from __future__ import annotations

from deadletter import loads
from deadletter.graph import build
from deadletter.model import Function, Kind


def edge_set(graph, kind=None):
    return {(e.source, e.target) for e in graph.edges(kind)}


def test_rule_to_queue_to_function_is_one_connected_path(orders):
    """The whole product rests on this path existing across three resources."""
    assert ("OrdersBus", "OrdersQueue") in edge_set(orders, "rule_target")
    assert ("OrdersQueue", "ProcessOrderFunction") in edge_set(orders, "poll")


def test_consumers_of_pairs_a_queue_with_its_consumer(orders):
    consumers = orders.consumers_of("OrdersQueue")
    assert len(consumers) == 1
    esm, function = consumers[0]
    assert function.logical_id == "ProcessOrderFunction"
    # EDA001 will compare exactly these three numbers.
    assert (function.timeout, esm.batching_window, orders.node("OrdersQueue").visibility_timeout) == (30, 10, 60)


def test_redrive_edge_marks_the_dead_letter_queue(orders):
    assert ("OrdersQueue", "OrdersDlq") in edge_set(orders, "redrive")
    assert orders.has_failure_path("OrdersQueue") is True


def test_stream_to_function_edge(orders):
    assert ("OrderEventsStream", "AnalyticsFunction") in edge_set(orders, "poll")


def test_sns_subscription_edge(orders):
    assert ("OrderEventsTopic", "NotifyCustomerFunction") in edge_set(orders, "subscribe")


def test_write_edges_are_inferred_from_policies(orders):
    """EDA007 needs to know which functions write to a provisioned table."""
    writes = edge_set(orders, "writes")
    assert ("ProcessOrderFunction", "OrdersTable") in writes
    assert ("AnalyticsFunction", "OrdersTable") in writes
    assert all(e.inferred for e in orders.edges("writes"))


def test_publish_edge_needs_putevents_permission(orders):
    """EDA004's loop detection depends on knowing who can publish back to a bus."""
    publishes = edge_set(orders, "publish")
    assert ("ProcessOrderFunction", "OrdersBus") in publishes
    assert ("NotifyCustomerFunction", "OrdersBus") not in publishes


def test_async_invokers_of_a_function(orders):
    invokers = orders.async_invokers_of("NotifyCustomerFunction")
    assert [e.kind for e in invokers] == ["subscribe"]


def test_cross_stack_references_are_dropped_not_guessed():
    """An imported queue has no node, so no half-edge may appear."""
    graph = build(
        loads(
            """
            Resources:
              Consumer:
                Type: AWS::Lambda::Function
                Properties: {Handler: app.handler}
              Mapping:
                Type: AWS::Lambda::EventSourceMapping
                Properties:
                  EventSourceArn: {"Fn::ImportValue": shared-queue-arn}
                  FunctionName: {Ref: Consumer}
            """
        )
    )
    assert not edge_set(graph, "poll")


def test_mermaid_renders_every_connected_resource(orders):
    diagram = orders.to_mermaid()
    assert diagram.startswith("graph LR")
    assert "OrdersQueue" in diagram and "poll" in diagram


def test_env_var_mention_alone_is_not_a_write_edge(orders):
    """Globals hands ORDERS_TABLE to every function; only permission proves a write."""
    writes = edge_set(orders, "writes")
    assert ("NotifyCustomerFunction", "OrdersTable") not in writes
    assert all(e.props.get("basis") == "iam-policy" for e in orders.edges("writes"))


# --------------------------------------------------------------------------
# IAM written as its own resource
#
# CDK emits every grant as a separate AWS::IAM::Policy, so a graph that reads
# only inline `Policies` sees a role with no permissions and builds no edges.
# --------------------------------------------------------------------------

CDK_SHAPED = """
Resources:
  OrdersBus:
    Type: AWS::Events::EventBus
    Properties: {Name: orders}
  HandlerServiceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - {Action: sts:AssumeRole, Effect: Allow, Principal: {Service: lambda.amazonaws.com}}
  HandlerServiceRoleDefaultPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Action: events:PutEvents
            Effect: Allow
            Resource: {"Fn::GetAtt": [OrdersBus, Arn]}
      PolicyName: HandlerServiceRoleDefaultPolicy
      Roles: [{Ref: HandlerServiceRole}]
  Handler:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: {"Fn::GetAtt": [HandlerServiceRole, Arn]}
"""


def test_a_policy_resource_attached_by_ref_produces_the_publish_edge():
    graph = build(loads(CDK_SHAPED))
    assert ("Handler", "OrdersBus") in edge_set(graph, "publish")


def test_the_policy_edge_names_the_resource_its_statements_came_from():
    """A reader has to be able to open the policy the edge was derived from."""
    graph = build(loads(CDK_SHAPED))
    edge = next(iter(graph.edges("publish")))
    assert edge.inferred is True
    assert edge.props["policy_source"] == "iam-policy-resource:HandlerServiceRoleDefaultPolicy"
    assert graph.policy_resources_read == {"HandlerServiceRoleDefaultPolicy"}


def test_a_managed_policy_attached_by_literal_role_name_also_counts():
    """`Roles` may carry a hardcoded RoleName rather than a Ref."""
    graph = build(
        loads(
            """
            Resources:
              OrdersTable:
                Type: AWS::DynamoDB::Table
                Properties: {TableName: orders}
              WorkerRole:
                Type: AWS::IAM::Role
                Properties: {RoleName: worker-role}
              WorkerWrites:
                Type: AWS::IAM::ManagedPolicy
                Properties:
                  Roles: [worker-role]
                  PolicyDocument:
                    Statement:
                      - Action: [dynamodb:PutItem]
                        Effect: Allow
                        Resource: {"Fn::GetAtt": [OrdersTable, Arn]}
              Worker:
                Type: AWS::Lambda::Function
                Properties:
                  Handler: app.handler
                  Role: {"Fn::GetAtt": [WorkerRole, Arn]}
            """
        )
    )
    assert ("Worker", "OrdersTable") in edge_set(graph, "writes")


def test_a_role_outside_the_template_is_recorded_rather_than_ignored():
    """No edges can be derived from a role this scan cannot read. Saying so is
    the difference between "checked" and "did not look"."""
    graph = build(
        loads(
            """
            Resources:
              Worker:
                Type: AWS::Lambda::Function
                Properties:
                  Handler: app.handler
                  Role: {"Fn::ImportValue": platform-worker-role-arn}
            """
        )
    )
    assert "Worker" in graph.unresolved_roles


def test_a_policy_attached_to_another_role_grants_this_function_nothing():
    """Matching any policy in the template would invent permissions."""
    graph = build(
        loads(
            """
            Resources:
              OrdersBus:
                Type: AWS::Events::EventBus
                Properties: {Name: orders}
              WorkerRole:
                Type: AWS::IAM::Role
                Properties: {}
              OtherRole:
                Type: AWS::IAM::Role
                Properties: {}
              OtherPolicy:
                Type: AWS::IAM::Policy
                Properties:
                  Roles: [{Ref: OtherRole}]
                  PolicyDocument:
                    Statement:
                      - {Action: events:PutEvents, Effect: Allow, Resource: {"Fn::GetAtt": [OrdersBus, Arn]}}
              Worker:
                Type: AWS::Lambda::Function
                Properties:
                  Handler: app.handler
                  Role: {"Fn::GetAtt": [WorkerRole, Arn]}
            """
        )
    )
    assert not edge_set(graph, "publish")
