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
