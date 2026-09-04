"""EDA007 — an unbounded consumer writing into a fixed capacity ceiling."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import EventSourceMapping, Function, Kind, Table
from .base import Rule, register, remediation


@register
class EDA007(Rule):
    id = "EDA007"
    severity = Severity.BLOCK
    title = "Unbounded consumer writes into a provisioned capacity ceiling"
    condition = "Any burst that scales the consumer past the table's write capacity."

    def check(self, graph):
        """Lambda scales to the account concurrency limit in seconds. A
        provisioned table does not. The write edge comes from IAM, so the
        finding is always marked inferred.
        """
        for edge in graph.edges("writes"):
            function = graph.node(edge.source)
            table = graph.node(edge.target)
            if not isinstance(function, Function) or not isinstance(table, Table):
                continue
            if not table.provisioned:
                continue  # on-demand absorbs the burst
            if graph.autoscaling_targets_on(table.logical_id):
                continue  # the ceiling is allowed to move

            if function.reserved_concurrency is not None:
                continue  # the consumer is capped account-side

            pollers = graph.in_edges(function.logical_id, "poll")
            async_invokers = graph.async_invokers_of(function.logical_id)
            if not pollers and not async_invokers:
                continue  # nothing in this template drives it

            uncapped: list[str] = []
            for poll in pollers:
                mapping = graph.template.get(poll.via)
                if isinstance(mapping, EventSourceMapping) and mapping.maximum_concurrency is None:
                    uncapped.append(mapping.logical_id)
            uncapped.extend(sorted({e.via or e.source for e in async_invokers}))
            if not uncapped:
                continue  # every source has a MaximumConcurrency

            capacity = table.write_capacity
            capacity_text = (
                f"{capacity} write capacity units" if capacity is not None else "fixed write capacity"
            )
            driver = ", ".join(sorted(uncapped))
            reserve_fix = remediation(
                graph,
                function,
                "ReservedConcurrentExecutions",
                description=(
                    "Cap the consumer with ReservedConcurrentExecutions sized to the table's "
                    "write capacity."
                ),
                suggested_value=capacity if capacity is not None else 10,
            )
            billing_fix = remediation(
                graph,
                table,
                "BillingMode",
                description=(
                    "Switch the table to PAY_PER_REQUEST, or attach an Application Auto Scaling "
                    "target so the ceiling can move with the load."
                ),
                suggested_value="PAY_PER_REQUEST",
            )
            yield Finding(
                rule_id=self.id,
                severity=self.severity,
                title=self.title,
                message=(
                    f"BLOCK: {function.logical_id} writes to {table.logical_id} with no "
                    f"ReservedConcurrentExecutions and is driven by {driver} with no concurrency "
                    f"ceiling, while {table.logical_id} is provisioned at {capacity_text} and has "
                    f"no scaling target. Required: a concurrency cap on the consumer, or capacity "
                    f"that moves with it. Consequence: a burst scales the consumer far past what "
                    f"the table accepts, so writes fail with ProvisionedThroughputExceededException "
                    f"and the events behind them are retried or dead-lettered."
                ),
                resources=[function.logical_id, table.logical_id, *sorted(uncapped)],
                evidence={
                    f"{function.logical_id}.ReservedConcurrentExecutions": None,
                    f"{table.logical_id}.BillingMode": table.billing_mode,
                    f"{table.logical_id}.ProvisionedThroughput.WriteCapacityUnits": capacity,
                    "uncapped_sources": sorted(uncapped),
                    "write_edge_basis": (edge.props or {}).get("basis", "iam-policy"),
                    "write_actions": (edge.props or {}).get("actions", []),
                },
                inferred=True,
                patch_hint=(
                    f"Set {reserve_fix.path}, or change {billing_fix.path} to PAY_PER_REQUEST."
                ),
                remediations=[reserve_fix, billing_fix],
            )
