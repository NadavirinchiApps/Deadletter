"""EDA007 — a consumer whose concurrency ceiling outruns a table's write capacity."""

from __future__ import annotations

from ..findings import Basis, Confidence, Finding, Impact
from ..model import EventSourceMapping, Function, Table
from .base import Rule, register, remediation

# What the scanner has to guess to say anything at all about capacity. Stated on
# every finding, because a reader who disagrees with these numbers needs to be
# able to see them and dismiss the finding on the spot.
ASSUMED_WRITES_PER_INVOCATION = 1
ASSUMED_ITEM_SIZE_KB = 1


@register
class EDA007(Rule):
    id = "EDA007"
    impact = Impact.STALL
    title = "Consumer concurrency exceeds the table's write capacity"
    condition = "Any burst that scales the consumer past the table's write capacity."

    def check(self, graph):
        """Lambda scales to its concurrency limit in seconds. A provisioned
        table does not.

        This rule cannot know the true write rate — that needs traffic, handler
        duration, writes per event and item size, none of which a template
        states. So it makes the one comparison it can defend, between the
        consumer's concurrency ceiling and the table's write ceiling, and
        publishes the assumptions that comparison rests on. It never claims a
        capacity figure is correct, only that two numbers are inconsistent under
        conditions the reader can check.

        The bug this replaced treated any ReservedConcurrentExecutions as
        protection: a cap of 1000 against a 5-WCU table silenced the finding.
        An autoscaling target silenced it too, though scaling reacts over
        minutes and stops at MaxCapacity.
        """
        for edge in graph.edges("writes"):
            function = graph.node(edge.source)
            table = graph.node(edge.target)
            if not isinstance(function, Function) or not isinstance(table, Table):
                continue
            if not table.provisioned:
                continue  # on-demand absorbs the burst

            pollers = graph.in_edges(function.logical_id, "poll")
            async_invokers = graph.async_invokers_of(function.logical_id)
            if not pollers and not async_invokers:
                continue  # nothing in this template drives it

            capacity = table.write_capacity
            ceiling, ceiling_source = self._concurrency_ceiling(
                graph, function, pollers, async_invokers
            )

            # A ceiling at or below the table's WCU cannot overrun it under the
            # stated assumptions, so there is nothing to report.
            if capacity is not None and ceiling is not None and ceiling <= capacity:
                continue

            scaling = graph.autoscaling_targets_on(table.logical_id)
            yield self._finding(
                graph, function, table, capacity, ceiling, ceiling_source, scaling
            )

    def _concurrency_ceiling(self, graph, function, pollers, async_invokers):
        """The most concurrent invocations this template allows, and where it comes from.

        None means unbounded: no reserved concurrency and at least one source
        with no ceiling of its own.
        """
        reserved = function.reserved_concurrency
        uncapped: list[str] = []
        source_caps: list[int] = []
        for poll in pollers:
            mapping = graph.template.get(poll.via)
            if not isinstance(mapping, EventSourceMapping):
                continue
            if mapping.maximum_concurrency is None:
                uncapped.append(mapping.logical_id)
            else:
                source_caps.append(mapping.maximum_concurrency)
        uncapped.extend(sorted({e.via or e.source for e in async_invokers}))

        if reserved is not None:
            # Reserved concurrency binds whatever drives the function.
            if source_caps and not uncapped:
                return min(reserved, sum(source_caps)), (
                    f"ReservedConcurrentExecutions ({reserved}) and the event source "
                    f"maximum concurrency"
                )
            return reserved, f"ReservedConcurrentExecutions ({reserved})"
        if uncapped:
            return None, ", ".join(sorted(uncapped)) + " with no concurrency ceiling"
        if source_caps:
            return sum(source_caps), "the event source MaximumConcurrency settings"
        return None, "the account concurrency limit"

    def _finding(self, graph, function, table, capacity, ceiling, ceiling_source, scaling):
        capacity_text = (
            f"{capacity} write capacity units" if capacity is not None else "fixed write capacity"
        )
        if ceiling is None:
            ceiling_text = "has no concurrency ceiling"
            overrun = "a burst scales the consumer far past what the table accepts"
        else:
            ceiling_text = f"can reach {ceiling} concurrent executions"
            overrun = (
                f"{ceiling} concurrent executions can demand roughly {ceiling} writes per "
                f"second against {capacity_text}"
                if capacity is not None
                else f"{ceiling} concurrent executions can outrun a fixed ceiling"
            )

        assumptions = [
            f"Each invocation performs about {ASSUMED_WRITES_PER_INVOCATION} write of up "
            f"to {ASSUMED_ITEM_SIZE_KB} KB, so one concurrent execution consumes roughly "
            f"one write capacity unit per second.",
            "Invocations are sustained rather than brief, so concurrency approximates the "
            "simultaneous write rate.",
            f"The write edge to {table.logical_id} comes from an IAM policy, which shows "
            f"{function.logical_id} may write to it — not that it does on every invocation.",
        ]
        if scaling:
            names = ", ".join(sorted(target.logical_id for target in scaling))
            assumptions.append(
                f"{names} can raise the ceiling, but Application Auto Scaling reacts over "
                f"minutes and stops at its MaxCapacity, so it does not absorb a burst that "
                f"arrives in seconds."
            )
            scaling_text = f", and {names} can raise the ceiling only over minutes"
        else:
            scaling_text = " and has no scaling target"

        reserve_fix = remediation(
            graph,
            function,
            "ReservedConcurrentExecutions",
            description=(
                "Cap the consumer with ReservedConcurrentExecutions sized to the table's "
                "write capacity"
                + (f" ({capacity})." if capacity is not None else ".")
            ),
            suggested_value=capacity if capacity is not None else 10,
        )
        billing_fix = remediation(
            graph,
            table,
            "BillingMode",
            description=(
                "Switch the table to PAY_PER_REQUEST so the ceiling moves with the load."
            ),
            suggested_value="PAY_PER_REQUEST",
        )
        return Finding(
            rule_id=self.id,
            impact=self.impact,
            basis=Basis.RECOMMENDATION,
            confidence=Confidence.ASSUMED,
            assumptions=assumptions,
            title=self.title,
            message=(
                f"{function.logical_id} writes to {table.logical_id} and {ceiling_text} "
                f"— bounded by {ceiling_source} — while {table.logical_id} is provisioned "
                f"at {capacity_text}{scaling_text}. Required: a concurrency ceiling at or "
                f"below the table's write capacity, or capacity that moves with the "
                f"consumer. Consequence: under the assumptions below, {overrun}, so writes "
                f"fail with ProvisionedThroughputExceededException and the events behind "
                f"them are retried or dead-lettered."
            ),
            resources=[function.logical_id, table.logical_id],
            evidence={
                f"{function.logical_id}.ReservedConcurrentExecutions": (
                    function.reserved_concurrency
                ),
                f"{table.logical_id}.BillingMode": table.billing_mode,
                f"{table.logical_id}.ProvisionedThroughput.WriteCapacityUnits": capacity,
                "concurrency_ceiling": ceiling,
                "concurrency_ceiling_source": ceiling_source,
                "autoscaling_targets": sorted(target.logical_id for target in scaling),
                "assumed_writes_per_invocation": ASSUMED_WRITES_PER_INVOCATION,
                "assumed_item_size_kb": ASSUMED_ITEM_SIZE_KB,
            },
            patch_hint=(
                f"Set {reserve_fix.path} to {capacity if capacity is not None else 10}, "
                f"or change {billing_fix.path} to PAY_PER_REQUEST."
            ),
            remediations=[reserve_fix, billing_fix],
        )
