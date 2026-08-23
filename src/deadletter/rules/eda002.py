"""EDA002 — missing dead-letter path on a delivery that can fail."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import Function, Kind
from .base import Rule, register


@register
class EDA002(Rule):
    id = "EDA002"
    severity = Severity.BLOCK
    title = "No dead-letter path for a failing delivery"
    condition = "Any consumer failure that exhausts retries."

    def check(self, graph):
        yield from self._queues(graph)
        yield from self._async_targets(graph)

    def _queues(self, graph):
        """A polled queue with no RedrivePolicy retries the same message forever
        until it expires, then drops it silently."""
        for queue in graph.resources(Kind.QUEUE):
            consumers = graph.consumers_of(queue.logical_id)
            if not consumers or queue.redrive_target:
                continue
            names = ", ".join(fn.logical_id for _, fn in consumers)
            yield Finding(
                rule_id=self.id,
                severity=self.severity,
                title=self.title,
                message=(
                    f"BLOCK: {queue.logical_id} has no RedrivePolicy, while it is consumed by "
                    f"{names}. Required: a RedrivePolicy naming a dead-letter queue. "
                    f"Consequence: a message that always fails is retried until "
                    f"MessageRetentionPeriod expires and is then deleted with no record, "
                    f"while blocking throughput behind it."
                ),
                resources=[queue.logical_id, *(fn.logical_id for _, fn in consumers)],
                evidence={
                    f"{queue.logical_id}.RedrivePolicy": None,
                    f"{queue.logical_id}.MessageRetentionPeriod": queue.prop(
                        "MessageRetentionPeriod", default="unset (default 4 days)"
                    ),
                    "consumers": [fn.logical_id for _, fn in consumers],
                },
                patch_hint=(
                    f"  {queue.logical_id}:\n"
                    f"    Type: AWS::SQS::Queue\n"
                    f"    Properties:\n"
                    f"+     RedrivePolicy:\n"
                    f"+       deadLetterTargetArn: !GetAtt {queue.logical_id}Dlq.Arn\n"
                    f"+       maxReceiveCount: 5"
                ),
            )

    def _async_targets(self, graph):
        """Async invocation drops the event after its retries unless something
        catches it — either a bus-level DeadLetterConfig or a function-level
        destination."""
        for function in graph.resources(Kind.FUNCTION):
            if not isinstance(function, Function):
                continue
            for edge in graph.async_invokers_of(function.logical_id):
                bus_dlq = bool((edge.props or {}).get("dead_letter_config"))
                fn_dlq = bool(function.dead_letter_queue) or bool(function.on_failure)
                if bus_dlq or fn_dlq:
                    continue
                carrier = edge.via or edge.source
                yield Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"BLOCK: {carrier} delivers to {function.logical_id} asynchronously, "
                        f"while neither the target DeadLetterConfig nor the function's "
                        f"DeadLetterQueue/OnFailure destination is set. Required: one of the two. "
                        f"Consequence: after the retry budget is exhausted the event is "
                        f"discarded with no trace and no way to replay it."
                    ),
                    resources=[carrier, function.logical_id, edge.source],
                    evidence={
                        "delivery": f"{edge.source} --{edge.kind}--> {function.logical_id}",
                        f"{carrier}.Targets[].DeadLetterConfig": None,
                        f"{function.logical_id}.DeadLetterQueue": None,
                        f"{function.logical_id}.EventInvokeConfig.DestinationConfig.OnFailure": None,
                    },
                    patch_hint=(
                        f"  {function.logical_id}:\n"
                        f"    Properties:\n"
                        f"+     EventInvokeConfig:\n"
                        f"+       DestinationConfig:\n"
                        f"+         OnFailure:\n"
                        f"+           Destination: !GetAtt {function.logical_id}Dlq.Arn"
                    ),
                )
