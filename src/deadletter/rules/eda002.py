"""EDA002 — missing dead-letter path on a delivery that can fail."""

from __future__ import annotations

from ..findings import Basis, Confidence, Finding, Impact
from ..model import Function, Kind
from .base import Rule, register, remediation


@register
class EDA002(Rule):
    id = "EDA002"
    impact = Impact.LOSS
    basis = Basis.RECOMMENDATION
    title = "Incomplete dead-letter coverage for a failing delivery"
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
            fix = remediation(
                graph,
                queue,
                "RedrivePolicy",
                description="Configure an SQS dead-letter queue and a finite maxReceiveCount.",
                suggested_value={
                    "deadLetterTargetArn": {"Fn::GetAtt": [f"{queue.logical_id}Dlq", "Arn"]},
                    "maxReceiveCount": 5,
                },
            )
            yield Finding(
                rule_id=self.id,
                impact=self.impact,
                                basis=self.basis,
                                title=self.title,
                message=(
                    f"{queue.logical_id} has no RedrivePolicy, while it is consumed by "
                    f"{names}. Required: a RedrivePolicy naming a dead-letter queue. "
                    f"Consequence: a message that always fails is retried until "
                    f"MessageRetentionPeriod expires and is then deleted with no record, "
                    f"while consuming retry capacity and, for FIFO queues, blocking its message group."
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
                    f"Configure a dead-letter queue at {fix.path}."
                ),
                remediations=[fix],
            )

    def _async_targets(self, graph):
        """Async invocation drops the event after its retries unless something
        catches it — either a bus-level DeadLetterConfig or a function-level
        destination."""
        for function in graph.resources(Kind.FUNCTION):
            if not isinstance(function, Function):
                continue
            invoke_configs = graph.invoke_configs_for(function.logical_id)
            for edge in graph.async_invokers_of(function.logical_id):
                transport_dlq = bool((edge.props or {}).get("dead_letter_config")) or bool(
                    (edge.props or {}).get("has_redrive")
                )
                execution_dlq = (
                    bool(function.dead_letter_queue)
                    or bool(function.on_failure)
                    or any(config.on_failure for config in invoke_configs)
                )
                if transport_dlq and execution_dlq:
                    continue
                carrier = edge.via or edge.source
                carrier_resource = graph.template.get(carrier)
                fixes = []
                if not transport_dlq and carrier_resource is not None and edge.kind == "subscribe":
                    fixes.append(
                        remediation(
                            graph,
                            carrier_resource,
                            "RedrivePolicy",
                            description="Configure an SNS subscription dead-letter queue.",
                            suggested_value={
                                "deadLetterTargetArn": {
                                    "Fn::GetAtt": [f"{carrier_resource.logical_id}Dlq", "Arn"]
                                }
                            },
                        )
                    )
                elif not transport_dlq and carrier_resource is not None and edge.kind == "rule_target":
                    target_index = int((edge.props or {}).get("target_index", 0))
                    target_path = (
                        ("DeadLetterConfig",)
                        if carrier_resource.synthetic
                        else ("Targets", target_index, "DeadLetterConfig")
                    )
                    fixes.append(
                        remediation(
                            graph,
                            carrier_resource,
                            *target_path,
                            description="Configure an EventBridge target dead-letter queue.",
                            suggested_value={
                                "Arn": {"Fn::GetAtt": [f"{carrier_resource.logical_id}Dlq", "Arn"]}
                            },
                        )
                    )
                if not execution_dlq:
                    config_resource = invoke_configs[0] if invoke_configs else function
                    config_path = (
                        ("DestinationConfig", "OnFailure")
                        if invoke_configs
                        else ("EventInvokeConfig", "DestinationConfig", "OnFailure")
                        if function.cfn_type == "AWS::Serverless::Function"
                        else ()
                    )
                    fixes.append(
                        remediation(
                            graph,
                            config_resource,
                            *config_path,
                            description=(
                                "Configure a Lambda asynchronous on-failure destination; native "
                                "AWS::Lambda::Function templates require AWS::Lambda::EventInvokeConfig."
                            ),
                        )
                    )
                # Neither layer covered means the event is lost outright. One
                # layer covered is a hole in a net that exists — real, but not
                # the same claim.
                impact = (
                    Impact.LOSS
                    if not transport_dlq and not execution_dlq
                    else Impact.DEGRADED
                )
                if transport_dlq:
                    gap = "the delivery service has a DLQ but Lambda execution failures have no destination"
                elif execution_dlq:
                    gap = "Lambda execution failures have a destination but the delivery service has no DLQ"
                else:
                    gap = "neither the delivery service nor Lambda has a dead-letter destination"
                yield Finding(
                    rule_id=self.id,
                    basis=self.basis,
                    impact=impact,
                    title=self.title,
                    message=(
                        f"{carrier} delivers to {function.logical_id} asynchronously, "
                        f"while {gap}. Required: dead-letter coverage for both transport failure "
                        f"and post-acceptance Lambda execution failure. Consequence: an event can "
                        f"be discarded at the uncovered stage with no replay path."
                    ),
                    resources=[carrier, function.logical_id, edge.source],
                    evidence={
                        "delivery": f"{edge.source} --{edge.kind}--> {function.logical_id}",
                        "transport_dead_letter_path": transport_dlq,
                        "lambda_execution_dead_letter_path": execution_dlq,
                        f"{carrier}.DeadLetterConfig/RedrivePolicy": "set" if transport_dlq else None,
                        f"{function.logical_id}.DeadLetterQueue/OnFailure": "set" if execution_dlq else None,
                    },
                    patch_hint=f"Configure a dead-letter path at {fixes[0].path}.",
                    remediations=fixes,
                )
