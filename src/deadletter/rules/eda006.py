"""EDA006 — a dead-letter queue that nothing drains and nobody watches."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import Kind, Queue
from .base import Rule, register, remediation


@register
class EDA006(Rule):
    id = "EDA006"
    severity = Severity.BLOCK
    title = "Dead-letter queue is never drained"
    condition = "Any message that reaches the dead-letter queue."

    def check(self, graph):
        """EDA002 asks whether a dead-letter path exists. This asks whether it
        goes anywhere: a DLQ with no consumer and no alarm converts a loud
        failure into a silent one on the queue's retention clock."""
        for queue in graph.resources(Kind.QUEUE):
            if not isinstance(queue, Queue):
                continue
            senders = graph.failure_senders(queue.logical_id)
            if not senders:
                continue  # not a dead-letter queue
            if graph.consumers_of(queue.logical_id):
                continue  # something drains it

            if graph.alarms_on(queue.logical_id):
                continue  # not drained, but a human is told while the messages exist

            producers = sorted({edge.source for edge in senders})
            retention = queue.message_retention
            window = (
                f"{retention}s"
                if queue.message_retention_declared
                else f"{retention}s (unset, AWS default)"
            )

            fix = remediation(
                graph,
                queue,
                "MessageRetentionPeriod",
                description=(
                    "Give this dead-letter queue a consumer that redrives or records its "
                    "messages, or alarm on ApproximateNumberOfMessagesVisible so a human is "
                    "told before retention expires."
                ),
                suggested_value=1_209_600,
            )
            yield Finding(
                rule_id=self.id,
                severity=self.severity,
                title=self.title,
                message=(
                    f"BLOCK: {queue.logical_id} receives failed messages from "
                    f"{', '.join(producers)}, while no consumer polls it and no CloudWatch alarm "
                    f"watches its depth. Required: a consumer or an alarm on the queue depth. "
                    f"Consequence: every dead-lettered message is deleted when "
                    f"MessageRetentionPeriod ({window}) expires with nothing raised, so the queue "
                    f"added to prevent loss becomes where the loss happens."
                ),
                resources=[queue.logical_id, *producers],
                evidence={
                    f"{queue.logical_id}.MessageRetentionPeriod": window,
                    "dead_letter_producers": producers,
                    "consumers": [],
                    "alarms": [],
                },
                patch_hint=(
                    f"Add a consumer for {queue.logical_id}, or an alarm on its "
                    f"ApproximateNumberOfMessagesVisible metric."
                ),
                remediations=[fix],
            )
