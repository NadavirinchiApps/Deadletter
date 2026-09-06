"""EDA006 — a dead-letter queue that nothing drains and nobody watches."""

from __future__ import annotations

from ..findings import Basis, Confidence, Finding, Impact
from ..graph import SQS_DEPTH_METRICS
from ..model import Kind, Queue
from .base import Rule, register, remediation


@register
class EDA006(Rule):
    id = "EDA006"
    impact = Impact.LOSS
    basis = Basis.RECOMMENDATION
    title = "Dead-letter queue is never drained"
    condition = "Any message that reaches the dead-letter queue."

    def check(self, graph):
        """EDA002 asks whether a dead-letter path exists. This asks whether it
        goes anywhere: a DLQ with no consumer and no alarm converts a loud
        failure into a silent one on the queue's retention clock.

        The alarm half of that question is not "does an alarm mention this
        queue". An alarm on the wrong metric, with actions disabled, or with no
        action configured leaves exactly the silence this rule exists to catch
        — and is worse than no alarm, because somebody believes it works.
        """
        for queue in graph.resources(Kind.QUEUE):
            if not isinstance(queue, Queue):
                continue
            senders = graph.failure_senders(queue.logical_id)
            if not senders:
                continue  # not a dead-letter queue
            if graph.consumers_of(queue.logical_id):
                continue  # something drains it

            coverage = graph.alarm_coverage(queue.logical_id, SQS_DEPTH_METRICS)
            effective = [entry for entry in coverage if entry.effective]
            producers = sorted({edge.source for edge in senders})

            if effective:
                yield from self._weak_threshold(graph, queue, effective, producers)
                continue

            yield self._unwatched(graph, queue, coverage, producers)

    def _unwatched(self, graph, queue, coverage, producers):
        retention = queue.message_retention
        window = (
            f"{retention}s"
            if queue.message_retention_declared
            else f"{retention}s (unset, AWS default)"
        )
        broken = [entry for entry in coverage if not entry.effective]

        if broken:
            # Naming the alarm that looks like protection is the whole value
            # here: somebody added it on purpose and believes they are covered.
            detail = "; ".join(entry.describe() for entry in broken)
            state = f"no consumer polls it, and the alarm on it cannot raise anyone — {detail}"
        else:
            state = "no consumer polls it and no CloudWatch alarm watches its depth"

        fix = remediation(
            graph,
            queue,
            "MessageRetentionPeriod",
            description=(
                "Give this dead-letter queue a consumer that redrives or records its "
                "messages, or alarm on ApproximateNumberOfMessagesVisible with "
                "ActionsEnabled and an AlarmActions target so a human is told before "
                "retention expires."
            ),
            suggested_value=1_209_600,
        )
        return Finding(
            rule_id=self.id,
            impact=self.impact,
            basis=self.basis,
            title=self.title,
            message=(
                f"{queue.logical_id} receives failed messages from "
                f"{', '.join(producers)}, while {state}. Required: a consumer, or an "
                f"alarm on queue depth that is enabled and has an action. Consequence: "
                f"every dead-lettered message is deleted when MessageRetentionPeriod "
                f"({window}) expires with nothing raised, so the queue added to prevent "
                f"loss becomes where the loss happens."
            ),
            resources=[
                queue.logical_id,
                *producers,
                *(entry.alarm.logical_id for entry in broken),
            ],
            evidence={
                f"{queue.logical_id}.MessageRetentionPeriod": window,
                "dead_letter_producers": producers,
                "consumers": [],
                "alarms_naming_this_queue": [entry.alarm.logical_id for entry in coverage],
                "alarms_that_can_notify": [],
                "alarm_defects": {
                    entry.alarm.logical_id: list(entry.defects) for entry in broken
                },
            },
            patch_hint=(
                f"Add a consumer for {queue.logical_id}, or an enabled alarm with an "
                f"AlarmActions target on its ApproximateNumberOfMessagesVisible metric."
            ),
            remediations=[fix],
        )

    def _weak_threshold(self, graph, queue, effective, producers):
        """A working alarm that only fires once a backlog has built up.

        Whether that matters depends on how much traffic the queue sees, which
        no template states — so it is reported as the assumption it is, and
        never as a violation.
        """
        for entry in effective:
            alarm = entry.alarm
            threshold = alarm.threshold
            if threshold is None or not alarm.fires_above_threshold or threshold <= 0:
                continue
            yield Finding(
                rule_id=self.id,
                impact=Impact.DEGRADED,
                basis=Basis.RECOMMENDATION,
                confidence=Confidence.ASSUMED,
                assumptions=[
                    f"That {queue.logical_id} can accumulate {threshold:g} messages "
                    f"within the time somebody still has to act on them — a rate no "
                    f"template states."
                ],
                title=self.title,
                message=(
                    f"{alarm.logical_id} watches {queue.logical_id} on "
                    f"{alarm.metric_name} but only fires above {threshold:g} messages, "
                    f"while nothing drains the queue. Required: confirm that many "
                    f"dead-lettered messages is an acceptable backlog before anyone is "
                    f"told, or alarm above 0. Consequence: below the threshold the queue "
                    f"fills and expires silently, which is the state this alarm was "
                    f"added to prevent."
                ),
                resources=[queue.logical_id, alarm.logical_id, *producers],
                evidence={
                    f"{alarm.logical_id}.MetricName": alarm.metric_name,
                    f"{alarm.logical_id}.Threshold": threshold,
                    f"{alarm.logical_id}.ComparisonOperator": alarm.comparison_operator,
                    "dead_letter_producers": producers,
                    "consumers": [],
                },
                patch_hint=(
                    f"Consider lowering {alarm.logical_id} Threshold to 0 so any "
                    f"dead-lettered message raises it."
                ),
            )
