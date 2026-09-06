"""EDA008 — a dead-letter queue that expires messages before anyone can act."""

from __future__ import annotations

from ..findings import Basis, Confidence, Finding, Impact
from ..model import Queue
from .base import Rule, register, remediation

SQS_MAX_RETENTION = 1_209_600  # 14 days


@register
class EDA008(Rule):
    id = "EDA008"
    impact = Impact.LOSS
    title = "Dead-letter queue retention is shorter than its source"
    condition = "Any message that fails late in the source queue's retention window."

    def check(self, graph):
        """Redrive does not reset the enqueue timestamp.

        A message keeps the age it accumulated on the source queue, so its life
        in the dead-letter queue is `dlq_retention - age_at_failure`, not the
        full DLQ retention. When the DLQ is not configured to outlive the
        source, a message that fails near the end of the source window is
        deleted from the DLQ almost immediately.
        """
        for edge in graph.edges("redrive"):
            source = graph.node(edge.source)
            dlq = graph.node(edge.target)
            if not isinstance(source, Queue) or not isinstance(dlq, Queue):
                continue

            source_retention = source.message_retention
            dlq_retention = dlq.message_retention
            if source_retention is None or dlq_retention is None:
                unknown = [
                    f"{queue.logical_id}.MessageRetentionPeriod"
                    for queue, value in ((source, source_retention), (dlq, dlq_retention))
                    if value is None
                ]
                yield Finding(
                    rule_id=self.id,
                    impact=self.impact,
                    confidence=Confidence.UNASSESSED,
                    title=self.title,
                    message=(
                        f"cannot verify that {dlq.logical_id} outlives {source.logical_id} "
                        f"because {', '.join(unknown)} is unresolved. Required: resolve the "
                        f"deployment value and verify the dead-letter queue retains messages "
                        f"longer than its source. Consequence: a late failure can be deleted from "
                        f"the dead-letter queue before anyone sees it."
                    ),
                    resources=[dlq.logical_id, source.logical_id],
                    evidence={
                        f"{source.logical_id}.MessageRetentionPeriod": source.raw_prop(
                            "MessageRetentionPeriod"
                        ),
                        f"{dlq.logical_id}.MessageRetentionPeriod": dlq.raw_prop(
                            "MessageRetentionPeriod"
                        ),
                        "unresolved": unknown,
                    },
                )
                continue

            if dlq_retention > source_retention:
                continue

            equal = dlq_retention == source_retention
            # Strictly longer is the advice. Equal is not a violation of
            # anything AWS enforces, so it is reported as the recommendation it
            # is; shorter is arithmetic on documented redrive behaviour.
            basis = Basis.RECOMMENDATION if equal else Basis.REQUIREMENT
            both_default = not source.message_retention_declared and not dlq.message_retention_declared
            if equal:
                exposure = (
                    "a message that fails in the final seconds of the source window arrives at the "
                    "dead-letter queue already at its retention limit and is deleted at once"
                )
                if both_default:
                    exposure += ", which is what both queues do by default"
            else:
                shortfall = source_retention - dlq_retention
                exposure = (
                    f"a message older than {dlq_retention}s when it fails is deleted from the "
                    f"dead-letter queue immediately, and every message loses {shortfall}s of the "
                    f"window it should have had"
                )

            fix = remediation(
                graph,
                dlq,
                "MessageRetentionPeriod",
                description=(
                    f"Retain dead-lettered messages longer than the {source_retention}s source "
                    f"window so a late failure still leaves time to act."
                ),
                suggested_value=SQS_MAX_RETENTION,
                automatic=True,
            )
            yield Finding(
                rule_id=self.id,
                impact=self.impact,
                basis=basis,
                # Only the dead-letter queue's own retention is decisive. If the
                # author wrote a short value there, the source sitting at its
                # AWS default does not excuse it.
                defaults_relied_on=(
                    []
                    if dlq.message_retention_declared
                    else [f"{dlq.logical_id}.MessageRetentionPeriod"]
                ),
                title=self.title,
                message=(
                    f"{dlq.logical_id} MessageRetentionPeriod is {dlq_retention}s, "
                    f"while its source {source.logical_id} retains messages for "
                    f"{source_retention}s. Required: more than {source_retention}s, up to the "
                    f"{SQS_MAX_RETENTION}s maximum. Consequence: redrive does not reset a "
                    f"message's age, so {exposure}."
                ),
                resources=[dlq.logical_id, source.logical_id],
                evidence={
                    f"{source.logical_id}.MessageRetentionPeriod": source_retention,
                    f"{dlq.logical_id}.MessageRetentionPeriod": dlq_retention,
                    f"{source.logical_id}.RedrivePolicy.maxReceiveCount": (
                        edge.props or {}
                    ).get("max_receive_count"),
                    "retention_declared": {
                        source.logical_id: source.message_retention_declared,
                        dlq.logical_id: dlq.message_retention_declared,
                    },
                },
                patch_hint=f"Set {fix.path} to {SQS_MAX_RETENTION}.",
                remediations=[fix],
            )
