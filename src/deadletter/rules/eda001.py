"""EDA001 — SQS visibility timeout vs its consumer."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import Kind
from .base import Rule, register

# AWS's own guidance: visibility timeout should be at least 6x the consumer's
# timeout, plus the batching window, so a retrying invocation never overlaps
# with the message becoming visible again.
SAFETY_FACTOR = 6


@register
class EDA001(Rule):
    id = "EDA001"
    severity = Severity.BLOCK
    title = "SQS visibility timeout too short for its consumer"
    condition = "Any invocation that runs longer than the visibility timeout."

    def check(self, graph):
        for queue in graph.resources(Kind.QUEUE):
            for esm, function in graph.consumers_of(queue.logical_id):
                required = SAFETY_FACTOR * function.timeout + esm.batching_window
                actual = queue.visibility_timeout
                if actual >= required:
                    continue
                yield Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"BLOCK: {queue.logical_id} VisibilityTimeout is {actual}s, while "
                        f"{function.logical_id} Timeout is {function.timeout}s with a "
                        f"{esm.batching_window}s batching window. Required: {required}s. "
                        f"Consequence: a slow or retrying invocation lets the message become "
                        f"visible again before it finishes, so a second consumer processes it "
                        f"in parallel — duplicate processing under load."
                    ),
                    resources=[queue.logical_id, function.logical_id, esm.logical_id],
                    evidence={
                        f"{queue.logical_id}.VisibilityTimeout": actual,
                        f"{function.logical_id}.Timeout": function.timeout,
                        f"{esm.logical_id}.MaximumBatchingWindowInSeconds": esm.batching_window,
                        "required_minimum": required,
                        "visibility_timeout_declared": queue.visibility_timeout_declared,
                    },
                    patch_hint=(
                        f"  {queue.logical_id}:\n"
                        f"    Type: AWS::SQS::Queue\n"
                        f"    Properties:\n"
                        f"-     VisibilityTimeout: {actual}\n"
                        f"+     VisibilityTimeout: {required}"
                    ),
                )
