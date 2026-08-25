"""EDA001 — SQS visibility timeout vs its consumer."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import Kind
from .base import Rule, register, remediation

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
                actual = queue.visibility_timeout
                timeout = function.timeout
                if actual is None or timeout is None:
                    unknown = []
                    if actual is None:
                        unknown.append(f"{queue.logical_id}.VisibilityTimeout")
                    if timeout is None:
                        unknown.append(f"{function.logical_id}.Timeout")
                    yield Finding(
                        rule_id=self.id,
                        severity=Severity.WARN,
                        title=self.title,
                        message=(
                            f"WARN: cannot verify the SQS visibility-timeout safety margin for "
                            f"{queue.logical_id} and {function.logical_id} because "
                            f"{', '.join(unknown)} is unresolved. Required: resolve the deployment "
                            f"value and verify VisibilityTimeout >= 6 x Timeout + batching window. "
                            f"Consequence: an unsafe deployed value can cause duplicate processing."
                        ),
                        resources=[queue.logical_id, function.logical_id, esm.logical_id],
                        evidence={
                            f"{queue.logical_id}.VisibilityTimeout": queue.raw_prop("VisibilityTimeout"),
                            f"{function.logical_id}.Timeout": function.raw_prop("Timeout"),
                            "unresolved": unknown,
                        },
                    )
                    continue
                required = SAFETY_FACTOR * timeout + esm.batching_window
                if actual >= required:
                    continue
                fix = remediation(
                    graph,
                    queue,
                    "VisibilityTimeout",
                    description=f"Set VisibilityTimeout to at least {required} seconds.",
                    suggested_value=required,
                )
                yield Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"BLOCK: {queue.logical_id} VisibilityTimeout is {actual}s, while "
                        f"{function.logical_id} Timeout is {timeout}s with a "
                        f"{esm.batching_window}s batching window. Required: {required}s. "
                        f"Consequence: a slow or retrying invocation lets the message become "
                        f"visible again before it finishes, so a second consumer processes it "
                        f"in parallel — duplicate processing under load."
                    ),
                    resources=[queue.logical_id, function.logical_id, esm.logical_id],
                    evidence={
                        f"{queue.logical_id}.VisibilityTimeout": actual,
                        f"{function.logical_id}.Timeout": timeout,
                        f"{esm.logical_id}.MaximumBatchingWindowInSeconds": esm.batching_window,
                        "required_minimum": required,
                        "visibility_timeout_declared": queue.visibility_timeout_declared,
                    },
                    patch_hint=(
                        f"Set {fix.path} to {required} (VisibilityTimeout: {required})."
                    ),
                    remediations=[fix],
                )
