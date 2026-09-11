"""EDA001 — SQS visibility timeout vs its consumer."""

from __future__ import annotations

from ..findings import Basis, Confidence, Finding, Impact
from ..model import Kind
from .base import Rule, register, remediation

# AWS's guidance: visibility timeout should be at least 6x the consumer's
# timeout, plus the batching window, so a retrying invocation never overlaps
# with the message becoming visible again. This is advice, not a constraint the
# service imposes — see the class docstring.
SAFETY_FACTOR = 6


@register
class EDA001(Rule):
    id = "EDA001"
    impact = Impact.DUPLICATION
    title = "SQS visibility timeout too short for its consumer"
    condition = "Any invocation that runs longer than the visibility timeout."

    def check(self, graph):
        """Two different claims live in this rule, and conflating them was a bug.

        AWS's *constraint* is that a queue's visibility timeout must be at least
        the consuming function's timeout; below that, a message is guaranteed to
        become visible again while its first invocation is still running. Lambda
        enforces it at the mapping API, so a template written this way fails to
        deploy rather than duplicating work — the state the finding describes is
        reached by lowering the queue's timeout under a mapping that already
        exists, which nothing rejects.

        AWS's *recommendation* is six times the function timeout plus the
        batching window, which buys room for retries. Falling short of the
        recommendation is worth telling somebody about. It is not a violation,
        and a scanner that blocks a release over it has spent the credibility it
        needs for the case that really is broken.
        """
        for queue in graph.resources(Kind.QUEUE):
            for esm, function in graph.consumers_of(queue.logical_id):
                actual = queue.visibility_timeout
                timeout = function.timeout
                if actual is None or timeout is None:
                    yield self._unresolved(queue, function, esm)
                    continue

                required = SAFETY_FACTOR * timeout + esm.batching_window
                if actual >= required:
                    continue

                if actual < timeout:
                    yield self._violation(graph, queue, function, esm, actual, timeout, required)
                else:
                    yield self._below_recommendation(
                        graph, queue, function, esm, actual, timeout, required
                    )

    @staticmethod
    def _inherited(queue, function) -> list[str]:
        """The decisive value, when AWS supplied it rather than the author.

        Only the queue's visibility timeout is decisive: it is the value that is
        too short. A consumer left at its own default Timeout does not make an
        explicitly chosen VisibilityTimeout somebody else's fault.
        """
        if queue.visibility_timeout_declared:
            return []
        return [f"{queue.logical_id}.VisibilityTimeout"]

    def _unresolved(self, queue, function, esm):
        unknown = []
        if queue.visibility_timeout is None:
            unknown.append(f"{queue.logical_id}.VisibilityTimeout")
        if function.timeout is None:
            unknown.append(f"{function.logical_id}.Timeout")
        return Finding(
            rule_id=self.id,
            impact=self.impact,
            confidence=Confidence.UNASSESSED,
            title=self.title,
            message=(
                f"cannot verify the SQS visibility-timeout margin for {queue.logical_id} "
                f"and {function.logical_id} because {', '.join(unknown)} is unresolved. "
                f"Required: resolve the deployment value, then verify VisibilityTimeout "
                f"is at least {function.logical_id}'s Timeout. Consequence: an unsafe "
                f"deployed value can cause duplicate processing."
            ),
            resources=[queue.logical_id, function.logical_id, esm.logical_id],
            evidence={
                f"{queue.logical_id}.VisibilityTimeout": queue.raw_prop("VisibilityTimeout"),
                f"{function.logical_id}.Timeout": function.raw_prop("Timeout"),
                "unresolved": unknown,
            },
        )

    def _violation(self, graph, queue, function, esm, actual, timeout, required):
        fix = remediation(
            graph,
            queue,
            "VisibilityTimeout",
            description=(
                f"Set VisibilityTimeout to at least {timeout} seconds to satisfy the AWS "
                f"constraint, and to {required} to meet the recommended retry margin."
            ),
            suggested_value=required,
        )
        return Finding(
            rule_id=self.id,
            impact=self.impact,
            basis=Basis.REQUIREMENT,
            defaults_relied_on=self._inherited(queue, function),
            title=self.title,
            message=(
                f"{queue.logical_id} VisibilityTimeout is {actual}s, while its consumer "
                f"{function.logical_id} has a Timeout of {timeout}s. Required: at least "
                f"{timeout}s — Lambda rejects CreateEventSourceMapping and "
                f"UpdateEventSourceMapping below that with InvalidParameterValueException, "
                f"so this template does not deploy as written. Consequence: a fresh deploy "
                f"fails at the mapping rather than duplicating anything, but an existing "
                f"mapping survives its queue's VisibilityTimeout being lowered afterwards — "
                f"which the SQS API accepts — and from then on every invocation that runs "
                f"its full timeout releases the message back to the queue before it "
                f"finishes, so a second consumer picks up work already in progress."
            ),
            resources=[queue.logical_id, function.logical_id, esm.logical_id],
            evidence={
                f"{queue.logical_id}.VisibilityTimeout": actual,
                f"{function.logical_id}.Timeout": timeout,
                f"{esm.logical_id}.MaximumBatchingWindowInSeconds": esm.batching_window,
                "aws_minimum": timeout,
                "aws_rejects_at_mapping_creation": True,
                "recommended_minimum": required,
                "visibility_timeout_declared": queue.visibility_timeout_declared,
            },
            patch_hint=f"Set {fix.path} to at least {timeout} (recommended: {required}).",
            remediations=[fix],
        )

    def _below_recommendation(self, graph, queue, function, esm, actual, timeout, required):
        fix = remediation(
            graph,
            queue,
            "VisibilityTimeout",
            description=(
                f"Set VisibilityTimeout to {required} seconds to leave room for the "
                f"retries AWS recommends allowing for."
            ),
            suggested_value=required,
        )
        headroom = actual // timeout
        return Finding(
            rule_id=self.id,
            impact=self.impact,
            basis=Basis.RECOMMENDATION,
            defaults_relied_on=self._inherited(queue, function),
            title=self.title,
            message=(
                f"{queue.logical_id} VisibilityTimeout is {actual}s, which clears its "
                f"consumer {function.logical_id}'s {timeout}s Timeout but leaves room for "
                f"only {headroom} attempt(s). Recommended: {required}s "
                f"({SAFETY_FACTOR} x Timeout + a {esm.batching_window}s batching window). "
                f"Consequence: a message that has to be retried can become visible again "
                f"mid-attempt, so a second consumer processes it in parallel under load."
            ),
            resources=[queue.logical_id, function.logical_id, esm.logical_id],
            evidence={
                f"{queue.logical_id}.VisibilityTimeout": actual,
                f"{function.logical_id}.Timeout": timeout,
                f"{esm.logical_id}.MaximumBatchingWindowInSeconds": esm.batching_window,
                "aws_minimum": timeout,
                "aws_minimum_satisfied": True,
                "recommended_minimum": required,
                "attempts_that_fit": headroom,
                "visibility_timeout_declared": queue.visibility_timeout_declared,
            },
            patch_hint=f"Set {fix.path} to {required} (VisibilityTimeout: {required}).",
            remediations=[fix],
        )
