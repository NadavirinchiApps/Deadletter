"""EDA010 — a workflow task that treats a transient error as final."""

from __future__ import annotations

from ..findings import Basis, Confidence, Finding, Impact
from ..model import Kind, StateMachine
from .base import Rule, register, remediation

# The four errors AWS documents as transient for a Lambda integration. A task
# that does not retry them fails an execution for a blip it never saw.
LAMBDA_TRANSIENT = (
    "Lambda.ServiceException",
    "Lambda.AWSLambdaException",
    "Lambda.SdkClientException",
    "Lambda.TooManyRequestsException",
)
CATCH_ALL = frozenset({"States.ALL", "States.TaskFailed"})


@register
class EDA010(Rule):
    id = "EDA010"
    impact = Impact.STALL
    basis = Basis.RECOMMENDATION
    title = "Workflow task has no retry or catch path"
    condition = "Any transient error from the service the task calls."

    def check(self, graph):
        for machine in graph.resources(Kind.STATE_MACHINE):
            if not isinstance(machine, StateMachine):
                continue
            targets = self._targets(graph, machine)
            for name, state in machine.iter_states():
                if str(state.get("Type")) != "Task":
                    continue
                target_id = targets.get(name)
                if target_id is None:
                    continue  # nothing in this template to name as the other half

                retries = [r for r in _entries(state.get("Retry"))]
                catches = [c for c in _entries(state.get("Catch"))]
                target = graph.node(target_id)
                is_lambda = target is not None and target.kind is Kind.FUNCTION

                finding = self._assess(
                    graph, machine, name, state, target_id, retries, catches, is_lambda
                )
                if finding is not None:
                    yield finding

    def _assess(self, graph, machine, name, state, target_id, retries, catches, is_lambda):
        path = ("Definition", "States", name)
        if not retries and not catches:
            fix = remediation(
                graph,
                machine,
                *path,
                "Retry",
                description=(
                    "Add a Retry block covering the transient errors of the service this task "
                    "calls, and a Catch for what survives them."
                ),
                suggested_value=[
                    {
                        "ErrorEquals": list(LAMBDA_TRANSIENT) if is_lambda else ["States.TaskFailed"],
                        "IntervalSeconds": 2,
                        "MaxAttempts": 3,
                        "BackoffRate": 2,
                    }
                ],
            )
            return Finding(
                rule_id=self.id,
                impact=self.impact,
                                basis=self.basis,
                                title=self.title,
                message=(
                    f"state {name} in {machine.logical_id} calls {target_id} with no Retry "
                    f"and no Catch, while every call to it can fail transiently. Required: a Retry "
                    f"for the retryable errors and a Catch for the rest. Consequence: one "
                    f"throttle or service blip fails the whole execution, and the work already "
                    f"done by earlier states is abandoned with no compensating path."
                ),
                resources=[machine.logical_id, target_id],
                evidence={
                    f"{machine.logical_id}.States.{name}.Retry": None,
                    f"{machine.logical_id}.States.{name}.Catch": None,
                    f"{machine.logical_id}.States.{name}.Resource": state.get("Resource"),
                    "target": target_id,
                },
                patch_hint=f"Add a Retry block at {fix.path}.",
                remediations=[fix],
            )

        if not retries:
            handlers = sorted(
                {str(c.get("Next")) for c in catches if c.get("Next")}
            )
            fix = remediation(
                graph,
                machine,
                *path,
                "Retry",
                description=(
                    "Retry the transient errors before falling through to the catch handler."
                ),
                suggested_value=[
                    {
                        "ErrorEquals": list(LAMBDA_TRANSIENT) if is_lambda else ["States.TaskFailed"],
                        "IntervalSeconds": 2,
                        "MaxAttempts": 3,
                        "BackoffRate": 2,
                    }
                ],
            )
            return Finding(
                rule_id=self.id,
                impact=self.impact,
                basis=self.basis,
                confidence=Confidence.UNASSESSED,
                title=self.title,
                message=(
                    f"state {name} in {machine.logical_id} calls {target_id} with a Catch "
                    f"but no Retry, while the errors it catches include transient ones. Required: "
                    f"a Retry ahead of the catch. Consequence: a momentary throttle takes the "
                    f"failure path, so compensating logic runs for work that would have succeeded "
                    f"on a second attempt."
                ),
                resources=[machine.logical_id, target_id],
                evidence={
                    f"{machine.logical_id}.States.{name}.Retry": None,
                    f"{machine.logical_id}.States.{name}.Catch": [
                        c.get("ErrorEquals") for c in catches
                    ],
                    "catch_handlers": handlers,
                    "target": target_id,
                },
                patch_hint=f"Add a Retry block at {fix.path}.",
                remediations=[fix],
            )

        if not is_lambda:
            return None
        covered = {
            str(error)
            for entry in retries
            for error in _entries(entry.get("ErrorEquals"), plain=True)
        }
        if covered & CATCH_ALL:
            return None
        missing = [error for error in LAMBDA_TRANSIENT if error not in covered]
        if not missing:
            return None

        fix = remediation(
            graph,
            machine,
            *path,
            "Retry",
            description=f"Add {', '.join(missing)} to the retried errors.",
            suggested_value=list(LAMBDA_TRANSIENT),
        )
        return Finding(
            rule_id=self.id,
            impact=self.impact,
            basis=self.basis,
            confidence=Confidence.UNASSESSED,
            title=self.title,
            message=(
                f"state {name} in {machine.logical_id} retries {', '.join(sorted(covered))} "
                f"when calling {target_id}, while {', '.join(missing)} "
                f"{'is' if len(missing) == 1 else 'are'} not retried. Required: every transient "
                f"Lambda error, or States.ALL. Consequence: the untried errors still fail the "
                f"execution, so the retry block reads as protection it does not give."
            ),
            resources=[machine.logical_id, target_id],
            evidence={
                f"{machine.logical_id}.States.{name}.Retry.ErrorEquals": sorted(covered),
                "missing_transient_errors": missing,
                "target": target_id,
            },
            patch_hint=f"Extend the ErrorEquals list at {fix.path}.",
            remediations=[fix],
        )

    @staticmethod
    def _targets(graph, machine: StateMachine) -> dict[str, str]:
        """State name -> the resource that state calls, from the graph edges."""
        found: dict[str, str] = {}
        for edge in graph.out_edges(machine.logical_id):
            state = (edge.props or {}).get("state") or edge.via
            if state and state not in found:
                found[str(state)] = edge.target
        return found


def _entries(value, plain: bool = False) -> list:
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    return items if plain else [item for item in items if isinstance(item, dict)]
