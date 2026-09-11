"""Resources -> directed event-flow graph.

The graph is Deadletter's differentiator: rules reason about connected AWS
resources rather than linting one resource at a time. IAM-derived edges retain
their evidence and are always marked inferred.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

import networkx as nx

from . import model as m
from .findings import SourceLocation
from .intrinsics import ensure_list, referenced_ids, resolve, resolve_definition
from .parse import Template

DELIVERY_EDGES = frozenset({"poll", "rule_target", "subscribe", "invoke"})
FAILURE_EDGES = frozenset({"redrive", "dlq", "on_failure"})

# The SQS metrics that tell an operator a queue is holding messages. Anything
# else on a queue (empty receives, sent-message counts) says nothing about a
# backlog and must not be counted as depth monitoring.
SQS_DEPTH_METRICS = frozenset(
    {
        "ApproximateNumberOfMessagesVisible",
        "ApproximateNumberOfMessagesNotVisible",
        "ApproximateAgeOfOldestMessage",
    }
)


@dataclass(frozen=True)
class AlarmAssessment:
    """An alarm on a resource, and the reasons it cannot raise anybody."""

    alarm: m.Alarm
    defects: tuple[str, ...] = ()

    @property
    def effective(self) -> bool:
        return not self.defects

    def describe(self) -> str:
        return f"{self.alarm.logical_id} {'; '.join(self.defects)}"

_SAM_POLICY_ACTIONS: dict[str, tuple[str, ...]] = {
    "EventBridgePutEventsPolicy": ("events:putevents",),
    "SNSPublishMessagePolicy": ("sns:publish",),
    "DynamoDBCrudPolicy": ("dynamodb:*",),
    "DynamoDBWritePolicy": (
        "dynamodb:batchwriteitem",
        "dynamodb:deleteitem",
        "dynamodb:putitem",
        "dynamodb:transactwriteitems",
        "dynamodb:updateitem",
    ),
}

_DYNAMODB_WRITE_ACTIONS = {
    "dynamodb:batchwriteitem",
    "dynamodb:deleteitem",
    "dynamodb:putitem",
    "dynamodb:transactwriteitems",
    "dynamodb:updateitem",
}


@dataclass
class Edge:
    source: str
    target: str
    kind: str
    via: str | None = None
    inferred: bool = False
    props: dict[str, Any] = field(default_factory=dict)


class EventGraph:
    def __init__(self, template: Template) -> None:
        self.template = template
        self.g = nx.MultiDiGraph()
        # Functions whose execution role points somewhere this template cannot
        # follow. Their IAM-derived edges do not exist, and the coverage block
        # has to say so rather than let the silence read as "no permissions".
        self.unresolved_roles: dict[str, str] = {}
        # Policy resources whose statements were read into edges, by logical ID.
        self.policy_resources_read: set[str] = set()
        self._build()

    # -- construction -------------------------------------------------

    def _build(self) -> None:
        for resource in self.template:
            self.g.add_node(resource.logical_id, resource=resource)

        for resource in list(self.template):
            if resource.kind is m.Kind.API and resource.synthetic and resource.origin:
                self._add_api_event(resource)
            match resource:
                case m.EventSourceMapping():
                    self._add_esm(resource)
                case m.Rule():
                    self._add_rule(resource)
                case m.Subscription():
                    self._add_subscription(resource)
                case m.Queue():
                    self._add_redrive(resource)
                case m.Function():
                    self._add_function_edges(resource)
                case m.EventInvokeConfig():
                    self._add_event_invoke_config(resource)
                case m.StateMachine():
                    self._add_state_machine_edges(resource)
                case _:
                    pass

    def _add(self, source: Any, target: Any, kind: str, **kw: Any) -> None:
        """Add an edge only when both ends resolve inside this template."""
        source_id = source.logical_id if isinstance(source, m.Resource) else source
        target_id = target.logical_id if isinstance(target, m.Resource) else target
        if not source_id or not target_id or source_id == target_id:
            return
        if source_id not in self.g or target_id not in self.g:
            return
        self.g.add_edge(source_id, target_id, key=f"{kind}:{kw.get('via') or ''}", kind=kind, **kw)

    def _add_esm(self, esm: m.EventSourceMapping) -> None:
        source = self.template.resolve_ref(esm.source)
        target = self.template.resolve_ref(esm.target)
        # Enhanced fan-out points the mapping at a consumer, not the stream.
        # The delivery still originates at the stream, so resolve through and
        # record that this reader has its own throughput.
        fan_out = False
        if isinstance(source, m.StreamConsumer):
            fan_out = True
            source = self.template.resolve_ref(source.stream) or source
        if source is not None and esm.source_kind is m.Kind.UNKNOWN:
            esm.source_kind = source.kind
        if source is not None and target is not None:
            self._add(source, target, "poll", via=esm.logical_id, props={"enhanced_fan_out": fan_out})
        failure = self.template.resolve_ref(esm.on_failure)
        if failure is not None:
            self._add(esm, failure, "on_failure", via=esm.logical_id)

    def _add_rule(self, rule: m.Rule) -> None:
        bus = self.template.resolve_ref(rule.bus)
        for index, target_spec in enumerate(rule.targets):
            target = self.template.resolve_ref(resolve(target_spec.get("Arn")))
            if target is None:
                continue
            props = {
                "dead_letter_config": target_spec.get("DeadLetterConfig"),
                "retry_policy": target_spec.get("RetryPolicy"),
                "target_index": index,
            }
            if bus is not None and not rule.scheduled:
                self._add(bus, target, "rule_target", via=rule.logical_id, props=props)
            else:
                # A schedule is a time source; publishing to a bus cannot retrigger it.
                self._add(rule, target, "rule_target", via=rule.logical_id, props=props)

    def _add_subscription(self, subscription: m.Subscription) -> None:
        topic = self.template.resolve_ref(subscription.topic)
        endpoint = self.template.resolve_ref(subscription.endpoint)
        if topic is not None and endpoint is not None:
            self._add(
                topic,
                endpoint,
                "subscribe",
                via=subscription.logical_id,
                props={
                    "redrive_policy": subscription.prop("RedrivePolicy"),
                    "has_redrive": subscription.has_redrive,
                },
            )

    def _add_redrive(self, queue: m.Queue) -> None:
        dlq = self.template.resolve_ref(queue.redrive_target)
        if dlq is not None:
            self._add(queue, dlq, "redrive", props={"max_receive_count": queue.max_receive_count})

    def _add_function_edges(self, function: m.Function) -> None:
        role_reference = function.ref("Role")
        if role_reference.configured and not isinstance(
            self.template.resolve_ref(role_reference), m.Role
        ):
            self.unresolved_roles[function.logical_id] = _reference_text(role_reference)

        dlq = self.template.resolve_ref(function.dead_letter_queue)
        if dlq is not None:
            self._add(function, dlq, "dlq")
        failure = self.template.resolve_ref(function.on_failure)
        if failure is not None:
            self._add(function, failure, "on_failure")

        for actions, target_ids, basis in self._permissions(function):
            for target_id in target_ids:
                target = self.template.get(target_id)
                if target is None:
                    continue
                props = {"basis": "iam-policy", "policy_source": basis, "actions": sorted(actions)}
                if target.kind in (m.Kind.TABLE, m.Kind.DATABASE) and self._can_write(actions, target.kind):
                    self._add(function, target, "writes", inferred=True, props=props)
                elif target.kind is m.Kind.BUS and self._action_allowed(actions, "events", "putevents"):
                    self._add(function, target, "publish", inferred=True, props=props)
                elif target.kind is m.Kind.TOPIC and self._action_allowed(actions, "sns", "publish"):
                    self._add(function, target, "publish", inferred=True, props=props)

    def _permissions(self, function: m.Function) -> list[tuple[set[str], set[str], str]]:
        """Return action/resource pairs without mixing separate IAM statements."""
        policies = list(ensure_list(function.prop("Policies")))
        role = self.template.resolve_ref(function.ref("Role"))
        if isinstance(role, m.Role):
            policies.extend(ensure_list(role.prop("Policies")))

        permissions: list[tuple[set[str], set[str], str]] = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            if len(policy) == 1:
                template_name, config = next(iter(policy.items()))
                template_actions = _SAM_POLICY_ACTIONS.get(str(template_name))
                if template_actions:
                    permissions.append(
                        (
                            set(template_actions),
                            self._policy_target_ids(config),
                            f"sam-policy:{template_name}",
                        )
                    )
                    continue

            document = policy.get("PolicyDocument", policy)
            if not isinstance(document, dict):
                continue
            permissions.extend(
                self._statement_permissions(ensure_list(document.get("Statement")), "iam-policy")
            )

        # IAM written as its own resource. CDK emits every grant this way, so a
        # synthesized stack has no inline `Policies` at all: without this the
        # role looks empty and the graph loses every publish and write edge.
        for attached in self._attached_policies(role):
            statements = attached.policy_statements
            found = self._statement_permissions(
                statements, f"iam-policy-resource:{attached.logical_id}"
            )
            if found:
                self.policy_resources_read.add(attached.logical_id)
            permissions.extend(found)
        return permissions

    def _attached_policies(self, role: m.Resource | None) -> list[m.Policy]:
        """Policy resources whose `Roles` names this role."""
        if role is None:
            return []
        return [
            policy
            for policy in self.template.of_kind(m.Kind.POLICY)
            if isinstance(policy, m.Policy) and policy.attaches_to(role)
        ]

    def _statement_permissions(
        self, statements: Iterable[Any], basis: str
    ) -> list[tuple[set[str], set[str], str]]:
        found: list[tuple[set[str], set[str], str]] = []
        for statement in statements:
            if not isinstance(statement, dict) or str(statement.get("Effect", "Allow")).lower() != "allow":
                continue
            actions = {
                action.lower()
                for action in ensure_list(statement.get("Action"))
                if isinstance(action, str)
            }
            targets = self._policy_target_ids(statement.get("Resource"))
            if actions and targets:
                found.append((actions, targets, basis))
        return found

    def _policy_target_ids(self, node: Any) -> set[str]:
        """Resolve logical references and literal names/ARNs in a policy resource."""
        targets = set(referenced_ids(node))

        def walk(value: Any) -> None:
            reference = resolve(value)
            target = self.template.resolve_ref(reference)
            if target is not None:
                targets.add(target.logical_id)
            if isinstance(value, dict):
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(node)
        return targets

    @staticmethod
    def _action_allowed(actions: set[str], service: str, action: str) -> bool:
        return "*" in actions or f"{service}:*" in actions or f"{service}:{action}" in actions

    @classmethod
    def _can_write(cls, actions: set[str], kind: m.Kind) -> bool:
        if kind is m.Kind.TABLE:
            return bool(actions & _DYNAMODB_WRITE_ACTIONS) or "*" in actions or "dynamodb:*" in actions
        return "*" in actions or "rds-data:*" in actions or bool(
            actions & {"rds-data:executestatement", "rds-data:batchexecutestatement"}
        )

    def _add_event_invoke_config(self, config: m.EventInvokeConfig) -> None:
        destination = self.template.resolve_ref(config.on_failure)
        if destination is not None:
            self._add(config, destination, "on_failure", via=config.logical_id)

    def _add_state_machine_edges(self, machine: m.StateMachine) -> None:
        """A workflow is event delivery too: a Task state is a real invocation."""
        for name, state in machine.iter_states():
            if str(state.get("Type")) != "Task":
                continue
            parameters = state.get("Parameters")
            # A CDK definition arrives with placeholders where the ARNs were,
            # so the reference has to be read through them.
            candidates = [resolve_definition(state.get("Resource"))]
            if isinstance(parameters, dict):
                for key in ("FunctionName", "QueueUrl", "TopicArn", "StateMachineArn"):
                    candidates.append(resolve_definition(parameters.get(key)))
            for reference in candidates:
                target = self.template.resolve_ref(reference)
                if target is None:
                    continue
                kind = "invoke" if target.kind in (m.Kind.FUNCTION, m.Kind.STATE_MACHINE) else "publish"
                self._add(machine, target, kind, via=name, props={"state": name})

    def _add_api_event(self, event: m.Resource) -> None:
        function = self.template.get(event.origin)
        if not isinstance(function, m.Function):
            return
        api = self.template.resolve_ref(event.ref("ApiId", "RestApiId"))
        self._add(api or event, function, "invoke", via=event.logical_id)

    # -- queries rules use --------------------------------------------

    def node(self, logical_id: str) -> m.Resource | None:
        data = self.g.nodes.get(logical_id)
        return data.get("resource") if data else None

    def resources(self, *kinds: m.Kind) -> list[m.Resource]:
        return self.template.of_kind(*kinds) if kinds else list(self.template)

    def edges(self, kind: str | None = None) -> Iterator[Edge]:
        for source, target, data in self.g.edges(data=True):
            if kind is None or data.get("kind") == kind:
                yield Edge(
                    source=source,
                    target=target,
                    kind=data.get("kind", ""),
                    via=data.get("via"),
                    inferred=data.get("inferred", False),
                    props=data.get("props", {}),
                )

    def out_edges(self, logical_id: str, kind: str | None = None) -> list[Edge]:
        return [edge for edge in self.edges(kind) if edge.source == logical_id]

    def in_edges(self, logical_id: str, kind: str | None = None) -> list[Edge]:
        return [edge for edge in self.edges(kind) if edge.target == logical_id]

    def consumers_of(self, logical_id: str) -> list[tuple[m.EventSourceMapping, m.Function]]:
        pairs = []
        for edge in self.out_edges(logical_id, "poll"):
            esm = self.template.get(edge.via)
            function = self.node(edge.target)
            if isinstance(esm, m.EventSourceMapping) and isinstance(function, m.Function):
                pairs.append((esm, function))
        return pairs

    def async_invokers_of(self, logical_id: str) -> list[Edge]:
        return [edge for edge in self.in_edges(logical_id) if edge.kind in ("rule_target", "subscribe")]

    def has_failure_path(self, logical_id: str) -> bool:
        return any(edge.kind in FAILURE_EDGES for edge in self.out_edges(logical_id))

    def failure_senders(self, logical_id: str) -> list[Edge]:
        """Edges that dump failed traffic into this resource."""
        return [edge for edge in self.in_edges(logical_id) if edge.kind in FAILURE_EDGES]

    def delivery_routes(self, logical_id: str) -> list[Edge]:
        """Edges by which something this resource carries actually reaches a consumer."""
        return [edge for edge in self.out_edges(logical_id) if edge.kind in DELIVERY_EDGES]

    def autoscaling_targets_on(self, logical_id: str) -> list[m.Resource]:
        """Application Auto Scaling targets pointed at this resource.

        Not modelled as a kind of its own — the only question a rule asks is
        whether the capacity ceiling is fixed or allowed to move.
        """
        return [
            resource
            for resource in self.template
            if resource.cfn_type == "AWS::ApplicationAutoScaling::ScalableTarget"
            and logical_id in referenced_ids(resource.prop("ResourceId"))
        ]

    def alarms_on(self, logical_id: str) -> list[m.Alarm]:
        """Alarms whose dimensions name this resource.

        Membership only. A rule that treats this as evidence somebody is told
        is making a claim this method does not support — use `alarm_coverage`.
        """
        resource = self.template.get(logical_id)
        name_hint = resource.name_hint if resource is not None else None
        found: list[m.Alarm] = []
        for alarm in self.resources(m.Kind.ALARM):
            if not isinstance(alarm, m.Alarm):
                continue
            for dimension in alarm.dimensions:
                value = dimension.get("Value")
                if logical_id in referenced_ids(value):
                    found.append(alarm)
                    break
                if name_hint is not None and value == name_hint:
                    found.append(alarm)
                    break
        return found

    def alarm_coverage(
        self, logical_id: str, metrics: Iterable[str]
    ) -> list["AlarmAssessment"]:
        """Assess whether each alarm on this resource can actually notify anyone.

        An alarm that names the right resource but measures an unrelated metric,
        has its actions disabled, or has no action to take is indistinguishable
        from no alarm at all when the queue starts filling. Reporting it as
        coverage is how a scanner tells somebody they are safe when they are not.
        """
        wanted = frozenset(metrics)
        assessments: list[AlarmAssessment] = []
        for alarm in self.alarms_on(logical_id):
            defects: list[str] = []
            metric = alarm.metric_name
            if metric is None:
                defects.append("has no resolvable MetricName")
            elif metric not in wanted:
                defects.append(
                    f"watches {metric}, not {' or '.join(sorted(wanted))}"
                )
            if not alarm.actions_enabled:
                defects.append("has ActionsEnabled set to false")
            if not alarm.alarm_actions:
                defects.append("has no AlarmActions, so it notifies nobody")
            assessments.append(
                AlarmAssessment(alarm=alarm, defects=tuple(defects))
            )
        return assessments

    def invoke_configs_for(self, function_id: str) -> list[m.EventInvokeConfig]:
        configs: list[m.EventInvokeConfig] = []
        for resource in self.resources(m.Kind.INVOKE_CONFIG):
            if isinstance(resource, m.EventInvokeConfig):
                target = self.template.resolve_ref(resource.function)
                if target is not None and target.logical_id == function_id:
                    configs.append(resource)
        return configs

    def source_location(self, resource: m.Resource | str, *parts: str | int) -> SourceLocation:
        item = self.template.get(resource) if isinstance(resource, str) else resource
        path = item.property_path(*parts) if item is not None else ()
        line, column = self.template.location(path)
        pointer = "/" + "/".join(_pointer_escape(part) for part in path) if path else ""
        return SourceLocation(
            path=pointer,
            line=line,
            column=column,
            address=item.construct_path if item is not None else None,
        )

    def to_mermaid(self) -> str:
        shapes = {
            m.Kind.FUNCTION: "[{}]",
            m.Kind.QUEUE: "[/{}/]",
            m.Kind.TOPIC: "([{}])",
            m.Kind.BUS: "{{{}}}",
            m.Kind.TABLE: "[({})]",
            m.Kind.DATABASE: "[({})]",
            m.Kind.STREAM: "[/{}/]",
            m.Kind.API: "([{}])",
        }
        lines = ["graph LR"]
        drawn = {edge.source for edge in self.edges()} | {edge.target for edge in self.edges()}
        for logical_id in sorted(drawn):
            resource = self.node(logical_id)
            if resource is None:
                continue
            shape = shapes.get(resource.kind, "[{}]")
            safe = logical_id.replace("#", "_")
            label = resource.name_hint or logical_id
            lines.append(f"    {safe}{shape.format(label)}")
        for edge in self.edges():
            style = "-.->" if edge.kind in FAILURE_EDGES or edge.inferred else "-->"
            lines.append(
                f"    {edge.source.replace('#', '_')} {style}|{edge.kind}| {edge.target.replace('#', '_')}"
            )
        return "\n".join(lines)


def _pointer_escape(value: str | int) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _reference_text(reference) -> str:
    """How the template wrote a reference, for a coverage note to quote back."""
    if reference.logical_ids:
        return ", ".join(sorted(reference.logical_ids))
    if reference.literal:
        return reference.literal
    return "an unresolved value"


def build(template: Template) -> EventGraph:
    return EventGraph(template)


__all__ = ["EventGraph", "Edge", "build", "DELIVERY_EDGES", "FAILURE_EDGES", "ensure_list"]
