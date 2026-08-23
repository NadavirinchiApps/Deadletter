"""Resources -> directed event-flow graph.

This is the differentiator. Per-resource linters already tell you a queue has
no DLQ. Only a graph can tell you that *this* queue's visibility timeout is
too short for *that* function's timeout, because only a graph knows the two
are connected.

Nodes are logical IDs carrying their typed resource. Edges are deliveries,
each tagged with the mechanism that carries them:

    poll        queue/stream/table-stream -> function   (event source mapping)
    rule_target bus -> target                           (EventBridge rule)
    subscribe   topic -> endpoint                       (SNS subscription)
    invoke      api -> function
    publish     function -> bus                         (inferred from IAM)
    writes      function -> table/database              (inferred from IAM/env)
    redrive     queue -> dead-letter queue
    dlq         function -> dead-letter queue/topic
    on_failure  esm/function -> failure destination

`publish` and `writes` are inferred rather than declared, so they carry
`inferred=True`. Rules that lean on them must downgrade severity accordingly —
a BLOCK built on a guess is how a scanner loses a prospect's trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator

import networkx as nx

from . import model as m
from .intrinsics import ensure_list, referenced_ids, resolve
from .parse import Template

DELIVERY_EDGES = frozenset({"poll", "rule_target", "subscribe", "invoke"})
FAILURE_EDGES = frozenset({"redrive", "dlq", "on_failure"})

_PUBLISH_ACTIONS = ("events:putevents", "events:*")


@dataclass
class Edge:
    source: str
    target: str
    kind: str
    via: str | None = None  # logical ID of the ESM / rule / subscription carrying it
    inferred: bool = False
    props: dict[str, Any] = field(default_factory=dict)


class EventGraph:
    def __init__(self, template: Template) -> None:
        self.template = template
        self.g = nx.MultiDiGraph()
        self._build()

    # -- construction -------------------------------------------------

    def _build(self) -> None:
        for resource in self.template:
            self.g.add_node(resource.logical_id, resource=resource)

        for resource in list(self.template):
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
                case _:
                    pass

    def _add(self, source: Any, target: Any, kind: str, **kw: Any) -> None:
        """Add an edge only when both ends resolve to resources in this template.

        Cross-stack and imported references are dropped on purpose: a finding
        we cannot show both sides of is a finding we cannot defend.
        """
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
        if source is not None and esm.source_kind is m.Kind.UNKNOWN:
            esm.source_kind = source.kind
        if source is not None and target is not None:
            self._add(source, target, "poll", via=esm.logical_id)
        failure = self.template.resolve_ref(esm.on_failure)
        if failure is not None:
            self._add(esm.logical_id if esm.logical_id in self.g else target, failure, "on_failure", via=esm.logical_id)

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
            if bus is not None:
                self._add(bus, target, "rule_target", via=rule.logical_id, props=props)
            else:
                # default bus: rule has no node of its own, hang the edge off the rule
                self._add(rule.logical_id, target, "rule_target", via=rule.logical_id, props=props)

    def _add_subscription(self, subscription: m.Subscription) -> None:
        topic = self.template.resolve_ref(subscription.topic)
        endpoint = self.template.resolve_ref(subscription.endpoint)
        if topic is not None and endpoint is not None:
            self._add(topic, endpoint, "subscribe", via=subscription.logical_id)

    def _add_redrive(self, queue: m.Queue) -> None:
        dlq = self.template.resolve_ref(queue.redrive_target)
        if dlq is not None:
            self._add(queue, dlq, "redrive", props={"max_receive_count": queue.max_receive_count})

    def _add_function_edges(self, function: m.Function) -> None:
        dlq = self.template.resolve_ref(function.dead_letter_queue)
        if dlq is not None:
            self._add(function, dlq, "dlq")
        failure = self.template.resolve_ref(function.on_failure)
        if failure is not None:
            self._add(function, failure, "on_failure")

        permitted, mentioned = self._iam_referenced(function)
        for target_id in permitted | mentioned:
            target = self.template.get(target_id)
            if target is None:
                continue
            if target.kind in (m.Kind.TABLE, m.Kind.DATABASE):
                # A write edge requires permission. An environment variable naming
                # the table proves only that someone pasted a config value —
                # Globals blocks hand it to every function in the stack.
                if target_id not in permitted:
                    continue
                self._add(function, target, "writes", inferred=True, props={"basis": "iam-policy"})
            elif target.kind is m.Kind.BUS and target_id in permitted and self._can_publish(function):
                self._add(function, target, "publish", inferred=True, props={"basis": "iam-policy"})

        api = self.template.get(f"{function.logical_id}#Api")
        if api is not None:
            self._add(api, function, "invoke")

    def _iam_referenced(self, function: m.Function) -> tuple[set[str], set[str]]:
        """(permission-backed, merely-mentioned) logical IDs for a function.

        The split matters: `Globals: Environment` gives every function in the
        stack the same variables, so an environment mention is not evidence
        that this function touches that resource. Permissions are.
        """
        permitted = referenced_ids(function.prop("Policies"))
        role = self.template.resolve_ref(function.ref("Role"))
        if isinstance(role, m.Role):
            permitted |= referenced_ids(role.prop("Policies"))
        mentioned = referenced_ids(function.prop("Environment")) - permitted
        return permitted, mentioned

    def _can_publish(self, function: m.Function) -> bool:
        blob = str(function.prop("Policies")).lower()
        role = self.template.resolve_ref(function.ref("Role"))
        if isinstance(role, m.Role):
            blob += str(role.prop("Policies")).lower()
        return any(action in blob for action in _PUBLISH_ACTIONS) or "eventbridgeputeventspolicy" in blob

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
        return [e for e in self.edges(kind) if e.source == logical_id]

    def in_edges(self, logical_id: str, kind: str | None = None) -> list[Edge]:
        return [e for e in self.edges(kind) if e.target == logical_id]

    def consumers_of(self, logical_id: str) -> list[tuple[m.EventSourceMapping, m.Function]]:
        """Every (event source mapping, consuming function) pair for a queue/stream."""
        pairs = []
        for edge in self.out_edges(logical_id, "poll"):
            esm = self.template.get(edge.via)
            function = self.node(edge.target)
            if isinstance(esm, m.EventSourceMapping) and isinstance(function, m.Function):
                pairs.append((esm, function))
        return pairs

    def async_invokers_of(self, logical_id: str) -> list[Edge]:
        """Edges that invoke a function asynchronously — the paths where a missing
        failure destination means events vanish without trace."""
        return [e for e in self.in_edges(logical_id) if e.kind in ("rule_target", "subscribe")]

    def has_failure_path(self, logical_id: str) -> bool:
        return any(e.kind in FAILURE_EDGES for e in self.out_edges(logical_id))

    def to_mermaid(self) -> str:
        """Architecture diagram for the report. Every paid deliverable opens with this."""
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
        drawn = {e.source for e in self.edges()} | {e.target for e in self.edges()}
        for logical_id in sorted(drawn):
            resource = self.node(logical_id)
            if resource is None:
                continue
            shape = shapes.get(resource.kind, "[{}]")
            safe = logical_id.replace("#", "_")
            lines.append(f"    {safe}{shape.format(logical_id)}")
        for edge in self.edges():
            style = "-.->" if edge.kind in FAILURE_EDGES or edge.inferred else "-->"
            lines.append(
                f"    {edge.source.replace('#', '_')} {style}|{edge.kind}| {edge.target.replace('#', '_')}"
            )
        return "\n".join(lines)


def build(template: Template) -> EventGraph:
    return EventGraph(template)


__all__ = ["EventGraph", "Edge", "build", "DELIVERY_EDGES", "FAILURE_EDGES", "ensure_list"]
