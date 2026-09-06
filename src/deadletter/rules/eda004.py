"""EDA004 - recursive event loop through an EventBridge bus or SNS topic."""

from __future__ import annotations

import networkx as nx

from ..findings import Basis, Confidence, Finding, Impact
from ..model import Kind, Rule as EventRule
from .base import Rule, register, remediation

CYCLE_EDGES = {"poll", "rule_target", "subscribe", "invoke", "publish"}
FILTER_KEYS = ("source", "detail-type", "detail")


@register
class EDA004(Rule):
    id = "EDA004"
    impact = Impact.STALL
    title = "Recursive event loop"
    condition = "Any event that re-enters the hub it was delivered from."

    def check(self, graph):
        """Emit at most one representative finding per strongly connected component.

        Enumerating every simple cycle is exponential on dense templates. Strongly
        connected components identify the same risk in linear time. A filter only
        downgrades the result: without emitted event values, no template-only scan
        can prove that an ``anything-but`` clause excludes the producer.
        """
        loop_graph = nx.DiGraph()
        carriers: dict[tuple[str, str], list[str]] = {}
        for edge in graph.edges():
            if edge.kind not in CYCLE_EDGES:
                continue
            loop_graph.add_edge(edge.source, edge.target)
            if edge.via:
                carriers.setdefault((edge.source, edge.target), []).append(edge.via)

        components = [
            component
            for component in nx.strongly_connected_components(loop_graph)
            if len(component) > 1
        ]
        for component in sorted(components, key=lambda nodes: sorted(nodes)):
            hubs = sorted(
                node
                for node in component
                if graph.node(node) and graph.node(node).kind in (Kind.BUS, Kind.TOPIC)
            )
            if not hubs:
                continue
            hub = hubs[0]
            cycle = _representative_cycle(loop_graph, component, hub)
            if not cycle:
                continue

            routes = [
                edge
                for edge in graph.edges()
                if edge.kind in ("rule_target", "subscribe")
                and edge.source in component
                and edge.target in component
            ]
            rules = self._rules_in_component(graph, component)
            filters = {
                key
                for rule in rules
                for key in FILTER_KEYS
                if key in rule.pattern
            }
            all_routes_filtered = bool(routes) and all(
                edge.kind == "rule_target"
                and isinstance(graph.template.get(edge.via), EventRule)
                and any(
                    key in graph.template.get(edge.via).pattern
                    for key in FILTER_KEYS
                )
                for edge in routes
            )
            # A filter on every route may well break the cycle. Whether it does
            # depends on values the consumer emits at runtime, which no
            # template-only scan can read — so this rests on an assumption, and
            # says so rather than quietly softening the wording.
            # Never CONFIRMED: the return edge that closes a cycle is usually an
            # IAM-derived publish, which shows the consumer *may* publish back,
            # not that it does.
            confidence = Confidence.ASSUMED if all_routes_filtered else Confidence.INFERRED
            assumptions = (
                [
                    "The event values this cycle's consumers emit are not visible to a "
                    "template scan, so no filter on the return path can be shown to exclude them."
                ]
                if all_routes_filtered
                else []
            )
            path = " -> ".join([*cycle, cycle[0]])
            guard = (
                f"rule patterns filter on {', '.join(sorted(filters))}, but the emitted values are unknown"
                if filters
                else "at least one route has no source, detail-type, or detail filter"
            )

            fixes = [
                remediation(
                    graph,
                    rule,
                    "Pattern" if rule.raw_prop("Pattern") is not None else "EventPattern",
                    description=(
                        "Add a producer-specific exclusion that is verified against the values "
                        "the consumer publishes, or remove its publish permission."
                    ),
                    suggested_value={
                        "source": [{"anything-but": "REPLACE_WITH_CONSUMER_EMITTED_SOURCE"}]
                    },
                )
                for rule in rules
            ]
            carrier_names = sorted(
                {
                    carrier
                    for pair, names in carriers.items()
                    if pair[0] in component and pair[1] in component
                    for carrier in names
                }
            )
            yield Finding(
                rule_id=self.id,
                impact=self.impact,
                confidence=confidence,
                assumptions=assumptions,
                title=self.title,
                message=(
                    f"events delivered from {hub} can return to it via {path}, while "
                    f"{guard}. Required: verify a filter excludes the consumer's own emissions, "
                    f"or remove the return edge. Consequence: each matching event can re-trigger "
                    f"the cycle, multiplying invocations and cost until throttling stops it."
                ),
                resources=list(dict.fromkeys(cycle)),
                evidence={
                    "cycle": path,
                    "hub": hub,
                    "pattern_filters": sorted(filters) or None,
                    "carriers": carrier_names,
                    "analysis": "strongly-connected-component",
                },
                patch_hint=(
                    f"Verify and update {fixes[0].path}." if fixes else "Remove the inferred publish return edge."
                ),
                remediations=fixes,
            )

    @staticmethod
    def _rules_in_component(graph, component: set[str]) -> list[EventRule]:
        rules: dict[str, EventRule] = {}
        for edge in graph.edges("rule_target"):
            if edge.source not in component or edge.target not in component or not edge.via:
                continue
            carrier = graph.template.get(edge.via)
            if isinstance(carrier, EventRule):
                rules[carrier.logical_id] = carrier
        return [rules[name] for name in sorted(rules)]


def _representative_cycle(graph: nx.DiGraph, component: set[str], hub: str) -> list[str]:
    subgraph = graph.subgraph(component)
    for successor in sorted(subgraph.successors(hub)):
        try:
            return [hub, *nx.shortest_path(subgraph, successor, hub)[:-1]]
        except nx.NetworkXNoPath:
            continue
    return []
