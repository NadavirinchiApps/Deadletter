"""EDA004 — recursive event loop through a bus or topic.

Severity is graded rather than fixed, deliberately. A cycle through a rule
with *no* filtering is a near-certain loop and blocks. A cycle through a rule
that filters on source or detail-type can only close if the function re-emits
a matching event, which no static analysis can prove — that is a WARN, not a
BLOCK. Firing BLOCK on every filtered cycle would cry wolf on ordinary
templates, and a false BLOCK in front of a prospect costs more than a missed
rule.
"""

from __future__ import annotations

import networkx as nx

from ..findings import Finding, Severity
from ..model import Kind
from .base import Rule, register

CYCLE_EDGES = {"poll", "rule_target", "subscribe", "invoke", "publish"}
FILTER_KEYS = ("source", "detail-type", "detail")


@register
class EDA004(Rule):
    id = "EDA004"
    severity = Severity.BLOCK
    title = "Recursive event loop"
    condition = "Any event that re-enters the bus it was delivered from."

    def check(self, graph):
        loop_graph = nx.DiGraph()
        carriers: dict[tuple[str, str], str | None] = {}
        for edge in graph.edges():
            if edge.kind in CYCLE_EDGES:
                loop_graph.add_edge(edge.source, edge.target)
                carriers.setdefault((edge.source, edge.target), edge.via)

        for cycle in nx.simple_cycles(loop_graph):
            hubs = [n for n in cycle if graph.node(n) and graph.node(n).kind in (Kind.BUS, Kind.TOPIC)]
            if not hubs:
                continue  # a cycle with no fan-out hub cannot amplify
            hub = hubs[0]
            if self._proves_exclusion(graph, cycle, carriers):
                continue  # anything-but is the only clause that statically closes the loop
            filters = self._filters_on(graph, cycle, carriers)
            severity = Severity.WARN if filters else Severity.BLOCK
            verdict = "WARN" if filters else "BLOCK"
            path = " -> ".join([*cycle, cycle[0]])
            guard = (
                f"the rule pattern filters on {', '.join(sorted(filters))}"
                if filters
                else "the rule pattern applies no source or detail-type filter"
            )
            yield Finding(
                rule_id=self.id,
                severity=severity,
                title=self.title,
                message=(
                    f"{verdict}: events delivered from {hub} can return to it via "
                    f"{path}, while {guard}. Required: a filter excluding the "
                    f"consumer's own emissions, or removal of the return edge. "
                    f"Consequence: each event can re-trigger the cycle, multiplying "
                    f"invocations and cost without bound until throttling stops it."
                ),
                resources=list(dict.fromkeys(cycle)),
                evidence={
                    "cycle": path,
                    "hub": hub,
                    "pattern_filters": sorted(filters) or None,
                    "carriers": [c for c in (carriers.get(pair) for pair in zip(cycle, cycle[1:] + cycle[:1])) if c],
                },
                inferred=True,
                patch_hint=(
                    "  # exclude the consumer's own source from the rule pattern\n"
                    "    EventPattern:\n"
                    "      source:\n"
                    "+       - anything-but: <consumer source>"
                ),
            )

    def _filters_on(self, graph, cycle, carriers) -> set[str]:
        """Which pattern keys narrow the rules involved in this cycle."""
        found: set[str] = set()
        pairs = list(zip(cycle, cycle[1:] + cycle[:1]))
        for pair in pairs:
            rule = graph.template.get(carriers.get(pair))
            if rule is None or rule.kind is not Kind.RULE:
                continue
            found |= {k for k in FILTER_KEYS if k in getattr(rule, "pattern", {})}
        return found

    def _proves_exclusion(self, graph, cycle, carriers) -> bool:
        """An `anything-but` clause is the only thing in an EventPattern that
        proves, without knowing what the consumer emits, that its own events
        cannot match. Everything else merely narrows the pattern."""
        for pair in zip(cycle, cycle[1:] + cycle[:1]):
            rule = graph.template.get(carriers.get(pair))
            if rule is None or rule.kind is not Kind.RULE:
                continue
            if _has_anything_but(getattr(rule, "pattern", {})):
                return True
        return False


def _has_anything_but(node) -> bool:
    if isinstance(node, dict):
        return "anything-but" in node or any(_has_anything_but(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_anything_but(v) for v in node)
    return False
