"""EDA012 — a hub that accepts events and routes them nowhere."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import Kind
from .base import Rule, register, remediation


@register
class EDA012(Rule):
    id = "EDA012"
    severity = Severity.BLOCK
    title = "Events are published to a hub with no delivery route"
    condition = "Every event published to this topic or bus."

    def check(self, graph):
        """SNS and EventBridge both accept a publish that matches nothing and
        return success. The producer's metrics show delivery; no consumer ever
        runs. This is the one failure mode with no error anywhere to find.
        """
        for hub in graph.resources(Kind.TOPIC, Kind.BUS):
            producers = [
                edge for edge in graph.in_edges(hub.logical_id) if edge.kind == "publish"
            ]
            if not producers:
                continue
            if graph.delivery_routes(hub.logical_id):
                continue
            if hub.logical_id in graph.template.exports:
                # Exported, so a consumer may live in a stack this scan cannot
                # see. Absence of a local route stops being evidence.
                continue

            publishers = sorted({edge.source for edge in producers})
            noun = "topic" if hub.kind is Kind.TOPIC else "event bus"
            route = "subscription" if hub.kind is Kind.TOPIC else "rule"

            fix = remediation(
                graph,
                hub,
                description=(
                    f"Add the {route} that delivers these events to their consumer, or remove "
                    f"the {noun} and the publish permission that feeds it."
                ),
            )
            yield Finding(
                rule_id=self.id,
                severity=self.severity,
                title=self.title,
                message=(
                    f"BLOCK: {hub.logical_id} receives events from {', '.join(publishers)}, while "
                    f"no {route} routes anything out of it and its ARN is not exported, so nothing "
                    f"outside this template can reach it either. Required: at least one {route} "
                    f"delivering to a consumer. Consequence: every published event is accepted, "
                    f"counted as delivered, and discarded because it matches no destination — the "
                    f"one failure mode that raises no error anywhere."
                ),
                resources=[hub.logical_id, *publishers],
                evidence={
                    f"{hub.logical_id}.publishers": publishers,
                    f"{hub.logical_id}.delivery_routes": [],
                    f"{hub.logical_id}.exported": False,
                    "publish_edge_basis": sorted(
                        {(edge.props or {}).get("basis", "template") for edge in producers}
                    ),
                },
                inferred=any(edge.inferred for edge in producers),
                patch_hint=f"Add a {route} that delivers {hub.logical_id} events to a consumer.",
                remediations=[fix],
            )
