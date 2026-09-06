"""EDA012 — a hub that accepts events and routes them nowhere."""

from __future__ import annotations

from ..findings import Basis, Confidence, Finding, Impact
from ..model import Kind
from .base import Rule, register, remediation


@register
class EDA012(Rule):
    id = "EDA012"
    impact = Impact.LOSS
    title = "Events are published to a hub with no delivery route"
    condition = "Every event published to this topic or bus."

    def check(self, graph):
        """SNS and EventBridge both accept a publish that matches nothing and
        return success. The producer's metrics show delivery; no consumer ever
        runs. This is the one failure mode with no error anywhere to find.

        Two limits on what this rule can prove, both stated on the finding
        rather than hidden behind a confident message:

        A missing CloudFormation export is *not* proof of no external consumer.
        A subscription in another stack can name the topic ARN directly. The
        export check stays because it is a useful signal that the author did not
        intend outside use — but the finding says "confirm", not "nothing can
        reach it", which is what it used to say and was wrong.

        A publish edge derived from an IAM policy shows a principal is permitted
        to publish, not that it does. That lowers confidence to INFERRED, so the
        default policy warns rather than blocking.
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
                # Exported, so a consumer very likely lives in a stack this scan
                # cannot see. Absence of a local route stops being a signal.
                continue

            publishers = sorted({edge.source for edge in producers})
            noun = "topic" if hub.kind is Kind.TOPIC else "event bus"
            route = "subscription" if hub.kind is Kind.TOPIC else "rule"
            inferred = any(edge.inferred for edge in producers)

            basis_note = (
                f"{', '.join(publishers)} holds permission to publish to it, which does "
                f"not establish that it does"
                if inferred
                else f"{', '.join(publishers)} publishes to it"
            )

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
                impact=self.impact,
                basis=Basis.REQUIREMENT,
                confidence=Confidence.INFERRED if inferred else Confidence.CONFIRMED,
                title=self.title,
                message=(
                    f"{hub.logical_id} has no {route} routing anything out of it, while "
                    f"{basis_note}. Its ARN is also not exported, so this template shows no "
                    f"intended consumer anywhere. Required: at least one {route} delivering "
                    f"to a consumer, or confirmation that a consumer outside this template "
                    f"subscribes using the ARN directly — which needs no export and this "
                    f"scan cannot see. Consequence: if there is no such consumer, every "
                    f"published event is accepted, counted as delivered, and discarded "
                    f"because it matches no destination — the one failure mode that raises "
                    f"no error anywhere."
                ),
                resources=[hub.logical_id, *publishers],
                evidence={
                    f"{hub.logical_id}.publishers": publishers,
                    f"{hub.logical_id}.delivery_routes": [],
                    f"{hub.logical_id}.exported": False,
                    "external_subscribers_visible_to_this_scan": False,
                    "publish_edge_basis": sorted(
                        {(edge.props or {}).get("basis", "template") for edge in producers}
                    ),
                },
                patch_hint=f"Add a {route} that delivers {hub.logical_id} events to a consumer.",
                remediations=[fix],
            )
