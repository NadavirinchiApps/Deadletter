"""EDA011 — a synchronous handler allowed to outlive its API integration."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import (
    HTTP_API_INTEGRATION_TIMEOUT,
    REST_API_INTEGRATION_TIMEOUT,
    Function,
    Kind,
)
from .base import Rule, register, remediation


@register
class EDA011(Rule):
    id = "EDA011"
    severity = Severity.BLOCK
    title = "Handler outlives the API integration timeout"
    condition = "Any request whose handler runs past the integration timeout."

    def check(self, graph):
        """API Gateway stops waiting at a fixed limit; Lambda does not stop
        working. The caller is told the request failed while the side effects
        it asked for are still being committed.
        """
        for edge in graph.edges("invoke"):
            carrier = graph.template.get(edge.via)
            if carrier is None or carrier.kind is not Kind.API:
                continue
            function = graph.node(edge.target)
            if not isinstance(function, Function):
                continue

            http = str(carrier.prop("DeadletterEventType")) == "HttpApi" or (
                carrier.cfn_type == "AWS::Serverless::HttpApi"
            )
            limit = HTTP_API_INTEGRATION_TIMEOUT if http else REST_API_INTEGRATION_TIMEOUT
            flavour = "HTTP" if http else "REST"
            timeout = function.timeout

            if timeout is None:
                yield Finding(
                    rule_id=self.id,
                    severity=Severity.WARN,
                    title=self.title,
                    message=(
                        f"WARN: cannot verify that {function.logical_id} finishes inside the "
                        f"{limit}s {flavour} API integration timeout because its Timeout is "
                        f"unresolved. Required: resolve the deployment value and verify Timeout is "
                        f"at most {limit}s. Consequence: a handler that outlives the integration "
                        f"returns 504 while it keeps running."
                    ),
                    resources=[function.logical_id, edge.source, carrier.logical_id],
                    evidence={
                        f"{function.logical_id}.Timeout": function.raw_prop("Timeout"),
                        "integration_timeout": limit,
                    },
                )
                continue

            if timeout <= limit:
                continue

            fix = remediation(
                graph,
                function,
                "Timeout",
                description=(
                    f"Set Timeout to at most {limit} seconds, or move the work off the request "
                    f"path and return an identifier the caller can poll."
                ),
                suggested_value=limit,
            )
            yield Finding(
                rule_id=self.id,
                severity=self.severity,
                title=self.title,
                message=(
                    f"BLOCK: {function.logical_id} Timeout is {timeout}s, while "
                    f"{carrier.logical_id} invokes it through a {flavour} API whose integration "
                    f"gives up at {limit}s. Required: at most {limit}s. Consequence: past {limit}s "
                    f"the caller receives 504 while the invocation runs on to completion, so a "
                    f"client retry repeats work that already succeeded and was never reported."
                ),
                resources=[function.logical_id, carrier.logical_id, edge.source],
                evidence={
                    f"{function.logical_id}.Timeout": timeout,
                    f"{function.logical_id}.Timeout_declared": function.timeout_declared,
                    f"{carrier.logical_id}.Type": carrier.prop("DeadletterEventType") or carrier.cfn_type,
                    f"{carrier.logical_id}.Path": carrier.prop("Path"),
                    f"{carrier.logical_id}.Method": carrier.prop("Method"),
                    "integration_timeout": limit,
                },
                patch_hint=f"Set {fix.path} to {limit} (Timeout: {limit}).",
                remediations=[fix],
            )
