"""EDA003 — batched consumer without partial batch failure reporting."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import EventSourceMapping, Kind
from .base import Rule, register, remediation


@register
class EDA003(Rule):
    id = "EDA003"
    severity = Severity.BLOCK
    title = "Batch reprocessed wholesale on a single record failure"
    condition = "Any batch in which at least one record fails."

    def check(self, graph):
        for esm in graph.resources(Kind.ESM):
            if not isinstance(esm, EventSourceMapping):
                continue
            batch_size = esm.batch_size
            if batch_size is None and esm.batch_size_declared:
                yield Finding(
                    rule_id=self.id,
                    severity=Severity.WARN,
                    title=self.title,
                    message=(
                        f"WARN: {esm.logical_id} BatchSize is unresolved, so Deadletter cannot "
                        f"verify whether whole-batch retries can replay successful records. "
                        f"Required: resolve BatchSize and configure ReportBatchItemFailures when "
                        f"it exceeds 1. Consequence: duplicate side effects may be hidden."
                    ),
                    resources=[esm.logical_id],
                    evidence={f"{esm.logical_id}.BatchSize": esm.raw_prop("BatchSize")},
                )
                continue
            if not batch_size or batch_size <= 1 or esm.reports_batch_item_failures:
                continue
            source = graph.template.resolve_ref(esm.source)
            target = graph.template.resolve_ref(esm.target)
            if source is None or target is None:
                continue
            fix = remediation(
                graph,
                esm,
                "FunctionResponseTypes",
                description=(
                    "Enable ReportBatchItemFailures and update the handler to return failed item identifiers."
                ),
                suggested_value=["ReportBatchItemFailures"],
            )
            yield Finding(
                rule_id=self.id,
                severity=self.severity,
                title=self.title,
                message=(
                    f"BLOCK: {esm.logical_id} BatchSize is {batch_size}, while "
                    f"FunctionResponseTypes is {esm.function_response_types or 'unset'}. "
                    f"Required: ReportBatchItemFailures. Consequence: one failing record "
                    f"fails the whole batch, so up to {batch_size - 1} records that already "
                    f"succeeded in {target.logical_id} are delivered again — duplicate side "
                    f"effects on every retry."
                ),
                resources=[esm.logical_id, source.logical_id, target.logical_id],
                evidence={
                    f"{esm.logical_id}.BatchSize": batch_size,
                    f"{esm.logical_id}.FunctionResponseTypes": esm.function_response_types or None,
                    "batch_size_declared": esm.batch_size_declared,
                    "source": source.logical_id,
                    "consumer": target.logical_id,
                },
                patch_hint=(
                    f"Set {fix.path} to ['ReportBatchItemFailures'] and update the handler response."
                ),
                remediations=[fix],
            )
