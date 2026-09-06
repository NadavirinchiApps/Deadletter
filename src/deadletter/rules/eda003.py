"""EDA003 — batched consumer without partial batch failure reporting."""

from __future__ import annotations

from ..findings import Basis, Confidence, Finding, Impact
from ..model import EventSourceMapping, Kind
from .base import Rule, register, remediation


@register
class EDA003(Rule):
    id = "EDA003"
    impact = Impact.DUPLICATION
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
                    impact=self.impact,
                    confidence=Confidence.UNASSESSED,
                    title=self.title,
                    message=(
                        f"{esm.logical_id} BatchSize is unresolved, so Deadletter cannot "
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
            size_text = (
                f"BatchSize is {batch_size}"
                if esm.batch_size_declared
                else f"BatchSize is unset, so AWS applies its default of {batch_size}"
            )
            yield Finding(
                rule_id=self.id,
                impact=self.impact,
                # Whole-batch redelivery on a partial failure is documented AWS
                # behaviour, not a prediction. Whether it *harms* anything
                # depends on whether the handler is idempotent, which no
                # template states — so this is advice, not a violation.
                basis=Basis.RECOMMENDATION,
                defaults_relied_on=(
                    [] if esm.batch_size_declared else [f"{esm.logical_id}.BatchSize"]
                ),
                title=self.title,
                message=(
                    f"{esm.logical_id} {size_text}, while "
                    f"FunctionResponseTypes is {esm.function_response_types or 'unset'}. "
                    f"Required: ReportBatchItemFailures, unless {target.logical_id} is "
                    f"idempotent for these records. Consequence: one failing record fails "
                    f"the whole batch, so up to {batch_size - 1} records that already "
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
