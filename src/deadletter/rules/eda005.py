"""EDA005 — poison record blocks a stream shard."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import EventSourceMapping, Kind
from .base import Rule, register

STREAM_SOURCES = {Kind.STREAM, Kind.TABLE}


@register
class EDA005(Rule):
    id = "EDA005"
    severity = Severity.BLOCK
    title = "Poison record blocks the shard until expiry"
    condition = "Any record the consumer cannot process."

    def check(self, graph):
        for esm in graph.resources(Kind.ESM):
            if not isinstance(esm, EventSourceMapping):
                continue
            source = graph.template.resolve_ref(esm.source)
            if source is None or source.kind not in STREAM_SOURCES:
                continue  # SQS failure handling is EDA002's territory
            retries = esm.maximum_retry_attempts
            bounded = retries is not None and retries >= 0
            if esm.bisect_on_error and bounded:
                continue
            if bounded and esm.on_failure:
                continue
            target = graph.template.resolve_ref(esm.target)
            if target is None:
                continue
            yield Finding(
                rule_id=self.id,
                severity=self.severity,
                title=self.title,
                message=(
                    f"BLOCK: {esm.logical_id} reads from {source.logical_id} with "
                    f"BisectBatchOnFunctionError {esm.bisect_on_error} and MaximumRetryAttempts "
                    f"{retries if retries is not None else 'unset (infinite)'}, while no "
                    f"OnFailure destination is configured. Required: a bounded retry count "
                    f"plus either bisection or a failure destination. Consequence: a single "
                    f"unprocessable record is retried indefinitely and every later record on "
                    f"that shard waits behind it until the retention period expires."
                ),
                resources=[esm.logical_id, source.logical_id, target.logical_id],
                evidence={
                    f"{esm.logical_id}.BisectBatchOnFunctionError": esm.bisect_on_error,
                    f"{esm.logical_id}.MaximumRetryAttempts": retries,
                    f"{esm.logical_id}.DestinationConfig.OnFailure": None if not esm.on_failure else "set",
                    f"{esm.logical_id}.BatchSize": esm.batch_size,
                    "source_kind": str(source.kind),
                },
                patch_hint=(
                    f"  {esm.logical_id}:\n"
                    f"    Properties:\n"
                    f"+     BisectBatchOnFunctionError: true\n"
                    f"+     MaximumRetryAttempts: 3\n"
                    f"+     DestinationConfig:\n"
                    f"+       OnFailure:\n"
                    f"+         Destination: !GetAtt StreamFailureDlq.Arn"
                ),
            )
