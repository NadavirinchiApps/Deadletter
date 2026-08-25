"""EDA005 — poison record blocks a stream shard."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import EventSourceMapping, Kind
from .base import Rule, register, remediation

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
            record_age = esm.maximum_record_age
            retry_declared = esm.prop("MaximumRetryAttempts") is not None
            age_declared = esm.prop("MaximumRecordAgeInSeconds") is not None
            unresolved = (
                (retry_declared and retries is None)
                or (age_declared and record_age is None)
            )
            target = graph.template.resolve_ref(esm.target)
            if target is None:
                continue
            if unresolved:
                yield Finding(
                    rule_id=self.id,
                    severity=Severity.WARN,
                    title=self.title,
                    message=(
                        f"WARN: {esm.logical_id} has an unresolved stream retry or record-age "
                        f"limit. Required: verify MaximumRetryAttempts or MaximumRecordAgeInSeconds "
                        f"is finite. Consequence: an unbounded poison record can pause its shard."
                    ),
                    resources=[esm.logical_id, source.logical_id, target.logical_id],
                    evidence={
                        f"{esm.logical_id}.MaximumRetryAttempts": esm.raw_prop("MaximumRetryAttempts"),
                        f"{esm.logical_id}.MaximumRecordAgeInSeconds": esm.raw_prop(
                            "MaximumRecordAgeInSeconds"
                        ),
                    },
                )
                continue

            bounded = (retries is not None and retries >= 0) or (
                record_age is not None and record_age >= 0
            )
            recoverable = bool(esm.on_failure)
            if bounded and recoverable:
                continue

            retry_fix = remediation(
                graph,
                esm,
                "MaximumRetryAttempts",
                description="Set a finite stream retry limit.",
                suggested_value=3,
            )
            destination_fix = remediation(
                graph,
                esm,
                "DestinationConfig",
                "OnFailure",
                description="Send discarded stream records to an SQS queue or SNS topic.",
                suggested_value={
                    "Destination": {"Fn::GetAtt": [f"{esm.origin or esm.logical_id}FailureDlq", "Arn"]}
                },
            )
            severity = Severity.BLOCK if not bounded else Severity.WARN
            if bounded:
                message = (
                    f"WARN: {esm.logical_id} has a finite retry/record-age limit but no OnFailure "
                    f"destination. Required: preserve discarded records in SQS or SNS. Consequence: "
                    f"the shard recovers, but the poison record is discarded without a replay path."
                )
                fixes = [destination_fix]
            else:
                message = (
                    f"BLOCK: {esm.logical_id} reads from {source.logical_id} with "
                    f"MaximumRetryAttempts {retries if retries is not None else 'unset (infinite)'} "
                    f"and MaximumRecordAgeInSeconds "
                    f"{record_age if record_age is not None else 'unset (infinite)'}. Required: a "
                    f"finite retry count or record age plus an OnFailure destination. Consequence: "
                    f"one unprocessable record is retried until source retention expires and later "
                    f"records on that shard wait behind it."
                )
                fixes = [retry_fix, destination_fix]
            yield Finding(
                rule_id=self.id,
                severity=severity,
                title=self.title,
                message=message,
                resources=[esm.logical_id, source.logical_id, target.logical_id],
                evidence={
                    f"{esm.logical_id}.BisectBatchOnFunctionError": esm.bisect_on_error,
                    f"{esm.logical_id}.MaximumRetryAttempts": retries,
                    f"{esm.logical_id}.MaximumRecordAgeInSeconds": record_age,
                    f"{esm.logical_id}.DestinationConfig.OnFailure": None if not esm.on_failure else "set",
                    f"{esm.logical_id}.BatchSize": esm.batch_size,
                    "source_kind": str(source.kind),
                },
                patch_hint="; ".join(f"Update {fix.path}" for fix in fixes) + ".",
                remediations=fixes,
            )
