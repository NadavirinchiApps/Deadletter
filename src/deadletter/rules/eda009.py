"""EDA009 — too many shared-throughput readers on one stream shard."""

from __future__ import annotations

from ..findings import Finding, Severity
from ..model import STREAM_SHARED_CONSUMER_LIMIT, Kind, Stream, Table
from .base import Rule, register, remediation


@register
class EDA009(Rule):
    id = "EDA009"
    severity = Severity.BLOCK
    title = "Stream shard is read by too many shared-throughput consumers"
    condition = "Any sustained throughput near the shard's read limit."

    def check(self, graph):
        """A shard serves 2 MB/s of reads shared across every consumer that
        polls it directly. Kinesis and DynamoDB Streams both document two as
        the practical ceiling; a third reader takes throughput from the other
        two rather than adding any.
        """
        for source in graph.resources(Kind.STREAM, Kind.TABLE):
            if isinstance(source, Table) and not source.stream_enabled:
                continue

            shared = [
                edge
                for edge in graph.out_edges(source.logical_id, "poll")
                if not (edge.props or {}).get("enhanced_fan_out")
            ]
            fan_out = [
                edge
                for edge in graph.out_edges(source.logical_id, "poll")
                if (edge.props or {}).get("enhanced_fan_out")
            ]
            if len(shared) <= STREAM_SHARED_CONSUMER_LIMIT:
                continue

            readers = sorted({edge.via or edge.target for edge in shared})
            consumers = sorted({edge.target for edge in shared})
            shards = source.shard_count if isinstance(source, Stream) else None
            capacity = (
                f"its {shards} shard(s) serve" if shards is not None else "one shard serves"
            )

            last = graph.template.get(readers[-1])
            fix = remediation(
                graph,
                last if last is not None else source,
                "EventSourceArn",
                description=(
                    "Give this reader its own throughput with an "
                    "AWS::Kinesis::StreamConsumer (enhanced fan-out), or fold it into an existing "
                    "consumer so the shard is shared by at most two."
                ),
            )
            yield Finding(
                rule_id=self.id,
                severity=self.severity,
                title=self.title,
                message=(
                    f"BLOCK: {source.logical_id} is polled by {len(shared)} shared-throughput "
                    f"readers ({', '.join(readers)}), while {capacity} 2 MB/s across all of them. "
                    f"Required: at most {STREAM_SHARED_CONSUMER_LIMIT} shared readers, or enhanced "
                    f"fan-out for the rest. Consequence: their GetRecords calls compete for the "
                    f"same read budget, every consumer's iterator age climbs together, and records "
                    f"expire from the stream before the slowest reader reaches them."
                ),
                resources=[source.logical_id, *readers, *consumers],
                evidence={
                    f"{source.logical_id}.shared_throughput_readers": readers,
                    f"{source.logical_id}.enhanced_fan_out_readers": sorted(
                        {edge.via or edge.target for edge in fan_out}
                    ),
                    f"{source.logical_id}.ShardCount": shards,
                    f"{source.logical_id}.StreamMode": (
                        "ON_DEMAND" if isinstance(source, Stream) and source.on_demand else "PROVISIONED"
                    ),
                    "shared_reader_limit": STREAM_SHARED_CONSUMER_LIMIT,
                },
                patch_hint=(
                    f"Move {readers[-1]} to enhanced fan-out, or reduce the number of direct "
                    f"readers on {source.logical_id}."
                ),
                remediations=[fix],
            )
