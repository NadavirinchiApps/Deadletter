"""Typed resource objects.

Rules never touch raw template dicts. They ask a Queue for its
`visibility_timeout` and a Function for its `timeout`, and get either a real
value or None (meaning "template didn't say, so the AWS default applies").
Keeping the raw props around matters: findings quote the template verbatim,
and a finding that can't quote the config it objects to isn't credible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .intrinsics import Reference, as_bool, as_int, ensure_list, first, resolve


class Kind(StrEnum):
    FUNCTION = "function"
    QUEUE = "queue"
    TOPIC = "topic"
    BUS = "bus"
    RULE = "rule"
    ESM = "esm"
    SUBSCRIPTION = "subscription"
    STATE_MACHINE = "state_machine"
    STREAM = "stream"
    TABLE = "table"
    DATABASE = "database"
    ALARM = "alarm"
    ROLE = "role"
    API = "api"
    UNKNOWN = "unknown"


# AWS defaults that apply when a template stays silent. Several rules exist
# purely because these defaults are wrong for production.
LAMBDA_DEFAULT_TIMEOUT = 3
SQS_DEFAULT_VISIBILITY_TIMEOUT = 30
ASYNC_DEFAULT_MAX_EVENT_AGE = 21_600  # 6 hours
ASYNC_DEFAULT_RETRY_ATTEMPTS = 2


@dataclass
class Resource:
    logical_id: str
    cfn_type: str
    kind: Kind
    props: dict[str, Any] = field(default_factory=dict)
    synthetic: bool = False  # derived from a SAM Events block, not written literally
    origin: str | None = None  # logical ID of the resource that implied it

    def prop(self, *names: str, default: Any = None) -> Any:
        return first(*(self.props.get(n) for n in names)) if names else default

    def ref(self, *names: str) -> Reference:
        return resolve(self.prop(*names))

    @property
    def name_hint(self) -> str | None:
        """Physical name, when the template hardcodes one — used to match literal ARNs."""
        value = self.prop("QueueName", "TopicName", "FunctionName", "Name", "TableName", "StreamName")
        return value if isinstance(value, str) else None


@dataclass
class Function(Resource):
    @property
    def timeout(self) -> int:
        return as_int(self.prop("Timeout"), LAMBDA_DEFAULT_TIMEOUT) or LAMBDA_DEFAULT_TIMEOUT

    @property
    def timeout_declared(self) -> bool:
        return self.prop("Timeout") is not None

    @property
    def reserved_concurrency(self) -> int | None:
        return as_int(self.prop("ReservedConcurrentExecutions"))

    @property
    def dead_letter_queue(self) -> Reference:
        """SAM DeadLetterQueue.TargetArn or CFN DeadLetterConfig.TargetArn."""
        for block in (self.prop("DeadLetterQueue"), self.prop("DeadLetterConfig")):
            if isinstance(block, dict):
                target = resolve(first(block.get("TargetArn"), block.get("Arn")))
                if target:
                    return target
        return Reference()

    @property
    def on_failure(self) -> Reference:
        cfg = self.prop("EventInvokeConfig")
        if isinstance(cfg, dict):
            dest = cfg.get("DestinationConfig")
            if isinstance(dest, dict) and isinstance(dest.get("OnFailure"), dict):
                return resolve(dest["OnFailure"].get("Destination"))
        return Reference()

    @property
    def max_event_age(self) -> int | None:
        cfg = self.prop("EventInvokeConfig")
        return as_int(cfg.get("MaximumEventAgeInSeconds")) if isinstance(cfg, dict) else None

    @property
    def max_retry_attempts(self) -> int | None:
        cfg = self.prop("EventInvokeConfig")
        return as_int(cfg.get("MaximumRetryAttempts")) if isinstance(cfg, dict) else None


@dataclass
class Queue(Resource):
    @property
    def visibility_timeout(self) -> int:
        return as_int(self.prop("VisibilityTimeout"), SQS_DEFAULT_VISIBILITY_TIMEOUT) or SQS_DEFAULT_VISIBILITY_TIMEOUT

    @property
    def visibility_timeout_declared(self) -> bool:
        return self.prop("VisibilityTimeout") is not None

    @property
    def redrive_target(self) -> Reference:
        policy = self.prop("RedrivePolicy")
        if isinstance(policy, dict):
            return resolve(policy.get("deadLetterTargetArn"))
        return Reference()

    @property
    def max_receive_count(self) -> int | None:
        policy = self.prop("RedrivePolicy")
        return as_int(policy.get("maxReceiveCount")) if isinstance(policy, dict) else None


@dataclass
class EventSourceMapping(Resource):
    """Poll-based delivery: SQS / Kinesis / DynamoDB Streams -> Function.

    Covers both `AWS::Lambda::EventSourceMapping` and the SAM `Events:` blocks
    that compile down to one.
    """

    source: Reference = field(default_factory=Reference)
    target: Reference = field(default_factory=Reference)
    source_kind: Kind = Kind.UNKNOWN

    @property
    def batch_size(self) -> int | None:
        return as_int(self.prop("BatchSize"))

    @property
    def batching_window(self) -> int:
        return as_int(self.prop("MaximumBatchingWindowInSeconds"), 0) or 0

    @property
    def function_response_types(self) -> list[str]:
        return [str(t) for t in ensure_list(self.prop("FunctionResponseTypes"))]

    @property
    def reports_batch_item_failures(self) -> bool:
        return "ReportBatchItemFailures" in self.function_response_types

    @property
    def maximum_concurrency(self) -> int | None:
        config = self.prop("ScalingConfig")
        if isinstance(config, dict):
            return as_int(config.get("MaximumConcurrency"))
        return None

    @property
    def bisect_on_error(self) -> bool:
        return as_bool(self.prop("BisectBatchOnFunctionError"), False) or False

    @property
    def maximum_retry_attempts(self) -> int | None:
        return as_int(self.prop("MaximumRetryAttempts"))

    @property
    def on_failure(self) -> Reference:
        cfg = self.prop("DestinationConfig")
        if isinstance(cfg, dict) and isinstance(cfg.get("OnFailure"), dict):
            return resolve(cfg["OnFailure"].get("Destination"))
        return Reference()


@dataclass
class Rule(Resource):
    """EventBridge rule. Targets are resolved into the graph as delivery edges."""

    bus: Reference = field(default_factory=Reference)

    @property
    def pattern(self) -> dict[str, Any]:
        pattern = self.prop("EventPattern", "Pattern")
        return pattern if isinstance(pattern, dict) else {}

    @property
    def targets(self) -> list[dict[str, Any]]:
        return [t for t in ensure_list(self.prop("Targets")) if isinstance(t, dict)]


@dataclass
class Subscription(Resource):
    topic: Reference = field(default_factory=Reference)
    endpoint: Reference = field(default_factory=Reference)

    @property
    def protocol(self) -> str | None:
        value = self.prop("Protocol")
        return value if isinstance(value, str) else None

    @property
    def has_redrive(self) -> bool:
        return self.prop("RedrivePolicy") is not None


@dataclass
class StateMachine(Resource):
    @property
    def definition(self) -> dict[str, Any]:
        definition = self.prop("Definition", "DefinitionString")
        return definition if isinstance(definition, dict) else {}

    @property
    def states(self) -> dict[str, Any]:
        states = self.definition.get("States")
        return states if isinstance(states, dict) else {}


@dataclass
class Alarm(Resource):
    @property
    def metric_name(self) -> str | None:
        value = self.prop("MetricName")
        return value if isinstance(value, str) else None

    @property
    def dimensions(self) -> list[dict[str, Any]]:
        return [d for d in ensure_list(self.prop("Dimensions")) if isinstance(d, dict)]


@dataclass
class Bus(Resource):
    pass


@dataclass
class Stream(Resource):
    pass


@dataclass
class Table(Resource):
    @property
    def billing_mode(self) -> str | None:
        value = self.prop("BillingMode")
        return value if isinstance(value, str) else None

    @property
    def provisioned(self) -> bool:
        """Provisioned tables throttle under burst; on-demand mostly doesn't."""
        return self.billing_mode != "PAY_PER_REQUEST" and self.prop("ProvisionedThroughput") is not None

    @property
    def stream_enabled(self) -> bool:
        spec = self.prop("StreamSpecification")
        return isinstance(spec, dict) and bool(spec.get("StreamViewType"))


@dataclass
class Role(Resource):
    @property
    def policy_statements(self) -> list[dict[str, Any]]:
        statements: list[dict[str, Any]] = []
        for policy in ensure_list(self.prop("Policies")):
            if isinstance(policy, dict):
                document = policy.get("PolicyDocument", policy)
                if isinstance(document, dict):
                    statements.extend(
                        s for s in ensure_list(document.get("Statement")) if isinstance(s, dict)
                    )
        return statements
