"""Template -> typed resources.

Two jobs beyond reading YAML:

1. **SAM expansion.** A SAM `Events:` block is a real event source mapping or
   EventBridge rule wearing a costume. Rules must see it as the former, so we
   synthesise the resource SAM would have generated. Without this the scanner
   is blind to most modern serverless repos, which never write an
   `AWS::Lambda::EventSourceMapping` by hand.
2. **Globals merge.** `Globals: Function: Timeout: 30` is how half of real
   templates set the value EDA001 needs. Missing it produces a false BLOCK,
   which costs more in front of a prospect than a missed finding.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import model as m
from .intrinsics import ensure_list, iter_dict, resolve

_TYPE_KIND: dict[str, m.Kind] = {
    "AWS::Lambda::Function": m.Kind.FUNCTION,
    "AWS::Serverless::Function": m.Kind.FUNCTION,
    "AWS::SQS::Queue": m.Kind.QUEUE,
    "AWS::SNS::Topic": m.Kind.TOPIC,
    "AWS::SNS::Subscription": m.Kind.SUBSCRIPTION,
    "AWS::Events::EventBus": m.Kind.BUS,
    "AWS::Events::Rule": m.Kind.RULE,
    "AWS::Lambda::EventSourceMapping": m.Kind.ESM,
    "AWS::Lambda::EventInvokeConfig": m.Kind.INVOKE_CONFIG,
    "AWS::StepFunctions::StateMachine": m.Kind.STATE_MACHINE,
    "AWS::Serverless::StateMachine": m.Kind.STATE_MACHINE,
    "AWS::Kinesis::Stream": m.Kind.STREAM,
    "AWS::Kinesis::StreamConsumer": m.Kind.STREAM_CONSUMER,
    "AWS::DynamoDB::Table": m.Kind.TABLE,
    "AWS::Serverless::SimpleTable": m.Kind.TABLE,
    "AWS::RDS::DBInstance": m.Kind.DATABASE,
    "AWS::RDS::DBCluster": m.Kind.DATABASE,
    "AWS::CloudWatch::Alarm": m.Kind.ALARM,
    "AWS::IAM::Role": m.Kind.ROLE,
    "AWS::IAM::Policy": m.Kind.POLICY,
    "AWS::IAM::ManagedPolicy": m.Kind.POLICY,
    "AWS::ApiGateway::RestApi": m.Kind.API,
    "AWS::Serverless::Api": m.Kind.API,
    "AWS::Serverless::HttpApi": m.Kind.API,
}

_CLASS: dict[m.Kind, type[m.Resource]] = {
    m.Kind.FUNCTION: m.Function,
    m.Kind.QUEUE: m.Queue,
    m.Kind.ESM: m.EventSourceMapping,
    m.Kind.RULE: m.Rule,
    m.Kind.SUBSCRIPTION: m.Subscription,
    m.Kind.STATE_MACHINE: m.StateMachine,
    m.Kind.ALARM: m.Alarm,
    m.Kind.BUS: m.Bus,
    m.Kind.STREAM: m.Stream,
    m.Kind.TABLE: m.Table,
    m.Kind.STREAM_CONSUMER: m.StreamConsumer,
    m.Kind.ROLE: m.Role,
    m.Kind.POLICY: m.Policy,
    m.Kind.INVOKE_CONFIG: m.EventInvokeConfig,
}

# SAM event type -> (source property name, kind of the thing it polls)
_POLL_EVENTS: dict[str, tuple[str, m.Kind]] = {
    "SQS": ("Queue", m.Kind.QUEUE),
    "Kinesis": ("Stream", m.Kind.STREAM),
    "DynamoDB": ("Stream", m.Kind.TABLE),
    "MSK": ("Stream", m.Kind.STREAM),
}
_BUS_EVENTS = {"EventBridgeRule", "CloudWatchEvent", "Schedule", "ScheduleV2"}


class Template:
    """A parsed template: resources by logical ID, plus lookup helpers."""

    def __init__(
        self,
        resources: dict[str, m.Resource],
        source: str | None = None,
        locations: dict[tuple[str | int, ...], tuple[int, int]] | None = None,
        exports: set[str] | None = None,
    ) -> None:
        self.resources = resources
        self.source = source
        for resource in resources.values():
            if resource.source_file is None:
                resource.source_file = source
        self.locations = locations or {}
        # Logical IDs published through an Output Export. Another stack can
        # reach these, so their absence of local consumers proves less.
        self.exports = exports or set()

    def __iter__(self):
        return iter(self.resources.values())

    def get(self, logical_id: str | None) -> m.Resource | None:
        return self.resources.get(logical_id) if logical_id else None

    def of_kind(self, *kinds: m.Kind) -> list[m.Resource]:
        return [r for r in self.resources.values() if r.kind in kinds]

    def resolve_ref(self, ref) -> m.Resource | None:
        """Reference -> resource, falling back to literal-ARN name matching."""
        candidates = {
            logical_id: self.resources[logical_id]
            for logical_id in ref.logical_ids
            if logical_id in self.resources
        }
        if len(candidates) == 1:
            return next(iter(candidates.values()))
        if len(candidates) > 1:
            return None  # a singular property must never pick a target arbitrarily
        if ref.literal:
            from .intrinsics import name_from_arn

            name = name_from_arn(ref.literal) or ref.literal
            matches = [
                resource
                for resource in self.resources.values()
                if resource.name_hint and resource.name_hint == name
            ]
            if len(matches) == 1:
                return matches[0]
        return None

    def location(self, path: tuple[str | int, ...]) -> tuple[int | None, int | None]:
        """Line/column for a path, falling back to its nearest existing parent."""
        current = path
        while current:
            if current in self.locations:
                return self.locations[current]
            current = current[:-1]
        return self.locations.get((), (None, None))


def load(path: str | Path) -> Template:
    path = Path(path)
    return loads(path.read_text(encoding="utf-8"), source=str(path))


def loads(text: str, source: str | None = None) -> Template:
    raw, locations = _decode(text)
    if not isinstance(raw, dict):
        raise ValueError("template did not parse to a mapping")
    return Template(
        _build(raw), source=source, locations=locations, exports=_exported_ids(raw)
    )


def from_dict(raw: dict[str, Any], source: str | None = None) -> Template:
    """Build a Template from an already-decoded template body.

    For callers that run inside something which has already parsed the file —
    cfn-lint hands its rules a decoded `cfn.template` — so the text is not
    parsed twice and the two halves cannot disagree about what it says. Line
    numbers are not available this way; the structural path still is.
    """
    plain = _plain(raw)
    if not isinstance(plain, dict):
        raise ValueError("template did not parse to a mapping")
    return Template(_build(plain), source=source, exports=_exported_ids(plain))


def _exported_ids(raw: dict[str, Any]) -> set[str]:
    """Logical IDs an Output publishes under an Export name."""
    from .intrinsics import referenced_ids

    exported: set[str] = set()
    for _, output in iter_dict(raw.get("Outputs")):
        if isinstance(output, dict) and output.get("Export") is not None:
            exported.update(referenced_ids(output.get("Value")))
    return exported


def _decode(text: str) -> tuple[Any, dict[tuple[str | int, ...], tuple[int, int]]]:
    """cfn-lint's decoder first (handles short-form intrinsics and duplicate keys),
    cfn-flip second, plain JSON last."""
    try:
        from cfnlint.decode.cfn_yaml import loads as cfn_loads

        marked = cfn_loads(text)
        locations: dict[tuple[str | int, ...], tuple[int, int]] = {}
        _collect_locations(marked, (), locations)
        return _plain(marked), locations
    except Exception as cfn_error:
        errors = [f"CloudFormation YAML: {cfn_error}"]
    try:
        import cfn_flip

        return _plain(cfn_flip.load(text)[0]), {}
    except Exception as flip_error:
        errors.append(f"YAML fallback: {flip_error}")
    try:
        return json.loads(text), {}
    except Exception as json_error:
        errors.append(f"JSON: {json_error}")
        raise ValueError("unable to parse template; " + "; ".join(errors)) from json_error


def _collect_locations(
    node: Any,
    path: tuple[str | int, ...],
    locations: dict[tuple[str | int, ...], tuple[int, int]],
) -> None:
    mark = getattr(node, "start_mark", None)
    if mark is not None:
        locations.setdefault(path, (mark.line + 1, mark.column + 1))
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = (*path, str(key))
            key_mark = getattr(key, "start_mark", None)
            if key_mark is not None:
                locations[child_path] = (key_mark.line + 1, key_mark.column + 1)
            _collect_locations(value, child_path, locations)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _collect_locations(value, (*path, index), locations)


def _plain(node: Any) -> Any:
    """cfn-lint returns str/dict subclasses carrying line numbers. Strip to builtins
    so equality checks and JSON serialisation behave."""
    if isinstance(node, dict):
        return {str(k): _plain(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_plain(v) for v in node]
    if isinstance(node, bool) or node is None:
        return node
    if isinstance(node, str):
        return str(node)
    if isinstance(node, int):
        return int(node)
    if isinstance(node, float):
        return float(node)
    return node


def _build(raw: dict[str, Any]) -> dict[str, m.Resource]:
    globals_block = raw.get("Globals") if isinstance(raw.get("Globals"), dict) else {}
    function_globals = globals_block.get("Function", {}) if isinstance(globals_block, dict) else {}
    parameter_defaults = _parameter_defaults(raw)
    condition_values = _condition_values(raw, parameter_defaults)
    resources: dict[str, m.Resource] = {}

    for logical_id, body in iter_dict(raw.get("Resources")):
        if not isinstance(body, dict):
            continue
        cfn_type = str(body.get("Type", ""))
        condition = body.get("Condition") if isinstance(body.get("Condition"), str) else None
        condition_value = condition_values.get(condition) if condition else True
        if condition_value is False:
            continue
        raw_props = body.get("Properties") if isinstance(body.get("Properties"), dict) else {}
        kind = _TYPE_KIND.get(cfn_type, m.Kind.UNKNOWN)

        if cfn_type == "AWS::Serverless::Function" and isinstance(function_globals, dict):
            raw_props = _sam_merge(function_globals, raw_props)

        props = _resolve_parameter_defaults(raw_props, parameter_defaults)
        metadata = body.get("Metadata") if isinstance(body.get("Metadata"), dict) else {}
        resources[logical_id] = _make(
            logical_id,
            cfn_type,
            kind,
            props,
            raw_props=raw_props,
            source_path=("Resources", logical_id, "Properties"),
            condition=condition,
            condition_value=condition_value,
            metadata=metadata,
        )

    # Second pass: SAM Events need the full resource map to exist first.
    synthetic: dict[str, m.Resource] = {}
    for logical_id, body in iter_dict(raw.get("Resources")):
        if isinstance(body, dict) and str(body.get("Type")) == "AWS::Serverless::Function":
            function = resources.get(logical_id)
            if function is not None:
                synthetic.update(
                    _expand_sam_events(
                        logical_id,
                        function.props,
                        function.raw_props or function.props,
                        condition=function.condition,
                        condition_value=function.condition_value,
                    )
                )

    resources.update(synthetic)
    _attach_default_event_bus(resources)
    return resources


def _make(logical_id: str, cfn_type: str, kind: m.Kind, props: dict[str, Any], **extra: Any) -> m.Resource:
    cls = _CLASS.get(kind, m.Resource)
    resource = cls(logical_id=logical_id, cfn_type=cfn_type, kind=kind, props=props, **extra)
    if isinstance(resource, m.EventSourceMapping) and not resource.synthetic:
        resource.source = resolve(props.get("EventSourceArn") or props.get("SelfManagedEventSource"))
        resource.target = resolve(props.get("FunctionName"))
    if isinstance(resource, m.Rule) and not resource.synthetic:
        resource.bus = resolve(props.get("EventBusName"))
    if isinstance(resource, m.Subscription) and not resource.synthetic:
        resource.topic = resolve(props.get("TopicArn"))
        resource.endpoint = resolve(props.get("Endpoint"))
    if isinstance(resource, m.EventInvokeConfig) and not resource.synthetic:
        resource.function = resolve(props.get("FunctionName"))
    if isinstance(resource, m.StreamConsumer):
        resource.stream = resolve(props.get("StreamARN"))
    if isinstance(resource, m.Policy):
        resource.roles = [resolve(role) for role in ensure_list(props.get("Roles"))]
    return resource


def _expand_sam_events(
    function_id: str,
    props: dict[str, Any],
    raw_props: dict[str, Any],
    condition: str | None = None,
    condition_value: bool | None = True,
) -> dict[str, m.Resource]:
    """Synthesise the resources SAM would generate from an `Events:` block."""
    out: dict[str, m.Resource] = {}
    events = props.get("Events")
    raw_events = raw_props.get("Events") if isinstance(raw_props.get("Events"), dict) else {}
    if not isinstance(events, dict):
        return out

    for event_name, event in events.items():
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("Type", ""))
        event_props = event.get("Properties") if isinstance(event.get("Properties"), dict) else {}
        raw_event = raw_events.get(event_name) if isinstance(raw_events, dict) else None
        raw_event_props = (
            raw_event.get("Properties")
            if isinstance(raw_event, dict) and isinstance(raw_event.get("Properties"), dict)
            else event_props
        )
        synthetic_id = f"{function_id}#{event_name}"
        source_path = ("Resources", function_id, "Properties", "Events", event_name, "Properties")

        if event_type in _POLL_EVENTS:
            source_key, source_kind = _POLL_EVENTS[event_type]
            esm = m.EventSourceMapping(
                logical_id=synthetic_id,
                cfn_type="AWS::Lambda::EventSourceMapping",
                kind=m.Kind.ESM,
                props=event_props,
                raw_props=raw_event_props,
                synthetic=True,
                origin=function_id,
                source_path=source_path,
                condition=condition,
                condition_value=condition_value,
            )
            esm.source = resolve(event_props.get(source_key))
            esm.target = resolve({"Ref": function_id})
            esm.source_kind = source_kind
            out[synthetic_id] = esm

        elif event_type in _BUS_EVENTS:
            rule = m.Rule(
                logical_id=synthetic_id,
                cfn_type="AWS::Events::Rule",
                kind=m.Kind.RULE,
                props={
                    **event_props,
                    "DeadletterEventType": event_type,
                    "Targets": [
                        {
                            "Arn": {"Fn::GetAtt": [function_id, "Arn"]},
                            **(
                                {"DeadLetterConfig": event_props["DeadLetterConfig"]}
                                if isinstance(event_props.get("DeadLetterConfig"), dict)
                                else {}
                            ),
                            **(
                                {"RetryPolicy": event_props["RetryPolicy"]}
                                if isinstance(event_props.get("RetryPolicy"), dict)
                                else {}
                            ),
                        }
                    ],
                },
                raw_props=raw_event_props,
                synthetic=True,
                origin=function_id,
                source_path=source_path,
                condition=condition,
                condition_value=condition_value,
            )
            rule.bus = resolve(event_props.get("EventBusName"))
            out[synthetic_id] = rule

        elif event_type == "SNS":
            subscription = m.Subscription(
                logical_id=synthetic_id,
                cfn_type="AWS::SNS::Subscription",
                kind=m.Kind.SUBSCRIPTION,
                props={"Protocol": "lambda", **event_props},
                raw_props=raw_event_props,
                synthetic=True,
                origin=function_id,
                source_path=source_path,
                condition=condition,
                condition_value=condition_value,
            )
            subscription.topic = resolve(event_props.get("Topic"))
            subscription.endpoint = resolve({"Ref": function_id})
            out[synthetic_id] = subscription

        elif event_type in ("Api", "HttpApi"):
            out[synthetic_id] = m.Resource(
                logical_id=synthetic_id,
                cfn_type=(
                    "AWS::Serverless::HttpApi" if event_type == "HttpApi" else "AWS::Serverless::Api"
                ),
                kind=m.Kind.API,
                props={**event_props, "DeadletterEventType": event_type},
                raw_props=raw_event_props,
                synthetic=True,
                origin=function_id,
                source_path=source_path,
                condition=condition,
                condition_value=condition_value,
            )

    return out


def _parameter_defaults(raw: dict[str, Any]) -> dict[str, Any]:
    defaults: dict[str, Any] = {}
    for name, definition in iter_dict(raw.get("Parameters")):
        if isinstance(definition, dict) and "Default" in definition:
            defaults[name] = definition["Default"]
    return defaults


def _condition_values(raw: dict[str, Any], defaults: dict[str, Any]) -> dict[str, bool | None]:
    conditions = raw.get("Conditions") if isinstance(raw.get("Conditions"), dict) else {}
    resolved = {
        name: _resolve_parameter_defaults(expression, defaults)
        for name, expression in conditions.items()
    }
    values: dict[str, bool | None] = {}
    # Conditions may refer to earlier or later conditions. Iterate to a fixed point.
    for _ in range(len(resolved) + 1):
        changed = False
        for name, expression in resolved.items():
            value = _evaluate_condition(expression, values)
            if values.get(name) != value:
                values[name] = value
                changed = True
        if not changed:
            break
    return values


def _evaluate_condition(node: Any, values: dict[str, bool | None]) -> bool | None:
    if isinstance(node, bool):
        return node
    if isinstance(node, str):
        if node.lower() in ("true", "false"):
            return node.lower() == "true"
        return None
    if not isinstance(node, dict):
        return None
    if set(node) == {"Condition"} and isinstance(node["Condition"], str):
        return values.get(node["Condition"])
    if "Fn::Equals" in node:
        operands = node["Fn::Equals"]
        if not isinstance(operands, list) or len(operands) != 2:
            return None
        if any(isinstance(value, (dict, list)) for value in operands):
            return None
        return operands[0] == operands[1]
    if "Fn::Not" in node:
        operands = ensure_list(node["Fn::Not"])
        value = _evaluate_condition(operands[0], values) if len(operands) == 1 else None
        return None if value is None else not value
    for operator, reducer in (("Fn::And", all), ("Fn::Or", any)):
        if operator not in node:
            continue
        operands = [_evaluate_condition(value, values) for value in ensure_list(node[operator])]
        if any(value is None for value in operands):
            return None
        return reducer(operands)
    return None


def _resolve_parameter_defaults(node: Any, defaults: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if set(node) == {"Ref"} and isinstance(node.get("Ref"), str) and node["Ref"] in defaults:
            return _resolve_parameter_defaults(defaults[node["Ref"]], defaults)
        return {key: _resolve_parameter_defaults(value, defaults) for key, value in node.items()}
    if isinstance(node, list):
        return [_resolve_parameter_defaults(value, defaults) for value in node]
    return node


def _sam_merge(global_value: Any, resource_value: Any) -> Any:
    """Implement SAM Globals rules: maps merge, lists prepend, scalars replace."""
    if isinstance(global_value, dict) and isinstance(resource_value, dict):
        merged = {key: _sam_merge(value, {}) if isinstance(value, dict) else list(value) if isinstance(value, list) else value for key, value in global_value.items()}
        for key, value in resource_value.items():
            merged[key] = _sam_merge(merged[key], value) if key in merged else value
        return merged
    if isinstance(global_value, list) and isinstance(resource_value, list):
        return [*global_value, *resource_value]
    return resource_value


def _attach_default_event_bus(resources: dict[str, m.Resource]) -> None:
    rules = [
        resource
        for resource in resources.values()
        if isinstance(resource, m.Rule) and not resource.scheduled and not resource.bus.configured
    ]
    if not rules:
        return
    logical_id = "__deadletter_default_event_bus__"
    if logical_id not in resources:
        resources[logical_id] = m.Bus(
            logical_id=logical_id,
            cfn_type="AWS::Events::EventBus",
            kind=m.Kind.BUS,
            props={"Name": "default"},
            synthetic=True,
        )
    for rule in rules:
        rule.bus = resolve({"Ref": logical_id})


def sam_event_names(props: dict[str, Any]) -> list[str]:
    return [name for name, _ in iter_dict(props.get("Events"))]


__all__ = ["Template", "load", "loads", "from_dict", "ensure_list"]
