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
    "AWS::StepFunctions::StateMachine": m.Kind.STATE_MACHINE,
    "AWS::Serverless::StateMachine": m.Kind.STATE_MACHINE,
    "AWS::Kinesis::Stream": m.Kind.STREAM,
    "AWS::DynamoDB::Table": m.Kind.TABLE,
    "AWS::Serverless::SimpleTable": m.Kind.TABLE,
    "AWS::RDS::DBInstance": m.Kind.DATABASE,
    "AWS::RDS::DBCluster": m.Kind.DATABASE,
    "AWS::CloudWatch::Alarm": m.Kind.ALARM,
    "AWS::IAM::Role": m.Kind.ROLE,
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
    m.Kind.ROLE: m.Role,
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

    def __init__(self, resources: dict[str, m.Resource], source: str | None = None) -> None:
        self.resources = resources
        self.source = source

    def __iter__(self):
        return iter(self.resources.values())

    def get(self, logical_id: str | None) -> m.Resource | None:
        return self.resources.get(logical_id) if logical_id else None

    def of_kind(self, *kinds: m.Kind) -> list[m.Resource]:
        return [r for r in self.resources.values() if r.kind in kinds]

    def resolve_ref(self, ref) -> m.Resource | None:
        """Reference -> resource, falling back to literal-ARN name matching."""
        for logical_id in ref.logical_ids:
            found = self.resources.get(logical_id)
            if found is not None:
                return found
        if ref.literal:
            from .intrinsics import name_from_arn

            name = name_from_arn(ref.literal) or ref.literal
            for resource in self.resources.values():
                if resource.name_hint and resource.name_hint == name:
                    return resource
        return None


def load(path: str | Path) -> Template:
    path = Path(path)
    return loads(path.read_text(encoding="utf-8"), source=str(path))


def loads(text: str, source: str | None = None) -> Template:
    raw = _decode(text)
    if not isinstance(raw, dict):
        raise ValueError("template did not parse to a mapping")
    return Template(_build(raw), source=source)


def _decode(text: str) -> Any:
    """cfn-lint's decoder first (handles short-form intrinsics and duplicate keys),
    cfn-flip second, plain JSON last."""
    try:
        from cfnlint.decode.cfn_yaml import loads as cfn_loads

        return _plain(cfn_loads(text))
    except Exception:
        pass
    try:
        import cfn_flip

        return _plain(cfn_flip.load(text)[0])
    except Exception:
        pass
    return json.loads(text)


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
    resources: dict[str, m.Resource] = {}

    for logical_id, body in iter_dict(raw.get("Resources")):
        if not isinstance(body, dict):
            continue
        cfn_type = str(body.get("Type", ""))
        props = body.get("Properties") if isinstance(body.get("Properties"), dict) else {}
        kind = _TYPE_KIND.get(cfn_type, m.Kind.UNKNOWN)

        if kind is m.Kind.FUNCTION and isinstance(function_globals, dict):
            props = {**function_globals, **props}  # explicit props win over Globals

        resources[logical_id] = _make(logical_id, cfn_type, kind, props)

    # Second pass: SAM Events need the full resource map to exist first.
    synthetic: dict[str, m.Resource] = {}
    for logical_id, body in iter_dict(raw.get("Resources")):
        if isinstance(body, dict) and str(body.get("Type")) == "AWS::Serverless::Function":
            props = body.get("Properties") if isinstance(body.get("Properties"), dict) else {}
            synthetic.update(_expand_sam_events(logical_id, props))

    resources.update(synthetic)
    return resources


def _make(logical_id: str, cfn_type: str, kind: m.Kind, props: dict[str, Any], **extra: Any) -> m.Resource:
    cls = _CLASS.get(kind, m.Resource)
    resource = cls(logical_id=logical_id, cfn_type=cfn_type, kind=kind, props=props, **extra)
    if isinstance(resource, m.EventSourceMapping) and not extra:
        resource.source = resolve(props.get("EventSourceArn") or props.get("SelfManagedEventSource"))
        resource.target = resolve(props.get("FunctionName"))
    if isinstance(resource, m.Rule) and not extra:
        resource.bus = resolve(props.get("EventBusName"))
    if isinstance(resource, m.Subscription) and not extra:
        resource.topic = resolve(props.get("TopicArn"))
        resource.endpoint = resolve(props.get("Endpoint"))
    return resource


def _expand_sam_events(function_id: str, props: dict[str, Any]) -> dict[str, m.Resource]:
    """Synthesise the resources SAM would generate from an `Events:` block."""
    out: dict[str, m.Resource] = {}
    events = props.get("Events")
    if not isinstance(events, dict):
        return out

    for event_name, event in events.items():
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("Type", ""))
        event_props = event.get("Properties") if isinstance(event.get("Properties"), dict) else {}
        synthetic_id = f"{function_id}#{event_name}"

        if event_type in _POLL_EVENTS:
            source_key, source_kind = _POLL_EVENTS[event_type]
            esm = m.EventSourceMapping(
                logical_id=synthetic_id,
                cfn_type="AWS::Lambda::EventSourceMapping",
                kind=m.Kind.ESM,
                props=event_props,
                synthetic=True,
                origin=function_id,
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
                synthetic=True,
                origin=function_id,
            )
            rule.bus = resolve(event_props.get("EventBusName"))
            out[synthetic_id] = rule

        elif event_type == "SNS":
            subscription = m.Subscription(
                logical_id=synthetic_id,
                cfn_type="AWS::SNS::Subscription",
                kind=m.Kind.SUBSCRIPTION,
                props={"Protocol": "lambda", **event_props},
                synthetic=True,
                origin=function_id,
            )
            subscription.topic = resolve(event_props.get("Topic"))
            subscription.endpoint = resolve({"Ref": function_id})
            out[synthetic_id] = subscription

        elif event_type in ("Api", "HttpApi"):
            out[synthetic_id] = m.Resource(
                logical_id=synthetic_id,
                cfn_type="AWS::Serverless::Api",
                kind=m.Kind.API,
                props=event_props,
                synthetic=True,
                origin=function_id,
            )

    return out


def sam_event_names(props: dict[str, Any]) -> list[str]:
    return [name for name, _ in iter_dict(props.get("Events"))]


__all__ = ["Template", "load", "loads", "ensure_list"]
