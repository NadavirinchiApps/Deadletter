"""Resolve CloudFormation intrinsics down to the logical IDs they point at.

Every rule ultimately asks "which resource does this property refer to?".
Templates answer that question in about six different ways:

    !Ref MyQueue
    !GetAtt MyQueue.Arn
    !Sub "${MyQueue.Arn}"
    {"Fn::ImportValue": ...}          -> unresolvable, cross-stack
    "arn:aws:sqs:us-east-1:1234:orders-queue"   -> literal, may match a resource by name

This module normalises all of them to a set of logical IDs, plus keeps the
literal string around so findings can quote what the template actually said.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# ${Foo} and ${Foo.Arn} inside !Sub strings. AWS pseudo-params (${AWS::...}) excluded.
_SUB_TOKEN = re.compile(r"\$\{([A-Za-z0-9]+)(?:\.[A-Za-z0-9.]+)?\}")
_ARN_TAIL = re.compile(r"arn:[^:]*:[^:]*:[^:]*:[^:]*:(?:[^:/]+[:/])?([A-Za-z0-9_.:-]+)$")

# A state-machine definition assembled by Fn::Join or Fn::Sub is JSON with
# resource ARNs punched out of it. Substituting a marker for each one keeps the
# document parseable, so the workflow can be read, while still saying which
# resource stood there. See `model.StateMachine.definition`.
_PLACEHOLDER = re.compile(r"__dl_ref:([A-Za-z0-9]+)__")

# The same token pattern, for callers that rewrite a !Sub body rather than
# resolve it.
SUB_TOKEN = _SUB_TOKEN


@dataclass(frozen=True)
class Reference:
    """What a template property pointed at, and how it said it."""

    logical_ids: frozenset[str] = field(default_factory=frozenset)
    literal: str | None = None
    unresolved: bool = False

    @property
    def logical_id(self) -> str | None:
        """The single target, when there is exactly one. Most properties are singular."""
        return next(iter(self.logical_ids)) if len(self.logical_ids) == 1 else None

    @property
    def configured(self) -> bool:
        """Whether the template supplied a value, even if it is cross-stack."""
        return bool(self.logical_ids) or self.literal is not None or self.unresolved

    def __bool__(self) -> bool:
        return self.configured


def resolve(node: Any) -> Reference:
    """Resolve one property value to the resource(s) it references."""
    if node is None:
        return Reference()

    if isinstance(node, str):
        return Reference(literal=node)

    if isinstance(node, dict):
        if "Ref" in node and isinstance(node["Ref"], str):
            target = node["Ref"]
            if target.startswith("AWS::"):
                return Reference(literal=target)
            return Reference(logical_ids=frozenset({target}))

        if "Fn::GetAtt" in node:
            att = node["Fn::GetAtt"]
            if isinstance(att, str):
                return Reference(logical_ids=frozenset({att.split(".")[0]}))
            if isinstance(att, list) and att:
                return Reference(logical_ids=frozenset({str(att[0])}))

        if "Fn::Sub" in node:
            body = node["Fn::Sub"]
            template = body[0] if isinstance(body, list) and body else body
            if isinstance(template, str):
                variables = body[1] if isinstance(body, list) and len(body) > 1 and isinstance(body[1], dict) else {}
                ids: set[str] = set()
                unresolved = False
                for token in _SUB_TOKEN.findall(template):
                    if token.startswith("AWS"):
                        continue
                    if token in variables:
                        mapped = resolve(variables[token])
                        ids.update(mapped.logical_ids)
                        unresolved = unresolved or mapped.unresolved
                    else:
                        ids.add(token)
                return Reference(logical_ids=frozenset(ids), literal=template, unresolved=unresolved)

        if "Fn::Join" in node:
            body = node["Fn::Join"]
            pieces = body[1] if isinstance(body, list) and len(body) > 1 else []
            return _combine(resolve(piece) for piece in ensure_list(pieces))

        if "Fn::If" in node:
            body = node["Fn::If"]
            branches = body[1:] if isinstance(body, list) else []
            return _combine(resolve(branch) for branch in branches)

        if any(k.startswith("Fn::") for k in node):
            # ImportValue and transforms may point outside this template. Keep
            # any nested in-template references, but never claim full resolution.
            nested = _combine(resolve(value) for value in node.values())
            return Reference(
                logical_ids=nested.logical_ids,
                literal=nested.literal,
                unresolved=True,
            )

    return Reference()


def _combine(references: Iterable[Reference]) -> Reference:
    ids: set[str] = set()
    unresolved = False
    literals: list[str] = []
    for reference in references:
        ids.update(reference.logical_ids)
        unresolved = unresolved or reference.unresolved
        if reference.literal is not None:
            literals.append(reference.literal)
    literal = literals[0] if len(literals) == 1 and not ids else None
    return Reference(logical_ids=frozenset(ids), literal=literal, unresolved=unresolved)


def placeholder(logical_id: str) -> str:
    return f"__dl_ref:{logical_id}__"


def resolve_definition(node: Any) -> Reference:
    """Resolve a value read out of a rebuilt state-machine definition.

    Same as `resolve`, except a string holding one or more placeholders points
    at the resources they stand for rather than being treated as a literal ARN.
    """
    if isinstance(node, str):
        ids = set(_PLACEHOLDER.findall(node))
        if ids:
            return Reference(logical_ids=frozenset(ids), literal=node)
    return resolve(node)


def referenced_ids(node: Any) -> set[str]:
    """Every logical ID mentioned anywhere inside an arbitrary property subtree.

    Deliberately greedy — used for best-effort edges (a function's IAM policies
    referencing a table) where over-collection is better than a missed edge.
    """
    found: set[str] = set()
    _walk(node, found)
    return found


def _walk(node: Any, found: set[str]) -> None:
    if isinstance(node, dict):
        ref = resolve(node)
        found.update(ref.logical_ids)
        for value in node.values():
            _walk(value, found)
    elif isinstance(node, list):
        for item in node:
            _walk(item, found)


def name_from_arn(arn: str) -> str | None:
    """Pull the resource name out of a literal ARN, for matching against Name props."""
    match = _ARN_TAIL.match(arn)
    return match.group(1) if match else None


def as_int(value: Any, default: int | None = None) -> int | None:
    """Template numbers arrive as int, str, or unresolvable intrinsic."""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def as_bool(value: Any, default: bool | None = None) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "false"):
            return low == "true"
    return default


def first(*values: Any) -> Any:
    """First non-None value — for properties CFN and SAM spell differently."""
    return next((v for v in values if v is not None), None)


def ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def iter_dict(value: Any) -> Iterable[tuple[str, Any]]:
    return value.items() if isinstance(value, dict) else ()
