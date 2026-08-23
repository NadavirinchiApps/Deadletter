"""Rule interface and registry.

Every rule is a pure function of the graph. No I/O, no credentials, no
network — that property is what lets sales say "repo-only, no access to your
account", which kills the security objection before it is raised.

Adding a rule:

    from .base import Rule, register

    @register
    class EDA001(Rule):
        id = "EDA001"
        severity = Severity.BLOCK
        title = "SQS visibility timeout too short for its consumer"
        def check(self, graph): ...

A rule without fixtures does not merge. `tests/fixtures/<rule_id>/violating.yaml`
must produce exactly the documented finding; `passing.yaml` must produce none.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from ..findings import Finding, Severity
from ..graph import EventGraph

_REGISTRY: dict[str, type["Rule"]] = {}


class Rule(ABC):
    id: str = ""
    severity: Severity = Severity.INFO
    title: str = ""
    # One-line description of what has to be true in the account for this to bite.
    condition: str = ""

    @abstractmethod
    def check(self, graph: EventGraph) -> Iterable[Finding]:
        """Return findings. Silence means the template is clean for this rule."""

    def __repr__(self) -> str:
        return f"<{self.id} {self.severity}>"


def register(cls: type[Rule]) -> type[Rule]:
    if not cls.id:
        raise ValueError(f"{cls.__name__} must define an id")
    if cls.id in _REGISTRY:
        raise ValueError(f"duplicate rule id {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def all_rules() -> list[Rule]:
    return [cls() for _, cls in sorted(_REGISTRY.items())]


def get_rule(rule_id: str) -> Rule | None:
    cls = _REGISTRY.get(rule_id)
    return cls() if cls else None


def run(graph: EventGraph, rule_ids: Iterable[str] | None = None) -> list[Finding]:
    selected = [r for r in all_rules() if rule_ids is None or r.id in set(rule_ids)]
    findings: list[Finding] = []
    for rule in selected:
        findings.extend(rule.check(graph))
    return sorted(findings, key=lambda f: f.sort_key)
