"""Rule interface and registry.

Every rule is a pure function of the graph. No I/O, no credentials, no
network — that property is what lets sales say "repo-only, no access to your
account", which kills the security objection before it is raised.

Adding a rule:

    from .base import Rule, register

    @register
    class EDA001(Rule):
        id = "EDA001"
        impact = Impact.DUPLICATION
        title = "SQS visibility timeout too short for its consumer"
        def check(self, graph): ...

A rule declares what breaks (`impact`), and each finding declares how well it
is known (`confidence`) and whether the threshold is AWS's rule or AWS's advice
(`basis`). No rule decides whether the build stops — a `Policy` does that, so
the customer owns the blocking decision instead of inheriting ours.

A rule without fixtures does not merge. `tests/fixtures/<rule_id>/violating.yaml`
must produce exactly the documented finding; `passing.yaml` must produce none.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import date
from typing import Any, Iterable

from ..findings import (
    DEFAULT_POLICY,
    Basis,
    Confidence,
    Finding,
    Impact,
    Policy,
    Remediation,
)
from ..graph import EventGraph
from ..model import Resource
from ..suppress import apply, collect

_REGISTRY: dict[str, type["Rule"]] = {}


class Rule(ABC):
    id: str = ""
    title: str = ""
    # The consequence this rule exists to prevent. A rule declares what breaks;
    # it never declares whether the build should stop, which is policy.
    impact: Impact = Impact.DEGRADED
    # Whether the threshold this rule enforces is AWS's rule or AWS's advice.
    # Findings override it where one rule covers both, as EDA001 does.
    basis: Basis = Basis.REQUIREMENT
    # One-line description of what has to be true in the account for this to bite.
    condition: str = ""

    @abstractmethod
    def check(self, graph: EventGraph) -> Iterable[Finding]:
        """Return findings. Silence means the template is clean for this rule."""

    def __repr__(self) -> str:
        return f"<{self.id} {self.impact}>"


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


def run(
    graph: EventGraph,
    rule_ids: Iterable[str] | None = None,
    today: date | None = None,
    policy: Policy = DEFAULT_POLICY,
) -> list[Finding]:
    selected_ids = set(rule_ids) if rule_ids is not None else None
    selected = [rule for rule in all_rules() if selected_ids is None or rule.id in selected_ids]
    findings: list[Finding] = []
    for rule in selected:
        findings.extend(rule.check(graph))
    for finding in findings:
        if finding.source is None:
            finding.source = graph.template.source
        if finding.location is None:
            if finding.remediations:
                finding.location = finding.remediations[0].location
            elif finding.resources:
                finding.location = graph.source_location(finding.resources[0])
        conditional = [
            resource.logical_id
            for resource_id in finding.resources
            if (resource := graph.template.get(resource_id)) is not None
            and resource.condition_value is None
        ]
        if conditional:
            # The configuration is wrong, but whether these resources are
            # deployed at all depends on a Condition this scan cannot evaluate.
            # That is a limit on our knowledge, so it lowers confidence — it
            # never raises it.
            finding.confidence = _least_confident(finding.confidence, Confidence.INFERRED)
            finding.evidence["conditional_resources"] = conditional
        finding.verdict = policy.verdict(finding)

    suppressions, _ = collect(graph.template)
    apply(findings, suppressions, today)
    return sorted(findings, key=lambda f: f.sort_key)


def _least_confident(*values: Confidence) -> Confidence:
    return max(values, key=lambda c: c.rank)


def remediation(
    graph: EventGraph,
    resource: Resource,
    *property_path: str | int,
    description: str,
    suggested_value: Any = None,
    automatic: bool = False,
) -> Remediation:
    return Remediation(
        location=graph.source_location(resource, *property_path),
        description=description,
        suggested_value=suggested_value,
        automatic=automatic,
    )
