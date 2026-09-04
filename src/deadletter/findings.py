"""The Finding contract.

The message format is fixed and non-negotiable, because it is the product:

    <VERDICT>: <resource> <config> is <value>, while <related> <config> is
    <value>. Required: <threshold>. Consequence: <one sentence>.

A finding that cannot name both resources and quote both values is not a
finding — it is a warning, and warnings are what the free tools already give
away. Every `evidence` entry must be a value literally present in the
template so a sceptical staff engineer can grep for it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    BLOCK = "BLOCK"  # will cause loss / duplication / outage under defined conditions
    WARN = "WARN"    # likely incident under load
    INFO = "INFO"    # missing safety net

    @property
    def rank(self) -> int:
        return {"BLOCK": 0, "WARN": 1, "INFO": 2}[self.value]


@dataclass(frozen=True)
class SourceLocation:
    """A stable structural location, optionally backed by a YAML line/column."""

    path: str
    line: int | None = None
    column: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"path": self.path}
        if self.line is not None:
            data["line"] = self.line
        if self.column is not None:
            data["column"] = self.column
        return data


@dataclass(frozen=True)
class Remediation:
    """A source-aware change recommendation.

    ``automatic`` is deliberately false for changes that require the owner to
    choose a destination or modify handler code. The scanner must never present
    a placeholder as a safe, apply-ready patch.
    """

    location: SourceLocation
    description: str
    suggested_value: Any = None
    automatic: bool = False

    @property
    def path(self) -> str:
        return self.location.path

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.location.to_dict(),
            "description": self.description,
            "suggested_value": self.suggested_value,
            "automatic": self.automatic,
        }


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    resources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    patch_hint: str | None = None
    inferred: bool = False
    source: str | None = None
    location: SourceLocation | None = None
    remediations: list[Remediation] = field(default_factory=list)
    # Set when a template suppresses this finding. Suppressed findings are kept
    # and reported; they just stop failing the build.
    suppressed: bool = False
    suppression: str | None = None

    def __post_init__(self) -> None:
        if not self.resources:
            raise ValueError(f"{self.rule_id}: a finding must name the resources involved")
        if not self.evidence:
            raise ValueError(f"{self.rule_id}: a finding must quote evidence from the template")

    @property
    def sort_key(self) -> tuple[int, str, str]:
        return (self.severity.rank, self.rule_id, ",".join(self.resources))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": str(self.severity),
            "title": self.title,
            "message": self.message,
            "resources": list(self.resources),
            "evidence": dict(self.evidence),
            "patch_hint": self.patch_hint,
            "inferred": self.inferred,
            "source": self.source,
            "location": self.location.to_dict() if self.location else None,
            "remediations": [remediation.to_dict() for remediation in self.remediations],
            "suppressed": self.suppressed,
            "suppression": self.suppression,
        }
