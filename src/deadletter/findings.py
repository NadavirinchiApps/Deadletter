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
        }
