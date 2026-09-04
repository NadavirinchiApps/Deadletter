"""Suppression: the escape hatch that keeps the scanner in the pipeline.

A gate with no way past it gets removed from the pipeline the first Friday it
blocks a release nobody can wait on. So Deadletter takes suppressions, on three
conditions that keep them from becoming a way to hide:

1. **In the template, next to the resource.** A suppression lives where the
   config it excuses lives, so it shows up in the diff that adds it and in the
   review of the resource it covers.
2. **A reason is mandatory.** An entry without one is not honoured, and the
   scan says so. "Suppressed by someone, at some point, for some reason" is
   worse than the finding.
3. **Expiry is supported and honoured.** `expires` lets a team defer a finding
   to a date instead of forever; the day it passes, the finding comes back.

Suppressed findings are never deleted. They are marked, kept out of the exit
code, and still reported, so the count of what a repository is choosing not to
fix stays visible.

    Resources:
      OrdersQueue:
        Type: AWS::SQS::Queue
        Metadata:
          deadletter:
            ignore:
              - rule: EDA001
                reason: Consumer is idempotent on order id; see ADR-114.
                expires: 2026-12-31
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable

from .findings import Finding
from .intrinsics import ensure_list

METADATA_KEY = "deadletter"


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    resource_id: str
    reason: str
    expires: date | None = None

    def expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today

    def covers(self, finding: Finding, today: date) -> bool:
        return (
            finding.rule_id == self.rule_id
            and self.resource_id in finding.resources
            and not self.expired(today)
        )

    def describe(self) -> str:
        window = f", expires {self.expires.isoformat()}" if self.expires else ""
        return f"{self.resource_id}{window}: {self.reason}"


def collect(template: Iterable[Any]) -> tuple[list[Suppression], list[str]]:
    """Read every resource's Metadata. Returns (suppressions, problems).

    Problems are reported rather than raised: one malformed entry must not stop
    a scan, but it must not silently grant an exemption either.
    """
    suppressions: list[Suppression] = []
    problems: list[str] = []

    for resource in template:
        block = resource.metadata.get(METADATA_KEY) if resource.metadata else None
        if not isinstance(block, dict):
            continue
        entries = block.get("ignore")
        if entries is None:
            continue
        for entry in ensure_list(entries):
            if not isinstance(entry, dict):
                problems.append(
                    f"{resource.logical_id}: each deadletter.ignore entry must be a mapping "
                    f"with a rule and a reason"
                )
                continue

            rule_ids = [str(r) for r in ensure_list(entry.get("rule", entry.get("rules")))]
            reason = entry.get("reason")
            if not rule_ids:
                problems.append(f"{resource.logical_id}: deadletter.ignore entry names no rule")
                continue
            if not isinstance(reason, str) or not reason.strip():
                problems.append(
                    f"{resource.logical_id}: suppression of {', '.join(rule_ids)} has no reason "
                    f"and was not applied"
                )
                continue

            expires, problem = _parse_expiry(entry.get("expires"), resource.logical_id, rule_ids)
            if problem:
                problems.append(problem)
                continue

            for rule_id in rule_ids:
                suppressions.append(
                    Suppression(
                        rule_id=rule_id,
                        resource_id=resource.logical_id,
                        reason=reason.strip(),
                        expires=expires,
                    )
                )
    return suppressions, problems


def _parse_expiry(
    value: Any, resource_id: str, rule_ids: list[str]
) -> tuple[date | None, str | None]:
    if value is None:
        return None, None
    if isinstance(value, date):
        return value, None
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip()), None
        except ValueError:
            pass
    return None, (
        f"{resource_id}: suppression of {', '.join(rule_ids)} has an unreadable expires value "
        f"({value!r}); use YYYY-MM-DD. The suppression was not applied."
    )


def apply(
    findings: list[Finding],
    suppressions: list[Suppression],
    today: date | None = None,
) -> list[Finding]:
    """Mark covered findings as suppressed. Nothing is removed."""
    if not suppressions:
        return findings
    when = today or date.today()
    for finding in findings:
        for suppression in suppressions:
            if suppression.covers(finding, when):
                finding.suppressed = True
                finding.suppression = suppression.describe()
                break
    return findings


__all__ = ["Suppression", "collect", "apply", "METADATA_KEY"]
