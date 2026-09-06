"""Human and machine-readable report rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .findings import Confidence, Finding, Verdict


def summary(findings: Iterable[Finding]) -> dict[str, int]:
    """Counts of what still fails the build, plus how much was waived."""
    counts = {str(verdict): 0 for verdict in Verdict}
    counts["suppressed"] = 0
    for finding in findings:
        if finding.suppressed:
            counts["suppressed"] += 1
        else:
            counts[str(finding.verdict)] += 1
    return counts


def report_dict(findings: list[Finding], coverage=None) -> dict:
    report = {
        "tool": {"name": "deadletter", "version": _version()},
        "summary": summary(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    if coverage is not None:
        report["coverage"] = coverage.to_dict()
    return report


def render_json(findings: list[Finding], coverage=None) -> str:
    return json.dumps(report_dict(findings, coverage), indent=2, sort_keys=True)


def render_text(
    findings: list[Finding], show_suppressed: bool = False, coverage=None
) -> str:
    counts = summary(findings)
    shown = [f for f in findings if show_suppressed or not f.suppressed]
    if not shown:
        # "No findings" on its own invites the reader to conclude the system is
        # sound, when it may only mean the scan could not see the part that
        # matters. The scope always travels with the result.
        tail = _suppressed_note(counts)
        head = "No findings." + (f" {tail}" if tail else "")
        return head + _coverage_block(coverage)

    lines: list[str] = []
    for finding in shown:
        location = _display_location(finding)
        prefix = "SUPPRESSED " if finding.suppressed else ""
        lines.append(f"[{prefix}{finding.verdict}] {finding.rule_id} - {finding.title}")
        if location:
            lines.append(f"  at {location}")
        lines.append(f"  {finding.message}")
        # The reader has to be able to tell a demonstrated violation from a
        # prediction without opening the JSON.
        lines.append(
            f"  basis: {finding.confidence.lower()} "
            f"{finding.basis.lower()} | impact if it bites: {finding.impact.lower()}"
        )
        for assumption in finding.assumptions:
            lines.append(f"  assumes: {assumption}")
        lines.append(f"  resources: {', '.join(finding.resources)}")
        if finding.suppressed and finding.suppression:
            lines.append(f"  suppressed by {finding.suppression}")
        for fix in finding.remediations:
            lines.append(f"  fix {fix.path}: {fix.description}")
        lines.append("")

    line = f"Summary: {counts['BLOCK']} BLOCK, {counts['WARN']} WARN, {counts['INFO']} INFO"
    note = _suppressed_note(counts)
    lines.append(line + (f", {counts['suppressed']} suppressed" if counts["suppressed"] else ""))
    if note and not show_suppressed:
        lines.append(note)
    return "\n".join(lines) + _coverage_block(coverage)


def _coverage_block(coverage) -> str:
    if coverage is None:
        return ""
    scanned = len(coverage.templates_scanned)
    resources = sum(coverage.resources_by_kind.values())
    lines = [
        "",
        f"Coverage: {scanned} template(s), {resources} resource(s), "
        f"{len(coverage.rules_run)} rule(s).",
    ]
    limits = coverage.limits()
    if not limits:
        lines.append("  Nothing limited this scan.")
    else:
        lines.append("  Not assessed:")
        lines.extend(f"    - {limit}" for limit in limits)
    return "\n" + "\n".join(lines)


def _suppressed_note(counts: dict[str, int]) -> str:
    if not counts.get("suppressed"):
        return ""
    plural = "" if counts["suppressed"] == 1 else "s"
    return (
        f"{counts['suppressed']} suppressed finding{plural} hidden; "
        f"re-run with --show-suppressed to see what was waived."
    )


def render_sarif(findings: list[Finding]) -> str:
    rule_ids = sorted({finding.rule_id for finding in findings})
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    rules = []
    for rule_id in rule_ids:
        example = next(finding for finding in findings if finding.rule_id == rule_id)
        rules.append(
            {
                "id": rule_id,
                "name": example.title.replace(" ", ""),
                "shortDescription": {"text": example.title},
                "defaultConfiguration": {"level": _sarif_level(example.verdict)},
            }
        )

    results = []
    for finding in findings:
        result = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": _sarif_level(finding.verdict),
            "message": {"text": finding.message},
            "properties": {
                "resources": finding.resources,
                "evidence": finding.evidence,
                "impact": str(finding.impact),
                "confidence": str(finding.confidence),
                "basis": str(finding.basis),
                "assumptions": finding.assumptions,
                "inferred": finding.inferred,
                "remediations": [fix.to_dict() for fix in finding.remediations],
            },
        }
        physical = _sarif_location(finding)
        if physical:
            result["locations"] = [{"physicalLocation": physical}]
        if finding.suppressed:
            # SARIF models this natively, so code-scanning UIs grey the result
            # out instead of raising it. Inventing a property would not.
            result["suppressions"] = [
                {
                    "kind": "inSource",
                    "justification": finding.suppression or "suppressed in template metadata",
                }
            ]
        results.append(result)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deadletter",
                        "version": _version(),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _display_location(finding: Finding) -> str:
    if not finding.source:
        return ""
    if finding.location and finding.location.line:
        return f"{finding.source}:{finding.location.line}:{finding.location.column or 1}"
    return finding.source


def _sarif_location(finding: Finding) -> dict | None:
    if not finding.source:
        return None
    source = Path(finding.source)
    if source.is_absolute():
        try:
            uri = source.as_uri()
        except ValueError:
            uri = source.as_posix()
    else:
        uri = source.as_posix()
    physical: dict = {"artifactLocation": {"uri": uri}}
    if finding.location and finding.location.line:
        physical["region"] = {
            "startLine": finding.location.line,
            "startColumn": finding.location.column or 1,
        }
    return physical


def _sarif_level(verdict: Verdict) -> str:
    return {
        Verdict.BLOCK: "error",
        Verdict.WARN: "warning",
        Verdict.INFO: "note",
    }[verdict]


def _version() -> str:
    from . import __version__

    return __version__


__all__ = ["render_json", "render_sarif", "render_text", "report_dict", "summary"]
