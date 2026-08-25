"""Human and machine-readable report rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .findings import Finding, Severity


def summary(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {str(severity): 0 for severity in Severity}
    for finding in findings:
        counts[str(finding.severity)] += 1
    return counts


def report_dict(findings: list[Finding]) -> dict:
    return {
        "tool": {"name": "deadletter", "version": _version()},
        "summary": summary(findings),
        "findings": [finding.to_dict() for finding in findings],
    }


def render_json(findings: list[Finding]) -> str:
    return json.dumps(report_dict(findings), indent=2, sort_keys=True)


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."

    lines: list[str] = []
    for finding in findings:
        location = _display_location(finding)
        lines.append(f"[{finding.severity}] {finding.rule_id} - {finding.title}")
        if location:
            lines.append(f"  at {location}")
        lines.append(f"  {finding.message}")
        lines.append(f"  resources: {', '.join(finding.resources)}")
        for fix in finding.remediations:
            lines.append(f"  fix {fix.path}: {fix.description}")
        lines.append("")

    counts = summary(findings)
    lines.append(
        f"Summary: {counts['BLOCK']} BLOCK, {counts['WARN']} WARN, {counts['INFO']} INFO"
    )
    return "\n".join(lines)


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
                "defaultConfiguration": {"level": _sarif_level(example.severity)},
            }
        )

    results = []
    for finding in findings:
        result = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.message},
            "properties": {
                "resources": finding.resources,
                "evidence": finding.evidence,
                "inferred": finding.inferred,
                "remediations": [fix.to_dict() for fix in finding.remediations],
            },
        }
        physical = _sarif_location(finding)
        if physical:
            result["locations"] = [{"physicalLocation": physical}]
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


def _sarif_level(severity: Severity) -> str:
    return {
        Severity.BLOCK: "error",
        Severity.WARN: "warning",
        Severity.INFO: "note",
    }[severity]


def _version() -> str:
    from . import __version__

    return __version__


__all__ = ["render_json", "render_sarif", "render_text", "report_dict", "summary"]
