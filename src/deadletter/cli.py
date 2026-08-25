"""Command-line interface for repository and CI scans."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__, build, load
from .findings import Finding, Severity
from .report import render_json, render_sarif, render_text
from .rules import all_rules, run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deadletter",
        description="Scan CloudFormation and SAM templates for event-delivery correctness defects.",
    )
    parser.add_argument("templates", nargs="+", type=Path, help="YAML or JSON template path")
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif", "mermaid"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "--rule",
        dest="rules",
        action="append",
        choices=[rule.id for rule in all_rules()],
        help="run only this rule; repeat for multiple rules",
    )
    parser.add_argument(
        "--fail-on",
        choices=("BLOCK", "WARN", "INFO", "none"),
        default="BLOCK",
        help="exit 1 when this severity or worse is found (default: BLOCK)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the report to this file instead of stdout",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.format == "mermaid" and len(args.templates) != 1:
        print("ERROR: mermaid output accepts exactly one template", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    graphs = []
    for path in args.templates:
        try:
            graph = build(load(path))
            graphs.append(graph)
            findings.extend(run(graph, args.rules))
        except (OSError, ValueError) as error:
            print(f"ERROR: {path}: {error}", file=sys.stderr)
            return 2

    if args.format == "json":
        output = render_json(findings)
    elif args.format == "sarif":
        output = render_sarif(findings)
    elif args.format == "mermaid":
        output = graphs[0].to_mermaid()
    else:
        output = render_text(findings)
    if args.output:
        try:
            args.output.write_text(output + "\n", encoding="utf-8")
        except OSError as error:
            print(f"ERROR: {args.output}: {error}", file=sys.stderr)
            return 2
    else:
        print(output)

    return 1 if _threshold_met(findings, args.fail_on) else 0


def _threshold_met(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = Severity(fail_on)
    return any(finding.severity.rank <= threshold.rank for finding in findings)


if __name__ == "__main__":  # pragma: no cover - exercised through __main__
    raise SystemExit(main())
