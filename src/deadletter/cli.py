"""Command-line interface for repository and CI scans."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__, build, load
from .discover import resolve
from .findings import Finding, Severity
from .report import render_json, render_sarif, render_text
from .rules import all_rules, run
from .suppress import collect


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deadletter",
        description="Scan CloudFormation and SAM templates for event-delivery correctness defects.",
    )
    parser.add_argument(
        "templates",
        nargs="+",
        type=Path,
        help="template file, or a directory to search for templates",
    )
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
    parser.add_argument(
        "--show-suppressed",
        action="store_true",
        help="include findings waived by template metadata in the text report",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _use_utf8_stdout() -> None:
    """Emit reports as UTF-8 whatever the console code page says.

    Finding messages carry em dashes and arrows. On Windows a piped stdout
    defaults to the ANSI code page, so those characters reach the reader as
    mojibake even though the same report written with --output is correct.
    """
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is None:
        return
    try:
        reconfigure(encoding="utf-8")
    except (OSError, ValueError):  # pragma: no cover - stream already detached
        pass


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _use_utf8_stdout()

    targets, problems = resolve(args.templates)
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        return 2
    if args.format == "mermaid" and len(targets) != 1:
        print(
            f"ERROR: mermaid output accepts exactly one template, got {len(targets)}",
            file=sys.stderr,
        )
        return 2

    findings: list[Finding] = []
    graphs = []
    for target in targets:
        path = target.path
        try:
            graph = build(load(path))
        except (OSError, ValueError) as error:
            if target.explicit:
                print(f"ERROR: {path}: {error}", file=sys.stderr)
                return 2
            continue  # discovered by walking, and it turned out not to be a template
        graphs.append(graph)
        findings.extend(run(graph, args.rules))
        # A suppression that does not parse must never be mistaken for one that
        # was honoured, so say so on stderr and leave the finding standing.
        for problem in collect(graph.template)[1]:
            print(f"WARNING: {path}: {problem}", file=sys.stderr)

    if not graphs:
        print("ERROR: no template could be read", file=sys.stderr)
        return 2

    if args.format == "json":
        output = render_json(findings)
    elif args.format == "sarif":
        output = render_sarif(findings)
    elif args.format == "mermaid":
        output = graphs[0].to_mermaid()
    else:
        output = render_text(findings, show_suppressed=args.show_suppressed)
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
    return any(
        finding.severity.rank <= threshold.rank
        for finding in findings
        if not finding.suppressed
    )


if __name__ == "__main__":  # pragma: no cover - exercised through __main__
    raise SystemExit(main())
