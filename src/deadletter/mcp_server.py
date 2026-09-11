"""Deadletter as an MCP server.

    claude mcp add deadletter -- deadletter-mcp

An AI reviewer reading a pull request has no way to know that a queue's
visibility timeout has to clear the timeout of the function three resources
away. It will guess, and it will guess confidently. This turns the guess into a
tool call against the same graph and the same twelve rules the CLI runs.

Three tools:

    scan_paths(paths, policy, rules)  the JSON report, coverage block included
    explain_rule(rule_id)             what the rule claims and what it rests on
    event_graph(path)                 the delivery graph as Mermaid

The tool functions are plain functions and do not import the MCP SDK, so they
can be tested — and reused — without a server process or the optional
dependency. `mcp` is only needed to actually serve them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import __version__, build, load
from .coverage import collect as collect_coverage
from .discover import resolve as resolve_targets
from .findings import POLICIES
from .report import report_dict
from .rules import all_rules, get_rule, run

SERVER_NAME = "deadletter"


def scan_paths(
    paths: list[str],
    policy: str = "default",
    rules: list[str] | None = None,
) -> dict[str, Any]:
    """Scan templates or directories and return the full JSON report.

    The report carries the coverage block, so a caller can tell "nothing is
    wrong here" apart from "this scan could not see the part that matters".
    """
    if policy not in POLICIES:
        raise ValueError(f"unknown policy {policy!r}; choose one of {sorted(POLICIES)}")

    targets, problems = resolve_targets([Path(p) for p in paths])
    findings = []
    graphs = []
    unreadable: list[tuple[str, str]] = []
    for target in targets:
        try:
            graph = build(load(target.path))
        except (OSError, ValueError) as error:
            unreadable.append((str(target.path), type(error).__name__))
            continue
        graphs.append(graph)
        findings.extend(run(graph, rules, policy=POLICIES[policy]))

    coverage = collect_coverage(
        graphs,
        rules_run=rules or [rule.id for rule in all_rules()],
        unreadable=unreadable,
        roots=[Path(p) for p in paths],
    )
    report = report_dict(sorted(findings, key=lambda f: f.sort_key), coverage)
    report["policy"] = {"name": policy, "description": POLICIES[policy].description}
    if problems:
        report["problems"] = problems
    return report


def explain_rule(rule_id: str) -> dict[str, Any]:
    """What one rule claims, what it can carry, and who else reports it."""
    rule = get_rule(rule_id.upper())
    if rule is None:
        raise ValueError(
            f"unknown rule {rule_id!r}; the pack is {', '.join(r.id for r in all_rules())}"
        )
    return {
        "id": rule.id,
        "title": rule.title,
        "impact": str(rule.impact),
        "basis": str(rule.basis),
        "condition": rule.condition,
        "overlaps": list(rule.overlaps),
        "docs": rule.docs,
        "documentation": _rule_docs(rule.docs),
    }


def event_graph(path: str) -> str:
    """The delivery graph of one template, as a Mermaid diagram."""
    return build(load(Path(path))).to_mermaid()


def _rule_docs(relative: str) -> str | None:
    """The rule's write-up, when it ships beside the package or the repository."""
    for base in (Path(__file__).resolve().parents[2], Path.cwd()):
        candidate = base / relative
        if candidate.is_file():
            try:
                return candidate.read_text(encoding="utf-8")
            except OSError:  # pragma: no cover - unreadable file on disk
                return None
    return None


def _server():
    """Build the MCP server. Imported lazily: `mcp` is an optional dependency."""
    try:
        # 2.x. FastMCP was renamed to MCPServer; the decorator API is the same.
        from mcp.server.mcpserver import MCPServer as Server
    except ModuleNotFoundError:  # pragma: no cover - depends on the installed SDK
        from mcp.server.fastmcp import FastMCP as Server  # type: ignore[no-redef]

    server = Server(
        name=SERVER_NAME,
        version=__version__,
        instructions=(
            "Checks event delivery between AWS serverless resources in "
            "CloudFormation, SAM and synthesized CDK templates. Every finding "
            "states its impact, how well the condition is known (confidence), "
            "and whether the threshold is an AWS requirement or AWS advice "
            "(basis). Read those before repeating a finding as fact, and read "
            "the coverage block before reporting that a template is clean."
        ),
    )
    server.tool()(scan_paths)
    server.tool()(explain_rule)
    server.tool()(event_graph)
    return server


def main() -> int:  # pragma: no cover - exercised by running the server
    _server().run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
