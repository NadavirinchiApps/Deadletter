"""The MCP tools.

An AI reviewer reading a diff cannot see that a queue's visibility timeout has
to clear the timeout of a function three resources away, so it guesses. These
tools exist to replace the guess — which only works if what they return is the
same thing the CLI returns, coverage block and all.

The tool functions are called directly. No server process, and no dependency on
the MCP SDK being installed.
"""

from __future__ import annotations

import pytest

from deadletter.mcp_server import event_graph, explain_rule, scan_paths

from conftest import FIXTURES


def test_scan_paths_returns_the_same_report_the_cli_prints():
    report = scan_paths([str(FIXTURES / "EDA001" / "violating-requirement.yaml")])

    assert report["summary"]["BLOCK"] == 1
    assert report["findings"][0]["rule_id"] == "EDA001"
    assert report["policy"]["name"] == "default"


def test_the_report_carries_the_coverage_block():
    """Without it, "no findings" reads as "your system is sound"."""
    report = scan_paths([str(FIXTURES / "EDA004" / "passing.yaml")], rules=["EDA004"])

    assert report["findings"] == []
    assert "coverage" in report and report["coverage"]["rules_run"] == ["EDA004"]


def test_a_directory_is_scanned_as_a_whole():
    report = scan_paths([str(FIXTURES / "cdk")])

    sources = {finding["source"] for finding in report["findings"]}
    assert len(sources) == 2
    assert any(f["rule_id"] == "EDA004" for f in report["findings"])


def test_the_policy_travels_with_the_report():
    path = str(FIXTURES / "EDA001" / "violating.yaml")

    assert scan_paths([path], policy="default")["summary"]["BLOCK"] == 0
    strict = scan_paths([path], policy="strict")
    assert strict["summary"]["BLOCK"] >= 1
    assert "recommended" in strict["policy"]["description"]


def test_an_unknown_policy_says_what_the_choices_are():
    with pytest.raises(ValueError, match="advisory"):
        scan_paths([str(FIXTURES / "orders" / "template.yaml")], policy="paranoid")


def test_explain_rule_states_the_axes_and_the_overlaps():
    explained = explain_rule("eda002")

    assert explained["id"] == "EDA002"
    assert explained["impact"] == "LOSS"
    assert explained["basis"] == "RECOMMENDATION"
    assert any("cfn-lint-serverless" in o for o in explained["overlaps"])
    assert explained["docs"] == "docs/rules/EDA002.md"


def test_explain_rule_reads_the_written_page_when_it_ships():
    explained = explain_rule("EDA001")

    assert explained["documentation"] is not None
    assert "EDA001" in explained["documentation"]


def test_an_unknown_rule_lists_the_pack():
    with pytest.raises(ValueError, match="EDA012"):
        explain_rule("EDA999")


def test_event_graph_returns_mermaid():
    diagram = event_graph(str(FIXTURES / "cdk" / "Stack.template.json"))

    assert diagram.startswith("graph LR")
    assert "publish" in diagram
