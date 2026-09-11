from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from deadletter.cli import main

from conftest import FIXTURES


def test_json_cli_report_and_blocking_exit_code(capsys):
    # A confirmed violation of an AWS constraint — the only shape that blocks
    # under the default policy.
    path = FIXTURES / "EDA001" / "violating-requirement.yaml"

    exit_code = main([str(path), "--format", "json"])

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert report["summary"]["BLOCK"] >= 1
    assert report["findings"][0]["source"] == str(path)
    assert report["findings"][0]["remediations"][0]["path"].startswith("/Resources/")


def test_cli_returns_zero_when_fail_threshold_is_not_met(capsys):
    path = FIXTURES / "EDA004" / "passing.yaml"

    exit_code = main([str(path), "--format", "text", "--rule", "EDA004"])

    assert exit_code == 0
    assert "No findings" in capsys.readouterr().out


def test_cli_returns_two_for_a_scan_error(capsys, tmp_path: Path):
    missing = tmp_path / "missing.yaml"

    exit_code = main([str(missing)])

    assert exit_code == 2
    assert "ERROR" in capsys.readouterr().err


def test_sarif_report_is_valid_json(capsys):
    path = Path("tests/fixtures/EDA003/violating.yaml")

    exit_code = main([str(path), "--format", "sarif", "--fail-on", "none"])

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["version"] == "2.1.0"
    assert report["runs"][0]["results"]
    uri = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert not uri.startswith("file:")


def test_mermaid_output_is_available_from_the_cli(capsys):
    path = FIXTURES / "orders" / "template.yaml"

    exit_code = main([str(path), "--format", "mermaid", "--fail-on", "none"])

    assert exit_code == 0
    assert capsys.readouterr().out.startswith("graph LR")


def test_report_text_reaches_stdout_as_utf8(monkeypatch):
    """A cp1252 stdout must not mangle the em dashes in finding messages."""
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))

    exit_code = main(
        [str(FIXTURES / "EDA001" / "violating-requirement.yaml"), "--fail-on", "none"]
    )
    sys.stdout.flush()

    assert exit_code == 0
    assert "—" in raw.getvalue().decode("utf-8")


def test_cli_can_write_a_report_file(capsys, tmp_path: Path):
    path = FIXTURES / "EDA001" / "violating-requirement.yaml"
    output = tmp_path / "report.json"

    exit_code = main(
        [str(path), "--format", "json", "--fail-on", "none", "--output", str(output)]
    )

    assert exit_code == 0
    assert capsys.readouterr().out == ""
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["BLOCK"] >= 1


def test_the_deprecated_severity_key_is_gone(capsys):
    """0.4.0 promised removal in the next minor. `verdict` is the only name for
    the policy decision; `severity` used to mean impact, confidence and policy
    at once, which is the confusion the three axes exist to end."""
    main([str(FIXTURES / "EDA001" / "violating-requirement.yaml"), "--format", "json"])
    report = json.loads(capsys.readouterr().out)

    finding = report["findings"][0]
    assert "severity" not in finding
    assert finding["verdict"] == "BLOCK"


def test_a_finding_carries_the_tools_that_also_report_it(capsys):
    """EDA002's dead-letter half is covered by three free tools. A reader who
    hears it from us first has no reason to doubt the rest of the report."""
    main(
        [
            str(FIXTURES / "EDA002" / "violating.yaml"),
            "--format", "json",
            "--rule", "EDA002",
            "--fail-on", "none",
        ]
    )
    report = json.loads(capsys.readouterr().out)

    assert any("cfn-lint-serverless" in o for o in report["findings"][0]["overlaps"])

    main([str(FIXTURES / "EDA002" / "violating.yaml"), "--rule", "EDA002", "--fail-on", "none"])
    assert "also reported by:" in capsys.readouterr().out


def test_a_cdk_finding_names_the_construct_the_author_wrote(capsys):
    """`Handler2F3E4D5C` is not something anyone can search for. The construct
    path is what they typed, and it has to reach text, JSON and SARIF."""
    path = FIXTURES / "cdk" / "StateMachine.template.json"

    main([str(path), "--rule", "EDA010", "--fail-on", "none"])
    assert "construct: PaymentsStack/PaymentsStateMachine/Resource" in capsys.readouterr().out

    main([str(path), "--rule", "EDA010", "--fail-on", "none", "--format", "json"])
    finding = json.loads(capsys.readouterr().out)["findings"][0]
    assert finding["location"]["address"] == "PaymentsStack/PaymentsStateMachine/Resource"

    main([str(path), "--rule", "EDA010", "--fail-on", "none", "--format", "sarif"])
    result = json.loads(capsys.readouterr().out)["runs"][0]["results"][0]
    assert result["properties"]["address"] == "PaymentsStack/PaymentsStateMachine/Resource"


def test_sarif_rules_point_at_their_documentation(capsys):
    main([str(FIXTURES / "EDA010" / "violating.yaml"), "--fail-on", "none", "--format", "sarif"])
    driver = json.loads(capsys.readouterr().out)["runs"][0]["tool"]["driver"]

    assert driver["rules"][0]["helpUri"].endswith("docs/rules/EDA010.md")
