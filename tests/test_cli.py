from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from deadletter.cli import main

from conftest import FIXTURES


def test_json_cli_report_and_blocking_exit_code(capsys):
    path = FIXTURES / "EDA001" / "violating.yaml"

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

    exit_code = main([str(FIXTURES / "EDA001" / "violating.yaml"), "--fail-on", "none"])
    sys.stdout.flush()

    assert exit_code == 0
    assert "—" in raw.getvalue().decode("utf-8")


def test_cli_can_write_a_report_file(capsys, tmp_path: Path):
    path = FIXTURES / "EDA001" / "violating.yaml"
    output = tmp_path / "report.json"

    exit_code = main(
        [str(path), "--format", "json", "--fail-on", "none", "--output", str(output)]
    )

    assert exit_code == 0
    assert capsys.readouterr().out == ""
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["BLOCK"] >= 1
