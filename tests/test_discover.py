"""Discovery has to be quiet about what isn't a template and loud about typos."""

from __future__ import annotations

from pathlib import Path

from deadletter.cli import main
from deadletter.discover import looks_like_template, resolve, walk

from conftest import FIXTURES

TEMPLATE = """\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: q
"""


def test_a_directory_expands_to_the_templates_inside_it():
    found = walk(FIXTURES)

    assert len(found) > 10
    assert all(path.suffix in (".yaml", ".yml", ".json") for path in found)
    assert FIXTURES / "orders" / "template.yaml" in found


def test_ordinary_repository_yaml_is_not_mistaken_for_a_template(tmp_path: Path):
    (tmp_path / "template.yaml").write_text(TEMPLATE, encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n", encoding="utf-8"
    )
    (tmp_path / "config.json").write_text('{"log_level": "debug"}', encoding="utf-8")

    assert walk(tmp_path) == [tmp_path / "template.yaml"]


def test_generated_and_vendored_directories_are_skipped(tmp_path: Path):
    """A build directory holds a copy of a template already scanned from source;
    scanning both reports every finding twice."""
    (tmp_path / "template.yaml").write_text(TEMPLATE, encoding="utf-8")
    for noise in (".aws-sam", "node_modules", "cdk.out", ".git"):
        directory = tmp_path / noise
        directory.mkdir()
        (directory / "template.yaml").write_text(TEMPLATE, encoding="utf-8")

    assert walk(tmp_path) == [tmp_path / "template.yaml"]


def test_a_named_file_is_scanned_even_where_discovery_would_skip_it(tmp_path: Path):
    """Naming a path is a statement that it is a template."""
    build = tmp_path / "build"
    build.mkdir()
    named = build / "template.yaml"
    named.write_text(TEMPLATE, encoding="utf-8")

    targets, problems = resolve([named])

    assert not problems
    assert [t.path for t in targets] == [named]
    assert targets[0].explicit is True


def test_the_same_template_named_twice_is_scanned_once(tmp_path: Path):
    path = tmp_path / "template.yaml"
    path.write_text(TEMPLATE, encoding="utf-8")

    targets, _ = resolve([tmp_path, path])

    assert [t.path for t in targets] == [path]


def test_a_directory_with_no_templates_is_an_error_not_a_clean_scan(tmp_path: Path):
    """Silence here would let a wrong path pass CI as a green run."""
    (tmp_path / "readme.md").write_text("nothing here", encoding="utf-8")

    _, problems = resolve([tmp_path])

    assert problems and "no CloudFormation or SAM templates" in problems[0]


def test_cli_rejects_a_path_that_does_not_exist(capsys, tmp_path: Path):
    exit_code = main([str(tmp_path / "missing.yaml")])

    assert exit_code == 2
    assert "no such file or directory" in capsys.readouterr().err


def test_cli_fails_on_a_named_file_that_does_not_parse(tmp_path: Path, capsys):
    broken = tmp_path / "template.yaml"
    broken.write_text("Resources: [this is not a mapping\n", encoding="utf-8")

    exit_code = main([str(broken)])

    assert exit_code == 2
    assert "ERROR" in capsys.readouterr().err


def test_cli_scans_a_directory_and_reports_across_every_template(capsys):
    exit_code = main([str(FIXTURES / "EDA011"), "--format", "json", "--fail-on", "none"])

    import json

    report = json.loads(capsys.readouterr().out)
    sources = {finding["source"] for finding in report["findings"]}
    assert exit_code == 0
    assert len(sources) >= 1
    assert any("violating" in source for source in sources)


def test_mermaid_still_refuses_more_than_one_template(capsys):
    exit_code = main([str(FIXTURES / "EDA011"), "--format", "mermaid"])

    assert exit_code == 2
    assert "exactly one template" in capsys.readouterr().err


def test_looks_like_template_needs_more_than_the_word_resources(tmp_path: Path):
    prose = tmp_path / "notes.yaml"
    prose.write_text("title: Resources we still need to buy\n", encoding="utf-8")

    assert not looks_like_template(prose)
