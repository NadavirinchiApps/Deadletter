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


# --------------------------------------------------------------------------
# Synthesized CDK output
#
# `cdk.out` stays out of the generic walk: it is full of asset copies and
# nested templates that would be scanned twice. The manifest says exactly which
# files are stacks, so a CDK team gets scanned without listing templates by hand.
# --------------------------------------------------------------------------

def _assembly(tmp_path: Path, template: str = TEMPLATE) -> Path:
    import json

    out = tmp_path / "cdk.out"
    out.mkdir()
    (out / "OrdersStack.template.json").write_text(
        '{"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": "q"}}}}',
        encoding="utf-8",
    )
    (out / "OrdersStack.assets.json").write_text('{"files": {}}', encoding="utf-8")
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "version": "36.0.0",
                "artifacts": {
                    "OrdersStack.assets": {"type": "cdk:asset-manifest"},
                    "OrdersStack": {
                        "type": "aws:cloudformation:stack",
                        "properties": {"templateFile": "OrdersStack.template.json"},
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return out


def test_a_cloud_assembly_manifest_names_the_stacks_to_scan(tmp_path: Path):
    from deadletter.discover import cdk_stacks

    out = _assembly(tmp_path)

    assert cdk_stacks(tmp_path) == [out / "OrdersStack.template.json"]


def test_only_the_manifests_stacks_are_scanned_not_the_whole_directory(tmp_path: Path):
    """Asset staging copies live in cdk.out too, and scanning them would report
    the same finding twice against a file nobody edits."""
    out = _assembly(tmp_path)
    staged = out / "asset.abc123"
    staged.mkdir()
    (staged / "template.yaml").write_text(TEMPLATE, encoding="utf-8")

    targets, problems = resolve([tmp_path])

    assert not problems
    assert [t.path for t in targets] == [out / "OrdersStack.template.json"]
    assert targets[0].origin == "cdk"


def test_a_cdk_out_with_no_manifest_is_still_skipped(tmp_path: Path):
    out = tmp_path / "cdk.out"
    out.mkdir()
    (out / "OrdersStack.template.json").write_text(TEMPLATE, encoding="utf-8")

    _, problems = resolve([tmp_path])

    assert problems and "no CloudFormation or SAM templates" in problems[0]


def test_allow_empty_turns_an_empty_directory_into_a_clean_exit(tmp_path: Path, capsys):
    """pre-commit runs the hook on whatever repository it is installed in, and
    a checkout with no templates is not a wrong path."""
    (tmp_path / "readme.md").write_text("nothing here", encoding="utf-8")

    assert main([str(tmp_path)]) == 2
    assert main([str(tmp_path), "--allow-empty"]) == 0
    assert capsys.readouterr().err.count("ERROR") == 1


def test_allow_empty_still_fails_on_a_path_that_does_not_exist(tmp_path: Path, capsys):
    """"Nothing to scan" and "you typed the wrong path" are different answers."""
    assert main([str(tmp_path / "missing"), "--allow-empty"]) == 2
    assert "no such file or directory" in capsys.readouterr().err
