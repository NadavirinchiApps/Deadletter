from __future__ import annotations

import tomllib
from pathlib import Path

from cfnlint.decode.cfn_yaml import loads as yaml_loads

from deadletter import __version__


ROOT = Path(__file__).parents[1]


def test_package_version_and_console_entry_point_stay_in_sync():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["project"]["version"] == __version__
    assert metadata["project"]["scripts"]["deadletter"] == "deadletter.cli:main"


def test_composite_action_passes_user_inputs_through_quoted_environment_values():
    action = yaml_loads((ROOT / "action.yml").read_text(encoding="utf-8"))
    scan = next(step for step in action["runs"]["steps"] if step.get("name") == "Scan template")

    assert scan["env"]["DEADLETTER_TEMPLATE"] == "${{ inputs.template }}"
    assert "${{ inputs.template }}" not in scan["run"]
    assert '"$DEADLETTER_TEMPLATE"' in scan["run"]


def test_ci_actions_are_pinned_to_full_commit_shas():
    for name in ("ci.yml", "release.yml"):
        workflow = yaml_loads((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
        uses = [
            step["uses"]
            for job in workflow["jobs"].values()
            for step in job["steps"]
            if isinstance(step, dict) and "uses" in step
        ]

        assert uses, name
        assert all(
            len(reference.rsplit("@", 1)[1].split()[0]) == 40 for reference in uses
        ), name


def test_the_action_passes_every_input_it_advertises():
    """An input the action documents and then drops is worse than not having it:
    the workflow says `policy: strict` and the scan runs the default."""
    action = yaml_loads((ROOT / "action.yml").read_text(encoding="utf-8"))
    scan = next(step for step in action["runs"]["steps"] if step.get("name") == "Scan template")

    for name in action["inputs"]:
        variable = "DEADLETTER_" + name.replace("-", "_").upper()
        assert scan["env"][variable] == "${{ inputs.%s }}" % name
        assert variable in scan["run"]


def test_every_rule_ships_a_documentation_page():
    """SARIF helpUri and the MCP explain_rule tool both point at these, so a
    missing page is a broken link in somebody else's UI."""
    from deadletter.rules import all_rules

    for rule in all_rules():
        page = ROOT / rule.docs
        assert page.is_file(), f"{rule.id} has no {rule.docs}"
        text = page.read_text(encoding="utf-8")
        assert text.startswith(f"# {rule.id} "), rule.id
        # The section that stops a page becoming marketing.
        assert "## What it cannot know" in text, rule.id


def test_the_pre_commit_hook_matches_the_cli_it_calls():
    hooks = yaml_loads((ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
    hook = next(entry for entry in hooks if entry["id"] == "deadletter")

    assert hook["entry"].startswith("deadletter ")
    # Without --allow-empty the hook fails in any checkout with no templates.
    assert "--allow-empty" in hook["entry"]
    assert hook["pass_filenames"] is False
