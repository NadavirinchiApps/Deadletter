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
    workflow = yaml_loads((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    uses = [
        step["uses"]
        for step in workflow["jobs"]["test"]["steps"]
        if isinstance(step, dict) and "uses" in step
    ]

    assert uses
    assert all(len(reference.rsplit("@", 1)[1].split()[0]) == 40 for reference in uses)
