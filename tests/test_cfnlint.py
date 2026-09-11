"""The rule pack that runs inside cfn-lint.

cfn-lint is already in the pipeline of most teams who write CloudFormation, so
this adapter is the cheapest distribution the engine has. What it must not do is
report something different from the CLI: same findings, same messages, split
into errors and warnings by the same default policy.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from deadletter import build, load
from deadletter.findings import Verdict
from deadletter.rules import all_rules, run

from conftest import FIXTURES

cfnlint = pytest.importorskip("cfnlint", reason="cfn-lint is an optional dependency")

from cfnlint.decode import cfn_yaml  # noqa: E402
from cfnlint.template import Template as CfnTemplate  # noqa: E402

from deadletter.integrations.cfnlint import BLOCKING_RULES  # noqa: E402
from deadletter.integrations import cfnlint as pack  # noqa: E402


def _cfn(path):
    decoded = cfn_yaml.load(str(path))
    # Older cfn-lint returned (template, matches); current returns the template.
    body = decoded[0] if isinstance(decoded, tuple) else decoded
    return CfnTemplate(str(path), body)


def _adapters(rule_id: str):
    advisory = getattr(pack, f"Advisory{rule_id}")()
    blocking = getattr(pack, f"Blocking{rule_id}", None)
    return advisory, blocking() if blocking else None


@pytest.mark.parametrize("rule", [rule.id for rule in all_rules()])
def test_the_pack_reports_exactly_what_the_cli_reports(rule):
    path = FIXTURES / rule / "violating.yaml"
    cfn = _cfn(path)
    expected = [f for f in run(build(load(path)), [rule]) if not f.suppressed]

    advisory, blocking = _adapters(rule)
    matches = list(advisory.match(cfn))
    if blocking is not None:
        matches.extend(blocking.match(cfn))

    assert len(matches) == len(expected), f"{rule}: {[m.message for m in matches]}"
    reported = {m.message.split(": ", 1)[1] for m in matches}
    assert reported == {f.message for f in expected}
    for match in matches:
        # cfn-lint reports against a component path, and a path that does not
        # reach a resource points the reader at the top of the file.
        assert match.path[0] == "Resources"
        assert len(match.path) >= 2


@pytest.mark.parametrize("rule", [rule.id for rule in all_rules()])
def test_a_finding_is_an_error_or_a_warning_and_never_both(rule):
    """cfn-lint has no policy flag, so the split has to survive as severity.
    Reporting the same defect under two ids would just be noise."""
    path = FIXTURES / rule / "violating.yaml"
    cfn = _cfn(path)
    findings = [f for f in run(build(load(path)), [rule]) if not f.suppressed]
    blocks = sum(1 for f in findings if f.verdict is Verdict.BLOCK)

    advisory, blocking = _adapters(rule)
    assert len(advisory.match(cfn)) == len(findings) - blocks
    if blocking is not None:
        assert len(blocking.match(cfn)) == blocks
    else:
        assert blocks == 0, f"{rule} can block but ships no E-class"


def test_only_rules_that_can_block_ship_an_error_class():
    for rule in all_rules():
        has_error_class = hasattr(pack, f"Blocking{rule.id}")
        assert has_error_class is (rule.id in BLOCKING_RULES)


def test_ids_stay_in_the_range_reserved_for_rules_cfn_lint_does_not_ship():
    for rule in all_rules():
        advisory, blocking = _adapters(rule.id)
        assert advisory.id.startswith("W91") and len(advisory.id) == 5
        if blocking is not None:
            assert blocking.id == "E" + advisory.id[1:]


def test_cfn_lint_actually_loads_and_runs_the_pack():
    """The unit tests call `match` directly; this one proves cfn-lint finds the
    classes, which is the part a refactor breaks silently."""
    path = FIXTURES / "EDA001" / "violating-requirement.yaml"
    out = subprocess.run(
        [
            sys.executable, "-c", "import sys; from cfnlint.runner import main; sys.exit(main())",
            "-a", "deadletter.integrations.cfnlint", "-f", "json", "-t", str(path),
        ],
        capture_output=True, text=True,
    )
    reported = json.loads(out.stdout or "[]")
    ours = [m for m in reported if m["Rule"]["Id"].startswith(("E91", "W91"))]

    assert any(m["Rule"]["Id"] == "E9101" and m["Level"] == "Error" for m in ours)
    assert all(m["Rule"]["Source"].endswith(".md") for m in ours)
    match = next(m for m in ours if m["Rule"]["Id"] == "E9101")
    assert match["Location"]["Path"] == [
        "Resources", "ChargeQueue", "Properties", "VisibilityTimeout"
    ]
