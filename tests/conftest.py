"""Fixture harness.

`assert_rule` is the contract every rule ships against: the violating fixture
must produce exactly the expected findings, and the passing fixture must
produce silence. The passing half is the one that matters commercially — a
false BLOCK in front of a prospect costs more than a missing rule.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deadletter import build, load
from deadletter.rules import get_rule

FIXTURES = Path(__file__).parent / "fixtures"


def graph_for(name: str, filename: str = "template.yaml"):
    return build(load(FIXTURES / name / filename))


@pytest.fixture
def orders():
    return graph_for("orders")


def assert_rule(rule_id: str, expected: int = 1, fixture_dir: str | None = None):
    """Run one rule against its violating/passing fixture pair.

    Returns the findings from the violating fixture so a test can assert on
    the numbers quoted in the message.
    """
    rule = get_rule(rule_id)
    assert rule is not None, f"{rule_id} is not registered"

    directory = FIXTURES / (fixture_dir or rule_id)
    violating, passing = directory / "violating.yaml", directory / "passing.yaml"
    assert violating.exists(), f"{rule_id} has no violating fixture"
    assert passing.exists(), f"{rule_id} has no passing fixture — a rule must prove it stays quiet"

    found = list(rule.check(build(load(violating))))
    assert len(found) == expected, f"{rule_id}: expected {expected} finding(s), got {len(found)}"
    for finding in found:
        assert finding.resources, "finding must name resources"
        assert finding.evidence, "finding must quote template values"

    clean = list(rule.check(build(load(passing))))
    assert not clean, f"{rule_id}: false positive on passing fixture: {[f.message for f in clean]}"
    return found
