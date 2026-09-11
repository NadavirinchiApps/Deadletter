"""deadletter — pre-deployment event-delivery correctness scanner for AWS.

    from deadletter import scan
    findings = scan("template.yaml")
"""

from .findings import DEFAULT_POLICY, Finding, Remediation, SourceLocation
from .graph import EventGraph, build
from .parse import Template, load, loads

__version__ = "0.6.0"


def scan(path, rule_ids=None, policy=DEFAULT_POLICY, today=None):
    """Parse a template, build its event graph, run the rule pack.

    `policy` decides which findings come back as BLOCK; `today` is the date
    suppression expiry is measured against, so a caller can test it.
    """
    from .rules import run

    return run(build(load(path)), rule_ids, today=today, policy=policy)


__all__ = [
    "Finding",
    "Remediation",
    "SourceLocation",
    "EventGraph",
    "Template",
    "build",
    "load",
    "loads",
    "scan",
    "__version__",
]
