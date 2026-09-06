"""deadletter — pre-deployment event-delivery correctness scanner for AWS.

    from deadletter import scan
    findings = scan("template.yaml")
"""

from .findings import Finding, Remediation, Severity, SourceLocation
from .graph import EventGraph, build
from .parse import Template, load, loads

__version__ = "0.4.1"


def scan(path, rule_ids=None):
    """Parse a template, build its event graph, run the rule pack."""
    from .rules import run

    return run(build(load(path)), rule_ids)


__all__ = [
    "Finding",
    "Remediation",
    "Severity",
    "SourceLocation",
    "EventGraph",
    "Template",
    "build",
    "load",
    "loads",
    "scan",
    "__version__",
]
