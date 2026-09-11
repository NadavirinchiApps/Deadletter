"""Deadletter's rules as a cfn-lint rule pack.

    cfn-lint -t template.yaml -a deadletter.integrations.cfnlint

`-a` takes one or more module names, so a template written after it is read as
another module name and cfn-lint fails before it lints anything. Pass the
template under `-t`.

cfn-lint is already in most CloudFormation pipelines, so this is the cheapest
way for the cross-resource rules to reach somebody: no new tool, no new step,
no new configuration file.

Rule IDs
--------
cfn-lint reserves the 9000 range for rules that do not ship with it — no
built-in rule uses it. Each EDA rule gets `W91<nn>`; the five that can reach a
BLOCK verdict under Deadletter's default policy also get `E91<nn>`.

The two never both fire for one finding. A finding the default policy would
block is reported as an error and nothing else; everything else is reported as
a warning. cfn-lint has no policy flag, so this is how the same distinction
survives the trip — and reporting the same defect twice under two IDs would be
noise, which is what this project spends its credibility avoiding.

What is lost compared to the CLI: cfn-lint shows one message per finding, so
the assumptions, the evidence and the coverage block do not travel with it. The
message names both resources and quotes both values, which is the part a reader
cannot do without.
"""

from __future__ import annotations

from typing import Any

from cfnlint.rules import CloudFormationLintRule, RuleMatch

from .. import parse
from ..findings import DEFAULT_POLICY, Finding, Verdict
from ..graph import build
from ..rules import all_rules, get_rule, run

# The rules whose findings can reach BLOCK under the default policy. Anything
# else is warn-only by construction, so shipping an E-class for it would
# promise a severity it can never carry.
BLOCKING_RULES = ("EDA001", "EDA005", "EDA008", "EDA009", "EDA012")


def _findings_for(rule_id: str, cfn: Any) -> list[Finding]:
    """Run one Deadletter rule against a template cfn-lint has already decoded."""
    template = parse.from_dict(cfn.template or {}, source=getattr(cfn, "filename", None))
    return run(build(template), [rule_id], policy=DEFAULT_POLICY)


def _path(finding: Finding) -> list[str | int]:
    """A JSON pointer back into the component path cfn-lint reports against."""
    pointer = finding.location.path if finding.location else ""
    parts: list[str | int] = []
    for part in pointer.strip("/").split("/"):
        if not part:
            continue
        unescaped = part.replace("~1", "/").replace("~0", "~")
        parts.append(int(unescaped) if unescaped.isdigit() else unescaped)
    return parts or ["Resources"]


def _make(rule_id: str, prefix: str, blocking: bool) -> type[CloudFormationLintRule]:
    source = get_rule(rule_id)
    assert source is not None, rule_id

    class _Adapter(CloudFormationLintRule):
        id = f"{prefix}91{rule_id[3:].lstrip('0').rjust(2, '0')}"
        shortdesc = source.title
        description = source.condition or source.title
        source_url = f"https://github.com/NadavirinchiApps/Deadletter/blob/prod/{source.docs}"
        tags = ["deadletter", "event-driven", rule_id.lower()]

        def match(self, cfn):
            matches = []
            for finding in _findings_for(rule_id, cfn):
                if finding.suppressed:
                    continue  # the template waived it, with a reason
                if (finding.verdict is Verdict.BLOCK) is not blocking:
                    continue
                matches.append(RuleMatch(_path(finding), f"{rule_id}: {finding.message}"))
            return matches

    _Adapter.__name__ = f"{'Blocking' if blocking else 'Advisory'}{rule_id}"
    _Adapter.__qualname__ = _Adapter.__name__
    return _Adapter


# cfn-lint discovers rules by scanning this module for CloudFormationLintRule
# subclasses, so each generated class has to land in the module namespace.
for _rule in all_rules():
    globals()[f"Advisory{_rule.id}"] = _make(_rule.id, "W", blocking=False)
    if _rule.id in BLOCKING_RULES:
        globals()[f"Blocking{_rule.id}"] = _make(_rule.id, "E", blocking=True)
del _rule
