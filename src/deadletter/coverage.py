"""What the scan actually looked at, and what it could not.

"No findings" is not a result on its own. It is only meaningful next to the
scope it was produced from — a clean report over a template whose consumers all
live in another stack says almost nothing, and a reader who cannot see that
will read it as an all-clear.

So every report carries the boundaries of its own analysis:

    what was read        templates parsed, resources by kind, rules run
    what was skipped     files that did not parse, directories not walked
    what stayed open     cross-stack imports and exports, unresolved values
    what was not covered resource kinds no rule reasons about

None of these are findings. They are the reasons a finding might be missing,
which is the question somebody asks the first time they scan a repository and
get nothing back.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import model as m
from .discover import SKIP_DIRS, SUFFIXES
from .graph import EventGraph
from .intrinsics import Reference

# Resource kinds at least one rule reasons about. A kind outside this set is
# parsed and graphed but never checked, and saying so is more honest than
# letting the silence imply coverage.
COVERED_KINDS = frozenset(
    {
        m.Kind.QUEUE,
        m.Kind.TOPIC,
        m.Kind.BUS,
        m.Kind.FUNCTION,
        m.Kind.ESM,
        m.Kind.STREAM,
        m.Kind.TABLE,
        m.Kind.STATE_MACHINE,
        m.Kind.API,
        m.Kind.RULE,
        m.Kind.INVOKE_CONFIG,
        m.Kind.ALARM,
        # Not checked directly, but read: their statements are what the
        # publish and write edges several rules reason about are derived from.
        m.Kind.ROLE,
        m.Kind.POLICY,
    }
)

# Infrastructure this scanner does not read. Finding these next to the
# templates it does read is the single most useful coverage signal there is:
# it means the event flow probably continues somewhere the scan cannot follow.
OUT_OF_SCOPE = {
    ".tf": "Terraform",
    ".tfvars": "Terraform",
    ".bicep": "Bicep",
}
OUT_OF_SCOPE_DIRS = {
    "cdk.out": "synthesized CDK output",
    ".terraform": "Terraform state",
    ".aws-sam": "SAM build output",
}


@dataclass
class Coverage:
    """The scope a report was produced from."""

    templates_scanned: list[str] = field(default_factory=list)
    templates_unreadable: list[tuple[str, str]] = field(default_factory=list)
    rules_run: list[str] = field(default_factory=list)
    resources_by_kind: dict[str, int] = field(default_factory=dict)
    uncovered_kinds: dict[str, int] = field(default_factory=dict)
    cross_stack_exports: list[str] = field(default_factory=list)
    cross_stack_imports: list[str] = field(default_factory=list)
    unresolved_values: list[str] = field(default_factory=list)
    out_of_scope_infrastructure: dict[str, int] = field(default_factory=dict)
    # Functions whose execution role is not in this scan. Every rule that rests
    # on an IAM-derived edge is silent for them, and silence must not read as
    # "checked and found nothing".
    iam_unresolved_roles: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """True when nothing limited what this scan could see."""
        return not (
            self.templates_unreadable
            or self.cross_stack_exports
            or self.cross_stack_imports
            or self.unresolved_values
            or self.uncovered_kinds
            or self.out_of_scope_infrastructure
            or self.iam_unresolved_roles
        )

    def limits(self) -> list[str]:
        """Every reason a finding could be missing, in plain sentences."""
        notes: list[str] = []
        if self.templates_unreadable:
            listed = ", ".join(f"{path} ({why})" for path, why in self.templates_unreadable)
            notes.append(f"{len(self.templates_unreadable)} file(s) could not be read: {listed}")
        if self.cross_stack_imports:
            notes.append(
                f"{len(self.cross_stack_imports)} cross-stack import(s) point outside this "
                f"scan — the resources behind them were not analysed: "
                f"{', '.join(self.cross_stack_imports[:5])}"
                + (" ..." if len(self.cross_stack_imports) > 5 else "")
            )
        if self.cross_stack_exports:
            notes.append(
                f"{len(self.cross_stack_exports)} resource(s) are exported, so consumers may "
                f"live in stacks this scan cannot see: "
                f"{', '.join(self.cross_stack_exports[:5])}"
                + (" ..." if len(self.cross_stack_exports) > 5 else "")
            )
        if self.unresolved_values:
            notes.append(
                f"{len(self.unresolved_values)} value(s) could not be resolved at scan time, so "
                f"checks that depend on them were not completed: "
                f"{', '.join(self.unresolved_values[:5])}"
                + (" ..." if len(self.unresolved_values) > 5 else "")
            )
        if self.iam_unresolved_roles:
            notes.append(
                f"publish and write edges from IAM were not inferred for: "
                f"{', '.join(self.iam_unresolved_roles[:5])}"
                + (" ..." if len(self.iam_unresolved_roles) > 5 else "")
            )
        if self.uncovered_kinds:
            listed = ", ".join(f"{kind} ({count})" for kind, count in sorted(self.uncovered_kinds.items()))
            notes.append(f"resource kinds no rule reasons about were skipped: {listed}")
        if self.out_of_scope_infrastructure:
            listed = ", ".join(
                f"{what} ({count})"
                for what, count in sorted(self.out_of_scope_infrastructure.items())
            )
            notes.append(
                f"infrastructure this scanner does not read was found alongside the "
                f"templates: {listed}"
            )
        return notes

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "templates_scanned": list(self.templates_scanned),
            "templates_unreadable": [
                {"path": path, "reason": why} for path, why in self.templates_unreadable
            ],
            "rules_run": list(self.rules_run),
            "resources_by_kind": dict(self.resources_by_kind),
            "uncovered_kinds": dict(self.uncovered_kinds),
            "cross_stack_exports": list(self.cross_stack_exports),
            "cross_stack_imports": list(self.cross_stack_imports),
            "unresolved_values": list(self.unresolved_values),
            "out_of_scope_infrastructure": dict(self.out_of_scope_infrastructure),
            "iam_unresolved_roles": list(self.iam_unresolved_roles),
            "limits": self.limits(),
        }


def collect(
    graphs: Iterable[EventGraph],
    rules_run: Iterable[str],
    unreadable: Iterable[tuple[str, str]] = (),
    roots: Iterable[Path] = (),
) -> Coverage:
    """Assemble the scope of a completed scan."""
    coverage = Coverage(
        rules_run=sorted(rules_run),
        templates_unreadable=sorted(unreadable),
    )
    kinds: Counter[str] = Counter()
    for graph in graphs:
        template = graph.template
        if template.source:
            coverage.templates_scanned.append(template.source)
        for resource in template:
            kinds[str(resource.kind)] += 1
            if resource.kind not in COVERED_KINDS:
                # "unknown (3)" tells a reader nothing they can act on. The CFN
                # type tells them exactly which three resources went unread, and
                # whether that matters in their stack.
                label = (
                    resource.cfn_type or str(resource.kind)
                    if resource.kind is m.Kind.UNKNOWN
                    else str(resource.kind)
                )
                coverage.uncovered_kinds[label] = coverage.uncovered_kinds.get(label, 0) + 1
        for function_id, role in sorted(graph.unresolved_roles.items()):
            coverage.iam_unresolved_roles.append(
                _qualify(template.source, f"{function_id} (Role: {role})")
            )
        for export in sorted(template.exports):
            coverage.cross_stack_exports.append(_qualify(template.source, export))
        for label in _open_references(template):
            coverage.cross_stack_imports.append(_qualify(template.source, label))
        for label in _unresolved_values(template):
            coverage.unresolved_values.append(_qualify(template.source, label))

    coverage.resources_by_kind = dict(sorted(kinds.items()))
    coverage.out_of_scope_infrastructure = _out_of_scope(
        roots, {str(Path(source)) for source in coverage.templates_scanned}
    )
    return coverage


def _assembly_was_read(assembly: Path, scanned: set[str]) -> bool:
    """Whether at least one stack this cloud assembly declares was scanned.

    A `cdk.out` beside the templates used to mean "the event flow probably
    continues somewhere this scan cannot follow". Once the manifest is read,
    that is no longer true for the stacks it names — but it stays true for an
    assembly nobody pointed the scanner at, so the check is per-assembly.
    """
    from .discover import cdk_stacks

    return any(str(path) in scanned for path in cdk_stacks(assembly.parent))


def _qualify(source: str | None, label: str) -> str:
    return f"{Path(source).name}:{label}" if source else label


# Properties whose values a rule actually reads. An unresolved value anywhere
# else does not limit the analysis, and listing it would bury the ones that do.
_LOAD_BEARING = (
    "VisibilityTimeout",
    "Timeout",
    "MessageRetentionPeriod",
    "BatchSize",
    "MaximumRetryAttempts",
    "MaximumRecordAgeInSeconds",
    "MaximumConcurrency",
    "ReservedConcurrentExecutions",
    "WriteCapacityUnits",
    "ShardCount",
)


def _unresolved_values(template) -> list[str]:
    """Load-bearing properties still holding an intrinsic at scan time.

    A property that collapsed to a scalar is resolved. One that is still a dict
    or list is an intrinsic the parser could not evaluate — a parameter with no
    default, a cross-stack import, a Fn::If on an unknown condition — and every
    check that reads it was answered on a value nobody has.
    """
    found = []
    for resource in template:
        for name in _LOAD_BEARING:
            value = resource.raw_prop(name)
            if isinstance(value, (dict, list)):
                found.append(f"{resource.logical_id}.{name}")
    return sorted(found)


def _open_references(template) -> list[str]:
    """Properties whose value comes from another stack via Fn::ImportValue."""
    found = []
    for resource in template:
        for name, value in (resource.props or {}).items():
            if _has_import(value):
                found.append(f"{resource.logical_id}.{name}")
    return sorted(found)


def _has_import(value: Any, depth: int = 0) -> bool:
    if depth > 6:
        return False
    if isinstance(value, Reference):
        return value.unresolved
    if isinstance(value, dict):
        if "Fn::ImportValue" in value:
            return True
        return any(_has_import(item, depth + 1) for item in value.values())
    if isinstance(value, list):
        return any(_has_import(item, depth + 1) for item in value)
    return False


def _out_of_scope(roots: Iterable[Path], scanned: set[str] = frozenset()) -> dict[str, int]:
    """Infrastructure next to the templates that this scanner does not read."""
    counts: Counter[str] = Counter()
    for root in roots:
        base = root if root.is_dir() else root.parent
        if not base.exists():
            continue
        for path in base.rglob("*"):
            parts = set(path.parts)
            if path.is_dir():
                for name, what in OUT_OF_SCOPE_DIRS.items():
                    if path.name != name:
                        continue
                    if name == "cdk.out" and _assembly_was_read(path, scanned):
                        continue  # its manifest named the stacks, and we read them
                    counts[what] += 1
                continue
            if parts & (SKIP_DIRS - set(OUT_OF_SCOPE_DIRS)):
                continue
            what = OUT_OF_SCOPE.get(path.suffix)
            if what:
                counts[what] += 1
    return dict(counts)


__all__ = ["Coverage", "collect", "COVERED_KINDS", "SUFFIXES"]
