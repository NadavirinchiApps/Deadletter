"""The Finding contract.

The message format is fixed and non-negotiable, because it is the product:

    <resource> <config> is <value>, while <related> <config> is <value>.
    Required: <threshold>. Consequence: <one sentence>.

A finding that cannot name both resources and quote both values is not a
finding — it is a warning, and warnings are what the free tools already give
away. Every `evidence` entry must be a value literally present in the
template so a sceptical staff engineer can grep for it.

Three axes, not one
-------------------

A finding carries three independent facts, and a fourth that is not a fact
at all:

    impact       what breaks when the condition is met
    confidence   how well we know the condition is met
    basis        whether the threshold is enforced by AWS or merely advised
    verdict      whether *this* team wants the build to stop — a policy choice

Collapsing these into a single severity is what makes a scanner untrustworthy.
A severe possible outcome does not make the evidence certain, and a departure
from a recommendation is not a demonstrated violation. The verdict is computed
from the other three by a `Policy` the customer chooses; rules never set it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Impact(StrEnum):
    """What goes wrong when the condition is met."""

    LOSS = "LOSS"                # events are destroyed and cannot be recovered
    STALL = "STALL"              # delivery halts or backs up behind the failure
    DUPLICATION = "DUPLICATION"  # the same event is processed more than once
    DEGRADED = "DEGRADED"        # a safety net is missing; nothing breaks yet

    @property
    def rank(self) -> int:
        return {"LOSS": 0, "STALL": 1, "DUPLICATION": 2, "DEGRADED": 3}[self.value]


class Confidence(StrEnum):
    """How well the scanner knows the condition actually holds."""

    # Every value was read literally from the template. The violation is shown,
    # not predicted.
    CONFIRMED = "CONFIRMED"
    # Rests on an edge derived from IAM permission or naming, which establishes
    # capability, not that the application does it.
    INFERRED = "INFERRED"
    # Holds only under workload assumptions the template cannot state. Those
    # assumptions must be listed on the finding.
    ASSUMED = "ASSUMED"
    # The scanner could not evaluate this — a value was unresolved at scan time.
    # Never evidence of a defect, and never evidence of its absence.
    UNASSESSED = "UNASSESSED"

    @property
    def rank(self) -> int:
        return {"CONFIRMED": 0, "INFERRED": 1, "ASSUMED": 2, "UNASSESSED": 3}[self.value]


class Basis(StrEnum):
    """Whether the threshold is AWS's rule or AWS's advice."""

    # AWS enforces this, or documents it as a constraint the service imposes.
    REQUIREMENT = "REQUIREMENT"
    # AWS or established practice advises it. Sound guidance; not a violation.
    RECOMMENDATION = "RECOMMENDATION"


class Verdict(StrEnum):
    """What the build should do about it. Computed by policy, never by a rule."""

    BLOCK = "BLOCK"
    WARN = "WARN"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"BLOCK": 0, "WARN": 1, "INFO": 2}[self.value]


BREAKING_IMPACTS = frozenset({Impact.LOSS, Impact.STALL, Impact.DUPLICATION})


@dataclass(frozen=True)
class Policy:
    """The deployment choice: which findings are allowed to stop a build.

    A rule states what it found and how well it knows it. Whether that should
    fail CI is the customer's decision, and making it theirs explicitly is the
    difference between a tool that is trusted and one that is disabled after
    the first bad block.
    """

    name: str
    description: str
    confidence: frozenset[Confidence]
    basis: frozenset[Basis]
    impact: frozenset[Impact]
    # Whether a finding resting on an AWS default may stop a build. Off by
    # default: see `Finding.defaults_relied_on`.
    block_on_defaults: bool = False

    def verdict(self, finding: "Finding") -> Verdict:
        blocks = (
            finding.confidence in self.confidence
            and finding.basis in self.basis
            and finding.impact in self.impact
            and (self.block_on_defaults or not finding.defaults_relied_on)
        )
        if blocks:
            return Verdict.BLOCK
        return Verdict.INFO if finding.impact is Impact.DEGRADED else Verdict.WARN


# Only a confirmed violation of something AWS actually enforces, with a real
# delivery consequence, stops the build. Everything else is reported and
# reviewable but does not block.
DEFAULT_POLICY = Policy(
    name="default",
    description=(
        "Block only on a confirmed violation of an AWS requirement that causes "
        "loss, stall or duplication."
    ),
    confidence=frozenset({Confidence.CONFIRMED}),
    basis=frozenset({Basis.REQUIREMENT}),
    impact=frozenset(BREAKING_IMPACTS),
)

# For teams who have decided to enforce AWS's recommendations as house policy,
# to treat an IAM-derived edge as good enough to act on, and to hold themselves
# to explicit values rather than inheriting AWS's defaults.
STRICT_POLICY = Policy(
    name="strict",
    description=(
        "Also block on recommended safeguards, on findings inferred from IAM "
        "permissions, and on values left at their AWS default. "
        "Assumption-dependent findings still only warn."
    ),
    confidence=frozenset({Confidence.CONFIRMED, Confidence.INFERRED}),
    basis=frozenset({Basis.REQUIREMENT, Basis.RECOMMENDATION}),
    impact=frozenset(BREAKING_IMPACTS | {Impact.DEGRADED}),
    block_on_defaults=True,
)

# Report everything, block nothing. The setting for a first scan of a repository
# nobody has scanned before, where an unexpected block costs you the install.
ADVISORY_POLICY = Policy(
    name="advisory",
    description="Report every finding; never fail the build.",
    confidence=frozenset(),
    basis=frozenset(),
    impact=frozenset(),
)

POLICIES = {p.name: p for p in (DEFAULT_POLICY, STRICT_POLICY, ADVISORY_POLICY)}


@dataclass(frozen=True)
class SourceLocation:
    """A stable structural location, optionally backed by a YAML line/column."""

    path: str
    line: int | None = None
    column: int | None = None
    # What the author calls this resource in the language they actually wrote:
    # a CDK construct path, later a Terraform resource address. A synthesized
    # logical ID like `Handler2F3E4D5C` is not something anyone can search for.
    address: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"path": self.path}
        if self.line is not None:
            data["line"] = self.line
        if self.column is not None:
            data["column"] = self.column
        if self.address is not None:
            data["address"] = self.address
        return data


@dataclass(frozen=True)
class Remediation:
    """A source-aware change recommendation.

    ``automatic`` is deliberately false for changes that require the owner to
    choose a destination or modify handler code. The scanner must never present
    a placeholder as a safe, apply-ready patch.
    """

    location: SourceLocation
    description: str
    suggested_value: Any = None
    automatic: bool = False

    @property
    def path(self) -> str:
        return self.location.path

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.location.to_dict(),
            "description": self.description,
            "suggested_value": self.suggested_value,
            "automatic": self.automatic,
        }


@dataclass
class Finding:
    rule_id: str
    title: str
    message: str
    impact: Impact
    confidence: Confidence = Confidence.CONFIRMED
    basis: Basis = Basis.REQUIREMENT
    resources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    # The workload facts a reader must supply before an ASSUMED finding means
    # anything. Required when confidence is ASSUMED: a risk whose assumptions
    # are not stated cannot be argued with, and so cannot be trusted.
    assumptions: list[str] = field(default_factory=list)
    # Properties whose value came from an AWS default rather than the template.
    #
    # The analysis is still CONFIRMED — the deployed system really will behave
    # this way — but the author never made this choice, and stopping their
    # release over a value they never typed is how a scanner gets uninstalled.
    # They open the file, find nothing matching the finding, and conclude the
    # tool is wrong. Being right is no defence. Default policy will not block
    # on these; `--policy strict` will.
    defaults_relied_on: list[str] = field(default_factory=list)
    patch_hint: str | None = None
    # Other tools that report this same defect, stamped from `Rule.overlaps`.
    # A reader who already runs one of them deserves to hear it from us rather
    # than discover it later and wonder what else was oversold.
    overlaps: list[str] = field(default_factory=list)
    source: str | None = None
    location: SourceLocation | None = None
    remediations: list[Remediation] = field(default_factory=list)
    # Assigned by the policy in rules.run(). Rules never set it.
    verdict: Verdict = Verdict.WARN
    # Set when a template suppresses this finding. Suppressed findings are kept
    # and reported; they just stop failing the build.
    suppressed: bool = False
    suppression: str | None = None

    def __post_init__(self) -> None:
        if not self.resources:
            raise ValueError(f"{self.rule_id}: a finding must name the resources involved")
        if not self.evidence:
            raise ValueError(f"{self.rule_id}: a finding must quote evidence from the template")
        if self.confidence is Confidence.ASSUMED and not self.assumptions:
            raise ValueError(
                f"{self.rule_id}: an ASSUMED finding must state the assumptions it rests on"
            )
        if self.message[:6].isupper() and self.message[:6].rstrip(":") in {
            "BLOCK",
            "WARN",
            "INFO",
        }:
            raise ValueError(
                f"{self.rule_id}: a rule must not prefix its message with a verdict — "
                f"the verdict is set by policy"
            )

    @property
    def inferred(self) -> bool:
        """Back-compatible view: anything not read straight from the template."""
        return self.confidence is not Confidence.CONFIRMED

    @property
    def headline(self) -> str:
        return f"{self.verdict}: {self.message}"

    @property
    def sort_key(self) -> tuple[int, int, int, str, str]:
        return (
            self.verdict.rank,
            self.impact.rank,
            self.confidence.rank,
            self.rule_id,
            ",".join(self.resources),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "verdict": str(self.verdict),
            "impact": str(self.impact),
            "confidence": str(self.confidence),
            "basis": str(self.basis),
            "title": self.title,
            "message": self.message,
            "headline": self.headline,
            "resources": list(self.resources),
            "evidence": dict(self.evidence),
            "assumptions": list(self.assumptions),
            "defaults_relied_on": list(self.defaults_relied_on),
            "overlaps": list(self.overlaps),
            "patch_hint": self.patch_hint,
            "inferred": self.inferred,
            "source": self.source,
            "location": self.location.to_dict() if self.location else None,
            "remediations": [remediation.to_dict() for remediation in self.remediations],
            "suppressed": self.suppressed,
            "suppression": self.suppression,
        }
