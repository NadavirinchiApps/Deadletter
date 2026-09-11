"""Finding the templates in a repository.

`deadletter .` has to work, because the alternative is asking every team to
enumerate their templates in a workflow file and keep that list correct forever.

Discovery and naming are treated differently on purpose:

- A path the user **named** is scanned, and a failure to read or parse it is an
  error. They said it was a template; being wrong about that is worth knowing.
- A path Deadletter **found** by walking a directory is scanned only if it
  parses and declares resources. A repository is full of YAML that was never
  meant to be a CloudFormation template, and none of it should produce noise.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

SUFFIXES = frozenset({".yaml", ".yml", ".json", ".template"})

# What `cdk synth` calls a stack in its cloud assembly manifest. Each such
# artifact names the template it wrote, relative to the assembly root.
CDK_STACK_ARTIFACT = "aws:cloudformation:stack"

# A directory holding no template is normally a typo worth failing on. Under
# `--allow-empty` it is expected — pre-commit hands us whatever changed, and a
# monorepo has directories with no infrastructure in them. The CLI has to tell
# the two apart, so the message it recognises lives here rather than inline.
NO_TEMPLATES = "no CloudFormation or SAM templates found"

# Directories that either are not source or contain generated copies of
# templates already scanned from their real location.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".aws-sam",
        "cdk.out",
        "dist",
        "build",
        "site-packages",
        ".terraform",
    }
)


@dataclass(frozen=True)
class Target:
    path: Path
    explicit: bool  # named on the command line rather than found by walking
    origin: str | None = None  # "cdk" when a cloud assembly manifest named it


def resolve(inputs: Sequence[Path]) -> tuple[list[Target], list[str]]:
    """Expand directories into the templates they contain.

    Returns the targets to scan and any problems worth reporting. A directory
    that contains no template is a problem: it is almost always a wrong path,
    and staying silent would let a typo pass CI as a clean scan.
    """
    targets: list[Target] = []
    problems: list[str] = []
    seen: set[Path] = set()

    for raw in inputs:
        path = Path(raw)
        if path.is_dir():
            synthesized = [p for p in cdk_stacks(path) if p not in seen]
            found = [p for p in walk(path) if p not in seen and p not in synthesized]
            if not found and not synthesized:
                problems.append(f"{path}: {NO_TEMPLATES}")
                continue
            for candidate in synthesized:
                seen.add(candidate)
                targets.append(Target(path=candidate, explicit=False, origin="cdk"))
            for candidate in found:
                seen.add(candidate)
                targets.append(Target(path=candidate, explicit=False))
        elif path.exists():
            if path not in seen:
                seen.add(path)
                targets.append(Target(path=path, explicit=True))
        else:
            problems.append(f"{path}: no such file or directory")

    return targets, problems


def walk(root: Path) -> list[Path]:
    """Every file under `root` that reads like a CloudFormation template."""
    found = [
        path
        for path in sorted(root.rglob("*"))
        if path.suffix.lower() in SUFFIXES
        and path.is_file()
        and not _skipped(path, root)
        and looks_like_template(path)
    ]
    return found


def cdk_stacks(root: Path) -> list[Path]:
    """Templates a `cdk synth` under `root` says it produced.

    The generic walk skips `cdk.out`, and rightly: it is generated output full
    of assets and nested copies. But the manifest names exactly which files are
    stacks, so a CDK team gets scanned without having to point at each template
    by hand. Anything the manifest does not name is still skipped.
    """
    found: list[Path] = []
    for manifest_path in sorted(root.rglob("cdk.out/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue  # an unreadable manifest is reported by the coverage block
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, dict):
            continue
        assembly = manifest_path.parent
        for _, artifact in sorted(artifacts.items()):
            if not isinstance(artifact, dict) or artifact.get("type") != CDK_STACK_ARTIFACT:
                continue
            template = (artifact.get("properties") or {}).get("templateFile")
            if not isinstance(template, str):
                continue
            candidate = assembly / template
            if candidate.is_file() and candidate not in found:
                found.append(candidate)
    return found


def _skipped(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:  # pragma: no cover - rglob results are always relative
        parts = path.parts
    return any(part in SKIP_DIRS for part in parts)


def looks_like_template(path: Path) -> bool:
    """A cheap structural check, not a parse.

    Reading every YAML file in a monorepo through the full CloudFormation
    decoder is slow and noisy. A template declares resources; that is enough to
    decide whether the real parser should be asked.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    if "Resources" not in text:
        return False
    return any(
        marker in text
        for marker in ("AWSTemplateFormatVersion", "AWS::", "Transform", '"Resources"', "Resources:")
    )


__all__ = [
    "Target",
    "resolve",
    "walk",
    "cdk_stacks",
    "looks_like_template",
    "SUFFIXES",
    "SKIP_DIRS",
]
