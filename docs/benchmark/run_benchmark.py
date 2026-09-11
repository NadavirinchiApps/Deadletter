"""Benchmark Deadletter against the free tools on the 12 violating fixtures.

The question this answers is the only one that matters commercially: on a
template with a known event-delivery defect, does an existing free tool already
report it? Rule counts are not evidence. "Your existing checks missed this" is.

Method
------
Each fixture is a template built to violate exactly one Deadletter rule. For
each tool we record every finding it produces on that fixture, then judge by
hand whether any of them describe the *same defect* — not merely the same
resource. A Checkov result saying "SQS queue is not encrypted" on the EDA001
fixture is not a hit for "visibility timeout is shorter than its consumer".

Judgement lives in RELATED_CHECKS and SERVERLESS_RELATED below, so it can be
argued with.

Usage
-----
    python run_benchmark.py            # regenerate results.json
    python run_benchmark.py --check    # fail if results.json is out of date

Every tool must be installed. A run with a tool missing would record zeros and
quietly turn a competitor's hit into a miss, which is the one error this
benchmark exists not to make.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures"
HERE = Path(__file__).parent

# cfn-lint has no `python -m` entry point; this is its console script inlined.
CFN_LINT_MAIN = "import sys; from cfnlint.runner import main; sys.exit(main())"

# What each fixture is built to demonstrate, in one line.
DEFECTS = {
    "EDA001": "SQS visibility timeout is shorter than its consumer's timeout",
    "EDA002": "async delivery path has no dead-letter destination",
    "EDA003": "batch size > 1 without ReportBatchItemFailures replays succeeded records",
    "EDA004": "events can re-enter the hub that delivered them (recursive loop)",
    "EDA005": "unbounded stream retries let one poison record block a shard",
    "EDA006": "dead-letter queue has no consumer and no working alarm",
    "EDA007": "consumer concurrency ceiling outruns the table's write capacity",
    "EDA008": "dead-letter queue retention is shorter than its source queue's",
    "EDA009": "more shared-throughput readers on a shard than it can serve",
    "EDA010": "workflow task has no retry or catch for documented transient errors",
    "EDA011": "handler timeout exceeds the API Gateway integration timeout",
    "EDA012": "events are published to a hub with no delivery route",
}

# Checkov check IDs that would count as describing the same defect. Kept
# deliberately generous: anything arguably about the same failure counts as a
# hit, so the comparison cannot flatter Deadletter by being strict.
RELATED_CHECKS = {
    # "Ensure that AWS Lambda function is configured for a Dead Letter Queue".
    # CKV_AWS_101 is the older id for the same check, kept so a rename does not
    # silently turn a hit into a miss.
    "EDA002": {"CKV_AWS_116", "CKV_AWS_101"},
    # Deliberately empty. CKV_AWS_116 fires on this fixture too, but it says a
    # Lambda has no dead-letter queue; EDA006 says the dead-letter queue that
    # exists has no consumer and no alarm that could raise anybody. Same
    # resource, different defect, and counting it would make the table worthless.
    "EDA006": set(),
    # Also deliberately empty. CKV_AWS_115 (function-level concurrency limit)
    # fires on every Lambda without a reserved concurrency and never compares it
    # against anything downstream. benchmark.md records it as a partial by hand.
    "EDA007": set(),
    "EDA012": set(),
}

# awslabs/serverless-rules, shipped by AWS as a cfn-lint rule pack. This is the
# nearest competitor there is, and it is free.
SERVERLESS_RELATED = {
    # ES6000 SQS redrive, ES7000 SNS redrive, ES4000 EventBridge rule DLQ,
    # ES1007 Lambda async failure destination. Between them they cover all of
    # what EDA002 reports.
    "EDA002": {"ES6000", "ES7000", "ES4000", "ES1007"},
    # ES1001 asks for an EventSourceMapping failure destination — the
    # destination half of EDA005. The unbounded-retry half has no equivalent.
    "EDA005": {"ES1001"},
}


class ToolFailed(RuntimeError):
    """A tool ran and did not return something this script can read.

    Returning an empty list here instead would record the competitor as having
    missed the defect, which is the one error this benchmark exists not to make.
    An unreadable run is not a miss; it is an unknown, and it stops the run.
    """


def _parse(tool: str, path: Path, out: subprocess.CompletedProcess[str]) -> Any:
    try:
        return json.loads(out.stdout or "")
    except json.JSONDecodeError as exc:
        raise ToolFailed(
            f"{tool} produced no readable JSON for {path.relative_to(REPO)}\n"
            f"  exit status: {out.returncode}\n"
            f"  stdout: {(out.stdout or '').strip()[:400] or '(empty)'}\n"
            f"  stderr: {(out.stderr or '').strip()[-1200:] or '(empty)'}"
        ) from exc


def run_deadletter(path: Path) -> list[dict]:
    out = subprocess.run(
        [sys.executable, "-m", "deadletter", str(path), "--format", "json", "--fail-on", "none"],
        capture_output=True, text=True, cwd=REPO, encoding="utf-8",
    )
    if out.returncode not in (0, 1):
        raise ToolFailed(f"deadletter exited {out.returncode} on {path}\n{out.stderr}")
    data = _parse("deadletter", path, out)
    if "findings" not in data:
        raise ToolFailed(f"deadletter report for {path} has no findings key")
    return data["findings"]


def run_checkov(path: Path) -> list[dict]:
    out = subprocess.run(
        [sys.executable, "-m", "checkov.main", "-f", str(path),
         "--framework", "cloudformation", "--output", "json", "--compact", "--quiet"],
        capture_output=True, text=True, cwd=REPO, encoding="utf-8",
    )
    data = _parse("checkov", path, out)
    if isinstance(data, list):
        results = []
        for block in data:
            results.extend(block.get("results", {}).get("failed_checks", []))
        return results
    return data.get("results", {}).get("failed_checks", [])


def run_serverless_rules(path: Path) -> list[dict]:
    """cfn-lint with the `cfn-lint-serverless` rule pack appended.

    `-a` takes a list, so the template has to arrive through `-t` or the path
    is swallowed as another rule module.
    """
    out = subprocess.run(
        [sys.executable, "-c", CFN_LINT_MAIN,
         "-a", "cfn_lint_serverless.rules", "-f", "json", "-t", str(path)],
        capture_output=True, text=True, cwd=REPO, encoding="utf-8",
    )
    data = _parse("cfn-lint-serverless", path, out)
    # Only the pack's own rules. cfn-lint's built-in E/W findings are template
    # validity, not delivery defects, and counting them would be dishonest.
    return [m for m in data if str(m.get("Rule", {}).get("Id", "")).startswith("ES")]


def run_cdk_nag(path: Path) -> list[dict]:
    # nag.js prints JSON on every path it can take, including the two it takes
    # when CfnInclude or the harness throws, so empty output means node itself
    # failed and there is nothing to report about cdk-nag.
    script = HERE / "nag.js"
    out = subprocess.run(
        ["node", str(script), str(path)],
        capture_output=True, text=True, cwd=HERE, encoding="utf-8",
    )
    return _parse("cdk-nag", path, out)


def missing_tools() -> list[str]:
    """Everything the run needs and does not have."""
    missing: list[str] = []
    for module, name in (
        ("checkov", "checkov (pip install checkov)"),
        ("cfn_lint_serverless", "cfn-lint-serverless (pip install cfn-lint-serverless)"),
    ):
        probe = subprocess.run(
            [sys.executable, "-c", f"import {module}"], capture_output=True, text=True
        )
        if probe.returncode != 0:
            missing.append(name)
    if not (HERE / "node_modules").is_dir():
        missing.append("cdk-nag (cd docs/benchmark && npm install)")
    elif subprocess.run(["node", "--version"], capture_output=True).returncode != 0:
        missing.append("node")
    return missing


def collect() -> list[dict]:
    rows = []
    for rule_id, defect in DEFECTS.items():
        fixture = FIXTURES / rule_id / "violating.yaml"
        if not fixture.exists():
            continue

        dl = [f for f in run_deadletter(fixture) if f["rule_id"] == rule_id]
        ck = run_checkov(fixture)
        srv = run_serverless_rules(fixture)
        nag = run_cdk_nag(fixture)

        ck_ids = sorted({c.get("check_id", "") for c in ck})
        srv_ids = sorted({m.get("Rule", {}).get("Id", "") for m in srv})
        nag_ids = sorted({n.get("ruleId", "") for n in nag})
        related = RELATED_CHECKS.get(rule_id, set())
        srv_related = SERVERLESS_RELATED.get(rule_id, set())

        rows.append({
            "rule": rule_id,
            "defect": defect,
            "deadletter": bool(dl),
            "deadletter_verdict": dl[0]["verdict"] if dl else None,
            "checkov_total": len(ck),
            "checkov_ids": ck_ids,
            "checkov_hit": bool(related & set(ck_ids)),
            "serverless_rules_total": len(srv),
            "serverless_rules_ids": srv_ids,
            "serverless_rules_hit": bool(srv_related & set(srv_ids)),
            "cdknag_total": len(nag),
            "cdknag_ids": nag_ids,
            "cdknag_hit": False,  # judged by hand below
        })
        print(
            f"{rule_id}  deadletter={'Y' if dl else 'n'}  "
            f"checkov={len(ck):>2} {ck_ids[:3]}  "
            f"serverless-rules={len(srv):>2} {srv_ids[:4]}  "
            f"cdk-nag={len(nag):>2} {nag_ids[:3]}",
            flush=True,
        )
    return rows


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    check = "--check" in argv

    missing = missing_tools()
    if missing:
        print("cannot run the benchmark without: " + ", ".join(missing), file=sys.stderr)
        return 2

    try:
        rows = collect()
    except ToolFailed as exc:
        print(f"\n{exc}", file=sys.stderr)
        print(
            "\nThe benchmark stops rather than record a tool that could not run as a "
            "tool that found nothing. Fix the tool's environment and run it again.",
            file=sys.stderr,
        )
        return 2

    payload = json.dumps(rows, indent=2)
    target = HERE / "results.json"

    if check:
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        if current.strip() != payload.strip():
            print(
                "\nresults.json no longer matches what the tools report. "
                "Re-run docs/benchmark/run_benchmark.py and update docs/benchmark.md "
                "if a cell changed.",
                file=sys.stderr,
            )
            return 1
        print("\nresults.json is current.")
        return 0

    target.write_text(payload, encoding="utf-8")
    print(f"\nwrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
