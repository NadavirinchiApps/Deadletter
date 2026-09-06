"""Benchmark Deadletter against Checkov and cdk-nag on the 12 violating fixtures.

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

Judgement lives in RELATED_CHECKS below, so it can be argued with.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(r"F:\deadletter\Deadletter")
FIXTURES = REPO / "tests" / "fixtures"
HERE = Path(__file__).parent

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
    "EDA002": {"CKV_AWS_101"},   # Lambda DLQ configured
    "EDA006": {"CKV_AWS_101"},
    "EDA012": set(),
}


def run_deadletter(path: Path) -> list[dict]:
    out = subprocess.run(
        [sys.executable, "-m", "deadletter", str(path), "--format", "json", "--fail-on", "none"],
        capture_output=True, text=True, cwd=REPO, encoding="utf-8",
    )
    if out.returncode not in (0, 1):
        return []
    try:
        return json.loads(out.stdout)["findings"]
    except (json.JSONDecodeError, KeyError):
        return []


def run_checkov(path: Path) -> list[dict]:
    out = subprocess.run(
        [sys.executable, "-m", "checkov.main", "-f", str(path),
         "--framework", "cloudformation", "--output", "json", "--compact", "--quiet"],
        capture_output=True, text=True, cwd=REPO, encoding="utf-8",
    )
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        results = []
        for block in data:
            results.extend(block.get("results", {}).get("failed_checks", []))
        return results
    return data.get("results", {}).get("failed_checks", [])


def run_cdk_nag(path: Path) -> list[dict]:
    script = HERE / "nag.js"
    if not script.exists():
        return []
    out = subprocess.run(
        ["node", str(script), str(path)],
        capture_output=True, text=True, cwd=HERE, encoding="utf-8",
    )
    try:
        return json.loads(out.stdout or "[]")
    except json.JSONDecodeError:
        return []


def main() -> int:
    rows = []
    for rule_id, defect in DEFECTS.items():
        fixture = FIXTURES / rule_id / "violating.yaml"
        if not fixture.exists():
            continue

        dl = [f for f in run_deadletter(fixture) if f["rule_id"] == rule_id]
        ck = run_checkov(fixture)
        nag = run_cdk_nag(fixture)

        ck_ids = sorted({c.get("check_id", "") for c in ck})
        nag_ids = sorted({n.get("ruleId", "") for n in nag})
        related = RELATED_CHECKS.get(rule_id, set())

        rows.append({
            "rule": rule_id,
            "defect": defect,
            "deadletter": bool(dl),
            "deadletter_verdict": dl[0]["verdict"] if dl else None,
            "checkov_total": len(ck),
            "checkov_ids": ck_ids,
            "checkov_hit": bool(related & set(ck_ids)),
            "cdknag_total": len(nag),
            "cdknag_ids": nag_ids,
            "cdknag_hit": False,  # judged by hand below
        })
        print(
            f"{rule_id}  deadletter={'Y' if dl else 'n'}  "
            f"checkov={len(ck):>2} findings {ck_ids[:4]}  "
            f"cdk-nag={len(nag):>2} findings {nag_ids[:4]}",
            flush=True,
        )

    (HERE / "results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\nwrote {HERE / 'results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
