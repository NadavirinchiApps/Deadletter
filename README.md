# deadletter

Pre-deployment event-delivery correctness scanner for AWS event-driven architectures.

Checkov tells you your bucket is public. Infracost tells you what the diff costs.
Nobody tells you that your queue's visibility timeout guarantees duplicate order
processing — before you deploy. That is this tool's lane: **cross-resource
event-delivery correctness, pre-deployment, with generated patches.**

Repo-only. No cloud credentials, ever.

## Status — Session 2 (A2) complete

| Component | State |
|---|---|
| Template parsing (CFN + SAM, YAML/JSON, short-form intrinsics, Globals) | done |
| Typed resource model | done |
| Event-flow graph (poll / rule_target / subscribe / publish / writes / redrive / dlq / on_failure) | done |
| Fixture harness + rule interface | done |
| Rule pack EDA001–005 (BLOCK) | done |
| EDA006–012, reporters, CLI, GitHub Action | A3–A4 |

## Develop

    pip install -e ".[dev]"
    pytest

## Adding a rule

Fixtures first, always. `tests/fixtures/<RULE_ID>/violating.yaml` must yield exactly
the documented finding; `passing.yaml` must yield silence. A rule without both does
not merge. Never weaken a fixture to make a test pass.

    from deadletter.rules.base import Rule, register
    from deadletter.findings import Finding, Severity

    @register
    class EDA001(Rule):
        id, severity = "EDA001", Severity.BLOCK
        title = "SQS visibility timeout too short for its consumer"
        def check(self, graph): ...

Message format is fixed:

    <VERDICT>: <resource> <config> is <value>, while <related> <config> is <value>.
    Required: <threshold>. Consequence: <one sentence>.

## Deliberately out of scope

Cost estimation (point at Infracost) · generic security and IAM linting beyond the
event graph (point at Checkov) · Terraform plan JSON (v1.1, only on a paying
customer's ask) · Azure/GCP (not before five paying AWS customers).
