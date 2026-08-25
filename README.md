# deadletter

Deadletter catches event-delivery failures in AWS infrastructure before they
reach production.

Checkov can tell you that a bucket is public. Infracost can tell you what a
change costs. Deadletter follows delivery paths across queues, functions,
topics, streams, and event buses to find configurations that cause duplicate
processing, silent event loss, poison-record stalls, or recursive invocation
loops.

It scans CloudFormation and AWS SAM in the repository. It never needs AWS
credentials or access to a cloud account.

## What it detects

| Rule | Severity | Defect |
|---|---|---|
| EDA001 | BLOCK/WARN | SQS visibility timeout is unsafe for the connected Lambda timeout |
| EDA002 | BLOCK/WARN | A polled or asynchronous delivery has missing or partial dead-letter coverage |
| EDA003 | BLOCK/WARN | A failed item replays an entire batch because partial failure reporting is absent |
| EDA004 | BLOCK/WARN | A function can publish back into the bus or topic that invoked it |
| EDA005 | BLOCK/WARN | A stream poison record can block a shard or be discarded without recovery |

`BLOCK` is reserved for a relationship Deadletter can establish from the
template. Filtered or conditionally deployed paths are downgraded to `WARN`
when runtime values are required to prove the failure.

## Install and scan

Deadletter requires Python 3.12 or newer.

```console
pip install .
deadletter template.yaml
```

Example:

```text
[BLOCK] EDA001 - SQS visibility timeout too short for its consumer
  at template.yaml:24:7
  BLOCK: OrdersQueue VisibilityTimeout is 60s, while ProcessOrder Timeout is
  30s with a 10s batching window. Required: 190s.
  fix /Resources/OrdersQueue/Properties/VisibilityTimeout: Set
  VisibilityTimeout to at least 190 seconds.
```

The default exit policy is CI-friendly:

- `0`: the selected threshold was not reached.
- `1`: a finding met the `--fail-on` threshold.
- `2`: the template or report could not be read or written.

Useful commands:

```console
# Do not fail; inspect every result
deadletter template.yaml --fail-on none

# Scan selected rules
deadletter template.yaml --rule EDA001 --rule EDA003

# Machine-readable reports
deadletter template.yaml --format json --output deadletter.json
deadletter template.yaml --format sarif --output deadletter.sarif

# Event-flow architecture diagram
deadletter template.yaml --format mermaid --fail-on none

# Scan more than one template into one report
deadletter api.yaml workers.yaml --format json
```

Formats are `text`, `json`, `sarif`, and `mermaid`. Mermaid accepts one template
at a time.

## GitHub Actions

The repository includes a composite action. After publishing the repository,
replace `<owner>` with its GitHub owner:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7.0.1
  - name: Scan event delivery
    uses: <owner>/deadletter@v0.2.0
    with:
      template: template.yaml
      format: sarif
      output: deadletter.sarif
      fail-on: BLOCK
  - name: Upload findings
    if: always()
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: deadletter.sarif
```

The action passes inputs through environment variables and quotes them before
invoking the CLI. It does not evaluate template paths as shell source.

## How it works

1. Parse YAML or JSON CloudFormation, including short-form intrinsics.
2. Apply CloudFormation parameter defaults, determinable conditions, and SAM
   Globals merge semantics.
3. Expand SAM event declarations into their effective event source mappings,
   subscriptions, rules, and API routes.
4. Build a directed event-flow graph. IAM statements can add inferred publish
   or write edges only when the action and resource occur in the same Allow
   statement.
5. Run pure graph rules and emit evidence, source lines, structural JSON-pointer
   paths, and remediation guidance.

Remediations are deliberately marked non-automatic when a human must choose a
DLQ, verify emitted event values, or change handler behavior. Deadletter does
not turn placeholders into apply-ready patches.

## Analysis boundaries

Deadletter is intentionally conservative about what a repository can prove:

- Cross-stack resources are not guessed. A configured `Fn::ImportValue` counts
  as configured, but no edge is invented for its unseen target.
- Parameter defaults are evaluated. Unresolved numeric rule inputs and
  conditions that cannot be decided statically produce uncertainty rather than
  false deployment blocks.
- IAM-derived publish/write relationships are labeled inferred.
- Enabling `ReportBatchItemFailures` also requires correct handler behavior;
  Deadletter identifies the infrastructure half and says when code must change.
- It does not inspect deployed drift, runtime traffic, application idempotency,
  generic IAM security, or cost.
- Terraform, CDK source code, Azure, and GCP are outside version 0.2.

## Development

```console
pip install -e ".[dev]"
pytest
python -m build
```

Every rule must ship with a violating fixture and a passing fixture. Regression
tests additionally cover AWS defaults, parameterized properties, conditions,
SAM/native equivalents, cross-stack destinations, IAM statement boundaries,
CLI exit codes, and report serialization.

The next rule-pack milestone is EDA006-012. The current five-rule pack, CLI,
SARIF/JSON reporting, source-aware remediation, package build, and GitHub Action
are implemented in version 0.2.
