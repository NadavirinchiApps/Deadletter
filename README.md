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
| EDA006 | BLOCK | A dead-letter queue has no consumer and no alarm, so what lands there expires unseen |
| EDA007 | BLOCK | An unbounded consumer writes into a provisioned table that cannot absorb its burst |
| EDA008 | BLOCK/WARN | A dead-letter queue expires messages sooner than the queue that feeds it |
| EDA009 | BLOCK | More shared-throughput readers on a stream shard than its read budget serves |
| EDA010 | BLOCK/WARN | A workflow task treats a transient error as final, with no retry or catch |
| EDA011 | BLOCK/WARN | A synchronous handler may outlive the API integration timeout waiting on it |
| EDA012 | BLOCK | Events are published to a topic or bus that routes them nowhere |

`BLOCK` is reserved for a relationship Deadletter can establish from the
template. Filtered or conditionally deployed paths are downgraded to `WARN`
when runtime values are required to prove the failure.

## Install and scan

Deadletter requires Python 3.12 or newer.

```console
pip install .
deadletter template.yaml
deadletter .              # search the repository for templates
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

# Scan more than one template, or a whole tree, into one report
deadletter api.yaml workers.yaml --format json
deadletter infra/ --format json

# Show what the repository is choosing not to fix
deadletter . --show-suppressed
```

Formats are `text`, `json`, `sarif`, and `mermaid`. Mermaid accepts one template
at a time.

Given a directory, Deadletter walks it for CloudFormation and SAM templates and
skips generated trees such as `.aws-sam`, `cdk.out`, `node_modules`, and
`build`. A path you name is always scanned, and failing to read it is an error;
a path found by walking is skipped silently if it turns out not to be a
template. A directory containing no templates is an error rather than a clean
scan, because that is nearly always a wrong path.

## Suppressing a finding

A gate with no way past it gets removed from the pipeline the first Friday it
blocks a release nobody can wait on. Suppressions live in the template, next to
the resource they excuse:

```yaml
Resources:
  OrdersQueue:
    Type: AWS::SQS::Queue
    Metadata:
      deadletter:
        ignore:
          - rule: EDA001
            reason: Consumer is idempotent on order id; see ADR-114.
            expires: 2026-12-31   # optional
    Properties:
      VisibilityTimeout: 30
```

Three rules keep this from becoming a way to hide:

- **A reason is mandatory.** An entry without one is not applied, and the scan
  says so on stderr.
- **`expires` is honoured.** The day it passes, the finding returns. An
  unreadable date is not treated as no date.
- **Nothing is deleted.** Suppressed findings stay in the JSON report, are
  counted separately in the summary, and are marked in SARIF with a native
  `suppressions` entry so code-scanning greys them out instead of dropping
  them. They just stop failing the build.

## GitHub Actions

The repository includes a composite action:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7.0.1
  - name: Scan event delivery
    uses: NadavirinchiApps/Deadletter@v0.3.0
    with:
      template: .
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
6. Apply any suppressions the template declares, marking rather than deleting
   what they waive.

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
- A topic or bus whose ARN is exported may be consumed by another stack, so
  EDA012 stays silent for it. Absence of a local route stops being evidence
  once something outside the template can reach it.
- EDA011 sees API routes declared as SAM `Api` and `HttpApi` events. A native
  `AWS::ApiGateway::Method` integration is not yet resolved to its handler.
- EDA010 reads inline `Definition` bodies and JSON `DefinitionString` bodies. A
  definition behind `DefinitionUri`, or one whose `Fn::Sub` cannot be
  substituted, is left alone rather than guessed at.
- It does not inspect deployed drift, runtime traffic, application idempotency,
  generic IAM security, or cost.
- Terraform, CDK source code, Azure, and GCP are outside version 0.3.

## Development

```console
pip install -e ".[dev]"
pytest
python -m build
```

Every rule must ship with a violating fixture and a passing fixture. The passing
half is the one that matters commercially: a false `BLOCK` in front of a
prospect costs more than a missing rule. Regression tests additionally cover AWS
defaults, parameterized properties, conditions, SAM/native equivalents,
cross-stack destinations, IAM statement boundaries, suppression handling,
template discovery, CLI exit codes, and report serialization.
