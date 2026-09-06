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

| Rule | Impact | Defect |
|---|---|---|
| EDA001 | duplication | SQS visibility timeout is unsafe for the connected Lambda timeout |
| EDA002 | loss | A polled or asynchronous delivery has missing or partial dead-letter coverage |
| EDA003 | duplication | A failed item replays an entire batch because partial failure reporting is absent |
| EDA004 | stall | A function can publish back into the bus or topic that invoked it |
| EDA005 | stall / loss | A stream poison record can block a shard or be discarded without recovery |
| EDA006 | loss | A dead-letter queue has no consumer and no working alarm, so what lands there expires unseen |
| EDA007 | stall | A consumer's concurrency ceiling outruns a provisioned table's write capacity |
| EDA008 | loss | A dead-letter queue expires messages sooner than the queue that feeds it |
| EDA009 | stall | More shared-throughput readers on a stream shard than its read budget serves |
| EDA010 | stall | A workflow task treats a transient error as final, with no retry or catch |
| EDA011 | duplication | A synchronous handler may outlive the API integration timeout waiting on it |
| EDA012 | loss | Events are published to a topic or bus that routes them nowhere |

For how these compare against Checkov and cdk-nag on the same templates, see
[docs/benchmark.md](docs/benchmark.md). Two of the twelve overlap with checks
those tools already run; ten do not.

## Findings say how well they are known

A severe possible outcome does not make the evidence certain, and a departure
from a recommendation is not a violation. Collapsing those into one severity is
how a scanner blocks a release it should not have, and gets removed from the
pipeline.

Every finding carries three separate facts, and the verdict is computed from
them rather than chosen by the rule:

| Axis | Values | Means |
|---|---|---|
| `impact` | `LOSS` `STALL` `DUPLICATION` `DEGRADED` | what breaks if the condition holds |
| `confidence` | `CONFIRMED` `INFERRED` `ASSUMED` `UNASSESSED` | how well we know it holds |
| `basis` | `REQUIREMENT` `RECOMMENDATION` | AWS's rule, or AWS's advice |

- `CONFIRMED` — every value was read literally from the template.
- `INFERRED` — rests on an IAM-derived edge: permission is capability, not behaviour.
- `ASSUMED` — holds only under workload assumptions, which the finding lists.
- `UNASSESSED` — a value was unresolved, so the check could not be completed.
  Never evidence of a defect, and never evidence of its absence.

Which of those stops a build is your decision, not Deadletter's:

```console
deadletter . --policy default    # block only CONFIRMED violations of a REQUIREMENT
deadletter . --policy strict     # also block RECOMMENDATION and INFERRED findings
deadletter . --policy advisory   # report everything, block nothing
```

The default blocks considerably less than version 0.3 did. That is the point:
EDA001's 6x visibility-timeout margin is AWS guidance, not a constraint AWS
enforces, and blocking on it spent credibility the tool needs for the case that
is genuinely broken.

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
  OrdersQueue VisibilityTimeout is 10s, while its consumer ProcessOrder has a
  Timeout of 30s. Required: at least 30s - AWS requires a queue's visibility
  timeout to be no shorter than the function that consumes it. Consequence:
  every invocation that runs its full timeout releases the message back to the
  queue before it finishes, so a second consumer picks up work already in
  progress.
  basis: confirmed requirement | impact if it bites: duplication
  resources: OrdersQueue, ProcessOrder, ProcessOrder#FromQueue
  fix /Resources/OrdersQueue/Properties/VisibilityTimeout: Set VisibilityTimeout
  to at least 30 seconds to satisfy the AWS constraint, and to 190 to meet the
  recommended retry margin.

Coverage: 1 template(s), 6 resource(s), 12 rule(s).
  Not assessed:
    - 1 resource(s) are exported, so consumers may live in stacks this scan
      cannot see: template.yaml:OrdersTopic
```

Every report states the scope it was produced from. "No findings" on its own
reads as "your system is sound", when it can mean "the part that matters was
not visible to this scan" — so the boundaries always travel with the result:
cross-stack imports and exports, unresolved values, files that could not be
read, resource kinds no rule covers, and Terraform or `cdk.out` sitting beside
the templates.

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

# Choose what is allowed to fail the build
deadletter . --policy strict
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
    uses: NadavirinchiApps/Deadletter@v0.4.1
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
  EDA012 stays silent for it. When there is no export, EDA012 still only warns:
  a subscription in another stack can name the topic ARN directly, and no
  CloudFormation export is required for it to do so. The finding asks you to
  confirm; it does not claim nothing can reach the topic.
- An alarm counts as monitoring only if it could actually raise someone: the
  right metric, `ActionsEnabled` not false, and a non-empty `AlarmActions`. An
  alarm that names a queue but cannot notify anyone is reported as worse than
  no alarm, because somebody believes it works.
- EDA007 cannot know a true write rate — that needs traffic, handler duration,
  writes per event and item size, none of which a template states. It compares
  the consumer's concurrency ceiling against the table's write ceiling and
  publishes the assumptions that comparison rests on.
- Templates are scanned individually and their findings combined. Deadletter
  does not yet build one graph across several templates, so a delivery path
  that spans stacks is reported as an analysis boundary rather than followed.
- EDA011 sees API routes declared as SAM `Api` and `HttpApi` events. A native
  `AWS::ApiGateway::Method` integration is not yet resolved to its handler.
- EDA010 reads inline `Definition` bodies and JSON `DefinitionString` bodies. A
  definition behind `DefinitionUri`, or one whose `Fn::Sub` cannot be
  substituted, is left alone rather than guessed at.
- It does not inspect deployed drift, runtime traffic, application idempotency,
  generic IAM security, or cost.
- Terraform, CDK source code, Azure, and GCP are outside version 0.4. When
  Deadletter finds them beside the templates it does read, it says so in the
  coverage block rather than reporting a clean scan.

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
