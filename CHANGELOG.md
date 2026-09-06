# Changelog

## 0.4.0

Trust. An external review found that several findings claimed more than the
evidence supported, and one returned a clean result on a template that was not
clean. This release is the correction, and it deliberately blocks less than
0.3.0 did.

### A finding now separates what it knows from what it recommends

`Severity` was doing three jobs at once — how bad the outcome is, how sure we
are, and whether the build should stop — and every rule shipped as `BLOCK`.
That conflation was the root cause of two of the defects below.

Findings now carry `impact`, `confidence` and `basis` as independent facts, and
the **verdict is computed by a `Policy` the customer chooses**, never by a rule:

- `--policy default` blocks only a `CONFIRMED` violation of a `REQUIREMENT`
  with a real delivery consequence.
- `--policy strict` also blocks `RECOMMENDATION` and `INFERRED` findings.
- `--policy advisory` reports everything and blocks nothing.

A finding whose `confidence` is `ASSUMED` must now list the assumptions it
rests on; the constructor rejects one that does not. A rule can no longer bake
a verdict into its message, and a test enforces it across the rule pack.

### Fixed: findings that were not trustworthy

- **EDA006 returned no finding for a dead-letter queue nobody was told about.**
  Alarms were matched on dimensions alone, so an alarm on an unrelated metric,
  with `ActionsEnabled: false` and no `AlarmActions`, counted as monitoring.
  Coverage now requires an alarm that could actually raise someone, and the
  finding names the alarm and every reason it cannot fire — an alarm somebody
  trusts that does nothing is worse than no alarm.
- **EDA007 treated any concurrency cap as protection.**
  `ReservedConcurrentExecutions: 1000` against a 5-WCU table silenced the rule.
  It now compares the consumer's concurrency ceiling to the table's write
  ceiling and publishes the assumptions that comparison needs. An autoscaling
  target no longer returns early: scaling reacts over minutes and stops at
  `MaxCapacity`, which belongs in the assumptions where a reader can weigh it.
- **EDA012 claimed a missing export proved no external consumer.**
  It does not — a subscription in another stack can name the topic ARN
  directly. The message now asks for confirmation instead of asserting
  reachability, and an IAM-derived publish edge is `INFERRED`, so it warns
  rather than blocks.
- **EDA001 blocked on AWS's recommendation as though it were AWS's rule.**
  The constraint AWS imposes is `VisibilityTimeout >= function Timeout`; the 6x
  margin is guidance. These are now separate findings with different `basis`,
  and only the first blocks by default. The existing `violating.yaml` fixture
  turned out to satisfy the constraint and miss only the recommendation, so a
  fixture that breaks the constraint itself was added.

### Reports state their own scope

`No findings.` on its own reads as "your system is sound" when it can mean "the
part that matters was not visible". Every report now carries a coverage block:
templates read, resources by kind, rules run, and every reason a finding could
be missing — cross-stack imports and exports, unresolved values, unreadable
files, resource kinds no rule covers, and Terraform or `cdk.out` found beside
the templates.

### Benchmark

`docs/benchmark.md` measures all twelve rules against Checkov 3.3.16 and
cdk-nag 2.38.2 on the same fixtures, with the harness in `docs/benchmark/`.
Ten of twelve defects were reported by neither tool; **EDA002 is substantially
covered by both** and should not be sold as a differentiator, and Checkov
partially covers EDA007. The caveats section explains what the result does and
does not establish.

### Compatibility

- `Finding.severity` remains as a read-only alias for `verdict`, and JSON
  reports still emit a `severity` key alongside `verdict`. Both are removed in
  the next minor.
- `Finding.inferred` is now derived from `confidence` rather than set directly.
- Rules declare `impact` and `basis` instead of `severity`.

## 0.3.0

Twelve rules, an escape hatch, and a scanner you can point at a repository.

### Rules

Seven rules join the original five. Each ships with a violating and a passing
fixture, and each reasons across connected resources rather than linting one.

- **EDA006** — a dead-letter queue with no consumer and no alarm. EDA002 asks
  whether a dead-letter path exists; this asks whether it goes anywhere.
- **EDA007** — an unbounded consumer writing into a provisioned-throughput
  table. Lambda reaches account concurrency in seconds; the table does not move.
- **EDA008** — a dead-letter queue that expires messages sooner than its source.
  Redrive does not reset a message's age, so the DLQ window is what is left of
  it, not the full retention.
- **EDA009** — more shared-throughput readers on a stream shard than its 2 MB/s
  serves. Enhanced fan-out consumers are resolved back to their stream and not
  counted against it.
- **EDA010** — a workflow task with no `Retry` and no `Catch`, including tasks
  nested inside `Parallel` branches and `Map` item processors.
- **EDA011** — a synchronous handler whose timeout exceeds the API integration
  limit, where the caller is told the request failed while it goes on succeeding.
- **EDA012** — a topic or bus with a publisher and no delivery route. The only
  failure mode that raises no error anywhere.

### Suppression

Findings can be waived from the template, next to the resource they concern:

```yaml
Metadata:
  deadletter:
    ignore:
      - rule: EDA001
        reason: Consumer is idempotent on order id; see ADR-114.
        expires: 2026-12-31
```

A reason is mandatory, `expires` is honoured, and an unreadable date is not
treated as no date. Entries that do not qualify are reported on stderr and not
applied. Nothing is deleted: suppressed findings stay in the JSON report, are
counted separately in the summary, and are marked in SARIF with a native
`suppressions` entry. They stop failing the build and nothing else.

### Discovery

`deadletter .` now works. Directories are walked for CloudFormation and SAM
templates, skipping `.aws-sam`, `cdk.out`, `node_modules`, `build`, and similar
generated trees. A named path is always scanned and failing to read it is an
error; a discovered path is skipped silently if it is not a template. A
directory with no templates in it is an error rather than a clean scan.

### Graph and parser

- Step Functions state machines contribute `invoke` and `publish` edges, so a
  workflow is part of the event-flow graph rather than a blind spot.
- `AWS::Kinesis::StreamConsumer` is modelled; a mapping that reads through one
  resolves to the underlying stream and is marked as enhanced fan-out.
- Output exports are recorded, which is what lets EDA012 tell a dead topic from
  one consumed by another stack.
- Resource `Metadata` is captured, `DefinitionString` state machines are parsed
  when they hold plain JSON, and SAM `Api` and `HttpApi` events keep their type.

### Fixed

- Report text is written to stdout as UTF-8 regardless of the console code
  page. Em dashes in finding messages previously arrived as mojibake on Windows
  when stdout was a pipe, while the same report written with `--output` was
  correct.

## 0.2.0

The five BLOCK rules, CLI, text/JSON/SARIF/mermaid reporters, source-aware
remediation, package build, and composite GitHub Action.
