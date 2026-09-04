# Changelog

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
