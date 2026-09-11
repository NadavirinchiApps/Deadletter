# Changelog

## 0.6.0

0.5.0 fixed what the scanner got wrong. This release is about where it runs.
No new rules: the twelve are enough to answer the question this project exists
to ask, and asking it somewhere nobody has installed anything is worth more than
a thirteenth.

### CDK, through the cloud assembly

`cdk.out` stays out of the generic walk — it is full of asset staging copies
that would be scanned twice — but `cdk.out/manifest.json` names exactly which
files are stacks, so `deadletter .` in a CDK repository now scans them. Findings
from a synthesized template carry the construct path from `aws:cdk:path`:

```text
  at cdk.out/OrdersStack.template.json:121:4
  construct: OrdersStack/Handler/Resource
```

`Handler886CB40B` is not something the author of the CDK app can search for.
The path travels in JSON as `location.address` and in SARIF as a result
property.

CDK also writes state machine definitions as an `Fn::Join` of literal JSON
fragments with `Fn::GetAtt` spliced in where the ARNs go. That arrived as a dict
with no `States` key, so EDA010 was silent on every CDK workflow. The join is
now reassembled with a placeholder for each reference, parsed, and the
placeholders mapped back to resources — the workflow is read, and the graph
still knows which resource stood at each point. Same for `Fn::Sub` bodies.

`docs/samples/cdk` is a small CDK app whose synthesized output the whole path is
checked against, rather than a template written by hand to look like one. It
finds four defects, including one in the retry list AWS's own `LambdaInvoke`
construct generates.

### The rules run inside cfn-lint

```console
cfn-lint -t template.yaml -a deadletter.integrations.cfnlint
```

One adapter per rule, in the 9000 range cfn-lint reserves for rules it does not
ship. Each finding is reported once: `E91xx` when the default policy would block
it, `W91xx` otherwise, so the split survives a tool that has no policy flag.
Optional dependency group `cfnlint`.

### The rules run inside an AI reviewer

`deadletter-mcp` serves `scan_paths`, `explain_rule` and `event_graph` over MCP.
A model reviewing a diff cannot see that a queue's visibility timeout has to
clear the timeout of a function three resources away; it guesses, and it guesses
confidently. Reports carry the coverage block for the same reason the CLI does.

The tool functions do not import the MCP SDK, so they are testable and reusable
without it. Note for anyone following the 2026 plan: the SDK renamed `FastMCP`
to `MCPServer` in 2.0, and the optional dependency is pinned `mcp>=2.0`.

### pre-commit

`.pre-commit-hooks.yaml`, plus the `--allow-empty` flag it needs: a checkout
with no templates in it is not a wrong path when a hook is what is running.
`allow-empty` is an input on the GitHub Action too.

### Rule documentation

`docs/rules/EDA001.md` through `EDA012.md`: what each rule detects, which values
of each axis it can carry, whether it can ever block, the AWS documentation it
rests on, **what it cannot know**, who else reports it, a real example, and how
to suppress it. SARIF results link to them through `helpUri`, and the MCP
`explain_rule` tool returns the page.

`docs/field/README.md` is the write-up template for scans of production code,
which is the evidence `docs/field-scan.md` is missing and Phase 2 is gated on.

## 0.5.0

Four things were wrong, and one of them meant the scanner reported a clean
result on templates it had barely read.

### The graph was blind to every CDK-synthesized stack

CDK does not write inline `Policies`. It emits each grant as its own
`AWS::IAM::Policy` resource with a `Roles` list, and the graph read only
`Function.Policies` and `Role.Policies`. On a synthesized stack that meant no
IAM-derived edges at all: EDA004, EDA007 and EDA012 were silent, and the report
came back with findings missing rather than with a note saying so.

`AWS::IAM::Policy` and `AWS::IAM::ManagedPolicy` are now parsed as
`Kind.POLICY`, matched to a function's role by logical ID or by literal role
name, and their statements feed the same publish and write edges as inline
policies. Each edge records which policy resource it came from
(`iam-policy-resource:<logical_id>`), so the statement behind an inferred edge
can be opened. On `tests/fixtures/cdk/Stack.template.json` — a CDK-shaped stack
that previously produced one edge and nothing else — the scan now finds the bus
loop and the write against a 5-WCU table.

### The coverage block said "unknown (3)"

Which told a reader nothing they could act on. Unknown resources are now listed
by CloudFormation type — `AWS::Lambda::Permission (1), AWS::CDK::Metadata (1)` —
and a function whose execution role is not in the scan is named explicitly:
"publish and write edges from IAM were not inferred for: ...". Roles and policies
stopped being reported as kinds no rule reasons about, because they now are.

### EDA001 described a state a fresh deploy cannot reach

Lambda rejects `CreateEventSourceMapping` and `UpdateEventSourceMapping` with
`InvalidParameterValueException` when the queue's visibility timeout is below the
function's timeout. A template that violates the requirement does not deploy, so
the old message — duplicate processing — described something that could not
happen from this template. The live risk is an existing mapping whose queue
timeout is lowered afterwards, which the SQS API accepts. The message now says
both, and carries `aws_rejects_at_mapping_creation` in its evidence. It still
blocks: the defect is real, and the deploy failure is worth catching first.

### EDA004 claimed an unbounded loop where AWS caps it at 16

Lambda's recursive-loop detection has been in every commercial region since
August 2026: it drops an event after 16 hops around a Lambda/SQS/SNS/S3 loop and
raises a Health event. A loop whose hub is an SNS topic and whose every node is a
function, topic or queue is now reported as `DEGRADED` — 16 invocations per event
plus a dropped event, expensive rather than unbounded — with
`aws_runtime_guardrail: lambda-recursive-loop-detection` in the evidence. A
function that sets `RecursiveLoop: Allow` turns the guardrail off and the finding
back to `STALL`, naming the function that opted out. Loops through an EventBridge
bus, a stream, or a state machine are not covered by the guardrail and were never
downgraded.

### Findings name the tools that also report them

`Rule.overlaps` is stamped onto every finding and printed as `also reported by:`.
EDA002 names `cfn-lint-serverless` ES6000/ES7000/ES4000/ES1007, Checkov
CKV_AWS_116 and cdk-nag AwsSolutions-SQS3; EDA005 names ES1001 for its
destination half. AWS ships `cfn-lint-serverless` free and it covers all of
EDA002. The benchmark now measures it as a fourth tool, the README leads with
what is left after that overlap, and every EDA002 finding says it out loud.

### Removed

- `Severity`, `Finding.severity`, and the `severity` key in JSON reports. 0.4.0
  said they would go in the next minor. `verdict` is the only name for the
  policy decision.

### Also

- `--policy` is available as a `policy` input on the GitHub Action.
- `docs/benchmark/run_benchmark.py` no longer hardcodes an absolute path, runs
  `cfn-lint-serverless` as a fourth tool, refuses to run with a tool missing,
  and has a `--check` mode that CI runs on every push so the benchmark table
  cannot rot quietly. Regenerating it caught three stale verdicts left over from
  0.4.1.
- CI runs on Windows as well as Ubuntu; the UTF-8 stdout fix in `cli.py` was
  written for Windows and never tested there.
- A tagged release builds, publishes to PyPI through trusted publishing, and
  cuts a GitHub release.
- SARIF results carry a `helpUri` per rule.
- `scan()` accepts `policy` and `today`.

## 0.4.1

Scanning 683 templates from `aws-samples/serverless-patterns`,
`aws/aws-sam-cli-app-templates` and `aws-serverless-ecommerce-platform` — code
written with no knowledge of this tool — produced 160 blocks, of which **two**
were unambiguously correct and worth stopping a release for. This release is
the correction. Full adjudication in [`docs/field-scan.md`](docs/field-scan.md).

Block count on that corpus goes from **160 to 5**, with the finding count
unchanged at 317. Nothing was hidden; 155 findings simply stopped stopping
releases.

### A finding may not block on a value the author never wrote

The largest single problem, 63 of 160 blocks. EDA003 applied AWS's default
`BatchSize` of 100 and blocked; EDA005 applied the infinite stream-retry
defaults and blocked. The analysis is right — the deployed system really does
behave that way — but an engineer who opens the file, finds nothing matching the
finding, and concludes the tool is wrong is an engineer who uninstalls it.

`Finding.defaults_relied_on` names the properties whose values came from AWS.
The default policy will not block on them; `--policy strict` will. The text
report says so in as many words, so nobody hunts for a line that was never
there. Only the *decisive* side of a comparison counts — if the author wrote a
short retention on a dead-letter queue, the source queue sitting at its default
does not excuse it.

### Rules corrected

- **EDA011** claimed `CONFIRMED`/`REQUIREMENT` on a modelling error: a Lambda
  `Timeout` is a ceiling, not a duration. `Timeout: 100` means the handler *may*
  run 100s, not that it does, so whether the 504 ever happens depends on runtime
  behaviour no template states. Now `ASSUMED`, states that assumption, and
  reports how many seconds beyond the integration timeout the ceiling sits. This
  removed 50 blocks, 19 of which were a *one-second* overshoot and 16 of which
  were AWS's own `sam init` scaffolding.
- **EDA005** demanded an `OnFailure` destination that four findings' own
  evidence showed was already configured. The rule computed `recoverable`, used
  it to decide whether to skip, then ignored it when composing the message and
  the remediation list. The unbounded-retry half was always correct; the demand
  attached to it was not.
- **EDA003** is now `RECOMMENDATION`. Whole-batch redelivery on a partial
  failure is documented AWS behaviour, but whether it is *harmful* depends on
  whether the handler is idempotent, which no template states. The message now
  says so.

### What the field scan confirmed was working

Reported for balance: EDA008 warned rather than blocked on 18 dead-letter queues
whose retention equals their source, EDA012 warned on all 14 unrouted topics as
`INFERRED`, and 80% of the 683 templates came back completely clean. All three
are behaviour introduced in 0.4.0.

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
