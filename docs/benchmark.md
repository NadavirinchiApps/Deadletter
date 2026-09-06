# Benchmark: Deadletter vs Checkov and cdk-nag

Rule counts are not evidence. The only claim worth making to a buyer is:

> On a template with a known event-delivery defect, the tools you already run
> did not report it.

This document is that claim, measured. It is reproducible from the repository:
`docs/benchmark/run_benchmark.py`.

## Method

Each of the 12 fixtures in `tests/fixtures/EDA0*/violating.yaml` is a template
built to demonstrate exactly one delivery defect. Every tool was run against
every fixture:

| Tool | Version | Invocation |
|---|---|---|
| Deadletter | 0.4.0 | `deadletter <template> --format json` |
| Checkov | 3.3.16 | `checkov -f <template> --framework cloudformation` |
| cdk-nag | 2.38.2 (aws-cdk-lib 2.268.0) | `AwsSolutionsChecks` over `CfnInclude` |

cdk-nag reads a CDK construct tree rather than a template file, so each template
is pulled in with `CfnInclude` and the `AwsSolutions` pack applied as an Aspect.
That is the closest honest equivalent to "what would cdk-nag have told this
team", but it is not identical to running cdk-nag on the CDK source that
produced the template — see *Caveats*.

A competitor counts as **detecting the defect** only if one of its findings
describes the same failure. It is not enough to fire on the same resource. On
the EDA001 fixture Checkov reports that the queue is unencrypted; that is a real
finding about a different problem, and counting it would make this benchmark
worthless.

## Result

| Rule | Defect the fixture demonstrates | Deadletter | Checkov | cdk-nag |
|---|---|:--:|:--:|:--:|
| EDA001 | SQS visibility timeout shorter than its consumer's timeout | ● | — | — |
| EDA002 | Async delivery path with no dead-letter destination | ● | **●** | **●** |
| EDA003 | `BatchSize > 1` without `ReportBatchItemFailures` replays succeeded records | ● | — | — |
| EDA004 | Events can re-enter the hub that delivered them | ● | — | — |
| EDA005 | Unbounded stream retries let one poison record block a shard | ● | — | ○ |
| EDA006 | Dead-letter queue with no consumer and no working alarm | ● | — | — |
| EDA007 | Consumer concurrency ceiling outruns the table's write capacity | ● | ◐ | — |
| EDA008 | Dead-letter queue retention shorter than its source queue's | ● | — | — |
| EDA009 | More shared-throughput readers on a shard than it can serve | ● | — | — |
| EDA010 | Workflow task with no retry or catch for transient errors | ● | — | — |
| EDA011 | Handler timeout exceeds the API Gateway integration timeout | ● | — | — |
| EDA012 | Events published to a hub with no delivery route | ● | — | — |

● detected ◐ partially detected ○ tool could not read the template — no result

**10 of 12 defects were reported by neither tool.**

## Where the competitors do overlap

Two honest overlaps, and they matter more than the ten misses when setting
positioning.

**EDA002 — missing dead-letter path. Both tools cover this.**
Checkov's `CKV_AWS_116` ("Ensure that AWS Lambda function is configured for a
Dead Letter Queue") and cdk-nag's `AwsSolutions-SQS3` both fire on this defect.
"We find missing DLQs" is not a differentiator and should not be sold as one.
Deadletter's addition here is narrow: it distinguishes transport-level failure
from post-acceptance Lambda execution failure and reports which of the two is
uncovered. That is a refinement of an existing check, not a new capability.

**EDA007 — concurrency. Checkov covers half of it.**
`CKV_AWS_115` ("function-level concurrent execution limit") fires whenever a
Lambda has no reserved concurrency. It fires on *every* Lambda without one,
regardless of what that function writes to. It never compares the limit to the
capacity of anything downstream, so it cannot distinguish a cap of 5 against a
5-WCU table from a cap of 1000 against the same table. Deadletter makes that
comparison and states the assumptions it rests on. Related check, different
claim.

## Signal-to-noise

Detection is not the only axis. The two tools reported **96 findings** across
the 12 fixtures (71 from Checkov, 25 from cdk-nag), of which **3** describe the
defect the fixture was built to demonstrate: `CKV_AWS_116` and
`AwsSolutions-SQS3` on EDA002, and `CKV_AWS_115` on EDA007. The other 93 are
real but unrelated — encryption at rest, SSL
enforcement, VPC placement, point-in-time recovery. Three checks
(`CKV_AWS_115`, `CKV_AWS_116`, `CKV_AWS_117`) fire on all 12 fixtures purely
because every fixture contains a Lambda.

This is not a criticism of either tool: they are security and posture scanners
and those are the findings they exist to produce. It is a statement about what
a team reviewing an event-flow change gets from running them, which is a long
list that does not contain the delivery defect.

## An observed false positive worth confirming

On the EDA008 fixture, cdk-nag reported `AwsSolutions-SQS3` against `OrdersDlq`:

> The SQS queue is not used as a dead-letter queue (DLQ) and does not have a DLQ
> enabled.

`OrdersDlq` *is* used as a dead-letter queue — `OrdersQueue` names it at
`RedrivePolicy.deadLetterTargetArn` on line 15 of the same file. The same
finding appears on the dead-letter queues in most other fixtures.

This is the per-resource versus per-relationship difference in one example: the
check reads one queue at a time and cannot see that another queue points at it.
**Confirm this against a native CDK app before using it in a customer
conversation** — it may be an artifact of `CfnInclude` rather than a defect in
the rule, and this benchmark cannot distinguish the two.

## Caveats

These are the reasons not to over-claim from this table.

1. **Twelve fixtures Deadletter wrote itself.** They demonstrate defects
   Deadletter was built to find, on templates authored to contain them. That
   the competitors miss defects nobody designed them to catch is expected. The
   result establishes a coverage gap; it does not establish that the gap
   matters commercially. Only a scan of a customer's real infrastructure does
   that.
2. **cdk-nag was run through `CfnInclude`.** A team using cdk-nag natively
   writes CDK constructs, and some rules read construct-level context that
   `CfnInclude` does not reproduce. Results may differ on the CDK source.
3. **cdk-nag could not read the EDA005 fixture at all** (`CfnInclude` rejected
   the SAM transform). Recorded as "no result", not as a miss.
4. **Checkov ran with its default policy set.** Custom or graph-based Checkov
   policies could encode several of these checks; a platform team that has
   already written them would see different results.
5. **Neither tool was tuned.** No suppressions, no custom checks, no config.

## Reproducing

```bash
cd docs/benchmark
npm install                 # aws-cdk-lib, cdk-nag@^2, constructs
pip install checkov
python run_benchmark.py     # writes results.json
```

Raw per-fixture output is in `docs/benchmark/results.json`.
