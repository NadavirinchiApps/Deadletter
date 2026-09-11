# Field scan: 683 templates nobody wrote for us

The benchmark in [`benchmark.md`](benchmark.md) has a weakness stated in its own
caveats: twelve fixtures we authored, demonstrating defects we wrote rules for.
That competitors miss them is close to tautological, and it says nothing about
how the scanner behaves on code written without any knowledge of it.

This is that test. It is the closest thing to a customer scan available without
a customer, and it was run to find false positives, not to produce a good
number.

It found them.

## Corpus

| Repository | Templates |
|---|---|
| `aws-samples/serverless-patterns` | 502 |
| `aws/aws-sam-cli-app-templates` | ~140 |
| `aws-samples/aws-serverless-ecommerce-platform` | ~41 |
| **Total scanned** | **683** |

Two of these are AWS's own: `serverless-patterns` is the source of
serverlessland.com, and `aws-sam-cli-app-templates` is what `sam init`
scaffolds. If Deadletter blocks AWS's own starter templates, that is worth
knowing before a prospect discovers it.

Run at commit `c4f9ff9` (v0.4.0), default policy.

## Headline

| Measure | Result |
|---|---|
| Templates scanned | 683 |
| Templates entirely clean | 546 (79.9%) |
| Templates with any finding | 137 (20.1%) |
| Templates with at least one `BLOCK` | 78 (11.4%) |
| Total findings | 317 |
| `BLOCK` / `WARN` / `INFO` | 160 / 146 / 11 |

**The v0.4.0 policy split is doing real work.** The same corpus under
`--policy strict`, which approximates 0.3.0 behaviour where every rule shipped
as `BLOCK`, produces **312 blocks instead of 160**. Roughly half of what this
tool would have failed a build over yesterday, it now reports without blocking.

That is the good news, and it is where the good news ends.

## Adjudicating all 160 blocks

The expert's gate was "every pilot blocking finding is adjudicated". Applied
here:

| Class | Count | Verdict |
|---|---|---|
| Blocks on an AWS **default the author never wrote** | 63 | **Should not block** |
| EDA011 where the handler exceeds the limit by 1 second | 19 | **Should not block** |
| EDA005 demanding an `OnFailure` that is already configured | 4 | **Bug** |
| EDA003 on an explicitly chosen `BatchSize` | 41 | Defensible, wrong `basis` |
| EDA011 at 45–900s against a 29s integration | 31 | Defensible |
| EDA009 stream fan-out | 2 | **Correct** |
| EDA008 short dead-letter retention | 1 | *Reclassified — see below* |

Two blocks out of 160 are unambiguously correct *and* worth stopping a release
for.

> **Correction.** The single EDA008 block was first counted as correct. It is
> not: `DataProcessingDLQ` leaves `MessageRetentionPeriod` unset while its
> source declares 14 days, so the "too short" value is AWS's 4-day default and
> the author never wrote it. It belongs in the first row. Caught while
> implementing the fix, which is an argument for implementing fixes.

### 1. Blocking on AWS defaults the author never wrote — 63 blocks (39%)

The largest single problem, and it spans two rules.

EDA003 fires on a DynamoDB stream consumer with `BatchSize: 100` and no
`ReportBatchItemFailures`. In 28 cases the evidence says
`batch_size_declared: false` — **the template never set `BatchSize`.** 100 is
the AWS default. The same shape appears in EDA005: 35 blocks where both
`MaximumRetryAttempts` and `MaximumRecordAgeInSeconds` are unset, and Deadletter
applies AWS's infinite defaults and blocks on them.

Applying documented defaults is correct analysis — the deployed system really
will behave that way. Blocking a release over a value the author never typed is
a different thing. The engineer opens the file, finds nothing matching the
finding, and concludes the tool is wrong. That is how an installation is lost,
and correctness is no defence.

### 2. EDA011 blocking on a one-second overshoot — 19 blocks

Of 50 EDA011 blocks, 19 are `Timeout: 30` against a 29-second REST API
integration timeout. Deadletter reports:

> Required: at most 29s. Consequence: past 29s the caller receives 504 while the
> invocation runs on to completion.

Technically true. As grounds for failing a build over one second, indefensible.
A further 16 are `Timeout: 100` in `sam init` scaffolding — **AWS's own starter
templates fail this check.**

There is a deeper modelling error here. A Lambda `Timeout` is a ceiling, not a
duration. `Timeout: 100` does not mean the handler runs 100 seconds; it means it
is permitted to. Whether the 504 ever happens depends on actual handler
duration, which no template states. That is the definition of `ASSUMED`, and
EDA011 currently claims `CONFIRMED` `REQUIREMENT`.

### 3. EDA005 demands a destination that already exists — 4 blocks, a real bug

`src/deadletter/rules/eda005.py:93`. When retries are unbounded, the message
reads:

> Required: a finite retry count or record age **plus an OnFailure destination**

In four cases the evidence on that same finding says
`DestinationConfig.OnFailure: "set"`. The rule computes `recoverable` and uses
it to decide whether to skip, then ignores it when composing the message and the
remediation list. The unbounded-retry half of the finding is correct; the
demand attached to it is not.

## What it got right

Not everything here is a correction, and the parts that worked are the parts
0.4.0 changed this morning:

- **EDA008 correctly warned rather than blocked** on 18 dead-letter queues whose
  retention *equals* their source (both at the 4-day default). Under 0.3.0 that
  was a `BLOCK`. Equalling AWS's default is not a violation, and the
  `REQUIREMENT`/`RECOMMENDATION` split caught it.
- **EDA012 correctly warned** on all 14 unrouted-topic findings, marked
  `INFERRED` because the publish edge came from IAM. Every one would have been a
  `BLOCK` yesterday, and the message now asks for confirmation instead of
  asserting nothing can reach the topic.
- **EDA006's 29 findings all describe genuine gaps** — dead-letter queues with
  no consumer and no alarm, retention left at the AWS default. Correctly `WARN`.
- **The two EDA009 blocks are good catches**: 7 and 8 shared-throughput readers
  on a single DynamoDB/Kinesis stream, well past the 2 MB/s a shard serves.
  Both are AWS filter-syntax demos where the fan-out is deliberate, so a real
  user would suppress them — but the analysis is right and no per-resource
  scanner would find it.
- **80% of templates came back clean.** The scanner is not indiscriminate.

## What this changes

Before selling anything:

1. **Never block on an undeclared value.** When a rule's finding rests on an AWS
   default rather than a written one, it must not reach `BLOCK`. The parser
   already tracks `*_declared` for exactly this; the rules ignore it. This alone
   removes 63 of 160 blocks.
2. **EDA011 should be `ASSUMED`, not `CONFIRMED`/`REQUIREMENT`**, because a
   timeout ceiling is not a duration — and it needs a margin so a one-second
   overshoot is not a release-stopper.
3. **Fix the EDA005 message and remediation** to account for `recoverable`.
4. **EDA003's basis should be `RECOMMENDATION`.** Whole-batch redelivery is
   guaranteed AWS behaviour, but whether it is *harmful* depends on handler
   idempotency, which a template cannot state.

## Result after the fixes

All four were applied in v0.4.1 and the corpus re-scanned at the same commit
depth.

| | Before | After |
|---|---|---|
| Total findings | 317 | 317 |
| `BLOCK` | 160 | **5** |
| `WARN` | 146 | 301 |
| `INFO` | 11 | 11 |
| Templates with at least one block | 78 | **5** |
| Findings flagged as resting on an AWS default | — | 92 |

**Nothing was hidden.** The finding count is identical: every defect Deadletter
reported before, it still reports. What changed is that 155 of them no longer
stop a release, and 92 now say in the report which values came from AWS rather
than from the template — so nobody goes looking for a line that was never there.

The predicted landing point was ~45 blocks. The real figure is 5, because
fixing EDA003's `basis` and EDA011's `confidence` removed the 41 and 31
"defensible" blocks as well as the indefensible ones. That is the intended
behaviour of the policy split rather than an accident: both remain available
through `--policy strict`, which blocks 262 of the 317.

The five survivors, each resting on a value somebody wrote:

| Rule | Where | Why it stands |
|---|---|---|
| EDA005 ×3 | `dynamodb-streams-appsync-subscription`, `dynamodb-streams-lambda-eventbridge-sam-{node,rust}` | A finite retry limit was set with no `OnFailure` destination, so poison records are discarded with no replay path |
| EDA009 ×2 | `lambda-esm-ddb-filters-sam`, `lambda-esm-kinesis-filters-sam` | 7 and 8 shared-throughput readers on one shard |

Each fix carries a regression test in `tests/test_trust.py`.

## Honest limits of this exercise

- **These are sample repositories.** Demo code legitimately cuts corners a
  production system would not, so the finding *rate* here says little about a
  real customer estate. The false positives it exposed transfer; the density
  does not.
- **No engineer from those projects adjudicated anything.** Every judgement
  above is ours, which is the same weakness the benchmark has. It narrows the
  gap the expert identified; it does not close it.
- **`aws-serverless-airline-booking` failed to clone** and is not included.
- Findings were adjudicated by class, with samples inspected per class, not
  individually across all 160.

## Re-run at 0.6.0

The corpus was scanned again after the 0.5.0 trust fixes and the 0.6.0
integration work, on 2026-09-07, from fresh clones of the same three
repositories under the default policy. The commitment made when those fixes
landed was that the block count would be unchanged or lower.

| Measure | 0.4.1 | 0.6.0 |
|---|--:|--:|
| Templates scanned | 683 | 683 |
| Templates entirely clean | 546 | 546 |
| Templates with any finding | 137 | 137 |
| Templates with at least one `BLOCK` | 5 | 5 |
| Total findings | 317 | 317 |
| `BLOCK` / `WARN` / `INFO` | 5 / 301 / 11 | 5 / 301 / 11 |
| Under `--policy strict` | 262 blocks | 262 blocks |

Identical, and the same five templates block:

| Rule | Template |
|---|---|
| EDA005 | `serverless-patterns/dynamodb-streams-appsync-subscription` |
| EDA005 | `serverless-patterns/dynamodb-streams-lambda-eventbridge-sam-node` |
| EDA005 | `serverless-patterns/dynamodb-streams-lambda-eventbridge-sam-rust` |
| EDA009 | `serverless-patterns/lambda-esm-ddb-filters-sam` |
| EDA009 | `serverless-patterns/lambda-esm-kinesis-filters-sam` |

Two of the 0.5.0 corrections could not show up here, and it is worth saying
which rather than presenting an unchanged table as confirmation of everything:

- **The `AWS::IAM::Policy` fix changes nothing on this corpus.** These are SAM
  and hand-written CloudFormation templates, which write inline `Policies`. The
  defect it fixed only appears in synthesized CDK output, and there is none in
  these three repositories. It is covered by `tests/fixtures/cdk/` and by
  `docs/samples/cdk`, not by this scan.
- **EDA004 produces no findings on this corpus at all**, so the recursive-loop
  guardrail scoping has no effect on these numbers either. It is covered by the
  two fixtures added for it.

What the re-run does establish is the thing worth checking: reading IAM policy
resources, correcting two messages and adding four new code paths did not
introduce a single new finding on 683 templates nobody wrote for us.
