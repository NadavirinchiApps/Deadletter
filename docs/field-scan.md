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
| EDA009 fan-out, EDA008 short retention | 3 | **Correct** |

Three blocks out of 160 are unambiguously correct *and* worth stopping a
release for.

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

Applying 1–4 takes the block count from 160 to roughly 45, and every survivor
would be a value somebody actually wrote.

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
