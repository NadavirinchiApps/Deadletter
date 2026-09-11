# Deadletter: handoff for the next engineer

> **Status, 2026-09-07.** Phase 0 and Phase 1 have landed; see the `0.5.0` and
> `0.6.0` entries in `CHANGELOG.md` for what changed and why. What is left of
> Phase 0 needs the repository owner rather than an engineer: pushing the tag,
> configuring the PyPI trusted publisher, and clicking "Publish to Marketplace"
> on the release. Phase 2 is deliberately not started — §7 gates it on scans of
> production code through design partners, and none have happened. Two
> deviations from the plan below are recorded where they occur: the CDK fixture
> yields an `ASSUMED` EDA004 rather than `INFERRED` (§3), and the MCP SDK
> renamed `FastMCP` to `MCPServer` in 2.0 (§9). Everything else was built as
> written.

This document is the file-level plan for turning Deadletter from a standalone
CloudFormation/SAM scanner into a cross-resource rule engine that rides the
tools and IaC surfaces people already use. It is written for a fresh model or
engineer with no conversation history. Everything in it was verified on
2026-09-07 against the code at commit `fc69c79` (v0.4.1) and against live
external sources; where a claim was *not* verified it is marked **verify**.

Read this whole file before touching code. Then read `README.md`,
`CHANGELOG.md`, `docs/field-scan.md`, and `src/deadletter/findings.py`, in that
order. They carry the design principles that must survive every change below.

---

## 1. Where the product stands, in one page

**What is good and must not be broken**

- The event-flow graph (`src/deadletter/graph.py`) and the typed resource model
  (`src/deadletter/model.py`). Rules reason about connected resources, not one
  resource at a time. Nothing else in the free ecosystem does this.
- The three-axis finding contract in `src/deadletter/findings.py`: `impact`,
  `confidence`, `basis` are facts; `verdict` is computed by a customer-chosen
  `Policy`. Rules never set a verdict. A test enforces it.
- `Finding.defaults_relied_on`: a finding never blocks on a value the author
  never wrote.
- The coverage block (`src/deadletter/coverage.py`): every report states what
  it could not see.
- Suppressions with mandatory reason and honoured expiry (`suppress.py`).
- Per-rule violating and passing fixtures, and `tests/test_trust.py`, which is
  where every externally found false claim gets a regression.

**What was found to be wrong or weak (each verified)**

| # | Finding | Evidence |
|---|---|---|
| 1 | Only raw CloudFormation and SAM are read. Terraform and CDK, the two largest IaC surfaces, get a coverage note. `cdk.out` is skipped by `discover.SKIP_DIRS`. | `src/deadletter/discover.py:39-40`, `coverage.py:55-65` |
| 2 | On CDK-synthesized templates the graph builds no IAM-derived edges, because CDK emits IAM as separate `AWS::IAM::Policy` resources and `graph._permissions` reads only inline `Function.Policies` and `Role.Policies`. EDA004, EDA007 and EDA012 are silent, and coverage reports `unknown (3)` without naming the policy resource. | Reproduced with `tests/fixtures/cdk/Stack.template.json` (seeded, see §4). Expected today: one `rule_target` edge, no loop, no capacity finding. |
| 3 | AWS ships the nearest competitor free: `awslabs/serverless-rules` (cfn-lint rule pack `cfn-lint-serverless`, tflint plugin, cdk-nag pack). Its `ES6000` (SQS redrive), `ES7000` (SNS redrive), `ES4000` (EventBridge rule DLQ) and `ES1007` (async Lambda failure destination) together cover all of EDA002. `ES1001` covers the destination half of EDA005. `docs/benchmark.md` never mentions it. | https://awslabs.github.io/serverless-rules/rules/ ; PyPI `cfn-lint-serverless` 0.3.5, Feb 2026, requires `cfn-lint>=1.44` |
| 4 | EDA001's only blocking half duplicates a deploy-time error. Lambda's `CreateEventSourceMapping` / `UpdateEventSourceMapping` reject `VisibilityTimeout < function Timeout` with `InvalidParameterValueException: Queue visibility timeout: N seconds is less than Function timeout: M seconds`. The finding's consequence text describes a state a fresh deploy cannot reach. The residual real case: an existing mapping whose queue timeout is later lowered. | terraform-provider-aws issue 18099; aws-cdk issue 20527 (open, no synth-time check) |
| 5 | Lambda recursive-loop detection covers Lambda/SQS/SNS/S3 loops at runtime (drops after 16 hops, Health event), in all commercial regions since 2026-08. EventBridge and DynamoDB Streams loops are **not** covered. EDA004's honest scope is those. | https://aws.amazon.com/about-aws/whats-new/2026/08/lambda-recursion-regions/ |
| 6 | Under `--policy default` only five rules can ever BLOCK: EDA001 (requirement half), EDA005 (finite limit, no destination), EDA008 (declared shorter retention), EDA009, EDA012 (only when the publisher is a state machine, since IAM edges are INFERRED). Everything else is warn-only forever. | `findings.py` `DEFAULT_POLICY` + each rule's `basis`/`confidence` |
| 7 | On 683 real templates: 317 findings, 5 blocks, 2 of them deliberate demos. The README leads with "blocks releases"; the product is an advisory linter. | `docs/field-scan.md` |
| 8 | No distribution: not on PyPI (the name `deadletter` is unclaimed), no Marketplace listing, `action.yml` has no `policy` input. | PyPI JSON API 404 |

**The strategic call**

Do not build a standalone product around this. Build the engine into cfn-lint,
pre-commit, GitHub Actions, MCP, and the CDK and Terraform surfaces, so that the
cross-resource rules ride install paths that already exist. Reposition from
"catches failures before production" to "the checks for the wiring *between*
serverless resources, with stated confidence". Money, if any, comes later from
a hosted cross-repo graph and drift view, and only after design partners ask.

---

## 2. Principles you inherit (do not relitigate)

1. A rule declares `impact` and `basis`; each finding declares `confidence`.
   Verdict comes from `Policy`. A rule that sets a verdict is a bug.
2. Never block on an AWS default the author never wrote. Use `*_declared`.
3. An `ASSUMED` finding lists its assumptions or the constructor rejects it.
4. Every finding names both resources and quotes both values. Every `evidence`
   entry is greppable in the template.
5. "No findings" always travels with the coverage block.
6. Every rule ships `violating.yaml` and `passing.yaml`. The passing half is the
   one that matters.
7. Every trust fix gets a regression in `tests/test_trust.py` with a docstring
   saying what was wrong.
8. No AWS credentials, no network, no I/O inside rules.
9. Message format: `<resource> <config> is <value>, while <related> <config> is
   <value>. Required: <threshold>. Consequence: <one sentence>.`

---

## 3. File map

Legend: **KEEP** unchanged · **MODIFY** · **DELETE** · **CREATE**. Phase in
brackets. Anything not listed is KEEP.

### Repository root

| File | Action | Notes |
|---|---|---|
| `README.md` | MODIFY [P0] | Rewrite lead and rule table per §5. Add "Also reported by" column. State CDK and Terraform status truthfully as each phase lands. |
| `CHANGELOG.md` | MODIFY [P0, P1, P2] | Add `0.5.0`, `0.6.0`, `0.7.0` entries in the existing voice: what was wrong, what changed, what it removed. |
| `pyproject.toml` | MODIFY [P0] | Version bump; `[project.urls]`; optional deps `cfnlint = ["cfn-lint>=1.44"]`, `mcp = ["mcp>=1.0"]` (**verify** current SDK name/version); script `deadletter-mcp`. |
| `action.yml` | MODIFY [P0] | Add `policy` input (default `default`) passed as `--policy`. Add `allow-empty` input once the CLI flag exists (P1). |
| `.gitignore` | MODIFY [P0] | Add `.claude/`. It holds personal permission grants and is currently untracked only by luck. |
| `HANDOFF.md` | KEEP | This file. Delete it when Phase 2 ships; the CHANGELOG will carry the history. |
| `LICENSE` | KEEP | Apache-2.0. |
| `build/`, `dist/`, `src/deadletter.egg-info/`, `.pytest_cache/` | DELETE (local only) | Generated. Already gitignored and untracked. Never commit them. |
| `.claude/settings.local.json` | KEEP (untracked) | Personal. Do not commit. |

### `.github/workflows/`

| File | Action | Notes |
|---|---|---|
| `ci.yml` | MODIFY [P0] | Add a job that runs `docs/benchmark/run_benchmark.py --check` (see below) so the benchmark table cannot silently rot. Add a Windows runner to the matrix; the tool is developed on Windows and the UTF-8 fix in `cli.py` deserves a test there. |
| `release.yml` | CREATE [P0] | On tag `v*`: build sdist and wheel, publish to PyPI with `pypa/gh-action-pypi-publish` using trusted publishing (the owner configures the publisher on PyPI once), then create a GitHub release. Tagging is what lists the action on the Marketplace; the owner clicks "Publish to Marketplace" once. |

### `src/deadletter/` (engine)

| File | Action | Notes |
|---|---|---|
| `__init__.py` | MODIFY [P0] | Remove the `Severity` export. Make `scan()` accept `policy` and `today` and pass them to `rules.run`. Version string. |
| `__main__.py` | KEEP | |
| `cli.py` | MODIFY [P1, P2] | P1: `--allow-empty` (exit 0 when a directory holds no templates; needed for pre-commit and monorepos). P1: accept `cdk.out` manifests (see `discover.py`). P2: accept Terraform plan JSON; `--no-merge`. |
| `coverage.py` | MODIFY [P0, P2] | P0: list unknown resources by CFN type (`AWS::Lambda::Permission (1), AWS::CDK::Metadata (1)`), not `unknown (3)`. P0: add `iam_unresolved_roles`: functions whose `Role` could not be resolved in-template, with the sentence "publish and write edges from IAM were not inferred for: ...". P2: drop imports/exports that the merge resolved. |
| `discover.py` | MODIFY [P1] | If a scanned directory contains `cdk.out/manifest.json`, read the manifest and add every artifact of type `aws:cloudformation:stack` (**verify** the type string) by its `templateFile`, tagged `origin="cdk"`. Keep skipping `cdk.out` in the generic walk so nothing is scanned twice. Note: `deadletter cdk.out` already works today because `_skipped` is relative to the root. |
| `findings.py` | MODIFY [P0, P1, P2] | P0: delete `Severity = Verdict`, `Finding.severity`, and the `"severity"` JSON key (CHANGELOG 0.4.0 promised removal in the next minor). P0: add `Finding.overlaps: list[str]` stamped by `rules.run` from `Rule.overlaps`. P1: add `SourceLocation.address: str \| None` for a CDK construct path (P1) or Terraform resource address (P2). |
| `graph.py` | MODIFY [P0, P1] | P0: in `_permissions`, also collect statements from every `Kind.POLICY` resource whose `Roles` references the function's role (by logical ID via `referenced_ids`, or by literal role name via `name_hint`). Basis string `iam-policy-resource:<logical_id>`. Expose counts for coverage. P1: resolve the placeholder tokens that `StateMachine.definition` emits for `Fn::Join`/`Fn::Sub` definitions (see `model.py`). |
| `intrinsics.py` | MODIFY [P2] | Add `Reference.import_name` populated from `Fn::ImportValue` so the estate merge can resolve it. Everything else stays. |
| `model.py` | MODIFY [P0, P1] | P0: `Kind.POLICY` and a `Policy` dataclass (`roles: list[Reference]`, `policy_statements` like `Role`). Map both `AWS::IAM::Policy` and `AWS::IAM::ManagedPolicy`. P0: `Function.recursive_loop_terminates` reading the `RecursiveLoop` property (`Terminate` default, `Allow` disables the guardrail; **verify** the property name and values against the current CFN schema). P1: `Resource.construct_path` from `metadata["aws:cdk:path"]`. P1: `StateMachine.definition` must handle the CDK shape, a `DefinitionString` that is an `Fn::Join` of literal JSON fragments and `Ref`/`Fn::GetAtt` pieces: join the literals, replace each non-literal piece with a placeholder such as `"__dl_ref:<LogicalId>__"`, parse the JSON, and let `graph._add_state_machine_edges` map placeholders back to resources. Same trick for `Fn::Sub` bodies with `${Fn.Arn}` tokens. Today EDA010 is blind on every CDK state machine. |
| `parse.py` | MODIFY [P0, P2] | P0: map the two IAM policy types in `_TYPE_KIND` / `_CLASS`. P2: split into a frontend-agnostic container and a CloudFormation frontend (see CREATE below); keep `deadletter.parse` as a shim re-exporting `Template`, `load`, `loads` so the public API and tests do not break. P2: capture `Outputs` exports as `{export_name: Reference}` (today only the exported logical IDs are kept). |
| `report.py` | MODIFY [P0, P1] | P0: stop emitting `severity`; print `also reported by: ...` when `overlaps` is set; SARIF `helpUri` per rule pointing at `docs/rules/<id>.md` once those exist. P1: print `construct:` / `address:` after the `at` line when `SourceLocation.address` is set; add it to JSON and SARIF properties. |
| `suppress.py` | MODIFY [P2] | `Suppression.covers` must compare un-namespaced IDs within the same stack once logical IDs are namespaced by the merge. Nothing else. |
| `template.py` | CREATE [P2] | The container half of today's `parse.py`: `Template` with `resources`, `source`, `locations`, `exports`, `get`, `of_kind`, `resolve_ref`, `location`. Frontend-agnostic. |
| `frontends/__init__.py` | CREATE [P2] | |
| `frontends/cloudformation.py` | CREATE [P2] | Everything in today's `parse.py` that is CloudFormation- or SAM-specific: `_decode`, SAM expansion, Globals merge, parameter defaults, conditions, default bus. |
| `frontends/terraform_plan.py` | CREATE [P2] | See §6 Phase 2. |
| `estate.py` | CREATE [P2] | Merge several `Template`s into one graph. See §6 Phase 2. |
| `integrations/__init__.py` | CREATE [P1] | |
| `integrations/cfnlint.py` | CREATE [P1] | One `CloudFormationLintRule` per EDA rule. See §6 Phase 1. |
| `mcp_server.py` | CREATE [P1] | MCP server exposing `scan_paths`, `explain_rule`, `event_graph`. See §6 Phase 1. |

### `src/deadletter/rules/`

| File | Action | Notes |
|---|---|---|
| `base.py` | MODIFY [P0] | Add `Rule.overlaps: tuple[str, ...] = ()` and `Rule.docs: str` (URL or relative path). In `run()`, stamp `finding.overlaps` from the rule. Set `finding.source` from the first named resource's file, not `graph.template.source`, so the merge in P2 needs no change here. |
| `eda001.py` | MODIFY [P0] | Keep `REQUIREMENT`/`CONFIRMED`/`DUPLICATION`. Rewrite `_violation`'s message: AWS rejects this when the mapping is created or updated, so a fresh deploy fails rather than duplicates; the live risk is an existing mapping whose queue `VisibilityTimeout` is later lowered below the function `Timeout`, which the update API accepts. Add evidence `aws_rejects_at_mapping_creation: true`. Leave `_below_recommendation` alone. |
| `eda002.py` | MODIFY [P0] | `overlaps = ("cfn-lint-serverless ES6000/ES7000/ES4000/ES1007", "checkov CKV_AWS_116", "cdk-nag AwsSolutions-SQS3")`. Keep the rule; its transport-versus-execution split is a real refinement. Stop marketing it. |
| `eda004.py` | MODIFY [P0] | Compute `runtime_guardrail`: if the hub is a `TOPIC` and every node on the representative cycle is a `FUNCTION`, `TOPIC` or `QUEUE`, and no function on it sets `RecursiveLoop: Allow`, Lambda's recursive-loop detection stops the loop after 16 hops. Then `impact = DEGRADED`, evidence `aws_runtime_guardrail: "lambda-recursive-loop-detection"`, and the message says the cost is 16 invocations per event plus dropped events, not an unbounded loop. Cycles through a `BUS`, a `STREAM`/`TABLE` stream, or a `STATE_MACHINE` keep `STALL`. Add a passing fixture for the SNS-only loop and a violating fixture for the bus loop. |
| `eda005.py` | MODIFY [P0] | `overlaps = ("cfn-lint-serverless ES1001",)` for the destination half. No logic change. |
| `eda003`, `eda006`–`eda012` | KEEP | Logic is sound. `eda011.py`: in P2 read `timeout_milliseconds` from Terraform integrations instead of assuming 29/30 s. |
| `__init__.py` | KEEP | |

### `tests/`

| File | Action | Notes |
|---|---|---|
| `conftest.py` | MODIFY [P2] | Let `assert_rule` take an explicit filename pair so Terraform plan fixtures can reuse it. |
| `fixtures/cdk/Stack.template.json` | CREATE [P0] | **Seeded already.** A CDK-shaped stack: handler with `events:PutEvents` on the bus that invokes it and `dynamodb:PutItem` on a 5-WCU provisioned table, IAM in a separate `AWS::IAM::Policy`. Today it yields one edge and no EDA004/EDA007. After P0 it must yield an EDA004 bus loop (`INFERRED`, `STALL`) and an EDA007 finding, and coverage must name `AWS::Lambda::Permission` and `AWS::CDK::Metadata` by type. **Landed as `ASSUMED`, `STALL`:** the seeded rule filters on `source`, and by design that lowers confidence a step. The fixture was left as written rather than weakened to match the prediction. |
| `fixtures/cdk/StateMachine.template.json` | CREATE [P1] | A CDK-shaped `DefinitionString` built from `Fn::Join` with a `Fn::GetAtt` for the Lambda ARN. Must produce an EDA010 finding after P1. |
| `fixtures/EDA004/passing-sns-guardrail.yaml` | CREATE [P0] | SNS-only loop; expected `DEGRADED`, not `STALL`. |
| `fixtures/EDA004/violating-allow.yaml` | CREATE [P0] | Same loop with `RecursiveLoop: Allow`; expected `STALL` again. |
| `fixtures/estate/producer.yaml`, `consumer.yaml` | CREATE [P2] | `Export` in one, `Fn::ImportValue` subscription in the other. EDA012 must be silent on the merged graph and warn on the producer alone. Add a cross-stack bus loop pair too. |
| `fixtures/terraform/*.plan.json` | CREATE [P2] | Hand-written minimal `terraform show -json` outputs, one violating and one passing per rule that has a Terraform equivalent. |
| `test_graph.py` | MODIFY [P0] | Policy-resource edges; role resolved through `Fn::GetAtt`; managed policy attached via `Roles`; unresolved role recorded. |
| `test_trust.py` | MODIFY [P0] | Regressions for the four P0 corrections (IAM::Policy, EDA001 message, EDA004 guardrail, coverage naming). Docstring each with what was wrong. |
| `test_coverage.py` | MODIFY [P0] | Unknown resources listed by CFN type; unresolved roles reported. |
| `test_cli.py` | MODIFY [P0, P1] | `severity` key gone; `--allow-empty`; `cdk.out` manifest discovery. |
| `test_cfnlint.py` | CREATE [P1] | Skips unless `cfnlint` imports. Runs the rule pack over every violating fixture and asserts one match per expected finding, with a path. |
| `test_mcp.py` | CREATE [P1] | Calls the tool functions directly; no server process. |
| `test_terraform.py` | CREATE [P2] | |
| `test_estate.py` | CREATE [P2] | |
| everything else | KEEP | |

### `docs/`

| File | Action | Notes |
|---|---|---|
| `benchmark.md` | MODIFY [P0] | Add a `cfn-lint-serverless` column. Expected result: EDA002 ● (all four ES rules), EDA005 ◐ (ES1001, destination half only), all others —. Say plainly that EDA002 is covered by three free tools. |
| `benchmark/run_benchmark.py` | MODIFY [P0] | Replace the hardcoded `REPO = Path(r"F:\deadletter\Deadletter")` with `Path(__file__).resolve().parents[2]`. Add a runner for `cfn-lint -a cfn_lint_serverless.rules <template> -f json`. Add `--check`, which re-runs and fails if `results.json` would change, for CI. |
| `benchmark/results.json` | MODIFY [P0] | Regenerate. Never hand-edit. |
| `benchmark/nag.js`, `package.json`, `.gitignore` | KEEP | |
| `field-scan.md` | KEEP | Add one paragraph at the end when P0 lands: re-run the corpus and report the new block count; the number should be unchanged or lower. |
| `rules/EDA001.md` … `rules/EDA012.md` | CREATE [P1] | One page per rule: what it detects, impact/basis/confidence it can carry, the AWS documentation it rests on, what other tools cover it, an example finding, how to suppress. `report.py`'s SARIF `helpUri` and the MCP `explain_rule` tool point here. |
| `field/README.md` | CREATE [P1] | Template for design-partner scan write-ups (see §7). |

### Root additions

| File | Action | Notes |
|---|---|---|
| `.pre-commit-hooks.yaml` | CREATE [P1] | `id: deadletter`, `entry: deadletter . --allow-empty`, `language: python`, `pass_filenames: false`, `files: \.(ya?ml|json|template)$`. Requires the `--allow-empty` flag. |

---

## 4. What to do first (before any phase work)

1. Run the suite. On a Windows machine where the default temp directory is
   locked down, pytest errors with `PermissionError ... pytest-of-<user>`; that
   is the environment, not the code. Use
   `python -m pytest -q --basetemp=<any writable directory>`. CI on Ubuntu is
   unaffected. Do not change the repo for this.
2. Reproduce the CDK blind spot:
   `python -m deadletter tests/fixtures/cdk/Stack.template.json --fail-on none --policy strict --format mermaid`
   should print a single `rule_target` edge. That is the bug P0 fixes.
3. Re-read `docs/field-scan.md` §"What this changes". The same standard applies
   to everything below: a finding a reader cannot verify by opening the file is
   a finding that gets the tool uninstalled.

---

## 5. README changes, concretely

Replace the opening claim "catches event-delivery failures ... before they reach
production" with what the tool is: checks for the wiring *between* serverless
resources, each finding stating how well it is known, with the blocking decision
left to the customer. Keep the Checkov/Infracost contrast; add serverless-rules
to it honestly: "serverless-rules checks that a dead-letter path exists;
Deadletter checks whether it goes anywhere, whether the timeouts on both ends
agree, and whether the consumer can publish back into the bus that invoked it."

Rule table: add an "Also reported by" column. EDA002 lists three tools. EDA005
lists ES1001 for the destination half. EDA001 gets a footnote: the requirement
half is also rejected by Lambda at mapping creation. EDA004 gets a footnote:
Lambda stops SQS/SNS loops at runtime; EventBridge and stream loops it does not.

Install section: PyPI, pre-commit, GitHub Action with `policy`, cfn-lint
`-a deadletter.integrations.cfnlint`, MCP. Add each as it ships, never before.

Analysis boundaries: keep the section, update it phase by phase. Do not list a
surface as supported until its fixtures pass.

---

## 6. Phases

### Phase 0: trust fixes and distribution plumbing (target 0.5.0, about two weeks)

Deliverables, all listed in §3 with `[P0]`:

- `AWS::IAM::Policy` / `AWS::IAM::ManagedPolicy` feed the graph. Acceptance: the
  CDK fixture produces EDA004 and EDA007.
- Coverage names unknown resources by type and reports unresolved roles.
- EDA001 requirement message corrected; EDA004 scoped by the runtime guardrail;
  `overlaps` on EDA002 and EDA005.
- `Severity` alias and `severity` key removed.
- Benchmark extended with `cfn-lint-serverless`; hardcoded path removed;
  `--check` mode in CI.
- `action.yml` `policy` input. `.gitignore` covers `.claude/`.
- `release.yml`; first tag `v0.5.0`; PyPI publish; Marketplace listing.
- README and CHANGELOG per §5.
- Re-run the 683-template corpus (the repositories are named in
  `docs/field-scan.md`) and append the result.

Do not add rules in this phase.

### Phase 1: ride existing install paths (target 0.6.0, one to two months)

**CDK via `cdk.out`.** Manifest-driven discovery; `construct_path` from
`aws:cdk:path`; printed as `construct: OrdersStack/Handler/Resource` after the
`at` line, and carried in JSON and SARIF. `Fn::Join` state-machine definitions
parsed via placeholders so EDA010 works on CDK. Nested stacks are separate
manifest artifacts and are scanned individually until P2. Acceptance: a real
`cdk synth` output from a sample app (write one under `docs/samples/cdk/`, do
not commit `node_modules`) yields findings with construct paths, and the
coverage block names no `unknown` for CDK's own resource types.

**cfn-lint rule pack.** `src/deadletter/integrations/cfnlint.py`. One
`CloudFormationLintRule` subclass per EDA rule. In `match(self, cfn)`, build the
`Template` from `cfn.template` (add `parse.from_dict(raw, source)`; `cfn.template`
is already decoded), run the one rule under the default policy, and return one
`RuleMatch(path, message)` per finding using `finding.location.path` split into
components. Rule IDs: cfn-lint reserves the `E9xxx`/`W9xxx`/`I9xxx` ranges for
custom rules (**verify** in the current cfn-lint docs). Ship `W91xx` for every
EDA rule, and `E91xx` classes for the five rules that can BLOCK under the
default policy, emitting only BLOCK verdicts, so a cfn-lint user gets the same
split without a policy flag. Usage line for the README:
`cfn-lint -a deadletter.integrations.cfnlint template.yaml`. Optional
dependency group `cfnlint`.

**pre-commit.** `.pre-commit-hooks.yaml` plus the `--allow-empty` CLI flag.

**MCP server.** `src/deadletter/mcp_server.py` with the official Python MCP SDK
(**verify** the current package name, `mcp`, and its `FastMCP` API). Tools:
`scan_paths(paths: list[str], policy: str = "default", rules: list[str] | None)`
returning the JSON report dict; `explain_rule(rule_id)` returning id, title,
impact, basis, condition, overlaps, and the `docs/rules/<id>.md` text;
`event_graph(path)` returning Mermaid. Entry point `deadletter-mcp`. README
snippet: `claude mcp add deadletter -- deadletter-mcp`. This is the cheapest
distribution channel available in 2026 and the one that turns the engine into
something an AI reviewer calls instead of guesses at.

**Rule docs.** `docs/rules/EDA0xx.md`, wired into SARIF `helpUri` and the MCP
tool.

**Do not build a cdk-nag NagPack in this phase.** It would mean re-implementing
the graph in TypeScript. Revisit only if a design partner is CDK-native and
requires synth-time checks; `cdk.out` scanning in CI gives them the same
findings one step later.

### Phase 2: Terraform via plan JSON, and multi-stack (target 0.7.0, three to four months)

**Frontend split first.** Move the container to `template.py` and the
CloudFormation logic to `frontends/cloudformation.py`; `parse.py` becomes a
shim. Run the full suite; nothing may change.

**Terraform plan JSON**, `frontends/terraform_plan.py`. Input is
`terraform show -json tfplan` written to a file. Do not parse HCL. Two halves of
the plan matter:

- Values come from `planned_values.root_module.resources[*].values`, recursing
  through `child_modules`.
- Edges come from `configuration.root_module.resources[*].expressions.<attr>.references`
  (recursing through `module_calls`), because planned ARNs are
  "known after apply" and only the configuration block says which resource an
  attribute points at. **Verify** the exact shape against the current
  `terraform show -json` schema.

Translate into the existing `model` classes with CloudFormation property names
so the rules stay untouched. Minimum resource map: `aws_sqs_queue`
(`visibility_timeout_seconds`, `message_retention_seconds`, `redrive_policy`
JSON string), `aws_sqs_queue_redrive_policy` (merge into the queue),
`aws_lambda_function` (`timeout`, `reserved_concurrent_executions`,
`dead_letter_config`, `role`), `aws_lambda_event_source_mapping` (`batch_size`,
`function_response_types`, `maximum_retry_attempts`,
`maximum_record_age_in_seconds`, `bisect_batch_on_function_error`,
`destination_config.on_failure.destination_arn`, `scaling_config.maximum_concurrency`,
`event_source_arn`, `function_name`), `aws_lambda_function_event_invoke_config`,
`aws_sns_topic`, `aws_sns_topic_subscription` (`redrive_policy`),
`aws_cloudwatch_event_bus`, `aws_cloudwatch_event_rule`,
`aws_cloudwatch_event_target` (`dead_letter_config`, `retry_policy`, attach to
the rule's `Targets`), `aws_sfn_state_machine` (`definition` JSON string),
`aws_kinesis_stream`, `aws_kinesis_stream_consumer`, `aws_dynamodb_table`
(`billing_mode`, `write_capacity`, `stream_enabled`),
`aws_cloudwatch_metric_alarm`, `aws_iam_role`, `aws_iam_role_policy`,
`aws_iam_policy` + `aws_iam_role_policy_attachment` (become `Kind.POLICY`),
`aws_apigatewayv2_integration` and `aws_api_gateway_integration`
(`integration_uri`/`uri` to the function, `timeout_milliseconds` for EDA011).
Ignore `aws_lambda_permission`.

Locations: plan JSON has no line numbers. Findings carry
`SourceLocation.address = "module.orders.aws_sqs_queue.main"` and the attribute
name; `report.py` prints `fix aws_sqs_queue.main.visibility_timeout_seconds:`.
Messages will still say `VisibilityTimeout`; accept that for the first release
and note it in the README. CLI: detect a plan by the top-level
`format_version` + `planned_values` keys. When `deadletter .` finds `.tf` files,
the coverage note should now say how to produce the plan.

**Multi-stack merge**, `estate.py`. Given several `Template`s: namespace logical
IDs as `<stack>.<id>` (stack = file stem, or the CDK artifact id), resolve
`Fn::ImportValue <name>` against other stacks' export names, and let
`name_hint` literal matching work across stacks as it already does within one.
Rules run once on the merged graph. `finding.source` comes from each resource's
own file (done in P0 in `base.run`). Suppressions compare un-namespaced IDs
within their own stack. CLI merges by default when more than one template is
scanned; `--no-merge` keeps today's behaviour. Coverage drops imports and
exports the merge resolved. Acceptance: the `estate` fixtures; EDA012 silent on
the merged pair, warning on the producer alone; a bus loop that spans two
stacks is found.

### Phase 3: only on evidence

A hosted cross-repo graph with deployed-versus-template drift is the only thing
in this space with a moat. Do not start it until ten design partners run Phase
1 in CI and ask for it. Nothing in this phase has a file plan on purpose.

---

## 7. The validation experiment, and the kill criteria

The field scan in `docs/field-scan.md` used demo repositories and says so. The
missing evidence is production code. Before Phase 2:

- Scan three to five real estates through design partners. CDK estates via
  `cdk.out` count. Record per estate, under `docs/field/<alias>.md`: templates
  scanned, findings by rule and verdict, and for every BLOCK whether an
  engineer on that team agreed it was worth stopping a release for.
- If the release-worthy hit rate on production code stays near the demo rate
  (about 0.4 percent of templates), the product is a credibility asset and a
  portfolio piece. Keep it open source, finish Phase 1 for completeness, and
  stop.

Kill criteria after Phase 1 ships: fewer than a hundred installs across PyPI,
pre-commit and the Action, or no design partner reply within a month of asking.

---

## 8. Do not build

- A hosted service, dashboard, database, auth, or billing before Phase 3.
- A TypeScript cdk-nag pack (see Phase 1).
- An HCL parser (use plan JSON).
- Azure or GCP.
- Automatic patch application. `Remediation.automatic` stays false wherever a
  human must choose a destination or change handler code.
- New rules before Phase 0 and Phase 1 ship. The twelve are enough to prove the
  surface question; more rules do not change the answer.

---

## 9. Things stated here that you must verify before relying on them

- ~~cfn-lint's reserved custom rule ID ranges and the exact `RuleMatch` API.~~
  **Verified.** No shipped rule uses the 9000 range (323 rules checked in 1.55.1).
  `RuleMatch(path, message)`; a rule subclasses `CloudFormationLintRule` and
  implements `match(self, cfn) -> list[RuleMatch]`.
- ~~The `RecursiveLoop` property name and values on `AWS::Lambda::Function`.~~
  **Verified.** `RecursiveLoop: Allow | Terminate`, `Terminate` by default, and
  SAM passes its identically named property straight through.
- ~~The Python MCP SDK package name and `FastMCP` API surface.~~ **Verified and
  wrong:** the package is `mcp`, but 2.0 renamed `FastMCP` to `MCPServer`
  (`from mcp.server.mcpserver import MCPServer`). The decorator API is
  unchanged. `mcp_server.py` prefers the new name and falls back; the optional
  dependency is pinned `mcp>=2.0`.
- ~~The `cdk.out/manifest.json` artifact type string for stack templates.~~
  **Verified.** `aws:cloudformation:stack`, with `properties.templateFile`
  relative to the assembly root.
- The `terraform show -json` schema for `configuration.*.expressions.*.references`.
  Still unverified; Phase 2 is not started.
- ~~That `cfn-lint-serverless` 0.3.5 installs cleanly beside the `cfn-lint>=1.0`
  pin in `pyproject.toml` on Python 3.12 and 3.13.~~ **Verified on 3.12.6.** It
  requires `cfn-lint>=1.44.0` and resolved to 1.55.1 alongside this package.

Everything else in this document was read from the code or reproduced by
running it.

---

## 10. Working conventions

- Python 3.12+. `pip install -e ".[dev]"`. `python -m pytest -q`.
- Branch `prod` is the main branch. Commits are imperative one-liners in the
  style of the existing log ("Never block on a value the author never wrote").
- After any rule change: run `docs/benchmark/run_benchmark.py`, update
  `results.json`, update `benchmark.md` if a cell changed, add a CHANGELOG line.
- A finding message that a staff engineer cannot verify by grepping the
  template is not done.
