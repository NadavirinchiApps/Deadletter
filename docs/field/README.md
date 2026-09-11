# Field scans

`docs/field-scan.md` measured 683 templates from public demo repositories. It
was worth doing and it does not answer the question that matters: demo code is
written to be short, and the defects this tool looks for come from systems that
have been changed by more than one person over more than one quarter.

This directory holds what a scan of production code found, one file per estate,
written up by whoever ran it. `<alias>.md` — never the customer's name.

The purpose is a single number: **of the findings that would have stopped a
release, how many did an engineer on that team agree were worth stopping it
for?** If that stays near the demo rate of roughly 0.4 percent of templates,
Deadletter is a credibility asset and a portfolio piece rather than a product,
and the honest thing is to say so.

Copy the template below.

---

```markdown
# <alias>

- **Date:** YYYY-MM-DD
- **Deadletter version:** 0.x.y
- **Surface:** CloudFormation / SAM / synthesized CDK (`cdk.out`)
- **Templates scanned:** N
- **Resources:** N
- **How it was run:** `deadletter . --policy default --format json`

## What the coverage block said

Paste it. If the scan could not see most of the estate, every number below is
about the part it could see, and the write-up has to say so first.

## Findings

| Rule | Findings | BLOCK | WARN | INFO |
|---|--:|--:|--:|--:|
| EDA001 | | | | |
| ... | | | | |

## Every BLOCK, adjudicated

One row per blocking finding. "Agreed" means an engineer who owns that system
said they would have wanted the release stopped — not that the finding was
technically correct, which is a much lower bar and the one that produced 160
blocks on the demo corpus.

| # | Rule | Resources | Agreed? | What they said |
|---|---|---|---|---|
| 1 | | | yes / no | |

## What was wrong

Findings the team disputed, with the reason. These become fixtures in
`tests/test_trust.py`, docstring included, whether or not the rule changes.

## What they asked for that does not exist

Verbatim where possible. This is the only reliable signal about what to build
next, and it is worth more than the numbers above.
```
