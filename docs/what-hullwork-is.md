# What Hullwork is

> **The canonical statement of the product, fixed 2026-08-09 by the operator.** Every other document
> describes a part; this one says what the parts are parts of. When a document and this page
> disagree, this page is what was decided and the other one has not caught up yet.
>
> The reasoning behind it is DR-0017. This page is
> the short form, kept separate so it can be read in a minute and quoted without a link.

## In one sentence

**Hullwork takes the work off a developer that nobody wants to do — errors, dependencies,
incidents — by verifying, before a person is asked, which of the things their tools claim are
actually true.**

## Why it is not a list of features

Every signal Hullwork accepts arrives from a tool that **asserts something and proves nothing**:

| what arrives | from | what it really says | verified by |
|---|---|---|---|
| a production error | Sentry, GlitchTip | *something broke* | a test that reproduces it |
| a dependency advisory | Renovate, Dependabot, OSV | *this version is vulnerable* | the project's own suite |
| a static finding | CodeQL, Opengrep | *this could be exploited* | a test naming the hostile input |

Three signals, three oracles, **one mechanism**: take the claim into a sandbox, submit it to an
oracle the agent cannot influence, return a verdict with the run attached.

That is why these are not three features that happen to share a repository. The oracle changes; the
machine does not.

## The three properties everything else follows from

**No oracle is written by the agent to make itself look right.** A reproducing test must fail first
on untouched code; the project's suite belongs to the project; a hostile input has to be nameable.
Remove this and the verdicts are worth nothing.

**"I could not verify this" is a first-class answer.** On this repository's own numbers — 160 code
scanning alerts, five real — that is the answer roughly nine times in ten, and delivering it
honestly is worth more than a fix, because nobody else delivers it at all.

**What is measured is how much left a person's desk with evidence attached.** Not a success rate.
An instance computes its own, on its own code, from its first day.

## What that means against the tools it sits beside

None of them verify anything, and that is the whole position:

- **Renovate and Dependabot** open the pull request and let the reviewer find out. Their own
  documented weakness is noise — *"here is every update, you decide"* — and it is structural: they
  do not execute, so they cannot rank. Hullwork runs the suite first and hands over the ones that
  pass.
- **Sentry Seer and Copilot Autofix** fix from unverified claims, with the same confidence for the
  five that are real and the hundred and fifty-five that are not.
- **Reachability vendors** reduce the same noise with static analysis, which is another unverified
  claim about an unverified claim. Executing is more expensive and it is not arguable.

## What Hullwork does not do, and will not

Merge by itself (constitution principle 1). Attempt a fix without a reproducing
test (DR-0003). Match a competitor's breadth for its own sake:
depth over coverage, because a verified verdict in five ecosystems is worth more than an unverified
one in ninety.

## Which documents have caught up, and when

Recorded so this page can be checked rather than believed. **Kept as a record rather than deleted**:
a page that could be checked and then cannot is a page that got weaker as it got more accurate.

All five were rewritten on **2026-08-09** (work item 181). None of them had been wrong; all of them
were partial, describing the product by one signal's pipeline where a reader was deciding what it is.

| | what it said before | what it says now |
|---|---|---|
| `pyproject.toml` | one signal's two endpoints, in the line PyPI shows | the one-sentence claim above |
| `README.md` | opened with the pipeline as *what it does* | opens with what is verified; the pipeline is named as the error signal's path |
| the roadmap | a segment and an obstacle order, with no product above them | says what is being roadmapped, and that the sections are not three products in a queue |
| the interface document | readers and their three questions | says what the surface is a surface *of*, and the constraint that follows |
| `docs/status.md` | accurate about the halves | says what they are halves of, per signal, with the state of each |

**The images caught up too**, on the same day and after the sentence above first said they would
not. `images/banner.svg` is the top of the README; `images/the-pipeline.svg` now says it is the path
*a production error* takes rather than what Hullwork does; and `images/social-preview.png` — the
card a link to this repository renders as, anywhere it is pasted — was the last one and the one with
the most reach.

That PNG had **no source in the repository**, which is what made it look unfixable. It has one now:
`images/social-preview.svg`, rasterised by `scripts/render-social-preview.sh`, both committed.

**What is guarded rather than remembered.**
`test_no_published_document_describes_the_product_by_its_plumbing` asserts that the old sentence
appears in no published document, in no packaging metadata, and in **no image source**. It failed
the day it was written, which is what made it a gate rather than a decoration, and it caught three
more instances afterwards — including the first line of the README, which is the banner's alt text
and the first thing a screen reader announces.

## What is released, and what is only built

Stated here because everything above describes a mechanism with three oracles, and a reader who
takes that as an inventory would be misled by this page rather than by the ones it corrects.

| signal | state, 2026-08-09 |
|---|---|
| a production error | **released** |
| a dependency advisory | **built and unreleased** — work items 172–180, absent from `published-surface.json`, which records `0.1.0a7` |
| a static finding | does not exist |

`CONTRIBUTING.md`'s rule is that documentation describes the released artefact rather than the
working tree, so no document may show that command until a release carries it — which is why it is
not named on this page either. The guard refused the first draft of this section for exactly that,
and naming a command a reader cannot run would invite them to type it and be told it does not
exist.
