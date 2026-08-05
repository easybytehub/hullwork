# Hullwork

[![CI](https://github.com/easybytehub/hullwork/actions/workflows/ci.yml/badge.svg)](https://github.com/easybytehub/hullwork/actions/workflows/ci.yml)
[![Licence: FSL-1.1-ALv2](https://img.shields.io/badge/licence-FSL--1.1--ALv2-blue)](LICENSE.md)

> The missing link in your self-hosted stack: from production errors to reviewable pull requests — on
> your infrastructure, with your API keys, with a human gate on every merge.

```
 production error ──► error tracker ──► webhook ──┐
 (GlitchTip / any                                  │
  Sentry-compatible)                               ▼
                                        ┌─────── HULLWORK ───────┐
 human report ────► normalizer ───────► │ triage · dedup · lanes │
 (email / chat)                         └───────────┬────────────┘
                                                    ▼
                                        work item (risk-laned)
                                                    ▼
                                 coding agent (sandboxed, your key)
                                                    ▼
                                        pull request (draft)
                                                    ▼
                                     ✋ HUMAN GATE — review & merge
                                                    ▼
                                        deploy (your pipeline)
```

One declarative file per repository (`hullwork.yml`) — no per-project glue code.

**Pre-alpha.** Both halves run end to end, five attempts have reached a draft pull request, and nobody
outside this project has installed it. What works, what does not, and what nobody has demonstrated are
all in **[docs/status.md](docs/status.md)** — read that before relying on any of this.

## What it actually produced, once

Before installing anything, read one real attempt: **[one attempt, end to end](docs/an-attempt-end-to-end.md)**.
Taken from the instance's own database, not written for the page — a `SandboxError` from production at
11:35, a merged fix at 12:27.

The two rows worth skipping ahead for. First, the agent said this about its own work:

> I wrote `tests/test_regression.py`. **I could not execute it — the Bash tool is unavailable in this
> environment**, so the "confirm it fails" and "run ruff/mypy" steps are unverified.

Second, what happened next, because nothing here takes an agent's word for anything:

![Six phases in order with the exit code each one owes: baseline must exit 0, the red gate MUST exit 1,
the green and lint gates must exit 0. Measured on that attempt: 904 passed untouched, 2 failed with the
new test and no fix, 906 passed with the fix applied. Only then a draft pull request, and a person
merges it or does not.](images/the-red-green-gate.svg)

The agent could not run its own test and it did not matter, because the gates decide and they run
outside its reach (DR-0003). The seal on that attempt says
`"models_served": ["claude-opus-5"]` because that is what the responses on the wire said — not because
anything was configured to claim it.

## What you look at every day

![Hullwork's daily page: what is running now, six columns with counts and ages, and what does not add
up](images/the-daily-page.png)

One read-only page, no buttons, about forty seconds. What is running, what is stuck behind it, and what
is **waiting on you** — the third column, because that is the only one that is your problem. The
evidence an evaluator wants is further down the same page, never in front of the person who opens it
daily. There is nothing to log into: the URL carries a bearer token and that URL *is* the credential
(the interface).

## See it work in five minutes, with no account anywhere

The differentiator is a test that failed against unmodified code and passes with the change, in a
sandbox, by a model whose identity was read off the wire. You can judge exactly that without giving
Hullwork a credential that writes anywhere: a checkout, a stack trace you already have, and a model key.

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e .
export HULLWORK_MODEL_KEY="…"        # any provider — Anthropic, OpenAI, DeepSeek, OpenRouter, local

hullwork try /path/to/your/checkout --error trace.txt
```

Your checkout needs a `hullwork.yml`. This is the whole of the smallest one that reaches an attempt:

```yaml
project: myproject
git: { provider: forgejo, repo: owner/myproject }   # a coordinate; nothing is contacted
tests: pytest                                       # your real test command
runtime: { base: python-3.12 }                      # any Linux image with a shell
autofix:
  agent: claude-code        # `none` is the DEFAULT, and with it nothing is ever attempted
  lanes:
    green: [keyerror]       # error types you accept an agent trying. Unlisted ⇒ red ⇒ refused
```

**The last three lines are the ones people leave out**, and both defaults are deliberate: `agent: none`
runs no agent at all, and an error matching no lane is **red**, which nothing ever hands to an agent. Get
either wrong and `try` prints a refusal naming which one. `hullwork propose --checkout .` writes most of
this file from your CI configuration, with no credential. Requirements, and the three that are hard
limits, are in **[docs/install.md](docs/install.md#before-you-start)**.

Two more that need no credential at all:

```bash
hullwork projects lanes --checkout .   # which of your files this instance keeps a human on, and why
hullwork propose --checkout .          # a manifest, read from your CI configuration
```

## Ways to run it

**1. Try the agent half.** Needs Docker, a model key, a checkout. Gives you the fix loop on your own
code, and writes nothing outside a directory you name. → above, and
[docs/install.md § 1](docs/install.md#1-try-the-agent-half)

**2. The evaluation stack.** Needs Docker and nothing else — **no clone and no build**: one compose
file and a published image (`ghcr.io/easybytehub/hullwork:0.1.0a1`, amd64 and arm64). One container, the
half that answers webhooks, which starts with no credentials at all and says in a sentence what it
cannot do yet.
→ [docs/install.md § 2](docs/install.md#2-the-evaluation-stack)

**3. A real deployment.** Needs Docker on a Linux host, and a forge token that can file issues and
provably not push. `hullwork init` writes the compose file and the environment; the traps of running it
next to a self-hosted tracker are recorded in [docs/deployment-notes.md](docs/deployment-notes.md).
→ [docs/install.md § 3](docs/install.md#3-a-real-deployment)

There is no hosted option, and multi-tenancy is deliberately not in this repository.

## How this differs from things that sound like it

**Your error tracker's own AI fix feature** (Sentry's, and whatever ships next) is the closest thing, and
if you already pay for that tracker it is the cheaper answer — nothing new to run. The differences are
structural rather than better/worse: that feature belongs to the tracker, so it ships with the tracker's
model choices and the tracker's hosting, and your source and stack traces go wherever the vendor sends
them. Hullwork ingests from anything Sentry-compatible, runs on your box, calls the endpoint you name,
and puts a provenance seal on every attempt saying which model actually replied. If you are happy with
your vendor's answer to those three questions, you do not need this.

**Coding agents that take an issue and open a pull request** (Copilot's, Devin, and the rest) start from
a task a human wrote and can attempt almost anything — features, refactors, migrations. Hullwork starts
from an error that already happened in production and attempts only that, in territory you declared in
advance. Much narrower on purpose: it never has to decide whether a task is a good idea, only whether
this failure is inside the lines you drew. They are better at everything else.

**Renovate and Dependabot** are the other bots that open pull requests, and they solve a different
problem — dependency bumps, where the diff is mechanical and the risk is in the upgrade. Nothing here
competes with them; run both.

**A cron job with an agent CLI in it** is the honest DIY version, and it is genuinely close: wire your
tracker's webhook to a script that shells out to a coding agent. What you would then build, in this
order, is what this repository is — deduplication by fingerprint so one error is one item and not forty,
risk lanes so an agent cannot touch payments, two processes with disjoint credentials so the half facing
the internet cannot push, a red gate so an unverified fix cannot reach a pull request, one attempt per
item so a failure cannot loop, and an evidence artefact a reviewer can read in two minutes. If you want
only the first two, the cron is less work and you should write it.

**What it is not for.** Feature requests, refactors, performance work, anything without a reproducible
failure, and anything you would not let a stranger open a draft pull request about.

## Principles

1. **Trust is the product.** A human gate on every merge. Risk lanes — green, amber, red — decide what
   an agent may even attempt, and anything unmatched is red. Every action leaves an auditable trail.
2. **Your infrastructure, your keys.** Self-hosted first. Bring your own model endpoint, error tracker
   and forge. Nothing leaves your network unless you configure it to — and be clear about what
   configuring it means: point Hullwork at a hosted model and your source and stack traces go to that
   provider, because that is what asking a hosted model to read your code is. `autofix.agent: none` is
   the default and sends nothing anywhere; a local endpoint sends nothing off your network; anything
   else is a decision with a destination, and the seal records which endpoint answered every time.
3. **Provider-agnostic.** The forge and the tracker are adapters; the coding agent is a *container
   contract* rather than an integration, so any harness that takes a worktree and returns a diff
   qualifies, and any model endpoint works because all model traffic passes through Hullwork's own
   recording gateway (DR-0004).
4. **Any stack, and no queue of stacks to support.** A manifest declares the *environment* your tests
   run in — the image your CI already uses — never an ecosystem Hullwork has to have learned. Go, Rust,
   PHP, Elixir and whatever ships next year work on the day you connect them
   (DR-0007). The one permanent limit: a Linux image
   with a shell, on this instance's architecture.
5. **Single-tenant core, uncapped.** Everything a team needs for N projects, free to self-host under
   the FSL. No seat count, no project cap, nothing withheld behind a paywall.
6. **Boring tech.** Python, FastAPI, Postgres or SQLite, Docker Compose. The agent sandbox requires
   Docker anyway, so container distribution is the design rather than a compromise.
7. **Dogfood.** Hullwork maintains Hullwork. This repository is wired to its own pipeline, and two of
   the defects fixed in it were found, reproduced and patched by its own loop.

## The two properties everything else rests on

**The two halves hold different credentials, and that is the product.**

![The receiver answers webhooks and holds a token that files issues; it cannot push code, guaranteed,
and refuses to start if it finds a credential that can. The dispatcher holds the token that pushes one
branch and listens on nothing — no port, no route, nothing to reach. They never call each other: the
only thing they share is one database.](images/the-credential-split.svg)

The half an attacker can reach cannot push. The half that can push cannot be reached
(DR-0009).

**Which model answered is measured, not declared.** Every request passes through Hullwork's own
recording gateway, so the seal on each attempt says which endpoint replied and which model it was. A
different model answering is a recorded violation rather than a shrug
(DR-0002).

## Documentation

**[docs/](docs/)** is indexed by what you are trying to do. The six you are most likely to want:

- **[One attempt, end to end](docs/an-attempt-end-to-end.md)** — a real one, with its seal and gates.
- **[Questions people actually ask](docs/faq.md)** — cost, control, what leaves your network.
- **[What works and what does not](docs/status.md)** — the honest scope, with dates.
- **[Installing Hullwork](docs/install.md)** — three ways in, and what each one needs.
- **[Connecting a project](docs/connecting-a-project.md)** — the manifest, registration, the webhook.
- **[`hullwork.yml` reference](docs/hullwork-yml.md)** — every field.

Security: **[SECURITY.md](SECURITY.md)** states the threat model, including what it does not cover.
Prompt injection through an error payload is *assumed* rather than prevented — natural language cannot
be sanitised, and a filter that half-works turns a known exposure into a believed-safe one — so the
defence is what an injected instruction can reach, and that is enumerated.

## For development

```bash
python3.12 -m venv .venv && source .venv/bin/activate   # 3.12, not `python3` — see CONTRIBUTING.md
pip install -e ".[dev]"

ruff check . && mypy . && pytest    # the three gates — green is the definition of done
```

Contributions open when this repository does. [CONTRIBUTING.md](CONTRIBUTING.md) has the sign-off rule,
and [PULL_REQUEST_TEMPLATE.md](PULL_REQUEST_TEMPLATE.md) is the whole of the contributor agreement —
there is no form to sign anywhere else.

## Where this is going

No roadmap and no dates. Every estimate this project has made about its own pace has been wrong in both
directions, and the honest answer to "what is next" is whatever the first installation from outside this
project turns out to need. Nobody has done that yet, which is the only fact about the future here worth
publishing.

## Licence

[Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md) — free to use, modify and
self-host; you may not offer it as a competing hosted service. Each release becomes Apache-2.0 two years
after publication.

---

Built by [EasyByte](https://easybyte.es).
