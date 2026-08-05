# Hullwork documentation

Grouped by what you are trying to do, because that is how you arrived here.

## I want to see whether this works

- **[One attempt, end to end](an-attempt-end-to-end.md)** — a single real attempt from 2026-07-30, taken
  from the instance's database: the error, what the agent worked out, the four gates with their exit
  codes, the provenance seal as stored, and the 52 minutes from production error to merged fix. Start
  here if you want to know what the output actually looks like before installing anything.
- **[What works, what does not, and what nobody has shown](status.md)** — the honest scope, with dates.
  Read this before relying on anything else in here.
- **[Questions people actually ask](faq.md)** — what an attempt costs, whether it can push to your main
  branch, how to stop it, what leaves your network, and what the red/green gate does *not* prove. With
  the instance's real numbers, and *nobody has measured that* where that is the answer.
- **[Installing Hullwork](install.md#1-try-the-agent-half)** § 1 — the fix loop on your own code, with
  no forge account of any kind. A checkout, a stack trace, and about five minutes.

## I want to install it

- **[Installing Hullwork](install.md)** — three ways in, each stating what it needs before what to type,
  and the four requirements up front.
- **[Deployment notes](deployment-notes.md)** — what went wrong putting it on a real box next to a
  self-hosted tracker, in the order it happened, with what fixed each one. Not a guide; a record. It is
  long because the failures were, and it is the most useful thing here on the day something breaks.

## I want to connect a project

- **[Connecting a project](connecting-a-project.md)** — the manifest, registration, the webhook URL, why
  that URL is a credential, and where it goes on your tracker.
- **[`hullwork.yml` reference](hullwork-yml.md)** — every field, with what each one costs if you get it
  wrong.

## I want to know whether to trust it

- **[`SECURITY.md`](../SECURITY.md)** — the threat model. Prompt injection is *assumed*, not prevented;
  what an injected instruction cannot reach is the defence. It also says what is **not** covered.
- **[One attempt, end to end](an-attempt-end-to-end.md)** again, for a different reason: it is the only
  document here that can be checked against a running instance rather than believed.
- The **`README`**'s principles, and the two properties under them — the credential split and the
  provenance seal — are the short form of the argument.

---

## What is cited here and not published

Three kinds of internal document are referred to by name throughout the source and these pages, and
none of them is in this repository:

- **Decision records** — `DR-0002`, `DR-0004`, `DR-0009` and the rest. One file per decision, each with
  the alternatives it rejected and what would reopen it. They also contain EasyByte's own commercial
  reasoning, which is why they stay in the private repository.
- **Work items** — `item 122` and the like. A unit of work with its own measurement and acceptance
  criteria, kept in the project's tracker.
- **The specifications** (`m1 — ingest and triage`, `m2 — agent dispatch`), **the constitution** and
  **the plan**. The first two were written before the code and corrected by it, so where they disagree
  the code is right — working documents rather than contracts.

They are cited rather than paraphrased so that the reasoning behind a line has a name you can ask
about. **If one of them matters to you, ask and it will be published.** Nothing in them is needed to
run Hullwork; everything needed for that is on this page.
