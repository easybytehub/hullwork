# Questions people actually ask

Answers with numbers where numbers exist, and *nobody has measured that* where they do not. Everything
quantitative below comes from the instance that runs this project, which is one instance with two
repositories on it — read [status.md](status.md) for how narrow that is.

## Money and time

### What does one attempt cost?

On our instance: **0.2991 USD on average** across the six attempts that counted against an item, 3.3446
USD total across eleven attempts that reached a model. Median wall clock **12m 55s**, slowest 30m 5s.

That average is a **floor**, and Hullwork says so on every seal rather than in a footnote: the endpoint
used there reported no cached context, so the largest term in a modern bill was invisible to the
measurement. Against a provider that does report it, expect more. Your model, your prompt sizes and your
suite's runtime move this number more than anything Hullwork does.

### Can I cap it?

`HULLWORK_MAX_ATTEMPT_TOKENS` stops the gateway forwarding once one attempt crosses it, and the attempt
ends `abandoned` **without consuming the item's one try** — so it is safe to set low and raise on
measurement.

**With one honest limit**: it binds on what the wire reports, and some endpoints report nothing during a
stream. Measured against OpenRouter's Anthropic-compatible route, an attempt spent 1.2 million cache-read
tokens under a one-million ceiling without the ceiling noticing, because none of them were counted. The
seal carries `unmeasured` naming the categories no completion reported — **empty means the ceiling was
real, populated means it was decorative**. Read that field before trusting the number.

### Does it retry until it succeeds?

No. **One attempt per item**, and a failed attempt closes the item as `failed`
(DR-0003). A product that retries is a product that can spend your
balance overnight on an item it will never fix.

## Control

### Can it push to my main branch? Can it merge?

No, twice, and by construction rather than by policy.

The pull request is opened as a **draft** and Hullwork has no merge path in it at all. The credential
that can push is held only by the dispatcher, which pushes one branch per attempt and nothing else — and
that process **listens on nothing**: no port, no route, nothing an attacker can reach. The half that does
answer webhooks cannot push, and **refuses to start** if it finds a credential that can
(DR-0009).

### How do I stop it?

Three levers, in increasing bluntness:

- `autofix.agent: none` in a project's `hullwork.yml` — that project still gets ingest, deduplication,
  triage and issues; nothing is ever attempted. **This is the default.**
- Stop the dispatcher (`docker compose stop dispatcher`). Ingest keeps working, the queue keeps filling,
  nothing runs. Items already claimed are released when its lease expires.
- Remove the model key. Every attempt then refuses before the sandbox starts, and says why.

### What decides which errors it may touch?

Risk lanes, declared per project and matched against the error rather than the file
(DR-0008):

- **green** — may be attempted unattended.
- **amber** — waits for `hullwork approve <id>` from a person. Nothing happens until then.
- **red** — never attempted by anything. Filed, deduplicated, and left for a human.

**Anything that matches no lane is red.** The default is refusal, so an unlisted error type cannot become
an attempt by omission. `hullwork projects lanes --checkout .` prints what your manifest actually
declares, before you connect anything.

## Trust

### What if the agent writes a test that passes without fixing anything?

That specific failure is what the red gate exists for: the test must **fail** against unmodified code and
**pass** with the change, both runs recorded with their exit codes, or no pull request is opened. A test
that passes before the change ends the attempt.

**What the gate does not prove is meaning.** A test tautologically tied to the change satisfies red-then-
green while asserting nothing useful. Hullwork cannot tell the difference and does not claim to — which
is why every pull request is a draft, the two test names are printed at the top of the body, and the
diff is a human's decision. The gate removes the cheapest failure mode, not the need to read the code.

### What if the error payload contains instructions aimed at the agent?

Assumed rather than prevented. Natural language cannot be sanitised, and a filter that half-works turns a
known exposure into a believed-safe one — so the defence is the *reach* of an injected instruction:
the sandbox's network, the credentials that are not in it, the branch it can push, the gate it cannot
skip, and the human who merges. [SECURITY.md](../SECURITY.md) enumerates what an injection can and cannot
touch, including what is not covered.

### Which model actually answered?

Read off the wire, never from configuration. Every request the agent makes passes through Hullwork's own
recording gateway, and the seal on each attempt lists the models the responses said they came from. A
provider serving something other than what you pinned is a recorded violation on that attempt rather than
a shrug (DR-0002). See a real seal in
[one attempt, end to end](an-attempt-end-to-end.md).

## Data

### What leaves my network?

Whatever you point it at, plus one thing: ~~There is no telemetry to us, no licence check, no
registration~~ — **the published image reports Hullwork's own crashes to us.** That sentence was true
when it was written on 2026-08-04 and stopped being true on 2026-08-06; it is struck rather than
deleted because a claim this project made in public is not something to quietly edit.

There is still no licence check and no registration. The only hardcoded external host in the codebase
is `api.github.com`, used when your forge *is* GitHub.

**What the reporting is, exactly.** A crash inside Hullwork produces about 350 bytes: the exception
class, Hullwork's own stack frames, its version, your Python version, a random identifier for the
installation, and how many projects, items and attempts it holds. It cannot carry the error message,
local variables, URLs, your hostname, your repository names, or anything from the errors your own
software reports — not because those are filtered out, but because the payload is *built* from a fixed
list of fields and there is nowhere for them to be. [`hullwork/upstream.py`](../hullwork/upstream.py)
is short and is the whole of it.

```
hullwork config --telemetry     # the exact payload this instance would send
HULLWORK_TELEMETRY=off          # stop it
```

The destination exists **only in the image we publish**. A build made from a checkout has nowhere to
send anything, and a test in this repository fails if a destination ever appears in the source. The
first line of every start says all of this in the terminal, before anything is sent. Details in
[PRIVACY.md](../PRIVACY.md).

Be clear about what configuring a hosted model means, though: **point Hullwork at a hosted endpoint and
your source and stack traces go to that provider**, because that is what asking a hosted model to read
your code is. `agent: none` sends nothing anywhere. A local endpoint keeps everything on your network.
Anything else is a decision with a destination, and the seal records which endpoint answered every time.

### Do you see my errors, my code, or my usage?

**Your errors, your code and your usage: no.** Nothing about them can reach us — the payload above has
no field that could hold them.

**Hullwork's own crashes: yes, from the published image.** ~~Nothing reports to EasyByte.~~ The
exception class and our own stack frames, so a defect somebody hits on an installation we will never
see becomes something we can fix. `HULLWORK_TELEMETRY=off` stops it; a build you make yourself never
starts.

Separately and unchanged: `HULLWORK_ERROR_DSN` sends Hullwork's *own* crashes to **your** tracker, if
you set it, with secrets scrubbed by name and by value. The two are independent — neither silences the
other, and yours gets the whole event while ours gets the constructed payload.

## Fit

### Which forges work?

Forgejo and Gitea (same adapter, both exercised), and GitHub (exercised). A GitLab adapter is written and
**unmeasured** — no instance has run against a real GitLab, so treat it as unsupported until one has
([status.md](status.md)).

### Which languages and stacks?

Any, and there is no queue of stacks to support. Your manifest declares the **image your tests run in** —
the one your CI already uses — rather than an ecosystem Hullwork has to have learned
(DR-0007). Go, Rust, PHP, Elixir and whatever ships next year
work on the day you connect them. The one permanent limit: a Linux image with a shell, built for this
instance's architecture. `distroless` and `scratch` are refused at registration.

### Postgres or SQLite?

Both. SQLite is fine for one instance and is what ours runs on; Postgres if you would rather.

### Does it work on a Mac?

Ways 1 and 2 of [install.md](install.md) do. A real deployment needs a Linux host, because the dispatcher
joins the Docker daemon's group to reach its socket and Docker Desktop ignores `group_add`.

### Is there a hosted version?

No, and multi-tenancy is deliberately not in this repository. One instance, your infrastructure, no seat
count and no project cap.

### Can I use it at work? Is it open source?

Yes, and no — in that order.

**Yes to using it**: commercially, on any number of projects, modified however you like, with your
changes kept private, on the software you sell to your own customers. No seat count, no project cap, no
key to ask us for. The single restriction is offering *Hullwork itself* to third parties as a service.

**No to "open source"**, by the OSI's definition, and we do not use the word — the honest one is
**source-available**. The licence is [FSL-1.1-ALv2](../LICENSE.md), and every release becomes
**Apache-2.0 two years after it is published**, automatically. What you install today is Apache-2.0 in
2028. `LICENSE.md` opens with the plain-language version of all of this.

The reason is not ideology: two people maintain this, and the failure they cannot survive is somebody
hosting it as a product while they keep fixing it. Everything else is permitted and the restriction
expires.
