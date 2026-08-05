# One attempt, end to end

Everything below is a record of a single attempt that actually happened, on 2026-07-30, taken from the
instance's own database rather than written for this document. The numbers are the numbers. Where
something is unflattering it is here anyway, because the unflattering parts are the ones that tell you
whether the design works.

It is Hullwork fixing Hullwork. That is the honest choice and also the limited one: this is our own
repository, our own test suite, and a bug in code we wrote. **Nobody outside this project has run this
loop on their own code yet** — see [status.md](status.md).

## The 52 minutes

| | |
|---|---|
| 11:35:07 | A `SandboxError` reaches the tracker from production and becomes item 14 |
| 11:35:07 | Triage puts it in the **green** lane — the file it points at is in territory this instance lets an agent touch |
| 12:05:00 | The dispatcher takes the item and starts attempt 16 |
| 12:17:42 | Attempt ends. Six phases ran, four gates passed, a **draft** pull request is open |
| 12:27:54 | A person reads it and merges it |

**52 minutes and 47 seconds from a production error to a merged fix**, of which 12 minutes 42 seconds
were the agent and about 40 were the queue and a human's attention. One attempt. No retries.

## What arrived

```
SandboxError: '/nonexistent/docker' is not on PATH; the dispatcher needs the Docker daemon
```

A real failure in Hullwork's own sandbox teardown, reported by Hullwork's own error tracking, on the
instance that runs Hullwork. Fingerprint `93b933b8460816f4…` — the hash that makes the *next* occurrence
a recurrence instead of a second item.

## What the agent worked out

Its own words, from the transcript the gateway recorded:

> `Cable.close()` (`hullwork/sandbox/net.py:205`) documents itself as *"Safe to call twice, and never
> raises"* — but its **first** statement is a bare `_docker` call, while every other teardown call in
> the method goes through `_quietly`. […] `_docker` raises `SandboxError` when `shutil.which(argv[0])`
> is `None`. That is the reported message, and it is the correct answer to a missing daemon — not the
> bug. The bug is what happens next: `Cable.__enter__` catches it deliberately (*"Half a network is
> worse than none"*) and calls `self.close()`.

A method promising never to raise, raising on its first line, inside the error path of the thing that
calls it. That is a real root cause, not a plausible-looking patch.

## The part that argues for the whole design

The same transcript, one paragraph earlier:

> I wrote `tests/test_regression.py`. **I could not execute it — the Bash tool is unavailable in this
> environment**, so the "confirm it fails" and "run ruff/mypy" steps are unverified.

The agent could not run its own test and said so. **Hullwork ran it anyway**, because the gates do not
take the agent's word for anything:

| Step | Command | Exit | Took |
|---|---|---|---|
| `baseline` | `pytest` | `0` | 63.2s |
| `reproduce` | agent writes a failing test | `0` | 378.1s |
| `red-gate` | `pytest` | **`1`** | 59.0s |
| `fix` | agent writes the change | `0` | 172.1s |
| `green-gate` | `pytest` | `0` | 60.0s |
| `lint-gate` | `ruff check . && mypy .` | `0` | 18.9s |

Read the `red-gate` row again: exit `1` is the **required** outcome. A test that passes before the fix
proves nothing, so an attempt whose red gate goes green is thrown away. In counts:

- **904 passed** before anything changed — the suite was already green, so the attempt was allowed to start
- **2 failed, 904 passed** with the new test and no fix — the reproduction is real
- **906 passed** with the fix applied — and the 904 that passed before still pass

The verdict Hullwork recorded, verbatim: *"a test that failed against unmodified code passes with the
change applied — 2 test(s) failed with the candidate added, and the 904 test(s) that passed before still
pass — a clean reproduction."*

If the agent had been right about being unable to run anything, nothing would have changed: the gates
are what decide, and they run outside the agent's reach.

## Which model answered, measured rather than declared

The provenance seal, exactly as stored:

```json
{
  "endpoint": "https://api.anthropic.com",
  "model_requested": null,
  "models_served": ["claude-opus-5"],
  "model_drift": false,
  "precision": "undisclosed",
  "responses": 38,
  "statuses": {"200": 38},
  "completions": 35,
  "input_tokens": 1807,
  "output_tokens": 36559,
  "streamed": true,
  "violations": [],
  "refused_paths": []
}
```

`models_served` is not configuration being echoed back. Every request the agent made passed through
Hullwork's own recording gateway, and that list is what the responses on the wire said
(DR-0002). If a provider had silently served something else, it
would be in `model_drift` and in `violations`, on the attempt, permanently.

`precision: undisclosed` is the same rule applied to something nobody discloses. `refused_paths: []`
means the agent asked for nothing outside what it was allowed to reach — and had it tried, the path
would be listed rather than merely blocked.

For contrast, from a different attempt's seal on the same instance: `"statuses": {"200": 46, "429": 36}`.
Thirty-six rate-limit responses on one attempt. Kept because it is true, and because *"the attempt took
15 minutes"* means something different once you know why.

## What it cost, and what could not be measured

| | |
|---|---|
| Wall clock | 12m 42s |
| Tokens on the wire | 1,807 in · 36,559 out |
| Cached context | **not reported by this endpoint**, so any cost derived from the above is a floor |
| Cost | not priced on this instance — no price table ships with Hullwork, and none will ([why](deployment-notes.md)) |

The middle row is the honest one. Hullwork prints `null` for what the wire did not report rather than
`0`, and says out loud that the total is a floor. Across six counted attempts on this instance the
average was **0.2991 USD**, and that average has the same floor caveat attached.

## What the reviewer saw

The pull request opened as a **draft**, titled from the item, and its body led with this:

> **A test that failed against unmodified code passes with this change applied.** Both runs are below,
> with the commands and their exit codes.

Then: the two test names, the three exit codes, the provenance table above, the six phases with their
durations, and every phase's output in a collapsible block — including the agent's full transcript,
truncated where it was too long to store, and saying so where it truncated.

The last line of every pull request Hullwork opens:

> Opened by Hullwork as a **draft**. Nobody merges this but you.

The same evidence is on the instance's own page, for anyone without a forge account:

![The evidence page for one item: its lane and why, how often the error was seen, the tracker link, and
the pull request body as published](../images/the-evidence-page.png)

The data in that screenshot is seeded rather than this instance's, for the same reason the example above
is our own repository: a public document should not carry another project's issue titles. The layout,
the fields and the wording are the real ones.

## What this example does not show

- **A stranger's repository.** This is ours, with a suite Hullwork's own gates were designed against.
  The five attempts that reached a pull request are all on two repositories, both ours.
- **A rejection.** All four merged pull requests were merged. Nobody has yet closed one unmerged, so
  the rejection path is built, tested against a fake forge, and unproven in production.
- **A red or amber item.** This one was green, which is the case where an agent may act unattended. An
  amber item waits for `hullwork approve`; a red one is never attempted at all
  (DR-0008).
- **Cost against a metered provider.** The endpoint here reported no cached context. Against one that
  does, the numbers are larger and the seal says so.

Issue and pull request numbers above are from the instance's own forge, which is not this repository's
mirror.
