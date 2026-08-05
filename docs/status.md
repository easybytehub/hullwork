# What works, what does not, and what nobody has shown

Pre-alpha. This page is the honest scope, kept apart from the README so it has room to be specific and
so nothing in it has to be shortened to keep an introduction readable. It changes weekly; the date on
each claim is part of the claim.

## What works today

A production error posted by your error tracker is authenticated, stored, normalised, deduplicated,
triaged into a risk lane and filed as a labelled issue in your forge — with nobody touching anything.
Repeats increment a counter and stay silent.

A digest per run can summarise it, ordered by what needs you rather than by what happened first.

**The agent half, stated exactly.** `autofix.agent: none` is the **default** and is still the whole
product for a project that wants nothing else. It is not the only supported value: this repository's
manifest declares `agent: claude-code`, and so does the other project this instance watches.

As of 2026-08-04, **five attempts have reached a draft pull request**. Three of the first four were
merged after review, and two of those fixed defects in Hullwork itself that its author had not noticed.
The fifth was produced on 2026-08-04 as the first run driven by a third-party endpoint rather than by a
subscription, and it fixed a real defect in this repository's readiness check.

Each carries two commits — the failing test, then the fix — and the claim rests on the gates rather
than on the agent's account of itself.

**Lanes are derived, not written.** This instance has its own opinion about which code is dangerous —
schema migrations, CI and deployment definitions, your test and lint configuration, dependency
manifests, licence and ownership files — read from the path an error came from rather than from a list
you maintain. Each rule carries a sentence saying why a wrong automated fix there is not a bug.

`hullwork projects lanes --checkout .` prints that policy applied to **your** tree, file by file, with
no credential of any kind. Run it before you trust an instance with a repository: a policy nobody has
read is a policy nobody has agreed to.

**Services in the sandbox work.** The other project this instance watches declares `postgres-16` and
its suite runs against a blank one per phase. That path has been exercised by **one** project, and
`alembic upgrade head` in its test command is what made it necessary.

## What does not exist yet

- **Only the GlitchTip webhook route is enabled.** Sentry signs its webhooks properly and would be
  verified by HMAC — that route is written and switched off, because verifying a signature means
  storing a client secret in reversible form, which is a different storage decision from the one-way
  hash used here and has not been made.
- **Of the notification channels, only `none` and `console` deliver.** `telegram` and `email` parse in
  the manifest and are refused at delivery, because a transport nobody has exercised is a transport
  whose first real run happens in front of a user.
- **The GitLab forge adapter is written and unmeasured.** GitHub, Forgejo and Gitea are exercised.
- **No hosted or managed option exists**, and multi-tenancy is deliberately not in this repository.

## What has not been shown

This is the section that matters, and it is the reason this project publishes no success rate.

**Nobody outside this project has installed Hullwork.** Four automated evaluations by agents given no
prior knowledge of it were run on 2026-08-04; they found nineteen and then twenty-five points of
friction, ten of them defects, and two of those had been silently red in CI. Every one is fixed. But an
agent following documentation is a proxy for a person, not a person.

**Every error the loop has fixed was provoked from inside this project.** A real defect each time,
reachable by ordinary use — but triggered deliberately rather than by a stranger's traffic.

**Whether a model writes a reproducing test for real bugs at a useful *rate* is unknown.** Five
attempts is not a rate. Nothing here publishes a success figure; your instance computes yours, on your
repository, and `hullwork status` prints it.

**Nobody who did not write Hullwork has read one of its artefacts and said whether they would merge it
from the evidence alone.** That is the observation this project considers the one that matters, and it
is waiting for a reader who is not us. If you would like to be that reader, the evidence trail is what
`hullwork try` writes and it needs no forge account.

**No third-party security review has been done.** [`SECURITY.md`](../SECURITY.md) states the threat
model and what it does not cover.

## Where the numbers on this page come from

Nothing here is estimated. Attempt counts come from the instance's own database, defect counts from
the evaluations' own reports, and the cost figures in the deployment notes from a provider's billing
rather than from Hullwork's own accounting — which, against an endpoint whose stream does not report
usage, says `null` rather than guessing. A figure this project cannot measure is absent, not rounded.
