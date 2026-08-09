# What works, what does not, and what nobody has shown

Pre-alpha. This page is the honest scope, kept apart from the README so it has room to be specific and
so nothing in it has to be shortened to keep an introduction readable. It changes weekly; the date on
each claim is part of the claim.

> **What all of this is the state of.** Hullwork verifies which of the things your tools claim are
> actually true, before a person is asked — [what Hullwork is](what-hullwork-is.md). Three signals,
> three oracles, one mechanism. This page was accurate about the halves and silent about what they
> were halves of, so here is the row that was missing (item 181, 2026-08-09):
>
> | signal | oracle | state |
> |---|---|---|
> | a production error | a test that fails first and passes after | **released**, and everything below describes it |
> | a dependency advisory | your own suite, run against the upgrade | **built and unreleased** — in no image you can pull |
> | a static finding | a test naming the hostile input | does not exist |
>
> The second row is work items 172–180. Its command is deliberately **not named here**: the guard on
> this repository's documentation refused the sentence that named it, and it was right to — a command
> a reader cannot run is an invitation to type it and be told it does not exist. What is actionable
> is the state, and the state is *not in an image you can pull*.
>
> This page will keep saying so until a release contains it: documentation describes the released
> artefact, not the working tree (`CONTRIBUTING.md`, and item 165 records the three times that rule
> was learnt the hard way).

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

- **Only the GlitchTip webhook route is enabled in a release.** Sentry's is **built and unreleased**
  as of 2026-08-09 (item 189): in the working tree it is authenticated by the token in the URL — the
  same credential GlitchTip has, checked the same way, because GlitchTip cannot sign at all. Its
  signature is deliberately not verified; that would need Sentry's client secret held in reversible
  form, which is a storage decision this project has not made.

  The image you can pull still answers `501` there, and this page will say so until a release
  carries it — the same rule as the dependency signal above, and for the same reason.
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
