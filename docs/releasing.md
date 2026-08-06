# Releasing, and what lands how

Two rules, and everything below is the reasoning behind them.

1. **Nothing reaches `main` except through a pull request whose checks passed.**
2. **A version tag is a claim that a state is worth pinning.** If you need the published artefact in
   order to *measure* something, that is what `edge` is for.

## What lands, and how

| | mechanism | who |
|---|---|---|
| a change | pull request → `ruff`, `mypy`, `pytest` green → merge | opened and merged by the maintainer |
| the public tree | `scripts/publish.sh` opens the pull request; the diff is readable before it is public | same |
| `edge` and `sha-<commit>` | every commit on `main`, automatically | nobody decides |
| `v0.1.0aN` | a tag, deliberately | a person |
| `latest` | only a plain `N.N.N`, and there is not one yet | nobody, for now |

The branch rules are a **ruleset** on `main`: a pull request is required, the `gates` check must pass,
force pushes are blocked, deletion is blocked, history stays linear. That is
[OpenSSF Scorecard](https://github.com/ossf/scorecard/blob/main/docs/checks.md)'s Branch-Protection at
tier 3 of 5.

**Approvals are not required, and pretending otherwise would be worse.** Tier 4 wants a second
reviewer; there are two people here and one of them has no hours, so a required approval would be a
rule satisfied by clicking a bypass button — which is worse than a rule that says what it does. What
*is* enforced is that no change reaches `main` without a pull request and green gates, and that
nobody can rewrite history to hide one. When there is a second maintainer with time, the rule moves up
a tier and this paragraph gets deleted.

## Why `edge` exists

On **2026-08-06** this project cut four releases in nineteen hours: `0.1.0a1` at 16:22, `a2` at 23:13,
`a3` at 10:08, `a4` at 11:45. Not one of them was because there was something new to offer.

* `a1` shipped without its optional extras, so the reporting it documented was impossible in it.
* `a2` predated the module that does the reporting, so it could not report at all.
* `a3` had no destination baked in, so it reported nowhere.

Each fix was real. The problem is that the *measurement* required a published image — item 155's gate
says so in as many words — so proving each fix meant publishing another version. Four promises to
strangers to settle three questions of ours.

`edge` is the fix: every commit on `main` builds `ghcr.io/easybytehub/hullwork:edge` and
`:sha-<commit>`, with the same extras and the same destination as a release. Measuring against the
real artefact now costs a push instead of a version.

**Use `sha-<commit>` when writing a result down.** `edge` moves, so *"measured against edge"* stops
meaning anything the next time anybody pushes.

## What earns a version

A version tag is for a state somebody else might pin. In practice:

* a capability that is now reachable in the artefact, where it was not before;
* a defect that made a documented capability impossible — the reason `a2`, `a3` and `a4` were all
  legitimate individually;
* a change in what the software sends, stores or exposes, which is the class that needs a number
  people can refer to;
* nothing else. Not a documentation pass, not a refactor, not a test.

Pre-alpha versions are `0.1.0aN`. `latest` deliberately does not move for them: somebody typing
`docker pull …:latest` a year from now should not silently land on the first alpha ever published.

## What a release produces

* a wheel, attached to the GitHub release;
* a multi-architecture image (`linux/amd64`, `linux/arm64`) at `ghcr.io/easybytehub/hullwork:<version>`;
* **build provenance for both**, signed by GitHub through OIDC rather than by a key of ours.

Verify either one without trusting us:

```bash
gh attestation verify oci://ghcr.io/easybytehub/hullwork:0.1.0a4 -R easybytehub/hullwork
gh attestation verify hullwork-0.1.0a4-py3-none-any.whl        -R easybytehub/hullwork
```

What that proves is *which commit, which workflow and which runner produced this artefact*. It does
not prove the artefact is good — that is what the gates and `docs/status.md` are for.

## Cutting one

```bash
./scripts/publish.sh                 # build the public tree, open the pull request
# merge it once the gates are green
git tag -a v0.1.0aN -m "…"           # the annotation is the release notes
git push origin v0.1.0aN
```

The workflow refuses a tag whose version disagrees with `hullwork.__version__`, before it pushes
anything — a release whose image says one version and whose wheel says another is unusable for
anybody pinning either, and the bug report arrives months later from somebody who cannot reproduce it.

## The private forge

Development happens on a Forgejo instance, and this repository is a **derivation** of it: the publish
script exports the tree, withholds what is not published, and delinks the references. That history has
one commit per piece of work and no pull requests, because it is a work log with one author and the
same three gates run before every commit.

The rules on this page are about what becomes **public**, which is the step where a mistake is
permanent and where one has already happened.
