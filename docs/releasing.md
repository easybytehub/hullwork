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
| `edge` and `sha-<commit>` | nightly, or on request (`gh workflow run edge`) | nobody decides |
| `v0.1.0aN` | a tag, deliberately | a person |
| `latest` | only a plain `N.N.N`, and there is not one yet | nobody, for now |

The branch rules are a **ruleset** on `main`: a pull request is required, the `gates` and `dco` checks
must pass, force pushes are blocked, deletion is blocked, history stays linear, and there are no bypass
actors — including the maintainer. Release tags (`v*`) cannot be deleted, updated or force-moved
either, because a moved tag makes every provenance statement about it a lie.

[OpenSSF Scorecard](https://github.com/ossf/scorecard/blob/main/docs/checks.md) scores that
**Branch-Protection 4/10**, and the reason is worth stating rather than rounding up: its tiers are
cumulative, tier 2 wants a required reviewer, and we do not require one. So 4 is the ceiling of that
choice — not a gap to close by configuration.

**Approvals are not required, and pretending otherwise would be worse.** Tier 2 wants one reviewer;
there are two people here, one of them has no hours, and GitHub does not let a pull request's author
approve it — so a required approval would be either a permanent block or a rule satisfied by clicking
bypass, which is worse than a rule that says what it does. What
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

`edge` is the fix: `ghcr.io/easybytehub/hullwork:edge` and `:sha-<commit>`, built with the same extras
and the same destination as a release. Measuring against the real artefact costs a workflow run instead
of a version:

```bash
gh workflow run edge --repo easybytehub/hullwork
```

**Nightly and on request, not per commit** — the first version built on every push, and six
multi-architecture pushes in one afternoon tripped GitHub's secondary rate limit hard enough to fail a
release mid-publish. The capability wanted was never "an image per commit".

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

## What the tool says, not what we say

The score is computed weekly by
[Scorecard](https://github.com/ossf/scorecard/blob/main/docs/checks.md) itself and published, so it can
be looked up rather than believed. When it last ran: **6.3/10**.

Ten out of ten, unprompted: SAST, Dangerous-Workflow, Vulnerabilities, Packaging, Binary-Artifacts,
Dependency-Update-Tool, CI-Tests, Security-Policy, Token-Permissions.

The low ones, with the reason each stays low:

| | why |
|---|---|
| Branch-Protection 4 | no required reviewer, deliberately — see above |
| Code-Review 0 | the same choice, counted from the other side |
| Signed-Releases 0 | fixed and unproven: the check reads existing releases, none of which carries the bundle yet |
| Pinned-Dependencies 6 | the application install is not hash-pinned; `uv.lock` does not reproduce a green suite yet |
| Maintained 0 | the repository is younger than ninety days |
| License 9 | source-available rather than OSI-approved |
| Fuzzing 0 · Contributors 3 · CII-Best-Practices 0 | none of them is bought with configuration |

## What a release produces

* a wheel, attached to the GitHub release;
* a multi-architecture image (`linux/amd64`, `linux/arm64`) at `ghcr.io/easybytehub/hullwork:<version>`;
* **build provenance for both**, signed by GitHub through OIDC rather than by a key of ours.

Verify either one without trusting us:

```bash
gh attestation verify oci://ghcr.io/easybytehub/hullwork:<version> -R easybytehub/hullwork
gh attestation verify hullwork-<version>-py3-none-any.whl         -R easybytehub/hullwork
```

**From the next release onwards.** `0.1.0a1` through `a4` were published before any of this existed
and carry no provenance; saying otherwise would be the exact kind of claim these rules are here to
stop. Scorecard's Signed-Releases still reads 0/10 for that reason, and will move on its own.

What that proves is *which commit, which workflow and which runner produced this artefact*. It does
not prove the artefact is good — that is what the gates and `docs/status.md` are for.

## Cutting one

```bash
./scripts/publish.sh                     # build the public tree and read the diff
./scripts/publish.sh --pr MESSAGE_FILE   # gate it, then open the pull request
gh pr merge <branch> --squash --delete-branch    # once the checks are green
git tag -a v0.1.0aN -m "…"               # here, for the record; the annotation is the notes
#   then create the same tag ON THE PUBLIC REPO, pointing at its own main — see the warning below.
#   Pushing this tag to the public remote publishes the private history it points at.
```

> [!warning] **The tag goes on the public commit, and `git push <mirror> vX` does not do that.**
> Measured on 2026-08-07, cutting `0.1.0a7`: the tag was created in the development checkout — where it
> points at a **private** commit — and pushed to the public remote. Git pushed the objects the tag
> needed, so for about ten minutes the withheld paths were browsable at that ref: `work/` (41 files)
> and `deploy/` (the deployment's compose and the relay). No credential was in them — `deploy.env` is
> not tracked — but the tailnet address, the port, the host's name and the private forge's hostname
> were, which is exactly the set `publish.sh` guards.
>
> Two things made it worse before they made it better. The tag ruleset **refused the deletion**, which
> is the rule doing its job and meant disabling it for the length of one API call. And the tag push
> started **two** release runs: one building from the private commit, which would have published an
> image with those paths inside it. It was cancelled at 40 seconds; the derived one produced the
> release.
>
> So: after the pull request merges, create the tag **on the public repository, pointing at its own
> `main`** — not in this checkout. The four earlier tags were cut that way and none of them exposes
> anything.
>
> ```bash
> head=$(gh api repos/<owner>/<repo>/commits/main --jq .sha)
> obj=$(gh api -X POST repos/<owner>/<repo>/git/tags \
>   -f tag=v0.1.0aN -f message="…" -f object="$head" -f type=commit --jq .sha)
> gh api -X POST repos/<owner>/<repo>/git/refs -f ref=refs/tags/v0.1.0aN -f sha="$obj"
> ```
>
> The tag in the development repository is still worth having — it is where the release was cut from —
> and it must never be pushed to the public remote.

The workflow refuses a tag whose version disagrees with `hullwork.__version__`, before it pushes
anything — a release whose image says one version and whose wheel says another is unusable for
anybody pinning either, and the bug report arrives months later from somebody who cannot reproduce it.

**Then, once the image is public**, and in this order, because each step needs the one before it:

```bash
./scripts/record-the-published-surface.py    # asks the new image what it accepts
# move the pins: README.md, docker-compose.yml, docs/install.md, PRIVACY.md
```

That is what lets the documentation describe the new release — including anything held back for it,
per [CONTRIBUTING](../CONTRIBUTING.md#documentation-describes-the-released-artefact-not-this-checkout).
Skipping either half is not quiet: re-record without moving the pins and the pins disagree with the
recording; move the pins without re-recording and they disagree the other way. Both fail
`tests/test_the_documentation_describes_the_published_artefact.py`, which is the whole point of
storing the recording rather than trusting the sequence.

## The private forge

Development happens on a Forgejo instance, and this repository is a **derivation** of it: the publish
script exports the tree, withholds what is not published, and delinks the references. That history has
one commit per piece of work and no pull requests, because it is a work log with one author and the
same three gates run before every commit.

The rules on this page are about what becomes **public**, which is the step where a mistake is
permanent and where one has already happened.
