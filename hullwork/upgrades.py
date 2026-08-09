"""Open the ones that pass. Item 178, DR-0018 step 3.

This is where DR-0018's claim stops being a report and becomes the thing a reviewer receives:
*Renovate opens forty pull requests; we open the thirty-one that pass and tell you what to do with
the nine that do not.*

**What it may open, and what it may never.** Only reports whose `needs_of` is `ready to take`. Not
the ones that break, not the blocked ones, not the ones whose baseline was red. A pull request from
Hullwork means *this was run and it passed*, and the moment it can mean anything else the claim is
worth nothing — including the ones it makes correctly.

**One pull request per package, never a batch.** A grouped upgrade that breaks cannot be bisected by
the reviewer without undoing our work for us, and the verdict was computed per package anyway.

**Nothing is remembered between runs, and nothing needs to be.** There is no database on this path:
the branch name carries the package and both versions, so a second pass over an unchanged repository
asks the forge for a branch that already exists and is told so. That is the same answer
`work.publish` has relied on since item 048, and it is better than a table — a table can disagree
with the forge, and this cannot.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence

from hullwork import bump, evidence
from hullwork.forge import BranchExistsError, ForgeError
from hullwork.osv import Advisory

log = logging.getLogger(__name__)

#: Where these branches live. Namespaced under `hullwork/` like every other branch this product
#: creates, and under `deps/` beneath that so an operator can tell an upgrade from an agent's fix
#: without opening either.
BRANCH_PREFIX = "hullwork/deps"

#: Everything git refuses in a ref name, plus the characters that merely make one awkward to type.
#: `@scope/pkg` is an ordinary npm name and `/` inside it would invent a directory level, so it goes
#: too — the branch has to be readable and it has to be creatable, and neither is negotiable.
_NOT_IN_A_REF = re.compile(r"[^A-Za-z0-9._-]+")


def branch_for(package: str, was: str, to: str) -> str:
    """The branch this upgrade goes on, derived from the upgrade and nothing else.

    **Derived rather than allocated**, and that is what makes "nothing is opened twice" true without
    any state: the same upgrade names the same branch on every run, for ever, so the forge is the
    thing that remembers. An id from a counter would need a database, and a random suffix would open
    the same pull request every hour.

    Both versions are in it because the pair is the work: next month's upgrade of the same package
    is different work and gets its own branch.
    """
    slug = "-".join(_NOT_IN_A_REF.sub("-", part).strip("-.") for part in (package, was, to))
    # A ref may not end in `.lock` nor contain `..`, and a name built from three sanitised parts
    # cannot produce either — but it can produce a run of hyphens, which is legal and ugly.
    return f"{BRANCH_PREFIX}/{re.sub('-{2,}', '-', slug)}"


def eligible(reports: Sequence[bump.Report]) -> list[bump.Report]:
    """The reports that may be opened, which is one bucket of four.

    `needs_of` rather than a scan for a clean answer, for the reason item 179 found the hard way: a
    report can carry a `breaks` answer *and* a later clean one, and asking what the report **needs**
    is the only reading that puts that in the right bucket.

    **A clean answer with no files is refused rather than opened.** Those bytes are the diff, and
    without them there would be a body making a claim about an empty commit — what was tested and
    what is published have to be the same tree, which is what item 045 is named after. It can happen
    honestly: an `Answer` built by hand, an older recording replayed.
    """
    return [
        report
        for report in reports
        if bump.needs_of(report) is bump.Needs.JUST_TAKE_IT
        and report.settled is not None
        and report.settled.files
    ]


def title_for(answer: bump.Answer) -> str:
    """What the pull request is called. The upgrade, and that a suite was run — nothing else."""
    return f"deps: {answer.package} {answer.was} → {answer.to} (your suite passes)"


def commit_message_for(answer: bump.Answer, advisories: Sequence[Advisory]) -> str:
    """One commit, saying what moved and why, without repeating the body.

    No DCO sign-off trailer, ever. `CONTRIBUTING.md` makes the sign-off a human act performed at the
    merge gate, and that a machine *can* emit the trailer is exactly why it must not.
    """
    named = ", ".join(a.id for a in advisories)
    because = f"\n\nPublished against {answer.package} {answer.was}: {named}." if named else ""
    return (
        f"deps: {answer.package} {answer.was} → {answer.to}\n\n"
        f"This project's own test suite was run against this change in a sandbox and passed, "
        f"having also passed before it. That is what was measured — not that the upgrade is safe."
        f"{because}\n\n"
        f"Opened by Hullwork."
    )


def open_them(
    code_forge: object,
    *,
    repo: str,
    reports: Sequence[bump.Report],
    advisories: Mapping[str, Sequence[Advisory]],
    base_sha: str,
    permitted: bool,
    secrets: list[str] | None = None,
) -> list[str]:
    """Open one draft pull request per verified-green package. Returns where each one went.

    **`permitted` is required and has no default, which is the whole of DR-0019's guard.** It is the
    project's `autofix.open_upgrades`, and item 017's rule is why it is a parameter of this function
    rather than a check at the call site: *a guardrail that depends on every caller remembering it
    is not a guardrail.* This is the only function in the product that opens anything, so a caller
    who forgets gets a `TypeError` rather than an unguarded pull request in somebody's repository.

    **A failure on one does not cost the others.** A queue of five with one bad name has to be four
    pull requests rather than a traceback, which is the same rule `publish` follows one layer up:
    publishing is the last thing that happens and the only thing here that can fail after the
    verdict already exists.

    `code_forge` is a parameter and is never built here, for the reason every other boundary in this
    repository is: the credential belongs to whoever owns the process, and this module stays
    testable against a double.
    """
    if not permitted:
        # **A decision somebody made, not a failure.** Logged rather than raised: the verification
        # above is the valuable half and it already ran, so a refusal here ends the opening and
        # nothing else. The caller says so in words; this is the record.
        log.info(
            "not opening: the project has not permitted it",
            extra={"repo": repo, "eligible": len(eligible(reports))},
        )
        return []

    opened: list[str] = []
    for report in eligible(reports):
        answer = report.settled
        assert answer is not None  # noqa: S101 - `eligible` returns none without one
        where = _open_one(
            code_forge,
            repo=repo,
            answer=answer,
            advisories=tuple(advisories.get(answer.package, ())),
            base_sha=base_sha,
            secrets=secrets,
        )
        if where is not None:
            opened.append(where)
    return opened


def _open_one(
    code_forge: object,
    *,
    repo: str,
    answer: bump.Answer,
    advisories: Sequence[Advisory],
    base_sha: str,
    secrets: list[str] | None,
) -> str | None:
    """Branch, commit, draft pull request. `None` when there is nothing new to open."""
    from hullwork.work import _commit

    branch = branch_for(answer.package, answer.was, answer.to)
    try:
        # **Rooted at the sha the gates ran against**, never at whatever the default branch points
        # at now. The base can move freely while a verification runs, and the pull request still
        # contains precisely the tree the suite passed on.
        code_forge.create_branch(repo, branch, base_sha)  # type: ignore[attr-defined]
    except BranchExistsError:
        # The record of what was opened, kept by the forge rather than by us. A second pass over an
        # unchanged repository lands here for every package it already dealt with, which is the
        # whole of "nothing is opened twice".
        log.info("already opened", extra={"branch": branch, "package": answer.package})
        return None
    except ForgeError as exc:
        log.warning(
            "could not branch for an upgrade",
            extra={"branch": branch, "package": answer.package, "error": str(exc)},
        )
        return None

    try:
        _commit(
            code_forge, repo, branch,
            commit_message_for(answer, advisories),
            dict(answer.files),
            base_sha,
        )
        pull = code_forge.open_draft_pull_request(  # type: ignore[attr-defined]
            repo,
            head=branch,
            base=code_forge.default_branch(repo),  # type: ignore[attr-defined]
            title=title_for(answer),
            body=evidence.dependency_pull_request_body(answer, advisories, secrets=secrets),
        )
    except ForgeError as exc:
        # The branch exists and the pull request does not. Said rather than swallowed, because the
        # next run will find the branch taken and open nothing — so this line is the only place
        # anybody learns why that package never appeared.
        log.warning(
            "branched but could not open the pull request",
            extra={"branch": branch, "package": answer.package, "error": str(exc)},
        )
        return None

    if not pull.draft:
        # Forgejo derives draft from a title prefix an instance can reconfigure and no API exposes
        # (spec §5.1), so the response is read back rather than assumed. A merge-ready pull request
        # from a bot is the one artefact this product must never leave behind.
        log.error("the forge did not mark it a draft", extra={"pull": pull.ref})
    log.info("opened", extra={"package": answer.package, "to": answer.to, "pull": pull.ref})
    return str(pull.html_url)
