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

import json
import logging
import os
import re
import shutil
from collections.abc import Callable, Iterable, Mapping, MutableMapping, Sequence
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TextIO

import sqlalchemy as sa
from sqlalchemy.orm import Session

from hullwork import bump, dependencies, evidence, resolve
from hullwork import dispatch as dispatch_module
from hullwork.config import Settings
from hullwork.forge import BranchExistsError, ForgeError
from hullwork.manifest import Manifest
from hullwork.osv import Advisory

log = logging.getLogger(__name__)

#: How long an opened pull request goes unasked about. The report's own clock (item 253), and the
#: same number `recurrence.RECHECK_SECONDS` uses for the identical question about an item.
RECHECK_SECONDS = 6 * 60 * 60

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


def verify_one(
    checkout: Path,
    paths: Sequence[str],
    read: Callable[[str], str | None],
    manifest: Manifest,
    dep: dependencies.Dependency,
    versions: list[str],
    out: TextIO,
) -> bump.Report | None:
    """One package, every candidate, each in its own sandbox.

    **Moved here from the CLI by item 233**, unchanged, because the dispatcher needs the same
    function and a private name in `cli` is a function only one caller can have. It takes a
    checkout and returns a report; it prints progress to a stream and knows nothing about who
    asked — which is what makes it callable from a loop as well as from a terminal.
    """
    from hullwork import trial
    from hullwork.sandbox import image as image_module
    from hullwork.sandbox.run import Sandbox

    runtime = manifest.runtime
    assert runtime is not None  # noqa: S101 - refused above, and mypy cannot see that
    tests = manifest.tests or ""
    source = dep.source

    # Which candidate `verify` is on, so a resolver-backed mover knows what to ask for.
    _pending: dict[str, str] = {"version": ""}

    with ExitStack() as stack:
        worktree = dispatch_module.prepare_worktree(checkout)
        stack.callback(shutil.rmtree, worktree, ignore_errors=True)

        def files_now() -> dict[str, bytes]:
            """The declared dependency files as they are in the worktree right now.

            Read per build rather than once: the rewrite happens between the two, and the second
            build has to see it — `image.dependency_digest` then makes the tag differ by itself,
            which is what turns the second build into a real rebuild.
            """
            found: dict[str, bytes] = {}
            for path in runtime.dependencies or [source]:
                whole = worktree / path
                if whole.exists():
                    found[path] = whole.read_bytes()
            return found

        built: dict[str, str] = {}
        leaves_behind: set[str] = set()
        stack.callback(lambda: _drop_images(leaves_behind))
        # **The commit the source is at, when the source goes into the build at all** (item 182).
        # Read once: it is what `image_tag` hashes to decide whether an image can be reused, and the
        # source does not move between candidates — only the dependency files do, and those are
        # hashed separately by `dependency_digest`.
        source_ref = trial.head_sha(checkout) if runtime.install_needs_source else None

        def build_now() -> str | None:
            try:
                image = image_module.build(
                    runtime, files_now(), None,
                    # **Item 113's fix, which this path never inherited** (found by item 182, on
                    # the first third-party tree it was pointed at). The build context holds the
                    # declared dependency files and never the source, and three ordinary installers
                    # read the source anyway: a `requirements.txt` beginning `-e .`, a `Gemfile`
                    # that says `gemspec`, and `mvn test`. Measured on `encode/httpx`, whose first
                    # requirement is `-e .[brotli,cli,http2,socks,zstd]`:
                    #
                    #   ERROR: file:///work does not appear to be a Python project:
                    #          neither 'setup.py' nor 'pyproject.toml' found.
                    #
                    # Reported as *your own environment does not build*, which was true of what we
                    # built and false of the project. Ruby, Java and PHP are on the roadmap as
                    # stacks whose attempts work; every one of them reaches this the same way.
                    source=worktree if runtime.install_needs_source else None,
                    source_ref=source_ref,
                )
            except image_module.ImageBuildError as failed:
                return str(failed)
            built["tag"] = image.tag
            # **Every image this verification builds, so every one of them can go** (item 241).
            # A candidate's image is not a cache: the lock it was built from exists for one run,
            # and the next candidate rewrites that lock and builds another. Measured on atlas —
            # seven of them, 1.09GB each, one every six minutes, on a disk that then had 211MB.
            leaves_behind.add(image.tag)
            return None

        # The baseline image, before anything is rewritten. A failure here is the project's
        # environment, not the upgrade's, so it is said as that.
        problem = build_now()
        if problem is not None:
            print(f"  {dep.name}: your own environment does not build — {problem}\n", file=out)
            return None

        made = {"n": 0}

        def make_box(_version: str) -> bump.Box:
            """A box on **whatever image `built` holds right now**.

            Called once per run rather than once per candidate, because the second run has to
            happen on the rebuilt image — reusing the first box measures the upgraded project's
            suite against the environment it replaced, and reports `clean` for a version that was
            never installed. Found by a real Docker run; see item 174.
            """
            made["n"] += 1
            # Built from the worktree **as it is now**, which is what makes each run happen in the
            # environment its own tree describes. Cheap when nothing changed: the digest is the
            # content, so `build` reuses the existing image rather than making another.
            build_now()
            # **The services the manifest declared** (item 238). `work.py` has passed these since
            # item 052 and this path never did, so a project with a database reached
            # `localhost:5432`, found nothing, and was reported `already-red` — the honest sentence
            # about the wrong thing: the suite was not failing, it was never given what it asked
            # for. Every project with a database, for ever, with no way for the report to say
            # anything else.
            box = Sandbox(
                image=built["tag"], worktree=worktree, services=list(runtime.services)
            )
            stack.callback(box.cleanup)
            box.ensure_volume(
                f"hullwork-deps-{os.getpid()}-{made['n']}",
                # **Item 114's fix, which this path never inherited either** (item 182). Anything
                # the build installed under `/work` is erased by the worktree volume unless the
                # image goes down first — which is what `vendor/` is for PHP, and the reason that
                # item exists. Off unless the project asks, so every other project takes the path
                # it took yesterday.
                seed_from_image=runtime.install_needs_source,
            )
            return box  # type: ignore[return-value]

        # How this file is moved, and everything moving it can touch (items 175 and 176). For a
        # list the line is the pin; for a resolved graph only the ecosystem's own tool may move it,
        # and `touches` is what stops one candidate leaving a widened range behind for the next.
        resolver = resolve.resolver_for(source)
        mover = None
        guarded: tuple[str, ...] = (source,)
        if resolver is not None:
            guarded = files_touched_by(resolver, source)
            here = [p for p in paths if p.rsplit("/", 1)[-1] in set(resolver.needs)]
            mover = mover_for(resolver, source, dep.name, _pending, here)

        report = bump.verify(
            tests=tests, source=source, package=dep.name,
            was=dep.version, versions=versions,
            make_box=make_box, rebuild=lambda _text: build_now(),
            mover=mover, touches=guarded, pending=_pending,
        )

    for answer in report.answers:
        print(f"  {answer.says}", file=out)
        if answer.detail:
            for line in answer.detail.splitlines()[:8]:
                print(f"      {line}", file=out)
    print("", file=out)
    return report


def files_touched_by(resolver: resolve.Resolver, source: str) -> tuple[str, ...]:
    """Every file this resolver may rewrite, **where the repository actually keeps them**.

    Item 239: `touches` names them relative to the lock, and on a monorepo the lock is not at the
    root — so a guard listing `pyproject.toml` protected a file that does not exist while
    `backend/pyproject.toml` was rewritten unwatched.
    """
    at = resolve.beside(source)
    return tuple(f"{at}/{one}" if at else one for one in resolve.touches(resolver))


def mover_for(
    resolver: resolve.Resolver,
    source: str,
    package: str,
    pending: MutableMapping[str, str],
    present: Sequence[str],
) -> Callable[[Path], str | None]:
    """How this graph is moved, in the directory the finding says it lives in. Item 239.

    **A function rather than a closure inside `verify_one`**, because the one thing worth asserting
    about it — that it runs where the lock is — was three levels of nesting deep and therefore
    untested: `at` was wrong for every monorepo and the suite was green.

    `pending` is read at call time on purpose: `bump.verify` moves through candidates and the mover
    is built once.
    """
    at = resolve.beside(source)

    def move(worktree: Path) -> str | None:
        outcome = resolve.upgrade(
            resolver=resolver, worktree=worktree, package=package, version=pending["version"],
            present=present, run=resolve.in_a_container, at=at,
        )
        return None if outcome.ok else f"{outcome.outcome.value}: {outcome.detail}"

    return move


def _drop_images(tags: Iterable[str]) -> None:
    """Remove the images a verification built, and the environment cache each one owns. Item 241.

    **Never raises, and never reported as a failure.** A host that could not delete an image is a
    host with debris on it, which is worse than it was and is not a wrong verdict about somebody's
    upgrade — the same rule every teardown in `sandbox` follows.

    The environment cache is named from a digest of the tag (`Sandbox._env_cache`), and it is
    derived here rather than asked for because the sandbox that owned it is already gone by the
    time this runs. It is the one place in this repository that computes that name twice, and the
    test that covers it asserts they agree.
    """
    import hashlib

    from hullwork.sandbox.docker import run_docker

    for tag in tags:
        try:
            run_docker(["docker", "image", "rm", tag], timeout=120)
            digest = hashlib.sha256(tag.encode()).hexdigest()[:12]
            run_docker(["docker", "volume", "rm", "-f", f"hullwork-envcache-{digest}"], timeout=60)
        except Exception:  # this runs while a stack unwinds; see below
            # **Broad on purpose, and this is the one place it is right.** `run_docker` swallows
            # what Docker answers; it does not swallow the socket being gone. This is a
            # `stack.callback`, so anything raised here replaces whatever the verification was
            # already reporting — a disk that will not let go would arrive as a crash in place of
            # a verdict that had already been measured.
            log.warning("could not remove what a verification built", extra={"image": tag})


#: What the dispatcher may spend on this in one turn. **One**, because each is a clone, an image
#: build and a suite run — and a queue that empties itself as fast as it can is a queue nobody can
#: watch (DR-0026).
ONE_PER_TURN = 1


def forget_stale(
    session: Session, project_id: int, findings: Sequence[Mapping[str, Any]]
) -> int:
    """Drop the artefact of every verdict about a version this project no longer pins. Item 245.

    Called where a new report is written, which is the only event that can make one stale. Returns
    how many were forgotten.

    **Why the artefact cannot simply sit there.** A verdict about a version no longer pinned is
    already hidden from the page for being stale, so nothing would ever open it — but a repository
    that bumps a dependency by hand leaves that row behind for good, and the row is now carrying a
    lock file. The report is the event that knows, so the report is where the forgetting goes.

    **The request goes with it.** A pending *open this* whose artefact has just been dropped would
    reach the dispatcher with nothing to commit, and the honest state of that row is *never asked*
    rather than *asked and failed*: nobody asked for a pull request against a version this project
    stopped pinning.
    """
    from hullwork.models import UpgradeVerdict

    pinned = {
        (str(one.get("package") or ""), str(one.get("version") or "")) for one in findings
    }
    forgotten = 0
    carrying = (
        session.query(UpgradeVerdict)
        .filter(
            UpgradeVerdict.project_id == project_id,
            UpgradeVerdict.artefact.is_not(None),
        )
        .all()
    )
    for verdict in carrying:
        if (verdict.package, verdict.was) in pinned:
            continue
        verdict.artefact = None
        verdict.asked_to_open_at = None
        forgotten += 1
    if forgotten:
        log.info(
            "forgot what stale verdicts passed with",
            extra={"project_id": project_id, "verdicts": forgotten},
        )
    return forgotten


def open_requested(
    session: Session,
    code_forge: object | None,
    *,
    secrets: list[str] | None = None,
) -> str | None:
    """Open one pull request a person asked for, or `None`. Item 245, DR-0026's other half.

    **DR-0026 said this was a button and the button had nowhere to press.** The receiver renders the
    page and cannot open anything — it refuses to start holding a credential that can push, and that
    refusal is load-bearing (DR-0009, spec M2 §1) — so the page writes an intention on the verdict
    and this reads it, in the process that holds the code token and binds no socket.

    **One per turn, oldest first**, for the same reason `open_them` opens one per package: a click
    that produces thirty-one pull requests is not a convenience.

    **A missing credential is not the verdict's fault.** It leaves the request pending and says so,
    because spending somebody's request on a dispatcher that was misconfigured for an afternoon
    would make them press a button that can never work twice.
    """
    from hullwork.models import DependencyReport, UpgradeVerdict
    from hullwork.models import Project as ProjectRow

    asked = (
        session.query(UpgradeVerdict)
        .filter(
            UpgradeVerdict.asked_to_open_at.is_not(None),
            UpgradeVerdict.opened_where.is_(None),
            UpgradeVerdict.open_note.is_(None),
        )
        .order_by(UpgradeVerdict.asked_to_open_at)
        .first()
    )
    if asked is None:
        return None
    if code_forge is None:
        log.warning(
            "somebody asked for an upgrade to be opened and this process cannot push",
            extra={"package": asked.package, "to": asked.to},
        )
        return None

    project = session.get(ProjectRow, asked.project_id)
    if project is None:  # pragma: no cover - a foreign key says otherwise
        return None
    pair = f"{asked.package} {asked.was} → {asked.to}"

    def refuse(why: str) -> str:
        asked.open_note = why
        session.commit()
        log.info("did not open", extra={"package": asked.package, "why": why})
        return f"{project.slug}: {pair} was not opened — {why}"

    permitted = False
    if project.manifest:
        from hullwork.manifest import parse_manifest

        permitted = parse_manifest(json.dumps(project.manifest)).autofix.open_upgrades
    if not permitted:
        # **The manifest outranks the button, and this is where a race lands** (DR-0019). The page
        # does not offer the control without the permission, so arriving here means it was withdrawn
        # between the click and the turn — which is the project changing its mind, and it wins.
        return refuse(
            "this project has not permitted opening upgrades: set "
            "`autofix: {open_upgrades: true}` in its manifest"
        )

    report = session.get(DependencyReport, project.id)
    still_pinned = report is not None and any(
        one.get("package") == asked.package and one.get("version") == asked.was
        for one in (report.findings or [])
    )
    if not still_pinned:
        return refuse(
            f"{asked.package} {asked.was} is not what this project pins any more, so what was "
            f"verified is not what would be opened"
        )

    answer = answer_from(asked)
    if answer is None:
        return refuse(
            "the files this verdict passed with were not kept, so there is nothing to open"
        )
    if not asked.base_sha:
        return refuse(
            "the commit this verdict was verified at was not kept, so a branch has no root"
        )

    advisories: dict[str, Sequence[Advisory]] = {}
    if report is not None:
        for one in report.findings or []:
            if one.get("package") != asked.package:
                continue
            advisories[asked.package] = tuple(
                Advisory(
                    id=str(each.get("id") or ""),
                    summary=str(each.get("summary") or ""),
                    fixed=tuple(str(version) for version in (each.get("fixed") or [])),
                )
                for each in (one.get("advisories") or [])
            )

    where = _open_one(
        code_forge,
        repo=project.repo,
        answer=answer,
        advisories=tuple(advisories.get(asked.package, ())),
        base_sha=asked.base_sha,
        secrets=secrets,
    )
    if where is None:
        # Never silence (item 178's rule, one layer along): a request that produced nothing is
        # either already open from an earlier run or something the forge refused, and both are facts
        # the person who pressed the button needs to read without opening a log.
        return refuse("already open from an earlier run, or the forge refused it")

    asked.opened_where = where
    # **The artefact has done its job.** The pull request now holds those exact files, and keeping a
    # second copy in the database is the unbounded half of this feature's cost.
    asked.artefact = None
    session.commit()
    return f"{project.slug}: {pair} → {where}"


def watch_opened(
    session: Session, forge: object, *, now: datetime | None = None
) -> str | None:
    """Ask the forge what became of one opened pull request. Item 253.

    **`opened_where` was written once and never read back**, so the page said *a draft pull request
    is waiting for a person* about two that had been merged days before — and would have said it for
    ever about one somebody closed without merging, which displays their explicit "no" as work they
    still owe. Measured on the live instance on 14 August: two rows *already open*, both `merged` at
    the forge.

    **This is `recurrence._watch_one`, one noun along**, and item 138's split is the whole of it:
    *not merged* is two facts wearing one answer, and a pull request nobody has looked at is not a
    pull request somebody refused.

    One per turn, oldest unchecked first, and never while rendering — a forge request per render is
    what item 142 forbids. A forge that will not answer changes nothing: the row keeps saying what
    it last knew, because a verdict written for a bad afternoon is worse than a stale one.

    A read, so the read credential is enough; this asks about a pull request and writes nothing to
    any repository.
    """
    from hullwork.forge import ForgeError as ForgeFailure
    from hullwork.models import Project as ProjectRow
    from hullwork.models import UpgradeVerdict
    from hullwork.outcomes import rejection_reason

    moment = now or datetime.now(UTC)
    cutoff = moment - timedelta(seconds=RECHECK_SECONDS)
    watching = (
        session.query(UpgradeVerdict)
        .filter(
            UpgradeVerdict.opened_where.is_not(None),
            # Terminal states are never asked about again: merged is merged, and a person who closed
            # one has answered. This is where the watch stops costing requests (item 121's lesson).
            #
            # **The `IS NULL` half is not decoration.** `NULL NOT IN (…)` is `NULL` in SQL, which is
            # not true, so `notin_` alone excludes every row that has never been asked about — which
            # is every row that exists when this ships, and the only ones with anything to learn.
            # Written that way first; the watcher did nothing at all and said nothing about it.
            sa.or_(
                UpgradeVerdict.opened_state.is_(None),
                UpgradeVerdict.opened_state.notin_(("merged", "closed")),
            ),
            sa.or_(
                UpgradeVerdict.open_checked_at.is_(None),
                UpgradeVerdict.open_checked_at < cutoff,
            ),
        )
        .order_by(UpgradeVerdict.open_checked_at.is_not(None), UpgradeVerdict.open_checked_at)
        .first()
    )
    if watching is None or forge is None:
        return None
    number = _pull_request_number(str(watching.opened_where))
    project = session.get(ProjectRow, watching.project_id)
    if number is None or project is None:
        # Permanent, so it is recorded rather than retried: a stored reference with no number in it
        # cannot be asked about however many times this runs. `recurrence._settled`'s reasoning.
        watching.opened_state = "unreadable"
        watching.open_checked_at = moment
        session.commit()
        return None

    try:
        state = forge.merge_state(project.repo, number)  # type: ignore[attr-defined]
    except ForgeFailure as exc:
        log.warning(
            "the forge could not be asked about an opened upgrade", extra={"error": str(exc)}
        )
        return None

    watching.open_checked_at = moment
    pair = f"{watching.package} {watching.was} → {watching.to}"
    if state.merged:
        watching.opened_state = "merged"
        session.commit()
        return f"{project.slug}: {pair} was merged"
    if state.state == "closed":
        watching.opened_state = "closed"
        why = rejection_reason(state.labels)
        # **Never silence** (item 178). A reviewer who gave no reason is a fact about the review,
        # not a blank to fill in — `rejection_reason` answers `None` for exactly that and this says
        # so rather than inventing one.
        watching.open_note = (
            f"a person closed the pull request without merging — {why}"
            if why
            else "a person closed the pull request without merging, and gave no reason"
        )
        session.commit()
        return f"{project.slug}: {pair} was closed without merging"
    watching.opened_state = "open"
    session.commit()
    return None


def _pull_request_number(where: str) -> int | None:
    """The number out of a stored pull request URL, or `None` if there is not one in it."""
    found = re.search(r"(\d+)\s*$", where.strip().rstrip("/"))
    return int(found.group(1)) if found else None


def next_to_try(
    session: Session, project_id: int, findings: Sequence[Mapping[str, Any]]
) -> tuple[str, str, str] | None:
    """The oldest `(package, was, to)` this instance has no current verdict for, or `None`.

    **A verdict is about a pair of versions, not about a package.** `cryptography 48.0.1 → 49.0.0`
    and `48.0.1 → 50.0.0` are two questions with two answers, and OSV publishes both when an
    advisory was fixed on two release branches.
    """
    from hullwork.models import UpgradeVerdict

    for one in findings:
        was = str(one.get("version") or "")
        package = str(one.get("package") or "")
        advisories = one.get("advisories") or []
        for to in dict.fromkeys(
            str(version)
            for advisory in advisories
            for version in (advisory.get("fixed") or [])
        ):
            # **A published version older than the one you pin is not a fix you can take** (item
            # 243). OSV publishes one per release branch — `brace-expansion` is fixed in 1.1.18,
            # 2.1.4, 3.0.6 *and* 5.0.9 — and this tried every one of them against a project pinned
            # at 5.0.6, at five minutes each, to be told the resolver will not go backwards. On a
            # resolver that would accept it, taking it is a regression shipped as a security fix.
            #
            # `None` means neither version could be read as one, and then it is tried: OSV carries
            # `1.2.3.RELEASE` and `2024-11-01` among the ordinary ones, and a rule that guessed
            # would hide a real fix.
            if dependencies.newer(to, was) is False:
                continue
            already = (
                session.query(UpgradeVerdict)
                .filter(
                    UpgradeVerdict.project_id == project_id,
                    UpgradeVerdict.package == package,
                    UpgradeVerdict.was == was,
                    UpgradeVerdict.to == to,
                )
                .one_or_none()
            )
            if already is None:
                return package, was, to
    return None


def _its_baseline_was_red(session: Session, project_id: int, taken_at: datetime) -> bool:
    """Whether this project's own suite was failing the last time anything was tried. Item 234.

    **The baseline is a property of the project at a commit, not of the upgrade.** `simplecheck`'s
    suite cannot reach a database inside the sandbox, so item 233's first hour on atlas spent a
    clone, an image build and a suite run per pair to print *your suite was already failing* fifty
    times over. Measuring it once answers every question in that queue at the same time.

    The way back in is a **new report**, which this instance takes on its own clock every six hours:
    a repository that fixes its suite is picked up again without anybody typing anything, and one
    that does not costs four builds a day instead of one a minute.
    """
    from hullwork.models import UpgradeVerdict

    latest = (
        session.query(UpgradeVerdict)
        .filter(UpgradeVerdict.project_id == project_id)
        .order_by(UpgradeVerdict.tried_at.desc())
        .first()
    )
    if latest is None or latest.outcome != "already-red":
        return False
    tried_at = latest.tried_at
    if tried_at.tzinfo is None:
        tried_at = tried_at.replace(tzinfo=UTC)
    asked_at = taken_at if taken_at.tzinfo is not None else taken_at.replace(tzinfo=UTC)
    return tried_at >= asked_at


def verify_next(
    session: Session,
    settings: Settings,
    *,
    clone: Callable[..., Path],
    say: Callable[[str | None], None] = lambda _: None,
) -> str | None:
    """Try one published fix, in a clone, and keep what happened. DR-0026, item 233.

    **The read credential, not the code one.** A verification writes nothing to a repository — that
    is the whole of what DR-0026 decided — so it clones with the token that cannot push, and the
    property holds by construction rather than by care.

    One per turn, and only where a bug is not waiting: a production error outranks a dependency
    upgrade, and the loop calls this after `work.run` found nothing.
    """
    import io
    import tempfile

    from hullwork import trial
    from hullwork.manifest import parse_manifest
    from hullwork.models import DependencyReport, UpgradeVerdict
    from hullwork.models import Project as ProjectRow

    projects = (
        session.query(ProjectRow)
        .filter(ProjectRow.active.is_(True))
        .order_by(ProjectRow.id)
        .all()
    )
    for project in projects:
        report = session.get(DependencyReport, project.id)
        if report is None or not report.asked or not report.findings or not project.manifest:
            continue
        if _its_baseline_was_red(session, project.id, report.taken_at):
            continue
        chosen = next_to_try(session, project.id, report.findings)
        if chosen is None:
            continue
        package, was, to = chosen
        manifest = parse_manifest(json.dumps(project.manifest))
        if manifest.runtime is None or not manifest.tests:
            continue

        # **What it is doing, said as it happens** (item 242). Four to five minutes pass between
        # here and a verdict — a clone, an image build and the project's own suite run twice — and
        # the page called all of it *nothing in progress*.
        pair = f"{package} {was} → {to}"
        said = io.StringIO()
        with tempfile.TemporaryDirectory() as where:
            say(f"{project.slug}: cloning to try {pair}")
            worktree = clone(settings, project, Path(where))
            paths = [
                str(one.relative_to(worktree))
                for one in worktree.rglob("*")
                if one.is_file() and ".git/" not in str(one)
            ]
            found = [
                one
                for one in report.findings
                if one.get("package") == package and one.get("version") == was
            ]
            source = str(found[0].get("source")) if found else ""
            # **Bound, because `worktree` is a loop variable.** A closure over it would read
            # whichever project the loop was on when it ran, which is exactly the bug that is
            # invisible until there are two projects.
            def _read(path: str, tree: Path = worktree) -> str:
                return (tree / path).read_text(encoding="utf-8", errors="replace")

            say(f"{project.slug}: verifying {pair}")
            report_of = verify_one(
                worktree,
                paths,
                _read,
                manifest,
                dependencies.Dependency("PyPI", package, was, source),
                [to],
                said,
            )
            # **Read here or never**: the clone goes with the `with`, and this is the only commit a
            # pull request opened later may be rooted at. `head_sha` answers `working tree` for a
            # directory that is not a repository — impossible for a clone, and stored as *no sha*
            # rather than as that string, because a branch cannot be rooted at a sentence.
            verified_at: str | None = trial.head_sha(worktree)
            if verified_at == "working tree":  # pragma: no cover - a clone is always a repository
                verified_at = None

        # **A `Report` holds one answer per candidate**, and one candidate was asked for. No
        # answer at all is the build refusing before anything could be tried, which is
        # `will-not-install` — a different fact from the suite failing, and DR-0026 says so.
        answered = report_of.answers[0] if report_of is not None and report_of.answers else None
        outcome = answered.verdict.value if answered is not None else "will-not-install"
        session.merge(
            UpgradeVerdict(
                project_id=project.id,
                package=package,
                was=was,
                to=to,
                outcome=outcome,
                detail=(answered.detail if answered is not None else said.getvalue())[:4000],
                # **Kept only for a verdict somebody could act on** (item 245). A `breaks` has a
                # finding and nothing to open; an `already-red` has neither. Storing files for
                # those would be paying for a button that must never exist.
                artefact=keepable(answered) if answered is not None else None,
                base_sha=verified_at,
            )
        )
        session.commit()
        return f"{project.slug}: {package} {was} → {to} is {outcome}"
    return None


def keepable(answer: bump.Answer) -> dict[str, Any] | None:
    """What a clean verdict has to keep to be openable later, or `None`. Item 245.

    **Both halves or neither.** The files are what gets committed; the runs are the evidence the
    pull request body is mostly made of. Keeping the files alone would produce a pull request that
    is quietly thinner than the one `hullwork deps --open` produces from the same verdict, and two
    surfaces disagreeing about what was measured is the failure this repository keeps finding.

    **Text and not bytes**, because every dependency file a resolver writes is text, and a base64
    blob in a database is a thing nobody can read when they are trying to work out what a pull
    request would contain. A file that does not decode keeps **no** artefact rather than part of
    one: a commit missing a file it needed is worse than a button that is not there, and the
    verdict — which is the valuable half — stands either way.
    """
    if answer.verdict is not bump.Verdict.CLEAN or not answer.files:
        return None
    files: dict[str, str] = {}
    for path, blob in answer.files.items():
        try:
            files[path] = blob.decode("utf-8")
        except UnicodeDecodeError:
            log.warning(
                "keeping no artefact: a dependency file is not text",
                extra={"package": answer.package, "path": path},
            )
            return None
    runs = answer.runs
    return {
        "files": files,
        "runs": None
        if runs is None
        else {
            "command": runs.command,
            "before_exit": runs.before_exit,
            "after_exit": runs.after_exit,
            "before_summary": runs.before_summary,
            "after_summary": runs.after_summary,
        },
    }


def answer_from(verdict: object) -> bump.Answer | None:
    """Rebuild the answer a stored artefact describes, or `None` when it cannot be opened.

    **The inverse of `keepable`, and it refuses rather than improvises.** A row with no artefact, or
    one whose artefact has no files, is not an answer with something missing — it is a verdict that
    was never openable, and `_open_one` must never be reached with an empty file set: that would
    branch, commit nothing and open a pull request claiming an upgrade it does not contain.
    """
    kept = getattr(verdict, "artefact", None)
    if not isinstance(kept, Mapping):
        return None
    files = kept.get("files")
    if not isinstance(files, Mapping) or not files:
        return None
    said = kept.get("runs")
    return bump.Answer(
        verdict=bump.Verdict.CLEAN,
        package=str(getattr(verdict, "package", "")),
        was=str(getattr(verdict, "was", "")),
        to=str(getattr(verdict, "to", "")),
        detail=str(getattr(verdict, "detail", "") or ""),
        files={str(path): str(text).encode("utf-8") for path, text in files.items()},
        runs=None
        if not isinstance(said, Mapping)
        else bump.Runs(
            command=str(said.get("command") or ""),
            before_exit=int(said.get("before_exit") or 0),
            after_exit=int(said.get("after_exit") or 0),
            before_summary=str(said.get("before_summary") or ""),
            after_summary=str(said.get("after_summary") or ""),
        ),
    )
