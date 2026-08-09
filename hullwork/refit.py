"""The fix for the ones that break. Item 179, DR-0018 step 4.

`deps --verify` ends with a queue, and the middle of it is the interesting part: *six break, tests
named*. Renovate leaves those where they fell; DR-0018 says this is the one item on its list nobody
else could ship. Making a broken upgrade fit is a refactor, it is what everybody postpones, and the
loop this repository already has applies to it without modification.

**Cheaper than it looks, because the expensive half is already paid for.** DR-0003's cost is *write
a test that reproduces the problem and show it failing first*, and item 174 produces exactly that as
a by-product of the verdict: the project's own tests, failing against the upgraded dependency, with
nobody having authored them for the occasion. No agent writes the oracle here, which is the property
`docs/what-hullwork-is.md` says every verdict rests on.

**What this module is and is not.** The sequence and its gates belong to `dispatch.refit`; the world
those run in belongs to `work._attempt`. What is here is the part neither of them should know: what
a breakage *is*, what the agent is told about it, and how the version is read back out of the tree
afterwards. Nothing here starts a container or touches a forge.
"""

from __future__ import annotations

import logging
import re
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from hullwork import bump, dependencies, resolve
from hullwork.manifest import Manifest
from hullwork.models import Item, ItemKind, ItemState, Lane, Project
from hullwork.normalise import derive_fingerprint
from hullwork.states import transition

if TYPE_CHECKING:  # `work` imports this module inside `_attempt`, so the runtime import is lazy
    from hullwork.config import Settings
    from hullwork.work import Outcome

log = logging.getLogger(__name__)


def _canonical(name: str) -> str:
    """PEP 503 again, and for the third time in this repository deliberately rather than shared.

    `bump` and `resolve` each carry one because each is about a different file's spellings. This one
    compares what OSV named against what a lock reader read back, and the two disagree the same way:
    `Jinja2`, `jinja_2` and `jinja.2` are one distribution. npm names pass through unchanged, since
    they contain none of the characters this collapses.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Upgrade:
    """One upgrade that broke a suite, and everything a refit needs to know about it.

    Frozen, and built once from the verdict rather than re-derived: the version this is about is
    the one the gates ran against, and a second derivation is a second chance to disagree with it.
    """

    package: str
    #: What the project pins today. Carried for the report, not for the run — nothing here ever
    #: puts it back, which is the whole point of the item.
    was: str
    #: What the upgrade moves to, and what the tree must still pin when the green gate passes.
    to: str
    #: The dependency file that pins it, as a path relative to the checkout.
    source: str
    #: Every file moving this dependency can rewrite — read-only to the fix phase. Item 175 measured
    #: that `npm install` rewrites `package.json` as well as the lock, so guarding only the file
    #: that pins would leave the range widened back with the pin looking untouched.
    guarded: tuple[str, ...]
    #: The tests that failed with the upgrade applied, in the runner's own words. This is the
    #: evidence, and it was written by the project rather than for the occasion.
    failing: str = ""
    #: The advisory that started this, when there is one. Empty is legal: an upgrade can be worth
    #: making fit without anything published against the version it replaces.
    advisory: str = ""
    url: str = ""

    @property
    def title(self) -> str:
        """What a person reads in a queue. The pair of versions, because that is the work."""
        return f"{self.package} {self.was} → {self.to} breaks this project's suite"

    @property
    def fingerprint(self) -> str:
        """The identity of this work: the package **and both versions**, never the package alone.

        A fingerprint over the name would make next month's upgrade of the same library a repeat of
        this one — `dedup` would increment a counter and no work would be created, which is the
        failure mode that is invisible because it looks like deduplication working.
        """
        return derive_fingerprint("deps", self.package, self.was, self.to, self.source)


def from_report(
    report: bump.Report,
    *,
    source: str,
    guarded: tuple[str, ...] = (),
    advisory: str = "",
    url: str = "",
) -> Upgrade | None:
    """The upgrade worth handing to an agent, or `None` when this report is not that.

    **Only `needs work` reaches here.** A clean verdict is item 178's to deliver and needs no
    agent; a red baseline is the project's own problem and nothing can be claimed against it; a
    blocked one has nothing to try. Filtering by `needs_of` rather than by scanning for a `breaks`
    answer is what keeps those three out — a report can carry a `breaks` answer *and* a later clean
    one, and that is a package to take rather than work to do.

    Among the candidates that broke, the one that broke **fewest** tests. Same reasoning as
    `bump.broke`'s ordering: the upgrade that breaks two tests is the one that can be closed this
    afternoon, and starting with the twelve-test one buries the achievable under the daunting.
    """
    if bump.needs_of(report) is not bump.Needs.NEEDS_WORK:
        return None
    broke = [a for a in report.answers if a.verdict is bump.Verdict.BREAKS]
    if not broke:  # pragma: no cover - `needs_of` returns NEEDS_WORK only when one exists
        return None
    chosen = min(broke, key=lambda a: (_failure_count(a.detail), a.to))
    return Upgrade(
        package=report.package,
        was=report.was,
        to=chosen.to,
        source=source,
        guarded=guarded or (source,),
        failing=chosen.detail,
        advisory=advisory,
        url=url,
    )


def _failure_count(detail: str) -> int:
    """How many tests a `breaks` answer named. Blank lines are not failures."""
    return len([line for line in detail.splitlines() if line.strip()])


def guarded_for(source: str) -> tuple[str, ...]:
    """Every file that moving this dependency can rewrite, asked of the resolver that owns it.

    Read from `resolve.touches` rather than listed here, so an ecosystem added there is guarded here
    without anybody remembering to. A file with no resolver is a list of versions and is the only
    file its own move touches.
    """
    resolver = resolve.resolver_for(source)
    return resolve.touches(resolver) if resolver is not None else (source,)


def version_now(upgrade: Upgrade, worktree: Path) -> str | None:
    """What this tree pins the package at **now**, read back after the gates have run.

    Item 172's readers rather than a fifth parser: they already know all four file shapes, they are
    the ones `deps` used to find this dependency in the first place, and a second reader is a second
    thing that can come to disagree about what a file says.

    `None` for a tree that no longer pins it at all — a deleted file, a removed line — which is a
    different fact from pinning the old version and is reported as one.
    """

    def read(path: str) -> str | None:
        try:
            return (worktree / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    wanted = _canonical(upgrade.package)
    for found in dependencies.read_lockfiles([upgrade.source], read):
        if _canonical(found.name) == wanted:
            return found.version
    return None


#: How much of the runner's output goes into the brief. Enough for the failures and their messages,
#: bounded because a suite that fails 300 tests must not become most of the prompt.
MAX_FAILING_CHARS = 3_000


def brief(upgrade: Upgrade) -> str:
    """What the agent is told. **Not `brief.build`**, and the difference is the honesty of it.

    That one answers *what Hullwork knows about this error* from the tracker and this instance's
    history, and for a refit every one of those fields is empty — there is no error, no fingerprint
    from a stranger, no occurrence count. A brief built from it would open by saying the full event
    was never fetched, which is true of a tracker nobody asked and misleading about work that has
    better evidence than any tracker produces.

    Nothing here is untrusted in the sense `brief.build` fences against: the package name and the
    versions came from a lock file and a vulnerability database, and the failing tests came from the
    project's own runner. The runner's output is still bounded, because a suite can print for as
    long as you let it.
    """
    failing = upgrade.failing.strip()[:MAX_FAILING_CHARS] or "(the runner named none)"
    lines = [
        "# What Hullwork knows about this upgrade",
        "",
        "This is context you cannot get by reading the repository: the upgrade below has already "
        "been applied to the checkout you are working in, and these are the tests it broke when "
        "Hullwork ran your own suite against it.",
        "",
        "## The upgrade",
        "",
        f"- Package: `{upgrade.package}`",
        f"- Pinned at: `{upgrade.was}`",
        f"- Applied here: `{upgrade.to}`",
        f"- Pinned by: `{upgrade.source}`",
    ]
    if upgrade.advisory:
        lines.append(f"- Advisory: {upgrade.advisory}{f' — {upgrade.url}' if upgrade.url else ''}")
    lines += [
        "",
        "## What it broke",
        "",
        "Your own tests, run by Hullwork with the upgrade applied and nothing else changed:",
        "",
        "```text",
        failing,
        "```",
        "",
        "## What you are being asked for",
        "",
        "Change this project's own source code so those tests pass with the new version. The whole "
        "suite has to pass, not only the ones named above.",
        "",
        "## What you must not do",
        "",
        f"**The dependency files are read-only.** {', '.join(upgrade.guarded)} — do not edit, "
        f"delete or replace any of them.",
        "",
        f"Putting `{upgrade.package}` back to `{upgrade.was}` would make the suite pass and is not "
        f"a fix: it is a revert, and it undoes the upgrade this work exists to make possible. "
        f"Hullwork restores those files before it runs the suite again and reads the version back "
        f"out of the tree afterwards, so a revert is reported as a revert rather than published as "
        f"a fix.",
        "",
        "If the upgrade genuinely cannot be made to work, change nothing and say so. That is a "
        "correct and useful answer, and it is a better one than a change that only looks like a "
        "fix.",
        "",
    ]
    return "\n".join(lines)


def prepare(
    checkout: Path, upgrade: Upgrade, *, present: Sequence[str], into: Path
) -> str | None:
    """A copy of the checkout with the upgrade already in it, or the reason there is not one.

    **The upgrade goes in before the attempt starts, not during it**, and that is what makes the
    first gate a red gate rather than a baseline. The agent then opens a tree where the new version
    is simply what the project pins, which is also the tree a reviewer will see.

    Applied by the same two paths `bump` uses and not by a third: the ecosystem's own resolver for a
    resolved graph (`resolve.upgrade`, which does not believe the tool's exit code either), and
    `bump.editing` for a file that is a list of versions. A refit that moved a dependency its own
    way would be a second opinion about what an upgrade is.

    **`.git` is not copied.** The agent gets history only if somebody chose to give it, and a
    worktree with a repository in it can grow a hook that runs on the host — `prepare_worktree`'s
    reasoning, and this directory is handed to the same machinery.
    """
    shutil.copytree(
        checkout, into, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git")
    )
    resolver = resolve.resolver_for(upgrade.source)
    if resolver is None:
        try:
            bump.can_rewrite(upgrade.source)
        except bump.CannotRewriteError as refused:
            return str(refused)
        return bump.editing(upgrade.source, upgrade.package, upgrade.to)(into)
    outcome = resolve.upgrade(
        resolver=resolver,
        worktree=into,
        package=upgrade.package,
        version=upgrade.to,
        present=present,
        run=resolve.in_a_container,
    )
    return None if outcome.ok else f"{outcome.outcome.value}: {outcome.detail}"


def stage(
    session: Session, manifest: Manifest, upgrade: Upgrade, *, repo: str
) -> tuple[Project, Item]:
    """Put one project and one item where the dispatcher reads them from. Item 179.

    Shaped after `trial.stage`, and it differs in one place on purpose: that one goes through
    `dedup.resolve` because a pasted stack trace has to be triaged, and the lane it lands in is the
    product working. **There is nothing to triage here.** Triage matches lane rules against an
    error's title and the code location that raised it, and this work has neither — the identity is
    a package and two versions, both known exactly, and the code that will be changed is not known
    until the agent has read the failures.

    So the lane is stated rather than derived, with the reason on the item where a person can
    disagree with it. Green, because what an agent is being asked to touch is the project's own
    source until its own suite passes again — the same territory `autofix` already covers — and
    because the operator asked for this upgrade by name.
    """
    project = session.query(Project).filter(Project.repo == repo).one_or_none()
    if project is None:
        project = Project(
            slug=repo.rsplit("/", 1)[-1],
            forge=manifest.git.provider,
            repo=repo,
            webhook_secret_hash="",  # nothing listens: a refit has no webhook to authenticate
            manifest=manifest.model_dump(mode="json"),
        )
        session.add(project)
        session.flush()

    item = Item(
        project_id=project.id,
        fingerprint=upgrade.fingerprint,
        title=upgrade.title,
        kind=ItemKind.OTHER,
        lane=Lane.GREEN,
        lane_reason=(
            "a dependency upgrade the operator named, whose failing tests are the project's own — "
            "there is no error to triage and no culprit to match a lane rule against, so the lane "
            "is stated here rather than derived"
        ),
        permalink=upgrade.url or None,
    )
    session.add(item)
    session.flush()
    # Through the state machine and never by assignment, which is item 042's single door. `new` is
    # where a row starts and `triaged` is what it has to pass through, even when — as here — the
    # triage was a decision rather than a match.
    transition(item, ItemState.TRIAGED)
    transition(item, ItemState.READY)
    session.flush()
    return project, item


class NotUpgradableError(Exception):
    """The upgrade could not be put into the tree, so no attempt was started. Item 179.

    Its own exception because nothing failed: a manifest whose range forbids the version, a lock
    file with no resolver, a registry that refused — each is a fact about the project, and the
    attempt was never begun, so nothing was consumed and nothing is owed. `resolve.upgrade`'s own
    refusals arrive here word for word rather than being summarised into "could not upgrade".
    """


def run(
    settings: Settings,
    checkout: Path,
    manifest: Manifest,
    upgrade: Upgrade,
    *,
    present: Sequence[str],
    into: Path,
    repo: str,
) -> Outcome:
    """One refit, end to end. Composes what exists; decides nothing new.

    Shaped after `trial.run` and for the same reason: an ephemeral database, no forge anywhere in
    the call path, and the artefact written to disk through `write_locally`. The forges are `None`
    and `_attempt` is handed a checkout, so nothing here can reach one — which is stronger than not
    configuring one, and it keeps this half of DR-0018 on the credential-free side of item 178.

    **What it does not remove is Docker and a model credential**, and saying so is part of the
    honesty. The claim is that a project's own suite failed with an upgrade applied and passes with
    a change, run in a sandbox, by a model whose identity was read off the wire. Faking either turns
    this into a demonstration of itself.
    """
    from hullwork import trial, work
    from hullwork.scrub import instance_secrets

    session = trial.ephemeral_session()
    project, item = stage(session, manifest, upgrade, repo=repo)

    # The sha of the tree the upgrade goes on top of, read **before** the copy: `prepare` leaves
    # `.git` behind, so afterwards there is nothing to ask. Everything the artefact claims is a
    # claim about one commit, and one that said `unknown` would be an artefact nobody could check.
    base = trial.head_sha(checkout)
    upgraded = Path(tempfile.mkdtemp(prefix="hullwork-refit-"))
    try:
        refused = prepare(checkout, upgrade, present=present, into=upgraded)
        if refused is not None:
            raise NotUpgradableError(refused)
        log.info(
            "refit starting",
            extra={"package": upgrade.package, "to": upgrade.to, "sha": base},
        )
        return work._attempt(
            session,
            settings,
            work.Eligible(item=item, project=project),
            code_forge=None,
            forge=None,
            credential=work._model_credential(settings),
            secrets=instance_secrets(settings),
            rehearse_into=into,
            local_checkout=work.Checkout(path=upgraded, sha=base),
            upgrade=upgrade,
        )
    finally:
        shutil.rmtree(upgraded, ignore_errors=True)
        session.close()
