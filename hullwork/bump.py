"""Does the upgrade survive the project's own suite. Item 173, DR-0016.

**The question nobody else answers.** Renovate opens the pull request; when the bump breaks the
suite it leaves the body where it fell. Item 172 says which pins have a published advisory. This
says what happens if you take the fix — and the oracle is not a test an agent wrote for the
occasion, it is the suite the project already has, which is the one authority in this system that
no model can flatter.

**No agent, no gateway, no model token.** There is nothing here for a model to do: rewriting
`jinja2==2.4.1` to `jinja2==2.10.1` is an edit, and the verdict comes from running commands. A
clean answer costs nothing but the two builds.

**Why this needs no change to the sandbox's isolation**, which is the property that would have made
it a bad idea. `image.dependency_digest` makes the tag the content, so changing a version *is* a
rebuild with no invalidation to remember; and `sandbox/image.py` puts the network in the build and
never in the phase. The upgraded package is therefore installed while there is a network, and the
suite still runs against nothing.

Shaped after `dispatch.dispatch()` deliberately: it is handed a box and a directory and gives back
a decision, so it is testable without Docker.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from hullwork import dependencies, resolve, testoutput
from hullwork.sandbox.run import RunResult

log = logging.getLogger(__name__)

#: How long one suite run may take. The same ceiling the dispatcher's gates use, for the same
#: reason: a gate that runs out of time says nothing about the upgrade.
GATE_TIMEOUT_SECONDS = 1800


class Verdict(StrEnum):
    """What running the project's own suite against the upgrade said."""

    #: The suite passed before and passes after. **Not** "this is safe" — see `says`.
    CLEAN = "clean"
    #: The finding. This upgrade breaks these tests.
    BREAKS = "breaks"
    #: The build failed, which is a different fact from the suite failing.
    WILL_NOT_INSTALL = "will-not-install"
    #: The suite was already failing, so no claim can be made either way.
    ALREADY_RED = "already-red"
    #: This file cannot be rewritten without producing something that will not install.
    CANNOT_REWRITE = "cannot-rewrite"
    #: The dependency could not be moved: the resolver failed, or the manifest forbids the version.
    CANNOT_MOVE = "cannot-move"


@dataclass(frozen=True)
class Runs:
    """The two suite runs a verdict rests on, in the runner's own words. Item 178.

    **Kept rather than recomputed**, because by the time anybody renders an artefact the containers
    are gone and the tree has been restored. Everything a reviewer checks is here: what was run,
    what it exited with twice, and the line the runner printed about itself.

    The summary lines are `testoutput.verdict_line`'s reading of captured output from an arbitrary
    command, so anything that renders them scrubs them first — which is `evidence`'s rule and the
    reason this carries the text rather than pre-formatting it.
    """

    command: str
    before_exit: int
    after_exit: int
    before_summary: str = ""
    after_summary: str = ""


@dataclass(frozen=True)
class Answer:
    """A verdict about one upgrade, and the evidence for it."""

    verdict: Verdict
    package: str
    was: str
    to: str
    detail: str = ""
    #: The dependency files **as the passing run saw them**, kept only for a clean verdict.
    #:
    #: This is what item 178 opens a pull request with, and carrying it is not an optimisation.
    #: `attempt` restores every file it moved, so working the diff out afterwards would mean running
    #: the resolver a second time — and a lock regenerated twice can differ: a version published in
    #: between, a different ordering, a registry that answered differently. Publishing files that
    #: are not the ones the suite passed against is the defect item 045 is named after, and this is
    #: the one place it could come back.
    files: dict[str, bytes] = field(default_factory=dict)
    #: What the two gates did, for the artefact. `None` for a verdict that never ran two.
    runs: Runs | None = None

    @property
    def says(self) -> str:
        """The claim in DR-0016's own words, which are deliberately narrower than they could be.

        *The suite passed before this change and passes after it* — never *this is safe* and never
        *this fixes the vulnerability*. A suite that never exercised the upgraded library says so
        by staying green, and a reader who knows that reads this correctly. Widening it here would
        be the defect item 171 removed: a claim that reads as more than it measured.
        """
        if self.verdict is Verdict.CLEAN:
            return (
                f"{self.package} {self.was} → {self.to}: your suite passed before this change and "
                f"passes after it. That is what was measured — not that the upgrade is safe, and "
                f"not that it fixes anything your suite does not exercise."
            )
        if self.verdict is Verdict.BREAKS:
            return f"{self.package} {self.was} → {self.to}: this upgrade breaks your suite."
        if self.verdict is Verdict.WILL_NOT_INSTALL:
            return f"{self.package} {self.was} → {self.to}: the environment could not be built."
        if self.verdict is Verdict.ALREADY_RED:
            return (
                "your suite does not pass on an untouched checkout, so nothing can be claimed "
                "about any upgrade. Nothing was rewritten."
            )
        if self.verdict is Verdict.CANNOT_MOVE:
            return f"{self.package} {self.was} → {self.to}: could not be moved. {self.detail}"
        return f"{self.package}: this file cannot be rewritten safely."


#: A `requirements.txt` pin, in five groups so the name can be compared on its own and the version
#: replaced without rebuilding the line: indent, **name**, extras-and-operator, version, tail.
#:
#: Extras, environment markers and comments survive because only the version group is replaced. A
#: line rebuilt from its parsed parts would quietly drop the marker, which changes what gets
#: installed on other platforms — a silent behaviour change from a cosmetic decision.
_PIN = re.compile(r"^(\s*)([A-Za-z0-9._-]+)((?:\s*\[[^\]]*\])?\s*==\s*)([^\s;#]+)(.*)$")


def _canonical(name: str) -> str:
    """PEP 503 normalisation, because two spellings of one package are one package.

    OSV answers with the canonical name and a requirements file may carry any of its spellings —
    `Jinja2`, `jinja_2`, `jinja.2` all name the same distribution. Comparing raw strings would
    refuse to rewrite a pin that is plainly there.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


#: Files whose version strings cannot be edited in place, and the reason, in the words the refusal
#: uses. **Not a "not yet"**: these files carry per-artefact hashes, so a hand-edited version string
#: describes an artefact the hash does not match. The install then fails on the checksum, or — worse
#: — succeeds against a stale cache and the suite runs against a version nobody chose.
#: Dependency files that are a **list**, where the line is the pin and rewriting it is the whole
#: edit. Everything not here is a resolved graph and needs its ecosystem's resolver.
#:
#: Stated as an allow-list rather than as a list of refusals, and a test is why: the refusals used
#: to name three lock files, so the day a reader learns `Cargo.lock` — which has no resolver — it
#: would have been edited by hand with nothing objecting. The safe answer has to be the default.
#:
#: **A predicate rather than a set of names since item 180**, and the reason is that widening the
#: reader without widening this produced a refusal that was *false*: `requirements/prod.txt` was
#: declined as *"a resolved graph rather than a list of versions"*, which is the opposite of what it
#: is. Every upgrade in every layout other than a root `requirements.txt` would have been refused,
#: with a wrong reason each time. `dependencies.is_requirements` is the one place that decides,
#: so a layout that becomes readable becomes editable in the same edit.
def editable_by_hand(source: str) -> bool:
    """Whether this file is a list of versions, where rewriting the line is the whole edit."""
    return dependencies.is_requirements(source)

#: Per-file reasons, for the ones where the generic sentence is not the useful one.
CANNOT_BE_EDITED: dict[str, str] = {
    "package-lock.json": "it carries `integrity` hashes per package",
    "uv.lock": "it carries a `sha256` per artefact",
    "poetry.lock": "it carries a `sha256` per artefact",
}


class CannotRewriteError(Exception):
    """The dependency file cannot be edited into a valid one. Names the file and the reason."""


def rewrite_pin(text: str, package: str, to: str) -> str:
    """`package==old` becomes `package==to`, and everything else on the line survives.

    Extras, environment markers and trailing comments are preserved because only the version group
    is replaced — `httpx[http2]==0.27.0 ; python_version >= "3.8"  # pinned` keeps all three.

    A `--hash=` line is refused for the same reason a lock file is: the hash describes the
    artefact that was pinned, and a version changed out from under it will not install.
    """
    wanted = _canonical(package)
    out: list[str] = []
    seen = False
    for line in text.splitlines(keepends=True):
        matched = _PIN.match(line.rstrip("\n"))
        if matched and _canonical(matched.group(2)) == wanted:
            if "--hash=" in line:
                msg = (
                    f"{package} is pinned with `--hash=`, and a hash describes the artefact that "
                    f"was pinned. Changing the version without recomputing it produces a "
                    f"requirements file that will not install."
                )
                raise CannotRewriteError(msg)
            ending = "\n" if line.endswith("\n") else ""
            indent, name, operator, _, tail = matched.groups()
            out.append(f"{indent}{name}{operator}{to}{tail}{ending}")
            seen = True
        else:
            out.append(line)
    if not seen:
        msg = f"no `{package}==…` line to rewrite"
        raise CannotRewriteError(msg)
    return "".join(out)


def can_rewrite(source: str) -> None:
    """Raise `CannotRewrite` when this file's versions must not be edited by hand.

    Called before anything runs, so a project whose only pins are in a lock file is told at once
    rather than after paying for a baseline build.
    """
    name = source.rsplit("/", 1)[-1]
    # A list of versions: the line *is* the pin, so rewriting it is the whole edit.
    if editable_by_hand(source):
        return
    # Anything else is a resolved graph, and only its own tool can move one (item 175).
    if resolve.resolver_for(source) is not None:
        return
    why = CANNOT_BE_EDITED.get(name, "it is a resolved graph rather than a list of versions")
    msg = (
        f"{source} cannot be rewritten here: {why}, so editing a version string by hand leaves a "
        f"file whose hashes describe the version that was there before. Upgrading it properly "
        f"means running that ecosystem's own tool, which this does not do yet — so it refuses "
        f"rather than producing a lock file that cannot install."
    )
    raise CannotRewriteError(msg)


class Box(Protocol):
    """What this needs from a sandbox, and nothing else.

    **Structural**, so the tests need no Docker and so this module never imports one — the same
    reason `dispatch` takes its box as an argument rather than building one.
    """

    worktree: Path

    def run(self, command: str, timeout: int = 0) -> RunResult:  # pragma: no cover - protocol
        ...


def attempt(
    make_box: Callable[[], Box],
    *,
    tests: str,
    source: str,
    package: str,
    was: str,
    to: str,
    rebuild: Callable[[str], str | None],
    mover: Callable[[Path], str | None] | None = None,
    touches: Sequence[str] | None = None,
) -> Answer:
    """Baseline, rewrite, rebuild, run again. The three phases of DR-0016.

    `rebuild` takes the rewritten file's text and returns `None` on success or the reason on
    failure. A parameter rather than an import because building an image is the caller's business:
    this function never learns that Docker exists, which is what makes it testable without it.

    **`make_box` is called twice, and that is the whole correctness of this function.** The second
    run has to happen in a box built from the *rebuilt* image; reusing the first one runs the
    upgraded project's suite against the environment it had before the upgrade, and reports `clean`
    for a version that was never installed. Taking a box rather than a factory is exactly that
    defect, and it survived nineteen unit tests before a real Docker run found it — a double has no
    image, so nothing in it could have noticed.
    """
    # Before the baseline is paid for: a file nothing can move is a fact on disk.
    if mover is None:
        can_rewrite(source)
    move = mover or editing(source, package, to)
    guarded = tuple(touches or (source,))

    # --- phase 0: is there a claim to make at all ------------------------------------------
    box = make_box()
    baseline = box.run(tests, GATE_TIMEOUT_SECONDS)
    if not baseline.ok:
        # Before anything is rewritten and before a second build is paid for. A suite that is
        # already red cannot support "passed before and passes after", and blaming the upgrade for
        # it would be the same error `dispatch` made until item 043.
        return Answer(
            Verdict.ALREADY_RED, package, was, to,
            detail=_tail(baseline.output),
        )

    # --- phase 1: move the dependency, however this file is moved -------------------------
    #
    # **Every file the move can touch is snapshotted, not just the one named.** Found by item 175's
    # gate: `npm install` rewrites `package.json` as well as the lock, and item 174 had already
    # shown what happens when a candidate leaves anything behind — the next candidate's baseline
    # describes the previous one, silently. Restoring only the lock would be that defect one file
    # over, invisible in exactly the same way.
    before = {
        name: (box.worktree / name).read_bytes()
        for name in guarded
        if (box.worktree / name).exists()
    }

    try:
        failed = move(box.worktree)
        if failed is not None:
            return Answer(Verdict.CANNOT_MOVE, package, was, to, detail=failed)

        # --- phase 2: rebuild — where the network is — and run the suite again -------------
        failure = rebuild((box.worktree / source).read_text(encoding="utf-8"))
        if failure is not None:
            return Answer(Verdict.WILL_NOT_INSTALL, package, was, to, detail=str(failure))

        # **A new box, on the image the rebuild just produced.** See the docstring: this line is
        # the difference between measuring the upgrade and measuring what it replaced.
        after = make_box().run(tests, GATE_TIMEOUT_SECONDS)
        # **Read inside the `try`, because the `finally` below puts the old versions back.** These
        # bytes are the whole of what item 178 opens a pull request with, and they only exist
        # between these two lines: after this function returns, the tree describes the version the
        # project had before, which is the opposite of what a reviewer would be asked to merge.
        moved = {
            name: (box.worktree / name).read_bytes()
            for name in guarded
            if after.ok and (box.worktree / name).exists()
        }
    finally:
        for name, content in before.items():
            (box.worktree / name).write_bytes(content)

    runs = Runs(
        command=tests,
        before_exit=baseline.exit_code,
        after_exit=after.exit_code,
        # `None` when the runner printed nothing this reader recognises, and an empty string is
        # the honest rendering of that: the exit codes beside it are the claim either way.
        before_summary=testoutput.verdict_line(baseline.output) or "",
        after_summary=testoutput.verdict_line(after.output) or "",
    )
    if after.ok:
        return Answer(Verdict.CLEAN, package, was, to, files=moved, runs=runs)
    return Answer(Verdict.BREAKS, package, was, to, detail=_tail(after.output), runs=runs)


def _tail(output: str, limit: int = 12) -> str:
    """The lines a runner uses to say what failed, or the tail when none are recognised.

    Deliberately the same shape as `dispatch.failing_lines` and deliberately not an import of it:
    that one is about an agent's attempt and carries its vocabulary. A tail is always better than
    the empty string, which is what a stricter matcher produces on an unknown runner.
    """
    marked = [
        line for line in output.splitlines()
        if line.startswith(("FAILED", "FAIL", "ERROR", "not ok", "  ✗", "✗"))
    ]
    chosen = marked[:limit] if marked else output.splitlines()[-limit:]
    more = len(marked) - limit if len(marked) > limit else 0
    text = "\n".join(chosen)
    return f"{text}\n… and {more} more" if more > 0 else text


def candidates(advisories: object) -> list[str]:
    """The fixed versions to try, in the order OSV gave them, without repeats.

    **This is item 172's deferred question, answered the way DR-0016 said it would be.** That item
    prints every published fixed version and chooses none, because choosing would mean comparing
    versions under two ecosystems' ordering rules. Here there is no need to compare: each is tried
    and the suite decides. Hullwork needs no ordering rule per ecosystem because it can execute.
    """
    seen: list[str] = []
    for advisory in advisories:  # type: ignore[attr-defined]
        for version in advisory.fixed:
            if version not in seen:
                seen.append(version)
    return seen


@dataclass(frozen=True)
class Report:
    """What trying every candidate for one package concluded."""

    package: str
    was: str
    answers: tuple[Answer, ...]

    @property
    def settled(self) -> Answer | None:
        """The first candidate whose suite stayed green, or `None` if none did."""
        return next((a for a in self.answers if a.verdict is Verdict.CLEAN), None)


def verify(
    *,
    tests: str,
    source: str,
    package: str,
    was: str,
    versions: Sequence[str],
    make_box: Callable[[str], Box],
    rebuild: Callable[[str], str | None],
    mover: Callable[[Path], str | None] | None = None,
    touches: Sequence[str] | None = None,
    pending: dict[str, str] | None = None,
) -> Report:
    """Try each candidate until one leaves the suite green. Item 174.

    **Stops at the first clean answer** rather than trying them all: the remaining candidates are
    higher versions of the same fix, and a project that upgrades further than it has to is a
    project taking a larger change than the advisory asked for.

    `make_box` and `rebuild` are parameters for the reason `attempt`'s box is: building images and
    starting containers is the caller's business, so this stays testable without Docker.
    """
    answers: list[Answer] = []
    for version in versions:
        # The mover is built once by the caller and asks for whichever candidate is current, so
        # this is where the two are kept in step.
        if pending is not None:
            pending["version"] = version
        answer = attempt(
            lambda version=version: make_box(version),  # type: ignore[misc]
            tests=tests, source=source,
            package=package, was=was, to=version, rebuild=rebuild,
            mover=mover, touches=touches,
        )
        answers.append(answer)
        # A red baseline is about the project, not the candidate: trying the next version would ask
        # the same broken suite the same question and get the same answer.
        if answer.verdict in (Verdict.CLEAN, Verdict.ALREADY_RED):
            break
    return Report(package, was, tuple(answers))


def editing(source: str, package: str, to: str) -> Callable[[Path], str | None]:
    """The mover for a file that is a list of versions: rewrite the line.

    Only `requirements.txt` reaches here — `can_rewrite` has already refused any lock file with no
    resolver, and the caller supplies a resolver-backed mover for the ones that have one.

    **Public since item 179**, which needs the same move outside a verdict: a refit has to put the
    upgrade into the tree the agent will work in, and a second implementation of *rewrite the pin*
    is a second thing that can come to disagree about what a requirements line means.
    """

    def move(worktree: Path) -> str | None:
        path = worktree / source
        try:
            path.write_text(rewrite_pin(path.read_text(encoding="utf-8"), package, to),
                            encoding="utf-8")
        except CannotRewriteError as refused:
            return str(refused)
        return None

    return move


class Needs(StrEnum):
    """What a verdict asks of a person, which is the only useful way to order them.

    **Not severity.** OSV publishes one and this does not read it yet, so ordering by it would be
    ordering by something unmeasured — the habit DR-0017 exists to break. This orders by what was
    actually established: whether a person has to do anything, and how much.
    """

    #: Your suite is red. Nothing else here can be decided until it is not.
    FIX_YOUR_SUITE = "fix your suite first"
    #: A fix exists, it breaks named tests, and somebody has to make the code fit.
    NEEDS_WORK = "needs work"
    #: Something is in the way of even trying — no fix published, a manifest that forbids it.
    BLOCKED = "blocked"
    #: Verified green. The only thing left is to take it.
    JUST_TAKE_IT = "ready to take"


#: Worst first: what stops everything, then what needs a person, then what is merely stuck, then
#: what needs nothing. A reader who stops after the first section has read the part that mattered.
_ORDER = (Needs.FIX_YOUR_SUITE, Needs.NEEDS_WORK, Needs.BLOCKED, Needs.JUST_TAKE_IT)


def needs_of(report: Report) -> Needs:
    """What this package asks of a person."""
    verdicts = [a.verdict for a in report.answers]
    if Verdict.ALREADY_RED in verdicts:
        return Needs.FIX_YOUR_SUITE
    if report.settled is not None:
        return Needs.JUST_TAKE_IT
    if Verdict.BREAKS in verdicts:
        return Needs.NEEDS_WORK
    return Needs.BLOCKED


def broke(report: Report) -> int:
    """How many tests the best candidate broke, or 0.

    Used to order within `NEEDS_WORK`, smallest first: the upgrade that breaks two tests is the one
    a person can close this afternoon, and putting the twelve-test one above it buries the
    achievable under the daunting.
    """
    counts = [
        len([line for line in a.detail.splitlines() if line.strip()])
        for a in report.answers
        if a.verdict is Verdict.BREAKS
    ]
    return min(counts) if counts else 0


def ranked(reports: Sequence[Report]) -> list[Report]:
    """The queue in the order a person should work it. DR-0018 step 2.

    **This is the answer to the complaint that Renovate cannot answer.** *"Here is every update,
    you decide"* is noise because nothing in it is ranked — and ranking requires knowing what each
    one does, which requires running them. That is the axis they cannot move.
    """
    return sorted(
        reports,
        key=lambda r: (_ORDER.index(needs_of(r)), broke(r), r.package),
    )


def summary(reports: Sequence[Report]) -> dict[Needs, int]:
    """How many fall in each bucket. The sentence that replaces forty undecided pull requests."""
    counted = dict.fromkeys(_ORDER, 0)
    for report in reports:
        counted[needs_of(report)] += 1
    return counted
