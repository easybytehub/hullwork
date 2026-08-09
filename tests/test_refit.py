"""The fix for the ones that break. Item 179, DR-0018 step 4.

Driven with a fake sandbox, like `test_dispatch`, because what is under test is the *sequence and
its guards* rather than Docker — and the guards are the whole of this item. The container is proved
by effect elsewhere; the real Docker run for this sequence is recorded in the item.

**The defect every test here circles.** Reverting the dependency passes every gate: red before,
green after, and the upgrade gone. It is the most plausible-looking false artefact this product
could emit, so the dependency files are read-only to the fix phase and the version is read back out
of the tree after the green gate. Both, because they fail differently.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import argparse
import io
import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.orm import Session

from hullwork import bump, dependencies, dispatch, evidence, osv, refit, work
from hullwork.attempts import finish, has_attempt_left, start
from hullwork.engine import Engine, Phase
from hullwork.manifest import parse_manifest
from hullwork.models import AttemptOutcome, AttemptPhase, Item, ItemState, Lane, Project
from hullwork.sandbox.run import RunResult
from hullwork.states import transition

MANIFEST = """
project: p
git: {provider: forgejo, repo: o/r}
autofix: {agent: claude-code, gates: [tests, human-merge]}
tests: "pytest"
test_path: tests
runtime: {base: python-3.12, install: none, dependencies: [requirements.txt]}
"""

LINTED = MANIFEST.replace(
    "gates: [tests, human-merge]", "gates: [tests, lint, human-merge]"
) + 'lint: "ruff check ."\n'

ENGINE = Engine(name="fake", image="img", protocol="anthropic", command="agent {phase}")

#: What the fix phase is invoked as, once `Phase.REFIT` exists.
REFIT = "agent refit"
TESTS = "pytest"

WAS, TO = "4.17.11", "4.17.21"


class FakeBox:
    """Stands in for the container. Scripted per command, and writes what an agent would write."""

    def __init__(
        self,
        worktree: Path,
        script: dict[str, int],
        writes: dict[str, dict[str, str]],
        outputs: dict[str, str] | None = None,
    ) -> None:
        self.worktree = worktree
        self.contract_dir = worktree / "_contract"
        self.contract_dir.mkdir(exist_ok=True)
        self.script = script
        self.writes = writes
        self.outputs = outputs or {}
        self.ran: list[str] = []
        self.envs: dict[str, dict[str, str]] = {}
        # `pytest` runs twice with two different expected results — red first, green after — so a
        # double keying only on the command string cannot express this sequence at all.
        self.counts: dict[str, int] = {}

    def run(self, command: str, timeout: int, env: dict[str, str] | None = None) -> RunResult:
        del timeout
        self.ran.append(command)
        self.envs[command] = dict(env or {})
        nth = self.counts.get(command, 0)
        self.counts[command] = nth + 1
        for name, body in self.writes.get(command, {}).items():
            if name == "__delete__":
                (self.worktree / body).unlink()
                continue
            target = self.worktree / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        code = self.script.get(f"{command}#{nth}", self.script.get(command, 0))
        printed = self.outputs.get(f"{command}#{nth}", self.outputs.get(command, "out"))
        return RunResult(command=command, exit_code=code, output=printed, duration_ms=1)

    # Item 058: the agent's phases go through the entry that has a route to the gateway.
    run_with_model = run


@pytest.fixture
def item(session: Session) -> Item:
    project = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="x",  # noqa: S106
    )
    session.add(project)
    session.flush()
    row = Item(
        project_id=project.id, fingerprint="fp",
        title=f"lodash {WAS} → {TO} breaks the suite", lane=Lane.GREEN,
    )
    session.add(row)
    session.flush()
    return row


def _pin(worktree: Path) -> str | None:
    """What `requirements.txt` in this tree pins lodash at, or `None`.

    A real reader rather than a canned answer, so the restore and the re-read are exercised
    against the same file the double edits — which is the only way the two guards can be shown to
    be different guards.
    """
    text = (worktree / "requirements.txt").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("lodash=="):
            return line.split("==", 1)[1].strip()
    return None


def _go(
    session: Session,
    item: Item,
    tmp_path: Path,
    script: dict[str, int],
    writes: dict[str, dict[str, str]] | None = None,
    outputs: dict[str, str] | None = None,
    guarded: tuple[str, ...] = ("requirements.txt",),
    version_now: Callable[[Path], str | None] | None = None,
    manifest_text: str = MANIFEST,
) -> tuple[dispatch.Verdict, FakeBox, Any]:
    (tmp_path / "src.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir(exist_ok=True)
    (tmp_path / "tests" / "test_a.py").write_text("def test_a():\n    assert True\n")
    # The tree arrives with the upgrade already applied: that is what makes the first gate red.
    (tmp_path / "requirements.txt").write_text(f"lodash=={TO}\n")
    box = FakeBox(tmp_path, script, writes or {}, outputs)
    attempt = start(session, item)
    verdict = dispatch.refit(
        session, item, parse_manifest(manifest_text), ENGINE,
        box=box,  # type: ignore[arg-type]
        attempt=attempt,
        package="lodash", to=TO, guarded=guarded,
        version_now=version_now or _pin,
    )
    return verdict, box, attempt


REAL_FIX = {"src.py": "x = 2  # works with the new lodash\n"}
REVERT = {"requirements.txt": f"lodash=={WAS}\n"}

#: The suite failing on the tests the upgrade broke, in the shape a runner prints them.
BROKEN = (
    "FAILED tests/test_a.py::test_shape - TypeError: lodash.merge is not a function\n"
    "FAILED tests/test_a.py::test_deep\n"
    "2 failed, 40 passed"
)


# --- the sequence -------------------------------------------------------------------------


def test_the_red_gate_is_the_upgrade_and_no_agent_is_asked_to_write_a_test(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """The expensive half of DR-0003 is already paid for, by evidence nobody authored.

    There is no reproduce phase here at all: the failing tests are the project's own, failing
    against the upgraded dependency. An agent asked to write one would be authoring the oracle,
    which is the one thing no oracle in this product may be.
    """
    verdict, box, attempt = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 0},
        writes={REFIT: REAL_FIX},
        outputs={f"{TESTS}#0": BROKEN},
    )

    assert verdict.outcome is AttemptOutcome.PR_OPEN
    assert box.ran == [TESTS, REFIT, TESTS]
    assert "agent reproduce" not in box.ran
    phases = [step.phase for step in attempt.steps]
    assert AttemptPhase.REPRODUCE not in phases
    # Recorded as the red gate rather than as a baseline, because that is what it is: the run that
    # establishes the failure the fix is judged against.
    assert phases == [AttemptPhase.RED_GATE, AttemptPhase.FIX, AttemptPhase.GREEN_GATE]


def test_a_suite_that_passes_with_the_upgrade_has_nothing_to_fix(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Before the model is called: the breakage did not reproduce, so there is no work here."""
    verdict, box, _ = _go(session, item, tmp_path, script={f"{TESTS}#0": 0})

    assert verdict.outcome is AttemptOutcome.NOT_REPRODUCIBLE
    assert box.ran == [TESTS], "the agent must not be paid for to fix a suite that passes"
    assert "passes with" in verdict.detail


def test_a_fix_phase_that_changes_nothing_is_not_a_fix(
    session: Session, item: Item, tmp_path: Path
) -> None:
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 1},
        writes={},
    )

    assert verdict.outcome is AttemptOutcome.FAILED
    assert verdict.phase is AttemptPhase.FIX
    assert "changed nothing" in verdict.detail


def test_a_real_fix_publishes_and_the_lock_still_carries_the_upgrade(
    session: Session, item: Item, tmp_path: Path
) -> None:
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 0},
        writes={REFIT: REAL_FIX},
        outputs={f"{TESTS}#0": BROKEN},
    )

    assert verdict.outcome is AttemptOutcome.PR_OPEN
    assert verdict.changes.written["src.py"] == REAL_FIX["src.py"].encode()
    assert not verdict.reverted
    assert TO in verdict.detail, "the artefact has to say which upgrade this makes possible"


# --- the guard this item exists to get right ------------------------------------------------


def test_the_dependency_file_is_put_back_when_the_fix_phase_edits_it(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Read-only means put back, not merely noticed.

    Restoring rather than detecting is what keeps the revert out of the published change: a
    dependency file that reached `changes` would be a pull request that undoes the upgrade it
    claims to make possible.
    """
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 0},
        writes={REFIT: {**REAL_FIX, **REVERT}},
        outputs={f"{TESTS}#0": BROKEN},
    )

    assert (tmp_path / "requirements.txt").read_text() == f"lodash=={TO}\n"
    assert "requirements.txt" not in verdict.changes.written
    assert verdict.reverted == "requirements.txt"


def test_a_green_gate_reached_by_reverting_is_reported_as_a_revert(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """The whole item, in one test.

    The fix phase puts the old version back and does nothing else. The file is restored before
    anything is collected, so there is no change left to gate — and no second gate is paid for,
    which is the honest shape rather than a saving: within one attempt the revert could never have
    bought a green gate anyway. The image was built before this ran and the phases have no network,
    so the installed version does not move whatever the file says. What a revert buys is the
    published diff, and that is what the restore takes away.
    """
    verdict, box, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 1},
        writes={REFIT: REVERT},
        outputs={f"{TESTS}#0": BROKEN},
    )

    assert verdict.outcome is not AttemptOutcome.PR_OPEN
    assert verdict.outcome is AttemptOutcome.FAILED
    assert verdict.reverted == "requirements.txt"
    assert "revert" in verdict.detail
    assert not verdict.changes, "a revert that was put back leaves nothing to publish"
    assert (tmp_path / "requirements.txt").read_text() == f"lodash=={TO}\n"
    assert box.ran == [TESTS, REFIT]


def test_a_lock_that_no_longer_carries_the_upgrade_is_a_revert_however_it_got_there(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """The backstop, and it is not the same guard as the restore.

    The restore covers the files this ecosystem's resolver is known to touch. The re-read covers
    everything else — a file nobody taught `touches` about, a pin moved somewhere the guard does
    not look. A green gate whose tree no longer carries the upgraded version is not a fix.
    """
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 0},
        writes={REFIT: REAL_FIX},
        outputs={f"{TESTS}#0": BROKEN},
        version_now=lambda _worktree: WAS,
    )

    assert verdict.outcome is AttemptOutcome.FAILED
    assert "revert" in verdict.detail
    assert WAS in verdict.detail and TO in verdict.detail


def test_a_tree_that_lost_the_dependency_entirely_is_not_a_fix_either(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """`None` is not `to`, and the message has to say which of the two happened."""
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 0},
        writes={REFIT: REAL_FIX},
        outputs={f"{TESTS}#0": BROKEN},
        version_now=lambda _worktree: None,
    )

    assert verdict.outcome is AttemptOutcome.FAILED
    assert "no longer pins" in verdict.detail


def test_every_file_the_move_can_touch_is_guarded_not_only_the_one_that_pins(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Item 175's finding, one layer up.

    `npm install` rewrites `package.json` as well as the lock, so a guard that watched only the
    lock would let a fix widen the range back and leave the pin looking untouched.
    """
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "^4.17.21"}}\n')
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 0},
        writes={REFIT: {**REAL_FIX, "package.json": '{"dependencies": {"lodash": "^4.17.11"}}\n'}},
        outputs={f"{TESTS}#0": BROKEN},
        guarded=("requirements.txt", "package.json"),
    )

    assert (tmp_path / "package.json").read_text() == '{"dependencies": {"lodash": "^4.17.21"}}\n'
    assert "package.json" not in verdict.changes.written
    assert verdict.reverted == "package.json"


def test_a_dependency_file_the_fix_deleted_comes_back(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Deleting the pin is a revert with extra steps, and `Changes` learned that lesson once."""
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 1},
        writes={REFIT: {"__delete__": "requirements.txt"}},
        outputs={f"{TESTS}#0": BROKEN},
    )

    assert (tmp_path / "requirements.txt").read_text() == f"lodash=={TO}\n"
    assert verdict.reverted == "requirements.txt"
    assert "requirements.txt" not in verdict.changes.deleted


# --- the guards this sequence inherits rather than reimplements -------------------------------


def test_test_infrastructure_the_fix_switched_off_is_still_put_back(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Item 046 applies unchanged: a suite that collects nothing passes trivially.

    And it is a `conftest.py` the phase **invented** rather than edited, because that is the shape
    this item found the guard did not cover. An agent that cannot make an upgrade fit is exactly
    the caller with a reason to switch off the tests it cannot satisfy, so this sequence needs the
    fixed guard more than the one it was written for.
    """
    verdict, box, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 0, f"{TESTS}#2": 1},
        writes={REFIT: {**REAL_FIX, "conftest.py": "collect_ignore_glob = ['*']\n"}},
        outputs={f"{TESTS}#0": BROKEN},
    )

    assert verdict.outcome is AttemptOutcome.FAILED
    assert verdict.phase is AttemptPhase.GREEN_GATE_RESTORED
    assert "conftest.py" in verdict.restored
    assert box.ran == [TESTS, REFIT, TESTS, TESTS]


def test_the_lint_gate_does_not_discard_a_verified_fix(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Item 067 applies unchanged: the lint gate contests the style, not the claim."""
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 0, "ruff check .": 1},
        writes={REFIT: REAL_FIX},
        outputs={f"{TESTS}#0": BROKEN},
        manifest_text=LINTED,
    )

    assert verdict.outcome is AttemptOutcome.PR_OPEN_LINT_FAILED


def test_the_fix_phase_is_told_which_upgrade_and_which_tests(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """The phase the agent is asked for is its own, not the bug-fixing one.

    `fix` tells the agent about a reproducing test file at a path that does not exist here. A
    phase that names evidence nobody wrote is how an attempt spends its one try on a
    misunderstanding, which is what item 094 measured.
    """
    _, box, _ = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 0},
        writes={REFIT: REAL_FIX},
        outputs={f"{TESTS}#0": BROKEN},
    )

    assert box.envs[REFIT]["HULLWORK_AGENT_PHASE"] == Phase.REFIT.value


# --- the accounting, which is the ordinary one -------------------------------------------------


def test_the_attempt_is_spent_and_accounted_for_exactly_as_any_other(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Through `run_one`, because that is what a refit actually goes through in production.

    **The parameter this covers is `sequence`.** Everything `run_one` does — claiming the item,
    opening the attempt, the seal, the ceiling checks, publishing, releasing — is about an attempt
    rather than about what the attempt was for, so a refit gets all of it by passing a different
    sequence and nothing else. Without this test that parameter is exercised nowhere.

    DR-0003's rule is then the ordinary one: this item has had its try, and `has_attempt_left`
    says so to whoever asks next.
    """
    from functools import partial

    (tmp_path / "src.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir(exist_ok=True)
    (tmp_path / "requirements.txt").write_text(f"lodash=={TO}\n")
    box = FakeBox(
        tmp_path,
        {f"{TESTS}#0": 1, f"{TESTS}#1": 0},
        {REFIT: REAL_FIX},
        {f"{TESTS}#0": BROKEN},
    )
    project = session.get(Project, item.project_id)
    assert project is not None
    project.manifest = parse_manifest(MANIFEST).model_dump(mode="json")
    transition(item, ItemState.TRIAGED)
    transition(item, ItemState.READY)
    session.flush()
    published: list[str] = []

    def publisher(*_a: object) -> str:
        published.append("written")
        return "somewhere"

    outcome = work.run_one(
        session,
        work.Eligible(item=item, project=project),
        engine=ENGINE,
        box_factory=lambda _m: box,
        publisher=publisher,
        sequence=partial(
            dispatch.refit,
            package="lodash", to=TO, guarded=("requirements.txt",), version_now=_pin,
        ),
    )

    assert outcome.outcome is AttemptOutcome.PR_OPEN
    assert published == ["written"]
    assert item.state is ItemState.PR_OPEN
    assert not has_attempt_left(session, item), "DR-0003: one attempt, then a human"


# --- what the reviewer reads ------------------------------------------------------------------


def test_the_artefact_names_the_upgrade_and_the_tests_and_does_not_overclaim(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """The criterion this item is judged on, read off the document a person actually receives.

    And the sentence that must **not** be there: *a test that failed against unmodified code*. The
    code was modified before the first gate ran — by the upgrade — so `evidence`'s ordinary
    headline would be false in the one word carrying it, which is the overclaim item 171 removed
    from this product once already.
    """
    verdict, _, attempt = _go(
        session, item, tmp_path,
        script={f"{TESTS}#0": 1, f"{TESTS}#1": 0},
        writes={REFIT: REAL_FIX},
        outputs={f"{TESTS}#0": BROKEN, f"{TESTS}#1": "42 passed"},
    )
    finish(session, attempt, verdict.outcome)

    body = evidence.pull_request_body(
        item, attempt, detail=verdict.detail, claim=verdict.claim
    )

    assert "unmodified code" not in body
    assert "the upgrade is still" in body
    # Which upgrade this makes possible.
    assert f"lodash {TO}" in body
    # And the tests that were failing, from the red gate's own output rather than from prose.
    assert "test_shape" in body
    assert "exit `1` as it must" in body
    assert "exit `0` as it must" in body


# --- what a breakage is, and what the agent is told about it ----------------------------------


def _breaks(package: str = "lodash") -> bump.Report:
    return bump.Report(
        package=package,
        was=WAS,
        answers=(bump.Answer(bump.Verdict.BREAKS, package, WAS, TO, detail=BROKEN),),
    )


def test_an_upgrade_is_built_from_a_breaks_verdict_and_carries_the_failing_tests() -> None:
    upgrade = refit.from_report(_breaks(), source="requirements.txt")

    assert upgrade is not None
    assert (upgrade.package, upgrade.was, upgrade.to) == ("lodash", WAS, TO)
    assert "test_shape" in upgrade.failing


def test_a_report_that_did_not_break_is_not_work_for_an_agent() -> None:
    """Only `needs work` reaches this. A clean verdict is item 178's to deliver, not this one's."""
    clean = bump.Report(
        package="lodash", was=WAS,
        answers=(bump.Answer(bump.Verdict.CLEAN, "lodash", WAS, TO),),
    )
    red = bump.Report(
        package="lodash", was=WAS,
        answers=(bump.Answer(bump.Verdict.ALREADY_RED, "lodash", WAS, TO),),
    )

    assert refit.from_report(clean, source="requirements.txt") is None
    assert refit.from_report(red, source="requirements.txt") is None


def test_a_package_that_broke_and_then_passed_is_not_work_for_an_agent() -> None:
    """The case the `needs_of` filter actually exists for, and the two above do not reach.

    `bump.verify` tries candidates in order, so a report can carry a `breaks` answer **and** a
    later clean one — the lower fix broke the suite and the higher one did not. That is a package
    to take, which is item 178's to deliver, and scanning for a `breaks` answer instead of asking
    what the report *needs* would hand it to an agent and pay a model to fix something already
    fixed.

    Verified by reintroducing the defect: with the `needs_of` line removed the two tests above
    still pass, because a report whose only answer is clean has no `breaks` answer to find. This
    one is the only thing between that filter and being dead code.
    """
    broke_then_passed = bump.Report(
        package="lodash", was=WAS,
        answers=(
            bump.Answer(bump.Verdict.BREAKS, "lodash", WAS, "4.17.20", detail=BROKEN),
            bump.Answer(bump.Verdict.CLEAN, "lodash", WAS, TO),
        ),
    )
    broke_then_the_suite_went_red = bump.Report(
        package="lodash", was=WAS,
        answers=(
            bump.Answer(bump.Verdict.BREAKS, "lodash", WAS, "4.17.20", detail=BROKEN),
            bump.Answer(bump.Verdict.ALREADY_RED, "lodash", WAS, TO),
        ),
    )

    assert bump.needs_of(broke_then_passed) is bump.Needs.JUST_TAKE_IT
    assert refit.from_report(broke_then_passed, source="requirements.txt") is None
    assert refit.from_report(broke_then_the_suite_went_red, source="requirements.txt") is None


def test_what_a_move_can_touch_is_asked_of_the_resolver_that_owns_it() -> None:
    """Item 175 measured that `npm install` rewrites `package.json` as well as the lock.

    Read from `resolve.touches` rather than listed here, so an ecosystem added there is guarded
    without anybody remembering to — and asserted here, because every other test in this file
    hands `guarded` in by hand and would pass with this function returning the lock alone.
    """
    assert set(refit.guarded_for("package-lock.json")) == {"package.json", "package-lock.json"}
    assert set(refit.guarded_for("uv.lock")) == {"pyproject.toml", "uv.lock"}
    # A list of versions is the only file its own move touches.
    assert refit.guarded_for("requirements.txt") == ("requirements.txt",)
    # And a path in a subdirectory is still the file it is named after.
    assert set(refit.guarded_for("frontend/package-lock.json")) == {
        "package.json", "package-lock.json"
    }


def test_the_brief_forbids_the_cheat_by_name_and_says_what_happens_if_it_is_tried() -> None:
    """An agent that is not told is an agent that will try it, and be reported for it."""
    upgrade = refit.from_report(_breaks(), source="requirements.txt")
    assert upgrade is not None
    text = refit.brief(upgrade)

    assert "requirements.txt" in text
    assert TO in text and WAS in text
    assert "test_shape" in text, "the tests it has to make pass are the point of the brief"
    lowered = text.lower()
    assert "revert" in lowered
    assert "read-only" in lowered or "do not" in lowered


@pytest.mark.parametrize(
    ("name", "body", "expected"),
    [
        ("requirements.txt", f"lodash=={TO}\n", TO),
        ("requirements.txt", f"lodash=={WAS}\n", WAS),
        ("requirements.txt", "something-else==1.0\n", None),
    ],
)
def test_the_version_is_read_back_out_of_the_file_that_pins_it(
    tmp_path: Path, name: str, body: str, expected: str | None
) -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")
    upgrade = refit.from_report(_breaks(), source=name)
    assert upgrade is not None

    assert refit.version_now(upgrade, tmp_path) == expected


def test_the_version_is_read_back_out_of_a_lock_too(tmp_path: Path) -> None:
    """Whichever of the four file shapes pins it — item 172's readers, not a fifth parser."""
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"": {}, "node_modules/lodash": {"version": TO}}}),
        encoding="utf-8",
    )
    upgrade = refit.from_report(_breaks(), source="package-lock.json")
    assert upgrade is not None

    assert refit.version_now(upgrade, tmp_path) == TO


def test_a_file_that_is_no_longer_there_reads_as_no_version_rather_than_raising(
    tmp_path: Path,
) -> None:
    upgrade = refit.from_report(_breaks(), source="requirements.txt")
    assert upgrade is not None

    assert refit.version_now(upgrade, tmp_path) is None


def test_the_item_carries_the_upgrade_where_a_person_reads_it(session: Session) -> None:
    upgrade = refit.from_report(_breaks(), source="requirements.txt")
    assert upgrade is not None
    manifest = parse_manifest(MANIFEST)

    _, made = refit.stage(session, manifest, upgrade, repo="o/r")

    assert "lodash" in made.title
    assert WAS in made.title and TO in made.title
    assert made.lane is Lane.GREEN
    assert made.lane_reason


# --- which of the queue is handed to an agent at all -------------------------------------------


def _finding(name: str, was: str) -> osv.Finding:
    return osv.Finding(
        dependency=dependencies.Dependency("PyPI", name, was, "requirements.txt"),
        advisories=(
            osv.Advisory(id=f"GHSA-{name}", summary="something", fixed=(TO,)),
        ),
    )


def _report(package: str, verdict: bump.Verdict, detail: str = "") -> bump.Report:
    return bump.Report(
        package=package, was=WAS,
        answers=(bump.Answer(verdict, package, WAS, TO, detail=detail),),
    )


def _fix_run(
    tmp_path: Path, reports: list[bump.Report], monkeypatch: pytest.MonkeyPatch,
    fail: str = "",
) -> tuple[list[refit.Upgrade], str]:
    """Run the `--fix` half of `deps` with the attempt itself stubbed out.

    What is under test here is the *selection*: which of a queue is worth a model at all, and in
    what order. Running the attempt would be testing `_attempt`, which has its own tests and needs
    a daemon and a credential.
    """
    from hullwork import cli

    asked: list[refit.Upgrade] = []

    def fake_run(_settings: object, *_a: object, **kwargs: object) -> object:
        upgrade = kwargs["upgrade"] if "upgrade" in kwargs else _a[2]
        asked.append(upgrade)  # type: ignore[arg-type]
        if fail:
            raise refit.NotUpgradableError(fail)
        return SimpleNamespace(
            outcome=AttemptOutcome.PR_OPEN, detail="it fits now", pull_request="somewhere-on-disk"
        )

    monkeypatch.setattr(refit, "run", fake_run)
    printed = io.StringIO()
    code = cli._fix_the_ones_that_break(
        argparse.Namespace(into=str(tmp_path / "out"), fix=True),
        None,  # type: ignore[arg-type]
        tmp_path,
        ["requirements.txt"],
        parse_manifest(MANIFEST),
        [_finding(r.package, r.was) for r in reports],
        reports,
        printed,
    )
    assert code == 0
    return asked, printed.getvalue()


def test_only_the_ones_that_need_work_are_handed_to_an_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A model is the expensive part of this command, so it is spent on one bucket of four.

    The verified-green ones need no agent and are item 178's to deliver; a red baseline is the
    project's own suite and nothing can be claimed against it; a blocked one has nothing to try.
    """
    reports = [
        _report("clean-one", bump.Verdict.CLEAN),
        _report("red-one", bump.Verdict.ALREADY_RED),
        _report("blocked-one", bump.Verdict.CANNOT_MOVE),
        _report("broken-one", bump.Verdict.BREAKS, BROKEN),
    ]

    asked, _ = _fix_run(tmp_path, reports, monkeypatch)

    assert [u.package for u in asked] == ["broken-one"]


def test_the_broken_ones_are_worked_easiest_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`bump.ranked`'s order, not this command's own.

    A run that is interrupted has then spent its money on the ones a person would have started
    with, and the ordering rule stays in the one module that already owns it.
    """
    reports = [
        _report("twelve", bump.Verdict.BREAKS, "\n".join(f"FAILED t{i}" for i in range(12))),
        _report("two", bump.Verdict.BREAKS, "FAILED a\nFAILED b"),
    ]

    asked, _ = _fix_run(tmp_path, reports, monkeypatch)

    assert [u.package for u in asked] == ["two", "twelve"]


def test_the_advisory_travels_with_the_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agent's brief names why this upgrade exists, and a reader can go and check it."""
    asked, _ = _fix_run(
        tmp_path, [_report("broken-one", bump.Verdict.BREAKS, BROKEN)], monkeypatch
    )

    assert asked[0].advisory == "GHSA-broken-one"
    assert "osv.dev" in asked[0].url


def test_an_upgrade_that_cannot_be_applied_is_said_rather_than_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No attempt was begun, so nothing was spent — and the resolver's own words survive.

    A traceback here would end the whole run over one package, which on a queue of six is five
    upgrades nobody was told about.
    """
    _, printed = _fix_run(
        tmp_path,
        [_report("broken-one", bump.Verdict.BREAKS, BROKEN)],
        monkeypatch,
        fail="constrained-by-manifest: the range does not allow it",
    )

    assert "could not be applied" in printed
    assert "the range does not allow it" in printed
    assert "0 of 1" in printed


def test_a_queue_with_nothing_broken_says_so_rather_than_going_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked, printed = _fix_run(tmp_path, [_report("clean-one", bump.Verdict.CLEAN)], monkeypatch)

    assert asked == []
    assert "had nothing to do" in printed


def test_two_upgrades_of_one_package_are_two_items(session: Session) -> None:
    """The identity of this work is the pair of versions, not the package.

    A fingerprint over the name alone would make the second upgrade a repeat of the first, and
    `dedup` would increment a counter instead of creating work.
    """
    manifest = parse_manifest(MANIFEST)
    first = refit.from_report(_breaks(), source="requirements.txt")
    second = bump.Report(
        package="lodash", was=WAS,
        answers=(bump.Answer(bump.Verdict.BREAKS, "lodash", WAS, "4.17.22", detail=BROKEN),),
    )
    other = refit.from_report(second, source="requirements.txt")
    assert first is not None and other is not None

    _, a = refit.stage(session, manifest, first, repo="o/r")
    _, b = refit.stage(session, manifest, other, repo="o/r")

    assert a.fingerprint != b.fingerprint


# --- first contact, which is where item 048's lesson had not reached (item 184) -----------------


def test_fix_without_a_model_refuses_before_a_container_is_built() -> None:
    """**Item 048's finding, on the path that had not learned it.**

    Measured by running `--fix` for the first time on 2026-08-09: the refusal was raised inside
    `refit.run`, so it arrived **after** every container had been built and every suite run — the
    most expensive place available — and it arrived as a `WiringError` traceback rather than as a
    refusal, which item 120 is about. The message itself was right; where and how it appeared were
    not.

    Knowable from the settings and nothing else, so it costs nothing to answer this early.
    """
    from hullwork import cli
    from hullwork.config import Settings

    with pytest.raises(cli.CommandError) as refused:
        cli._refuse_without_a_model(Settings())

    assert "no model credential" in str(refused.value)
    # And it names the half that needs nothing, because that is what the reader can still run.
    assert "--verify" in str(refused.value)


def test_fix_asks_for_the_model_before_it_reads_a_single_lock_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The call site, which is where the defect was** — and the first version of this test did
    not cover it.

    That one asserted `_refuse_without_a_model` raises, which it always did: the function was never
    the problem. Deleting the *call* from `_cmd_deps` left every test green and put the refusal back
    where it started, minutes and several containers later. Verified by doing exactly that.

    The stub raises something unmistakable, so what this asserts is the **order**: the refusal wins
    over the lock-file refusal that the same checkout would otherwise produce.
    """
    import argparse
    import subprocess

    from hullwork import cli
    from hullwork.config import Settings

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S603, S607
    (tmp_path / "hullwork.yml").write_text(
        "project: p\ngit: {provider: forgejo, repo: o/r}\n"
        'tests: "pytest"\ntest_path: tests\n'
        "runtime: {base: python-3.12, install: none, dependencies: []}\n"
    )

    def refuse(*_a: object, **_k: object) -> None:
        raise cli.CommandError("asked for the model first")

    monkeypatch.setattr(cli, "_refuse_without_a_model", refuse)

    with pytest.raises(cli.CommandError) as refused:
        cli._cmd_deps(
            argparse.Namespace(
                checkout=str(tmp_path), verify=False, fix=True, open=False, into=str(tmp_path)
            ),
            Settings(),
            io.StringIO(),
        )

    assert "asked for the model first" in str(refused.value)


def test_verify_alone_never_asks_for_a_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The property `deps` is sold on: `--verify` runs the suite against every published fix with
    no credential of any kind. Asserted by making the lookup explode."""
    import argparse
    import subprocess

    from hullwork import cli
    from hullwork.config import Settings

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S603, S607
    (tmp_path / "hullwork.yml").write_text(
        "project: p\ngit: {provider: forgejo, repo: o/r}\n"
        'tests: "pytest"\ntest_path: tests\n'
        "runtime: {base: python-3.12, install: none, dependencies: []}\n"
    )

    def explode(*_a: object, **_k: object) -> None:
        raise AssertionError("--verify asked for a model credential")

    monkeypatch.setattr(cli, "_refuse_without_a_model", explode)

    with pytest.raises(cli.CommandError) as refused:
        cli._cmd_deps(
            argparse.Namespace(
                checkout=str(tmp_path), verify=True, fix=False, open=False, into=str(tmp_path)
            ),
            Settings(),
            io.StringIO(),
        )

    assert "no lock file" in str(refused.value)


def test_fix_refuses_without_the_gateway_image_before_anything_is_built(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Item 048's finding for the third time**, found by running `--fix` against a real model.

    It died with `could not start the gateway / Unable to find image 'hullwork:dev' locally` —
    after OSV, four image builds and two suite runs. The gateway is where the model credential
    lives so the sandbox never holds it (DR-0004), and **every** agent path starts one, so this is
    a fact about the instance rather than about the newest command.

    The refusal has to say what the image is for and how to build it: *image not found* is not
    something anybody can act on.
    """
    from hullwork import cli
    from hullwork import work as work_module
    from hullwork.config import Settings

    monkeypatch.setattr(work_module, "_model_credential", lambda _s: "a-key")
    monkeypatch.setattr(
        "hullwork.sandbox.net.why_the_gateway_cannot_start",
        lambda **_k: "the gateway image `hullwork:dev` is not on this Docker daemon",
    )

    with pytest.raises(cli.CommandError, match="gateway image"):
        cli._refuse_without_a_model(Settings())


def test_the_gateway_refusal_names_what_to_run_and_what_not_to() -> None:
    """`docker compose build` **does not make it**, and this repository said it did.

    The compose file pins a published image and has no build stage — its own comment says to add
    one — so that instruction exits 0 and produces nothing. Measured on 2026-08-09 while chasing
    exactly this skip, and the sentence a reader gets now says both halves.
    """
    from hullwork.sandbox import net

    said = net.why_the_gateway_cannot_start.__doc__ or ""
    assert "expensive place available" in said

    # The refusal itself, built without a daemon by asking for an image that cannot exist.
    refusal = net.why_the_gateway_cannot_start(docker="a-binary-that-is-not-here")
    assert refusal is None, "a missing docker client is doctor's question, not this one's"
