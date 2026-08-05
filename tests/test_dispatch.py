"""The six steps and the gate between them (item 025).

Driven with a fake sandbox, because what is under test is the *sequence and its verdicts*, not
Docker — item 023 already proved the container by effect. Each test here is one way the sequence
can end, and the interesting ones are the endings that are not a pull request.
"""

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session

from hullwork import dispatch
from hullwork.attempts import start
from hullwork.engine import Engine, Phase
from hullwork.manifest import parse_manifest
from hullwork.models import AttemptOutcome, AttemptPhase, Item, Lane, Project
from hullwork.sandbox.run import RunResult

MANIFEST = """
project: p
git: {provider: forgejo, repo: o/r}
autofix: {agent: claude-code, gates: [tests, human-merge]}
tests: "pytest"
test_path: tests
runtime: {base: python-3.12, install: none, dependencies: []}
"""

ENGINE = Engine(name="fake", image="img", protocol="anthropic", command="agent {phase}")


class FakeBox:
    """Stands in for the container. Scripted per command, and writes what an agent would write."""

    def __init__(
        self,
        worktree: Path,
        script: dict[str, int],
        writes: dict[str, dict[str, str]],
        outputs: dict[str, str] | None = None,
    ) -> None:
        #: What a command printed, when a test cares. Item 092 made a verdict carry the failures it
        #: saw, and a double that answers `"out"` to everything cannot express that.
        self.outputs = outputs or {}
        self.worktree = worktree
        self.contract_dir = worktree / "_contract"
        self.contract_dir.mkdir(exist_ok=True)
        self.script = script
        self.writes = writes
        self.ran: list[str] = []
        #: The environment each command was given, by command. Item 064 asserts what the agent was
        #: told, and `ran` only records that it ran.
        self.envs: dict[str, dict[str, str]] = {}
        # `pytest` is run three times with three different expected results — baseline green, red
        # gate red, green gate green — so a doubles that keys only on the command string cannot
        # express the happy path at all. Counting the calls is the difference between testing the
        # sequence and testing that it did not crash.
        self.counts: dict[str, int] = {}

    def run(self, command: str, timeout: int, env: dict[str, str] | None = None) -> RunResult:
        self.ran.append(command)
        self.envs[command] = dict(env or {})
        nth = self.counts.get(command, 0)
        self.counts[command] = nth + 1
        for name, files in self.writes.get(command, {}).items():
            if name == "__delete__":
                # A phase can remove a file, and item 045 is about that being reported. The double
                # is the only place this can be expressed, since nothing here runs a real agent.
                (self.worktree / files).unlink()
                continue
            target = self.worktree / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(files)
        code = self.script.get(f"{command}#{nth}", self.script.get(command, 0))
        printed = self.outputs.get(f"{command}#{nth}", self.outputs.get(command, "out"))
        return RunResult(command=command, exit_code=code, output=printed, duration_ms=1)
    # Item 058: production has two entries — `run` (no route out) and `run_with_model`
    # (the gateway reachable). A double that answers only the old single method would
    # send the agent phases down whichever one it happens to have, so it must have both.
    run_with_model = run



@pytest.fixture
def item(session: Session) -> Item:
    project = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="x",  # noqa: S106
    )
    session.add(project)
    session.flush()
    row = Item(project_id=project.id, fingerprint="fp", title="ValueError: boom", lane=Lane.GREEN)
    session.add(row)
    session.flush()
    return row


def _go(
    session: Session, item: Item, tmp_path: Path, script: dict[str, int],
    writes: dict[str, dict[str, str]] | None = None, manifest_text: str = MANIFEST,
    outputs: dict[str, str] | None = None,
    engine: Engine = ENGINE,
) -> tuple[dispatch.Verdict, "FakeBox", Any]:
    (tmp_path / "src.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir(exist_ok=True)
    box = FakeBox(tmp_path, script, writes or {}, outputs)
    attempt = start(session, item)
    verdict = dispatch.dispatch(
        session, item, parse_manifest(manifest_text), engine,
        box=box,  # type: ignore[arg-type]
        attempt=attempt,
    )
    return verdict, box, attempt


REPRO = "agent reproduce"
FIX = "agent fix"
GOOD_TEST = {"tests/test_repro.py": "def test_x():\n    assert False\n"}


def test_the_happy_path_is_a_pull_request(session: Session, item: Item, tmp_path: Path) -> None:
    """Baseline green, red gate red, green gate green — the claim the whole product makes."""
    verdict, _, attempt = _go(
        session, item, tmp_path,
        # Third `pytest` call is the green gate; the second is the red one and must fail.
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
    )

    assert verdict.outcome is AttemptOutcome.PR_OPEN
    assert verdict.phase is AttemptPhase.PUBLISH
    assert set(verdict.candidate.written) == {"tests/test_repro.py"}
    assert verdict.changes.written["src.py"] == b"x = 2\n"
    assert [s.phase for s in attempt.steps] == [
        AttemptPhase.BASELINE, AttemptPhase.REPRODUCE, AttemptPhase.RED_GATE,
        AttemptPhase.FIX, AttemptPhase.GREEN_GATE,
    ]


def test_a_fix_that_deletes_a_file_carries_the_deletion_to_the_verdict(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Item 045. The gates ran against the tree with the file gone; the verdict said nothing."""
    (tmp_path / "validate.py").write_text("def check():\n    raise ValueError\n")

    verdict, _, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"__delete__": "validate.py"}},
    )

    assert verdict.outcome is AttemptOutcome.PR_OPEN
    assert verdict.changes.deleted == ("validate.py",)


def test_a_fix_that_does_not_make_the_suite_pass_fails(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """"My test passes" while three others broke is what stops reviewers trusting a bot."""
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, "pytest#2": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
    )

    assert verdict.outcome is AttemptOutcome.FAILED
    assert verdict.phase is AttemptPhase.GREEN_GATE


def test_editing_its_own_test_during_the_fix_is_caught(
    session: Session, item: Item, tmp_path: Path
) -> None:
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"tests/test_repro.py": "def test_x():\n    pass\n"}},
    )

    assert verdict.outcome is AttemptOutcome.FAILED
    assert verdict.phase is AttemptPhase.FIX
    assert "edited its own reproducing test" in verdict.detail


def test_the_lint_gate_runs_only_when_the_manifest_names_it(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """What the name promises: the declared gate runs, and it runs after the ones before it.

    **This also asserted `FAILED` at `LINT_GATE`, and item 067 is why it does not.** That outcome
    publishes nothing, so an attempt that had cleared the red gate *and* the green gate — proving
    the product's whole claim — was discarded over the style of the file that proves it. Measured
    on this repository: 67 model calls and ~25,000 output tokens, thrown away twice, both times for
    `Statement is unreachable`. What the failing gate is worth is now asserted where it belongs,
    next to the outcome that publishes it.
    """
    with_lint = MANIFEST.replace(
        "gates: [tests, human-merge]", "gates: [tests, lint, human-merge]"
    ) + '\nlint: "ruff check ."\n'
    verdict, box, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0, "ruff check .": 1},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
        manifest_text=with_lint,
    )

    assert "ruff check ." in box.ran
    # And last: a lint gate that ran before the suite would be judging a tree the gates had not
    # accepted yet.
    assert box.ran.index("ruff check .") > box.ran.index(FIX)
    assert verdict.candidate.written, "the change the gate judged is the one being published"


def test_no_lint_gate_means_no_lint_command(
    session: Session, item: Item, tmp_path: Path
) -> None:
    _, box, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
    )

    assert not any("ruff" in c for c in box.ran)


def test_a_red_baseline_stops_before_the_model_is_called(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Spending an attempt to discover the project's own suite is broken spends it on nothing.

    Which is precisely what this used to assert. The outcome was `failed`, `failed` consumes, so
    the docstring above described a defect rather than a guarantee (item 043).
    """
    verdict, box, _ = _go(session, item, tmp_path, script={"pytest": 1})

    assert verdict.outcome is AttemptOutcome.BASELINE_RED
    assert verdict.phase is AttemptPhase.BASELINE
    assert REPRO not in box.ran
    assert "does not pass on an untouched checkout" in verdict.detail
    assert "still has its attempt" in verdict.detail


def test_no_candidate_test_is_not_reproducible(
    session: Session, item: Item, tmp_path: Path
) -> None:
    verdict, _, _ = _go(session, item, tmp_path, script={"pytest": 0, REPRO: 0})

    assert verdict.outcome is AttemptOutcome.NOT_REPRODUCIBLE
    assert "wrote no test" in verdict.detail


def test_the_reproduce_phase_may_not_touch_source(
    session: Session, item: Item, tmp_path: Path
) -> None:
    verdict, box, _ = _go(
        session, item, tmp_path, script={"pytest": 0, REPRO: 0},
        writes={REPRO: {"src.py": "raise SystemExit\n"}},
    )

    assert verdict.outcome is AttemptOutcome.FAILED
    assert verdict.phase is AttemptPhase.REPRODUCE
    assert FIX not in box.ran


def test_a_candidate_that_passes_has_reproduced_nothing(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """The whole rule, and the reason the sequence is split in two (DR-0003)."""
    verdict, box, _ = _go(
        session, item, tmp_path, script={"pytest": 0, REPRO: 0}, writes={REPRO: GOOD_TEST},
    )

    assert verdict.outcome is AttemptOutcome.NOT_REPRODUCIBLE
    assert verdict.phase is AttemptPhase.RED_GATE
    assert "no fix was attempted" in verdict.detail
    assert FIX not in box.ran  # it did not go on to try


def test_every_step_reaches_the_evidence_trail(
    session: Session, item: Item, tmp_path: Path
) -> None:
    _, _, attempt = _go(session, item, tmp_path, script={"pytest": 1})

    assert [(s.phase, s.command, s.exit_code) for s in attempt.steps] == [
        (AttemptPhase.BASELINE, "pytest", 1)
    ]


def test_a_gate_that_times_out_does_not_spend_the_attempt(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """A gate that ran out of time says nothing about whether the bug is reproducible."""
    (tmp_path / "src.py").write_text("x = 1\n")
    box = FakeBox(tmp_path, {}, {})
    box.run = lambda command, timeout, env=None: RunResult(  # type: ignore[method-assign]
        command=command, exit_code=137, output="", duration_ms=1, timed_out=True
    )
    attempt = start(session, item)
    with pytest.raises(dispatch.Abandoned, match="did not finish in time"):
        dispatch.dispatch(
            session, item, parse_manifest(MANIFEST), ENGINE,
            box=box,  # type: ignore[arg-type]
            attempt=attempt,
        )


def test_the_candidate_test_is_restored_if_the_fix_phase_edits_it(tmp_path: Path) -> None:
    """A test the fix was allowed to change is not evidence about the fix."""
    (tmp_path / "tests").mkdir()
    original = {"tests/test_repro.py": b"assert False\n"}
    (tmp_path / "tests/test_repro.py").write_bytes(b"assert True\n")

    changed = dispatch._restore_candidate(tmp_path, original)

    assert changed == "tests/test_repro.py"
    assert (tmp_path / "tests/test_repro.py").read_bytes() == b"assert False\n"


def test_an_untouched_candidate_reports_nothing(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_repro.py").write_bytes(b"assert False\n")

    assert dispatch._restore_candidate(
        tmp_path, {"tests/test_repro.py": b"assert False\n"}
    ) == ""


def test_the_worktree_copy_leaves_the_git_directory_behind(tmp_path: Path) -> None:
    """A worktree with no repository in it cannot grow a hook that runs on the host."""
    source = tmp_path / "src"
    (source / ".git" / "hooks").mkdir(parents=True)
    (source / ".git" / "hooks" / "pre-commit").write_text("evil")
    (source / "code.py").write_text("1")

    copy = dispatch.prepare_worktree(source)

    assert (copy / "code.py").exists()
    assert not (copy / ".git").exists()


def test_the_phase_is_passed_to_the_engine() -> None:
    assert ENGINE.argv(Phase.REPRODUCE) == ["agent", "reproduce"]
    assert ENGINE.argv(Phase.FIX) == ["agent", "fix"]


# --- the fix may not neuter the suite (item 046) -------------------------------------------------

NEUTERED = {"tests/conftest.py": "collect_ignore_glob = ['*']\n"}


def _with_conftest(tmp_path: Path) -> None:
    """A `conftest.py` that already exists, which is the whole premise of item 046."""
    (tmp_path / "tests").mkdir(exist_ok=True)
    (tmp_path / "tests" / "conftest.py").write_text("# nothing yet\n")


def test_a_fix_that_switches_the_tests_off_is_caught(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """The live defect, reproduced.

    Measured before this existed: the fix wrote `collect_ignore_glob = ['*']` into a pre-existing
    `tests/conftest.py`, pytest collected nothing, the green gate passed trivially,
    `_restore_candidate` reported no tampering, and the pull request published with the
    unconditional red-green claim attached — with the mechanism inside the diff.
    """
    _with_conftest(tmp_path)

    verdict, _, attempt = _go(
        session, item, tmp_path,
        # baseline green, red gate red, green gate green (tests disabled), restored gate red.
        script={"pytest#1": 1, "pytest#3": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n", **NEUTERED}},
    )

    assert verdict.outcome is AttemptOutcome.FAILED
    assert verdict.phase is AttemptPhase.GREEN_GATE_RESTORED
    assert "passed only because it had disabled the tests" in verdict.detail
    assert "tests/conftest.py" in verdict.detail
    # And the trail shows both runs, so a reader can see which one the verdict rests on.
    assert [s.phase for s in attempt.steps][-2:] == [
        AttemptPhase.GREEN_GATE, AttemptPhase.GREEN_GATE_RESTORED,
    ]


def test_the_restored_file_is_not_published(session: Session, item: Item, tmp_path: Path) -> None:
    """The published set must be the one the second gate measured, never the pre-restore one."""
    _with_conftest(tmp_path)

    verdict, _, _ = _go(
        session, item, tmp_path,
        # The suite passes even with the conftest put back, so this is a fix that touched it
        # pointlessly rather than dishonestly. It still may not ship that change.
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n", **NEUTERED}},
    )

    assert verdict.outcome is AttemptOutcome.PR_OPEN
    assert "tests/conftest.py" not in verdict.changes.written
    assert verdict.restored == "tests/conftest.py"
    assert "rests on that second run" in verdict.detail


def test_a_fix_that_adds_a_test_is_left_alone(session: Session, item: Item, tmp_path: Path) -> None:
    """Pre-existing is the distinction. A fix that adds a test is welcome and must not be undone."""
    verdict, _, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={
            REPRO: GOOD_TEST,
            FIX: {"src.py": "x = 2\n", "tests/test_extra.py": "def test_more():\n    pass\n"},
        },
    )

    assert verdict.outcome is AttemptOutcome.PR_OPEN
    assert verdict.restored == ""
    assert "tests/test_extra.py" in verdict.changes.written


def test_an_untouched_suite_runs_exactly_one_green_gate(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """The guard must not make every attempt pay for a second suite run."""
    _with_conftest(tmp_path)

    _, box, attempt = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
    )

    assert box.counts["pytest"] == 3
    assert AttemptPhase.GREEN_GATE_RESTORED not in [s.phase for s in attempt.steps]


def test_a_deleted_conftest_is_restored(session: Session, item: Item, tmp_path: Path) -> None:
    """Deleting the file that configures collection is the same attack with a different verb."""
    _with_conftest(tmp_path)

    verdict, _, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, "pytest#3": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n", "__delete__": "tests/conftest.py"}},
    )

    assert verdict.outcome is AttemptOutcome.FAILED
    assert verdict.phase is AttemptPhase.GREEN_GATE_RESTORED
    assert "tests/conftest.py" in verdict.detail


# --- the agent is told what its test will be judged by (item 064) ---------------------------------


def test_the_agent_is_told_the_lint_command_when_there_is_a_gate(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Measured twice: both attempts that reached the lint gate failed there, on the same
    diagnostic, in the file the agent had just written — `Statement is unreachable`.

    The gate is right and is not relaxed. What changes is that the agent stops being judged by a
    command it was never shown: the reproduce phase is asked for a *failing* test, the lint gate is
    the fifth of six steps, and nothing connected the two.
    """
    from hullwork.engine import AGENT_ENTRYPOINT

    with_lint = MANIFEST.replace(
        "gates: [tests, human-merge]", "gates: [tests, lint, human-merge]"
    ) + '\nlint: "ruff check ."\n'

    _, box, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
        manifest_text=with_lint,
    )

    assert box.envs[REPRO]["HULLWORK_AGENT_LINT"] == "ruff check ."
    assert box.envs[FIX]["HULLWORK_AGENT_LINT"] == "ruff check ."
    # And the entrypoint uses it, or passing it would be decoration.
    assert "HULLWORK_AGENT_LINT" in AGENT_ENTRYPOINT
    assert "LINT_ASK" in AGENT_ENTRYPOINT


def test_the_pinned_model_reaches_the_container(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Item 139, and the reason no provider but one could actually be selected.

    `HULLWORK_MODEL_NAME` was read only by the gateway, which compares it to what answered
    (DR-0002) and forwards without rewriting — so the harness asked for its own default. Against
    Anthropic that is invisible, because the default is the model you pinned. Against anything else
    the request names a model the endpoint may not serve, and if it does serve it, the instance
    pays for a model nobody chose and records a violation of a pin that never left the process.

    Asserted on what the *container* was given rather than on `phase_env()`, because a test of the
    function alone passes with the call site deleted, which is item 136's defect.
    """
    steered = replace(
        ENGINE,
        model_env=("ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL"),
        model="deepseek/deepseek-v4-pro",
    )
    _, box, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
        engine=steered,
    )

    for phase in (REPRO, FIX):
        assert box.envs[phase]["ANTHROPIC_MODEL"] == "deepseek/deepseek-v4-pro"
        # Every tier, not just the headline one: a harness that asks for a cheap model for
        # subtasks would otherwise send that request to an endpoint that never heard of it.
        assert box.envs[phase]["ANTHROPIC_DEFAULT_HAIKU_MODEL"] == "deepseek/deepseek-v4-pro"


def test_an_unpinned_model_leaves_the_harness_its_own_default(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """The other half of item 139, and the one that protects every instance running today.

    Nothing pinned must mean nothing said. Setting these variables to an empty string would be a
    different thing entirely — a harness told to ask for a model called `""`.
    """
    _, box, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
    )

    assert "ANTHROPIC_MODEL" not in box.envs[REPRO]


def test_no_lint_gate_means_the_agent_is_told_nothing_about_one(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """Naming a command nobody will run is worse than silence: the agent would spend turns
    satisfying a gate this project does not have."""
    _, box, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
    )

    assert box.envs[REPRO]["HULLWORK_AGENT_LINT"] == ""


# --- a verdict says what it saw. Item 092 --------------------------------------------------------


def test_a_red_baseline_names_what_failed(session: Session, item: Item, tmp_path: Path) -> None:
    """**Diagnosing the first real occurrence meant a query against a file inside a volume.**

    The verdict said the suite does not pass and stopped there. The 24 failing test names were in
    `attempt_steps.output` at the moment it was written — in hand, and left where only somebody
    willing to open a SQLite file inside a Docker volume would find them. That is the place this
    product exists to keep its reader out of.
    """
    printed = (
        "FAILED tests/test_sandbox_net.py::test_the_sandbox_is_told_the_gateway_s_address\n"
        "FAILED tests/test_sandbox_services.py::test_the_suite_is_told_where_the_database_is\n"
        "24 failed, 875 passed in 56.54s\n"
    )
    verdict, _, _ = _go(session, item, tmp_path, script={"pytest": 1}, outputs={"pytest": printed})

    assert verdict.outcome is AttemptOutcome.BASELINE_RED
    assert "test_the_sandbox_is_told_the_gateway_s_address" in verdict.detail
    assert "test_the_suite_is_told_where_the_database_is" in verdict.detail
    # And still says the thing that tells the operator the item is not spent.
    assert "still has its attempt" in verdict.detail


def test_a_suite_with_many_failures_does_not_become_the_verdict() -> None:
    """A verdict is read by a person. Two thousand failures is a log, not a diagnosis."""
    output = "\n".join(f"FAILED tests/test_{n}.py::test_it" for n in range(2000))

    shown = dispatch.failing_lines(output)

    assert shown.count("FAILED") == dispatch.FAILURES_SHOWN
    assert f"and {2000 - dispatch.FAILURES_SHOWN} more" in shown


def test_an_unrecognised_runner_still_says_something() -> None:
    """A tail beats the empty string, and a parser per test runner is a promise this cannot keep.

    Every runner worth supporting prints a line per failure, but not with the same word. When none
    of the words match, what it printed last is still the best thing available.
    """
    output = "compiling…\nassertion at line 44 did not hold\nsummary: 1 of 3 checks unhappy\n"

    shown = dispatch.failing_lines(output)

    assert "1 of 3 checks unhappy" in shown
    assert "The last of what it printed" in shown


def test_a_silent_failing_suite_adds_nothing_rather_than_a_heading() -> None:
    """A heading over nothing reads as a bug in the reporter."""
    assert dispatch.failing_lines("") == ""
    assert dispatch.failing_lines("   \n\n") == ""


# --- a verified fix whose lint gate failed still reaches a human. Item 067 ------------------------


def _lint_gate_fails(
    session: Session, item: Item, tmp_path: Path, *, lint_output: str = "E501 line too long"
) -> tuple[dispatch.Verdict, "FakeBox"]:
    """Both gates green, lint red: the one case where every claim holds and a gate does not."""
    with_lint = MANIFEST.replace(
        "gates: [tests, human-merge]", "gates: [tests, lint, human-merge]"
    ) + '\nlint: "ruff check ."\n'
    verdict, box, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0, "ruff check .": 1},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
        manifest_text=with_lint,
        outputs={"ruff check .": lint_output},
    )
    return verdict, box


def test_a_failing_lint_gate_publishes_under_its_own_outcome(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """**Not `failed`, and not `pr-open` either.**

    `failed` publishes nothing, which discards a verified red-green claim over the style of the
    file that proves it. `pr-open` would make the trail say every gate passed. So it is a third
    thing, and the reason it has to be a third thing is that `hullwork status`, the issue comment
    and the pull request body all read the same field.
    """
    verdict, _ = _lint_gate_fails(session, item, tmp_path)

    assert verdict.outcome is AttemptOutcome.PR_OPEN_LINT_FAILED
    assert verdict.phase is AttemptPhase.PUBLISH, "it publishes, so publish is where it got to"
    assert verdict.changes.written, "there is a change to open a pull request with"


def test_the_artefact_leads_with_the_lint_failure(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """First paragraph, not behind a `<details>`.

    An artefact whose shape hides its own weakest part is worse than one that does not exist — and
    the reviewer decides from the top of the body, before the phase table.
    """
    from hullwork import evidence
    from hullwork.models import Attempt

    verdict, _ = _lint_gate_fails(session, item, tmp_path, lint_output="E501 line too long (104)")
    attempt = session.query(Attempt).order_by(Attempt.id.desc()).first()
    assert attempt is not None
    attempt.outcome = verdict.outcome
    attempt.phase_reached = verdict.phase

    body = evidence.pull_request_body(item, attempt, detail=verdict.detail)
    # Everything before the first heading, which is what a reviewer reads before deciding to scroll.
    # **Split on the literal `### Provenance` first, and that was wrong**: when the string is absent
    # `split` returns the whole document, so the assertions below passed against the step table in a
    # `<details>` further down — measured by deleting the fix and watching the test stay green.
    opening = body.split("\n### ")[0]
    assert len(opening) < len(body), "the split found no heading, so this is not the opening"

    assert "lint" in opening.lower(), "the failing gate is not named where it is read"
    assert "E501 line too long (104)" in opening, "the gate's own output is not in the first part"
    assert "ruff check ." in opening, "the command that failed is not named"
    # And the claim that is still true is there too, or the reviewer cannot tell what was verified.
    assert "passes with this" in opening


def test_the_attempt_is_consumed_because_there_is_something_to_read(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """The item has been dealt with: a human has an artefact.

    Requeueing it would be the retry loop DR-0003 forbids — the agent did its work and the remaining
    task is a lint fix, which is not another attempt's job.
    """
    from hullwork import attempts as attempts_module

    _lint_gate_fails(session, item, tmp_path)

    assert AttemptOutcome.PR_OPEN_LINT_FAILED not in attempts_module._DOES_NOT_CONSUME, (
        "an outcome with an artefact for a human must consume the attempt"
    )


def test_a_failing_green_gate_still_publishes_nothing(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """**The negative half, and the line item 067 draws.**

    Lint is the only gate that can fail while everything the product asserts is true. A green gate
    that fails says the fix does not work, and there is nothing to show a reviewer.
    """
    with_lint = MANIFEST.replace(
        "gates: [tests, human-merge]", "gates: [tests, lint, human-merge]"
    ) + '\nlint: "ruff check ."\n'
    verdict, box, _ = _go(
        session, item, tmp_path,
        # `pytest#2` is the green gate: red baseline pass, red gate red, green gate red.
        script={"pytest#1": 1, "pytest#2": 1, REPRO: 0, FIX: 0, "ruff check .": 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
        manifest_text=with_lint,
    )

    assert verdict.outcome is AttemptOutcome.FAILED
    assert verdict.phase is not AttemptPhase.PUBLISH
    assert "ruff check ." not in box.ran, "the lint gate must not run on a fix that does not work"


def test_nothing_handed_to_a_phase_is_inside_the_namespace_settings_validates(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """**Item 099, and it is asserted here because the gates could never have caught it.**

    `_run_gate` passes no environment; `_run_agent` passes five variables. They were named
    `HULLWORK_PHASE`, `HULLWORK_TEST_PATH`, … — inside `Settings`' own namespace, which
    `config._unknown_variables` rejects by design. So about four hundred of this project's tests
    errored at setup *inside the phase whose purpose is to run them*, the gates stayed green, and
    the only trace was the agent saying so in prose.

    Checked against the guard itself rather than against a list of names: a sixth variable added in
    the wrong namespace fails this without anybody remembering to update it.
    """
    from hullwork.config import AGENT_PREFIX, Settings

    _, box, _ = _go(
        session, item, tmp_path,
        script={"pytest#1": 1, REPRO: 0, FIX: 0},
        writes={REPRO: GOOD_TEST, FIX: {"src.py": "x = 2\n"}},
    )

    handed = {name for env in box.envs.values() for name in env}
    assert handed, "the agent must be told something, or this test proves nothing"

    settings_namespace = {f"HULLWORK_{field.upper()}" for field in Settings.model_fields}
    for name in handed:
        if not name.startswith("HULLWORK_"):
            continue  # the engine's own variables, e.g. ANTHROPIC_BASE_URL
        assert name.startswith(AGENT_PREFIX) or name in settings_namespace, (
            f"{name} is in the namespace the watched project validates and is not a setting — "
            f"a suite that reads HULLWORK_* will refuse to start inside the agent's phase"
        )
