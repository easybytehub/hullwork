"""The six steps, and the gate that sits between two of them.

Item 025. This is where authorisation becomes execution, and it is the only module that gets to
say how an attempt ended.

DR-0003 requires the reproducing test to be shown failing **before any edit is allowed**. One agent
run cannot demonstrate that: by the time it has written the test and the fix, the tree is already
modified and the claim is unverifiable. So the run is split and the gate lives between the halves,
here — in the party with no incentive to pass it.

```
 0. baseline      run `tests` on the pristine checkout          → must PASS
 1. reproduce     agent; new files under `test_path` only       → candidate test
 2. RED GATE      run `tests` on pristine + candidate           → must FAIL
 3. fix           agent; source editable, candidate read-only   → the change
 4. GREEN GATE    run `tests` on pristine + candidate + fix     → must PASS
 5. lint gate     run `lint` if the manifest declares the gate  → must PASS
```

**Nothing here believes the agent.** Its exit code, its `is_error` flag and its own report are
recorded and used for nothing: the verdict comes from commands this module runs. That is not a
posture, it is a measurement — the reference harness has been observed reporting success and
failure simultaneously.
"""

import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from hullwork import attempts, brief, testoutput
from hullwork.engine import REPORT_PATH, AgentReport, Engine, Phase
from hullwork.manifest import Manifest
from hullwork.models import Attempt, AttemptOutcome, AttemptPhase, Item
from hullwork.sandbox.docker import UnsafePathError
from hullwork.sandbox.run import (
    Changes,
    RunResult,
    Sandbox,
    collect_changes,
    is_test_infrastructure,
    snapshot,
)

log = logging.getLogger(__name__)

#: How long one agent phase may take. Generous: the model is thinking and the suite is running.
AGENT_TIMEOUT_SECONDS = 1800

#: How long a gate command may take. A suite slower than this is a project problem, and finding
#: that out costs an attempt either way — better to say so than to wait all night.
GATE_TIMEOUT_SECONDS = 900


class Abandoned(Exception):  # noqa: N818 - it is an outcome, not an error condition
    """Something went wrong that is **not** the agent's fault, so the attempt does not count.

    An exception rather than a return value because it can happen at any of six points, and a
    function that has to remember to propagate "this did not count" up through five callers will
    eventually forget at one of them. The item's one attempt is too expensive for that.
    """

    def __init__(self, reason: str, phase: AttemptPhase = AttemptPhase.BASELINE) -> None:
        super().__init__(reason)
        self.reason = reason
        self.phase = phase


@dataclass
class Verdict:
    """How one dispatch ended, and everything the evidence trail needs to explain it."""

    outcome: AttemptOutcome
    phase: AttemptPhase
    #: The files that should become a pull request, when there is one. Written *and* deleted, since
    #: item 045: a fix that removes a validation by deleting a file used to be tested as one tree
    #: and published as another.
    changes: Changes = field(default_factory=lambda: Changes({}))
    candidate: Changes = field(default_factory=lambda: Changes({}))
    detail: str = ""
    report: AgentReport | None = None
    #: Test infrastructure the fix phase had changed and this module put back (item 046). Non-empty
    #: means the published claim rests on the second green gate, not the first.
    restored: str = ""


def dispatch(
    session: object,
    item: Item,
    manifest: Manifest,
    engine: Engine,
    *,
    box: Sandbox,
    attempt: Attempt,
) -> Verdict:
    """Run the sequence in a sandbox the caller has already built, against a checkout it made.

    The caller owns both because it owns the credentials: this function never touches a forge,
    never starts a container and never learns that either exists. It is handed a box and a
    directory and gives back a decision — which is also why it is testable without Docker.
    """
    worktree = box.worktree
    tests = (manifest.tests or "").strip()
    # What the agent's own output will be judged by, if anything (item 064). Empty unless the
    # manifest declares the gate *and* gives it a command — the pair item 021 made inseparable.
    lint_ask = (manifest.lint or "") if "lint" in manifest.autofix.gates else ""
    if not tests:  # pragma: no cover - the manifest parser refuses this before we get here
        raise Abandoned("the manifest declares no test command")

    # --- step 0 ---------------------------------------------------------------------------
    baseline = _run_gate(session, attempt, box, AttemptPhase.BASELINE, tests)
    if not baseline.ok:
        # Before the model is called, and deliberately so: a suite that is already red cannot
        # support the claim "this test failed and now passes", and spending an attempt to discover
        # that would be spending it on the project's own state.
        #
        # Which is exactly what it used to do. This returned `failed`, `failed` consumes, and item
        # 025's own ticked criterion said it must end the item `human-only` — so the item lost its
        # one and only try to a message blaming the project's suite, before any model was called
        # (item 043). `baseline-red` does not consume, and does not go back in the queue either:
        # the suite will still be red next pass.
        return Verdict(
            AttemptOutcome.BASELINE_RED,
            AttemptPhase.BASELINE,
            detail=(
                "the project's own test suite does not pass on an untouched checkout, so no "
                "red-green claim can be made about it. Nothing was attempted and this item still "
                "has its attempt: fix the suite, or the bug by hand.\n"
                # **What it saw, not only that it saw something** (item 092). This used to end at
                # the sentence above, and diagnosing the first real occurrence meant querying
                # `attempt_steps.output` inside a SQLite file inside a Docker volume — sending its
                # reader exactly where this product exists to keep them out of. The failures were
                # already in hand when the verdict was written.
                + failing_lines(baseline.output)
            ),
        )

    # Snapshotted **after** the baseline, not before. The baseline is a real test run and a real
    # test run writes caches; taken before, every one of those files looks like something the agent
    # produced. Found by running this for the first time against a real project, where `pytest`
    # created `.pytest_cache/.gitignore` and the reproduce phase refused the whole attempt.
    pristine = snapshot(worktree)

    # --- step 1 ---------------------------------------------------------------------------
    _run_agent(
        session, attempt, box, engine, Phase.REPRODUCE,
        test_path=manifest.test_path, lint=lint_ask,
    )
    try:
        candidate = collect_changes(
            worktree, pristine, allow_new_only_under=manifest.test_path
        )
    except UnsafePathError as exc:
        return Verdict(
            AttemptOutcome.FAILED,
            AttemptPhase.REPRODUCE,
            detail=f"the reproduce phase produced something it may not: {exc}",
        )
    if not candidate:
        return Verdict(
            AttemptOutcome.NOT_REPRODUCIBLE,
            AttemptPhase.REPRODUCE,
            detail="the agent wrote no test, so there is nothing to reproduce the bug with",
        )

    # --- step 2: the red gate ---------------------------------------------------------------
    red = _run_gate(session, attempt, box, AttemptPhase.RED_GATE, tests)
    if not red.ok:
        # Spec §3.1, closed. A non-zero exit is not a reproduction: it is also what a candidate that
        # does not import produces, and the dogfood produced both on the way to one pull request.
        # The signal that separates them is the survivors — a reproduction adds one failure and
        # leaves the previously-passing tests green.
        judged = testoutput.judge_red_gate(
            baseline.output, red.output, red_failed=not red.ok
        )
        if not judged.reproduced:
            return Verdict(
                AttemptOutcome.FAILED,
                AttemptPhase.RED_GATE,
                candidate=candidate,
                detail=f"the candidate test is not a reproduction: {judged.reason}",
            )
        # **One author for the caveat** (item 098). `judge_red_gate` already ends its reason with
        # "the claim rests on the exit code alone" when it could not read the output, and this
        # appended the same sentence in other words — so the first paragraph of `acme!9` said
        # it twice and read like a program that had lost its place. The flag stays, because the seal
        # and `status` both read it; what goes is the second author of the same words.
        log.info(
            "red gate satisfied",
            extra={"reason": judged.reason, "from_exit_code": judged.from_exit_code_alone},
        )
        red_reason = judged.reason
    if red.ok:
        # The whole rule. A test that passes against unmodified code has not reproduced anything;
        # it has described behaviour that already works.
        return Verdict(
            AttemptOutcome.NOT_REPRODUCIBLE,
            AttemptPhase.RED_GATE,
            candidate=candidate,
            detail=(
                "the candidate test passes against unmodified code, so it does not reproduce the "
                "bug — no fix was attempted (DR-0003)"
            ),
        )

    # --- step 3 ---------------------------------------------------------------------------
    _run_agent(
        session, attempt, box, engine, Phase.FIX,
        test_path=manifest.test_path, lint=lint_ask,
    )
    tampered = _restore_candidate(worktree, candidate.written)
    if tampered:
        return Verdict(
            AttemptOutcome.FAILED,
            AttemptPhase.FIX,
            candidate=candidate,
            detail=(
                f"the agent edited its own reproducing test during the fix phase ({tampered}). A "
                f"test the fix was allowed to change is not evidence about the fix."
            ),
        )
    try:
        changes = collect_changes(worktree, pristine)
    except UnsafePathError as exc:
        return Verdict(
            AttemptOutcome.FAILED,
            AttemptPhase.FIX,
            candidate=candidate,
            detail=f"the fix phase produced something it may not: {exc}",
        )

    # --- step 4: the green gate --------------------------------------------------------------
    green = _run_gate(session, attempt, box, AttemptPhase.GREEN_GATE, tests)

    # --- step 4a: and did it pass because it had switched the tests off? (item 046) ------------
    # `_restore_candidate` above covers the test the *reproduce* phase wrote. Nothing covered a test
    # file that already existed, and the cheapest version of that is one line in a pre-existing
    # `conftest.py`: `collect_ignore_glob = ['*']` makes pytest collect nothing, the suite passes
    # trivially, and the unconditional red-green claim gets published with the mechanism inside the
    # diff. Measured before this existed, on exactly that input.
    #
    # Both gates are kept rather than restoring before the first one, because the *difference* is
    # the finding: a suite that passes with the tampering and fails without it says the fix was
    # gaming the gate, which "the fix failed" on its own does not.
    restored = _restore_infrastructure(worktree, pristine)
    if restored:
        try:
            changes = collect_changes(worktree, pristine)
        except UnsafePathError as exc:  # pragma: no cover - the earlier collection raises first
            return Verdict(
                AttemptOutcome.FAILED,
                AttemptPhase.GREEN_GATE_RESTORED,
                candidate=candidate,
                detail=f"the restored tree could not be read back: {exc}",
            )
        regated = _run_gate(session, attempt, box, AttemptPhase.GREEN_GATE_RESTORED, tests)
        if not regated.ok:
            gamed = (
                ", so it passed only because it had disabled the tests"
                if green.ok
                else " and the suite does not pass either way"
            )
            return Verdict(
                AttemptOutcome.FAILED,
                AttemptPhase.GREEN_GATE_RESTORED,
                candidate=candidate,
                changes=changes,
                restored=restored,
                detail=(
                    f"the fix modified test infrastructure it may not have ({restored}) and the "
                    f"suite fails once that is put back{gamed}"
                ),
            )
    elif not green.ok:
        return Verdict(
            AttemptOutcome.FAILED,
            AttemptPhase.GREEN_GATE,
            candidate=candidate,
            changes=changes,
            detail="the suite does not pass with the change applied",
        )

    # --- step 5: lint, only if the manifest names the gate ------------------------------------
    lint_failed = ""
    if "lint" in manifest.autofix.gates and manifest.lint:
        lint = _run_gate(session, attempt, box, AttemptPhase.LINT_GATE, manifest.lint)
        if not lint.ok:
            # **Published, not discarded** (item 067). This returned `failed`, which is terminal
            # and publishes nothing — so an attempt that cleared the red gate *and* the green gate,
            # and therefore proved the product's entire claim, was thrown away over the style of
            # the file that proves it. Measured here: 67 model calls and ~25,000 output tokens,
            # discarded twice, both times for `Statement is unreachable`.
            #
            # The lint gate does not contest the claim, it contests the test's conformance, and a
            # reviewer fixes that in seconds. What it must never do is publish under `pr-open`: the
            # trail would say everything passed. Hence its own outcome, and the artefact leads with
            # the failure rather than tucking it behind a `<details>`.
            lint_failed = (
                f"The gate that failed is `{manifest.lint}`, run against the change below.\n"
                f"{failing_lines(lint.output) or lint.output[-2000:]}"
            )

    note = (
        f" This fix had also modified test infrastructure it may not have ({restored}); those "
        f"files were put back and the suite was run again, so the claim above rests on that "
        f"second run and the published change does not contain them."
        if restored
        else ""
    )
    return Verdict(
        AttemptOutcome.PR_OPEN_LINT_FAILED if lint_failed else AttemptOutcome.PR_OPEN,
        AttemptPhase.PUBLISH,
        candidate=candidate,
        changes=changes,
        restored=restored,
        detail=(
            # The lint failure comes **first** when there is one, because `pull_request_body` puts
            # this straight under the headline, and item 067's whole point is that the weakest part
            # of an artefact does not get to hide further down.
            f"{lint_failed}\n\n" if lint_failed else ""
        ) + (
            f"a test that failed against unmodified code passes with the change applied — "
            f"{red_reason}.{note}"
        ),
    )


#: How many failure lines a verdict carries. A suite with 2000 failures must not become the verdict,
#: and after a dozen the operator has the shape of it — the rest is in `attempt_steps.output`.
FAILURES_SHOWN = 12


def failing_lines(output: str, limit: int = FAILURES_SHOWN) -> str:
    """The lines a test runner uses to say what failed, and the count if there were more.

    Matched by prefix rather than parsed: every runner worth supporting prints a line per failure
    starting with something like `FAILED`, `FAIL`, `ERROR` or `not ok`, and a parser per runner is a
    promise this cannot keep. Anything unrecognised falls back to the tail of the output, because a
    tail is always better than the empty string this used to produce.
    """
    marks = ("FAILED ", "FAIL ", "ERROR ", "not ok ", "E   ", "✗ ")
    found = [line for line in output.splitlines() if line.startswith(marks)]
    if not found:
        tail = [line for line in output.splitlines() if line.strip()][-limit:]
        return "\nThe last of what it printed:\n" + "\n".join(tail) if tail else ""
    shown = found[:limit]
    more = f"\n… and {len(found) - limit} more" if len(found) > limit else ""
    return "\nWhat failed:\n" + "\n".join(shown) + more


def why_it_ended(result: RunResult) -> str:
    """The line that tells the three meanings of exit 137 apart. Item 023, closed by item 106.

    **Measured and then dropped.** `Sandbox._run` reads `OOMKilled` off the container's state and
    puts it on the result, and until this existed nothing read that field — so a memory limit, a
    timeout we caused and a process that died on its own all arrived in the trail as the same
    `137`, which is the number a reader would then look up and misattribute. The distinction costs
    one line and it is the difference between "your suite needs more memory" and "the agent hung".

    Prepended to the step's output rather than stored in a column of its own: this is a sentence a
    reader needs beside the output it explains, it is already scrubbed and bounded on that path, and
    a column would need a migration to say something the text can say better.
    """
    if result.out_of_memory:
        return (
            "hullwork: the container hit its memory limit and was killed (OOMKilled). Exit 137 "
            "here is the kernel, not the command — raise the sandbox's memory or make the phase "
            "use less.\n"
        )
    if result.timed_out:
        return (
            "hullwork: the command did not finish in time and Hullwork killed it. Exit 137 here "
            "is that kill, not the command's own verdict.\n"
        )
    if result.exit_code == 137:
        return (
            "hullwork: exit 137 with no memory limit hit and no timeout from here — the process "
            "was killed by something else on this host.\n"
        )
    return ""


def _run_gate(
    session: object, attempt: Attempt, box: Sandbox, phase: AttemptPhase, command: str
) -> RunResult:
    """Run one of the dispatcher's own commands and record it. Never the agent's.

    Through `run`, which has no route out — this command is the watched project's own, so it is
    untrusted code and it must not be able to reach the gateway (item 058).
    """
    result = box.run(command, timeout=GATE_TIMEOUT_SECONDS)
    attempts.record(
        session,  # type: ignore[arg-type]
        attempt,
        phase,
        command,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        output=why_it_ended(result) + result.output,
        # **Empty, and recorded as empty** (item 106, part 6). `run` adds nothing, and that is
        # precisely what a reviewer needs beside an agent phase that does — item 099 was the two
        # differing without anything in the trail able to show it. `None` here would mean "not
        # recorded", which would be a different and untrue statement.
        environment={},
    )
    if result.timed_out:
        # Not the agent's verdict to lose: a gate that ran out of time says nothing about whether
        # the bug is reproducible.
        raise Abandoned(f"the {phase.value} command did not finish in time", phase)
    return result


def reproduction_filename(item_id: int) -> str:
    """What the agent's reproducing test is called, derived from the item it is about.

    A fixed name is a file two attempts fight over. Derived from the item id — which is short,
    stable, unique per item, and already in every log line about the attempt — so the tests
    accumulated by a repository read as a record: one file per bug Hullwork has ever reproduced.

    Not the fingerprint: it is a 64-character hex digest, and a filename nobody can say out loud is
    a filename nobody will reference in a review.
    """
    return f"test_hullwork_item_{item_id}.py"


def _run_agent(
    session: object,
    attempt: Attempt,
    box: Sandbox,
    engine: Engine,
    phase: Phase,
    *,
    test_path: str = "tests",
    lint: str = "",
) -> AgentReport:
    """Run one agent phase. Its exit code decides nothing; the gates do.

    `test_path` is part of the contract rather than something the image guesses. The dispatcher is
    the only party that has read the manifest, and an agent that writes its test somewhere the
    reproduce phase will not accept has spent the item's one attempt on a misunderstanding — which
    is what happened on the first real run.
    """
    mapped = AttemptPhase.REPRODUCE if phase is Phase.REPRODUCE else AttemptPhase.FIX
    command = " ".join(engine.argv(phase))
    filename = reproduction_filename(attempt.item_id)
    # **Built once and both used and recorded** (item 106, part 6). Passed to the phase and then
    # written to the trail from the same object, because two expressions of "the environment this
    # ran in" is how a trail comes to describe a run that did not happen.
    environment = {
        "HULLWORK_AGENT_PHASE": phase.value,
        "HULLWORK_AGENT_TEST_PATH": test_path,
        # **Named per item, not `test_regression.py`** (item 094). The first merged fix landed as
        # `tests/test_regression.py`, and the next attempt on any item would have been told to
        # write the same path — overwriting the evidence for a fix already merged, which is the one
        # file in the change nobody is allowed to edit. Both phases are told the same name, from
        # the same function, because a fix phase looking for a file the reproduce phase did not
        # write is the misunderstanding this environment variable exists to prevent.
        "HULLWORK_AGENT_TEST_FILE": filename,
        # Item 064: what the agent's own output will be judged by, when the manifest declares that
        # gate. Empty when it does not, so the brief never names a command nobody runs.
        "HULLWORK_AGENT_LINT": lint,
        "HULLWORK_AGENT_MAX_TURNS": str(engine.max_turns),
        # Item 139: the harness's own variables **and** the ones that tell it which model to ask
        # for, from one function. Before this the pin never left the gateway, so the harness asked
        # for its default — invisible against the provider whose default it is, and the reason no
        # other provider could actually be selected.
        **engine.phase_env(),
    }
    # The only two phases that get a route to the gateway, and the only place that asks for one
    # (item 058). `_run_gate` uses `run`, which has none.
    result = box.run_with_model(command, timeout=AGENT_TIMEOUT_SECONDS, env=environment)
    attempts.record(
        session,  # type: ignore[arg-type]
        attempt,
        mapped,
        command,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        output=why_it_ended(result) + result.output,
        environment=environment,
    )
    if result.timed_out:
        raise Abandoned(f"the agent's {phase.value} phase did not finish in time", mapped)
    # From the contract directory, never the worktree: a report written next to the source would be
    # indistinguishable from the agent's work, and the reproduce phase would refuse the attempt over
    # our own file. Found by running it.
    report_file = (
        (box.contract_dir / Path(REPORT_PATH).name) if box.contract_dir else None
    )
    text = (
        report_file.read_text(encoding="utf-8", errors="replace")
        if report_file and report_file.exists()
        else ""
    )
    return AgentReport.parse(text)


def _restore_candidate(worktree: Path, candidate: dict[str, bytes]) -> str:
    """Put the reproducing test back exactly as it was, and say if it had been changed.

    Step 3 gives the agent the source and **not** its own test. A test the fix was allowed to edit
    proves nothing about the fix — the easiest way to make a failing test pass is to change the
    test. Restoring rather than merely detecting means the green gate runs against the same test
    the red gate ran against, which is the comparison the whole claim rests on.
    """
    changed: list[str] = []
    for path, original in candidate.items():
        target = worktree / path
        if not target.exists() or target.read_bytes() != original:
            changed.append(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(original)
    return ", ".join(sorted(changed))


def _restore_infrastructure(worktree: Path, pristine: dict[str, bytes]) -> str:
    """Put back any **pre-existing** test infrastructure the fix phase changed, and say which.

    Pre-existing is the whole distinction, and it is why this iterates the snapshot rather than the
    tree: a fix that *adds* a test is welcome and its new file is not in `pristine`, so it is never
    touched. What is refused is editing or deleting the files that decide whether the suite runs.

    The scope comes from `is_test_infrastructure`, which belongs to the instance. It deliberately is
    not the manifest's `test_path`: that field arrives from the watched repository, and it already
    pulls the other way — narrowing it tightens the reproduce-phase guard while loosening this one.
    """
    restored: list[str] = []
    for path, original in pristine.items():
        if not is_test_infrastructure(path):
            continue
        target = worktree / path
        if target.exists() and target.read_bytes() == original:
            continue
        restored.append(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(original)
    return ", ".join(sorted(restored))


def prepare_worktree(source: Path) -> Path:
    """A throwaway copy for one attempt, without the git directory.

    `.git` is left behind rather than copied: the agent gets history only if the caller chose to
    give it, and a worktree with no repository in it cannot grow a hook that runs on the host.
    """
    destination = Path(tempfile.mkdtemp(prefix="hullwork-attempt-"))
    shutil.copytree(source, destination, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git"))
    return destination


#: The contract directory has to be readable *and writable* by the container's user: the brief goes
#: in and the agent's report comes out. It is a per-attempt temporary directory holding a scrubbed
#: brief and a report `engine.py` documents as "trusted for nothing", so the widest mode is the
#: cheapest correct answer — a `chown` needs the dispatcher to be root, which is the wall items 054
#: and 055 both met. Found by running it: `EACCES: permission denied, open /hullwork/brief.md`.
CONTRACT_DIR_MODE = 0o777


def build_brief_file(session: object, item: Item, contract_dir: Path) -> Path:
    """Write the brief where the contract says the image will look for it.

    Into the contract directory, not the worktree. The brief is Hullwork's input to the agent, not
    a change to the repository, and putting it in the tree made it look like one.
    """
    contract_dir.chmod(CONTRACT_DIR_MODE)
    target = contract_dir / Path("brief.md")
    target.write_text(brief.build(session, item), encoding="utf-8")  # type: ignore[arg-type]
    target.chmod(0o644)
    return target
