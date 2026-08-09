"""The six things closed items still owed. Item 106.

**Why one file for six unrelated properties.** They have one thing in common and it is the point of
the item: in every case *the behaviour was built and the test that would catch it coming back was
not*. Four of the six said so inside a `status: done` file, in their own words — *"STILL OWED"*,
*"STILL OPEN"*, *"Owed to the"*, *"Not done"* — which is honest of the author and is also how a
closed item comes to owe something. Keeping them together makes the audit checkable; each test says
which item it belongs to.

Three of them can only be answered by a real daemon and are skipped without one, on the same terms
as `test_sandbox_docker.py`: an argv assertion cannot see what the kernel did. They were run against
the daemon in production, and each test's docstring says what it measured there.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from hullwork import attempts, dispatch, evidence, work
from hullwork.attempts import start
from hullwork.engine import Engine
from hullwork.manifest import parse_manifest
from hullwork.models import Attempt, AttemptPhase, Item, Lane, Project
from hullwork.sandbox import inventory

# --- part 6: the trail says which environment a phase ran in (item 099) ----------------------

MANIFEST_WITH_LINT = """
project: p
git: {provider: forgejo, repo: o/r}
tests: pytest
lint: ruff check .
test_path: tests
autofix:
  agent: claude-code
  gates: [tests, lint, human-merge]
  lanes: {green: ['*']}
runtime: {base: python-3.12, install: none}
"""

ENGINE = Engine(name="fake", image="img", protocol="anthropic", command="agent {phase}")


class Box:
    """The container, scripted. Records the environment each command was given."""

    #: Whether the container reports having been OOM-killed. Item 023's third meaning of 137.
    oom = False

    def __init__(self, worktree: Path, script: dict[str, int], outputs: dict[str, str]) -> None:
        self.worktree = worktree
        self.contract_dir = worktree / "_contract"
        self.contract_dir.mkdir(exist_ok=True)
        self.script = script
        self.outputs = outputs
        self.counts: dict[str, int] = {}

    def run(self, command: str, timeout: int, env: dict[str, str] | None = None) -> object:
        del timeout
        assert env is None or env == {}, "a gate is run with nothing added; that is item 099"
        return self._result(command)

    def run_with_model(
        self, command: str, timeout: int, env: dict[str, str] | None = None
    ) -> object:
        del timeout, env
        if "reproduce" in command:
            (self.worktree / "tests").mkdir(exist_ok=True)
            (self.worktree / f"tests/test_hullwork_item_{ITEM_ID}.py").write_text(
                "def test_x():\n    assert False\n"
            )
        return self._result(command)

    def _result(self, command: str) -> object:
        from hullwork.sandbox.run import RunResult

        nth = self.counts.get(command, 0)
        self.counts[command] = nth + 1
        code = self.script.get(f"{command}#{nth}", self.script.get(command, 0))
        printed = self.outputs.get(f"{command}#{nth}", self.outputs.get(command, "out"))
        return RunResult(
            command=command, exit_code=code, output=printed, duration_ms=1,
            out_of_memory=self.oom and code == 137,
        )


ITEM_ID = 1



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


def _attempt_with_a_failing_lint_gate(
    session: Session, item: Item, tmp_path: Path
) -> tuple[dispatch.Verdict, Attempt]:
    """A whole attempt: baseline green, red gate red, green gate green, lint gate failing."""
    (tmp_path / "src.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir(exist_ok=True)
    box = Box(
        tmp_path,
        script={"pytest#1": 1, "ruff check .": 1},
        outputs={"ruff check .": "tests/test_x.py:3:5: F821 undefined name `nope`\n"},
    )
    attempt = start(session, item)
    verdict = dispatch.dispatch(
        session, item, parse_manifest(MANIFEST_WITH_LINT), ENGINE,
        box=box,  # type: ignore[arg-type]
        attempt=attempt,
    )
    return verdict, attempt


def test_each_phase_records_the_environment_it_ran_under(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """**Item 099's owed half.** That item fixed *which* environment a phase gets — five variables
    had been sitting inside the namespace the watched project validates, so the project's own suite
    failed whenever Hullwork's agent ran it.

    What no reviewer could do afterwards is see it. The trail recorded the command, the exit code
    and the output, never the environment — so the defect's whole shape, *the gate and the agent's
    phase ran in different environments*, left no trace in the one artefact anybody reads.
    """
    _, attempt = _attempt_with_a_failing_lint_gate(session, item, tmp_path)
    steps = attempt.steps

    by_phase = {step.phase: step for step in steps}
    agent = by_phase[AttemptPhase.REPRODUCE]
    gate = by_phase[AttemptPhase.BASELINE]

    assert agent.environment is not None, "an agent phase is given variables; the trail must say so"
    given = json.loads(agent.environment)
    assert given["HULLWORK_AGENT_PHASE"] == "reproduce"
    assert all(name.startswith("HULLWORK_AGENT_") or name.isupper() for name in given)
    # The asymmetry item 099 was about, now visible in the trail rather than only in the source.
    assert json.loads(gate.environment or "null") == {}


def test_nothing_recorded_and_nothing_added_are_different_answers(session: Session) -> None:
    """`—` is not `clean`, and conflating them is item 105's defect in the reviewer's own view.

    A step from before this column existed knows nothing about its environment. A gate knows
    something: that nothing was added. An artefact that renders both the same way invites a reader
    to conclude a measurement was taken when it was not.
    """
    assert attempts._environment(None) is None
    assert attempts._environment({}) == "{}"


def test_a_variable_that_looks_like_a_secret_is_scrubbed_by_name(session: Session) -> None:
    """Nothing Hullwork passes to a phase is a credential today — DR-0004 puts the model
    credential in the gateway, and the engine recipe carries a deliberate placeholder.

    This column is written from a dict somebody will add to, and it ends up in a pull request body.
    Scrubbed through `scrub.is_secret_name`, the rule the log filter already uses, so the sixth
    variable is covered by the same sentence as the first five — a list of five names nobody
    updated is precisely how item 099 happened.
    """
    stored = attempts._environment(
        {"HULLWORK_AGENT_PHASE": "fix", "SOMETHING_TOKEN": "sk-live-not-in-the-artefact"}
    )

    assert stored is not None
    assert "sk-live-not-in-the-artefact" not in stored
    assert json.loads(stored)["HULLWORK_AGENT_PHASE"] == "fix"


def test_the_artefact_shows_the_environment_where_a_reviewer_looks(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """In the step table, not in a footnote. The criterion asks for the place *"a reviewer deciding
    whether to trust a result will look"*, and that is the table they already read."""
    _, attempt = _attempt_with_a_failing_lint_gate(session, item, tmp_path)

    body = evidence.pull_request_body(item, attempt)

    assert "| Environment |" in body
    assert "clean" in body, "a gate that got nothing added has to say so"
    assert "`HULLWORK_AGENT_PHASE`" in body


# --- part 3: a rehearsal whose lint gate fails writes a local artefact (item 067) -------------


def test_a_rehearsal_with_a_failing_lint_gate_names_the_lint_output(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """**The half of item 067 that was never exercised.**

    That item made a failed lint gate *publish* rather than discard a verified fix, and the
    published path is tested. The rehearsal path — `--no-publish`, which writes to disk instead of
    the forge — is the one an evaluator uses first, under DR-0006, precisely because it needs no
    credential that can write anywhere. An artefact that dropped the lint failure there would tell
    the one reader we most want to convince that everything passed.
    """
    verdict, attempt = _attempt_with_a_failing_lint_gate(session, item, tmp_path)
    into = tmp_path / "rehearsals"

    written = work.write_locally(into)(item, attempt, verdict)

    assert written is not None
    artefact = (Path(written) / "artefact.md").read_text(encoding="utf-8")
    assert "ruff check ." in artefact, "the gate that failed has to be named"
    assert "F821 undefined name" in artefact, "and its output, not just the fact that it failed"
    # Item 067's shape rule: the weakest part of the artefact does not get to hide further down.
    assert artefact.index("ruff check .") < artefact.index("### What ran")


# --- item 023: the three meanings of exit 137 -------------------------------------------------


def test_the_three_meanings_of_exit_137_are_told_apart() -> None:
    """**Measured and then dropped, until this.** `Sandbox._run` reads `OOMKilled` off the
    container's state and puts it on the result — and nothing in the codebase read that field, so a
    memory limit, a timeout Hullwork caused and a process killed by something else all reached the
    trail as the same `137`.

    A reader who looks that number up finds "SIGKILL" and guesses which of the three it was. The
    guess is the defect: *"your suite needs more memory"* and *"the agent hung"* send an operator to
    different places.
    """
    from hullwork.sandbox.run import RunResult

    def result(**kwargs: object) -> RunResult:
        return RunResult(command="pytest", exit_code=137, output="", duration_ms=1, **kwargs)  # type: ignore[arg-type]

    # **Asserted on a token unique to each branch**, which the first version of this test was not:
    # every one of the three sentences contains the words "memory limit", so disabling the OOM
    # branch left the fallback satisfying the assertion. Found by reintroducing the defect, which
    # is the entire reason that discipline exists.
    assert "OOMKilled" in dispatch.why_it_ended(result(out_of_memory=True))
    assert "Hullwork killed it" in dispatch.why_it_ended(result(timed_out=True))
    assert "killed by something else" in dispatch.why_it_ended(result())
    # And the ordinary case says nothing at all: a line on every step is a line nobody reads.
    ordinary = RunResult(command="pytest", exit_code=1, output="F", duration_ms=1)
    assert dispatch.why_it_ended(ordinary) == ""


def test_the_reason_reaches_the_trail_and_not_only_the_verdict(
    session: Session, item: Item, tmp_path: Path
) -> None:
    """In the step's own output, beside the output it explains. The criterion says *"in the
    evidence trail"*, and a distinction that lives in a local variable is not in it."""
    (tmp_path / "src.py").write_text("x = 1\n")
    box = Box(tmp_path, script={"pytest": 137}, outputs={"pytest": "Killed\n"})
    box.oom = True
    attempt = start(session, item)

    dispatch.dispatch(
        session, item, parse_manifest(MANIFEST_WITH_LINT), ENGINE,
        box=box,  # type: ignore[arg-type]
        attempt=attempt,
    )

    baseline = next(step for step in attempt.steps if step.phase is AttemptPhase.BASELINE)
    assert "OOMKilled" in baseline.output
    assert "Killed" in baseline.output, "the command's own output is still there"


# --- part 4: a stop leaves no orphans (item 097) ----------------------------------------------


def test_a_content_addressed_cache_is_not_debris(monkeypatch: pytest.MonkeyPatch) -> None:
    """**The distinction that cost a measurement.** `hullwork-harness-*` volumes carry a Hullwork
    name and belong to no running attempt, which is what debris looks like from the outside. They
    are a cache keyed by the harness image, binary, installer and entrypoint, shared across attempts
    on purpose.

    Reaping them would be harmless, correct-looking and wrong: every first attempt after a restart
    would rebuild a bundle for nothing. The credential-bearing volume is `hullwork-wire-*`, and
    that is the one that has to go.
    """
    monkeypatch.setattr(
        inventory, "_run",
        lambda argv: {
            "volume": "hullwork-wire-abc\nhullwork-harness-7f764fa8b322\nhullwork-worktree-abc\n",
            "network": "hullwork-attempt-abc\nbridge\n",
            "ps": "hullwork-cable-abc\nhullwork-api-1\n",
        }[argv[1] if argv[1] != "ps" else "ps"],
    )

    found = inventory.find()

    assert found.volumes == ["hullwork-wire-abc", "hullwork-worktree-abc"]
    assert "hullwork-harness-7f764fa8b322" not in found.volumes
    assert found.networks == ["hullwork-attempt-abc"]
    assert found.containers == ["hullwork-cable-abc"]
    assert "holding a model credential" in found.summary()


def test_a_name_that_merely_contains_ours_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Docker's own `--filter name=` is a substring match, which is why the filtering is here.

    A project volume called `backup-hullwork-wire-archive` is not ours, and a reaper that removes by
    substring is one unlucky name away from deleting somebody's data.
    """
    monkeypatch.setattr(
        inventory, "_run",
        lambda argv: "backup-hullwork-wire-archive\nmy-hullwork-attempt-notes\n",
    )

    found = inventory.find()

    assert not found
    assert found.summary().startswith("0 container(s)")


def test_a_daemon_that_cannot_be_asked_reports_nothing_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Teardown that can fail is teardown that leaves a network holding a route on somebody's host
    — `Cable.close`'s rule, and the same applies to the thing that cleans up after it. A dispatcher
    must not refuse to start because the reaper could not run."""
    monkeypatch.setattr(inventory, "_run", lambda argv: None)

    assert not inventory.find()
    assert not inventory.reap()


def test_the_doctor_does_not_claim_a_clean_host_it_could_not_look_at() -> None:
    """Item 105's lesson, third application. On the receiver there is no Docker socket by design,
    so "nothing was left behind" would be a claim about a host this process cannot see."""
    from hullwork import doctor

    finding = doctor.nothing_was_left_behind("docker", asked=False)

    assert finding.state is doctor.State.UNKNOWN
    assert "not asked" in finding.detail


# --- what only a real daemon can answer -------------------------------------------------------

needs_docker = pytest.mark.skipif(
    shutil.which("docker") is None
    or subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],  # noqa: S607
        capture_output=True, timeout=30, check=False,
    ).returncode != 0,
    reason="needs a reachable Docker daemon; run on the deployment host",
)

#: A daemon is not enough for the tests that start a **gateway**: that runs the project's own image,
#: which no test builds. Found on 2026-08-04 by a clone whose `hullwork:dev` had been removed —
#: `docker compose build` had made it in some earlier session and nothing recorded the dependency,
#: so the test failed rather than skipped, with a message about the gateway rather than the image.
#:
#: **And the instruction went stale under it** (item 191, 2026-08-09). `docker-compose.yml` now pins
#: a published image and has no build stage — its own comment says to *add* one — so
#: `docker compose build` exits 0 and produces nothing. Measured while chasing this exact skip.
#:
#: A skip with a reason, not a build: building it here would put minutes into an unrelated test run
#: and hide the same gap. Saying what is missing is the honest answer, and the error that exposed
#: this now prints Docker's own words, which is how it was diagnosed in one read.
needs_image = pytest.mark.skipif(
    # **`shutil.which` first, and leaving it out broke the project's own baseline.** This runs at
    # import time, and `subprocess.run` on a missing binary raises `FileNotFoundError` rather than
    # returning non-zero — so in any environment without the docker client, *collection* of this
    # module died and the whole suite was red. `needs_docker` above guards the same way and this
    # copied its shape without its first clause.
    #
    # Measured on 2026-08-04 by the product itself: a real `hullwork try` run refused to attempt
    # anything with `baseline-red`, because the suite it was asked to hold constant would not even
    # collect inside the sandbox — where there is deliberately no docker client. The gate was right,
    # it cost no model call, and it found a defect introduced hours earlier on a host where `docker`
    # happens to exist.
    shutil.which("docker") is None
    or subprocess.run(
        ["docker", "image", "inspect", "hullwork:dev"],  # noqa: S607
        capture_output=True, timeout=30, check=False,
    ).returncode
    != 0,
    reason="needs the hullwork:dev image; build it with `docker build --tag hullwork:dev .`",
)


def _docker(*argv: str) -> str:
    done = subprocess.run(  # noqa: S603
        ["docker", *argv], capture_output=True, text=True, timeout=120, check=False  # noqa: S607
    )
    return done.stdout


def _exists(kind: str, name: str) -> bool:
    return name in _docker(kind, "ls", "--format", "{{.Name}}").split()


@needs_docker
def test_the_volume_is_removed_even_when_a_phase_raises(tmp_path: Path) -> None:
    """**Item 055's owed test.** The `finally` exists and item 095 hardened the path around it;
    nothing failed if somebody moved the cleanup out of it.

    By effect, as the criterion demands: `docker volume ls` before and after, not a mock of the
    remover. The structure mirrors production exactly — `stack.callback(sandbox.cleanup)` registered
    **before** the volume is seeded, so a failure while seeding still takes the volume with it.
    """
    from contextlib import ExitStack

    from hullwork.sandbox.run import Sandbox

    (tmp_path / "src.py").write_text("x = 1\n")
    name = f"hullwork-worktree-owed{ITEM_ID}"
    sandbox = Sandbox(image="alpine:3", worktree=tmp_path)

    with pytest.raises(RuntimeError), ExitStack() as stack:
        stack.callback(sandbox.cleanup)
        sandbox.ensure_volume(name)
        assert _exists("volume", name), "the volume has to exist for its removal to mean anything"
        msg = "the phase raised"
        raise RuntimeError(msg)

    assert not _exists("volume", name)


@needs_docker
@needs_image
def test_the_journal_comes_back_whole_when_the_gateway_dies(tmp_path: Path) -> None:
    """**Item 054's owed test.** The journal is the only channel out of the sandbox since that
    item put the gateway in a container, so a gateway that dies mid-attempt must not take the
    evidence with it.

    By effect: the *event*, not the file's existence. The recorded call here is a refused path,
    which the gateway journals without needing an upstream to answer — so this measures the
    survival of the recording rather than a model round trip.

    Measured in production: the call is journaled, `docker kill` takes the gateway, and
    `recording()` still reads it back — because `_pull_journal` reaches the volume through its own
    carrier container rather than through the gateway.
    """
    from hullwork.sandbox.net import Cable

    with Cable(
        upstream="http://127.0.0.1:9/never-answers", credential="not-a-real-key",
        work_dir=tmp_path, suffix=f"owed{ITEM_ID}",
    ) as cable:
        refused = "/v1/a-path-the-gateway-will-not-forward"
        _docker(
            "run", "--rm", "--network", cable.network, "alpine:3",
            "wget", "-q", "-O-", "--post-data", "{}", f"{cable.url}{refused}",
        )
        assert _docker("ps", "--format", "{{.Names}}").count(cable.container) == 1

        _docker("kill", cable.container)

        recording = cable.recording(endpoint="http://127.0.0.1:9/never-answers")
        assert refused in recording.refused, (
            "what the gateway recorded before it died has to survive it"
        )


@needs_docker
def test_reaping_removes_a_real_volume_and_a_real_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Item 097's inventory claim**, by listing them, which is the operator's standing rule.

    Named as an attempt would name them, and created here rather than by interrupting a real
    attempt: a test that has to kill a dispatcher mid-run to produce debris is a test nobody runs.
    What is being asserted is that the reaper removes exactly this shape of object.

    **This test was wrong in two ways until 2026-08-04, and a stranger evaluating the product found
    both** — on a machine that had Docker, which is where this suite is red and CI is green, because
    CI declares no Docker service and `needs_docker` skips.

    It created its debris **unlabelled**, so item 125's reaper ignored it exactly as it should and
    the assertion could not pass. The shape an attempt leaves behind carries `hullwork.instance`;
    an object without one belongs to another instance or to nobody, and refusing to delete those is
    the whole of item 125. So the label comes from `label_args()` rather than a literal, and cannot
    drift from what production writes.

    And it **leaked on failure**. Docker state is host-global, so the debris outlived the run — and
    both objects shared the `owed1` suffix with the Cable in the test above, which then failed too,
    on the next run, for a reason that was never its own. One defect produced two red tests and a
    false accusation, and it crossed checkouts: a fresh clone inherited debris from this one. Hence
    the distinct suffix, and the `finally` that runs even when an assertion does not.

    The instance label is a **test-only value**, so `reap()` here cannot reach a live instance's
    attempt on the same host. `instance_id()` reads the environment directly (see its docstring), so
    scoping this costs no production seam.
    """
    del tmp_path
    monkeypatch.setenv("HULLWORK_INSTANCE", f"owed-reap{ITEM_ID}")
    volume, network = f"hullwork-wire-reap{ITEM_ID}", f"hullwork-attempt-reap{ITEM_ID}"
    try:
        _docker("volume", "create", *inventory.label_args(), volume)
        _docker("network", "create", "--internal", *inventory.label_args(), network)
        assert _exists("volume", volume)
        assert _exists("network", network)

        reaped = inventory.reap()

        assert volume in reaped.volumes
        assert network in reaped.networks
        assert not _exists("volume", volume)
        assert not _exists("network", network)
    finally:
        # Host-global state: what this leaves behind poisons the next run, in this checkout or any
        # other. Unconditional, and ignoring failure, because reap has usually already done it.
        _docker("volume", "rm", "--force", volume)
        _docker("network", "rm", network)
