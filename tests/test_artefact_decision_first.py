"""The artefact leads with what decides it. Item 116.

**Measured before any of this existed**, on the four pull requests Hullwork has actually opened,
read back from the forge: 216 to 232 lines each, of which the facts a merge turns on — which test
reproduces the bug, that the rest of the suite kept passing, that both pass after the fix — sat in
*the fourth of seven identically-shaped collapsed blocks*, below eleven lines of progress dots.

Nothing here is about length for its own sake. Every byte that was published is still published;
what changes is that the reader is not asked to go and find the decision. The fixtures below are
the real shapes: pytest's summary wrapped in a rule of `=`, an agent phase whose output is its
harness's JSON, and a suite that prints migration logs *after* its own verdict.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from hullwork import evidence, testoutput
from hullwork.attempts import finish, record, start
from hullwork.models import Attempt, AttemptOutcome, AttemptPhase, Item, Lane, Project

#: pytest, as it really prints: dots, a rule, the failure, and the machine-readable summary.
RED_OUTPUT = """\
........................................................................ [ 47%]
...............................FF....................................... [ 63%]
........................................................................ [ 95%]
=================================== FAILURES ===================================
___________ test_teardown_does_not_raise_when_docker_is_not_on_path ____________
E           SandboxError: '/nonexistent/docker' is not on PATH
=========================== short test summary info ============================
FAILED tests/test_regression.py::test_teardown_does_not_raise_when_docker_is_not_on_path
FAILED tests/test_regression.py::test_the_failure_that_escapes_is_the_one_that_happened
========================= 2 failed, 904 passed in 57.02s =======================
"""

BASELINE_OUTPUT = """\
........................................................................ [ 50%]
........................................................................ [100%]
========================= 904 passed in 61.26s (0:01:01) =======================
"""

GREEN_OUTPUT = """\
........................................................................ [100%]
========================= 906 passed in 57.71s =================================
"""

#: What an agent phase leaves behind: the harness's transcript, cut mid-token when stored.
AGENT_OUTPUT = (
    '…chRequests":0,"costUSD":1.8440562499999997,"contextWindow":1000000,'
    '"maxOutputTokens":64000,"canonicalModel":"claude-opus-5"}'
)



@pytest.fixture
def item(session: Session) -> Item:
    project = Project(slug="p", forge="forgejo", repo="o/r", webhook_secret_hash="x")  # noqa: S106
    session.add(project)
    session.flush()
    row = Item(
        project_id=project.id, fingerprint="fp", lane=Lane.GREEN,
        title="SandboxError: '/nonexistent/docker' is not on PATH", forge_issue_ref="#9",
    )
    session.add(row)
    session.flush()
    return row


def _attempt(
    session: Session,
    item: Item,
    *,
    red: str = RED_OUTPUT,
    baseline: str = BASELINE_OUTPUT,
) -> Attempt:
    """One realistic `pr-open` attempt: six steps, two of them an agent's transcript."""
    attempt = start(session, item, base_sha="586e4d3", image_tag="hullwork-sandbox:d85c07")
    record(session, attempt, AttemptPhase.BASELINE, "pytest", exit_code=0, output=baseline,
           duration_ms=63_200)
    record(session, attempt, AttemptPhase.REPRODUCE, "hullwork-agent --phase reproduce",
           exit_code=0, output=AGENT_OUTPUT, duration_ms=378_100)
    record(session, attempt, AttemptPhase.RED_GATE, "pytest", exit_code=1, output=red,
           duration_ms=59_000)
    record(session, attempt, AttemptPhase.FIX, "hullwork-agent --phase fix", exit_code=0,
           output=AGENT_OUTPUT, duration_ms=172_100)
    record(session, attempt, AttemptPhase.GREEN_GATE, "pytest", exit_code=0, output=GREEN_OUTPUT,
           duration_ms=60_000)
    record(session, attempt, AttemptPhase.LINT_GATE, "ruff check . && mypy .", exit_code=0,
           output="All checks passed!", duration_ms=18_900)
    return finish(session, attempt, AttemptOutcome.PR_OPEN, seal={"precision": "undisclosed"})


def test_the_decision_is_in_the_first_screen(session: Session, item: Item) -> None:
    """**The item, in one assertion.** A reviewer decides on three facts, and before this they
    were on line ~140 of 233, inside a block they had to know to open.

    Twenty-five lines is not an aesthetic budget: it is roughly what a forge shows above the diff,
    which is the only part of the body many reviewers ever read.
    """
    body = evidence.pull_request_body(item, _attempt(session, item))
    first_screen = "\n".join(body.splitlines()[:25])

    assert "test_teardown_does_not_raise_when_docker_is_not_on_path" in first_screen
    assert "2 failed, 904 passed in 57.02s" in first_screen, "the red gate's own words"
    assert "906 passed in 57.71s" in first_screen, "and the green gate's"
    assert "exit `1`" in first_screen and "exit `0`" in first_screen


def test_a_runner_nobody_here_has_met_says_so_instead_of_implying_nothing_failed(
    session: Session, item: Item
) -> None:
    """**DR-0007 means this is the common case, not the exotic one.** Most projects run a test
    runner this repository has never parsed, and an artefact that silently omits the row reads as
    "no test was named" — a claim nobody made, in the sentence a reviewer trusts most.
    """
    exotic = "Running 42 specs\nSPEC FAILED: totals must not be negative\n1 failure, 41 ok\n"

    body = evidence.pull_request_body(item, _attempt(session, item, red=exotic))

    assert "does not name its failures in a shape Hullwork reads" in body
    assert "Reproduced by" in body, "the row is present and honest, not absent"
    # And what the runner *did* say still carries the claim.
    assert "1 failure, 41 ok" in body


def test_every_gate_states_its_verdict_without_being_expanded(
    session: Session, item: Item
) -> None:
    """A forge collapses `<details>`. Verdicts that live only inside them ask a reviewer to open
    six blocks to learn six numbers that fit on six lines."""
    body = evidence.pull_request_body(item, _attempt(session, item))

    summaries = [line for line in body.splitlines() if line.startswith("<details><summary>")]
    gates = [line for line in summaries if "gate</code>" in line or "baseline</code>" in line]
    assert len(gates) == 4
    assert any("904 passed in 61.26s" in line for line in gates)
    assert any("2 failed, 904 passed in 57.02s" in line for line in gates)


def test_an_agent_phase_is_labelled_rather_than_given_a_fake_verdict(
    session: Session, item: Item
) -> None:
    """**The defect the first version of this shipped.** Reading a verdict off an agent phase put
    120 characters of `{"is_error":false,"duration_api_ms":…}` where a reviewer reads a
    measurement. A summary that looks like a verdict and is a stream position is worse than none.
    """
    body = evidence.pull_request_body(item, _attempt(session, item))

    agent = [
        line for line in body.splitlines()
        if line.startswith("<details><summary>") and "reproduce</code>" in line
    ]
    assert agent == [
        "<details><summary><code>reproduce</code> output — the agent's own transcript, as its "
        "harness printed it</summary>"
    ]
    # The transcript itself is still published, untouched.
    assert "costUSD" in body


def test_progress_lines_go_and_the_removal_is_stated(session: Session, item: Item) -> None:
    """Eleven of them sat above the failure a reviewer had come to read.

    **Stated, never silent**: this text is the record of what a command printed, and evidence
    edited without saying so is not evidence.
    """
    body = evidence.pull_request_body(item, _attempt(session, item))

    assert "[ 47%]" not in body and "[100%]" not in body
    assert "… [3 progress line(s) omitted] …" in body, "the red gate had three"
    # Everything that was not a progress bar survives, character for character.
    for kept in ("FAILURES", "SandboxError: '/nonexistent/docker' is not on PATH",
                 "short test summary info", "904 passed in 61.26s"):
        assert kept in body


def test_a_verdict_survives_a_suite_that_keeps_printing_after_it(
    session: Session, item: Item
) -> None:
    """**Measured on `acme#6`**: twelve kilobytes of alembic migration logs after pytest's
    summary, so counts read from the last 4,000 characters came back empty from a run that had
    said `249 passed` in plain sight — and the row would have vanished from the table.

    Long lines, few of them: exactly the shape that defeats a character-window and not a line one.
    """
    noisy = BASELINE_OUTPUT + "\n".join(
        f"INFO  [alembic.runtime.migration] Running upgrade {n:04d} -> {n + 1:04d}, {'x' * 1000}"
        for n in range(12)
    )
    assert len(noisy) > 4_000 and len(noisy.splitlines()) < 40, "the shape that was measured"

    body = evidence.pull_request_body(item, _attempt(session, item, baseline=noisy))

    assert "| The suite before any change | exit `0` as it must — `904 passed in 61.26s" in body


def test_the_runners_own_words_verbatim_minus_its_decoration() -> None:
    """The summary line is quoted, so it is the runner's sentence and not ours. What comes off is
    the rule of `=` pytest draws around it, which is decoration and not a word."""
    assert testoutput.verdict_line(
        "=========== 2 failed, 249 passed, 16 warnings in 63.68s (0:01:03) ==========="
    ) == "2 failed, 249 passed, 16 warnings in 63.68s (0:01:03)"
    assert testoutput.verdict_line("no summary here\njust prose\n") is None
    assert testoutput.verdict_line("....... [100%]") is None, "a progress bar is not a verdict"


def test_failing_test_names_are_read_from_shapes_that_cannot_be_prose() -> None:
    """Four runners, and the reason the list is short: a wrong name in a pull request body sends a
    reviewer to a test that has nothing to do with the change, which is worse than no name."""
    assert testoutput.failing_tests(RED_OUTPUT) == [
        "tests/test_regression.py::test_teardown_does_not_raise_when_docker_is_not_on_path",
        "tests/test_regression.py::test_the_failure_that_escapes_is_the_one_that_happened",
    ]
    assert testoutput.failing_tests("--- FAIL: TestRouteMatch (0.00s)\nFAIL\n") == [
        "TestRouteMatch"
    ]
    assert testoutput.failing_tests("test parser::negative_totals ... FAILED\n") == [
        "parser::negative_totals"
    ]
    assert testoutput.failing_tests("not ok 1 - totals must not be negative\n") == [
        "totals must not be negative"
    ]
    # Prose that talks about failing tests names nothing.
    assert testoutput.failing_tests("the suite failed and 3 tests did not pass\n") == []


def test_a_comment_names_the_tests_too(session: Session, item: Item) -> None:
    """`failed` and `not-reproducible` are first-class results (DR-0003), and a comment that makes
    its reader open a collapsed block to learn which tests failed is the same defect in the half of
    the outcomes that never gets a pull request."""
    attempt = _attempt(session, item)
    attempt.outcome = AttemptOutcome.FAILED

    comment = evidence.issue_comment(item, attempt)
    first_screen = "\n".join(comment.splitlines()[:25])

    # In the head, not merely somewhere: the red gate's whole output is published further down, so
    # a test that only asked "is the name in the comment" passed with this block deleted.
    assert "test_teardown_does_not_raise_when_docker_is_not_on_path" in first_screen
    assert "2 failed, 904 passed in 57.02s" in first_screen
