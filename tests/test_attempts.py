"""Storing what an attempt did, and the accounting rule that decides if it counted.

There was nowhere to put any of this: four tables, none of which could hold an attempt, while
items 025, 027 and 028 all assumed one could and spec §8 claimed `hullwork status` already showed
the counter. The third guardrail this milestone found existing only in prose.
"""

import pytest
from sqlalchemy.orm import Session

from hullwork.attempts import (
    MAX_ATTEMPTS,
    MAX_OUTPUT_CHARS,
    bound,
    consumed_count,
    finish,
    has_attempt_left,
    record,
    start,
)
from hullwork.models import AttemptOutcome, AttemptPhase, Item, Lane, Project


@pytest.fixture
def item(session: Session) -> Item:
    project = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
    )
    session.add(project)
    session.flush()
    row = Item(project_id=project.id, fingerprint="fp", title="ValueError: boom", lane=Lane.GREEN)
    session.add(row)
    session.flush()
    return row


def test_the_claim_a_reviewer_checks_is_two_rows(session: Session, item: Item) -> None:
    """"Failed at commit X, passes at commit Y" is the whole product, and it is free to record."""
    attempt = start(session, item, base_sha="abc1234", image_tag="hullwork-sandbox:deadbeef")

    record(session, attempt, AttemptPhase.RED_GATE, "pytest", exit_code=1, output="1 failed")
    record(session, attempt, AttemptPhase.GREEN_GATE, "pytest", exit_code=0, output="12 passed")
    finish(session, attempt, AttemptOutcome.PR_OPEN)

    assert [(s.ordinal, s.phase, s.exit_code) for s in attempt.steps] == [
        (0, AttemptPhase.RED_GATE, 1),
        (1, AttemptPhase.GREEN_GATE, 0),
    ]
    assert attempt.base_sha == "abc1234"
    assert attempt.phase_reached is AttemptPhase.GREEN_GATE


def test_infrastructure_failure_does_not_spend_the_attempt(session: Session, item: Item) -> None:
    """DR-0003's line, in code. "The network was bad" is not "the agent could not fix this"."""
    attempt = start(session, item)

    finish(session, attempt, AttemptOutcome.ABANDONED, not_consumed_reason="endpoint unreachable")

    assert attempt.consumed is False
    assert attempt.not_consumed_reason == "endpoint unreachable"
    assert has_attempt_left(session, item)
    assert consumed_count(session, item) == 0


@pytest.mark.parametrize(
    "outcome",
    [AttemptOutcome.PR_OPEN, AttemptOutcome.FAILED, AttemptOutcome.NOT_REPRODUCIBLE],
)
def test_every_verdict_spends_the_attempt(
    session: Session, item: Item, outcome: AttemptOutcome
) -> None:
    """Including `not-reproducible`. It is an honest answer, and it is still an answer."""
    finish(session, start(session, item), outcome)

    assert consumed_count(session, item) == 1
    assert has_attempt_left(session, item) is False


def test_an_abandoned_run_always_says_why(session: Session, item: Item) -> None:
    """An item that will be tried again should say so rather than merely go quiet."""
    attempt = start(session, item)

    finish(session, attempt, AttemptOutcome.ABANDONED)

    assert attempt.not_consumed_reason


def test_a_reason_is_not_stored_against_a_consuming_outcome(session: Session, item: Item) -> None:
    """A caller confusing "why it failed" with "why it does not count" gets neither, not both."""
    attempt = start(session, item)

    finish(session, attempt, AttemptOutcome.FAILED, not_consumed_reason="ignore me")

    assert attempt.consumed is True
    assert attempt.not_consumed_reason is None


def test_one_attempt_then_a_human(session: Session, item: Item) -> None:
    assert MAX_ATTEMPTS == 1
    finish(session, start(session, item), AttemptOutcome.FAILED)
    finish(session, start(session, item), AttemptOutcome.ABANDONED)

    # The abandoned one did not count, and the failed one did.
    assert consumed_count(session, item) == 1
    assert has_attempt_left(session, item) is False


def test_output_is_cut_from_the_middle_and_says_so() -> None:
    """Cutting the tail is the obvious implementation and it throws away the failure summary."""
    text = "HEAD" + ("x" * (MAX_OUTPUT_CHARS * 2)) + "TAIL: 1 failed"

    trimmed, truncated = bound(text)

    assert truncated
    assert trimmed.startswith("HEAD")
    assert trimmed.endswith("TAIL: 1 failed")
    assert "characters removed from the middle" in trimmed
    assert len(trimmed) < len(text)


def test_short_output_is_left_exactly_alone() -> None:
    assert bound("2 passed") == ("2 passed", False)


def test_a_long_step_is_stored_marked(session: Session, item: Item) -> None:
    attempt = start(session, item)

    step = record(session, attempt, AttemptPhase.BASELINE, "pytest", output="y" * 99_999)

    assert step.output_truncated is True
    assert len(step.output) <= MAX_OUTPUT_CHARS + 200


def test_steps_keep_their_order_across_calls(session: Session, item: Item) -> None:
    attempt = start(session, item)
    for n in range(5):
        record(session, attempt, AttemptPhase.FIX, f"cmd{n}")

    assert [s.ordinal for s in attempt.steps] == [0, 1, 2, 3, 4]


def test_an_attempt_exists_before_anything_runs(session: Session, item: Item) -> None:
    """So a dispatcher killed mid-run still leaves a trace of having tried."""
    attempt = start(session, item)

    assert attempt.id is not None
    assert attempt.finished_at is None
    assert attempt.outcome is None
    assert attempt.consumed is False
