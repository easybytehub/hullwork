"""What arrived, and how much of it left with evidence attached. Item 183, DR-0017.

The decision signed on 2026-08-09 says what the product is measured by, and it is not `Funnel`:
that one's denominator is *attempts that spent an item's one try*, so every question it can answer
has the shape **of the attempts we made, how did they go**. The number signed for has *what arrived*
as its denominator, which is a different question and can produce a much worse answer.

**Three cases here exist because they are the ones designed to be miscounted**, and each is a way
the product could claim credit it has not earned: an item a person fixed themselves, an item whose
attempt was abandoned by the infrastructure, and a red-lane item nobody was ever allowed to attempt.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from hullwork import outcomes
from hullwork.models import (
    Attempt,
    AttemptOutcome,
    AttemptPhase,
    Item,
    ItemState,
    Lane,
    Project,
)


@pytest.fixture
def project(session: Session) -> Project:
    made = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="x",  # noqa: S106
    )
    session.add(made)
    session.flush()
    return made


def _item(
    session: Session, project: Project, state: ItemState, *, lane: Lane = Lane.GREEN, n: int = 0
) -> Item:
    row = Item(
        project_id=project.id, fingerprint=f"fp-{state.value}-{lane.value}-{n}",
        title="something", lane=lane, state=state,
    )
    session.add(row)
    session.flush()
    return row


def _attempt(
    session: Session,
    item: Item,
    outcome: AttemptOutcome | None,
    *,
    consumed: bool = True,
    rehearsal: bool = False,
) -> Attempt:
    row = Attempt(
        item_id=item.id, phase_reached=AttemptPhase.PUBLISH,
        outcome=outcome, consumed=consumed, rehearsal=rehearsal,
    )
    session.add(row)
    session.flush()
    return row


# --- the denominator, which is the whole change ------------------------------------------------


def test_the_denominator_is_what_arrived_and_not_what_was_attempted(
    session: Session, project: Project
) -> None:
    """`Funnel` cannot express this, and that is why it is being added rather than extended.

    Nine claims arrive; one is attempted. `Funnel` reports a denominator of one and every ratio it
    can form is about that one. The question DR-0017 signed for is what happened to the nine.
    """
    settled = _item(session, project, ItemState.PR_OPEN)
    _attempt(session, settled, AttemptOutcome.PR_OPEN)
    for n in range(8):
        _item(session, project, ItemState.TRIAGED, n=n)

    desk = outcomes.desk(session)

    assert desk.arrived == 9
    assert outcomes.funnel(session).fair_try == 1, "the old denominator, for contrast"


def test_the_buckets_sum_to_what_arrived_and_nothing_is_in_two(
    session: Session, project: Project
) -> None:
    """A report whose parts do not add up is a report nobody can act on."""
    _attempt(session, _item(session, project, ItemState.PR_OPEN), AttemptOutcome.PR_OPEN)
    _attempt(
        session, _item(session, project, ItemState.NOT_REPRODUCIBLE, n=1),
        AttemptOutcome.NOT_REPRODUCIBLE,
    )
    _item(session, project, ItemState.READY, n=2)
    _item(session, project, ItemState.HUMAN_ONLY, lane=Lane.RED, n=3)
    _attempt(session, _item(session, project, ItemState.IN_PROGRESS, n=4), None)

    desk = outcomes.desk(session)

    assert desk.arrived == 5
    assert (
        desk.left_with_evidence + desk.still_waiting + desk.handed_over + desk.running
        == desk.arrived
    )


# --- the three that are designed to be miscounted ----------------------------------------------


def test_an_item_a_person_fixed_themselves_is_not_ours(
    session: Session, project: Project
) -> None:
    """**`done` is reached two ways and there is no state history to tell them apart.**

    A merged pull request and a person closing their own issue both land here. The attempt trail is
    what separates them, and counting by state would have the product claiming credit for somebody
    else's afternoon — which is the single most dishonest thing this number could do.
    """
    theirs = _item(session, project, ItemState.DONE)
    ours = _item(session, project, ItemState.DONE, n=1)
    _attempt(session, ours, AttemptOutcome.PR_OPEN)

    desk = outcomes.desk(session)

    assert desk.left_with_evidence == 1, "only the one with a verdict behind it"
    assert desk.arrived == 2
    del theirs


def test_an_abandoned_attempt_left_nothing_on_anybodys_desk(
    session: Session, project: Project
) -> None:
    """The endpoint was unreachable, the sandbox would not start. No gate ran, so nothing is known.

    `abandoned` does not consume an item's attempt precisely because it says nothing about the
    claim, and a number that counted it would be counting the infrastructure's bad days as work.
    """
    stalled = _item(session, project, ItemState.READY)
    _attempt(session, stalled, AttemptOutcome.ABANDONED, consumed=False)

    desk = outcomes.desk(session)

    assert desk.left_with_evidence == 0
    assert desk.still_waiting == 1, "it is back in the queue, which is where it is"


def test_a_red_lane_item_was_added_to_the_desk_rather_than_removed(
    session: Session, project: Project
) -> None:
    """The row `Funnel` cannot have, and the reason this number is worth building.

    DR-0017's own Context says the first half of the pipeline is a **cost**: a team with a tracker
    has more issues than it can serve, and the opening move adds to the pile. An item nobody may
    attempt is Hullwork putting work on somebody's desk, and the count has to say so.
    """
    _item(session, project, ItemState.HUMAN_ONLY, lane=Lane.RED)
    _item(session, project, ItemState.REJECTED, n=1)

    desk = outcomes.desk(session)

    assert desk.handed_over == 2
    assert desk.left_with_evidence == 0


def test_a_rehearsal_is_not_a_desk_anybody_cleared(
    session: Session, project: Project
) -> None:
    """It publishes nothing, so no forge state and nobody's queue changed. `Funnel`'s rule, held."""
    rehearsed = _item(session, project, ItemState.READY)
    _attempt(session, rehearsed, AttemptOutcome.PR_OPEN, rehearsal=True)

    desk = outcomes.desk(session)

    assert desk.left_with_evidence == 0
    assert desk.still_waiting == 1


# --- what it says, which is the part a person reads --------------------------------------------


def test_a_refusal_is_reported_beside_a_change_and_not_inside_a_total(
    session: Session, project: Project
) -> None:
    """The second consequence of DR-0017, made visible rather than averaged away.

    *"I could not verify this" is a first-class result*, so a total that hides how much of the
    number it is would be the one place this product rounds its own honesty off.
    """
    _attempt(session, _item(session, project, ItemState.PR_OPEN), AttemptOutcome.PR_OPEN)
    _attempt(
        session, _item(session, project, ItemState.NOT_REPRODUCIBLE, n=1),
        AttemptOutcome.NOT_REPRODUCIBLE,
    )
    _attempt(session, _item(session, project, ItemState.FAILED, n=2), AttemptOutcome.FAILED)

    desk = outcomes.desk(session)

    assert desk.left_with_evidence == 3
    assert desk.with_a_change == 1
    assert desk.with_a_refusal == 2
    said = " ".join(outcomes.desk_lines(desk))
    assert "1" in said and "2" in said
    assert "refus" in said.lower()


def test_an_instance_that_attempted_nothing_says_so_in_words(
    session: Session, project: Project
) -> None:
    """Zeros read as *nothing happened*; this instance has claims and has cleared none of them.

    That is a different fact and the one worth printing on a first day — it is the state every
    instance starts in, and the row of noughts that used to stand for it reads like a failure.
    """
    for n in range(4):
        _item(session, project, ItemState.TRIAGED, n=n)

    said = " ".join(outcomes.desk_lines(outcomes.desk(session)))

    assert "4" in said
    assert "0 " not in said, "it says what is true rather than printing noughts"


def test_an_instance_with_nothing_at_all_says_nothing(session: Session) -> None:
    """No claims have arrived, so there is no desk to report on. Silence, like `lines`."""
    assert outcomes.desk_lines(outcomes.desk(session)) == []


def test_what_was_added_is_not_phrased_as_an_achievement(
    session: Session, project: Project
) -> None:
    """It is the row that can embarrass this product, and rounding it into good news is the way it
    would stop doing that."""
    _attempt(session, _item(session, project, ItemState.PR_OPEN), AttemptOutcome.PR_OPEN)
    _item(session, project, ItemState.HUMAN_ONLY, lane=Lane.RED, n=1)

    said = " ".join(outcomes.desk_lines(outcomes.desk(session)))

    assert "onto" in said or "added" in said or "put on" in said
    for congratulation in ("successfully", "great", "achieved", "handled"):
        assert congratulation not in said.lower()


def test_the_json_carries_the_parts_so_an_operator_computes_their_own_ratio(
    session: Session, project: Project
) -> None:
    """No percentage, for `Funnel`'s reason: six samples cannot carry that precision."""
    _attempt(session, _item(session, project, ItemState.PR_OPEN), AttemptOutcome.PR_OPEN)

    payload = outcomes.desk(session).as_dict()

    assert payload["arrived"] == 1
    assert payload["left_with_evidence"] == 1
    assert not any("percent" in key or "rate" in key for key in payload)


# --- and it has to be on the surface a person opens, not only in a terminal --------------------


def test_the_number_is_on_the_page_and_not_only_in_the_terminal(
    session: Session, project: Project
) -> None:
    """**The defect item 136 already found on this page once**, reintroduced by item 183 and caught
    the same day.

    That item's whole finding was three facts the instance knew and put where nobody reading would
    find them. This number was added to `status` and to `--json` and not here — and the interface
    design, rewritten the day before under the same decision, says this surface exists to show
    **what was verified and what was not**. A count of attempts is not that; this is.

    Ordered before the attempts block for `status`'s reason: the wider denominator first.
    """
    from hullwork import page
    from hullwork.config import Settings

    _attempt(session, _item(session, project, ItemState.PR_OPEN), AttemptOutcome.PR_OPEN)
    _item(session, project, ItemState.HUMAN_ONLY, lane=Lane.RED, n=1)
    # Committed rather than flushed: this page reads through its own transaction and cannot see
    # uncommitted state, which is invisible in production and is the whole of the difference here.
    session.commit()

    body = page.instance(session, Settings(), error_reporting=False)

    assert "went onto your desk rather than off it" in body
    assert "2 claim(s) have arrived" in body
    assert body.index("how much left your desk") < body.index("What its attempts came to")
