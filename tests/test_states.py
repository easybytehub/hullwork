"""The state machine, tested transition by transition.

Every legal path is asserted, and so is the fact that illegal ones raise rather than quietly do
nothing — an item silently stuck in an unexpected state is the failure that looks like success.
"""

from pathlib import Path

import pytest

from hullwork.models import Item, ItemState, Lane
from hullwork.states import AGENT_STATES, LEGAL, IllegalTransitionError, can, transition


def _item(state: ItemState = ItemState.NEW, lane: Lane = Lane.GREEN) -> Item:
    return Item(project_id=1, fingerprint="fp", title="boom", state=state, lane=lane)


def test_the_happy_path_from_arrival_to_merged() -> None:
    item = _item()
    for step in (
        ItemState.TRIAGED,
        ItemState.READY,
        ItemState.IN_PROGRESS,
        ItemState.PR_OPEN,
        ItemState.DONE,
    ):
        transition(item, step)

    assert item.state is ItemState.DONE


def test_the_amber_path_waits_for_approval_first() -> None:
    item = _item(ItemState.TRIAGED, Lane.AMBER)

    transition(item, ItemState.WAITING_APPROVAL)
    transition(item, ItemState.READY)

    assert item.state is ItemState.READY


def test_a_closed_item_reopens_as_a_regression_and_gets_retriaged() -> None:
    item = _item(ItemState.DONE)

    transition(item, ItemState.REOPENED)
    transition(item, ItemState.TRIAGED)

    assert item.state is ItemState.TRIAGED


def test_failed_and_not_reproducible_are_both_reachable_and_distinct() -> None:
    # DR-0003: "I could not fix it" and "I could not make it happen" are different outcomes.
    failed = _item(ItemState.IN_PROGRESS)
    transition(failed, ItemState.FAILED)

    unreproducible = _item(ItemState.IN_PROGRESS)
    transition(unreproducible, ItemState.NOT_REPRODUCIBLE)

    assert failed.state is not unreproducible.state


@pytest.mark.parametrize("target", sorted(AGENT_STATES))
def test_a_red_lane_item_is_never_handed_to_an_agent(target: ItemState) -> None:
    item = _item(ItemState.TRIAGED, Lane.RED)

    with pytest.raises(IllegalTransitionError) as caught:
        transition(item, target)

    assert "red lane" in str(caught.value)
    assert item.state is ItemState.TRIAGED  # unchanged


def test_red_lane_items_can_still_be_closed_by_a_human() -> None:
    item = _item(ItemState.HUMAN_ONLY, Lane.RED)

    transition(item, ItemState.DONE)

    assert item.state is ItemState.DONE


def test_an_undeclared_transition_raises_rather_than_doing_nothing() -> None:
    item = _item(ItemState.NEW)

    with pytest.raises(IllegalTransitionError):
        transition(item, ItemState.DONE)  # skipping triage entirely

    assert item.state is ItemState.NEW


def test_cannot_go_backwards_from_a_merged_item_except_by_regression() -> None:
    item = _item(ItemState.DONE)

    with pytest.raises(IllegalTransitionError):
        transition(item, ItemState.IN_PROGRESS)


def test_can_agrees_with_transition() -> None:
    # If they can disagree, callers that check first will be surprised by the ones that do not.
    for state in ItemState:
        for target in ItemState:
            item = _item(state)
            allowed = can(item, target)
            try:
                transition(item, target)
            except IllegalTransitionError:
                assert not allowed, f"{state} -> {target}: can() said yes, transition() said no"
            else:
                assert allowed, f"{state} -> {target}: can() said no, transition() said yes"


def test_every_state_is_declared_in_the_table() -> None:
    # A state missing from LEGAL is a dead end nobody notices until an item lands in it.
    assert set(LEGAL) == set(ItemState)


def test_nothing_outside_this_module_assigns_a_state_directly() -> None:
    """Item 042. The rule this module's docstring states, asserted rather than trusted.

    Two callers in `work.py` assigned `item.state` because the edge they needed was undeclared, and
    one of them was about to become load-bearing for DR-0006's dry run — a mode that runs on other
    people's machines before it runs on ours. A grep is a crude test and it is the right one here:
    the defect is textual, and anything subtler would miss the next copy.
    """
    root = Path(__file__).resolve().parent.parent / "hullwork"

    offenders = [
        f"{path.relative_to(root)}:{number}"
        for path in sorted(root.rglob("*.py"))
        if path.name != "states.py"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if ".state = ItemState" in line
    ]

    assert offenders == []


def test_a_transition_sets_the_clock_the_board_reads() -> None:
    """Item 141. `state_since` answers *how long has this been waiting*, and nothing else does.

    Set inside `transition` rather than at each call site, for the same reason the assignment it
    sits beside is: one door, so a state that moves without its clock moving is impossible by
    construction rather than by every caller remembering.
    """
    # A separate object: asserting `is None` on the one below narrows the attribute for the rest
    # of the function, and the checker does not know `transition` mutates it.
    assert _item().state_since is None, "an unsaved item has not entered anything yet"

    item = _item()
    transition(item, ItemState.TRIAGED)
    first = item.state_since
    assert first is not None

    transition(item, ItemState.READY)
    second = item.state_since

    assert second is not None
    assert second >= first, "a second move moved the clock again"


def test_the_clock_does_not_move_when_something_else_does() -> None:
    """**The defect this column exists for**, and why `updated_at` could not be used instead.

    `updated_at` moves on any change — an occurrence counter, a permalink, a context fetch — so an
    item six days into `waiting-approval` reads as fresh the morning its count is bumped. Asserted
    against a real session so `updated_at` actually fires: the two must disagree, and that
    disagreement is the whole reason for the column.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from hullwork.models import Base

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    item = _item()
    session.add(item)
    session.flush()

    transition(item, ItemState.TRIAGED)
    session.flush()
    entered, stamped = item.state_since, item.updated_at

    item.occurrences += 1
    item.permalink = "https://tracker.example/issue/1"
    session.flush()

    assert item.state_since == entered, "the item changed; the state it is in did not"
    assert item.updated_at > stamped, "…and `updated_at` did move, which is why it cannot be used"
