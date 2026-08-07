"""The two decisions a human makes about an amber item, and nothing else. Item 166.

**Here because two callers need them and neither should own them.** `approve` lived in `cli.py`, and
the route that item 166 added would have had to import it from there — a module that owns a command,
imported by a module that owns a route. That is the exact shape item 162 spent an item removing from
`sandbox/`, for the reason that survived it: a name two modules reach for does not belong to either.

Both take the **project**, already looked up, rather than a slug. The lookup is the caller's
business — `cli` refuses with an exit code, a route refuses with a status — and passing the slug
would have dragged one of those vocabularies into the other.

The pair is deliberately small and deliberately closed. `LEGAL[WAITING_APPROVAL]` is
`{READY, HUMAN_ONLY, DONE}`, and the third is not here: an item a human closes by hand is closed in
the forge, where the issue is, and the sweep reads it back. What a human decides *about an attempt*
is only ever these two — let it try, or take it away from it.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hullwork.models import Item, ItemState, Project
from hullwork.states import IllegalTransitionError, transition


class DecisionError(Exception):
    """The decision cannot be made, and the message says which state was found instead.

    Naming the state is the difference between a refusal and a puzzle: an item already `ready`, or
    one a human closed last week, is the common case at this door rather than the exception.
    """


def _the_item(session: Session, project: Project, item_id: int) -> Item:
    item = (
        session.query(Item)
        .filter(Item.id == item_id, Item.project_id == project.id)
        .one_or_none()
    )
    if item is None:
        msg = f"'{project.slug}' has no item {item_id}"
        raise DecisionError(msg)
    return item


def _move(item: Item, target: ItemState, *, only_from: ItemState, verb: str) -> Item:
    if item.state is not only_from:
        msg = (
            f"item {item.id} is '{item.state.value}', not '{only_from.value}' — "
            f"only an item waiting for approval can be {verb}"
        )
        raise DecisionError(msg)
    try:
        transition(item, target)
    except IllegalTransitionError as exc:
        # Red reaches here only if a manifest was edited underneath a queued item. The state machine
        # refuses it whatever this function thinks, which is the point of enforcing it there.
        raise DecisionError(str(exc)) from exc
    return item


def approve(session: Session, project: Project, item_id: int) -> Item:
    """Let an agent attempt one amber item. One item, named explicitly, by a human.

    **There is deliberately no `--all` and no equivalent.** One approval is one attempt, which costs
    money and opens a pull request somebody has to read; a button that approves a queue is a button
    that spends a budget.
    """
    item = _move(
        _the_item(session, project, item_id),
        ItemState.READY,
        only_from=ItemState.WAITING_APPROVAL,
        verb="approved",
    )
    session.commit()
    return item


def hand_to_human(session: Session, project: Project, item_id: int) -> Item:
    """Take an amber item away from the agent: a person will do this one.

    **Not `rejected`, and the state machine is why.** `LEGAL[WAITING_APPROVAL]` does not contain
    `REJECTED` — that state means *a reviewer closed a pull request*, and it feeds
    `counted.rejected` keyed by the reason on that pull request's labels. Calling this "reject"
    would file a decision about **whether to attempt** into the tally that counts **review**
    decisions, and the number would drift with nobody able to see why.

    `human-only` is the honest name and it already existed: it is what a lane says when the code
    location is somewhere an agent is not allowed to go.
    """
    item = _move(
        _the_item(session, project, item_id),
        ItemState.HUMAN_ONLY,
        only_from=ItemState.WAITING_APPROVAL,
        verb="handed to a human",
    )
    session.commit()
    return item
