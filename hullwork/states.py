"""The item state machine.

Kept in its own module because it is the one piece of logic that every other component has to agree
with, and because an illegal transition must be impossible to perform by accident from anywhere.

Two rules carry the safety of the whole pipeline:

* **Only declared transitions are permitted.** An undeclared one raises. Silently doing nothing is
  how an item ends up stuck in a state nobody expected while the logs say everything is fine.
* **A red-lane item is never handed to an agent.** Whatever the state machine would otherwise allow,
  red means a human. This is enforced here rather than at the call sites, because a guardrail that
  depends on every caller remembering it is not a guardrail.
"""

from datetime import UTC, datetime

from hullwork.models import Item, ItemState, Lane

#: Where each state may go. Absent from a set means the transition is a bug, not a possibility.
LEGAL: dict[ItemState, frozenset[ItemState]] = {
    ItemState.NEW: frozenset({ItemState.TRIAGED}),
    # `done` from here is the human's path, and it is the ordinary one: with `agent: none` — the
    # default — somebody fixes the bug and closes the issue, and no agent was ever involved. Its
    # absence made that outcome unrepresentable, which showed up the first time a real issue was
    # closed by hand (item 014).
    ItemState.TRIAGED: frozenset(
        {ItemState.READY, ItemState.WAITING_APPROVAL, ItemState.HUMAN_ONLY, ItemState.DONE}
    ),
    ItemState.WAITING_APPROVAL: frozenset(
        {ItemState.READY, ItemState.HUMAN_ONLY, ItemState.DONE}
    ),
    ItemState.READY: frozenset({ItemState.IN_PROGRESS, ItemState.HUMAN_ONLY, ItemState.DONE}),
    ItemState.IN_PROGRESS: frozenset(
        {
            ItemState.PR_OPEN,
            ItemState.FAILED,
            # DR-0003: could not reproduce the bug, so never attempted a fix. Distinct from failing
            # to fix one that was reproduced — a human needs different things in each case.
            ItemState.NOT_REPRODUCIBLE,
            # Item 042. The outcomes that do not settle the bug — `abandoned`, `already-fixed` —
            # leave the item with its try intact, so it goes back in the queue. This edge was being
            # taken by a bare assignment in `work.release` precisely because it was missing, which
            # made this module's opening rule — a guardrail every caller must remember is not a
            # guardrail — false about its own only bypass.
            #
            # A *consuming* outcome can never reach it: `release` maps each of those to a terminal
            # state above, and item 044 makes `eligible` check `has_attempt_left` so a consumed item
            # cannot be picked up again even from `ready`. Without that check this edge would be a
            # retry loop.
            ItemState.READY,
            # Item 043, and also the answer for a red-lane item that abandons: `ready` is an agent
            # state and red items are refused it below, so without this edge `release` would raise
            # after a run that had already happened.
            ItemState.HUMAN_ONLY,
        }
    ),
    ItemState.PR_OPEN: frozenset(
        {
            ItemState.DONE,
            ItemState.FAILED,
            ItemState.HUMAN_ONLY,
            # Item 138: a human read it and closed it without merging. Terminal, and the only way
            # into `rejected` — the state exists to be reached by a person's decision and by nothing
            # else, which is why no other row leads to it.
            ItemState.REJECTED,
            # Added for M9's watch, and the reason is that `pr-open` can be stale. The item moves to
            # `done` when `reconcile_closed` sees the *issue* closed, which happens automatically
            # only when the pull request body carries a closing keyword — merge one without it and
            # the item sits in `pr-open` with its fix already in production. A returning error
            # against merged code is a regression whether or not the tracker's issue got closed, and
            # refusing the edge would have meant recording the verdict and losing the state.
            ItemState.REOPENED,
        }
    ),
    # A closed item can come back. That is a regression, and `reopened` exists to say so.
    ItemState.DONE: frozenset({ItemState.REOPENED}),
    # `reopened` is passed through, not rested in: `resolve` moves an item straight on to `triaged`.
    # `done` and `human-only` are legal from here anyway, for rows an older build left stranded —
    # without them, closing such an item's issue raises inside the sweep and kills the whole pass
    # for every project, permanently (item 016).
    ItemState.REOPENED: frozenset({ItemState.TRIAGED, ItemState.DONE, ItemState.HUMAN_ONLY}),
    # Terminal until a human moves them: the agent has had its one attempt (DR-0003).
    ItemState.FAILED: frozenset({ItemState.HUMAN_ONLY, ItemState.DONE}),
    ItemState.NOT_REPRODUCIBLE: frozenset({ItemState.HUMAN_ONLY, ItemState.DONE}),
    ItemState.HUMAN_ONLY: frozenset({ItemState.DONE, ItemState.REOPENED}),
    # **A refusal is a person's decision, and nothing automated overturns it** (item 138). An item
    # can still be closed as `done` — somebody fixing it by hand is the ordinary sequel — and it can
    # be handed to `human-only`, which changes no fact and says nobody should try again. Absent on
    # purpose is a route back to `ready`: the agent had its one attempt (DR-0003), and a human read
    # the result and said no.
    ItemState.REJECTED: frozenset({ItemState.DONE, ItemState.HUMAN_ONLY}),
}

#: States that mean "an agent is about to touch, or is touching, this". Forbidden in the red lane.
AGENT_STATES = frozenset({ItemState.WAITING_APPROVAL, ItemState.READY, ItemState.IN_PROGRESS})

#: The only state from which a new occurrence counts as a regression rather than a repeat.
CLOSED = frozenset({ItemState.DONE})


class IllegalTransitionError(Exception):
    """A transition that the state machine does not allow. Never silently ignored."""

    def __init__(
        self,
        item_id: int | None,
        current: ItemState,
        target: ItemState,
        why: str = "",
    ) -> None:
        self.current = current
        self.target = target
        where = f"item {item_id}" if item_id else "item"
        suffix = f" ({why})" if why else ""
        super().__init__(f"{where}: cannot move from '{current.value}' to '{target.value}'{suffix}")


def can(item: Item, target: ItemState) -> bool:
    """Whether this item may move to `target` right now."""
    if target not in LEGAL.get(item.state, frozenset()):
        return False
    return not (item.lane is Lane.RED and target in AGENT_STATES)


def transition(item: Item, target: ItemState) -> Item:
    """Move an item, or raise. There is no third outcome.

    **The clock is set here and nowhere else** (item 141). `state_since` answers *how long has this
    been waiting*, which `updated_at` cannot: that moves on any change at all — an occurrence
    counter, a permalink arriving, a context fetch landing — so an item six days into
    `waiting-approval` reads as fresh the morning its count is bumped.

    Setting it in this function rather than at each call site is the same argument item 042 already
    made about the assignment below: one door, so a state that moves without its clock moving is
    impossible by construction rather than by everyone remembering.
    """
    if item.lane is Lane.RED and target in AGENT_STATES:
        raise IllegalTransitionError(
            item.id, item.state, target, "red lane items are never handed to an agent"
        )
    if target not in LEGAL.get(item.state, frozenset()):
        raise IllegalTransitionError(item.id, item.state, target)

    item.state = target
    item.state_since = datetime.now(UTC)
    return item
