"""Of N attempts, M merged — computed by your instance, about your code. Item 119.

DR-0005 gives each instance the job of counting its own outcomes, and the roadmap named the gap:
`status` could say how many items were waiting and whether anything was running, and could not say
what had come of the attempts it had already made.

**Three rules, and each one came from the data rather than from taste.**

* **Rehearsals are not attempts.** `hullwork work --no-publish` runs every gate and writes the patch
  to disk, so an attempt can be `rehearsal: true` **and** `pr-open` — attempt 10 on the live
  instance is exactly that. Counting it would report five pull requests where the forge holds four:
  wrong, in the flattering direction, on the line an outsider reads first.
* **`consumed` is the denominator.** It is already this codebase's answer to *did the agent get a
  fair try* (`attempts.finish`), and three outcomes deliberately fail it: `abandoned` (the
  infrastructure got in the way), `already-fixed` (the deployment is behind) and `baseline-red` (the
  project's suite was already red, so nothing was ever asked about the bug). Folding those into the
  denominator counts a broken suite as the agent's failure; dropping them quietly hides that a third
  of the runs never got to try. **They are counted and named.**
* **No percentage.** A fraction is reported as `4 of 6`, which carries the same information without
  asserting a precision six samples do not have — and a percentage invites comparison between two
  instances running different code on different repositories, which is a number that belongs to
  nobody. Nothing in this repository publishes a rate; this computes yours.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from hullwork.models import Attempt, AttemptOutcome, Item, ItemState
from hullwork.spend import spoken

#: Outcomes that never spend an item's one attempt, in the order a reader meets them, with the
#: sentence that says why. The mapping lives in `attempts._DOES_NOT_CONSUME`; these are the short
#: forms for a status line, and they exist because "4 did not count" is not an answer.
WHY_IT_DID_NOT_COUNT: dict[AttemptOutcome, str] = {
    AttemptOutcome.BASELINE_RED: "the project's suite was already failing",
    AttemptOutcome.ABANDONED: "the infrastructure got in the way",
    AttemptOutcome.ALREADY_FIXED: "the fix is deployed behind, not missing",
}


#: Why a human refused a pull request, and the only answers this instance will record. Item 138.
#:
#: **A closed set, because free text has no arithmetic.** Six spellings of "too big" produce a list
#: nobody can act on; six counts produce a distribution that says what to fix next — three refusals
#: for insufficient evidence mean *fix the artefact*, three for excessive scope mean *narrow what
#: the agent attempts*. Those are different products.
#:
#: **Read from labels**, because that is where a reviewer answers without leaving the page they are
#: already on. Nothing here asks anybody to run a command: a beta that requires a form measures the
#: partners who filled it in.
REJECTION_REASONS = {
    "hullwork:rejected-evidence": "insufficient evidence",
    "hullwork:rejected-scope": "excessive scope",
    "hullwork:rejected-wrong-fix": "wrong fix",
    "hullwork:rejected-cost": "cost",
    "hullwork:rejected-risk": "risk",
    "hullwork:rejected-not-reproducible": "not reproducible",
}


def rejection_reason(labels: Sequence[str]) -> str | None:
    """The reason a reviewer gave, or `None` for **not given**. Item 138.

    `None` is a first-class answer and is counted apart from every reason in the set: a rejection
    with no reason is a fact about the review, not a bucket to fold into "other". Item 110's rule,
    which this repository keeps rediscovering.

    The first recognised label wins, and unknown labels are ignored rather than refused — a
    repository has its own labels and a pull request carrying `needs-discussion` is not malformed.
    """
    for label in labels:
        reason = REJECTION_REASONS.get(label.strip().lower())
        if reason is not None:
            return reason
    return None


@dataclass(frozen=True)
class Funnel:
    """What became of this instance's attempts. Counts only — see the module docstring."""

    #: Attempts that spent an item's one try. The denominator of everything below.
    fair_try: int = 0
    pull_requests: int = 0
    merged: int = 0
    not_reproducible: int = 0
    failed: int = 0

    #: Started and not finished. Neither a success nor a failure, and saying so costs one word.
    in_flight: int = 0

    #: Excluded, and reported: they publish nothing, so their verdicts describe no forge state.
    rehearsals: int = 0

    #: Outcome → how many, for the runs that never spent an attempt.
    never_counted: dict[AttemptOutcome, int] = field(default_factory=dict)

    @property
    def did_not_count(self) -> int:
        return sum(self.never_counted.values())

    def as_dict(self) -> dict[str, object]:
        """For `--json`, where an operator who wants a percentage computes their own."""
        return {
            "fair_try": self.fair_try,
            "pull_requests": self.pull_requests,
            "merged": self.merged,
            "not_reproducible": self.not_reproducible,
            "failed": self.failed,
            "in_flight": self.in_flight,
            "rehearsals": self.rehearsals,
            "never_counted": {
                outcome.value: count for outcome, count in self.never_counted.items()
            },
        }


def funnel(session: Session) -> Funnel:
    """Count what became of every attempt this instance has made.

    One pass over the table rather than six `COUNT` queries: this runs inside `status`, which an
    operator types when something is already wrong, and a report that spends six round trips to say
    four numbers is a report nobody waits for.
    """
    rows = session.execute(
        select(
            Attempt.rehearsal,
            Attempt.consumed,
            Attempt.outcome,
            Attempt.pull_request_ref,
            Attempt.merge_commit,
            func.count().label("n"),
        ).group_by(
            Attempt.rehearsal,
            Attempt.consumed,
            Attempt.outcome,
            Attempt.pull_request_ref.is_not(None),
            Attempt.merge_commit.is_not(None),
        )
    ).all()

    rehearsals = fair = prs = merged = not_reproducible = failed = in_flight = 0
    never: dict[AttemptOutcome, int] = {}
    for rehearsal, consumed, outcome, pull_request, merge_commit, n in rows:
        if rehearsal:
            # Counted as a group and never mixed in. A rehearsal's verdict is real — every gate ran
            # — but it describes a patch on disk, and every number below is about a forge.
            rehearsals += n
            continue
        if outcome is None:
            in_flight += n
            continue
        if not consumed:
            never[outcome] = never.get(outcome, 0) + n
            continue
        fair += n
        if pull_request is not None:
            prs += n
        if merge_commit is not None:
            merged += n
        if outcome is AttemptOutcome.NOT_REPRODUCIBLE:
            not_reproducible += n
        elif outcome is AttemptOutcome.FAILED:
            failed += n

    return Funnel(
        fair_try=fair,
        pull_requests=prs,
        merged=merged,
        not_reproducible=not_reproducible,
        failed=failed,
        in_flight=in_flight,
        rehearsals=rehearsals,
        # Sorted by the order in `WHY_IT_DID_NOT_COUNT`, so two instances read the same way.
        never_counted={
            outcome: never[outcome] for outcome in WHY_IT_DID_NOT_COUNT if outcome in never
        },
    )


def lines(counted: Funnel) -> list[str]:
    """The funnel in words, for a terminal. Empty when this instance has never attempted anything.

    Silence rather than a row of zeros: an instance that has made no attempt has nothing to report
    about them, and four lines of `0` read like a failure rather than like a beginning.

    **Rehearsals alone are worth a line**, though. An operator who has run `--no-publish` ten times
    and sees nothing would read that as an instance that has never done anything, and the rehearsals
    are exactly the work that produced no forge state to count.

    There is no early return for the empty case, and that is deliberate rather than an omission:
    every line below is already guarded by its own count, so a guard at the top could not fire.
    Reintroducing its absence changed no test, which is how it was found — and a guard that cannot
    fire reads like a hazard somebody measured.
    """
    said = []
    if counted.fair_try:
        parts = [f"{counted.pull_requests} opened a pull request"]
        if counted.not_reproducible:
            parts.append(f"{counted.not_reproducible} found nothing to reproduce")
        if counted.failed:
            parts.append(f"{counted.failed} could not produce a passing suite")
        said.append(f"{counted.fair_try} attempt(s) got a fair try: " + ", ".join(parts))
    if counted.pull_requests:
        # "N of M", never a percentage: the same information, without a precision six samples
        # cannot carry, and without inviting comparison with somebody else's repository.
        said.append(
            f"{counted.merged} of those {counted.pull_requests} pull request(s) were merged"
        )
    if counted.did_not_count:
        why = ", ".join(
            f"{count} {outcome.value} ({WHY_IT_DID_NOT_COUNT[outcome]})"
            for outcome, count in counted.never_counted.items()
        )
        said.append(f"{counted.did_not_count} never counted against an item: {why}")
    if counted.in_flight:
        said.append(f"{counted.in_flight} still running, which is neither")
    if counted.rehearsals:
        said.append(
            f"{counted.rehearsals} rehearsal(s), which publish nothing and are counted in none "
            f"of the above"
        )
    return said


@dataclass
class Reviewed:
    """What the **humans** decided, which is the half `Funnel` cannot see. Item 138, M13.

    `Funnel` counts what Hullwork decided about every attempt. This counts what happened to the
    artefacts afterwards, and the number M13 is actually about is `waiting`: an instance that opens
    pull requests nobody reads has not reduced maintenance, it has moved it.
    """

    #: Mutable, unlike `Funnel`, because this is accumulated in one pass over the items rather
    #: than built from a single grouped query. Not part of the interface: `reviewed` returns it
    #: finished and nothing else writes to it.
    merged: int = 0
    #: Refused, with a reason from `REJECTION_REASONS`. Keyed by reason so the distribution is the
    #: report: it says what to fix next.
    rejected: dict[str, int] = field(default_factory=dict)
    #: Refused with nothing said. **Not folded into a bucket** — a rejection with no reason is a
    #: fact about the review, and hiding it inside "other" would make the distribution flattering.
    rejected_without_reason: int = 0
    #: Open, unread, unanswered. The review debt, which is the thing M13 claims not to create.
    waiting: int = 0
    #: How long from the first occurrence of the error to the human's decision, per decided item.
    #: Reported as a median beside the cost, because a mean over two items is not a statistic.
    decisions: list[timedelta] = field(default_factory=list)

    @property
    def decided(self) -> int:
        return self.merged + sum(self.rejected.values()) + self.rejected_without_reason


def reviewed(session: Session) -> Reviewed:
    """Read the human half off the items themselves. One pass, no forge call.

    Everything here was written by the recurrence watch when it asked the forge, so this is free and
    stays true when the forge is down — the same rule `status` follows everywhere else.
    """
    counted = Reviewed()
    # One query for the merges rather than one per item: `status` runs when something is already
    # wrong, and a report that walks the attempt table item by item is a report nobody waits for.
    merges = session.execute(
        select(Attempt.item_id, func.min(Attempt.merged_at))
        .where(Attempt.merged_at.isnot(None))
        .group_by(Attempt.item_id)
    ).all()
    merged_at: dict[int, datetime | None] = dict(merges)  # type: ignore[arg-type]
    for item in session.query(Item).all():
        decided_at: datetime | None = None
        if item.state is ItemState.REJECTED:
            if item.rejected_reason:
                counted.rejected[item.rejected_reason] = (
                    counted.rejected.get(item.rejected_reason, 0) + 1
                )
            else:
                counted.rejected_without_reason += 1
            decided_at = item.updated_at
        elif item.state is ItemState.PR_OPEN:
            counted.waiting += 1
        else:
            when = merged_at.get(item.id)
            if when is not None:
                counted.merged += 1
                decided_at = when
        if decided_at is not None and item.first_seen is not None:
            counted.decisions.append(decided_at - item.first_seen)
    return counted


def review_lines(counted: Reviewed) -> list[str]:
    """The human half in words. Empty when nothing has reached a human yet.

    Silence rather than zeros, as everywhere else here: an instance that has published nothing has
    nothing to say about what reviewers did with it.
    """
    if counted.decided == 0 and counted.waiting == 0:
        return []
    out = [f"{counted.merged} merged by a human"]
    for reason, count in sorted(counted.rejected.items()):
        out.append(f"{count} rejected — {reason}")
    if counted.rejected_without_reason:
        out.append(
            f"{counted.rejected_without_reason} rejected with no reason given "
            f"(a label from the set would say which)"
        )
    if counted.waiting:
        out.append(
            f"{counted.waiting} waiting for a human — this is the review debt, and it is the "
            f"number that decides whether any of the above reduced maintenance"
        )
    if counted.decisions:
        ordered = sorted(counted.decisions, key=lambda d: d.total_seconds())
        median = ordered[len(ordered) // 2]
        out.append(f"median time from first error to decision: {spoken(median)}")
    return out
