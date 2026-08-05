"""Deduplication: where the product earns its keep.

Around 80% of what arrives is a repeat of something already known, and **the correct behaviour for
that 80% is silence** — a counter moves and nothing else happens. Getting this wrong in either
direction is fatal: too eager and real bugs are buried, too shy and the tool becomes the noise
generator it was meant to replace.

The distinction that is easy to skip and expensive to lose: a known problem arriving against a
**closed** item is a regression, not a repeat. Conflating them hides the fix that did not hold,
which is precisely the failure this product exists to catch.
"""

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.orm import Session

from hullwork.manifest import Manifest
from hullwork.models import Item, ItemKind, ItemState
from hullwork.normalise import ErrorFact
from hullwork.states import CLOSED, transition
from hullwork.triage import choose_lane, route


class Outcome(StrEnum):
    """What resolving a fact did. `DEDUPLICATED` is the one that should happen most."""

    CREATED = "created"
    DEDUPLICATED = "deduplicated"
    REOPENED = "reopened"


@dataclass(frozen=True)
class Resolution:
    """The outcome and the item it applies to."""

    outcome: Outcome
    item: Item

    @property
    def needs_attention(self) -> bool:
        """Whether anything should leave the database because of this.

        A deduplicated occurrence never notifies and never opens an issue. It is the whole point.
        """
        return self.outcome is not Outcome.DEDUPLICATED


def resolve(session: Session, project_id: int, fact: ErrorFact, manifest: Manifest) -> Resolution:
    """Fold one fact into the item that represents it, creating that item if it is new.

    Identity is the fact's fingerprint, which already folds in the provider and its issue id — never
    the provider's own fingerprint, because GlitchTip does not send one and keying on it would mean
    no deduplication at all for the provider we recommend.
    """
    existing = (
        session.query(Item)
        .filter(Item.project_id == project_id, Item.fingerprint == fact.fingerprint)
        .one_or_none()
    )

    if existing is None:
        return Resolution(Outcome.CREATED, _create(session, project_id, fact, manifest))

    existing.occurrences += 1
    if fact.last_seen:
        existing.last_seen = fact.last_seen
    if fact.permalink and not existing.permalink:
        # Filled late rather than never: rows that predate item 086, and items whose first fact
        # arrived without one. Never overwritten — a permalink is stable, and the first one is as
        # good as the last.
        existing.permalink = fact.permalink

    if existing.state in CLOSED:
        # It came back. Re-triage from scratch: the manifest may have changed since, and a
        # regression deserves the same scrutiny as a new problem rather than inheriting old answers.
        decision = choose_lane(manifest, fact)
        existing.lane = decision.lane
        existing.lane_reason = decision.reason
        existing.regression = True

        # Both steps, here, now. `reopened` is a transition the item passes through, not a place it
        # rests: leaving it parked there was a dead end nothing could move it out of, and the next
        # human to close its issue crashed the sweep on an illegal `reopened → done` (item 016).
        # What makes this a regression is `regression` and the outcome below, not a stuck state.
        transition(existing, ItemState.REOPENED)
        transition(existing, ItemState.TRIAGED)
        # A regression is re-routed too: its lane was recomputed above, so a manifest edited in the
        # meantime can send it somewhere different from where it went the first time.
        route(existing, manifest)
        return Resolution(Outcome.REOPENED, existing)

    return Resolution(Outcome.DEDUPLICATED, existing)


def _create(session: Session, project_id: int, fact: ErrorFact, manifest: Manifest) -> Item:
    decision = choose_lane(manifest, fact)
    item = Item(
        project_id=project_id,
        fingerprint=fact.fingerprint,
        title=fact.title,
        lane=decision.lane,
        lane_reason=decision.reason,
        kind=ItemKind.BUG,
        state=ItemState.NEW,
        occurrences=1,
        permalink=fact.permalink,
    )
    if fact.first_seen:
        item.first_seen = fact.first_seen
    if fact.last_seen:
        item.last_seen = fact.last_seen

    session.add(item)
    session.flush()

    # Triage happens immediately: an item sitting in `new` is one nobody has classified, and the
    # lane is what every later decision depends on.
    transition(item, ItemState.TRIAGED)
    route(item, manifest)
    return item
