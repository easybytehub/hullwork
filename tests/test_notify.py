"""The digest, tested mostly for restraint.

Almost every assertion here is about something not being sent, or being sent last. A notifier that
gets this wrong is not merely annoying: it gets muted, and then the whole pipeline is invisible.
"""

import io

import pytest

from hullwork.dedup import Outcome, Resolution
from hullwork.models import Item, ItemState, Lane
from hullwork.notify import Digest, Line, build_digest
from hullwork.notify.adapters import (
    ConsoleNotifier,
    NullNotifier,
    UnsupportedChannelError,
    make_notifier,
    notify_safely,
)


def _item(title: str, lane: Lane = Lane.GREEN, state: ItemState = ItemState.TRIAGED) -> Item:
    return Item(
        project_id=1,
        fingerprint=title,
        title=title,
        lane=lane,
        state=state,
        lane_reason=f"matched something in the {lane.value} lane",
        forge_issue_ref="#7",
    )


def _resolution(outcome: Outcome, item: Item) -> Resolution:
    return Resolution(outcome=outcome, item=item)


# --- what goes in, and in what order -----------------------------------------------------------


def test_the_digest_leads_with_regressions() -> None:
    """A fix that did not hold is worse news than a new bug, so it goes first."""
    digest = build_digest(
        [
            _resolution(Outcome.CREATED, _item("brand new")),
            _resolution(Outcome.REOPENED, _item("came back")),
        ]
    )

    rendered = digest.render()
    assert rendered.index("Came back") < rendered.index("New")


def test_red_and_waiting_items_are_separated_from_the_merely_new() -> None:
    digest = build_digest(
        [
            _resolution(Outcome.CREATED, _item("in payments", Lane.RED)),
            _resolution(Outcome.CREATED, _item("needs approval", Lane.AMBER,
                                               ItemState.WAITING_APPROVAL)),
            _resolution(Outcome.CREATED, _item("ordinary")),
        ]
    )

    assert len(digest.needs_decision) == 2
    assert len(digest.created) == 1
    rendered = digest.render()
    assert rendered.index("Waiting on you") < rendered.index("New")


def test_deduplicated_occurrences_are_a_count_and_come_last() -> None:
    digest = build_digest(
        [_resolution(Outcome.DEDUPLICATED, _item(f"repeat {n}")) for n in range(40)]
        + [_resolution(Outcome.CREATED, _item("something new"))]
    )

    assert digest.deduplicated == 40
    rendered = digest.render()
    assert rendered.index("New") < rendered.index("deduplicated")
    # Their titles never appear: they are volume, not news.
    assert "repeat 0" not in rendered


# --- what does not get sent ----------------------------------------------------------------------


def test_a_digest_of_only_repeats_is_empty() -> None:
    """"40 repeats, nothing new" is the message that teaches people to stop reading digests."""
    digest = build_digest([_resolution(Outcome.DEDUPLICATED, _item("repeat")) for _ in range(40)])

    assert digest.is_empty


def test_an_empty_digest_is_never_written() -> None:
    stream = io.StringIO()

    ConsoleNotifier(stream).send(Digest(deduplicated=12))

    assert stream.getvalue() == ""


def test_notify_safely_skips_an_empty_digest_entirely() -> None:
    class Exploding:
        def send(self, digest: Digest) -> None:
            raise AssertionError("should never be called for an empty digest")

    notify_safely(Exploding(), Digest())


def test_the_null_notifier_is_a_real_no_op() -> None:
    # `none` is the default, so it has to be correct rather than merely absent.
    NullNotifier().send(Digest(created=[Line("x", Lane.GREEN)]))


# --- failure is contained --------------------------------------------------------------------


def test_a_delivery_failure_never_escapes() -> None:
    """Losing a message must not lose an event: a broken token cannot break ingest."""

    class Broken:
        def send(self, digest: Digest) -> None:
            msg = "telegram is down"
            raise RuntimeError(msg)

    notify_safely(Broken(), Digest(created=[Line("boom", Lane.GREEN)]))


# --- channels ----------------------------------------------------------------------------------


def test_none_and_console_are_available() -> None:
    assert isinstance(make_notifier("none"), NullNotifier)
    assert isinstance(make_notifier("console"), ConsoleNotifier)


@pytest.mark.parametrize("channel", ["telegram", "email"])
def test_unimplemented_channels_say_so_rather_than_pretending(channel: str) -> None:
    """Declared in the manifest, not deliverable yet. Silence would look like it worked."""
    with pytest.raises(UnsupportedChannelError, match="not implemented"):
        make_notifier(channel)


def test_an_unknown_channel_is_refused() -> None:
    with pytest.raises(UnsupportedChannelError, match="unknown"):
        make_notifier("carrier-pigeon")


def test_the_rendered_digest_carries_the_lane_reason_and_the_issue() -> None:
    # A digest a human cannot act on directly is a digest that costs a click to be useful.
    digest = build_digest([_resolution(Outcome.CREATED, _item("in payments", Lane.RED))])

    rendered = digest.render()
    assert "#7" in rendered
    assert "red lane" in rendered
