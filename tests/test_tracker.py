"""The read side of the tracker, and the scrubbing that has to happen on the way in.

The payload shape below is a real GlitchTip 6.2.2 response, trimmed: fetched live from the
instance on 2026-07-27, then hand-reduced to the keys that matter. Every field name here — the
camelCase `lineNo` and `absPath`, `context` as `(lineno, source)` pairs, release and environment
arriving as *tags* rather than fields — was confirmed against that instance rather than read
anywhere.

Half of these tests are about secrets rather than parsing, and that is the right proportion. A
fetched event is the most dangerous object this system handles: it carries frame locals, `sys.argv`
and request data out of somebody else's process, and an audit found a **live DSN** inside `sys.argv`
on one of our own real events plus Hullwork's own webhook token in the locals of another.
"""

from typing import Any

import pytest

from hullwork.scrub import REDACTED, Scrubber
from hullwork.tracker import FetchedEvent, PermanentTrackerError, Tracker
from hullwork.tracker.glitchtip import MAX_VAR_CHARS, GlitchTipTracker


def _payload(**overrides: Any) -> dict[str, Any]:  # noqa: ANN401 - JSON is arbitrary
    payload: dict[str, Any] = {
        "eventID": "c041c513f1824fdfb00b5e48e70d4a80",
        "dateCreated": "2026-07-27T11:04:09.724Z",
        "culprit": "app.billing in recalculate",
        "metadata": {"type": "ValueError", "value": "totals must not be negative"},
        "tags": [
            {"key": "release", "value": "b292599"},
            {"key": "environment", "value": "prod"},
            {"key": "server_name", "value": "65d5deab0608"},
        ],
        "contexts": {"runtime": {"name": "CPython", "version": "3.12.13"}},
        "packages": {"fastapi": "0.140.1", "sqlalchemy": "2.0.51"},
        "extra": {"sys.argv": ["app.py", "--dsn", "https://user:s3cr3t@errors.example.com/7"]},
        "entries": [
            {
                "type": "exception",
                "data": {
                    "values": [
                        {
                            "type": "ValueError",
                            "value": "totals must not be negative",
                            "mechanism": {"type": "generic", "handled": False},
                            "stacktrace": {
                                "frames": [
                                    {
                                        "filename": "main.py",
                                        "absPath": "/app/src/main.py",
                                        "module": "__main__",
                                        "function": "<module>",
                                        "lineNo": 35,
                                        "context_line": "    recalculate(order)",
                                        "context": [
                                            [34, "order = load()"],
                                            [35, "recalculate(order)"],
                                        ],
                                    },
                                    {
                                        "filename": "billing.py",
                                        "absPath": "/app/src/app/billing.py",
                                        "module": "app.billing",
                                        "function": "recalculate",
                                        "lineNo": 31,
                                        "context_line": "    raise ValueError(msg)",
                                        "context": [[31, "    raise ValueError(msg)"]],
                                        "vars": {
                                            "total": "-40",
                                            "password": "hunter2",
                                            "note": "auth used Bearer "
                                            "abcdefghijklmnopqrstuvwxyz012345",
                                        },
                                    },
                                ]
                            },
                        }
                    ]
                },
            }
        ],
    }
    payload.update(overrides)
    return payload


def _tracker() -> GlitchTipTracker:
    return GlitchTipTracker("http://tracker.invalid", "tok-abc")


def _build(payload: dict[str, Any]) -> FetchedEvent:
    event = _tracker()._build(payload)
    assert event is not None
    return event


def test_the_adapter_satisfies_the_protocol() -> None:
    assert isinstance(_tracker(), Tracker)


def test_what_the_webhook_could_never_say() -> None:
    """The whole reason item 036 exists, asserted as a list.

    Before this, the stored context of a real error was 437 bytes with `culprit` null in every
    delivery. None of the facts below were reachable at all.
    """
    event = _build(_payload())

    assert event.exception_type == "ValueError"
    assert event.frames[-1].abs_path == "/app/src/app/billing.py"
    assert event.frames[-1].lineno == 31
    assert event.frames[-1].context_line == "    raise ValueError(msg)"
    assert event.frames[-1].function == "recalculate"
    assert event.culprit == "app.billing in recalculate"
    assert event.packages["sqlalchemy"] == "2.0.51"
    assert event.runtime == "CPython 3.12.13"
    assert event.handled is False
    assert event.is_useful_for_reproduction


def test_release_environment_and_host_come_from_tags_not_fields() -> None:
    """Confirmed against the live instance. Reading them as top-level keys finds nothing."""
    event = _build(_payload())

    assert event.release == "b292599"
    assert event.environment == "prod"
    assert event.server_name == "65d5deab0608"


def test_frames_keep_their_order_innermost_last() -> None:
    event = _build(_payload())

    assert [f.function for f in event.frames] == ["<module>", "recalculate"]


def test_an_event_with_no_line_number_says_it_cannot_help() -> None:
    """`not-reproducible` should be a verdict about the bug, not about our own thin data.

    Dispatching against an event with no code location and then reporting that the agent could not
    reproduce it would blame the agent for something we knew before we started.
    """
    thin = _payload(entries=[])

    assert _build(thin).is_useful_for_reproduction is False


# --- the scrubbing, which is half the item -------------------------------------------------


def test_a_password_in_frame_locals_never_survives_the_fetch() -> None:
    event = _build(_payload())
    variables = event.frames[-1].variables

    assert variables is not None
    assert variables["password"] == REDACTED
    # And the frame is still a frame: the useful local is untouched.
    assert variables["total"] == "-40"


def test_a_dsn_hiding_in_sys_argv_is_caught_by_shape() -> None:
    """Not hypothetical: this is a real event in our own tracker.

    No name-based rule would flag `sys.argv`, which is exactly why the shape defence exists.
    """
    event = _build(_payload())

    assert "s3cr3t" not in repr(event.extra)


def test_a_bearer_token_inside_an_ordinary_string_is_caught() -> None:
    event = _build(_payload())
    variables = event.frames[-1].variables

    assert variables is not None
    assert "abcdefghijklmnopqrstuvwxyz012345" not in variables["note"]


def test_the_tracker_token_itself_cannot_be_stored() -> None:
    """If the tracker ever echoed our credential back, it must not land in the database."""
    event = _build(_payload(extra={"echo": "your token is tok-abc"}))

    assert "tok-abc" not in repr(event.extra)


def test_a_webhook_token_in_a_url_is_caught() -> None:
    """Item 015 found this exact string in three places. It must not come back in through here."""
    event = _build(_payload(extra={"url": "http://h/webhooks/glitchtip/hullwork/s3cretpath"}))

    assert "s3cretpath" not in repr(event.extra)


def test_absent_locals_and_empty_locals_are_different_facts() -> None:
    """One means the SDK was configured not to send them; the other means the scope was empty."""
    payload = _payload()
    frames = payload["entries"][0]["data"]["values"][0]["stacktrace"]["frames"]
    frames[1].pop("vars")

    assert _build(payload).frames[-1].variables is None
    assert _build(_payload()).frames[0].variables is None  # the outer frame never had any


def test_a_huge_local_is_truncated_and_says_so() -> None:
    payload = _payload()
    payload["entries"][0]["data"]["values"][0]["stacktrace"]["frames"][1]["vars"] = {
        "blob": "x" * (MAX_VAR_CHARS + 500)
    }

    variables = _build(payload).frames[-1].variables

    assert variables is not None
    assert "more characters]" in variables["blob"]
    assert len(variables["blob"]) < MAX_VAR_CHARS + 100


def test_deeply_nested_locals_terminate() -> None:
    """The event is a tree from outside; following it without a bound is our problem."""
    nested: dict[str, Any] = {"leaf": 1}
    for _ in range(200):
        nested = {"n": nested}
    payload = _payload()
    payload["entries"][0]["data"]["values"][0]["stacktrace"]["frames"][1]["vars"] = {"d": nested}

    assert _build(payload).frames[-1].variables is not None


# --- provider quirks that were measured, not assumed ----------------------------------------


def test_snake_case_from_a_list_route_still_parses() -> None:
    """The detail routes answer camelCase and the list routes snake_case, omitting `eventID`.

    The adapter avoids list routes on purpose, but a parser that silently returns nothing for half
    of a provider's own API is a trap for whoever reaches for one later.
    """
    payload = _payload()
    del payload["eventID"]
    payload["event_id"] = "abc123"
    payload["date_created"] = payload.pop("dateCreated")
    frames = payload["entries"][0]["data"]["values"][0]["stacktrace"]["frames"]
    frames[1]["lineno"] = frames[1].pop("lineNo")
    frames[1]["abs_path"] = frames[1].pop("absPath")

    event = _build(payload)

    assert event.provider_event_id == "abc123"
    assert event.frames[-1].lineno == 31
    assert event.occurred_at is not None


def test_a_permalink_with_no_issue_id_is_a_permanent_failure() -> None:
    """Permanent, not retryable: retrying a malformed reference forever is how a sweep jams."""
    with pytest.raises(PermanentTrackerError, match="no issue id"):
        _tracker().fetch_latest("http://tracker.invalid/organizations/foo")


def test_an_unparseable_event_returns_none_rather_than_raising() -> None:
    assert _tracker()._build({"nothing": True}) is None


def test_the_scrubber_leaves_the_shape_alone() -> None:
    """Structure is what the agent reproduces from. Safety must not be bought by dropping it."""
    scrubbed = Scrubber(shapes=True).scrub({"a": [{"password": "x", "keep": 1}]})

    assert scrubbed == {"a": [{"password": REDACTED, "keep": 1}]}
