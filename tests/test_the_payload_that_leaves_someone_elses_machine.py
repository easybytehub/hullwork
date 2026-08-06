"""What may travel upstream, and the proofs that nothing else can. Item 151.

Two things are being tested and they pull in opposite directions, which is why the hostile case and
the positive case are both here and neither is allowed to pass alone:

* an event stuffed with a stranger's data must yield a payload containing none of it;
* a crash in our own code must yield a payload that still says what broke and where — otherwise a
  constructor that returns `{}` passes the first test perfectly.

The hostile event below is the one measured on 2026-08-05 through the product's own `before_send`:
4,826 bytes, six identifiers, from a crash raised while processing a fabricated customer payload.
It is a fixture rather than a live capture so the six strings are literal and this file can be read
without running it. What a fixture cannot cover — an event the SDK itself assembled, on its own
defaults — is `test_a_live_sdk_event_with_locals_switched_on_still_says_only_three_things`.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import socket
import uuid
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session, sessionmaker

from hullwork import upstream
from hullwork.db import make_engine
from hullwork.upstream import Instance, installation_id, upstream_payload

ROOT = Path(__file__).resolve().parent.parent

#: A customer's manifest, in a frame local because that is where the parser had it.
THEIR_MANIFEST = "project: checkout-api\nruntime:\n  base: registry.cliente-real.es/python:3.12\n"

#: The six things that were in the event, each written out so a substring search cannot miss one.
#: These are what the payload is checked against; they are fabricated, but they are the shapes the
#: measurement found: an address, a repository, a hostname, a module, a file's contents, a machine.
IDENTIFIERS = (
    "ana@cliente-real.es",
    "acme/checkout-api",
    "tracker.cliente-real.es",
    "acme.billing",
    "registry.cliente-real.es/python:3.12",
    "srv-acme-01",
)

#: The measured event, trimmed to the fields that carry the six. Everything here is real SDK
#: vocabulary: `vars` per frame, `server_name`, `request`, `breadcrumbs`, `modules`.
HOSTILE: dict[str, Any] = {
    "event_id": "0" * 32,
    "level": "error",
    "server_name": "srv-acme-01",
    "release": "acme-internal-build-3",
    "environment": "production",
    "exception": {
        "values": [
            {
                "type": "KeyError",
                "value": (
                    "'currency' while materialising item 'KeyError: currency in "
                    "acme.billing' for acme/checkout-api at "
                    "https://tracker.cliente-real.es/api/0/"
                ),
                "stacktrace": {
                    "frames": [
                        {
                            "module": "acme.billing",
                            "function": "charge",
                            "lineno": 88,
                            "abs_path": "/srv/acme/app/billing.py",
                            "vars": {"customer": "ana@cliente-real.es"},
                        },
                        {
                            "module": "hullwork.ingest",
                            "function": "record_delivery",
                            "lineno": 918,
                            "abs_path": "/app/hullwork/ingest.py",
                            "vars": {
                                "manifest_text": THEIR_MANIFEST,
                                "tracker": "https://tracker.cliente-real.es/api/0/",
                                "repo": "acme/checkout-api",
                            },
                        },
                    ]
                },
            }
        ]
    },
    "request": {
        "url": "https://hullwork.cliente-real.es/webhooks/glitchtip/acme/s3cr3t",
        "headers": {"Host": "hullwork.cliente-real.es"},
    },
    "breadcrumbs": {
        "values": [{"message": "fetched hullwork.yml from acme/checkout-api", "category": "forge"}]
    },
    "modules": {"psycopg": "3.2.1", "sqlalchemy": "2.0.36", "acme-internal-sdk": "4.1.0"},
    "contexts": {"runtime": {"name": "CPython", "version": "3.12.7"}},
}

HERE = Instance(installation="a" * 32, operation="receiver", projects=3, items=41, attempts=7)


def _blob(payload: dict[str, Any] | None) -> str:
    assert payload is not None
    return json.dumps(payload, sort_keys=True)


def _the_way_it_would_have_been_done(event: dict[str, Any]) -> dict[str, Any]:
    """The filter version, written out so the leak is visible rather than argued about.

    Every field the measurement named, removed by name — which is what anybody would write, and what
    `test_the_filter_version_leaks` exists to disqualify. Nothing is wrong with this code; the
    approach is what is wrong with it.
    """
    filtered: dict[str, Any] = json.loads(json.dumps(event))
    for field in ("server_name", "request", "breadcrumbs", "modules"):
        filtered.pop(field, None)
    for value in filtered.get("exception", {}).get("values", []):
        for frame in value.get("stacktrace", {}).get("frames", []):
            frame.pop("vars", None)
    return filtered


# --------------------------------------------------------------------------------------------
# Hostile
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("identifier", IDENTIFIERS)
def test_no_identifier_from_the_measured_event_survives(identifier: str) -> None:
    """Parametrised so a failure names which one got through, not that one did."""
    assert identifier not in _blob(upstream_payload(HOSTILE, HERE))


def test_the_filter_version_leaks_which_is_the_argument_for_constructing() -> None:
    """The negative control for every assertion above.

    Without this, the hostile test proves nothing about the *approach* — only that this particular
    constructor happens to be careful. The filter removes all six sources the measurement found and
    two identifiers still travel, because they were interpolated into the exception message and into
    a breadcrumb by code that had no idea it was handling anything sensitive.
    """
    leaked = json.dumps(_the_way_it_would_have_been_done(HOSTILE))
    survivors = [identifier for identifier in IDENTIFIERS if identifier in leaked]

    assert survivors, "the filter stopped everything, so this control has lost its point"
    assert "acme/checkout-api" in survivors, "the repository is in the message, not in a field"


def test_each_dangerous_field_is_absent_by_its_own_name() -> None:
    """Named one at a time. A loop over "sensitive things" passes on an empty dict, which is the
    failure mode this whole file is arranged against.
    """
    payload = upstream_payload(HOSTILE, HERE)
    assert payload is not None
    blob = _blob(payload)

    assert "vars" not in blob
    assert "server_name" not in blob
    assert "request" not in blob
    assert "breadcrumbs" not in blob
    assert "modules" not in blob
    assert "abs_path" not in blob
    assert "'currency'" not in blob, "the exception message travelled"
    assert "acme-internal-build-3" not in blob, "the release string came from the event"
    assert payload["release"] != HOSTILE["release"]
    assert all(set(frame) == upstream.FRAME_KEYS for frame in payload["frames"])


def test_the_payload_carries_exactly_the_enumerated_keys() -> None:
    """Equality, not containment, at all three levels.

    A future SDK version that adds a field adds it to an event this module does not read — but only
    while this stays an equality. Containment would let a key be added here and nobody notice.
    """
    payload = upstream_payload(HOSTILE, HERE)
    assert payload is not None

    assert set(payload) == upstream.KEYS
    assert set(payload["counts"]) == upstream.COUNT_KEYS
    for frame in payload["frames"]:
        assert set(frame) == upstream.FRAME_KEYS


def test_the_whole_payload_stays_small() -> None:
    """4,826 bytes in, and the number below is what comes out. Recorded as a test because "smaller"
    is the kind of claim that decays: a size ceiling fails the day somebody adds a list.
    """
    size = len(_blob(upstream_payload(HOSTILE, HERE)))
    assert size < 512, f"the constructed payload has grown to {size} bytes"


# --------------------------------------------------------------------------------------------
# Positive — without these, a constructor that returns nothing passes everything above
# --------------------------------------------------------------------------------------------


def test_our_own_frame_survives_with_all_three_fields() -> None:
    payload = upstream_payload(HOSTILE, HERE)
    assert payload is not None

    assert payload["frames"] == [
        {"module": "hullwork.ingest", "function": "record_delivery", "lineno": 918}
    ]
    assert payload["exception"] == "KeyError"
    assert payload["operation"] == "receiver"
    assert payload["counts"] == {"projects": 3, "items": 41, "attempts": 7, "outcomes": 0}
    assert payload["python"] == platform.python_version()


def test_a_live_sdk_event_with_locals_switched_on_still_says_only_three_things() -> None:
    """The SDK builds the event, on its own defaults, and the constructor still cuts it down.

    **`include_local_variables` is deliberately left on here.** Production turns it off in
    `configure_error_reporting`, and this test does not, because what travels upstream must not
    depend on an init argument somebody can change or on an SDK release changing its own default.
    Item 150 earned that suspicion: a capability that worked in a checkout and not in the artefact.

    The crash is real — a customer's manifest text through the real parser, which raises with that
    text in a frame local, plus a chained `YAMLError` from `yaml.scanner`. That second one is why
    this is worth running live: a fixture would not have thought to include somebody else's library
    at the top of our own stack.
    """
    sentry_sdk = pytest.importorskip("sentry_sdk")
    from hullwork.manifest import ManifestError, parse_manifest

    seen: list[dict[str, Any]] = []

    def capture(event: dict[str, Any], _hint: object) -> None:
        seen.append(event)
        return None  # dropped: nothing leaves this process

    sentry_sdk.init(
        dsn="https://k@localhost/1",
        before_send=capture,
        include_local_variables=True,
        # No sessions and no traces, so nothing here tries to reach `localhost` and time out.
        auto_session_tracking=False,
        traces_sample_rate=0.0,
    )
    try:
        try:
            parse_manifest(THEIR_MANIFEST + "\n\tbroken: [", source="acme/checkout-api")
        except ManifestError:
            sentry_sdk.capture_exception()
        sentry_sdk.flush()
    finally:
        sentry_sdk.init(dsn=None)  # leave no live client behind for the rest of the suite

    assert seen, "the SDK produced no event, so this test measured nothing"
    live = json.dumps(seen[-1])
    assert '"vars"' in live, "the SDK sent no locals, so there was nothing to cut"
    assert "registry.cliente-real.es" in live, "the customer's manifest was not in the event"
    assert "acme/checkout-api" in live, "the repository was not in the event"

    payload = upstream_payload(seen[-1], HERE)
    assert payload is not None
    blob = _blob(payload)

    assert "cliente-real" not in blob
    assert "acme/checkout-api" not in blob, "the `source` argument is the customer's repository"
    assert "yaml" not in blob, "the chained YAMLError brought somebody else's frames with it"
    assert payload["exception"] == "ManifestError"
    assert any(frame["module"].startswith("hullwork.") for frame in payload["frames"])
    assert all(set(frame) == upstream.FRAME_KEYS for frame in payload["frames"])


# --------------------------------------------------------------------------------------------
# Which frames travel
# --------------------------------------------------------------------------------------------


def _event(frames: list[dict[str, Any]]) -> dict[str, Any]:
    return {"exception": {"values": [{"type": "RuntimeError", "stacktrace": {"frames": frames}}]}}


def test_three_kinds_of_foreign_frame_are_dropped_and_ours_is_not() -> None:
    """Mixed on purpose: the operator's application, a dependency, and a frame the SDK could not
    name. The last one is the interesting case — it is dropped rather than falling back to its path,
    because `/Users/ana/src/...` identifies a person and a module name does not.
    """
    payload = upstream_payload(
        _event(
            [
                {"module": "acme.billing", "function": "charge", "lineno": 88},
                {"module": "sqlalchemy.engine.base", "function": "_execute", "lineno": 1640},
                {"module": None, "function": "run", "lineno": 3, "abs_path": "/Users/ana/x.py"},
                {"module": "hullworkish.plugin", "function": "hook", "lineno": 12},
                {"module": "hullwork.work", "function": "attempt", "lineno": 757},
            ]
        ),
        HERE,
    )
    assert payload is not None

    assert payload["frames"] == [
        {"module": "hullwork.work", "function": "attempt", "lineno": 757}
    ], "a module merely starting with the letters is somebody else's code"


def test_the_frame_list_is_bounded() -> None:
    """A recursion error is a thousand frames, all ours, on somebody else's bandwidth."""
    deep = [{"module": "hullwork.engine", "function": "step", "lineno": n} for n in range(200)]
    payload = upstream_payload(_event(deep), HERE)
    assert payload is not None

    assert len(payload["frames"]) == upstream.FRAME_CEILING
    assert payload["frames"][-1]["lineno"] == 199, "the crash site is the end of the list, keep it"


def test_frames_from_a_chained_exception_are_collected_from_every_link() -> None:
    """`raise X from Y` puts the cause first, and the cause is usually the interesting half."""
    payload = upstream_payload(
        {
            "exception": {
                "values": [
                    {
                        "type": "ValidationError",
                        "stacktrace": {
                            "frames": [
                                {"module": "hullwork.manifest", "function": "p", "lineno": 1}
                            ]
                        },
                    },
                    {
                        "type": "ManifestError",
                        "stacktrace": {
                            "frames": [{"module": "hullwork.ingest", "function": "r", "lineno": 2}]
                        },
                    },
                ]
            }
        },
        HERE,
    )
    assert payload is not None

    assert [frame["module"] for frame in payload["frames"]] == [
        "hullwork.manifest",
        "hullwork.ingest",
    ]
    assert payload["exception"] == "ManifestError", "the type is the one that was raised last"


# --------------------------------------------------------------------------------------------
# What is not ours to send
# --------------------------------------------------------------------------------------------


def test_an_event_with_no_exception_is_not_sent() -> None:
    """A `log.error` becomes an event whose only content is its message — the one field that cannot
    travel. Nothing to say, so nothing is said. Item 157 is where that gets a code instead.
    """
    assert upstream_payload({"level": "error", "logentry": {"message": "x"}}, HERE) is None


def test_a_crash_with_no_frame_of_ours_is_not_sent() -> None:
    """The difference between reporting Hullwork's failures and reporting failures near Hullwork."""
    assert (
        upstream_payload(
            _event([{"module": "acme.billing", "function": "charge", "lineno": 88}]), HERE
        )
        is None
    )


def test_an_exception_with_no_type_is_not_sent() -> None:
    assert upstream_payload({"exception": {"values": [{"value": "something"}]}}, HERE) is None


# --------------------------------------------------------------------------------------------
# The operation, and the drift that would make it a lie
# --------------------------------------------------------------------------------------------


def test_an_operation_nobody_enumerated_becomes_unknown() -> None:
    """Not an exception: refusing to report a crash because the label for it was wrong would lose
    the crash to protect the label. And `cli:acme-secret-project` is exactly what a caller
    interpolating a string would send.
    """
    payload = upstream_payload(HOSTILE, Instance(installation="b" * 32, operation="cli:acme-thing"))
    assert payload is not None
    assert payload["operation"] == upstream.UNKNOWN
    assert "acme-thing" not in _blob(payload)


def test_every_subcommand_the_parser_accepts_has_an_operation() -> None:
    """The drift test. A subcommand added next year reports as `unknown` unless somebody remembers
    this list — and `unknown` is silent, which is the kind of gap item 157 is about.
    """
    from hullwork.cli import build_parser

    subcommands: set[str] = set()
    # `_actions` and `_SubParsersAction`: argparse exposes no public way to enumerate subcommands,
    # and asking the parser is still better than a second copy of the list to keep in step.
    for action in build_parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            subcommands |= set(action.choices)

    assert subcommands, "this test has lost its subject"
    missing = sorted(name for name in subcommands if f"cli:{name}" not in upstream.OPERATIONS)
    assert not missing, f"add these to upstream.OPERATIONS: {missing}"


# --------------------------------------------------------------------------------------------
# The installation id
# --------------------------------------------------------------------------------------------


def _migrate(url: str) -> None:
    """The migration chain against a temporary database.

    `-x url=` and not `sqlalchemy.url`: `migrations/env.py` reads the setting, so the main option is
    silently ignored and the chain would run against whatever `HULLWORK_DATABASE_URL` says — which
    is how these two tests first failed with `no such table: installation` on a database that had
    been migrated perfectly, somewhere else.
    """
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.cmd_opts = argparse.Namespace(x=[f"url={url}"])
    command.upgrade(config, "head")


def test_the_id_is_written_once_and_read_afterwards(session: Session) -> None:
    first = installation_id(session)
    assert first is not None, "the default mints, so this is never None here"
    assert re.fullmatch(r"[0-9a-f]{32}", first), first
    assert installation_id(session) == first


def test_reading_without_minting_answers_none_and_writes_nothing(session: Session) -> None:
    """`mint=False`, for `hullwork config --telemetry` (item 153).

    The command exists so somebody can decide whether to allow this, so it must not create the row
    that identifies them as the price of asking what would be sent.
    """
    from hullwork.models import Installation

    assert installation_id(session, mint=False) is None
    assert session.get(Installation, 1) is None
    assert installation_id(session) is not None, "and minting still works afterwards"


def test_the_id_survives_a_restart(tmp_path: Path) -> None:
    """A new engine, a new session, the same file — which is what a restart is. Item 150's lesson
    applies: the interesting behaviour is the one across a process boundary.
    """
    url = f"sqlite:///{tmp_path / 'restart.db'}"
    _migrate(url)

    seen = []
    for _ in range(2):
        engine = make_engine(url)
        with sessionmaker(bind=engine)() as db:
            seen.append(installation_id(db))
        engine.dispose()

    assert seen[0] == seen[1]
    assert seen[0] is not None
    assert re.fullmatch(r"[0-9a-f]{32}", seen[0])


def test_two_databases_are_two_installations(tmp_path: Path) -> None:
    """Otherwise forty events from one deployment and one from forty are the same forty events."""
    ids = []
    for name in ("one.db", "two.db"):
        url = f"sqlite:///{tmp_path / name}"
        _migrate(url)
        engine = make_engine(url)
        with sessionmaker(bind=engine)() as db:
            ids.append(installation_id(db))
        engine.dispose()

    assert ids[0] != ids[1]


def test_the_id_is_derived_from_nothing_about_this_machine(session: Session) -> None:
    """The property that makes it countable rather than identifying.

    A hash of a hostname is still the hostname to anybody holding a list of hostnames to try, so the
    check is against the raw values *and* against their digests.
    """
    import hashlib

    identifier = installation_id(session)
    assert identifier is not None
    machine = [
        socket.gethostname(),
        socket.getfqdn(),
        platform.node(),
        platform.platform(),
        str(uuid.getnode()),
        str(Path.home()),
    ]

    for fact in machine:
        if not fact:
            continue
        assert fact.lower() not in identifier
        # Weak digests on purpose: the question is whether the identifier *is* a hash of the
        # machine, and somebody reaching for one would reach for these.
        for digest in (hashlib.md5, hashlib.sha1, hashlib.sha256):
            assert digest(fact.encode()).hexdigest()[:32] != identifier


def test_the_table_stays_empty_until_something_asks(session: Session) -> None:
    """An upgrade must enrol nobody: the migration creates the table and writes no row."""
    from hullwork.models import Installation

    assert session.get(Installation, 1) is None
    installation_id(session)
    assert session.get(Installation, 1) is not None
