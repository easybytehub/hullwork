"""The receiving end enforces the same whitelist as the sending end. Item 154.

**Why this matters more than the sender's version.** `hullwork.upstream` builds the payload on
somebody else's machine, in code they can edit — so *"the payload cannot contain your data"* is, on
its own, a property of a client. The relay in front of our tracker re-validates, which turns that
into a property of the system: a hand-crafted envelope full of email addresses is dropped rather
than laundered through our ingest into our own tracker.

The relay is `deploy/relay/relay.py`, which is not published. The **enumeration** it enforces is
`hullwork.upstream`, which is — and this file exercises that half, because that is the half that
has to be right.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hullwork import upstream
from hullwork.upstream import Instance, upstream_payload, why_not_a_payload

ROOT = Path(__file__).resolve().parent.parent

CRASH = {
    "exception": {
        "values": [
            {
                "type": "ManifestError",
                "stacktrace": {
                    "frames": [
                        {"module": "hullwork.manifest", "function": "parse_manifest", "lineno": 707}
                    ]
                },
            }
        ]
    }
}


def _a_real_payload() -> dict[str, Any]:
    payload = upstream_payload(CRASH, Instance(installation="a" * 32, operation="receiver"))
    assert payload is not None
    return payload


def test_what_the_sender_builds_is_what_the_receiver_accepts() -> None:
    """The two ends agree, which is the only reason enforcing twice is not enforcing two things.

    Built by `upstream_payload` and handed straight to the validator: if these ever disagree, every
    honest report is dropped and the only events left are the forged ones.
    """
    assert why_not_a_payload(_a_real_payload()) is None


@pytest.mark.parametrize(
    ("what", "damage"),
    [
        ("an extra field carrying an address", {"reporter": "ana@cliente-real.es"}),
        ("a message smuggled in as a type", {"exception": "KeyError: 'currency' in acme.billing"}),
        ("an identifier that is not an identifier", {"installation": "acme/checkout-api"}),
        ("somebody else's frame", {"frames": [{"module": "acme.billing", "function": "x",
                                               "lineno": 1}]}),
        ("a frame with a path in it", {"frames": [{"module": "hullwork.a", "function": "x",
                                                   "lineno": 1, "abs_path": "/Users/ana/x.py"}]}),
        ("a note in the counts", {"counts": {"projects": 1, "items": 1, "attempts": 1,
                                             "outcomes": "acme"}}),
        ("an operation nobody enumerated", {"operation": "cli:exfiltrate"}),
        ("a schema from the future", {"schema": 99}),
        ("the tag the relay decides", {"origin": "ours"}),
    ],
)
def test_a_forged_payload_is_refused_with_a_reason(what: str, damage: dict[str, Any]) -> None:
    """One case per way somebody would try, and each answers *why* rather than *no*.

    The reason is what the relay counts drops by — *"why did that get dropped"* is the question a
    counter has to answer to be worth keeping — so a refusal with no reason is a defect here.
    """
    forged = {**_a_real_payload(), **damage}

    why = why_not_a_payload(forged)
    assert why is not None, f"{what} was accepted"
    assert len(why) > 10, "a reason nobody can act on is not a reason"


def test_the_message_length_ceiling_is_what_stops_a_message() -> None:
    """`exception` is a class name. A sentence in that field is the obvious way to smuggle prose."""
    forged = {**_a_real_payload(), "exception": "A" * (upstream.STRING_CEILING + 1)}
    assert why_not_a_payload(forged) is not None

    assert why_not_a_payload({**_a_real_payload(), "exception": "A" * 20}) is None


def test_a_payload_that_is_not_an_object_is_refused() -> None:
    for junk in ("[]", '"a string"', "42", "null"):
        assert why_not_a_payload(json.loads(junk)) is not None


def test_the_frame_ceiling_is_enforced_on_the_way_in_too() -> None:
    """The sender bounds this at twenty. A forged envelope does not have to."""
    many = [
        {"module": "hullwork.engine", "function": "step", "lineno": n}
        for n in range(upstream.FRAME_CEILING + 1)
    ]
    assert why_not_a_payload({**_a_real_payload(), "frames": many}) is not None
    assert why_not_a_payload({**_a_real_payload(), "frames": many[:-1]}) is None


def test_no_frames_at_all_is_refused() -> None:
    """A payload with nothing in `frames` says only that *something* crashed somewhere, which is not
    worth storing and is what an emptied-out forgery looks like.
    """
    assert why_not_a_payload({**_a_real_payload(), "frames": []}) is not None


def test_a_null_installation_is_allowed_because_a_first_run_has_none() -> None:
    """The crash most worth having is the one from an instance whose database is not there yet."""
    assert why_not_a_payload({**_a_real_payload(), "installation": None}) is None


def test_the_relay_imports_the_enumeration_rather_than_copying_it() -> None:
    """**Two whitelists are two whitelists**, and the one nobody reads is the one that drifts.

    Asserted on the relay's source because that is where the copy would be: a literal set of keys in
    the relay would pass every test in this file while diverging from what the sender builds.
    """
    relay = ROOT / "deploy/relay/relay.py"
    if not relay.is_file():
        pytest.skip("the relay is not in this tree (it is withheld from publication)")

    text = relay.read_text(encoding="utf-8")
    assert "from hullwork.upstream import why_not_a_payload" in text
    for copied in ("KEYS =", "COUNT_KEYS =", "FRAME_KEYS ="):
        assert copied not in text, f"the relay has its own copy of {copied}"


def test_the_relay_refuses_on_the_declared_length_before_reading() -> None:
    """A cap that reads the body first is a cap on storage, not on traffic."""
    relay = ROOT / "deploy/relay/relay.py"
    if not relay.is_file():
        pytest.skip("the relay is not in this tree (it is withheld from publication)")

    text = relay.read_text(encoding="utf-8")
    before_read = text.index("if declared > BODY_CAP")
    assert before_read < text.index("self.rfile.read(declared)")
    assert "413" in text, "a body over the cap is refused with a status, not truncated"


def test_the_enumeration_imports_without_an_orm() -> None:
    """**The relay runs on the public interface, so what it imports matters.**

    It installs this package with `--no-deps` and calls `why_not_a_payload`. That works only while
    `hullwork.upstream` needs nothing heavy at import time — and it did not, until this was
    measured: `from hullwork.models import …` at module scope pulled in SQLAlchemy, so the
    public-facing process would have needed an ORM to check the shape of a dict.

    In a subprocess, because the suite has already imported everything by the time this runs.
    """
    import subprocess
    import sys

    done = subprocess.run(
        [
            sys.executable,
            "-c",
            "import hullwork.upstream as u, sys;"
            "print('sqlalchemy' in sys.modules, u.why_not_a_payload({}) is not None)",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert done.stdout.strip() == "False True", (
        f"the validator no longer imports on its own: {done.stdout!r} {done.stderr[-300:]!r}"
    )
