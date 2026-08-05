"""Whether the dispatcher's own errors reach the tracker, said out loud. Item 110.

Item 090 built the reporting. Whether it is **on** was knowable by reading the container's first
line of output and in no other way, which is the thing this product exists to stop people doing —
and `/ready` cannot help, because it answers for the receiver by asking itself and the dispatcher
listens on nothing (DR-0009).

So the answer is left on the one row the two programs share. Three states, and the third is the
whole care taken here: `None` is *not recorded*, which a lease taken by an older build says, and
reporting that as "off" would announce a capability switched off on the strength of nothing —
item 105's defect, in the place an operator reads.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from hullwork import lease
from hullwork.cli import _dispatcher_reporting_line
from hullwork.cli import main as cli_main
from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.models import Base, DispatcherLease


@pytest.fixture
def session(tmp_path: Path) -> Session:
    engine = make_engine(f"sqlite:///{tmp_path / 'lease.db'}")
    Base.metadata.create_all(engine)
    return make_session_factory(engine)()


def test_the_lease_records_what_this_run_decided(session: Session) -> None:
    """Written beside the holder, because it describes **this** run. A dispatcher that took the
    lease with reporting off does not become a reporting one because the next process would be."""
    assert lease.acquire(session, "first", error_reporting=True) is True
    assert lease.reporting_of(session) is True

    session.get(DispatcherLease, 1).renewed_at = lease.RELEASED  # type: ignore[union-attr]
    session.commit()
    assert lease.acquire(session, "second", error_reporting=False) is True

    assert lease.reporting_of(session) is False, "the new holder's answer, not the old one's"


def test_an_unrecorded_lease_is_not_a_lease_with_reporting_off(session: Session) -> None:
    """The state that costs nothing to get wrong and everything to trust. A build older than the
    column wrote no answer; `None` says so, and `False` would be a claim nobody made."""
    assert lease.reporting_of(session) is None, "before any dispatcher has ever run"

    lease.acquire(session, "an-older-build")  # the call as it was before item 110

    assert lease.reporting_of(session) is None


@pytest.mark.parametrize(
    ("state", "reporting", "expected"),
    [
        ("alive", True, "the dispatcher reports its own errors"),
        ("alive", False, "does **not** report its own errors"),
        ("stale", True, "the last dispatcher reports its own errors"),
        ("released", False, "does **not** report its own errors"),
        ("alive", None, "was not recorded"),
        ("never", None, "no dispatcher has ever taken the lease"),
    ],
)
def test_it_is_said_in_words_and_the_three_states_stay_three(
    state: str, reporting: bool | None, expected: str
) -> None:
    """Six readings, and no two of them mean the same thing to somebody deciding what to fix."""
    assert expected in _dispatcher_reporting_line(state, reporting)


def test_off_says_where_the_variable_did_not_reach(session: Session) -> None:
    """A line that only said "off" would send an operator to check a setting that is probably
    present — in the *other* service. The two are configured separately and that is the fact."""
    said = _dispatcher_reporting_line("alive", False)

    assert "HULLWORK_ERROR_DSN" in said
    assert "configured separately" in said


def test_status_says_it_next_to_whether_anything_is_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End to end through the command an operator actually types, because the point of this item is
    that the answer was already in the process and not in the report."""
    url = f"sqlite:///{tmp_path / 'status.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as db:
        lease.acquire(db, "holder", error_reporting=True)

    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    get_settings.cache_clear()
    try:
        out = io.StringIO()
        cli_main(["status"], out=out)
        printed = out.getvalue()
    finally:
        get_settings.cache_clear()

    assert "a dispatcher is running" in printed
    assert "reports its own errors to the tracker" in printed


def test_the_json_carries_null_rather_than_false(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`--json` is what a monitor reads, and a monitor that cannot tell *unknown* from *off* pages
    somebody about a capability nobody ever measured."""
    import json

    url = f"sqlite:///{tmp_path / 'json.db'}"
    Base.metadata.create_all(make_engine(url))

    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    get_settings.cache_clear()
    try:
        out = io.StringIO()
        cli_main(["status", "--json"], out=out)
        payload = json.loads(out.getvalue())
    finally:
        get_settings.cache_clear()

    assert payload["dispatcher_loop"]["error_reporting"] is None
