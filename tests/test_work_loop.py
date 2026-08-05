"""The dispatcher as a resident process. Item 075, DR-0009.

The constraint that makes this coherent with DR-0005: **this process may hold a push credential
precisely because it accepts nothing from the network.** `main.lifespan` refuses that credential
to the receiver, and the reason it gives is the pairing — listening *and* holding — not the
duration. So the gate that matters most here is the one asserting no socket is ever bound.
"""

import argparse
import io
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from hullwork import lease
from hullwork.cli import main as cli_main
from hullwork.config import get_settings
from hullwork.models import Base, DispatcherLease


def _age(session: Session, seconds: int) -> None:
    """Push the lease's renewal into the past, which is how a dead dispatcher looks."""
    row = session.get(DispatcherLease, 1)
    assert row is not None
    row.renewed_at = datetime.now(UTC) - timedelta(seconds=seconds)
    session.commit()


def test_the_first_dispatcher_takes_the_lease(session: Session) -> None:
    assert lease.acquire(session, "first") is True
    assert lease.state(session)[0] == "alive"


def test_a_second_dispatcher_declines_while_the_first_is_alive(session: Session) -> None:
    """**Gate 3.** Asserted on the answer, not by reading the lock.

    Two loops both claiming items is the state the whole module exists to prevent, and `_SWEEP_LOCK`
    cannot prevent it because it is in-process — its own comment says so.
    """
    assert lease.acquire(session, "first") is True

    assert lease.acquire(session, "second") is False

    row = session.get(DispatcherLease, 1)
    assert row is not None
    assert row.holder == "first", "the incumbent keeps it; a decline must not overwrite"


def test_an_expired_lease_is_taken_over(session: Session) -> None:
    """The other half of gate 3, and the half that keeps a crash from being permanent.

    Without this, one `docker kill` at the wrong moment means no dispatcher ever runs again.
    """
    lease.acquire(session, "dead")
    _age(session, lease.LEASE_SECONDS + 60)

    assert lease.acquire(session, "next") is True
    row = session.get(DispatcherLease, 1)
    assert row is not None
    assert row.holder == "next"


def test_a_released_lease_is_free_immediately(session: Session) -> None:
    """The courtesy path: a clean shutdown must not make the next start wait an hour."""
    lease.acquire(session, "first")
    lease.release(session, "first")

    assert lease.acquire(session, "second") is True


def test_releasing_somebody_else_s_lease_does_nothing(session: Session) -> None:
    """A loop that lost its lease must not free the one that took it over."""
    lease.acquire(session, "first")
    lease.acquire(session, "first")
    row = session.get(DispatcherLease, 1)
    assert row is not None
    row.holder = "somebody-else"
    session.commit()

    lease.release(session, "first")

    assert lease.state(session)[0] == "alive", "the live holder's lease survived"


def test_renewal_is_the_heartbeat(session: Session) -> None:
    """One field, deliberately. A separate heartbeat could disagree with the lock about who runs."""
    lease.acquire(session, "first")
    _age(session, lease.ALIVE_SECONDS + 60)
    assert lease.state(session)[0] == "stale"

    assert lease.renew(session, "first") is True

    assert lease.state(session)[0] == "alive"


def test_a_dispatcher_that_lost_its_lease_is_told(session: Session) -> None:
    """It has to stop rather than work beside the new holder. Reported, never reacquired."""
    lease.acquire(session, "first")
    row = session.get(DispatcherLease, 1)
    assert row is not None
    row.holder = "second"
    session.commit()

    assert lease.renew(session, "first") is False


def test_status_tells_the_three_states_apart(session: Session) -> None:
    """**Gate 4.** The middle one is the point.

    Before this, an operator could see items waiting and had no way to distinguish a dispatcher that
    was busy from one that died four days ago — and those need opposite reactions.
    """
    assert lease.state(session) == ("never", None)

    lease.acquire(session, "first")
    assert lease.state(session)[0] == "alive"

    _age(session, lease.ALIVE_SECONDS + 60)
    kind, when = lease.state(session)
    assert kind == "stale"
    assert when is not None, "and it says since when, or an operator cannot judge"


def test_the_holder_never_names_the_machine_or_the_user() -> None:
    """It reaches the database and the logs. No place to disclose who runs Hullwork."""
    import getpass
    import platform

    holder = lease.new_holder()

    assert platform.node() not in holder
    assert getpass.getuser() not in holder
    assert holder != lease.new_holder(), "and it identifies a run, so two runs differ"


def test_the_loop_binds_no_socket() -> None:
    """**Gate 5, and the one that keeps DR-0009 true.**

    Asserted by containment rather than by watching a live process: the loop's module graph must not
    reach a web framework or a server. That is what stops somebody adding a `/healthz` in eight
    months — they cannot, without importing something this test refuses.

    It is a proxy and worth naming as one. What we want to know is "binds no port"; what we can
    check cheaply and deterministically is "cannot, the machinery is absent". The stronger direct
    check would need to enumerate the process's own sockets, which needs a dependency this project
    does not have — and `socket` being imported below is this test's, not the loop's.
    """
    import hullwork.cli

    forbidden = {"uvicorn", "fastapi", "starlette", "http.server", "socketserver"}
    reached = set()
    seen: set[str] = set()

    def walk(module_name: str) -> None:
        if module_name in seen:
            return
        seen.add(module_name)
        module = __import__(module_name, fromlist=["_"])
        for attr in vars(module).values():
            name = getattr(attr, "__name__", None)
            if isinstance(name, str) and name.split(".")[0] in forbidden:
                reached.add(name)

    walk(hullwork.cli.__name__)
    walk(lease.__name__)
    walk("hullwork.work")

    assert not reached, f"the dispatcher's module graph reaches a server: {sorted(reached)}"
    assert not hasattr(hullwork.cli, "app"), "the CLI must not carry an ASGI application"
    # And the loop must not be holding a listening socket type by accident either.
    assert not any(
        isinstance(value, socket.socket) for value in vars(hullwork.cli).values()
    ), "a module-level socket in the CLI is a listener waiting to happen"


def test_a_released_lease_is_not_reported_as_a_death(session: Session) -> None:
    """**Item 078, and both halves matter.**

    `release` writes a sentinel so the next start need not wait an hour for expiry, and `state` had
    no branch for it — so an orderly `SIGTERM` was reported as `stale` with the sentinel rendered as
    a date: `no dispatcher has run since 1970-01-01`. Measured on the live instance.

    The distinction is not cosmetic. `stale` means the holder **died** and may have left items
    claimed mid-attempt, which sends an operator to `--release-stale`; `released` means somebody
    stopped it and nothing is stuck.
    """
    lease.acquire(session, "first")
    lease.release(session, "first")

    kind, when = lease.state(session)
    assert kind == "released"
    assert when is None, "the sentinel is not a time, and printing it as one is the defect"

    # The other half: a holder that died is still `stale`, still with its date. A test that only
    # checked the new state would let the old one quietly collapse into it.
    lease.acquire(session, "second")
    _age(session, lease.ALIVE_SECONDS + 60)
    kind, when = lease.state(session)
    assert kind == "stale"
    assert when is not None


def test_status_has_a_sentence_for_a_released_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run the command, because the renderer is a dict lookup that raises on a missing key.

    A new state with no sentence would take `hullwork status` down with a `KeyError` on a
    **healthy**
    instance — the one place nobody is watching for a traceback. Asserted by running `status` rather
    than by reading `lease.state`, which is the half that cannot fail this way.
    """
    url = f"sqlite:///{tmp_path / 'lease.db'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        lease.acquire(db, "first")
        lease.release(db, "first")
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    # A **healthy** instance, as the docstring says, which since 2026-08-04 means one with a forge:
    # `status` now exits 1 on an instance that could never file an issue anywhere, and this test is
    # about the lease sentence rather than about that.
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example.com")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "t")
    get_settings.cache_clear()

    out = io.StringIO()
    assert cli_main(["status"], out=out) == 0
    printed = out.getvalue()
    get_settings.cache_clear()

    assert "gave up its lease" in printed
    assert "1970" not in printed, "the sentinel is not a date and must never be printed as one"
    assert "release-stale" not in printed, "nothing died, so nobody should be sent looking"


# --- the dispatcher as a compose service. Item 082 ------------------------------------------------


def _shipped_compose() -> dict[str, Any]:
    """The deployment **this product hands to an installer**, read as data.

    Asserted against real generated output rather than a fixture: the properties below belong to the
    deployment, and a fixture would let the deployment drift away from them silently.

    **Read from the generator, not from a file in this repository** (2026-08-04). It used to load a
    hand-written compose describing the host this project happens to run on, so these tests proved
    the property for *our* deployment and nobody else's. Item 145 made the compose generated from
    `Settings`, so the file every installer receives is `scaffold.compose(...)` — and that is where
    DR-0009's guarantee has to hold.
    """
    import yaml

    from hullwork.scaffold import compose

    loaded: dict[str, Any] = yaml.safe_load(compose(docker_gid="989"))
    return loaded


def test_the_dispatcher_service_binds_no_port() -> None:
    """**The guarantee that lets this service hold a push credential** (DR-0009).

    The code assertion above proves the program opens no socket. This proves the *deployment* does
    not open one for it — a `ports:` entry or an HTTP healthcheck would recreate exactly the pairing
    `main.lifespan` refuses, from the outside, where no test of the code would see it.
    """
    dispatcher = _shipped_compose()["services"]["dispatcher"]

    assert "ports" not in dispatcher
    assert "expose" not in dispatcher

    # **Disabled, not merely absent**, and the distinction was measured: the image defines a
    # healthcheck for the receiver (`urlopen /ready`), the dispatcher inherits it, and it aims at a
    # port this process does not listen on and must not. Absent from the compose file left the
    # container permanently `unhealthy` — a state that lies, and the day the dispatcher really
    # breaks, that word will carry no new information (item 087).
    assert dispatcher["healthcheck"] == {"disable": True}, (
        "liveness is the lease, read by `hullwork status` — never an answered request"
    )


def test_only_the_dispatcher_gets_the_socket_and_the_code_token() -> None:
    """The credential split, asserted on the deployment rather than trusted to a reviewer.

    Both halves: the receiver must not have the token that can push (`main.lifespan` refuses to boot
    with it, so this is also a boot failure waiting to happen), and it must not have the Docker
    socket, which is root-equivalent on the host.
    """
    services = _shipped_compose()["services"]
    api, dispatcher = services["api"], services["dispatcher"]

    assert "HULLWORK_FORGE_CODE_TOKEN" in dispatcher["environment"]
    assert "HULLWORK_FORGE_CODE_TOKEN" not in api["environment"], (
        "the service refuses to start holding it (spec M2 §1) — this is the 2026-07-29 boot failure"
    )

    def sockets(service: dict[str, Any]) -> list[str]:
        return [v for v in service.get("volumes", []) if "docker.sock" in v]

    assert sockets(dispatcher), "the dispatcher builds sandboxes; it needs the daemon"
    assert not sockets(api), "and the process that listens on the network must never reach it"


def test_both_services_restart_by_themselves() -> None:
    """Item 082's whole point: a reboot returns the instance with nobody logging in."""
    services = _shipped_compose()["services"]

    for name in ("api", "dispatcher"):
        assert services[name]["restart"] == "unless-stopped", name


def test_the_dispatcher_does_not_run_the_migrating_entrypoint() -> None:
    """The receiver owns the schema (item 076); two processes migrating one database race.

    And the shape matters as much as the fact: the image's entrypoint is a script, so overriding
    it with `hullwork` means `command` must be *its arguments*. Passing the program name again
    produces `hullwork hullwork work --loop` — measured, a restart loop on deploy.
    """
    dispatcher = _shipped_compose()["services"]["dispatcher"]

    assert dispatcher["entrypoint"] == ["hullwork"], "or the schema gets migrated twice"
    assert dispatcher["command"] == ["work", "--loop"], (
        "arguments to the entrypoint, never a repeat of the program name"
    )


def test_the_dispatcher_is_in_the_socket_group() -> None:
    """Mounting the socket is not enough, and the doctor found that out in production.

    `/var/run/docker.sock` is `root:docker 0660`, so uid 10001 gets `permission denied while trying
    to connect to the docker API` — the client is there and the daemon will not answer it, which is
    the distinction `doctor.docker_daemon` was written to draw (item 074). Without the group, no
    attempt can build its sandbox.
    """
    dispatcher = _shipped_compose()["services"]["dispatcher"]
    groups = dispatcher["group_add"]

    # **The resolved number, not a variable.** The hand-written compose this used to read carried
    # `${DOCKER_GID}`, one more thing an installer has to know to set; the generator reads the
    # socket's group off the host and writes it, or writes `REPLACE-ME` and says so in a note —
    # item 145's argument about a placeholder that fails loudly.
    assert groups, "the socket's group, or the daemon refuses every connection"
    assert "989" in [str(entry) for entry in groups], "the gid it was given, written literally"


# --- the loop refuses a schema it does not recognise. Item 076 -----------------------------------


def test_the_loop_refuses_to_start_against_an_empty_database(tmp_path: Path) -> None:
    """**The failure this prevents was measured twice, and both times by reading, not by a report.**

    A process missing `HULLWORK_DATABASE_URL` makes SQLite create an empty file beside the real one.
    `readiness` passes it — writable, plenty of disk — and the loop would take the lease, find
    nothing ready, and report a healthy instance for as long as it ran. The schema belongs to the
    receiver (it migrates in its entrypoint); this process only uses it, so the honest answer to a
    schema it does not recognise is to refuse rather than to claim items against it.
    """
    from hullwork import doctor
    from hullwork.db import make_engine, make_session_factory

    empty = tmp_path / "empty.db"
    factory = make_session_factory(make_engine(f"sqlite:///{empty}"))
    settings = get_settings()

    with factory() as session:
        # The measurement the refusal is built on, asserted here so this test fails for the right
        # reason if `database_built` ever stops making it.
        assert doctor.database_built(session, settings).state is doctor.State.BROKEN

        from hullwork.cli import CommandError, _work_loop

        with pytest.raises(CommandError) as refused:
            _work_loop(
                argparse.Namespace(loop=True, once=False, release_stale=False, project=None),
                session,
                settings,
                io.StringIO(),
            )

    message = str(refused.value)
    assert "refusing to start" in message
    assert "no tables at all" in message, "it must say what it found, not just that it refused"
    # And it refused *before* claiming the right to work: an unusable dispatcher holding the lease
    # keeps a usable one out. Asserted as the table's absence rather than as an empty row, because
    # querying a table that does not exist raises — which is itself how the old order failed.
    from sqlalchemy import inspect as sa_inspect

    with factory() as session:
        tables = sa_inspect(session.get_bind()).get_table_names()
    assert tables == [], f"the loop wrote to a database it had refused: {tables}"


# --- the loop refuses a credential that can never work. Item 103 ---------------------------------


@pytest.mark.parametrize(
    ("state", "prepare", "expected"),
    [
        ("empty", lambda p: p.write_text(""), "there is nothing to read at"),
        ("not JSON", lambda p: p.write_text('{"claudeAiOa'), "is not valid JSON"),
        ("absent", lambda p: None, "there is no file at"),
    ],
)
def test_the_loop_refuses_to_start_without_a_model_it_can_read(
    tmp_path: Path, state: str, prepare: object, expected: str
) -> None:
    """**The failure this prevents ran for forty minutes on the live instance** (issue #14).

    `MODEL_CREDENTIALS_HOST` was unset, so the compose bound `/dev/null` — an empty file — and the
    dispatcher stayed "Up" while unable to claim a single item. `docker ps` said healthy, `/ready`
    said ready, and `hullwork status` run from the receiver said READY — the credential is not the
    receiver's to hold. It ended because somebody read the tracker by hand.

    Exiting is not a smaller failure than looping, it is a **visible** one: `restart:
    unless-stopped` turns a non-zero exit into a container reporting "Restarting", the signal every
    operator already watches. Nothing to install, no alarm to configure, no cron.

    The distinction that makes this safe to do is in `doctor.credential_never_works`: a token that
    *expired* comes back by itself, and the loop is right to keep running and refuse to claim (item
    096). One that cannot be read comes back only when a person acts.
    """
    from hullwork.cli import CommandError, _work_loop
    from hullwork.config import Settings
    from hullwork.db import make_engine, make_session_factory

    source = tmp_path / "credentials.json"
    if callable(prepare):
        prepare(source)

    url = f"sqlite:///{tmp_path / 'loop.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    settings = Settings(database_url=url, model_credentials_file=str(source))

    with make_session_factory(engine)() as session:
        # **The lease is held by somebody else on purpose**, and not to test the lease. Without it,
        # removing the refusal under test would let this call into the loop and **hang** rather than
        # fail — a regression that hangs CI is a regression nobody diagnoses. With it, the loop can
        # only ever return by raising, and which sentence it raises is the whole assertion.
        assert lease.acquire(session, "somebody-else") is True

        with pytest.raises(CommandError) as refused:
            _work_loop(
                argparse.Namespace(loop=True, once=False, release_stale=False, project=None),
                session,
                settings,
                io.StringIO(),
            )

        message = str(refused.value)
        # And it refused for the credential, **before** it ever looked at the lease.
        assert "refusing to start" in message, f"it got as far as the lease: {message}"
        # The state, not a parser's sentence about column numbers in a file nobody has opened.
        assert expected in message, f"the message does not say the file is {state}: {message}"
        assert "will not fix itself" in message
        # And it did not take the lease from the holder above: a dispatcher that cannot work must
        # not keep one that can out of the queue (item 097's cost, from the other side).
        assert lease.holder_of(session) == "somebody-else"


def test_the_real_shape_of_this_failure_is_dev_null_and_it_is_not_a_regular_file(
    tmp_path: Path,
) -> None:
    """The production case, and the one the first fix got wrong.

    `MODEL_CREDENTIALS_HOST` unset makes the compose bind **`/dev/null`**, which is a *character
    device*: `Path.is_file()` is False for it, so an emptiness check written as `is_file() and
    st_size == 0` never fires where it matters. Measured on the live instance after deploying the
    fix — the refusal worked and the sentence said *"not valid JSON, it may have been read while the
    CLI was rewriting it"*, blaming a write race that was not happening, about a device.

    The unit test that passed used `write_text("")`, a regular empty file, and agreed with the bug.
    So this one points at the real thing.
    """
    from hullwork import doctor
    from hullwork.config import Settings

    assert not Path("/dev/null").is_file(), "the premise: /dev/null is a device, not a file"

    reason = doctor.credential_never_works(Settings(model_credentials_file="/dev/null"))

    assert "nothing to read" in reason
    assert "MODEL_CREDENTIALS_HOST" in reason
    assert "rewriting it" not in reason, "it blamed a write race about a device"


def test_an_expired_token_is_not_a_refusal_to_start(tmp_path: Path) -> None:
    """The other side of the same line, and the reason it is a line rather than a rule.

    This deployment's token lives about eight hours and a cron refreshes it every four. A dispatcher
    that exited for an expired token would flap several times a day — and be wrong every time,
    because the credential comes back without anybody doing anything. Item 096 built the loop's
    refusal-to-claim for exactly this, and it stays.
    """
    import json

    from hullwork import doctor
    from hullwork.cli import CommandError, _work_loop
    from hullwork.config import Settings
    from hullwork.db import make_engine, make_session_factory

    source = tmp_path / "credentials.json"
    source.write_text(json.dumps({"claudeAiOauth": {"accessToken": "t", "expiresAt": 1}}))
    settings = Settings(model_credentials_file=str(source))

    # Well-formed and long expired: `doctor` calls it broken, and this one still starts.
    assert doctor.model_credential(settings).state is doctor.State.BROKEN
    assert doctor.credential_expired(settings) != ""
    assert doctor.credential_never_works(settings) == "", (
        "an expired token must not be read as unusable — it comes back on its own"
    )

    # **And the call site is asserted, not just the predicate.** A test that only checked
    # `credential_never_works` would still pass if somebody later refused expiry at the startup
    # branch too. So: hold the lease from somewhere else and drive the loop. It must fail at the
    # *lease* — proof it got past the credential — and it returns immediately, where letting it
    # into the loop would block for ever.
    url = f"sqlite:///{tmp_path / 'expired.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as session:
        assert lease.acquire(session, "somebody-else") is True

        with pytest.raises(CommandError) as refused:
            _work_loop(
                argparse.Namespace(loop=True, once=False, release_stale=False, project=None),
                session,
                Settings(database_url=url, model_credentials_file=str(source)),
                io.StringIO(),
            )

    message = str(refused.value)
    assert "holds the lease" in message
    assert "refusing to start" not in message, (
        "an expired token stopped the dispatcher from starting — it comes back on its own"
    )


# --- recovering from a deliberate stop. Item 097 --------------------------------------------------


def test_releasing_a_lease_whose_holder_is_still_working_is_refused(session: Session) -> None:
    """**The property that makes the rest of this safe to have.**

    A recovery path that can cause the failure it recovers from is worse than the wait. "Alive" is
    `ALIVE_SECONDS`, not `LEASE_SECONDS`: a holder that renewed five minutes ago is working right
    now, whatever its lease is good for.
    """
    from hullwork.cli import CommandError, release_lease

    lease.acquire(session, "busy-holder-1")

    with pytest.raises(CommandError) as refused:
        release_lease(session)

    assert "working right now" in str(refused.value)
    assert lease.state(session)[0] == "alive", "the refusal must not have changed anything"


def test_releasing_a_lease_whose_holder_is_gone_frees_it(session: Session) -> None:
    """The supported way out of the state a `docker compose stop` mid-attempt leaves behind.

    Recovering from that needed an `UPDATE` against a SQLite file inside a Docker volume, which is
    the shape item 093 removed for items and this removes for the lease.
    """
    from hullwork.cli import release_lease

    lease.acquire(session, "dead-holder-1")
    _age(session, lease.LEASE_SECONDS + 60)

    said = release_lease(session)

    assert "released the lease" in said
    assert lease.state(session)[0] == "released"


def test_taking_the_lease_from_another_holder_frees_what_it_had_claimed(
    session: Session, tmp_path: Path
) -> None:
    """**`acquire` succeeding is the proof, and it is stronger than a clock.**

    A lease only changes hands when the previous holder released it or let it expire, so a different
    holder owning it now means the old one is gone. Without this the item waits out `STALE_AFTER` —
    three hours in which the dispatcher that *is* running cannot attempt it. Measured on the live
    instance after a `docker compose stop` mid-attempt.
    """
    from datetime import UTC, datetime

    from hullwork import work
    from hullwork.models import Attempt, AttemptPhase, Item, ItemState, Lane, Project

    project = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="x",  # noqa: S106
        manifest={"project": "p", "autofix": {"agent": "none"}},
    )
    session.add(project)
    session.flush()
    item = Item(
        project_id=project.id, fingerprint="fp", title="TypeError: boom",
        lane=Lane.GREEN, state=ItemState.IN_PROGRESS,
    )
    session.add(item)
    session.flush()
    session.add(
        Attempt(item_id=item.id, phase_reached=AttemptPhase.REPRODUCE, started_at=datetime.now(UTC))
    )
    session.commit()

    # Claimed seconds ago, so `STALE_AFTER` cannot free it — this is the case the clock refuses.
    assert work.release_stale(session) == []

    freed = work.release_stale(session, took_the_lease=True)

    assert freed == [item.id]
    assert session.get(Item, item.id).state is not ItemState.IN_PROGRESS  # type: ignore[union-attr]
    latest = session.query(Attempt).filter(Attempt.item_id == item.id).one()
    assert latest.consumed is False, "an item freed this way must keep its attempt"
    assert "different dispatcher" in (latest.not_consumed_reason or ""), (
        "the reason must say why it was freed, not just that it was"
    )


def test_a_live_dispatchers_claim_is_never_freed_by_the_clock_path(
    session: Session, tmp_path: Path
) -> None:
    """The negative half. `took_the_lease` is a claim about the *lease*, not a way to skip the rule.

    Called without it — which is what `--release-stale` does — a recently claimed item stays
    claimed, because a dispatcher that is still working is not stale.
    """
    from hullwork import work
    from hullwork.models import Attempt, AttemptPhase, Item, ItemState, Lane, Project

    project = Project(
        slug="p2", forge="forgejo", repo="o/r2",
        webhook_secret_hash="x",  # noqa: S106
        manifest={"project": "p2", "autofix": {"agent": "none"}},
    )
    session.add(project)
    session.flush()
    item = Item(
        project_id=project.id, fingerprint="fp2", title="TypeError: boom",
        lane=Lane.GREEN, state=ItemState.IN_PROGRESS,
    )
    session.add(item)
    session.flush()
    session.add(
        Attempt(item_id=item.id, phase_reached=AttemptPhase.REPRODUCE, started_at=datetime.now(UTC))
    )
    session.commit()

    assert work.release_stale(session) == [], "a fresh claim is not stale"
    assert session.get(Item, item.id).state is ItemState.IN_PROGRESS  # type: ignore[union-attr]
