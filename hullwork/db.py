"""Database engine and sessions.

Synchronous on purpose. The volume is hundreds of events a day, not thousands a second: sync code
types cleanly under mypy strict, FastAPI runs `def` endpoints in a threadpool anyway, and async here
would cost every future contributor something it never earns back.
"""

import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import ConnectionPoolEntry

from hullwork.config import ConfigError

#: How long a writer waits for another writer before giving up.
#:
#: **This is pysqlite's own default, written down rather than inherited — it fixes nothing.** Said
#: plainly because "add a `busy_timeout`" is the first thing anybody reaches for on reading
#: `database is locked`, and item 081 measured it was already 5000ms while 58 were happening. The
#: cause was a lock held for thirteen minutes by `attempts.record`, and no timeout is a defence
#: against that.
#:
#: Kept explicit for the reason `foreign_keys` and `journal_mode` are: a value this system's
#: behaviour depends on should not arrive from a driver default that a future `connect_args`, driver
#: swap or Python release can change without anybody noticing.
BUSY_TIMEOUT_MS = 5000

#: What a host can look like. Only used to decide whether a parsed URL is worth quoting back.
_PLAUSIBLE_HOST = re.compile(r"[A-Za-z0-9._-]+")


def _the_driver_has_to_be_installed(url: str) -> None:
    """Refuse a database URL whose driver is not here, and name the extra that carries it.

    **Measured against the published image, 2026-08-05** (item 150). `ghcr.io/…/hullwork:0.1.0a1`
    shipped without the `postgres` extra, so `postgresql+psycopg://…` died eleven frames down as
    `ModuleNotFoundError: No module named 'psycopg'`, raised inside SQLAlchemy's dialect loader —
    while the README's support matrix said Postgres works.

    The root cause was the build and is fixed there. This exists for the case that remains: somebody
    building their own image without the extra, who deserves the sentence `telemetry`'s missing SDK
    already gets in `config.py` rather than a traceback about a module they never heard of.

    Deliberately by *asking*, not by parsing the URL for names we recognise: `create_engine` knows
    which dialect a URL means and which module that dialect needs, and a list of our own would be
    wrong the day somebody uses a driver we did not think of.
    """
    try:
        make_url(url).get_dialect()
    except ModuleNotFoundError as missing:
        extra = "postgres" if "psycopg" in str(missing) else None
        remedy = (
            f"Install it with: pip install 'hullwork[{extra}]'"
            if extra
            else f"Install the driver it needs: pip install {missing.name}"
        )
        raise ConfigError(
            f"HULLWORK_DATABASE_URL names a database whose driver is not installed "
            f"({missing}).\n"
            f"  {remedy}\n"
            f"  Or use SQLite, which needs nothing: HULLWORK_DATABASE_URL=sqlite:////data/hullwork.db"
        ) from missing


def make_engine(url: str, *, echo: bool = False) -> Engine:
    """Build an engine, applying the settings SQLite needs to behave like a real database."""
    _the_driver_has_to_be_installed(url)
    connect_args: dict[str, object] = {}
    if url.startswith("sqlite"):
        # Sessions are used from FastAPI's threadpool, so the connection cannot be pinned to the
        # thread that created it.
        connect_args["check_same_thread"] = False

    engine = create_engine(url, echo=echo, future=True, connect_args=connect_args)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(
            dbapi_connection: DBAPIConnection,
            _record: ConnectionPoolEntry,
        ) -> None:
            cursor = dbapi_connection.cursor()
            # SQLite ignores foreign keys unless asked. Without this, a constraint that holds in
            # production silently does not hold in the quickstart — the worst kind of difference.
            cursor.execute("PRAGMA foreign_keys=ON")
            # Write-ahead logging, so a reader does not block on a writer. Under the default
            # rollback journal the periodic sweep and an inbound delivery contend for the whole
            # file, and the loser gets `database is locked` — which used to destroy the delivery
            # outright (item 016) and still costs it an attempt.
            cursor.execute("PRAGMA journal_mode=WAL")
            # The paragraph above stops one sentence too early, and item 081 is what that cost: WAL
            # keeps a reader from blocking a writer and does **nothing** about two writers. The
            # sweep and an inbound delivery are both writers.
            #
            # This line changes no behaviour — see `BUSY_TIMEOUT_MS`, it is already the default —
            # and it is here so the number sits next to the pragmas it belongs with. What actually
            # made writers collide for minutes at a time was `attempts.record` holding a transaction
            # open across a whole attempt; a timeout was never going to reach it.
            cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            cursor.close()

    return engine


@lru_cache(maxsize=8)
def get_engine(url: str) -> Engine:
    """The one engine for a given database, built at most once.

    Not a micro-optimisation. `make_engine` used to be called per HTTP request, each call building
    a fresh `QueuePool` that nothing ever disposed — measured at 500 new connections from 500
    anonymous requests with an unknown project slug, because dependencies resolve before the
    handler and therefore before authentication. Against a Postgres with the usual
    `max_connections`, a few hundred concurrent requests from anyone who can reach the port take
    down Hullwork and everything else sharing that server, with no token needed.

    Bounded cache rather than unbounded: an instance talks to one database, and the size is only
    there so a test suite that builds many can still be garbage-collected.
    """
    return make_engine(url)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Session factory bound to an engine."""
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """A transaction that commits on success and rolls back on any exception."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def where_this_database_is(url: str) -> str:
    """Where a reader should go looking, in the words of the setting rather than of an exception.

    **From the setting on purpose** (item 156). A driver's message names what *it* was handed —
    sometimes a path, sometimes nothing at all — and for Postgres there is no file to name, so
    quoting the exception would invent one. `HULLWORK_DATABASE_URL` is what the operator typed, and
    what they will edit.

    The password never appears: `make_url` parses it out, and this rebuilds the address by hand from
    the parts that are safe to print.
    """
    if url.startswith("sqlite"):
        path = url.split("sqlite://", 1)[-1].lstrip("/")
        return f"the file /{path}" if path else "an in-memory database"
    try:
        parsed = make_url(url)
    # An unparseable URL is still worth answering about.
    except Exception:
        return "the database HULLWORK_DATABASE_URL names"

    where = parsed.host or "localhost"
    # **`make_url` parses almost anything**, which the test found: `postgres://[not a url` came back
    # with a host of `[not a url`, and the sentence read *"the default database on [not a url"*.
    # Echoing garbage back at somebody who mistyped a URL is worse than declining to name it.
    if not _PLAUSIBLE_HOST.fullmatch(where):
        return "the database HULLWORK_DATABASE_URL names"
    if parsed.port:
        where = f"{where}:{parsed.port}"
    return f"{parsed.database or 'the default database'} on {where}"


def why_the_database_would_not_open(url: str, failure: BaseException) -> str:
    """A sentence for a database that will not answer, instead of eleven frames of SQLAlchemy.

    **Measured inside the published image** (item 156): with the SQLite file overwritten by bytes
    that are not a database — a half-copied volume, a truncated restore, a `docker cp` of the wrong
    file — `hullwork projects list` printed a traceback whose last line was a link to SQLAlchemy's
    error index. The good diagnosis, *"file is not a database"*, was the eleventh line up.

    **Three answers, not one** (item 076's distinction, kept). *Not a database*, *nowhere to open
    one*, and *a database with the wrong schema in it* need different remedies, so a single
    "database problem" here would be a regression: `doctor.database_built` exists to tell the last
    two apart, and this names it rather than guessing on its behalf.
    """
    said = str(failure).lower()
    where = where_this_database_is(url)

    if "file is not a database" in said or "not a database" in said:
        return (
            f"{where} is not a database.\n"
            f"  Something else is at that path — a half-copied volume, a truncated restore, or a\n"
            f"  file that was never a database. Nothing here can repair it; move it aside and let\n"
            f"  the receiver's entrypoint build a new one, or restore a backup over it.\n"
            f"  `hullwork doctor` tells this apart from an empty database and from one holding\n"
            f"  another build's schema, which need different answers."
        )
    if "unable to open database file" in said or "no such file" in said:
        return (
            f"{where} could not be opened.\n"
            f"  The usual causes are a directory that does not exist, a volume left unmounted,\n"
            f"  or a file this process cannot write — it runs as uid {os.getuid()}.\n"
            f"  `hullwork doctor` reports the whole environment, including what it can reach."
        )
    if "no such table" in said:
        return (
            f"{where} has no schema in it.\n"
            f"  The receiver applies migrations in its entrypoint; every other program only uses\n"
            f"  what it finds. If this is a new deployment, start the receiver once.\n"
            f"  `hullwork doctor` says which tables are missing — the difference between a\n"
            f"  database that was never built and one a migration has not reached."
        )

    # Not one of the three, so the driver's own words — and only its own words, on one line, since
    # the frames above them belong to SQLAlchemy and help nobody.
    first = str(failure).strip().splitlines()[0]
    return (
        f"{where} would not answer: {first}\n"
        f"  `hullwork doctor` reports the whole environment; it is the next thing to run."
    )
