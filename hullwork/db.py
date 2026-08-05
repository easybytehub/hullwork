"""Database engine and sessions.

Synchronous on purpose. The volume is hundreds of events a day, not thousands a second: sync code
types cleanly under mypy strict, FastAPI runs `def` endpoints in a threadpool anyway, and async here
would cost every future contributor something it never earns back.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import ConnectionPoolEntry

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


def make_engine(url: str, *, echo: bool = False) -> Engine:
    """Build an engine, applying the settings SQLite needs to behave like a real database."""
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
