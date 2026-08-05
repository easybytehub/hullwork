"""Fixtures every test file needs, defined once.

**This exists because the same four lines were copied into thirteen files and all thirteen
leaked.** Each built an in-memory engine, created the schema, and *returned* a session — never
closing it, never disposing the engine. On CPython 3.12 the reference count drops the moment a test
ends and the connection is finalised quietly, so the suite was green and had been for months. On
3.14 the same finalisation raises `ResourceWarning: unclosed database`, which
`filterwarnings = ["error"]` in `pyproject.toml` turns into a failure. That setting is right, so the
warning was a real leak nobody could see.

Measured on 2026-08-04: 34 unclosed connections across one run, and the suite red on 3.14 and on the
environment `uv.lock` describes, while green on the one resolution everybody happened to use.

One definition rather than thirteen, for the reason this project gives everywhere else: a rule
copied is a rule that will disagree with itself. A file that needs a *different* database — one on
disk, a schema built by migrations — still builds its own, and several do.

**And the fixture was only half of it.** Replacing it left the suite still red, because tests build
engines inline as well: 71 of them across the files, against 5 `dispose()` calls. Editing seventy
call sites across twenty-five files is the mechanical sweep that has broken this repository before,
so the cleanup is in one place instead — `_dispose_every_engine_a_test_opened` below. A test
harness cleaning up after the tests is the harness's job, and it cannot go stale the way seventy-one
copies of a `finally` would.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import suppress

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from hullwork.db import get_engine
from hullwork.models import Base


@pytest.fixture(autouse=True)
def _dispose_every_engine_a_test_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Every engine opened during a test is disposed when it ends, wherever it was opened.

    **Autouse and interposing, because the alternative is seventy-one `finally` blocks.** An engine
    holds a connection pool; for SQLite that pool holds the database, so an undisposed engine is an
    open connection at interpreter exit — reported as `ResourceWarning`, promoted to an error by
    this project's `filterwarnings`, and invisible on the one Python version everybody used.

    **SQLAlchemy's own class-level event, after two hooks that did not work**, and both failures are
    worth keeping because they are the obvious things to try:

    * Wrapping `sqlalchemy.create_engine` and `hullwork.db.make_engine` caught **nothing**. The
      tests do `from sqlalchemy import create_engine`, so patching the module leaves the name
      already bound in twenty-five namespaces untouched.
    * Wrapping `Engine.__init__` broke `create_engine` outright — *"Invalid argument(s) 'echo' sent
      to create_engine()"*. SQLAlchemy **introspects that signature** to decide which keyword
      arguments belong to the engine rather than to the dialect or pool, so a `*args, **kwargs`
      wrapper erases the information it needs.

    `engine_connect` is the documented hook and it is also the more precise one: it fires when an
    engine actually opens a connection, and an engine that never connects holds nothing and cannot
    leak. So the set is exactly the engines that could.

    It disposes only what the test itself opened. An engine made at import time, or by a fixture
    with a longer scope, is not this fixture's to close — disposing one would break the next test
    in a way far harder to find than the leak.
    """
    del monkeypatch  # the listener is removed by hand below; a patch cannot express that
    opened: set[Engine] = set()

    def remember(conn: object) -> None:
        engine = getattr(conn, "engine", None)
        if engine is not None:
            opened.add(engine)

    event.listen(Engine, "engine_connect", remember)
    try:
        yield
    finally:
        event.remove(Engine, "engine_connect", remember)
        # **`get_engine`'s cache outlives the test that filled it**, which is its whole point in
        # production — one engine per database rather than one per HTTP request, which was 500
        # connections from 500 calls. In a suite it means an engine survives to interpreter exit,
        # which is the leak, and it is why three tests failed only in a full run and passed alone.
        # Cleared here so a cache that is correct in production is not a leak in a test.
        get_engine.cache_clear()
        for engine in opened:
            # Suppressed: a test that disposed its own engine is doing the right thing, and a
            # teardown that failed over tidiness would hide what the test was reporting.
            with suppress(Exception):
                engine.dispose()


@pytest.fixture
def session() -> Iterator[Session]:
    """An empty in-memory database with this build's schema, closed and disposed afterwards.

    `Base.metadata.create_all` rather than migrations: these tests are about behaviour, and running
    the migration chain per test would make the suite an hour long. The tests that need the chain —
    because they are about it — build their own and say so.

    **Both matter, and the dispose is the one that was missing everywhere.**
    Closing the session returns its connection to the pool; disposing the engine closes the pool.
    For `sqlite://` the pool holds the whole database, so an undisposed engine is the leak — and it
    is invisible until an interpreter finalises it loudly.
    """
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    made = sessionmaker(bind=engine)()
    try:
        yield made
    finally:
        made.close()
        engine.dispose()
