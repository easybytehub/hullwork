"""A database that will not open gets a sentence, not eleven frames of SQLAlchemy. Item 156.

**Measured inside the published image on 2026-08-06.** With the SQLite file overwritten by bytes
that are not a database — a half-copied volume, a truncated restore, a `docker cp` of the wrong
file — `hullwork projects list` printed this:

```
Traceback (most recent call last):
  ...
    cursor.execute("PRAGMA journal_mode=WAL")
sqlalchemy.exc.DatabaseError: (sqlite3.DatabaseError) file is not a database
(Background on this error at: https://sqlalche.me/e/20/4xp6)
```

`file is not a database` is a good diagnosis and it was the eleventh line. The line that ends up on
screen last — the one somebody pastes into a search box — was a link to SQLAlchemy's error index.

**Three answers, not one.** *Not a database*, *nowhere to open one* and *a database with no schema*
need different remedies, and `doctor.database_built` already distinguishes the last two for the
dispatcher (item 076). A single "database problem" message here would undo that, so each case is
asserted separately below.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from sqlalchemy.exc import DatabaseError, OperationalError

from hullwork.cli import main
from hullwork.db import where_this_database_is, why_the_database_would_not_open


def _sqlite_failure(message: str) -> DatabaseError:
    """A failure shaped the way the driver hands it over: the class SQLAlchemy wraps it in."""
    return DatabaseError("PRAGMA journal_mode=WAL", None, Exception(message))


# --------------------------------------------------------------------------------------------
# Where, from the setting rather than from the exception
# --------------------------------------------------------------------------------------------


def test_the_path_comes_from_the_setting() -> None:
    """The criterion, and the reason it is one: a driver names what *it* was handed, which for
    Postgres is not a file at all.
    """
    assert where_this_database_is("sqlite:////data/hullwork.db") == "the file /data/hullwork.db"
    assert where_this_database_is("sqlite://") == "an in-memory database"


def test_a_postgres_url_says_a_host_and_a_database_and_never_the_password() -> None:
    """Inventing a file for Postgres would be worse than saying nothing, and the URL holds a
    password — the one thing that must not reach a terminal, a screenshot or a paste.
    """
    where = where_this_database_is("postgresql+psycopg://hull:s3cr3ta@db.interno:5433/hullwork")

    assert where == "hullwork on db.interno:5433"
    assert "s3cr3ta" not in where


def test_an_unparseable_url_still_gets_an_answer() -> None:
    """`None ≠ 0 ≠ absent`: a URL nobody can parse is a reason to say less, not to raise."""
    assert "HULLWORK_DATABASE_URL" in where_this_database_is("postgres://[not a url")


# --------------------------------------------------------------------------------------------
# The three answers stay three
# --------------------------------------------------------------------------------------------


def test_a_file_that_is_not_a_database_says_so_and_says_what_to_do() -> None:
    said = why_the_database_would_not_open(
        "sqlite:////data/hullwork.db",
        _sqlite_failure("(sqlite3.DatabaseError) file is not a database"),
    )

    assert "is not a database" in said
    assert "hullwork doctor" in said, "the command that distinguishes the other two cases"
    assert "Traceback" not in said
    assert "sqlalche.me" not in said, "the driver's link to its own error index helps nobody here"


def test_a_database_that_cannot_be_opened_names_the_uid_it_runs_as() -> None:
    """The three causes are a missing directory, an unmounted volume and a permission — and the
    third one is unanswerable without knowing who this process is.
    """
    said = why_the_database_would_not_open(
        "sqlite:////data/hullwork.db",
        OperationalError("x", None, Exception("unable to open database file")),
    )

    assert "could not be opened" in said
    assert "uid" in said
    assert "hullwork doctor" in said


def test_a_database_with_no_schema_points_at_who_migrates() -> None:
    """Item 076's boundary: the receiver applies migrations, everything else only uses them."""
    said = why_the_database_would_not_open(
        "sqlite:////data/hullwork.db",
        OperationalError("x", None, Exception("no such table: projects")),
    )

    assert "no schema" in said
    assert "receiver" in said
    assert "hullwork doctor" in said


def test_the_three_answers_are_actually_three() -> None:
    """The regression this guards against is a well-meaning consolidation into one message."""
    answers = {
        why_the_database_would_not_open("sqlite:////x.db", _sqlite_failure(message)).splitlines()[0]
        for message in (
            "(sqlite3.DatabaseError) file is not a database",
            "unable to open database file",
            "no such table: projects",
        )
    }
    assert len(answers) == 3, f"the distinction collapsed: {answers}"


def test_a_failure_that_is_none_of_the_three_keeps_the_drivers_own_words() -> None:
    """Anything unrecognised is still not a traceback — and the driver's first line is kept, because
    guessing would be worse than quoting.
    """
    said = why_the_database_would_not_open(
        "postgresql+psycopg://u@h/db",
        OperationalError("x", None, Exception("SSL connection has been closed unexpectedly")),
    )

    assert "SSL connection has been closed unexpectedly" in said
    assert said.count("\n") <= 2, "an unrecognised failure gets a line, not a paragraph"


# --------------------------------------------------------------------------------------------
# Through the command, because that is where the traceback was
# --------------------------------------------------------------------------------------------


def test_the_command_prints_a_sentence_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """**The whole item, end to end.** A real file that is not a database, through the real command.

    `capsys` for `stderr` here rather than an explicit stream: the boundary writes to `sys.stderr`
    directly, which is the thing being asserted — an operator reads the terminal, not a parameter.
    """
    corrupt = tmp_path / "hullwork.db"
    corrupt.write_bytes(b"esto ya no es una base de datos" * 40)

    monkeypatch.setenv("HULLWORK_DATABASE_URL", f"sqlite:///{corrupt}")
    from hullwork.config import get_settings

    get_settings.cache_clear()

    code = main(["projects", "list"], out=io.StringIO())
    said = capsys.readouterr().err

    assert code == 1, "a refusal that exits 0 is a refusal nothing scripted will notice"
    assert "is not a database" in said
    assert "Traceback" not in said
    assert "PRAGMA" not in said, "the frame the driver failed in is not the operator's business"

    get_settings.cache_clear()
