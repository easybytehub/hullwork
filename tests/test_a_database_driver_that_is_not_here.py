"""A database URL whose driver is missing gets a sentence, not eleven frames of SQLAlchemy.

**Measured against the published image on 2026-08-05** (item 150). `0.1.0a1` shipped with neither
the `postgres` nor the `telemetry` extra: the Dockerfile's `ARG EXTRAS=` is empty and the release
workflow passed no `--build-arg`. Two capabilities the documentation promises in three places
each, impossible in the artefact:

* `HULLWORK_ERROR_DSN` made the container **exit 3**, telling the operator to run a `pip install`
  nobody can run against an image they pulled. At least that one was a sentence.
* `postgresql+psycopg://…` died as `ModuleNotFoundError: No module named 'psycopg'` from inside
  SQLAlchemy's dialect loader — while the README's support matrix said Postgres works.

The build is fixed, which is the root cause. This file is about the case that survives it: somebody
building their own image without the extra. They get the sentence rather than the traceback.
"""

from __future__ import annotations

import pytest
from sqlalchemy.engine import make_url

from hullwork.config import ConfigError
from hullwork.db import make_engine


def test_a_missing_driver_names_the_extra_that_carries_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """The dialect's own answer, not a list of drivers we happen to recognise.

    Simulated rather than uninstalled, because `psycopg` is present in this development
    environment — which is exactly why the defect reached a published image: locally it cannot
    happen.
    """
    def no_module(self: object) -> object:
        raise ModuleNotFoundError("No module named 'psycopg'", name="psycopg")

    monkeypatch.setattr(type(make_url("postgresql+psycopg://u:p@h/db")), "get_dialect", no_module)

    with pytest.raises(ConfigError) as refused:
        make_engine("postgresql+psycopg://u:p@h/db")

    said = str(refused.value)
    assert "psycopg" in said, "name the module, because that is what the reader will search for"
    assert "hullwork[postgres]" in said, "and the extra that carries it, which is the actual remedy"
    assert "sqlite" in said, "and the way out that needs nothing installed"
    assert "Traceback" not in said


def test_an_unrecognised_driver_still_gets_a_sentence(monkeypatch: pytest.MonkeyPatch) -> None:
    """No extra of ours carries it, and the answer is still not a traceback.

    The point of asking the dialect rather than matching on names: a driver nobody here thought
    of produces the same shape of refusal, naming the module to install.
    """
    def no_module(self: object) -> object:
        raise ModuleNotFoundError("No module named 'sqlanydb'", name="sqlanydb")

    monkeypatch.setattr(type(make_url("sqlite://")), "get_dialect", no_module)

    with pytest.raises(ConfigError) as refused:
        make_engine("sybase+sqlanydb://u:p@h/db")

    said = str(refused.value)
    assert "sqlanydb" in said
    assert "hullwork[" not in said, "inventing an extra that does not exist is worse than none"


def test_sqlite_needs_nothing_and_is_unaffected() -> None:
    """The negative case: without it, the two above pass on a function that always raises."""
    assert make_engine("sqlite://") is not None
