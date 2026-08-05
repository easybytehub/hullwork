"""The schema is tested by running the real migration, not by trusting the model metadata.

A constraint that exists on the models but not in the migration is a constraint that does not exist.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError, StatementError

from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory, session_scope
from hullwork.models import Delivery, Item, ItemState, Lane, Project

ROOT = Path(__file__).resolve().parent.parent


def _migrate(url: str) -> None:
    # Config() without a file so alembic does not reconfigure global logging under the test suite.
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")


@pytest.fixture
def migrated_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    url = f"sqlite:///{tmp_path / 'hullwork-test.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    _migrate(url)
    yield url
    get_settings.cache_clear()


def _project(**overrides: object) -> Project:
    defaults: dict[str, object] = {
        "slug": "demo",
        "forge": "forgejo",
        "repo": "acme/demo",
        "webhook_secret_hash": "hashed",
    }
    return Project(**{**defaults, **overrides})


def test_the_migration_creates_every_table(migrated_url: str) -> None:
    inspector = inspect(make_engine(migrated_url))

    assert {"projects", "deliveries", "events", "items"} <= set(inspector.get_table_names())


def test_a_redelivery_cannot_create_a_second_row(migrated_url: str) -> None:
    """The constraint is what makes retries harmless. Test the behaviour, not the DDL."""
    factory = make_session_factory(make_engine(migrated_url))
    with session_scope(factory) as session:
        session.add(_project())
        session.flush()
        project_id = session.query(Project).one().id
        session.add(Delivery(project_id=project_id, provider_delivery_id="d-1", payload_hash="abc"))

    with pytest.raises(IntegrityError), session_scope(factory) as session:
        session.add(Delivery(project_id=project_id, provider_delivery_id="d-1", payload_hash="abc"))


def test_two_items_cannot_share_a_fingerprint_within_a_project(migrated_url: str) -> None:
    """This is what stops a race between two simultaneous events creating two items."""
    factory = make_session_factory(make_engine(migrated_url))
    with session_scope(factory) as session:
        session.add(_project())
        session.flush()
        project_id = session.query(Project).one().id
        session.add(Item(project_id=project_id, fingerprint="fp-1", title="boom"))

    with pytest.raises(IntegrityError), session_scope(factory) as session:
        session.add(Item(project_id=project_id, fingerprint="fp-1", title="boom again"))


def test_the_same_fingerprint_in_another_project_is_a_different_item(migrated_url: str) -> None:
    factory = make_session_factory(make_engine(migrated_url))
    with session_scope(factory) as session:
        session.add_all([_project(), _project(slug="other", repo="easybyte/other")])
        session.flush()
        ids = [p.id for p in session.query(Project).order_by(Project.id).all()]
        session.add_all(
            [
                Item(project_id=ids[0], fingerprint="shared", title="boom"),
                Item(project_id=ids[1], fingerprint="shared", title="boom"),
            ]
        )

    with session_scope(factory) as session:
        assert session.query(Item).count() == 2


def test_item_defaults_are_the_safe_ones(migrated_url: str) -> None:
    factory = make_session_factory(make_engine(migrated_url))
    with session_scope(factory) as session:
        session.add(_project())
        session.flush()
        session.add(Item(project_id=session.query(Project).one().id, fingerprint="fp", title="t"))

    with session_scope(factory) as session:
        item = session.query(Item).one()
        # An unclassified item is red and new: the safe default is "a human looks at it".
        assert item.state is ItemState.NEW
        assert item.lane is Lane.RED
        assert item.occurrences == 1
        assert item.regression is False
        assert item.forge_issue_ref is None


def test_an_invalid_state_is_refused_before_it_reaches_the_database(migrated_url: str) -> None:
    """First line of defence: SQLAlchemy rejects the value while binding it."""
    factory = make_session_factory(make_engine(migrated_url))
    with session_scope(factory) as session:
        session.add(_project())
        session.flush()
        project_id = session.query(Project).one().id

    with pytest.raises(StatementError), session_scope(factory) as session:
        item = Item(project_id=project_id, fingerprint="fp2", title="t")
        item.state = "not-a-real-state"  # type: ignore[assignment]
        session.add(item)


def test_an_invalid_state_is_also_refused_by_the_database_itself(migrated_url: str) -> None:
    """Second line of defence, and the one that matters.

    Bypassing the ORM must not bypass the rule: a check constraint is what protects the data from a
    raw statement, a future service, or a migration that forgets.
    """
    engine = make_engine(migrated_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO projects (slug, forge, repo, webhook_secret_hash, active, created_at)"
                " VALUES ('p', 'forgejo', 'o/r', 'h', 1, '2026-01-01 00:00:00')"
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO items (project_id, fingerprint, state, lane, kind, title,"
                " occurrences, first_seen, last_seen, regression, created_at, updated_at)"
                " VALUES (1, 'fp3', 'not-a-real-state', 'red', 'bug', 't', 1,"
                " '2026-01-01 00:00:00', '2026-01-01 00:00:00', 0,"
                " '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )


def test_timestamps_are_timezone_aware(migrated_url: str) -> None:
    factory = make_session_factory(make_engine(migrated_url))
    with session_scope(factory) as session:
        session.add(_project())

    with session_scope(factory) as session:
        created = session.query(Project).one().created_at
        # Naive timestamps are how a system ends up reporting events an hour in the future.
        assert created.tzinfo is not None
        assert created <= datetime.now(UTC)
