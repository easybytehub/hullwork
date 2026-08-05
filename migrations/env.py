"""Alembic environment.

The URL comes from the application settings, never from alembic.ini: one place decides which
database is in use, and `alembic upgrade head` therefore cannot target a different one than the app.
"""

from logging.config import fileConfig
from typing import Any, Literal

from alembic import context
from alembic.autogenerate.api import AutogenContext

from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import Base, UtcDateTime

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    # An explicit -x url=... wins, so tests can point at a temporary database.
    return str(context.get_x_argument(as_dictionary=True).get("url") or get_settings().database_url)


def render_item(
    type_: str,
    obj: Any,  # noqa: ANN401 - alembic's callback signature; obj is any SQLAlchemy construct
    autogen_context: AutogenContext,
) -> str | Literal[False]:
    """Render custom column types as plain SQLAlchemy.

    A migration must never import application code. `UtcDateTime` is our decorator around
    `DateTime(timezone=True)`; a migration referencing it directly would break the moment that
    class is renamed or removed — and old migrations have to keep working forever. The resulting
    DDL is identical either way.
    """
    if type_ == "type" and isinstance(obj, UtcDateTime):
        return "sa.DateTime(timezone=True)"
    return False


def run_migrations_offline() -> None:
    """Emit SQL without connecting."""
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        render_item=render_item,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live connection."""
    engine = make_engine(_url())
    with engine.connect() as connection:
        # **SQLite recreates a table to change a CHECK constraint, and a recreate is a `DROP
        # TABLE`** — which fails against rows in `attempts` that point at it. Measured on the live
        # instance, item 138: the migration ran on an empty database in testing and took the
        # receiver down on a database with twenty attempts in it.
        #
        # Off for the duration of the migration and on again after, which is what every SQLite
        # schema change of this shape needs. `db.py` turns it on per connection for the application,
        # and that is the one that matters: the constraints are re-checked the moment the receiver
        # opens its own connection.
        if connection.dialect.name == "sqlite":
            # **The commit is the whole of it.** `PRAGMA foreign_keys` is silently ignored inside a
            # transaction, and issuing it opens one — so without closing that transaction the pragma
            # does nothing *and* everything the migration does afterwards is rolled back at the end
            # of the block. Measured, item 138: the table came out with its new constraint and the
            # revision was never stamped, which is a worse state than the failure it was fixing.
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_item=render_item,
            # SQLite cannot ALTER most things; batch mode rewrites the table instead. Needed so the
            # same migration works on both backends.
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            connection.commit()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
