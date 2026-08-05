#!/bin/sh
# Bring the schema up to date, then hand over to whatever was asked for.
#
# Migrations run here rather than inside the application: the app should not be deciding to alter
# its own database, and with more than one replica they would race each other doing it.
#
# `docker compose exec` bypasses the entrypoint, so `hullwork projects add …` still works directly
# without migrating twice.
set -e

echo "hullwork: applying migrations…" >&2
alembic upgrade head

exec "$@"
