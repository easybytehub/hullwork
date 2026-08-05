# What these files are

Alembic migrations. Every file in `versions/` is named `<revision>_<what_it_did>.py`, where the
revision is a hash Alembic generates and the rest is a slug — so `682869bada6e_initial_schema.py`
reads as *"revision 682869bada6e, the initial schema"*. Nobody types those hashes; they exist so the
chain has an order that renaming a file cannot break.

There are more of them than a project this young looks like it needs, and that is normal: the count
grows with every schema change forever, and one file per change is what makes the chain replayable
against a database that already has data in it.

## What you have to do about them

Nothing. **The receiver applies them in its entrypoint** — `alembic upgrade head` runs before the
service starts — so a fresh installation builds its schema on first boot and an upgrade applies what
is new. The dispatcher never migrates; it only uses the database
(DR-0009 puts the schema on the half that serves).

From a checkout rather than the image, `alembic upgrade head` by hand.

`HULLWORK_DATABASE_URL` decides which database is migrated, and nothing else does — `env.py` reads it
and ignores `sqlalchemy.url` in `alembic.ini` on purpose, so there is exactly one answer to *which
database is in use*. A test that set the config and not the variable once migrated one database and
inspected another.

## Why they are not squashed into one

They could be: nobody outside this project has a database, so the chain has exactly one consumer today
— **our own instance**, whose schema was built by replaying it. Collapsing them would mean stamping
that instance at a new baseline, which is a real operation on the only running deployment, in exchange
for a shorter file listing. Not a trade worth making.

One of these migrations took the receiver down for twenty minutes (a `CHECK` constraint on an enum plus
foreign keys, on SQLite, where altering a table means rebuilding it). That history is worth keeping
where it happened.
