"""Promises the manifest and the CLI make to people outside this repository (item 020).

Once `hullwork.yml` is public, every field is a compatibility commitment and every default is one
people have already written down. These are the tests for the things that are expensive — or
impossible — to change afterwards.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr
from sqlalchemy.orm import Session

from hullwork.cli import CommandError, prune, refresh_manifest
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.forge.forgejo import ForgejoForge
from hullwork.ingest import _manifest_for
from hullwork.manifest import SCHEMA_VERSION, ManifestError, parse_manifest
from hullwork.models import Delivery, Event, Item, Lane, Project

ROOT = Path(__file__).resolve().parent.parent

MINIMAL = """
project: p
git: {provider: forgejo, repo: o/r}
"""

REGISTERED = """
project: p
git: {provider: forgejo, repo: o/r}
autofix:
  lanes:
    red: [payment]
"""


def _settings() -> Settings:
    return Settings(forge_url="https://forge.example", forge_token=SecretStr("t"))


def _register(session: Session) -> None:
    session.add(
        Project(
            slug="p",
            forge="forgejo",
            repo="o/r",
            webhook_secret_hash="x",  # noqa: S106 - fixture
            manifest=parse_manifest(REGISTERED).model_dump(mode="json"),
        )
    )
    session.commit()


def _serve_manifest(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    """Make the forge hand back this manifest, without opening a socket."""
    monkeypatch.setattr(ForgejoForge, "read_manifest", lambda self, repo: text)
    monkeypatch.setattr(ForgejoForge, "close", lambda self: None)


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'public.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")
    with make_session_factory(make_engine(url))() as db:
        yield db
    get_settings.cache_clear()


# --- the schema version ------------------------------------------------------------------------


def test_a_manifest_without_a_version_is_version_one_for_ever() -> None:
    """Both real manifests were written before the field existed. Reinterpreting `absent` later
    would break files nobody can be asked to change."""
    assert parse_manifest(MINIMAL).version == SCHEMA_VERSION


def test_a_manifest_from_the_future_says_so_instead_of_drowning_you() -> None:
    """Without this, a manifest using a field a newer Hullwork added produces a wall of
    `Extra inputs are not permitted` about keys that are perfectly correct."""
    with pytest.raises(ManifestError) as caught:
        parse_manifest("version: 99\n" + MINIMAL)

    message = str(caught.value)
    assert "understands" in message
    assert "upgrade Hullwork" in message


def test_a_cached_manifest_that_no_longer_validates_degrades_to_red(session: Session) -> None:
    """The upgrade hazard, and the reason it must not be an exception.

    The snapshot is re-validated by whatever code is running, so a renamed field would make every
    already-registered project raise on every delivery — and that is a permanent failure, so each
    one would be sealed on arrival while the instance looked perfectly healthy.
    """
    project = Project(
        slug="p",
        forge="forgejo",
        repo="o/r",
        webhook_secret_hash="x",  # noqa: S106 - fixture
        manifest={"project": "p", "git": {"provider": "forgejo", "repo": "o/r"}, "from_2027": True},
    )

    manifest = _manifest_for(project)

    assert manifest.project == "p"
    assert manifest.autofix.lanes.green == [], "no lanes means everything lands red"
    assert manifest.autofix.agent == "none"


# --- the manifest is re-readable ----------------------------------------------------------------


def test_refreshing_replaces_the_cached_manifest(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`projects refresh` exists because the README, the constitution and every filed issue all
    told users to edit `hullwork.yml`, and all three were false after `projects add`."""
    _register(session)
    tightened = (
        "project: p\ngit: {provider: forgejo, repo: o/r}\n"
        "autofix:\n  lanes:\n    red: [reports]\n"
    )
    _serve_manifest(monkeypatch, tightened)

    manifest = refresh_manifest(session, _settings(), "p")

    assert manifest.autofix.lanes.red == ["reports"]
    session.expire_all()
    cached = session.query(Project).one().manifest or {}
    assert cached["autofix"]["lanes"]["red"] == ["reports"]


def test_an_invalid_manifest_leaves_the_project_with_the_rules_it_had(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Losing your guardrails to a typo would be a worse outcome than a refused refresh."""
    _register(session)
    _serve_manifest(monkeypatch, "project: p\ngit: {provider: forgejo, repo: o/r}\nnonsense: 1\n")

    with pytest.raises(CommandError) as caught:
        refresh_manifest(session, _settings(), "p")

    assert "unchanged" in str(caught.value)
    session.expire_all()
    cached = session.query(Project).one().manifest or {}
    assert cached["autofix"]["lanes"]["red"] == ["payment"]


# --- retention ------------------------------------------------------------------------------------


def test_pruning_forgets_bodies_and_keeps_everything_else(session: Session) -> None:
    """`events.raw` stores the WHOLE delivery once per fact inside it, and nothing ever expired it:
    2,000 attachments in one 160 KB request measured as a 322 MB database."""
    session.add(
        Project(slug="p", forge="forgejo", repo="o/r", webhook_secret_hash="x")  # noqa: S106
    )
    session.commit()
    old = datetime.now(UTC) - timedelta(days=200)
    session.add(
        Delivery(
            project_id=1,
            payload_hash="h",
            payload_json=json.dumps({"attachments": ["…" * 100]}),
            received_at=old,
        )
    )
    session.add(
        Event(
            project_id=1,
            delivery_id=1,
            fingerprint="f",
            title="t",
            raw={"big": "…" * 100},
            received_at=old,
        )
    )
    session.add(
        Item(project_id=1, fingerprint="f", title="t", lane=Lane.GREEN, forge_issue_ref="#4")
    )
    session.commit()

    assert prune(session, older_than_days=90) == 1

    session.expire_all()
    assert session.query(Delivery).one().payload_json == ""
    assert session.query(Event).one().raw == {}
    # The parts that are small and irreplaceable stay: lose a fingerprint and every known error
    # looks new again tomorrow.
    item = session.query(Item).one()
    assert item.fingerprint == "f"
    assert item.forge_issue_ref == "#4"
    assert session.query(Delivery).one().payload_hash == "h"


def test_pruning_leaves_recent_deliveries_alone(session: Session) -> None:
    session.add(
        Project(slug="p", forge="forgejo", repo="o/r", webhook_secret_hash="x")  # noqa: S106
    )
    session.commit()
    session.add(Delivery(project_id=1, payload_hash="h", payload_json='{"still": "needed"}'))
    session.commit()

    assert prune(session, older_than_days=90) == 0
    assert session.query(Delivery).one().payload_json == '{"still": "needed"}'
