"""The core of M1, end to end: a real provider payload becomes triaged items in the database.

Everything here runs the path production will use — parse the manifest, normalise the payload,
resolve against existing items — with only the network absent. It is the test that proves the pieces
fit each other, rather than each fitting its own fixture.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.dedup import Outcome, resolve
from hullwork.manifest import Manifest, parse_manifest
from hullwork.models import Item, ItemState, Lane, Project
from hullwork.normalise import glitchtip

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
RECEIVED_AT = datetime(2026, 7, 26, 3, 41, tzinfo=UTC)

MANIFEST = """
project: demo
git: {provider: forgejo, repo: acme/demo}
autofix:
  lanes:
    green: [deprecation, typeerror]
    amber: [operationalerror]
    red: [payment, auth, secret]
"""


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'pipeline.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")

    with make_session_factory(make_engine(url))() as db:
        db.add(
            Project(
                slug="demo",
                forge="forgejo",
                repo="acme/demo",
                webhook_secret_hash="not-a-real-hash",  # noqa: S106 - fixture
            )
        )
        db.commit()
        yield db
    get_settings.cache_clear()


@pytest.fixture
def manifest() -> Manifest:
    return parse_manifest(MANIFEST)


def _payload(name: str) -> dict[str, object]:
    with (FIXTURES / name).open(encoding="utf-8") as handle:
        loaded: dict[str, object] = json.load(handle)
    return loaded


def _ingest(session: Session, manifest: Manifest, fixture: str) -> list[Outcome]:
    """The whole core path: raw payload in, resolved items out."""
    facts = glitchtip.parse(_payload(fixture), RECEIVED_AT)
    outcomes = [resolve(session, 1, fact, manifest).outcome for fact in facts]
    session.commit()
    return outcomes


def test_a_production_error_becomes_a_triaged_item_with_nobody_touching_anything(
    session: Session, manifest: Manifest
) -> None:
    outcomes = _ingest(session, manifest, "webhook-glitchtip-single.json")

    assert outcomes == [Outcome.CREATED]
    item = session.query(Item).one()
    assert item.state is ItemState.TRIAGED
    assert item.title.startswith("TypeError")

    # Worth reading carefully, because it is the whole point of triage looking at the culprit too:
    # the title matches the GREEN rule "typeerror", but the culprit is
    # "app.views.checkout in process_payment", which matches the RED rule "payment". Red is
    # evaluated first, so an innocuous-looking error inside the payment path stays with a human.
    assert item.lane is Lane.RED
    assert item.lane_reason is not None
    assert "payment" in item.lane_reason


def test_one_delivery_with_three_errors_becomes_three_items(
    session: Session, manifest: Manifest
) -> None:
    outcomes = _ingest(session, manifest, "webhook-glitchtip-multi.json")

    assert outcomes == [Outcome.CREATED, Outcome.CREATED, Outcome.CREATED]
    assert session.query(Item).count() == 3

    # Each was triaged on its own merits, not as a batch — and they land in different lanes:
    #   TypeError    → culprit is in the payment path                      → red
    #   OperationalError → matches the amber rule, culprit is the database → amber
    #   Deprecation notice in payment adapter → "payment" in the title     → red
    lanes = {item.title.split(":")[0].split(" ")[0]: item.lane for item in session.query(Item)}
    assert lanes["TypeError"] is Lane.RED
    assert lanes["OperationalError"] is Lane.AMBER
    assert lanes["Deprecation"] is Lane.RED


def test_the_same_delivery_arriving_again_changes_nothing_but_a_counter(
    session: Session, manifest: Manifest
) -> None:
    _ingest(session, manifest, "webhook-glitchtip-multi.json")
    outcomes = _ingest(session, manifest, "webhook-glitchtip-multi.json")

    assert outcomes == [Outcome.DEDUPLICATED] * 3
    assert session.query(Item).count() == 3
    assert {item.occurrences for item in session.query(Item).all()} == {2}


def test_a_debug_level_error_does_not_become_an_error(
    session: Session, manifest: Manifest
) -> None:
    # GlitchTip omits the colour below WARNING. The level must stay unknown rather than be invented,
    # all the way through to the stored item.
    facts = glitchtip.parse(_payload("webhook-glitchtip-sparse.json"), RECEIVED_AT)

    assert facts[0].level is None
    resolve(session, 1, facts[0], manifest)
    session.commit()
    # It matched no lane rule, so the safe default applies and a human decides.
    assert session.query(Item).one().lane is Lane.RED


def test_an_error_in_a_red_area_never_becomes_agent_work(
    session: Session, manifest: Manifest
) -> None:
    payload = {
        "attachments": [
            {
                "title": "KeyError in payment reconciliation",
                "title_link": "https://glitchtip.example.com/easybyte/issues/5000",
                "color": "#e52b50",
                "fields": [{"title": "Project", "value": "demo", "short": True}],
            }
        ]
    }
    facts = glitchtip.parse(payload, RECEIVED_AT)
    resolve(session, 1, facts[0], manifest)
    session.commit()

    item = session.query(Item).one()
    assert item.lane is Lane.RED
    assert item.state is ItemState.TRIAGED  # triaged, and going no further without a human
