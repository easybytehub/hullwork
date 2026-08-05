"""The way back: what the forge knows that this database does not.

Filing an issue is only half a loop. Somebody eventually fixes the bug and closes it, and if that
never reaches us then every later decision — what is outstanding, what a digest says, what an agent
is told is left to do — is made against a database that disagrees with the forge the team is
actually looking at.

Written after closing four real issues by hand and watching Hullwork not notice.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.dedup import Outcome, resolve
from hullwork.forge import ForgeIssue, MergeState, RetryableForgeError, Tree
from hullwork.ingest import normalise, process_delivery, reconcile_closed, sweep
from hullwork.manifest import parse_manifest
from hullwork.models import Delivery, Item, ItemState, Project

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
RECEIVED_AT = datetime(2026, 7, 27, 9, 28, tzinfo=UTC)

MANIFEST = """
project: demo
git: {provider: forgejo, repo: acme/demo}
autofix:
  lanes:
    green: [typeerror]
    red: [payment, auth, secret]
"""


class FakeForge:
    """A forge whose issues have a state a test can change, and that counts being asked."""

    def __init__(self, *, state: str = "open", fails: bool = False) -> None:
        self.state = state
        self.fails = fails
        self.reads: list[int] = []
        self.created = 0

    def get_issue(self, repo: str, number: int) -> ForgeIssue | None:
        if self.fails:
            raise RetryableForgeError("the forge is not answering")
        self.reads.append(number)
        return ForgeIssue(number=number, title="t", state=self.state, html_url="https://forge/x")

    def head_commit(self, repo: str, branch: str) -> str:  # pragma: no cover - not used here
        return "0" * 40

    def read_manifest(self, repo: str) -> str:  # pragma: no cover - not used here
        return MANIFEST

    def ensure_labels(self, repo: str, names: dict[str, str]) -> dict[str, int]:
        return {name: index + 1 for index, name in enumerate(names)}

    def create_issue(
        self, repo: str, title: str, body: str, label_ids: list[int] | None = None
    ) -> ForgeIssue:
        self.created += 1
        return ForgeIssue(
            number=self.created, title=title, state="open", html_url="https://forge/x", body=body
        )

    def find_issue_by_marker(  # pragma: no cover - not used here
        self, repo: str, fingerprint: str
    ) -> ForgeIssue | None:
        return None

    def comment(self, repo: str, number: int, body: str) -> None:
        return None

    def set_issue_state(self, repo: str, number: int, state: str) -> ForgeIssue:
        self.state = state
        return ForgeIssue(number=number, title="t", state=state, html_url="https://forge/x")

    def close(self) -> None:
        """Part of the `Forge` protocol since item 068, which declared what callers already did.

        Nothing to release in a double; present so the double still *is* a `Forge`. A double that
        drifts from the protocol stops testing the thing the protocol describes.
        """

    # --- M9 added two read methods to the protocol, so the double grew them too ------------------
    #
    # Unused by anything this file tests, and that is exactly why they are here: a double that no
    # longer satisfies the protocol stops testing the thing the protocol describes (the reason
    # `close` above was added for item 068). `merge_state` and `release_contains` are on the *read*
    # protocol on purpose — asking whether a pull request was merged is a read, and the recurrence
    # watch runs on the receiver's ingest credential.

    def read_file(self, repo: str, path: str) -> str | None:  # pragma: no cover - not used here
        """On the `Forge` protocol since item 107. A double that drifts stops testing it."""
        return None

    def tree(self, repo: str) -> Tree:  # pragma: no cover - not used here
        """On the `Forge` protocol since M8. A double that drifts stops testing the protocol."""
        return Tree(())

    def merge_state(self, repo: str, number: int) -> MergeState:  # pragma: no cover - not used here
        return MergeState(merged=False)

    def release_contains(  # pragma: no cover - not used here
        self, repo: str, release: str, commit: str
    ) -> bool | None:
        return None
@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'reconcile.db'}"
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
                manifest=parse_manifest(MANIFEST).model_dump(mode="json"),
            )
        )
        db.commit()
        yield db
    get_settings.cache_clear()


def _filed_item(session: Session, forge: FakeForge) -> Item:
    """Put one item through the real path so it ends up materialised, as production would."""
    with (FIXTURES / "webhook-glitchtip-single.json").open(encoding="utf-8") as handle:
        payload = json.load(handle)
    delivery = Delivery(
        project_id=1,
        provider="glitchtip",
        provider_delivery_id="d1",
        payload_hash="h1",
        payload_json=json.dumps(payload),
        received_at=RECEIVED_AT,
    )
    session.add(delivery)
    session.commit()
    project = session.get(Project, 1)
    assert project is not None
    process_delivery(session, delivery, project, forge)
    item = session.query(Item).one()
    assert item.forge_issue_ref is not None
    return item


def test_an_issue_closed_by_a_human_closes_the_item(session: Session) -> None:
    """The defect this work item exists for. Before it, the item stayed triaged forever."""
    forge = FakeForge()
    item = _filed_item(session, forge)
    assert item.state is ItemState.TRIAGED

    forge.state = "closed"  # somebody fixed the bug and closed the issue
    assert reconcile_closed(session, forge) == 1

    session.expire_all()
    assert session.query(Item).one().state is ItemState.DONE


def test_an_open_issue_leaves_the_item_alone_and_is_not_asked_about_twice(
    session: Session,
) -> None:
    forge = FakeForge()
    _filed_item(session, forge)

    assert reconcile_closed(session, forge) == 0
    assert len(forge.reads) == 1
    assert session.query(Item).one().state is ItemState.TRIAGED

    # Straight away again: the recheck window has not passed, so the forge is not troubled.
    assert reconcile_closed(session, forge) == 0
    assert len(forge.reads) == 1, "one call per item per window, not one per sweep"


def test_the_window_expiring_makes_it_ask_again(session: Session) -> None:
    forge = FakeForge()
    item = _filed_item(session, forge)
    reconcile_closed(session, forge)

    item.forge_checked_at = datetime.now(UTC) - timedelta(hours=1)
    session.commit()
    forge.state = "closed"

    assert reconcile_closed(session, forge, recheck_after=600) == 1
    assert len(forge.reads) == 2


def test_an_unreachable_forge_loses_nothing(session: Session) -> None:
    """A forge that cannot answer is not news about the issue, and must not be recorded as one."""
    forge = FakeForge()
    item = _filed_item(session, forge)

    broken = FakeForge(fails=True)
    assert reconcile_closed(session, broken) == 0

    session.refresh(item)
    assert item.state is ItemState.TRIAGED
    assert item.forge_checked_at is None, "an unanswered question must not start the clock"


def test_an_item_with_no_issue_is_never_asked_about(session: Session) -> None:
    down = FakeForge()
    down.create_issue = _raise  # type: ignore[method-assign]
    with (FIXTURES / "webhook-glitchtip-single.json").open(encoding="utf-8") as handle:
        payload = json.load(handle)
    delivery = Delivery(
        project_id=1,
        provider="glitchtip",
        provider_delivery_id="d1",
        payload_hash="h1",
        payload_json=json.dumps(payload),
        received_at=RECEIVED_AT,
    )
    session.add(delivery)
    session.commit()
    project = session.get(Project, 1)
    assert project is not None
    process_delivery(session, delivery, project, down)

    reader = FakeForge()
    assert reconcile_closed(session, reader) == 0
    assert reader.reads == [], "nothing to reconcile until the issue exists"


def _raise(*args: object, **kwargs: object) -> ForgeIssue:
    raise RetryableForgeError("the forge is not answering")


def test_a_closed_item_treats_the_same_error_as_a_regression(session: Session) -> None:
    """The point of knowing: a bug that comes back after being fixed is not a repeat."""
    forge = FakeForge()
    item = _filed_item(session, forge)
    forge.state = "closed"
    reconcile_closed(session, forge)
    session.expire_all()
    assert session.query(Item).one().state is ItemState.DONE

    with (FIXTURES / "webhook-glitchtip-single.json").open(encoding="utf-8") as handle:
        payload = json.load(handle)
    manifest = parse_manifest(MANIFEST)
    fact = normalise("glitchtip", payload, RECEIVED_AT)[0]
    resolution = resolve(session, 1, fact, manifest)
    session.commit()

    assert resolution.outcome is Outcome.REOPENED
    assert resolution.item.regression is True
    assert resolution.item.id == item.id


def test_sweep_reports_what_it_resolved(session: Session) -> None:
    forge = FakeForge()
    _filed_item(session, forge)
    forge.state = "closed"

    result = sweep(session, forge)

    assert result.resolved == 1
    assert result.deliveries == 0  # the only delivery was already processed
