"""Two passes at once, and what used to happen (item 018).

Every production path into the pipeline goes through `sweep`: start-up, the background task after
an accepted delivery, and the periodic ticker. The last two can overlap at any moment, and nothing
serialised them — selecting rows is not claiming them, and the gap between "file this issue" and
"record that it is filed" is a whole HTTP round trip wide.
"""

import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from hullwork.config import get_settings
from hullwork.db import get_engine, make_engine, make_session_factory
from hullwork.forge import ForgeIssue, MergeState, Tree
from hullwork.ingest import sweep
from hullwork.manifest import parse_manifest
from hullwork.models import Delivery, Item, Project

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
RECEIVED_AT = datetime(2026, 7, 27, 9, 28, tzinfo=UTC)

MANIFEST = """
project: demo
git: {provider: forgejo, repo: acme/demo}
autofix:
  lanes: {green: [typeerror], red: [payment]}
"""


class SlowForge:
    """A forge that parks inside `create_issue` until released — the real window, made visible."""

    def __init__(self) -> None:
        self.inside = threading.Event()
        self.release = threading.Event()
        self.created: list[str] = []
        self.filed_by_marker = 0
        self._lock = threading.Lock()

    def head_commit(self, repo: str, branch: str) -> str:  # pragma: no cover - not used here
        return "0" * 40

    def read_manifest(self, repo: str) -> str:  # pragma: no cover - not used here
        return MANIFEST

    def get_issue(self, repo: str, number: int) -> ForgeIssue | None:
        return ForgeIssue(number=number, title="t", state="open", html_url="https://forge/x")

    def find_issue_by_marker(self, repo: str, fingerprint: str) -> ForgeIssue | None:
        with self._lock:
            if not self.created:
                return None
            self.filed_by_marker += 1
            return ForgeIssue(
                number=1, title=self.created[0], state="open", html_url="https://forge/1"
            )

    def ensure_labels(self, repo: str, names: dict[str, str]) -> dict[str, int]:
        return {name: index + 1 for index, name in enumerate(names)}

    def create_issue(
        self, repo: str, title: str, body: str, label_ids: list[int] | None = None
    ) -> ForgeIssue:
        self.inside.set()
        self.release.wait(timeout=5)
        with self._lock:
            self.created.append(title)
            number = len(self.created)
        return ForgeIssue(
            number=number, title=title, state="open", html_url="https://forge/x", body=body
        )

    def comment(self, repo: str, number: int, body: str) -> None:
        return None

    def set_issue_state(self, repo: str, number: int, state: str) -> ForgeIssue:
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
def url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    database = f"sqlite:///{tmp_path / 'concurrency.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", database)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")

    with make_session_factory(make_engine(database))() as db:
        db.add(
            Project(
                slug="demo",
                forge="forgejo",
                repo="acme/demo",
                webhook_secret_hash="not-a-real-hash",  # noqa: S106 - fixture
                manifest=parse_manifest(MANIFEST).model_dump(mode="json"),
            )
        )
        db.commit()  # the delivery below references it by id, so it has to exist first
        with (FIXTURES / "webhook-glitchtip-single.json").open(encoding="utf-8") as handle:
            payload = json.load(handle)
        db.add(
            Delivery(
                project_id=1,
                provider="glitchtip",
                provider_delivery_id="d1",
                payload_hash="h1",
                payload_json=json.dumps(payload),
                received_at=RECEIVED_AT,
            )
        )
        db.commit()
    yield database
    get_settings.cache_clear()


def _sweep_in_thread(database: str, forge: SlowForge, done: list[object]) -> threading.Thread:
    def run() -> None:
        with make_session_factory(make_engine(database))() as session:
            done.append(sweep(session, forge))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def test_two_passes_at_once_file_one_issue_not_two(url: str) -> None:
    """The reproduction: one item, two issues, and the first one orphaned and open for ever."""
    forge = SlowForge()
    results: list[object] = []
    first = _sweep_in_thread(url, forge, results)

    assert forge.inside.wait(timeout=5), "the first pass never reached the forge"

    # The ticker fires while the webhook's pass is parked inside create_issue.
    second_results: list[object] = []
    second = _sweep_in_thread(url, forge, second_results)
    second.join(timeout=5)

    forge.release.set()
    first.join(timeout=5)

    assert len(forge.created) == 1, f"filed {len(forge.created)} issues for one item"
    with make_session_factory(make_engine(url))() as session:
        assert session.query(Item).count() == 1
        assert session.query(Item).one().forge_issue_ref == "#1"


def test_the_second_pass_says_it_skipped_rather_than_pretending_to_work(url: str) -> None:
    forge = SlowForge()
    results: list[object] = []
    first = _sweep_in_thread(url, forge, results)
    assert forge.inside.wait(timeout=5)

    with make_session_factory(make_engine(url))() as session:
        skipped = sweep(session, forge)

    forge.release.set()
    first.join(timeout=5)

    assert skipped.skipped is True
    assert (skipped.deliveries, skipped.filed, skipped.resolved) == (0, 0, 0)


def test_a_delivery_is_not_processed_twice(url: str) -> None:
    """Two drains selecting the same unprocessed row produced two events and a doubled counter."""
    forge = SlowForge()
    results: list[object] = []
    first = _sweep_in_thread(url, forge, results)
    assert forge.inside.wait(timeout=5)
    _sweep_in_thread(url, forge, []).join(timeout=5)
    forge.release.set()
    first.join(timeout=5)

    with make_session_factory(make_engine(url))() as session:
        assert session.query(Item).one().occurrences == 1
        assert session.execute(text("SELECT count(*) FROM events")).scalar_one() == 1


def test_an_issue_that_already_exists_is_adopted_rather_than_duplicated(url: str) -> None:
    """Idempotency that survives a restart, a second process, or a restored backup — the cases an
    in-process lock cannot see."""
    forge = SlowForge()
    forge.release.set()
    with make_session_factory(make_engine(url))() as session:
        sweep(session, forge)
        item = session.query(Item).one()
        # As if the commit recording the reference had failed after the issue was created.
        item.forge_issue_ref = None
        item.forge_sync_pending = True
        session.commit()

        sweep(session, forge)

        session.expire_all()
        assert session.query(Item).one().forge_issue_ref == "#1"
    assert len(forge.created) == 1, "a second issue was filed for an item that already had one"
    assert forge.filed_by_marker == 1


def test_the_engine_is_built_once_per_database(url: str) -> None:
    """A fresh engine per request, never disposed, was 500 connections from 500 anonymous calls.

    Disposed here rather than left to `conftest`'s autouse cleanup, and the reason is this test's
    own subject: that fixture tracks engines through SQLAlchemy's `engine_connect` event, and this
    asserts *identity* without ever opening a connection. So it is the one engine in the suite the
    cleanup cannot see — which is why it was the last leak standing on Python 3.14.
    """
    built = get_engine(url)
    try:
        assert built is get_engine(url)
    finally:
        built.dispose()
