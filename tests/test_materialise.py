"""What happens when the forge is not there at the moment an item needs its issue.

The interesting failure is not the forge being down — that is expected and handled. It is what the
system does *afterwards*: a delivery is processed exactly once, so an item that misses its issue
during that one pass has no second chance unless something else goes looking for it.

Nothing upstream will remind us either. GlitchTip excludes an issue from an alert once it has been
notified, permanently (`apps/alerts/tasks.py`), so a delivery that fails is a delivery that never
comes again. This database is the only place the intent survives.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.orm import Session

from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.forge import ForgeIssue, MergeState, PermanentForgeError, RetryableForgeError, Tree
from hullwork.ingest import drain_unmaterialised, process_delivery, sweep
from hullwork.manifest import parse_manifest
from hullwork.models import Delivery, Item, ItemState, Lane, Project

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
RECEIVED_AT = datetime(2026, 7, 27, 9, 28, tzinfo=UTC)

MANIFEST = """
project: demo
git: {provider: forgejo, repo: acme/demo}
autofix:
  lanes:
    green: [typeerror]
    amber: [operationalerror]
    red: [payment, auth, secret]
"""


class FakeForge:
    """A forge that can be told to fail, and that counts what was asked of it.

    Counting matters as much as failing here: the test that proves a sweep with nothing pending is
    silent can only be written against a forge that remembers being called.
    """

    def __init__(self, *, failures: int = 0, error: type[Exception] = RetryableForgeError) -> None:
        self.failures = failures
        self.error = error
        self.created: list[str] = []
        self.comments: list[tuple[int, str]] = []
        self.states: list[tuple[int, str]] = []
        self.calls = 0

    def _maybe_fail(self) -> None:
        self.calls += 1
        if self.failures > 0:
            self.failures -= 1
            raise self.error("the forge is not answering")

    def head_commit(self, repo: str, branch: str) -> str:  # pragma: no cover - not used here
        return "0" * 40

    def read_manifest(self, repo: str) -> str:  # pragma: no cover - not used here
        return MANIFEST

    def get_issue(self, repo: str, number: int) -> ForgeIssue | None:
        """Always open here: this file is about filing, and reconciliation has its own tests."""
        self._maybe_fail()
        return ForgeIssue(number=number, title="t", state="open", html_url="https://forge/x")

    def ensure_labels(self, repo: str, names: dict[str, str]) -> dict[str, int]:
        self._maybe_fail()
        return {name: index + 1 for index, name in enumerate(names)}

    def create_issue(
        self, repo: str, title: str, body: str, label_ids: list[int] | None = None
    ) -> ForgeIssue:
        self._maybe_fail()
        self.created.append(title)
        number = len(self.created)
        return ForgeIssue(
            number=number, title=title, state="open", html_url=f"https://forge/{number}", body=body
        )

    def find_issue_by_marker(  # pragma: no cover - not used here
        self, repo: str, fingerprint: str
    ) -> ForgeIssue | None:
        return None

    def comment(self, repo: str, number: int, body: str) -> None:
        self._maybe_fail()
        self.comments.append((number, body))

    def set_issue_state(self, repo: str, number: int, state: str) -> ForgeIssue:
        self._maybe_fail()
        self.states.append((number, state))
        return ForgeIssue(number=number, title="", state=state, html_url="https://forge/x")

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
def _migrate(target: str = "head") -> None:
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, target)


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'materialise.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    _migrate()

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


def _deliver(
    session: Session, fixture: str = "webhook-glitchtip-single.json", *, again: str = ""
) -> Delivery:
    """Store a delivery as the receiver would.

    `again` makes it a distinct delivery carrying the same body, which is what a second occurrence
    of the same error actually looks like.
    """
    with (FIXTURES / fixture).open(encoding="utf-8") as handle:
        payload = json.load(handle)
    delivery = Delivery(
        project_id=1,
        provider="glitchtip",
        provider_delivery_id=fixture + again,
        payload_hash=fixture + again,
        payload_json=json.dumps(payload),
        received_at=RECEIVED_AT,
    )
    session.add(delivery)
    session.commit()
    return delivery


def test_an_item_whose_issue_could_not_be_filed_is_filed_by_the_next_sweep(
    session: Session,
) -> None:
    """The hole this work item exists to close.

    The delivery is processed exactly once and is never revisited, so before the fix the item below
    stayed without an issue for as long as the instance lived.
    """
    down = FakeForge(failures=99)
    project = session.get(Project, 1)
    assert project is not None
    process_delivery(session, _deliver(session), project, down)

    stranded = session.query(Item).one()
    assert stranded.forge_issue_ref is None
    assert stranded.forge_sync_pending, "the intent to file must outlive the failed attempt"
    title = stranded.title

    # No new delivery arrives — that is the whole point. Something else has to go looking.
    up = FakeForge()
    assert drain_unmaterialised(session, up) == 1

    session.expire_all()
    filed = session.query(Item).one()
    assert filed.forge_issue_ref == "#1"
    assert not filed.forge_sync_pending
    assert up.created == [title]


def test_a_sweep_with_nothing_pending_makes_no_forge_calls(session: Session) -> None:
    forge = FakeForge()
    project = session.get(Project, 1)
    assert project is not None
    process_delivery(session, _deliver(session), project, forge)
    calls_after_filing = forge.calls

    assert drain_unmaterialised(session, forge) == 0
    assert forge.calls == calls_after_filing, "a quiet sweep must stay off the network"


def test_a_permanent_failure_keeps_the_item_pending_and_records_why(session: Session) -> None:
    """Giving up is the failure mode being removed, so a dead repository stays visible and queued.

    Retrying costs one call per pass; abandoning costs the bug.
    """
    project = session.get(Project, 1)
    assert project is not None
    process_delivery(session, _deliver(session), project, FakeForge(failures=99))

    broken = FakeForge(failures=99, error=PermanentForgeError)
    assert drain_unmaterialised(session, broken) == 0

    item = session.query(Item).one()
    assert item.forge_sync_pending
    assert item.forge_attempts == 2  # the delivery's attempt, and this one
    assert item.forge_error is not None
    assert "PermanentForgeError" in item.forge_error


def test_a_reopen_that_failed_is_retried_too(session: Session) -> None:
    """A regression whose reopen failed has an issue ref already, so `ref IS NULL` cannot see it."""
    forge = FakeForge()
    project = session.get(Project, 1)
    assert project is not None
    process_delivery(session, _deliver(session), project, forge)

    item = session.query(Item).one()
    item.state = ItemState.DONE
    session.commit()

    # The same error comes back against a closed item, with the forge unreachable at that moment.
    delivery = _deliver(session, again="-second")
    process_delivery(session, delivery, project, FakeForge(failures=99))

    session.refresh(item)
    assert item.regression
    assert item.forge_issue_ref == "#1"  # it has a ref, and still needs the forge
    assert item.forge_sync_pending

    recovered = FakeForge()
    assert drain_unmaterialised(session, recovered) == 1
    assert recovered.states == [(1, "open")]
    assert recovered.created == [], "a regression reopens its issue, it does not file a new one"
    session.refresh(item)
    assert not item.forge_sync_pending


def test_sweep_finishes_deliveries_and_files_items_in_one_pass(session: Session) -> None:
    project = session.get(Project, 1)
    assert project is not None
    process_delivery(session, _deliver(session), project, FakeForge(failures=99))
    _deliver(session, "webhook-glitchtip-multi.json")

    result = sweep(session, FakeForge())

    assert result.deliveries == 1  # the multi one, still unprocessed
    assert result.filed == 1  # the orphan from the first delivery
    assert session.query(Item).filter(Item.forge_sync_pending.is_(True)).count() == 0


def test_upgrading_a_database_with_orphaned_items_flags_them_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deploying the fix *is* the recovery — there is no script to remember to run.

    Written against the real migration chain rather than the models, because an item stranded in a
    live database is exactly the case that does not exist in a freshly created schema.
    """
    url = f"sqlite:///{tmp_path / 'upgrade.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    _migrate("1f83673e3596")  # the revision that was live when the orphans were created

    engine = make_engine(url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO projects (id, slug, forge, repo, webhook_secret_hash, active, "
                "created_at) VALUES (1, 'p', 'forgejo', 'o/r', 'x', 1, '2026-07-27 09:00:00')"
            )
        )
        for row, ref in ((1, "NULL"), (2, "'#7'")):
            connection.execute(
                text(
                    f"INSERT INTO items (id, project_id, fingerprint, state, lane, kind, title, "  # noqa: S608
                    f"occurrences, first_seen, last_seen, forge_issue_ref, regression, created_at, "
                    f"updated_at) VALUES ({row}, 1, 'fp{row}', 'triaged', 'green', 'bug', 't', 1, "
                    f"'2026-07-27 09:00:00', '2026-07-27 09:00:00', {ref}, 0, "
                    f"'2026-07-27 09:00:00', '2026-07-27 09:00:00')"
                )
            )

    _migrate()

    with make_session_factory(engine)() as db:
        stranded = db.get(Item, 1)
        filed = db.get(Item, 2)
        assert stranded is not None and filed is not None
        assert stranded.forge_sync_pending, "the orphan must come back into the queue"
        assert not filed.forge_sync_pending, "an item that already has its issue is left alone"
    get_settings.cache_clear()


def test_the_lane_survives_a_retry(session: Session) -> None:
    """The issue filed late must be the issue that would have been filed on time."""
    project = session.get(Project, 1)
    assert project is not None
    process_delivery(session, _deliver(session), project, FakeForge(failures=99))

    item = session.query(Item).one()
    assert item.lane is Lane.RED  # the fixture's culprit is in the payment path

    drain_unmaterialised(session, FakeForge())
    session.refresh(item)
    assert item.lane is Lane.RED
