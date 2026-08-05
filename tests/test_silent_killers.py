"""Three ways the pipeline used to die without saying anything (item 016).

Each test here corresponds to a failure the audit reproduced against the real code. They are
grouped in one file on purpose: what they have in common is not a module, it is that the system
kept answering 200 and reporting healthy while a whole subsystem was dead.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.dedup import Outcome, resolve
from hullwork.forge import ForgeIssue, MergeState, PermanentForgeError, Tree
from hullwork.ingest import (
    MAX_DELIVERY_ATTEMPTS,
    drain_pending,
    normalise,
    process_delivery,
    reconcile_closed,
)
from hullwork.manifest import parse_manifest
from hullwork.models import Delivery, Item, ItemState, Project
from hullwork.states import LEGAL, IllegalTransitionError

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
    """A forge whose issue state a test can set, and which can be made to fail on demand."""

    def __init__(self, *, state: str = "open", raises: Exception | None = None) -> None:
        self.state = state
        self.raises = raises
        self.created = 0

    def get_issue(self, repo: str, number: int) -> ForgeIssue | None:
        if self.raises is not None:
            raise self.raises
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
    url = f"sqlite:///{tmp_path / 'killers.db'}"
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


def _payload(name: str = "webhook-glitchtip-single.json") -> dict[str, object]:
    with (FIXTURES / name).open(encoding="utf-8") as handle:
        loaded: dict[str, object] = json.load(handle)
    return loaded


def _deliver(session: Session, *, tag: str = "d1", body: object | None = None) -> Delivery:
    delivery = Delivery(
        project_id=1,
        provider="glitchtip",
        provider_delivery_id=tag,
        payload_hash=tag,
        payload_json=json.dumps(body if body is not None else _payload()),
        received_at=RECEIVED_AT,
    )
    session.add(delivery)
    session.commit()
    return delivery


def _filed(session: Session, forge: FakeForge) -> Item:
    project = session.get(Project, 1)
    assert project is not None
    process_delivery(session, _deliver(session), project, forge)
    item = session.query(Item).one()
    assert item.forge_issue_ref is not None
    return item


# --- 1. the reopened dead end -------------------------------------------------------------


def test_a_regression_does_not_rest_in_reopened(session: Session) -> None:
    """`reopened` is passed through. Parked there, nothing could ever move the item again."""
    forge = FakeForge()
    _filed(session, forge)
    forge.state = "closed"
    reconcile_closed(session, forge)
    session.expire_all()
    assert session.query(Item).one().state is ItemState.DONE

    resolution = resolve(
        session, 1, normalise("glitchtip", _payload(), RECEIVED_AT)[0], parse_manifest(MANIFEST)
    )
    session.commit()

    assert resolution.outcome is Outcome.REOPENED
    assert resolution.item.regression is True
    assert resolution.item.state is ItemState.TRIAGED, (
        "a regression must land somewhere it can leave"
    )


def test_closing_a_regression_does_not_kill_the_sweep(session: Session) -> None:
    """The exact live bug: reopen, human closes the issue, `reopened → done` raised and the
    exception escaped reconcile_closed and sweep, killing reconciliation instance-wide for ever."""
    forge = FakeForge()
    item = _filed(session, forge)
    forge.state = "closed"
    reconcile_closed(session, forge)

    # It comes back, and then the human closes the issue again.
    resolve(
        session, 1, normalise("glitchtip", _payload(), RECEIVED_AT)[0], parse_manifest(MANIFEST)
    )
    session.commit()
    item.forge_checked_at = None
    session.commit()

    assert reconcile_closed(session, forge) == 1
    session.expire_all()
    assert session.query(Item).one().state is ItemState.DONE


def test_an_item_stranded_in_reopened_by_an_older_build_can_still_close(session: Session) -> None:
    assert ItemState.DONE in LEGAL[ItemState.REOPENED]
    forge = FakeForge()
    item = _filed(session, forge)
    item.state = ItemState.REOPENED  # as an older build would have left it
    item.forge_checked_at = None
    session.commit()
    forge.state = "closed"

    assert reconcile_closed(session, forge) == 1


def test_one_untransitionable_item_does_not_stop_the_pass(session: Session) -> None:
    """A row nobody anticipated must cost its own item and nothing else."""
    forge = FakeForge()
    good = _filed(session, forge)
    bad = Item(
        project_id=1,
        fingerprint="stuck",
        title="an item in a state with no way to done",
        state=ItemState.IN_PROGRESS,  # IN_PROGRESS -> DONE is not legal
        forge_issue_ref="#99",
    )
    session.add(bad)
    session.commit()
    forge.state = "closed"

    # The stuck item sorts first (lower id is irrelevant; both have null forge_checked_at), so this
    # would have raised before the guard existed.
    assert reconcile_closed(session, forge) == 1
    session.expire_all()
    assert session.get(Item, good.id).state is ItemState.DONE  # type: ignore[union-attr]
    stuck = session.get(Item, bad.id)
    assert stuck is not None
    assert stuck.forge_checked_at is not None, "a failed transition must still start the clock"


def test_an_illegal_transition_is_still_illegal(session: Session) -> None:
    """The guard catches the exception; it does not weaken the machine."""
    item = Item(project_id=1, fingerprint="x", title="t", state=ItemState.IN_PROGRESS)
    session.add(item)
    session.commit()
    with pytest.raises(IllegalTransitionError):
        from hullwork.states import transition

        transition(item, ItemState.TRIAGED)


# --- 2. transient failure destroying the delivery -------------------------------------------


def test_a_transient_failure_leaves_the_delivery_retryable(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reproduced by the audit as `database is locked`: the delivery was sealed, the payload sat
    there intact and unreachable, and the tracker never resends."""
    delivery = _deliver(session)

    def explode(*args: object, **kwargs: object) -> None:
        raise OperationalError("SELECT 1", {}, Exception("database is locked"))

    monkeypatch.setattr("hullwork.ingest.process_delivery", explode)
    assert drain_pending(session) == 0

    session.refresh(delivery)
    assert delivery.processed_at is None, "a transient failure must not seal the delivery"
    assert delivery.attempts == 1
    assert delivery.error is not None and "OperationalError" in delivery.error


def test_a_payload_that_cannot_be_understood_is_sealed_at_once(session: Session) -> None:
    """The other direction: retrying a body that will never parse just spins."""
    delivery = _deliver(session, body={"attachments": [{"no_title": True}]})

    assert drain_pending(session) == 0

    session.refresh(delivery)
    assert delivery.processed_at is not None, "an unparseable payload gets one attempt, not five"
    assert delivery.attempts == 1


def test_a_delivery_that_keeps_failing_stops_after_its_allowance(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never giving up would let one poisoned row jam the queue in front of everything else."""
    delivery = _deliver(session)

    def explode(*args: object, **kwargs: object) -> None:
        raise OperationalError("SELECT 1", {}, Exception("database is locked"))

    monkeypatch.setattr("hullwork.ingest.process_delivery", explode)
    for _ in range(MAX_DELIVERY_ATTEMPTS + 2):
        drain_pending(session)

    session.refresh(delivery)
    assert delivery.attempts == MAX_DELIVERY_ATTEMPTS
    assert delivery.processed_at is not None


# --- 3. the swallowed permanent forge error --------------------------------------------------


def test_a_revoked_token_is_not_mistaken_for_a_deleted_issue(session: Session) -> None:
    """A 401 used to return None, which reads as "the issue is gone": reconciliation quietly did
    nothing for the life of the instance."""
    forge = FakeForge()
    item = _filed(session, forge)
    item.forge_checked_at = None
    session.commit()

    revoked = FakeForge(raises=PermanentForgeError("GET /issues/1: HTTP 401", 401))
    assert reconcile_closed(session, revoked) == 0

    session.refresh(item)
    assert item.state is ItemState.TRIAGED
    assert item.forge_checked_at is None, "an unanswered question must not start the clock"


def test_a_genuinely_deleted_issue_is_still_ordinary_news(session: Session) -> None:
    """The adapter turns a 404 into `None` (tested against the real HTTP layer in
    `test_forge_forgejo.py`); here we check what the pipeline does with that answer — it counts as
    having been told something, so the clock starts and the item is not asked about again at once.
    """
    forge = FakeForge()
    item = _filed(session, forge)
    item.forge_checked_at = None
    session.commit()

    gone = FakeForge()
    gone.get_issue = lambda repo, number: None  # type: ignore[method-assign]
    assert reconcile_closed(session, gone) == 0

    session.refresh(item)
    assert item.state is ItemState.TRIAGED
    assert item.forge_checked_at is not None, "404 is an answer, and answers start the clock"
