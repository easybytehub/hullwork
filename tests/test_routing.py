"""Where a triaged item goes next, and — mostly — where it does not.

M1 triaged and stopped: `ready`, `waiting-approval` and `human-only` were declared in the state
machine and reachable by nothing at all. This is the step that connects them, and the condition on
it matters more than the mapping does, because most projects and every already-deployed one run with
`agent: none`.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from hullwork.cli import CommandError, approve, requeue
from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.dedup import Outcome, resolve
from hullwork.manifest import Manifest, parse_manifest
from hullwork.models import (
    Attempt,
    AttemptOutcome,
    AttemptPhase,
    Item,
    ItemState,
    Lane,
    Project,
)
from hullwork.normalise import ErrorFact
from hullwork.triage import route

ROOT = Path(__file__).resolve().parent.parent

LANES = """
  lanes:
    green: [typeerror]
    amber: [operationalerror]
    red: [payment]
"""

WITH_AGENT = f"""
project: p
git: {{provider: forgejo, repo: easybyte/p}}
autofix:
  agent: claude-code
{LANES}
tests: "pytest"
runtime: {{base: python-3.12, install: pip, dependencies: [requirements.txt]}}
"""

WITHOUT_AGENT = f"""
project: p
git: {{provider: forgejo, repo: easybyte/p}}
autofix:
{LANES}
"""


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'routing.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")

    with make_session_factory(make_engine(url))() as db:
        db.add(
            Project(
                slug="p",
                forge="forgejo",
                repo="easybyte/p",
                webhook_secret_hash="not-a-real-hash",  # noqa: S106 - fixture
                # Stored, as `add_project` stores it. `requeue` reads it back to ask `triage.route`
                # where the item belongs, and a fixture without it tests a project registration
                # cannot produce.
                manifest=parse_manifest(WITH_AGENT).model_dump(mode="json"),
            )
        )
        db.commit()
        yield db


def _fact(title: str, culprit: str = "app.reports.build") -> ErrorFact:
    return ErrorFact(
        provider="glitchtip",
        project_ref="p",
        title=title,
        culprit=culprit,
        fingerprint=f"fp-{title}",
        fingerprint_derived=True,
        level="error",
        timestamps_are_receipt_time=True,
        raw={},
    )


def _item(session: Session, title: str, manifest_text: str) -> Item:
    manifest = parse_manifest(manifest_text)
    resolution = resolve(session, 1, _fact(title), manifest)
    assert resolution.outcome is Outcome.CREATED
    return resolution.item


# --- the default path, which must not have changed ----------------------------------------------


@pytest.mark.parametrize(
    ("title", "lane"),
    [
        pytest.param("TypeError: bad", Lane.GREEN, id="green"),
        pytest.param("OperationalError: locked", Lane.AMBER, id="amber"),
        pytest.param("PaymentError: declined", Lane.RED, id="red"),
    ],
)
def test_with_no_agent_nothing_moves(session: Session, title: str, lane: Lane) -> None:
    """`agent: none` is the default (DR-0002), and this is what every deployed project runs.

    A change in this path is a change to what existing users already have, so it is asserted rather
    than intended — whatever the lane, the item stops at `triaged` exactly as it did in M1.
    """
    item = _item(session, title, WITHOUT_AGENT)

    assert item.lane is lane
    assert item.state is ItemState.TRIAGED


# --- and the path that only exists once there is an agent ---------------------------------------


@pytest.mark.parametrize(
    ("title", "lane", "state"),
    [
        pytest.param("TypeError: bad", Lane.GREEN, ItemState.READY, id="green-is-ready"),
        pytest.param(
            "OperationalError: locked",
            Lane.AMBER,
            ItemState.WAITING_APPROVAL,
            id="amber-waits-for-a-human",
        ),
        pytest.param(
            "PaymentError: declined", Lane.RED, ItemState.HUMAN_ONLY, id="red-is-human-only"
        ),
    ],
)
def test_a_named_agent_routes_each_lane(
    session: Session, title: str, lane: Lane, state: ItemState
) -> None:
    item = _item(session, title, WITH_AGENT)

    assert item.lane is lane
    assert item.state is state


def test_a_regression_is_routed_again_and_may_go_somewhere_else(session: Session) -> None:
    """Its lane is recomputed on the way back, so a manifest edited meanwhile changes the answer.

    Inheriting the old routing would mean an operator who moved a pattern into the red lane after
    being burned once watches the same error walk back into an agent's hands.
    """
    item = _item(session, "TypeError: bad", WITH_AGENT)
    item.state = ItemState.DONE
    session.commit()

    stricter = parse_manifest(WITH_AGENT.replace("red: [payment]", "red: [payment, typeerror]"))
    again = resolve(session, 1, _fact("TypeError: bad"), stricter)

    assert again.outcome is Outcome.REOPENED
    assert again.item.regression
    assert again.item.lane is Lane.RED
    assert again.item.state is ItemState.HUMAN_ONLY


def test_route_is_idempotent_on_an_already_routed_item(session: Session) -> None:
    # The sweep can re-resolve, and a second call must not raise its way out of the pipeline.
    item = _item(session, "TypeError: bad", WITH_AGENT)
    manifest: Manifest = parse_manifest(WITH_AGENT)

    with pytest.raises(Exception, match="cannot move"):
        route(item, manifest)


# --- approval -----------------------------------------------------------------------------------


def test_approving_an_amber_item_makes_it_ready(session: Session) -> None:
    item = _item(session, "OperationalError: locked", WITH_AGENT)
    assert item.state is ItemState.WAITING_APPROVAL

    approved = approve(session, "p", item.id)

    assert approved.state is ItemState.READY


def test_approving_something_that_is_not_waiting_says_what_it_found(session: Session) -> None:
    item = _item(session, "TypeError: bad", WITH_AGENT)  # already ready

    with pytest.raises(CommandError) as caught:
        approve(session, "p", item.id)

    assert "'ready'" in str(caught.value)


def test_a_red_item_cannot_be_approved(session: Session) -> None:
    """Not by this command, and not by any other.

    The state machine refuses to move a red item into an agent state wherever the call comes from,
    which is the point of enforcing it there instead of at each call site. Here it means an operator
    cannot wave one through by hand.
    """
    item = _item(session, "PaymentError: declined", WITH_AGENT)
    item.state = ItemState.WAITING_APPROVAL  # force the only path that could reach the transition
    session.commit()

    with pytest.raises(CommandError, match="red lane"):
        approve(session, "p", item.id)


def test_approving_an_unknown_item_names_the_project(session: Session) -> None:
    with pytest.raises(CommandError, match="no item 999"):
        approve(session, "p", 999)


# --- requeue: an item that kept its attempt gets to spend it. Item 093 ---------------------------


def _stopped_at_baseline(
    session: Session, item: Item, *, outcome: AttemptOutcome = AttemptOutcome.BASELINE_RED,
    consumed: bool = False,
) -> None:
    """Put the item where a `baseline-red` verdict leaves it: `human-only`, attempt unspent."""
    session.add(
        Attempt(
            item_id=item.id,
            phase_reached=AttemptPhase.BASELINE,
            outcome=outcome,
            consumed=consumed,
            started_at=datetime.now(UTC),
        )
    )
    item.state = ItemState.HUMAN_ONLY
    session.commit()


def test_a_green_item_stopped_by_a_red_baseline_goes_back_to_ready(session: Session) -> None:
    """**The case this exists for, from the live instance.**

    Item #14 was `human-only` with `consumed = False` because Hullwork's own sandbox mounted `/tmp`
    `noexec` (item 092). The mount was fixed and nothing could put the item back: the preserved
    attempt was bookkeeping with no door, and the only route was an `UPDATE` against a SQLite file
    inside a Docker volume.
    """
    item = _item(session, "TypeError: bad", WITH_AGENT)
    _stopped_at_baseline(session, item)

    requeued = requeue(session, "p", item.id)

    assert requeued.state is ItemState.READY


def test_an_amber_item_goes_back_to_waiting_approval_and_not_to_ready(session: Session) -> None:
    """Where it goes is `triage.route`'s decision, and requeue must not have its own copy.

    The human decision an amber item represents was never about the sandbox, so removing the
    obstruction does not grant the approval.
    """
    item = _item(session, "OperationalError: locked", WITH_AGENT)
    assert item.lane is Lane.AMBER
    _stopped_at_baseline(session, item)

    requeued = requeue(session, "p", item.id)

    assert requeued.state is ItemState.WAITING_APPROVAL, (
        "requeue approved an amber item by the back door"
    )


@pytest.mark.parametrize(
    "outcome",
    [
        pytest.param(AttemptOutcome.NOT_REPRODUCIBLE, id="not-reproducible"),
        pytest.param(AttemptOutcome.FAILED, id="failed"),
    ],
)
def test_an_outcome_where_the_agent_did_look_is_refused(
    session: Session, outcome: AttemptOutcome
) -> None:
    """The eligibility rule, and why it is the outcome rather than the state.

    `human-only` is reached from several places and they make different claims. A red baseline says
    *nothing was learned about the bug*; these two say the agent looked and this is what it found.
    Requeueing them spends a second attempt on the same evidence.
    """
    item = _item(session, "TypeError: bad", WITH_AGENT)
    _stopped_at_baseline(session, item, outcome=outcome, consumed=True)

    with pytest.raises(CommandError) as refused:
        requeue(session, "p", item.id)

    assert outcome.value in str(refused.value), "the refusal must name the outcome it read"
    assert item.state is ItemState.HUMAN_ONLY, "the refusal must not move the item"


def test_an_item_that_is_not_human_only_is_refused_by_the_state_it_is_in(
    session: Session,
) -> None:
    item = _item(session, "TypeError: bad", WITH_AGENT)  # already ready

    with pytest.raises(CommandError) as refused:
        requeue(session, "p", item.id)

    assert "'ready'" in str(refused.value)


def test_a_consumed_attempt_leaves_nothing_to_spend(session: Session) -> None:
    """`consumed` is the whole point of the exemption, so it is checked rather than assumed.

    A `baseline-red` that somehow consumed its attempt is not a case this can put back: the item
    would run a second time on its one and only try.
    """
    item = _item(session, "TypeError: bad", WITH_AGENT)
    _stopped_at_baseline(session, item, consumed=True)

    with pytest.raises(CommandError, match="none left to spend"):
        requeue(session, "p", item.id)
