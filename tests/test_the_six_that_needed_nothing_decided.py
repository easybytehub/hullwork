"""Six commands that were missing from the page and needed nothing decided. Item 219, item 218 §1.

Every one is a database write, or a call the receiver already makes with a credential it already
holds: `requeue`, `republish`, `sweep`, `lease`, `lease release`, `prune`. No new host, no new
capability. They were never placed, which is what item 218's guard exists to stop happening again.

Two of them are dangerous in the ordinary way and their gates are the interesting part: `sweep`'s
first pass counts before it writes, because filing three hundred forge issues on somebody's first
afternoon is how a tool gets uninstalled that evening (DR-0011); and `prune` is the only destructive
control on the page, so it says what it would drop before it drops anything.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import operator, page
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import Attempt, Base, Delivery, Item, ItemState, Lane, Project
from hullwork.page import Acting
from hullwork.security import generate_token, hash_token

SIGNED_IN = Acting(csrf="c", offered=True)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/six.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "t")
    get_settings.cache_clear()
    yield sessionmaker(bind=engine)()
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    from hullwork.main import app

    return TestClient(app)


def _project(db: Session) -> Project:
    row = Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        # `requeue` re-routes the item through the stored manifest, so a project without one
        # refuses before it gets anywhere near the state under test (DR-0012: adopted, not
        # followed — the instance holds the copy every decision reads).
        manifest={
            "project": "shop",
            "git": {"provider": "forgejo", "repo": "acme/shop"},
            "errors": {"provider": "glitchtip"},
            "autofix": {"lanes": {"green": ["keyerror"], "red": ["payment"]}},
        },
    )
    db.add(row)
    db.flush()
    return row


def _item(db: Session, project: Project, *, state: ItemState = ItemState.NEW) -> Item:
    row = Item(
        project_id=project.id,
        fingerprint=f"f{state.value}",
        title="KeyError: 'total' in checkout",
        state=state,
        lane=Lane.GREEN,
        last_seen=dt.datetime.now(dt.UTC),
    )
    db.add(row)
    db.flush()
    return row


def _signed_in(db: Session, client: TestClient) -> None:
    operator.set_password(db, "correct horse")
    db.commit()
    client.post("/page/me/login", data={"password": "correct horse"})


# --- the item's two ------------------------------------------------------------------------------


def _stopped_by_a_red_baseline(db: Session, project: Project) -> Item:
    """The one state `requeue` is for, built properly. Item 093: a `baseline-red` attempt ends the
    item `human-only` and records `consumed = False`, because nothing was learned about the bug —
    the suite was already failing. Item 092 was exactly this, waiting on a sandbox mount.

    **The first version of the test below used `failed` and asserted the state changed.** It did
    not, because `requeue` refused — correctly — and the test read that as the page being broken.
    A fixture that cannot reach the state under test measures the refusal instead."""
    from hullwork.models import AttemptOutcome, AttemptPhase

    item = _item(db, project, state=ItemState.HUMAN_ONLY)
    db.add(
        Attempt(
            item_id=item.id,
            phase_reached=AttemptPhase.BASELINE,
            outcome=AttemptOutcome.BASELINE_RED,
            consumed=False,
            not_consumed_reason="the suite was already red",
        )
    )
    db.flush()
    return item


def test_an_item_can_be_requeued_from_its_own_page(db: Session, client: TestClient) -> None:
    """**It calls `cli.requeue`**, which is the function the terminal calls. A second
    implementation would drift, and the one that drifts is the one nobody runs by hand."""
    project = _project(db)
    item = _stopped_by_a_red_baseline(db, project)
    db.commit()
    _signed_in(db, client)

    shown = client.post(
        f"/page/me/items/{item.id}", data={"action": "requeue", "csrf": _csrf(client, db)}
    )

    assert shown.status_code == 200
    db.expire_all()
    back = db.get(Item, item.id)
    assert back is not None and back.state is not ItemState.HUMAN_ONLY


def test_an_unknown_action_on_an_item_does_nothing_and_says_so(
    db: Session, client: TestClient
) -> None:
    """Item 207's rule, on the second route that takes an action: no default branch. A form field
    that falls through to whichever branch was written last is how a typo spends an attempt."""
    project = _project(db)
    item = _stopped_by_a_red_baseline(db, project)
    db.commit()
    _signed_in(db, client)

    shown = client.post(
        f"/page/me/items/{item.id}", data={"action": "delete-everything", "csrf": _csrf(client, db)}
    )

    db.expire_all()
    untouched = db.get(Item, item.id)
    assert untouched is not None and untouched.state is ItemState.HUMAN_ONLY, "it did something"
    assert "delete-everything" in shown.text and "Nothing was changed" in shown.text


def test_republishing_nothing_says_so_rather_than_failing(db: Session, client: TestClient) -> None:
    """`republish` on an instance with no stranded verdict is a no-op, and the page has to say
    that: a button that appears to do nothing is a button somebody presses again."""
    project = _project(db)
    _item(db, project)
    db.commit()
    _signed_in(db, client)

    shown = client.post(
        "/page/me/instance", data={"action": "republish", "csrf": _csrf(client, db)}
    )

    assert shown.status_code == 200
    assert "waiting to be published" in shown.text


# --- the instance's three ------------------------------------------------------------------------


def test_a_live_lease_is_refused_from_the_page(db: Session, client: TestClient) -> None:
    """**The product was right and my first test was not.** `release_lease` refuses a lease that is
    still being renewed, because releasing one would let a second dispatcher claim alongside the
    first — which is the thing the lease exists to prevent. A recovery path that can cause the
    failure it recovers from is worse than the wait.

    So what the page must carry is the refusal, in the command's own words."""
    from hullwork import lease

    lease.acquire(db, lease.new_holder())
    db.commit()
    _signed_in(db, client)

    shown = client.post(
        "/page/me/instance", data={"action": "lease-release", "csrf": _csrf(client, db)}
    )

    assert shown.status_code == 200
    assert "working right now" in shown.text
    db.expire_all()
    assert lease.acquire(db, lease.new_holder()) is False, "it released a live lease"


def test_a_stale_lease_can_be_released_from_the_page(db: Session, client: TestClient) -> None:
    """The case this control exists for: a dispatcher that died holding it. Without this the next
    one waits an hour for an expiry nobody is going to renew."""
    from hullwork import lease
    from hullwork.models import DispatcherLease

    lease.acquire(db, lease.new_holder())
    held = db.query(DispatcherLease).one()
    held.renewed_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=lease.ALIVE_SECONDS + 60)
    db.commit()
    _signed_in(db, client)

    seen = client.get("/page/me/instance").text
    assert "lease" in seen.lower(), "the instance report does not say who holds it"

    shown = client.post(
        "/page/me/instance", data={"action": "lease-release", "csrf": _csrf(client, db)}
    )

    assert shown.status_code == 200
    db.expire_all()
    assert lease.acquire(db, lease.new_holder()) is True, "the lease was not freed"


def test_prune_says_what_it_would_drop_before_dropping_it(
    db: Session, client: TestClient
) -> None:
    """**The only destructive control on the page.** A preview that costs one click is the whole
    difference between an operator clearing 4 old bodies and clearing 4,000."""
    project = _project(db)
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=90)
    db.add(
        Delivery(project_id=project.id, received_at=old, payload_hash="h", payload_json='{"x":1}')
    )
    db.commit()
    _signed_in(db, client)

    preview = client.post(
        "/page/me/instance",
        data={"action": "prune-preview", "older_than_days": "30", "csrf": _csrf(client, db)},
    )

    assert preview.status_code == 200
    assert "1" in preview.text
    db.expire_all()
    assert _bodies(db) == 1, "it pruned on the preview"


def test_prune_drops_only_after_the_second_submission(db: Session, client: TestClient) -> None:
    project = _project(db)
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=90)
    db.add(
        Delivery(project_id=project.id, received_at=old, payload_hash="h", payload_json='{"x":1}')
    )
    db.commit()
    _signed_in(db, client)

    client.post(
        "/page/me/instance",
        data={"action": "prune", "older_than_days": "30", "csrf": _csrf(client, db)},
    )

    db.expire_all()
    assert _bodies(db) == 0


def test_a_blank_retention_window_is_refused_rather_than_read_as_zero(
    db: Session, client: TestClient
) -> None:
    """**The one mistake this control must not make quietly.** An empty field parsed as `0` means
    *older than zero days*, which is everything — on the only destructive action here. The guard
    was in the code and nothing exercised it, which a mutation round found by deleting it and
    watching every test stay green."""
    project = _project(db)
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=90)
    db.add(
        Delivery(project_id=project.id, received_at=old, payload_hash="h", payload_json='{"x":1}')
    )
    db.commit()
    _signed_in(db, client)

    for bad in ("", "0", "-1", "todos"):
        shown = client.post(
            "/page/me/instance",
            data={"action": "prune", "older_than_days": bad, "csrf": _csrf(client, db)},
        )

        assert shown.status_code == 200, bad
        db.expire_all()
        assert _bodies(db) == 1, f"{bad!r} cleared something"


def test_a_reader_is_not_shown_the_upkeep_at_all(db: Session, client: TestClient) -> None:
    """DR-0021 again, and this time on what is *rendered* rather than on what a `POST` answers. A
    control that is drawn and then refuses is worse than one that is not drawn: it offers."""
    _project(db)
    minted = generate_token()
    page.issue(db, hash_token(minted))
    db.commit()

    seen = client.get(f"/page/{minted}/instance").text

    assert "Release the lease" not in seen
    assert "Forget them" not in seen
    assert "older_than_days" not in seen


# --- the project's one ---------------------------------------------------------------------------


def test_sweep_counts_before_it_writes_and_confirms_that_count(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**DR-0011's gate, on a page.** The webhook fires when an issue is created and never again, so
    a bug already failing when Hullwork was installed never arrives that way; sweeping is how it
    does. And a project with three hundred open issues becomes three hundred forge issues in one
    pass, which is a tool uninstalled the same evening — so the first submission writes nothing and
    the number it shows is the number the second one files.

    Asserted by counting calls rather than by reading the sentence: a preview computed from a
    different query than the write is a preview that can disagree with what it previews.
    """
    from hullwork import main as main_module

    project = _project(db)
    project.tracker_project = "shop-in-the-tracker"
    db.commit()
    _signed_in(db, client)

    calls: list[bool] = []

    def _fake(
        session_: Session,
        inventory: object = None,
        limit: int | None = None,
        *,
        slug: str | None = None,
        first_pass: bool = False,
        dry_run: bool = False,
    ) -> list[object]:
        from hullwork.ingest import InventoryResult

        calls.append(dry_run)
        return [
            InventoryResult(
                project=slug or "shop", created=3, deduplicated=1, swept_until=None
            )
        ]

    monkeypatch.setattr(main_module, "make_inventory", lambda settings: object())
    monkeypatch.setattr(main_module, "sweep_inventory", _fake)

    preview = client.post(
        "/page/me/projects/shop/settings", data={"action": "sweep", "csrf": _csrf(client, db)}
    )

    assert preview.status_code == 200
    assert calls == [True], "the preview was not a dry run"
    assert "3" in preview.text and "Nothing was written" in preview.text

    filed = client.post(
        "/page/me/projects/shop/settings",
        data={"action": "sweep-confirm", "csrf": _csrf(client, db)},
    )

    assert filed.status_code == 200
    assert calls == [True, False], "confirming did not write"
    assert "filed 3" in filed.text


def test_a_reader_is_not_offered_the_sweep(db: Session, client: TestClient) -> None:
    """The same line as the upkeep block, on the control that files issues in somebody's forge. It
    is drawn for a session and for nobody else."""
    project = _project(db)
    project.tracker_project = "shop-in-the-tracker"
    minted = generate_token()
    page.issue(db, hash_token(minted))
    db.commit()

    seen = client.get(f"/page/{minted}/projects").text

    assert "What the tracker still has" not in seen
    assert "File them" not in seen


def test_sweeping_without_a_tracker_refuses_and_says_what_is_missing(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The refusal names the three variables**, because the organisation cannot be discovered: the
    least-privilege token is refused the route that would list it, so an instance missing it cannot
    be told what to do by anything except this sentence."""
    from hullwork import main as main_module

    project = _project(db)
    project.tracker_project = "shop-in-the-tracker"
    db.commit()
    _signed_in(db, client)
    monkeypatch.setattr(main_module, "make_inventory", lambda settings: None)

    shown = client.post(
        "/page/me/projects/shop/settings", data={"action": "sweep", "csrf": _csrf(client, db)}
    )

    assert shown.status_code == 200
    assert "HULLWORK_TRACKER_ORG" in shown.text


def test_the_stylesheet_carries_no_control_characters() -> None:
    """**Found by opening the page and seeing a stray `2`.** `_STYLE` is an ordinary triple-quoted
    string, so the CSS escape `\\2212` was read by Python first as the octal escape `\\221` — the
    served stylesheet carried a raw U+0091 and a literal digit, beside every open fold, in every
    release so far.

    A control character in served bytes is never intentional, which makes this cheap to assert and
    impossible to trip over deliberately."""
    stray = [
        (index, char)
        for index, char in enumerate(page._STYLE)
        if (ord(char) < 32 and char not in "\n\t")
        or 0x7F <= ord(char) <= 0x9F
    ]

    assert stray == [], f"control characters in the stylesheet: {stray[:3]}"


def test_a_projects_own_view_knows_who_is_asking(db: Session, client: TestClient) -> None:
    """**Found by opening it in Chrome** (item 223). `page.project` took no `acting`, so a signed-in
    operator got the reader's three-noun rail, a *Sign in* block and the footer that says
    *read-only, this URL is the credential* — while every other view on the same session showed
    five nouns and the operator's footer.

    Asserted on the furniture rather than on one button, because the defect was the whole view being
    rendered for the wrong person."""
    _project(db)
    db.commit()
    _signed_in(db, client)

    shown = client.get("/page/me/projects/shop").text

    # **`../doctor` from here, not `doctor`** (item 227): this view sits one level down and says
    # so. An assertion on the literal string was asserting the depth as well as the noun, which is
    # how it broke on a fix that had nothing to do with it.
    assert re.search(r'href="[^"]*settings"', shown), "the rail is a reader's"
    assert "<summary>Sign in</summary>" not in shown
    assert "This URL is the credential" not in shown, "the footer is a reader's"


def test_a_proposed_manifest_keeps_its_line_breaks(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Forty-one lines of YAML in a `<p>` arrive as one run-on blob, and copying it is the whole
    point of the command. Seen in Chrome, not by any test."""
    from hullwork import cli as cli_module

    class _Forge:
        def close(self) -> None:
            pass

    _project(db)
    db.commit()
    monkeypatch.setattr(cli_module, "_forge_for", lambda settings, kind: _Forge())
    monkeypatch.setattr(cli_module, "propose_from_ci", lambda forge, repo: "a: 1\nb: 2\nc: 3")
    _signed_in(db, client)

    shown = client.post(
        "/page/me/projects/shop/settings", data={"action": "propose", "csrf": _csrf(client, db)}
    ).text

    block = re.search(r"<pre[^>]*>(.*?)</pre>", shown, re.S)
    assert block is not None, "the proposal is not in a block"
    assert block.group(1).count("\n") >= 2, "its line breaks were collapsed"


def test_the_read_link_can_be_rotated_from_the_page(db: Session, client: TestClient) -> None:
    """DR-0025, accepted: **rotating revokes, and revoking is strictly less than what this session
    already does.** Somebody holding it can stop watching a project; minting a new read URL takes a
    credential away. That asymmetry is the whole decision."""
    from hullwork.models import PageAccess

    _signed_in(db, client)
    before = db.get(PageAccess, 1)
    was = before.token_hash if before else None

    shown = client.post(
        "/page/me/instance", data={"action": "page-token", "csrf": _csrf(client, db)}
    )

    assert shown.status_code == 200
    assert "shown once" in shown.text
    assert "stopped working" in shown.text, "it does not say the old URL is dead"
    db.rollback()
    now = db.get(PageAccess, 1)
    assert now is not None and now.token_hash != was, "no new token was issued"


def test_it_says_the_current_link_dies_before_the_button(db: Session, client: TestClient) -> None:
    """**Before, not after.** The hazard of this control is that the URL a colleague is using stops
    the moment it succeeds, and a warning printed afterwards is a warning nobody could act on."""
    _signed_in(db, client)

    shown = client.get("/page/me/instance").text
    warning = shown.find("stops the URL anybody is using now")
    button = shown.find('value="page-token"')

    assert warning != -1, "the page does not say what rotating costs"
    assert warning < button, "the warning is after the button"


def test_a_read_link_cannot_rotate_itself(db: Session, client: TestClient) -> None:
    """It is the operator's control. A read link that could re-key the instance would be a shared
    key that can lock out the person who issued it."""
    minted = generate_token()
    page.issue(db, hash_token(minted))
    db.commit()

    refused = client.post(f"/page/{minted}/instance", data={"action": "page-token"})

    assert refused.status_code == 404


# --- what none of them may do --------------------------------------------------------------------


@pytest.mark.parametrize("where", ["instance", "items/1"])
def test_a_read_link_can_do_none_of_it(db: Session, client: TestClient, where: str) -> None:
    """DR-0021, restated where the routes are added. The URL reads; the password acts."""
    project = _project(db)
    _item(db, project)
    minted = generate_token()
    page.issue(db, hash_token(minted))
    db.commit()

    assert client.post(f"/page/{minted}/{where}", data={"action": "requeue"}).status_code == 404


def _bodies(db: Session) -> int:
    """Deliveries that still carry their verbatim body. `prune` clears the body and keeps the row —
    every fingerprint, counter and issue reference survives, which is the whole design of it."""
    return db.query(Delivery).filter(Delivery.payload_json.notin_(("", "{}"))).count()


def _csrf(client: TestClient, db: Session) -> str:
    """The token the session expects, read the way a browser reads it: off the rendered page."""
    found = re.search(r'name="csrf" value="([^"]+)"', client.get("/page/me/instance").text)
    assert found is not None, "no CSRF field on the instance report"
    return found.group(1)
