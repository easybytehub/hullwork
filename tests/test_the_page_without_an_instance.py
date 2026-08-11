"""The page a trial writes beside its artefact. Item 202.

`hullwork try` is the way to see a red-green cycle with no forge account and no instance, and it
produced one markdown file and a closing line pointing at `hullwork page-token` — a command that
needs a database, two containers and a minted token, to see a surface about a run that already
happened on the reader's own laptop.

It is small because `try` already builds the session the page renders from: `ephemeral_session` is
an in-memory database recording exactly what production records. Nothing needs collecting.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import re
from pathlib import Path

from hullwork import page as page_module
from hullwork import trial
from hullwork.config import Settings
from hullwork.models import Attempt, AttemptOutcome, AttemptPhase, Item, ItemState, Lane, Project

#: Anything that would make a browser leave the file it was opened from.
_REACHES_OUT = re.compile(r'(?:src|href)="(?!\./|#|data:)[^"]*"')


def _a_trial(session: object) -> Item:
    project = Project(
        slug="p", forge="forgejo", repo="o/r", active=True,
        webhook_secret_hash="x",  # noqa: S106
        manifest={},
    )
    session.add(project)  # type: ignore[attr-defined]
    session.flush()  # type: ignore[attr-defined]
    item = Item(
        project_id=project.id, fingerprint="fp", title="ValueError: boom",
        lane=Lane.GREEN, state=ItemState.PR_OPEN, occurrences=1,
    )
    session.add(item)  # type: ignore[attr-defined]
    session.flush()  # type: ignore[attr-defined]
    session.add(  # type: ignore[attr-defined]
        Attempt(
            item_id=item.id, phase_reached=AttemptPhase.PUBLISH,
            outcome=AttemptOutcome.PR_OPEN, consumed=True, rehearsal=True,
        )
    )
    session.commit()  # type: ignore[attr-defined]
    return item


# --- the page exists, without anything behind it --------------------------------------------------


def test_a_trial_can_render_the_page_it_produced() -> None:
    """The whole item: the evidence a reviewer reads, from a run that needed no instance."""
    session = trial.ephemeral_session()
    item = _a_trial(session)

    html = trial.page_for(session, Settings(), item.id)

    assert html
    assert "ValueError: boom" in html


def test_it_is_the_page_an_instance_serves_and_not_a_second_one() -> None:
    """**Asserted by construction.** A second renderer drifts — items 193, 194 and 200 each cost a
    day to exactly that — so this has to be the same function, differing only in what it strips."""
    session = trial.ephemeral_session()
    item = _a_trial(session)

    served = page_module.item(session, Settings(), item.id)
    written = trial.page_for(session, Settings(), item.id)

    assert served is not None and written is not None
    assert "ValueError: boom" in served and "ValueError: boom" in written


def test_nothing_in_it_reaches_a_host(tmp_path: Path) -> None:
    """It is opened from a filesystem, offline, possibly on a machine that never had an instance.
    A stylesheet or a font from somewhere else would make the page depend on the thing this whole
    command exists to do without."""
    session = trial.ephemeral_session()
    item = _a_trial(session)

    html = trial.page_for(session, Settings(), item.id) or ""

    assert not _REACHES_OUT.findall(html), _REACHES_OUT.findall(html)[:3]


def test_no_link_leads_somewhere_that_does_not_exist() -> None:
    """A page full of dead links is worse than no page. A trial has one item and one attempt, so
    there is nothing to navigate to — and the navigation that assumes an instance is removed rather
    than left to disappoint."""
    session = trial.ephemeral_session()
    item = _a_trial(session)

    html = trial.page_for(session, Settings(), item.id) or ""

    for href in re.findall(r'href="([^"]*)"', html):
        assert href.startswith(("#", "data:")), f"a link that goes nowhere from a file: {href}"


def test_nothing_offers_to_act_on_an_instance_that_is_not_there() -> None:
    """Worse than a dead link: a control that looks like it decides something. `Acting` already has
    the branch — `READING` is what an instance with no operator key renders, and it predates the
    ability to act at all."""
    session = trial.ephemeral_session()
    item = _a_trial(session)

    html = (trial.page_for(session, Settings(), item.id) or "").lower()

    assert "<form" not in html
    assert "<button" not in html


def test_it_is_written_beside_the_artefact(tmp_path: Path) -> None:
    """Beside, so somebody who opens the directory finds it without being told. The artefact is per
    attempt; the page is the same evidence a reviewer would be shown."""
    session = trial.ephemeral_session()
    item = _a_trial(session)

    written = trial.write_page(session, Settings(), item.id, tmp_path)

    assert written is not None
    assert written.parent == tmp_path
    assert written.suffix == ".html"
    assert written.read_text(encoding="utf-8").startswith("<!")


def test_it_writes_nothing_else_and_no_database(tmp_path: Path) -> None:
    """`try`'s whole claim, and this must not be what breaks it."""
    session = trial.ephemeral_session()
    item = _a_trial(session)

    trial.write_page(session, Settings(), item.id, tmp_path)

    written = sorted(p.name for p in tmp_path.rglob("*"))
    assert not [name for name in written if name.endswith(".db")]
    assert len(written) == 1
