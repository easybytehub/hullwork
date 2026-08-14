"""`hullwork features`, per project, on the page. Item 220, item 218 §2.

The command answers for the checkout it is run in. A page serves an instance that may watch somebody
else's repositories entirely, so the answer has to be per project — and the instance holds the
manifest (DR-0012) and its own variable names, and nothing else.

**Unmet means three different things here and only one of them is a defect**, which is the whole
item and what `Need.reads` was added to name:

* a *manifest* requirement the instance can answer, so unmet is a fact about the project;
* a *checkout* requirement nothing on the instance can answer — item 142 forbids a forge request per
  render — so unmet reads *not asked yet*, never as a pass and never as a no;
* an *instance* credential, which on the receiver is often the dispatcher's by design (DR-0005),
  so it is downgraded exactly as `doctor.not_from_here` downgrades it. Reporting the model key
  missing where the half that uses it holds it sends somebody to repair a working machine.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import features as features_module
from hullwork import page
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base, Project
from hullwork.page import Acting

SIGNED_IN = Acting(csrf="c", offered=True)

#: Enough manifest for the two features that only need one. Anything the page cannot answer has to
#: read as *not asked yet*, and a fixture that supplies everything would never exercise that.
A_MANIFEST = {
    "project": "shop",
    "git": {"provider": "forgejo", "repo": "acme/shop"},
    "errors": {"provider": "glitchtip"},
    "runtime": {"base": "python:3.12", "install": "pip install -r requirements.txt"},
    "tests": {"command": "pytest"},
    "autofix": {"agent": "none", "lanes": {"green": ["keyerror"], "red": ["payment"]}},
}


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/can.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    session.add(
        Project(
            slug="shop", forge="forgejo", repo="acme/shop",
            webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
            manifest=A_MANIFEST,
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


def _shown(db: Session, settings: Settings | None = None) -> str:
    """**The project's own view, not the list** (item 225). The block was 85% of the list and was
    rendered once per project there: on a list a reader is not looking *at* a project, they are
    looking *for* one."""
    # **On the project's Settings page since item 237.** What this instance can do *for* a project
    # is the same question as what it can be told to do, and both are that project's, not a
    # feature the reader browses across clients.
    return page.settings_for(db, settings or Settings(), "shop", acting=SIGNED_IN) or ""


def _block(html: str) -> str:
    found = re.search(r"What Hullwork can do for shop.*?</ul>", html, re.S)
    assert found is not None, "the feature block is not on the project's view"
    return found.group(0)


# --- every feature, with its limits -------------------------------------------------------------


def test_the_list_does_not_carry_it(db: Session) -> None:
    """**871 of the list's 1,021 words were this block**, rendered once per project (item 225). On
    a list a reader is not looking *at* a project — they are looking *for* one, and two projects
    made that page 1,932 words."""
    listed = page.projects(db, Settings(), acting=SIGNED_IN)

    assert "What Hullwork can do for" not in listed
    assert "It reads what you pinned" not in listed


def test_it_is_folded_where_it_lives(db: Session) -> None:
    """Reference rather than news: the settings page opens on what you can tell it, and this is one
    click below that. **A fold is for an evaluator's questions** (item 167, DR-0027) and this is
    exactly one: what could this do for me, asked once and not on every visit."""
    shown = _shown(db)

    fold = re.search(r"<details[^>]*>\s*<summary>What Hullwork can do for", shown)

    assert fold is not None, "the block is not folded on the settings page"
    assert " open" not in fold.group(0), "it is open, so it is the first thing read"


def test_every_feature_is_on_the_page(db: Session) -> None:
    """**All five, not the four item 203 counts.** Those are the instance-shaped ones — filing an
    issue, the page, notifications, the recurrence watch. These are the product: what it can do for
    a repository."""
    block = _block(_shown(db))

    for feature in features_module.FEATURES:
        assert feature.name in block, feature.name


def test_the_limits_are_there_for_what_is_available_too(db: Session) -> None:
    """**A limit is true whether or not the feature is available**, which is what makes it a
    description and not an excuse. *What is measured is your suite* is worth more to an evaluator
    than any green tick, and it is written already — this item moves it."""
    block = _block(_shown(db))

    assert "It reads what you pinned" in block
    assert "does not exercise the dependency" in block


# --- the three meanings of unmet ----------------------------------------------------------------


def test_a_checkout_requirement_reads_not_asked_yet(db: Session) -> None:
    """Nothing on the instance reads your tree and a page render does not spend a forge request to
    find out (item 142). So *do you pin your dependencies* has no answer here — and **the answer to
    a question nobody asked is not `no`**, which is the same `None != False` this project has got
    wrong three times."""
    block = _block(_shown(db))

    assert "not asked yet" in block
    assert "hullwork features --checkout ." in block


def test_a_dispatchers_credential_is_not_reported_missing_here(db: Session) -> None:
    """**The false alarm item 208's gate names.** The receiver holds no model key by design; the
    half that uses it does. With a dispatcher alive, saying *missing* would send somebody to repair
    a working machine, so it is downgraded exactly as `doctor.not_from_here` downgrades it — the
    same rule, not a second one."""
    from hullwork import lease

    lease.acquire(db, lease.new_holder())
    db.commit()

    block = _block(_shown(db))

    assert "not from here" in block
    assert "a dispatcher is running" in block


def test_with_no_dispatcher_alive_the_credential_is_reported_missing(db: Session) -> None:
    """**The other half of the same rule, and the reason it is not a blanket exemption.** With no
    dispatcher running, the absence of a model credential is exactly what somebody needs to know —
    `doctor` downgrades nothing in that state either."""
    block = _block(_shown(db))

    assert "not from here" not in block
    assert "a model credential" in block


def test_a_manifest_requirement_the_instance_can_answer_is_answered(db: Session) -> None:
    """The instance holds the manifest (DR-0012), so this one is a fact about the project rather
    than a question nobody asked — and it must not be softened into *not asked yet* along with the
    others."""
    from hullwork.models import Project as Row

    row = db.query(Row).one()
    row.manifest = {
        "project": "shop",
        "git": {"provider": "forgejo", "repo": "acme/shop"},
        "errors": {"provider": "glitchtip"},
    }
    db.commit()

    block = _block(_shown(db))

    assert "hullwork.yml naming an image" in block
    assert "hullwork propose" in block, "it does not say what to do about it"


# --- what it must not become --------------------------------------------------------------------


def test_it_answers_for_the_project_and_not_for_this_checkout(db: Session) -> None:
    """**The reason this is not just a rendering of the command.** `hullwork features` run on this
    instance answers for `hullwork` itself, from the tree the receiver happens to be installed in.
    The page serves an instance that may watch somebody else's repositories entirely."""
    from hullwork.models import Project as Row

    row = db.query(Row).one()
    row.manifest = None
    db.commit()

    block = _block(_shown(db))

    assert "hullwork.yml naming an image" in block, (
        "a project with no manifest reads as satisfied, which is this checkout's answer"
    )
