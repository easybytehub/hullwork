"""A project is the map, and its features are what is on it. Items 235 and 237, DR-0027.

Third time the operator said the page was difficult, and the first two answers were reductions —
1,932 words to 172, five `curl`-only routes given a button. Both were true and neither was it.

What was wrong was one decision nobody made on purpose: **the page was laid out along the database
tables**, so finding a feature required knowing which table it hung off. *Where are my
dependencies?* had the answer *inside a project, inside a closed fold*, and no page said so.

Item 235 named the features and gave each a page holding **every project's**, and the operator
corrected the axis rather than the naming: *¿no será mejor plantear esto mismo, pero a nivel de
proyecto? Así no mezclamos cosas.* He is right — a page called *Dependencies* listing two projects'
advisories one after another is a wall at two and unusable at ten. Nobody works by feature across
clients; they work on a client.

So this file holds the properties that make a project a map: every one of its features is a word in
its rail, every one of those words leads somewhere that exists, none of them is behind a disclosure,
and **nothing inside a project is ever about another project**.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import page
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import (
    Attempt,
    AttemptOutcome,
    AttemptPhase,
    Base,
    Delivery,
    DependencyReport,
    Item,
    ItemState,
    Lane,
    Project,
)

SIGNED_IN = page.Acting(csrf="c", offered=True)
READING = page.Acting(csrf=None, offered=False)

#: Every feature, the page it lives on, and what that page must render. **The whole item in one
#: table**: a feature missing from the rail is one a reader cannot find, and a rail entry whose page
#: renders nothing is a name that leads nowhere — worse than the fold it replaced, because it closes
#: the question without answering it.
#: The fourth column is **the feature itself**, and it is what makes this table more than a list of
#: headings: a page could keep its `<h1>` in the open and fold everything under it, which is exactly
#: the state this item exists to leave. So each row names a string that has to survive deleting
#: every `<details>` block on the page.
FEATURES: tuple[tuple[str, str, str, str], ...] = (
    ("Overview", "", "Overview</span></h1>", "Where everything is"),
    ("Errors", "errors", "Errors</span></h1>", "KeyError"),
    ("Fixes", "fixes", "Fixes</span></h1>", "green-gate"),
    ("Dependencies", "dependencies", "Dependencies</span></h1>", "cryptography"),
    ("Deliveries", "deliveries", "Deliveries</span></h1>", "understood"),
    ("Settings", "settings", "Settings</span></h1>", 'value="refresh"'),
)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    """An instance with something in every feature, because a page that is empty everywhere renders
    the same eight sentences whatever it is asked for."""
    url = f"sqlite:///{tmp_path}/map.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    project = Project(
        slug="shop", forge="forgejo", repo="acme/shop",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
    )
    session.add(project)
    session.flush()
    bug = Item(
        project_id=project.id, fingerprint="f", title="KeyError: 'total'",
        state=ItemState.WAITING_APPROVAL, lane=Lane.AMBER, last_seen=dt.datetime.now(dt.UTC),
    )
    session.add(bug)
    session.flush()
    session.add(
        Attempt(
            item_id=bug.id, phase_reached=AttemptPhase.GREEN_GATE,
            outcome=AttemptOutcome.PR_OPEN, consumed=True,
        )
    )
    session.add(
        Delivery(
            project_id=project.id, provider_delivery_id="d1", payload_hash="h",
            payload_json="{}", received_at=dt.datetime.now(dt.UTC),
            processed_at=dt.datetime.now(dt.UTC), attempts=1,
        )
    )
    session.merge(
        DependencyReport(
            project_id=project.id, taken_at=dt.datetime.now(dt.UTC), asked=True, pinned=50,
            findings=[
                {
                    "package": "cryptography", "version": "48.0.1", "source": "requirements.txt",
                    "advisories": [{"id": "GHSA-x", "summary": "s", "fixed": ["49.0.0"]}],
                }
            ],
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


def _render(db: Session, where: str, acting: page.Acting) -> str:
    settings = Settings()
    if where == "":
        return page.project(db, settings, "shop", acting=acting) or ""
    view = {
        "errors": page.errors,
        "fixes": page.fixes,
        "dependencies": page.dependencies,
        "deliveries": page.deliveries,
        "settings": page.settings_for,
    }[where]
    return view(db, settings, "shop", acting=acting) or ""


def _rail_of(shown: str) -> str:
    found = re.search(r'<nav class="rail"[^>]*>(.*?)</nav>', shown, re.S)
    assert found is not None, "the page has no rail at all"
    return found.group(1)


# --- the rail is the map ----------------------------------------------------------------------


def test_every_feature_is_a_word_in_the_rail(db: Session) -> None:
    """**The whole item.** *Items · Projects · This instance · Why it will not work · What it
    received* contained no word a reader looking for their dependencies could have clicked."""
    rail = _rail_of(_render(db, "", SIGNED_IN))

    for name, _, _, _ in FEATURES:
        assert f">{name}<" in rail, f"{name} is not in the navigation"


@pytest.mark.parametrize(("name", "where", "renders", "_open"), FEATURES)
def test_every_name_in_the_rail_reaches_a_page_that_exists(
    db: Session, name: str, where: str, renders: str, _open: str
) -> None:
    """A name leading nowhere is worse than the fold it replaced: it closes the question without
    answering it. The link's `href` is checked against the view it claims to reach."""
    rail = _rail_of(_render(db, "", SIGNED_IN))
    # From `projects/<slug>` the rail is written `../projects/<slug>/<feature>`, which is the
    # arithmetic item 227 got wrong by one and 404'd every link on the page.
    wanted = f'href="../projects/shop{"/" + where if where else ""}"'

    assert wanted in rail, f"{name} points somewhere else"
    assert renders in _render(db, where, SIGNED_IN)


def test_a_reader_is_shown_no_control_they_cannot_use(db: Session) -> None:
    """DR-0021: a read link gets the instance and nothing that administers it. The rail changed
    shape twice in two items and the operator-only rule has to survive both."""
    rail = _rail_of(_render(db, "", READING))

    assert "Settings" not in rail, "a reader is offered the controls"
    assert ">Dependencies<" in rail, "a reading is still allowed to see what is published"


# --- and no feature is behind a disclosure ------------------------------------------------------


@pytest.mark.parametrize(("_name", "where", "_renders", "in_the_open"), FEATURES)
def test_a_features_page_opens_with_the_feature_on_it(
    db: Session, _name: str, where: str, _renders: str, in_the_open: str
) -> None:
    """**The failure this item is named after.** Four of these were `<details>` on a project's view,
    so the answer to *what is published against what I pin* was one click and one guess away.

    `<details>` keeps what item 167 built it for — a stack trace, a payload, a table of pinned
    versions — and stops being where a feature lives.

    **Measured by deleting every fold on the page** and looking for the feature in what is left.
    Asserting that the `<h1>` is unfolded would pass over a page whose headline stands alone above
    everything it is the headline of, which is the shape being replaced.
    """
    body = _render(db, where, SIGNED_IN).split('<main class="sheet">')[1]
    unfolded = re.sub(r"<details[^>]*>.*?</details>", "", body, flags=re.S)

    assert in_the_open in unfolded, f"{where} holds its own feature behind a disclosure"


def test_the_counts_say_whether_there_is_anything_in_there(db: Session) -> None:
    """A number in the navigation is what makes it a map rather than a list of words: it answers
    *is there anything in there* before the click."""
    rail = _rail_of(_render(db, "", SIGNED_IN))

    assert '<span class="count">1</span>' in rail


def test_a_count_of_zero_is_not_rendered(db: Session, tmp_path: Path) -> None:
    """Item 073's rule one turn further: a badge reading `0` on every row on every page is furniture
    pretending to be information."""
    empty = make_engine(f"sqlite:///{tmp_path}/empty.db")
    Base.metadata.create_all(empty)
    with sessionmaker(bind=empty)() as blank:
        blank.add(
            Project(
                slug="shop", forge="forgejo", repo="acme/shop",
                webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
            )
        )
        blank.commit()
        rail = _rail_of(_render(blank, "", SIGNED_IN))

    assert 'class="count"' not in rail


# --- and the headings are labels ----------------------------------------------------------------


def test_a_heading_is_a_label_and_its_sentence_is_under_it(db: Session) -> None:
    """*What is published against what it pins* is accurate and unscannable, and an eye moving down
    a page cannot use it. The sentence is not deleted — it moves one line down and into grey."""
    shown = _render(db, "dependencies", SIGNED_IN)

    assert "Dependencies</span></h1>" in shown
    assert '<p class="says">' in shown
    assert "What OSV publishes against the versions this project pins" in shown


def test_no_heading_on_any_feature_page_is_a_sentence(db: Session) -> None:
    """**Measured rather than promised.** Nine of them were sentences; the guard is a word count,
    because that is what separates a label from prose and it cannot be argued with."""
    for _, where, _, _ in FEATURES:
        body = _render(db, where, SIGNED_IN).split('<main class="sheet">')[1]
        for heading in re.findall(r"<h[12][^>]*>(.*?)</h[12]>", body, re.S):
            words = len(re.sub(r"<[^>]+>", "", heading).split())
            assert words <= 4, f"{where} has a heading that is a sentence: {heading!r}"


def test_a_section_without_its_sentence_is_not_a_section() -> None:
    """`_section` is the shape DR-0027 decided on — label, sentence, thing — and a version that
    silently dropped the middle one would leave a page of bare labels that passes every other test
    in this file: the lede on a feature page is written inline, so nothing else covers this.
    """
    made = page._section("Dependencies", "What OSV publishes against what you pin.", "<p>x</p>")

    assert "<h2>Dependencies</h2>" in made
    assert '<p class="says">What OSV publishes against what you pin.</p>' in made
    assert made.index("<h2>") < made.index('class="says"') < made.index("<p>x</p>")


def test_a_project_says_what_each_of_its_sections_is(db: Session) -> None:
    """The view with the most sections, and the one an operator uses to act. A label with no
    sentence under it is the terse half of the redesign without the half that explains."""
    shown = page.project(db, Settings(), "shop", acting=SIGNED_IN) or ""
    labels = re.findall(r'<section class="feature"><h2>([^<]+)</h2>(<p class="says">)?', shown)

    assert labels, "the project view has no sections at all"
    for label, says in labels:
        if label != "What is wrong":
            assert says, f"{label} is a label with nothing under it"


def test_nothing_inside_a_project_is_about_another_project(db: Session) -> None:
    """**The operator's whole correction.** Item 235 put every project's advisories on one page,
    which is a wall at two projects and unusable at ten. Inside a project, the only slug on screen
    is this one — and the way back out is a link rather than a heading, because a rail that replaces
    itself has to say what it replaced.
    """
    db.add(
        Project(
            slug="other", forge="forgejo", repo="acme/other",
            webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        )
    )
    db.commit()

    for _, where, _, _ in FEATURES:
        shown = _render(db, where, SIGNED_IN)
        assert "other" not in _rail_of(shown), f"{where} lists another project in its rail"
        assert "acme/other" not in shown, f"{where} renders another project"
        assert "All projects" in shown, f"{where} has no way back out"
