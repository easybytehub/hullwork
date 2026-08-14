"""The item list where a table stops working. Item 221.

Item 215 left the narrow viewport *written and unverified*, because the browser I had renders at a
fixed layout width and the page correctly refuses both framing and `fetch` from its own context.
This is what a throwaway Chromium said when I stopped accepting that: no view scrolls the body
sideways at 390, 768 or 1440 — and the seven-column item list was unreadable anyway. Titles wrapped
to five lines, the timestamp was cut mid-value, and *issue / pull* sat behind a horizontal scroll
nobody discovers.

**Not breaking the page and being readable are different bars**, and item 215 cleared the first.

The browser tests here are skipped unless `playwright` is installed, because it is not a dependency
of this product and a page that needs a test harness to be looked at is not the thing being tested.
What is asserted without it is the markup those rules act on — the labels, the relative time, and
the target — since a stylesheet that reflows nothing is caught by the browser tests and a stylesheet
acting on labels that are not there is caught by these.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

import pytest
from sqlalchemy.orm import Session, sessionmaker

from hullwork import page
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base, Item, ItemState, Lane, Project
from hullwork.page import Acting


class _Page(Protocol):
    """The four things these tests ask of a browser page, and nothing else.

    A protocol rather than playwright's own types, because it is **not a dependency of this
    product**: a suite that type-checks differently depending on what somebody happens to have
    installed is worse than one that names the surface it uses. `Any` is banned here, and rightly.
    """

    def goto(self, url: str) -> object: ...
    def evaluate(self, expression: str) -> object: ...


def _read(page: _Page, expression: str) -> list[dict[str, object]]:
    """What the browser answered, as the shape every caller here expects.

    The protocol says `object` because a page can return anything; the casts live in one place
    rather than at four call sites, which is the same reason `_rows_for_standing` exists."""
    got = page.evaluate(expression)
    assert isinstance(got, list), f"the browser answered {type(got).__name__}, not a list"
    return got


class _Context(Protocol):
    def new_page(self) -> _Page: ...


class _Browser(Protocol):
    def new_context(self, *, viewport: dict[str, int]) -> _Context: ...
    def close(self) -> None: ...


SIGNED_IN = Acting(csrf="c", offered=True)

#: The width the measurement was taken at, and the one the rules are written for.
NARROW = 390


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/narrow.db"
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
    for n in range(3):
        session.add(
            Item(
                project_id=project.id,
                fingerprint=f"f{n}",
                title=f"KeyError: 'total' in checkout handler {n}",
                state=ItemState.NEW,
                lane=Lane.GREEN,
                last_seen=dt.datetime.now(dt.UTC) - dt.timedelta(hours=n * 9),
            )
        )
    session.commit()
    yield session
    get_settings.cache_clear()


def _front_door(db: Session) -> str:
    return page.items(db, acting=SIGNED_IN, here="./", settings=Settings(), front=True)


# --- the markup the rules act on ------------------------------------------------------------


def test_one_markup_serves_both_shapes(db: Session) -> None:
    """**One markup, two shapes**, which is the property; `data-label` was one way of having it.

    Since DR-0028 the header and the labels are both gone: the grouping's heading names what the
    rows are, and each field is legible without one — an id, a title, a slug and a lane, a time.
    What has to stay true is that the narrow layout is a **stylesheet**, so this asserts there is
    exactly one table markup and that the rules acting on it exist.
    """
    shown = _front_door(db)

    assert '<tr class="subject">' in shown
    assert "<th>" not in shown, "a header row is a second thing to keep in step"
    assert "@media (max-width: 46rem)" in shown, "nothing reflows the row"


def test_the_time_is_relative_and_the_exact_value_survives(db: Session) -> None:
    """`2026-08-11 10:45:13.847329+00:00` in a 90px column, with microseconds. `_ago` has existed
    since item 141 and renders *9h*; the exact value is what somebody needs when comparing against a
    log, and a `title` is where that belongs rather than in the cell."""
    shown = _front_door(db)

    assert "<time datetime=" in shown
    assert re.search(r"<time[^>]*>\s*(just now|\d+\s*[hdm])", shown), "no relative time in the list"
    # **Attributes are where the exact value belongs**, so they are stripped before looking for it
    # as text. The first version of this searched the whole document and failed on its own fix.
    text = re.sub(r"<[a-z]+[^>]*>", lambda m: re.sub(r'\s\w+="[^"]*"', "", m.group(0)), shown)
    assert "+00:00" not in text, "a raw datetime is still being printed as the cell's text"


def test_a_rows_link_is_a_real_target(db: Session) -> None:
    """17x17 measured. WCAG 2.2 AA 2.5.8 asks 24x24, and its *Inline* exception covers a link inside
    a sentence — the only way to open an item is not that."""
    rule = re.search(r"\.list td a\s*\{[^}]*\}", page._STYLE)

    assert rule is not None, "the row link rule was renamed; this test is measuring nothing"
    assert "24px" in rule.group(0)


# --- and what a browser says ----------------------------------------------------------------


@pytest.fixture
def chromium() -> Iterator[_Browser]:
    playwright = pytest.importorskip(
        "playwright.sync_api", reason="playwright is not a dependency of this product"
    )
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch()
        yield browser
        browser.close()


def _at(browser: _Browser, html: str, width: int, tmp_path: Path) -> _Page:
    """`Any` on purpose: playwright is not a dependency of this product, so on a machine without it
    every annotation naming its types is a name mypy cannot resolve — and a suite that type-checks
    differently depending on what somebody happens to have installed is worse than an untyped
    helper. The derived tree installs `.[dev]`, which does not include it."""
    where = tmp_path / "view.html"
    where.write_text(html, encoding="utf-8")
    context = browser.new_context(viewport={"width": width, "height": 900})
    shown = context.new_page()
    shown.goto(where.as_uri())
    return shown


def test_the_body_never_scrolls_sideways(db: Session, chromium: _Browser, tmp_path: Path) -> None:
    """**The bar item 215 cleared**, kept: at 390 the widest view in the product must not move the
    page under the reader's finger."""
    shown = _at(chromium, _front_door(db), NARROW, tmp_path)

    width = shown.evaluate("() => document.documentElement.scrollWidth")

    assert isinstance(width, int) and width <= NARROW


def test_no_field_needs_a_sideways_scroll_to_read(
    db: Session, chromium: _Browser, tmp_path: Path
) -> None:
    """**The bar it did not.** Every cell has to be inside the viewport at 390 — a table that must
    be scrolled sideways to read one row has not been made responsive, only made harmless."""
    shown = _at(chromium, _front_door(db), NARROW, tmp_path)

    outside = _read(
        shown,
        "() => [...document.querySelectorAll('.list td')]"
        "        .filter(e => e.getBoundingClientRect().right > innerWidth + 1)"
        "        .map(e => e.dataset.label)",
    )

    assert outside == [], f"off the right edge at {NARROW}px: {outside}"


def test_the_row_is_stacked_and_not_merely_squeezed(
    db: Session, chromium: _Browser, tmp_path: Path
) -> None:
    """**Written because a mutation escaped.** Deleting the reflow entirely left every test green:
    a seven-column table *fits* in 390px by squeezing its columns, so nothing overflows and nothing
    is off the right edge — and the title has 60px to wrap in, which is the unreadable original.

    So the property is not *does it fit*. It is *did it stop being a table*: in one item's row no
    two fields share a line, which is what makes each one readable at full width."""
    shown = _at(chromium, _front_door(db), NARROW, tmp_path)

    tops = _read(
        shown,
        "() => { const row = document.querySelector('tr.subject');"
        "  return [...row.querySelectorAll('td')].filter(td => td.textContent.trim())"
        "     .map(td => Math.round(td.getBoundingClientRect().top)); }",
    )

    assert tops, "no rows were painted"
    # The subject is on its own line; the context that describes it may share the one below.
    assert len(set(tops)) >= 2, f"the row is still one line at {NARROW}px: {tops}"


def test_the_title_leads_each_item(db: Session, chromium: _Browser, tmp_path: Path) -> None:
    """It is what identifies the item; the id is not. Asserted on painted position rather than on
    document order, because that is what `order` changes and what a reader sees."""
    shown = _at(chromium, _front_door(db), NARROW, tmp_path)

    tops = _read(
        shown,
        "() => { const row = document.querySelector('tr.subject');"
        "  return [...row.querySelectorAll('td')].filter(td => td.textContent.trim()).map(td =>"
        "     ({label: td.className, top: Math.round(td.getBoundingClientRect().top)})); }",
    )

    assert tops, "no rows were painted"
    first = min(tops, key=lambda cell: int(str(cell["top"])))
    # The cell that carries the subject: the id and the title together, since DR-0028 made the row
    # about one thing rather than about seven fields.
    assert first["label"] == "who"
