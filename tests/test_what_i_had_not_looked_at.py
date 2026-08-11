"""The half of the audit item 213 did not open. Item 215.

Two things it never looked at — the dark theme and a narrow window — and one finding it recorded
without closing. What came out:

- `items` renders **seven columns** with nothing around them, while the two narrower tables both sit
  inside `overflow-x: auto`. The view a person lands on is the one that can push the body sideways.
- the mark in the header is a **10x17** target, under WCAG 2.2 AA 2.5.8's 24x24. The other small
  targets are links inside sentences, which the *Inline* exception covers; this one is not.

The narrow viewport itself is still unverified: this browser renders at a fixed layout width, and
the page correctly refuses both framing and `fetch` from its own context, which are the two ways of
faking a small viewport from inside it. These tests assert the structure that makes the width matter
less. They do not claim somebody looked.

Every test verified by reintroducing the defect it covers.
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
from hullwork.models import Base, Item, ItemState, Lane, Project
from hullwork.page import Acting

SIGNED_IN = Acting(csrf="c", offered=True)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    """**With data in it.** An empty instance renders no tables at all, so the version of the sweep
    below that ran on one was asserting about nothing — the widest table in the product only exists
    once an item has arrived."""
    url = f"sqlite:///{tmp_path}/looked.db"
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
    session.add(
        Item(
            project_id=project.id,
            fingerprint="f1",
            title="KeyError: 'total' in checkout",
            state=ItemState.NEW,
            lane=Lane.GREEN,
            last_seen=dt.datetime.now(dt.UTC),
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


def _every_view(db: Session) -> dict[str, str]:
    settings = Settings()
    return {
        "items": page.items(db, acting=SIGNED_IN, here="./", settings=settings, front=True),
        "instance": page.instance(db, settings, error_reporting=False, acting=SIGNED_IN),
        "projects": page.projects(db, settings, acting=SIGNED_IN),
        "config": page.what_it_received(settings, acting=SIGNED_IN),
        "doctor": page.why_it_will_not_work(db, settings, acting=SIGNED_IN),
    }


def test_no_table_can_push_the_body_sideways(db: Session) -> None:
    """**The widest one was the only unwrapped one.** `instance`'s configuration fold and `config`'s
    variable list both sit in `.wide`; the seven-column item list, on the front door, did not. A
    page whose body scrolls horizontally is a page where the navigation moves when you read a title.

    Asserted by walking back from each `<table>` to the nearest opening tag before it, which is what
    the browser does, rather than by trusting that a class appears somewhere on the page.
    """
    for name, html in _every_view(db).items():
        body = re.sub(r"<style.*?</style>", "", html, flags=re.S)
        for found in re.finditer(r"<table", body):
            before = body[: found.start()]
            opened = re.findall(r'<(\w+)([^>]*)>', before)
            depth: list[tuple[str, str]] = []
            for tag, attrs in opened:
                if tag in ("br", "input", "img", "meta", "link"):
                    continue
                depth.append((tag, attrs))
            enclosing = " ".join(attrs for _, attrs in depth[-6:])
            assert "wide" in enclosing or "band" in enclosing, (
                f"a table in {name} is not inside a container that scrolls on its own"
            )


def test_every_view_closes_what_it_opens(db: Session) -> None:
    """**Written because a mutation escaped.** Removing the `</div>` that closes the new scroll
    container left every view still passing: the table was inside something, so the sweep above was
    satisfied, and the unclosed element would have swallowed the rest of the page in a browser.

    No parser was in the loop before this. The page is assembled from string concatenation across
    forty functions, which is fine and is also exactly the shape where one missing closing tag ships
    without anybody noticing — the suite reads the strings, and a string is happy to be malformed.
    """
    from html.parser import HTMLParser

    void = {"br", "hr", "img", "input", "meta", "link", "source", "col", "area", "base", "wbr"}

    class Stack(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.open: list[str] = []
            self.wrong: list[str] = []

        def handle_starttag(self, tag: str, attrs: object) -> None:
            if tag not in void:
                self.open.append(tag)

        def handle_endtag(self, tag: str) -> None:
            if tag in void:
                return
            if not self.open or self.open[-1] != tag:
                self.wrong.append(f"</{tag}> closes <{self.open[-1] if self.open else 'nothing'}>")
                if tag in self.open:
                    while self.open and self.open.pop() != tag:
                        pass
                return
            self.open.pop()

    for name, html in _every_view(db).items():
        reader = Stack()
        reader.feed(html)

        assert not reader.wrong, f"{name}: {reader.wrong[0]}"
        assert not reader.open, f"{name} never closes {reader.open}"


def test_the_mark_is_a_real_target() -> None:
    """WCAG 2.2 AA 2.5.8 asks 24x24 CSS px. The mark measured 10x17 on the running instance: a
    standalone control, not a link inside a sentence, so the *Inline* exception does not reach it.

    Asserted on the rule that guarantees the size rather than on a rendered pixel, because the suite
    has no browser — and named here so that is a stated limit rather than a hidden one.
    """
    rule = re.search(r"\.mark\s*\{[^}]*\}", page._STYLE)

    assert rule is not None, "the mark was renamed; this test is measuring nothing"
    assert "min-width" in rule.group(0) and "min-height" in rule.group(0)
    assert "24px" in rule.group(0)


def test_the_primary_action_keeps_its_target_when_open() -> None:
    """It drops to 21 px open, because the open state removes the padding that made it a button —
    and open is the state you are in when you go back to it to close it."""
    opened = re.search(r"details\.primary\[open\] > summary\s*\{[^}]*\}", page._STYLE)

    assert opened is not None
    assert "min-height" in opened.group(0), "the open state has no floor on its target"
