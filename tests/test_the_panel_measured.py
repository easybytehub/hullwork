"""The surface itself, asserted on the stylesheet rather than on a screenshot. Item 213.

DR-0023 settled what the page contains. This is
what the audit of the running instance found wrong with how it is drawn, at 1680 px:

- the work used **43%** of the window, `.wrap` being a 62rem measure for a document;
- **twelve** size/weight pairs on one page, eight of the thirteen `font-size` declarations being
  two-decimal one-offs, and one computed size (`11.69px`) an artefact of a nested `em`;
- `--faint` failing WCAG AA in **both** themes — 2.73:1 light, 3.90:1 dark — on the footer, which is
  where the page explains what the URL is and what the session may do.

Every test here reads the stylesheet or a rendered view. A rule that holds on the page somebody
happened to look at is not a rule, which is the lesson of every `**` and backtick found so far.

Every test verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import operator, page
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import Base, Project

#: The surfaces text is ever set on, and the tokens that set it. Both halves are named here rather
#: than discovered, because a token nobody lists is a token nobody checks.
SURFACES = ("canvas", "raise", "sunk")
INKS = ("ink", "muted", "faint", "waiting", "working", "passed", "refused", "human")

#: WCAG 2.2 AA for text under 18.66px bold / 24px regular. Every one of these is body text or a
#: pill's caps, so none of them earns the 3:1 large-text allowance.
AA = 4.5


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/panel.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    session.add(
        Project(
            slug="shop", forge="forgejo", repo="acme/shop",
            webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    from hullwork.main import app

    return TestClient(app)


def _signed_in(db: Session, client: TestClient) -> None:
    operator.set_password(db, "correct horse")
    db.commit()
    client.post("/page/me/login", data={"password": "correct horse"})


# --- colour ---------------------------------------------------------------------------------------


def _relative_luminance(hex_colour: str) -> float:
    raw = hex_colour.lstrip("#")
    channels = [int(raw[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(one: str, other: str) -> float:
    first, second = _relative_luminance(one), _relative_luminance(other)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


def _palette() -> tuple[dict[str, str], dict[str, str]]:
    """Both themes, read out of `light-dark()` in the stylesheet.

    Reading the source rather than a browser is the point: this runs in the suite, on every change,
    and a contrast regression is a thing somebody ships without noticing precisely because it still
    looks fine to the person who chose it.
    """
    light: dict[str, str] = {}
    dark: dict[str, str] = {}
    for name, first, second in re.findall(
        r"--([a-z-]+):\s*light-dark\((#[0-9a-fA-F]{6}),\s*(#[0-9a-fA-F]{6})\)", page._STYLE
    ):
        light[name], dark[name] = first, second
    return light, dark


def test_every_text_colour_meets_aa_on_every_surface_it_is_used_on() -> None:
    """**Measured on the running instance, then made a rule.** `--faint` carried the footer at
    2.73:1 in light and 3.90:1 in dark — the sentence explaining that the URL is a credential and
    what the session can do, set in the least legible thing on the page.

    Both themes, because a palette is two palettes and the second one is the one nobody opens.
    """
    for theme_name, theme in zip(("light", "dark"), _palette(), strict=True):
        missing = [one for one in (*INKS, *SURFACES) if one not in theme]
        assert not missing, f"{theme_name} defines no {missing}: renamed, and so unchecked"

        for ink in INKS:
            for surface in SURFACES:
                found = _contrast(theme[ink], theme[surface])
                assert found >= AA, (
                    f"{theme_name}: --{ink} on --{surface} is {found:.2f}:1, under {AA}:1"
                )


# --- type -----------------------------------------------------------------------------------------


def test_the_stylesheet_declares_no_size_outside_the_scale() -> None:
    """Twelve size/weight pairs on one page came from thirteen declarations, eight of them
    two-decimal one-offs — `.84rem`, `.82rem`, `.97rem`, `.87rem`. Each was reasonable where it was
    written and none of them were reasonable together, which is what a scale is for."""
    declared = re.findall(r"font-size:\s*([^;}]+)", page._STYLE)

    assert declared, "the stylesheet stopped declaring sizes; this test is measuring nothing"
    for size in declared:
        assert size.strip().startswith("var(--t-"), f"{size.strip()} is not on the scale"


def test_no_size_is_an_artefact_of_where_it_sits() -> None:
    """`11.69px` was on the page and nobody chose it: `.6em` inside something already reduced. A
    size in `em` means the same rule renders differently depending on what it is nested in, which
    is the opposite of a scale."""
    for size in re.findall(r"font-size:\s*([^;}]+)", page._STYLE):
        assert "em" not in size.replace("rem", ""), f"{size.strip()} is relative to its parent"


# --- the shell ------------------------------------------------------------------------------------


def test_the_counters_cannot_orphan_their_last_card() -> None:
    """Six tallies in a wrapping row of five left `closed` alone across the full width, and the
    two-word labels broke over two lines so one row's cards were taller than the next. A grid that
    fits its own columns cannot do either."""
    tally = re.search(r"\.board\s*\{[^}]*\}", page._STYLE)

    assert tally is not None, "the counters' container was renamed; this test is measuring nothing"
    assert "grid-template-columns" in tally.group(0)
    assert "auto-fit" in tally.group(0) or "auto-fill" in tally.group(0)


def test_prose_is_held_to_a_measure_and_the_shell_is_not() -> None:
    """**The fix for 43% is not a wider column of prose.** A panel fills the window and holds its
    sentences to a readable measure inside it; widening `.wrap` alone would trade dead margins for
    120-character lines, which is worse than what the audit found."""
    shell = re.search(r"\.wrap\s*\{[^}]*\}", page._STYLE)

    assert shell is not None
    assert "--measure" in page._STYLE, "no measure is defined for prose"
    assert "62rem" not in (shell.group(0)), "the document width is still the shell's width"


def test_prose_inside_a_fold_is_held_to_the_same_measure() -> None:
    """**Found on atlas, on the section item 233 had just added.** `.sheet > p` is a child selector
    and everything a `<details>` holds is one level deeper, so an open fold's prose ran the full
    1500px while the identical sentence above it stopped at 68ch.

    **Written twice.** The first version asserted `.sheet details > p` was in the stylesheet, which
    it was, and which matched nothing on any page: `_fold` wraps its body in a `<div>`, so the
    paragraphs are that div's children and not the `<details>`'s. A test that reads a selector out
    of the stylesheet and stops there is checking that I typed what I meant to type.

    So the wrapper's class is read off `_fold`'s own output and the rule is looked up by it. Rename
    the div and this fails, which is the point.
    """
    inside = r'<details><summary>[^<]*</summary><div class="([^"]+)"'
    wrapper = re.search(inside, page._fold("s", ""))

    assert wrapper is not None, "a fold no longer wraps its body in anything this can measure"
    held = f".{wrapper.group(1)} > p"

    assert held in page._STYLE, f"nothing holds {held} to a measure"


# --- what the views serve -------------------------------------------------------------------------


def test_no_view_serves_a_backtick_or_an_asterisk(db: Session, client: TestClient) -> None:
    """**Found by grepping every view for the character**, not by looking at the one just changed:
    `projects` said *not asked yet — \\`hullwork status\\` records this when it runs*, the same
    defect fixed in `doctor` that morning, in the view that does not go through `_as_code`.

    Both characters, one sweep: they are the same mistake — prose written for a terminal, served
    without being turned into what a browser draws.
    """
    _signed_in(db, client)

    for where in ("", "instance", "projects", "doctor", "config"):
        shown = client.get(f"/page/me/{where}")

        assert shown.status_code == 200, where
        served = re.sub(r"<style.*?</style>", "", shown.text, flags=re.S)
        served = re.sub(r"<code>.*?</code>", "", served, flags=re.S)
        assert "`" not in served, f"a terminal backtick reached {where or 'the front door'}"
        assert "**" not in served, f"markdown emphasis reached {where or 'the front door'}"


def test_every_control_says_what_it_is(db: Session, client: TestClient) -> None:
    """Three inputs, three placeholders, no `<label>`: the moment somebody types, the field stops
    saying what it is — and this is the one control on the page that creates something.

    A placeholder is not a label. It disappears exactly when it is needed, it is the wrong colour
    for text by design, and a screen reader may or may not read it depending on the browser.
    """
    _signed_in(db, client)

    shown = client.get("/page/me/projects").text
    fields = [
        one
        for one in re.findall(r"<(?:input|select|textarea)\b[^>]*>", shown)
        if 'type="hidden"' not in one and 'type="submit"' not in one
    ]

    assert fields, "the form vanished; this test is measuring nothing"
    for field in fields:
        found = re.search(r'\bid="([^"]+)"', field)
        assert found is not None, f"no id to bind a label to: {field}"
        assert f'for="{found.group(1)}"' in shown, f"nothing is labelled for {found.group(1)}"
