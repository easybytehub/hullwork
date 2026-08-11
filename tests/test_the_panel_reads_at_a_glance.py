"""The shape of the operational panel. Items 203 and 208, designed rather than assembled.

Both were shipped reusing `.decisions` — the list built for *things waiting for you*, which carries
a **fixed amber left border**. So a `cannot` row sat inside an amber stripe and the severity read as
the panel's rather than the row's, which is the one thing a status panel exists to get right.

These assert form, not prose: a state has to be legible as a shape before it is read as a word.
"""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from hullwork import features, page
from hullwork.config import Settings
from hullwork.doctor import Finding, State
from hullwork.page import Acting

#: Signed in, because two of the five nouns are the operator's (DR-0021).
AN_OPERATOR = Acting(csrf="c", offered=True)


def test_the_panel_does_not_borrow_the_waiting_list(session: Session) -> None:
    """**The defect this file exists for.** `.decisions` means *waiting for you* and paints itself
    amber to say so; a panel of feature states is a different thing and needed its own."""
    said = page._what_this_instance_has_switched_on(session, Settings())

    assert "decisions" not in said
    assert 'class="standing"' in said


def test_each_row_carries_its_own_severity(session: Session) -> None:
    """One stripe per row, not one per panel. A panel-level stripe says every row is the same kind
    of thing, and the whole job here is that they are not."""
    said = page._what_this_instance_has_switched_on(session, Settings())

    assert re.search(r'<li class="c-(refused|idle)"', said), said[:200]


def test_the_state_is_a_shape_before_it_is_a_word(session: Session) -> None:
    """`.pill` is uppercase, letterspaced and sized to align down one edge — the states are meant to
    be scanned in a column, not read in a sentence. A bare `<b>name</b> — state.` is a sentence.

    **Asserted on the markup, not on the character.** The first version forbade an em dash anywhere
    in the panel — and the details are prose that legitimately contains them, so it was banning
    punctuation rather than a shape. What matters is that the pill and the name are adjacent
    elements with nothing between them.
    """
    said = page._what_this_instance_has_switched_on(session, Settings())

    adjacent = re.search(r'</span>\s*<span class="name">', said)
    assert adjacent, "the state and the name are not adjacent"
    assert 'class="pill"' in said


def test_the_detail_is_secondary_and_says_so() -> None:
    """The name is what a reader scans for; the sentence under it is what they read once they have
    stopped. Same markup in both views, so one change cannot fix half of them."""
    found = [Finding("forge", State.BROKEN, "no forge configured")]
    said = page._rows_for_standing(found)

    assert 'class="name"' in said
    assert 'class="why"' in said


def test_both_views_render_the_same_component() -> None:
    """**Asserted by construction.** Two renderers that happened to look alike is how the borrowed
    list ended up in both of them, and how a fix to one would have left the other."""
    import inspect

    features_view = inspect.getsource(page._what_this_instance_has_switched_on)
    doctor_view = inspect.getsource(page.why_it_will_not_work)

    for source in (features_view, doctor_view):
        assert "_rows_for_standing" in source, source.split("(")[0]


def test_a_decision_is_never_painted_as_a_fault(session: Session) -> None:
    """DR-0019 in colour: `off` is something somebody chose, and `--refused` is for what is broken.
    Painting a decision red tells its reader to go and repair a choice they made."""
    del session
    said = page._rows_for_standing(
        [Finding("the daily page", State.EXPECTED, "off until you mint a token")]
    )

    assert "c-refused" not in said


def test_features_and_doctor_agree_about_what_is_worth_showing(session: Session) -> None:
    """Neither panel lists what is fine. Item 203's rule, and the reason the count is a sentence
    rather than fourteen green rows."""
    said = page._what_this_instance_has_switched_on(session, Settings())

    assert features.ON not in re.findall(r'class="pill">([^<]*)', said)


def test_a_terminals_backticks_become_code() -> None:
    """**Seen by opening the page, not by reading the source.** Every detail in both panels comes
    from a string a command prints, where a backtick is punctuation. Rendered into HTML they are
    literal backticks, and one beside a command name reads as a typo in the product.
    """
    said = page._rows_for_standing(
        [Finding("the daily page", State.EXPECTED, "off until you run `hullwork page-token`")]
    )

    assert "<code>hullwork page-token</code>" in said
    assert "`" not in said


def test_the_markup_is_escaped_before_it_is_marked_up() -> None:
    """Order matters and only one order is safe: escape, then mark up. The other way round would
    escape the `<code>` this function had just written, and a detail containing a `<` would decide
    which."""
    said = page._rows_for_standing(
        [Finding("x", State.BROKEN, "a value like <script> and a `command`")]
    )

    assert "&lt;script&gt;" in said
    assert "<code>command</code>" in said


def test_the_detail_has_a_measure() -> None:
    """**The other thing only visible on a wide window**: the rows ran to about 110 characters,
    which is a paragraph pretending to be a row. Read text gets a measure; scanned text does not."""
    assert "max-width: 62ch" in page._STYLE


def test_inline_code_does_not_push_punctuation_away() -> None:
    """**The fourth thing only a screen showed.** `.3em` of horizontal padding left a visible gap
    before a following comma — `page-token ,` — which reads as a typographic error in the product.
    The chip earns its separation from the background instead of from space.
    """
    import re

    css = re.search(r"\.standing code \{([^}]*)\}", page._STYLE)

    assert css is not None
    padding = re.search(r"padding:\s*[\d.]+em\s+([\d.]+)em", css.group(1))
    assert padding is not None and float(padding.group(1)) <= 0.2, css.group(1)


def test_the_operators_two_views_are_reachable(session: Session) -> None:
    """**Seen by opening the instance, not by reading the routes.** Item 208 added `doctor` and
    `config` and linked neither, so both were reachable only by typing a URL — and they are the two
    somebody wants on the morning they come to this page at all.

    Item 212 moved where they are linked from — a prose row under the statistics became the rail —
    so this asserts the property and not the furniture: they are reachable by opening the page. It
    also has to sign in now, because DR-0021 shows these two to the operator and not to a read link,
    and the version of this test that passed with the default `acting` was passing on a row that
    offered a reader two links to a `404`.
    """
    said = page.instance(session, Settings(), error_reporting=False, acting=AN_OPERATOR)

    assert 'href="doctor"' in said
    assert 'href="config"' in said


def test_only_one_thing_is_called_the_configuration(session: Session) -> None:
    """The landing fold showed seven rows of *state* under the word *configured*, which was harmless
    until `/config` existed and genuinely was it. Two things with one name is the drift this
    repository has spent a week removing."""
    said = page.instance(session, Settings(), error_reporting=False)

    assert "How this instance is configured" not in said
