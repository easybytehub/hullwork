"""The two views that carry the evidence. Item 123.

The plan M7 asks for a reviewer who did not write Hullwork to say whether they would merge from
the evidence trail alone. Before this, that reviewer needed ssh, a SQLite file and a CLI. These
tests are about the two properties that make the page worth showing them:

* **it is the artefact, not a description of it** — the same `evidence` function that wrote the
  pull request writes this, so the page cannot come to say something the forge does not;
* **it says what it cannot show** — the agent's prose and its brief are not stored (item 079), and
  a page that rendered the rest without a word would be claiming to be the whole document.

The surface — the token, the `404`, the headers, `_h` — arrives with item 122 and is asserted
there. What is asserted *here* is the part that file deliberately left open: hostile **content**
rendered through views that show an error's title and somebody else's captured output.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import evidence, page, readiness
from hullwork.attempts import finish, record, start
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import Attempt, AttemptOutcome, AttemptPhase, Base, Item, Lane, Project
from hullwork.security import generate_token, hash_token
from hullwork.work import verdict_detail

#: The forge token this instance holds. Distinctive on purpose: a test that redacts `ingest` proves
#: nothing, because `ingest` is a word.
FORGE_TOKEN = "gto_9f3c1d7b5a2e4806bb17c9d0e3f5a7b9"  # noqa: S105

#: Everything a third party writes, in one string. A tracker's title, a stack frame and a
#: permalink are all somebody else's text stored verbatim, and this is the shape that turns a page
#: about evidence into a page that runs their script.
HOSTILE = "<script>alert('pwned')</script>"


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'evidence.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_BASE_URL", "https://hullwork.example")
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", FORGE_TOKEN)
    get_settings.cache_clear()
    yield sessionmaker(bind=engine)()
    get_settings.cache_clear()


@pytest.fixture
def project(db: Session) -> Project:
    row = Project(
        slug="demo", forge="forgejo", repo="acme/demo",
        webhook_secret_hash="x",  # noqa: S106
    )
    db.add(row)
    db.flush()
    return row


def _item(
    db: Session,
    project: Project,
    *,
    title: str = "KeyError: 'total' in checkout",
    issue: str | None = "#9",
    lane: Lane = Lane.GREEN,
    permalink: str | None = "https://tracker.example/issues/41",
) -> Item:
    row = Item(
        project_id=project.id, fingerprint=f"fp-{title}", lane=lane, title=title,
        forge_issue_ref=issue, permalink=permalink,
    )
    db.add(row)
    db.commit()
    return row


#: What the green gate printed. Real shape: pytest's own summary line is the verdict.
GREEN = "........................................ [100%]\n===== 906 passed in 57.71s =====\n"
RED = (
    "F....................................... [100%]\n"
    "FAILED tests/test_checkout.py::test_total_is_present\n"
    "===== 1 failed, 905 passed in 59.02s =====\n"
)


def _attempt(
    db: Session,
    item: Item,
    *,
    outcome: AttemptOutcome = AttemptOutcome.PR_OPEN,
    pull: str | None = "#6",
    green_output: str = GREEN,
) -> Attempt:
    attempt = start(db, item, base_sha="586e4d3", image_tag="hullwork-sandbox:d85c07")
    record(db, attempt, AttemptPhase.BASELINE, "pytest", exit_code=0, output=GREEN,
           duration_ms=61_000)
    record(db, attempt, AttemptPhase.RED_GATE, "pytest", exit_code=1, output=RED,
           duration_ms=59_000)
    record(db, attempt, AttemptPhase.GREEN_GATE, "pytest", exit_code=0, output=green_output,
           duration_ms=60_000)
    attempt.pull_request_ref = pull
    return finish(db, attempt, outcome, seal={"precision": "undisclosed"})


@pytest.fixture
def client(db: Session) -> TestClient:
    from hullwork.main import app

    return TestClient(app)


def _token(db: Session) -> str:
    token = generate_token()
    page.issue(db, hash_token(token))
    return token


# --- the list ----------------------------------------------------------------------------------


def test_the_list_shows_each_item_and_the_most_recent_first(db: Session, project: Project) -> None:
    """**Ordered by what a reader is looking for.** An instance's newest item is the one somebody
    is being shown the page about; insertion order puts it last, below a year of history."""
    from datetime import UTC, datetime

    old = _item(db, project, title="old failure", issue="#1")
    new = _item(db, project, title="new failure", issue="#2")
    old.last_seen = datetime(2026, 1, 1, tzinfo=UTC)
    new.last_seen = datetime(2026, 8, 1, tzinfo=UTC)
    db.commit()

    rendered = page.items(db)

    assert rendered.index("new failure") < rendered.index("old failure")
    for fact in ("demo", "green", "new failure", "2026-08-01"):
        assert fact in rendered, fact


def test_the_list_says_which_attempt_reached_a_pull_request(db: Session, project: Project) -> None:
    """The column a reviewer scans for. An item that reached a pull request shows it; one that only
    reached an issue shows that; one that reached neither says so rather than showing an empty
    cell, which reads as a rendering fault."""
    reached = _item(db, project, title="fixed one", issue="#9")
    _attempt(db, reached, pull="#6")
    filed = _item(db, project, title="filed only", issue="#10")
    _item(db, project, title="never filed", issue=None)

    rendered = page.items(db)

    # Rows carry a class since item 247; the reach of each one is still its last cell.
    row = re.search(r'<tr class="subject">(?:(?!</tr>).)*fixed one.*?</tr>', rendered, re.DOTALL)
    assert row is not None and "#6" in row.group(0)
    filed_row = re.search(
        r'<tr class="subject">(?:(?!</tr>).)*filed only.*?</tr>', rendered, re.DOTALL
    )
    assert filed_row is not None and "#10" in filed_row.group(0)
    assert filed.forge_issue_ref == "#10"
    never = re.search(
        r'<tr class="subject">(?:(?!</tr>).)*never filed.*?</tr>', rendered, re.DOTALL
    )
    # **Nothing rather than a dash**: the column where a reference goes is empty, which is what the
    # other views do with an action nobody can take.
    assert never is not None and '<td class="do"></td>' in never.group(0)


def test_the_bound_is_on_the_page_and_not_only_in_the_query(
    db: Session, project: Project, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Silently showing 200 of 4,000 teaches a reader that this instance has done less than it
    has.** The number shown and the number held are both stated, or the bound is a lie of omission.
    """
    monkeypatch.setattr(page, "MAX_ITEMS", 2)
    for n in range(5):
        _item(db, project, title=f"failure {n}", issue=f"#{n}")

    rendered = page.items(db)

    assert "2 most recently seen of 5 item(s)" in rendered
    # Two rows and no header: the grouping's heading is what names them now (DR-0028).
    assert rendered.count('<tr class="subject">') == 2


def test_an_instance_with_no_items_says_so(db: Session) -> None:
    """The first afternoon of every installation, and the state a page like this renders as an
    empty table with a header — which reads as broken rather than as new."""
    rendered = page.items(db)

    assert "No items yet" in rendered
    assert "<table" not in rendered


# --- the item ------------------------------------------------------------------------------------


def test_the_page_is_the_artefact_and_not_a_second_description_of_it(
    db: Session, project: Project
) -> None:
    """**The property this whole item exists for.** Rendered both ways and compared line by line:
    everything the pull request carried is on the page, produced by the same function.

    A page that assembled its own version would drift from the forge, and the first anybody would
    know is a reviewer and a merge queue reading two different documents about one change.
    """
    item = _item(db, project)
    attempt = _attempt(db, item)
    published = evidence.pull_request_body(
        item, attempt, detail=verdict_detail(attempt),
        secrets=[FORGE_TOKEN],
    )

    rendered = page.item(db, get_settings(), item.id)

    assert rendered is not None
    for line in published.splitlines():
        if line.startswith("<details><summary>") or line == "</details>":
            continue  # became a real fold; asserted by its own test below
        assert page._h(line) in rendered, line


def test_the_verdicts_a_reviewer_decides_on_are_on_the_page(
    db: Session, project: Project
) -> None:
    """Item 116's three facts, reaching a reader through this surface rather than only a forge's.
    Named individually because "the artefact is present" is exactly the assertion that stays green
    while the artefact quietly stops saying the useful part."""
    item = _item(db, project)
    _attempt(db, item)

    rendered = page.item(db, get_settings(), item.id)

    assert rendered is not None
    assert "test_total_is_present" in rendered, "what reproduces it"
    assert "1 failed, 905 passed in 59.02s" in rendered, "the red gate, in its runner's words"
    assert "906 passed in 57.71s" in rendered, "and the green gate's"


def test_it_says_which_parts_of_the_artefact_are_not_stored(
    db: Session, project: Project
) -> None:
    """**The failure here is silence.** Item 079 decided not to store the agent's prose or the
    brief it was given; a page that renders the remainder with no note is presenting a subset as
    the whole, to the one audience that cannot tell."""
    item = _item(db, project)
    _attempt(db, item)

    rendered = page.item(db, get_settings(), item.id)

    assert rendered is not None
    assert "the agent&#x27;s own account of what it did" in rendered
    assert "item 079" in rendered


def test_an_attempt_that_opened_no_pull_request_shows_what_it_did_publish(
    db: Session, project: Project
) -> None:
    """`not-reproducible` and `failed` are first-class outcomes (DR-0003) that publish a comment on
    the issue. Rendering a pull request body for them would show a document that never existed."""
    item = _item(db, project)
    _attempt(db, item, outcome=AttemptOutcome.NOT_REPRODUCIBLE, pull=None)

    rendered = page.item(db, get_settings(), item.id)

    assert rendered is not None
    assert "could not be reproduced" in rendered.lower()
    assert "Opened by Hullwork as a" not in rendered, "a pull request body, on an attempt with none"


def test_captured_output_is_scrubbed_with_the_publishers_own_list(
    db: Session, project: Project
) -> None:
    """**The threat is stronger here than at the forge.** A forge has an access list; this page has
    one token that somebody pasted into a chat. The same scrubber runs, from the same function that
    builds the publisher's list, so the two cannot come to disagree about what a credential is."""
    item = _item(db, project)
    leaky = (
        # **Bare, and that is the point of this line.** In a URL or after `TOKEN=` the shape rules
        # catch it and the by-value list is never exercised — which is how the first version of
        # this test passed with the list removed entirely.
        f"subprocess.CalledProcessError: remote rejected credential {FORGE_TOKEN}\n"
        "HULLWORK_TRACKER_TOKEN=tkn_0d1e2f3a4b5c6d7e8f90\n"
    )
    _attempt(db, item, green_output=leaky)

    rendered = page.item(db, get_settings(), item.id)

    assert rendered is not None
    assert FORGE_TOKEN not in rendered, "held by this process, so redacted by value"
    assert "tkn_0d1e2f3a4b5c6d7e8f90" not in rendered, "never seen before, so caught by shape"
    assert "***" in rendered
    assert "CalledProcessError" in rendered, "the error itself survives, or the page is useless"


def test_the_empty_states_render(db: Session, project: Project) -> None:
    """Where a page like this breaks, and what an operator meets on their first afternoon."""
    no_attempts = _item(db, project, title="waiting", issue=None, lane=Lane.RED, permalink=None)

    rendered = page.item(db, get_settings(), no_attempts.id)

    assert rendered is not None
    assert "No attempts" in rendered
    assert "never filed" in rendered

    bare = _item(db, project, title="stopped early")
    attempt = start(db, bare, base_sha="586e4d3", image_tag=None)
    finish(db, attempt, AttemptOutcome.ABANDONED, seal={})

    stopped = page.item(db, get_settings(), bare.id)

    assert stopped is not None
    assert "No steps were recorded" in stopped


def test_an_item_that_does_not_exist_gets_the_same_404(db: Session, client: TestClient) -> None:
    """Same body, same shape. A distinct answer would let the token's holder — or whoever they
    forwarded it to — count an instance's items by probing."""
    token = _token(db)

    missing = client.get(f"/page/{token}/items/4242")
    unknown = client.get("/nope")

    assert missing.status_code == unknown.status_code == 404
    assert missing.json() == unknown.json()


# --- hostile content, which is all of it ---------------------------------------------------------


def test_a_third_partys_text_renders_escaped_in_these_views(
    db: Session, project: Project
) -> None:
    """**Asserted here rather than assumed from item 122.** That file asserts the escaping
    primitive; these are the first views that render an error's title, a stack frame and a stored
    permalink — every one of them written by somebody else's production."""
    item = _item(db, project, title=HOSTILE, permalink="javascript:alert(1)")
    _attempt(db, item, green_output=f"Traceback:\n  {HOSTILE}\n")

    listed = page.items(db)
    detail = page.item(db, get_settings(), item.id)

    assert detail is not None
    for rendered in (listed, detail):
        assert "<script" not in rendered.lower()
        assert "&lt;script&gt;" in rendered
    assert "javascript:alert(1)" in detail, "shown"
    assert '<a href="javascript' not in detail, "and not clickable"


def test_the_project_views_escape_a_slug_a_repo_and_a_title(db: Session) -> None:
    """**Item 142's two views, against the same fixture as the two above.**

    A project's slug and repository are as third-party as an error title: `projects add` takes them
    from an operator, and DR-0012 lets a *manifest* arrive from a repository. Both are rendered in
    an `href` here, the one place escaping a quote matters more than escaping a tag — hence
    `_h(..., quote=True)` everywhere and this test on the output rather than on the helper.
    """
    row = Project(
        slug=HOSTILE, forge="forgejo", repo=f"owner/{HOSTILE}",
        webhook_secret_hash="x",  # noqa: S106
    )
    db.add(row)
    db.flush()
    _item(db, row, title=HOSTILE)

    listed = page.projects(db, get_settings())
    detail = page.project(db, get_settings(), HOSTILE)

    assert detail is not None
    for rendered in (listed, detail):
        assert "<script" not in rendered.lower()
        assert "&lt;script&gt;" in rendered


def test_an_unknown_project_is_indistinguishable_from_a_wrong_token(
    db: Session, client: TestClient, project: Project
) -> None:
    """`404` with the same body, so a valid token cannot be used to enumerate slugs.

    Which clients a consultancy serves is a fact about that consultancy, and a page whose whole
    design is not being findable must not answer *this one exists and that one does not*.
    """
    del project
    token = _token(db)

    known = client.get(f"/page/{token}/projects/demo")
    unknown = client.get(f"/page/{token}/projects/no-such-client")

    assert known.status_code == 200
    assert unknown.status_code == 404
    assert unknown.json() == client.get(f"/page/{token}/nothing-here").json()


def test_a_project_says_here_that_its_manifest_stopped_validating(
    db: Session, project: Project
) -> None:
    """The degradation `ingest._manifest_for` performs **silently**: a cached manifest that no
    longer parses sends every error from that project to the red lane.

    It was reachable only by reading that function, and the reader who needs it is the one looking
    at this client. Asserted on the rendered page, and on the remedy being named — a symptom
    without the command that clears it is a puzzle.
    """
    project.manifest = {"project": "demo", "runtime": {"base": 12345}}
    db.flush()

    rendered = page.project(db, get_settings(), project.slug)

    assert rendered is not None
    assert "no longer validates" in rendered
    assert "projects refresh" in rendered, "the remedy, not only the symptom"
    assert "lands red" in rendered


def test_output_that_forges_a_fold_stays_inside_its_block(
    db: Session, project: Project
) -> None:
    """**Captured output is hostile input with a fold marker in its vocabulary.** A stack trace
    containing the literal line `</details>` would end the block early and put whatever follows in
    the page's own flow — markup injection with no script in it, where the reader is shown a
    structure the attacker chose. Inside the fence `evidence` writes, that line is content.
    """
    item = _item(db, project)
    _attempt(db, item, green_output="passed\n</details>\n<h1>Merged and approved</h1>\n")

    rendered = page.item(db, get_settings(), item.id)

    assert rendered is not None
    assert "<h1>Merged and approved</h1>" not in rendered, "escaped, whatever else happens"
    # And it is still *inside* the green gate's fold, rather than promoted into the page's flow.
    block = re.search(r"<details><summary>[^<]*green-gate.*?</details>", rendered, re.DOTALL)
    assert block is not None
    assert "&lt;h1&gt;Merged and approved&lt;/h1&gt;" in block.group(0)
    assert "&lt;/details&gt;" in block.group(0), "the marker itself, shown as the text it is"


def test_every_line_of_the_artefact_survives_being_folded() -> None:
    """The transform is presentation only. Text goes in a `<pre>`, a `<details>` becomes a real
    one, and nothing is dropped on the way — which is the difference between folding a document
    and summarising it."""
    body = "\n".join(
        ["### What ran", "", "<details><summary>green-gate output — 906 passed</summary>",
         "", "```text", "the output", "```", "", "</details>", "", "the last line"]
    )

    folded = page._folded(body)

    assert "<details><summary>green-gate output — 906 passed</summary>" in folded
    assert "the output" in folded
    assert "### What ran" in folded
    assert "the last line" in folded
    assert folded.count("<pre>") == 3, "before the fold, inside it, and after"


# --- the token, which is the whole security model ------------------------------------------------


def test_no_view_writes_the_token_into_the_page(
    db: Session, project: Project, client: TestClient
) -> None:
    """**Every link between views is relative, and that is the reason.** With the token in the
    path, an absolute `href` would put the credential in the HTML — where it survives being saved,
    screenshotted, pasted into an issue, or mailed to the colleague this page was made for."""
    item = _item(db, project)
    _attempt(db, item)
    token = _token(db)

    for path in (f"/page/{token}/", f"/page/{token}/items", f"/page/{token}/items/{item.id}"):
        answered = client.get(path)
        assert answered.status_code == 200, path
        assert token not in answered.text, path


def test_the_relative_links_actually_reach_the_other_views(
    db: Session, project: Project, client: TestClient
) -> None:
    """The other half of keeping the token out of the HTML: a relative `href` that resolves to the
    wrong place is a page whose navigation 404s, and it would 404 only in a browser — never in a
    test that renders a view by calling it. So the links are followed here, from the door inwards.
    """
    from urllib.parse import urljoin

    item = _item(db, project)
    _attempt(db, item)
    token = _token(db)

    door = client.get(f"/page/{token}")
    assert str(door.url).endswith(f"/page/{token}/"), "the slash is what makes the rest relative"
    # Item 212 made the door the work rather than the arithmetic; item 237 made it the projects and
    # what is waiting in each. The rail is on every page and therefore has as many chances to
    # resolve wrongly as it has entries, which is what the rest of this walk follows.
    assert "<h1>Hullwork</h1>" in door.text or "Projects" in door.text

    report = client.get(urljoin(str(door.url), _href(door.text, "This instance")))
    assert report.status_code == 200, "the noun the arithmetic moved behind"

    # **Three depths of relative link, which is where item 227 broke** — one level for `items/<id>`,
    # two for `projects/<slug>`, three for `projects/<slug>/<feature>`. Each is written once, in
    # `_document`, and each is followed here rather than asserted about.
    walked = client.get(urljoin(str(door.url), _href(door.text, project.slug)))
    assert walked.status_code == 200, "a project named on the door does not resolve"

    seen: dict[str, str] = {}
    for feature in ("Errors", "Fixes", "Dependencies", "Deliveries"):
        inside = client.get(urljoin(str(walked.url), _href(walked.text, feature)))
        assert inside.status_code == 200, f"{feature} does not resolve from the project"
        assert f"{feature}</span></h1>" in inside.text
        seen[feature] = inside.text

    from_errors = _href(seen["Errors"], str(item.id))
    detail = client.get(urljoin(f"/page/{token}/projects/{project.slug}/errors", from_errors))
    assert detail.status_code == 200, "an item does not resolve from its project's errors"
    assert "Attempt 1" in detail.text

    back = client.get(urljoin(str(detail.url), _href(detail.text, "What needs you")))
    assert back.status_code == 200
    assert "Projects" in back.text


def _href(html_text: str, label: str) -> str:
    """The `href` of the link whose text is `label`. A reader clicks these; so does this test."""
    # The rail carries a count inside the link since item 235, so a label is followed by the end of
    # the anchor **or** by that badge. Anchored on the label rather than on the whole anchor.
    found = re.search(rf'<a href="([^"]+)"[^>]*>{re.escape(label)}(?:<span|</a>)', html_text)
    if found is None:  # a name rendered inside its own element, as the door renders a project
        found = re.search(rf'<a href="([^"]+)"[^>]*>\s*{re.escape(label)}\s*<', html_text)
    assert found is not None, f"no link labelled {label!r}"
    return found.group(1)


def test_the_token_never_reaches_the_error_tracker(db: Session) -> None:
    """**The hole item 122 opened and this closes.** The receiver runs with `--no-access-log`
    because the webhook's token is a path segment — so the tracker was the one way out left, and
    an unhandled error inside a page route sends `request.url` with it.
    """
    from hullwork.scrub import Scrubber

    event = "GET /page/2f7c9a1b4e6d8f03/items/12 raised KeyError"

    assert "2f7c9a1b4e6d8f03" not in Scrubber(shapes=True).text(event)
    assert "/page/***/items/12" in Scrubber(shapes=True).text(event), "the useful part survives"


def test_links_out_of_these_views_cannot_leak_the_referrer(
    db: Session, project: Project, client: TestClient
) -> None:
    """The header is item 122's; that it is on **these** routes, which are the ones that actually
    link out to a forge and a tracker, is this item's."""
    item = _item(db, project)
    token = _token(db)

    for path in (f"/page/{token}/items", f"/page/{token}/items/{item.id}"):
        answered = client.get(path)
        assert answered.headers["referrer-policy"] == "no-referrer", path

    detail = answered.text
    assert 'rel="noreferrer noopener"' in detail
    assert "https://forge.example/acme/demo/issues/9" in detail, "the issue, as a link"


def test_the_daily_page_escapes_the_one_third_party_string_it_shows(
    db: Session, project: Project
) -> None:
    """**Item 143's view, and the measurement is sharper than the assertion.** Its own criterion
    asked for the hostile fixture to cover this page, and the first version of this test asserted
    that a hostile *title* renders escaped — which failed, for the best possible reason.

    **Item 167 changed the fact this test was written about, and that is worth recording.** Measured
    2026-08-05, the daily page showed counts, states and ages and never an item title — the oldest
    entry in a column was rendered as *how long*, never as *what* — so the widest surface in the
    product was narrow by construction rather than by escaping.

    It is not any more. The operator asked *"waiting on you 2 — and now what?"*, and the answer was
    to put the items on the front page **by name**, which puts a third party's exception title there
    too. The narrowness is gone and only the escaping is left, so this test asserts the escaping and
    stops counting on the page's own vocabulary: that arithmetic broke the day the stylesheet's
    comment said the words "no script", which is a false positive about a real property.
    """
    _item(db, project, title=HOSTILE, permalink="javascript:alert(1)")
    readiness.record_forge(f"unreachable:{HOSTILE}")
    try:
        rendered = page.instance(db, get_settings(), error_reporting=True)
    finally:
        readiness.record_forge("ok")

    assert "&lt;script&gt;" in rendered, "the forge's refusal reaches this page, so escape it"
    assert HOSTILE not in rendered, "and the raw string never does"

    # The one assertion that matters and cannot be defeated by prose: no tag that could execute or
    # fetch, anywhere. `<link>`, `<meta>` and `<style>` are the page's own and are in the head by
    # construction; everything below can only have arrived from a third party's string.
    for opening in ("<script", "<iframe", "<object", "<embed", "<svg", "<img", "<form action=http"):
        assert opening not in rendered.lower(), f"{opening} reached the page from outside"

    # Every escaped opening has its escaped close: a truncation that cut one off would be a tag
    # reassembled by a browser, and that is the failure this shape catches.
    assert rendered.count("&lt;script&gt;") == rendered.count("&lt;/script&gt;")


def test_every_colour_on_the_daily_page_carries_its_word(db: Session, project: Project) -> None:
    """Item 143's other closable criterion, and the product's own argument turned on its interface.

    Hullwork's core mechanic is a red/green gate. A page that encoded red and green in hue alone
    would fail exactly where it argues — for the reviewer who cannot tell them apart, the gate would
    be invisible on the one screen built to show it.

    Asserted structurally rather than by eye: every element carrying a state colour must also carry
    a word, so this fails if somebody later adds a bare coloured dot. `_h`-escaped content is
    ignored, since a hostile title is not a colour.
    """
    _item(db, project, title="a real failure")

    rendered = page.instance(db, get_settings(), error_reporting=True)
    coloured = re.findall(r'<span class="chip[^"]*"[^>]*>(.*?)</span>', rendered, re.S)

    assert coloured, "the fixture has to produce chips or this proves nothing"
    for chip in coloured:
        words = re.sub(r"<[^>]+>", "", chip).strip()
        assert words, f"a colour with no word in it: {chip!r}"
