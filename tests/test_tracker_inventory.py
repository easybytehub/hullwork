"""Reading the tracker's unresolved list. DR-0011, item 080.

Against the **real shape**, captured from the live GlitchTip on 2026-07-30 into
`fixtures/glitchtip-issues-unresolved.json` — eight issues, six of which had never entered
Hullwork, including the 58-event `OperationalError` that turned out to be item 081.

The assertion the whole design rests on is `test_the_fingerprint_matches_the_webhook_route`. If
the two routes ever derive different fingerprints, every swept issue becomes a **second item** for
a bug that already has one — and duplicate issues are, in this product's own words, its cardinal
sin.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from hullwork.normalise import glitchtip as webhook_adapter
from hullwork.tracker import PermanentTrackerError, TrackerIssue
from hullwork.tracker.glitchtip import GlitchTipTracker

FIXTURES = Path(__file__).parent / "fixtures"
ROWS: list[dict[str, Any]] = json.loads(
    (FIXTURES / "glitchtip-issues-unresolved.json").read_text(encoding="utf-8")
)


class _Answers(GlitchTipTracker):
    """The real adapter with its HTTP call replaced, so every line of parsing is the real one."""

    def __init__(self, payload: object, organisation: str = "easybyte-hub") -> None:
        super().__init__(
            "http://tracker.example",
            "token",
            organisation=organisation,
        )
        self._payload = payload
        self.asked: list[str] = []

    def _get(self, path: str) -> Any:  # noqa: ANN401 - matches the method it replaces
        self.asked.append(path)
        return self._payload


# --- the route, and what it is asked for --------------------------------------------------------


def test_it_asks_for_the_projects_unresolved_issues() -> None:
    tracker = _Answers(ROWS)

    tracker.list_unresolved("hullwork")

    assert tracker.asked == [
        "/api/0/projects/easybyte-hub/hullwork/issues/?query=is%3Aunresolved"
    ]


def test_a_project_the_tracker_does_not_have_is_an_error_not_an_empty_inventory() -> None:
    """A 404 arrives from `_get` as `None`, and "no such project" must not read as "nothing wrong".

    This is a configuration mistake — the wrong organisation or slug — and the two are
    indistinguishable from the outside while only one of them is fine.
    """
    tracker = _Answers(None)

    with pytest.raises(PermanentTrackerError, match="no project"):
        tracker.list_unresolved("typo")


# --- parsing the real shape ---------------------------------------------------------------------


def test_the_real_shape_parses_into_issues() -> None:
    issues = _Answers(ROWS).list_unresolved("hullwork", limit=50)

    assert len(issues) == len(ROWS)
    assert {issue.external_id for issue in issues} == {r["id"] for r in ROWS}
    assert all(issue.status == "unresolved" for issue in issues)


def test_camel_case_timestamps_are_read() -> None:
    """The module docstring said list routes answer snake_case. **This one does not.**

    Measured: `firstSeen`, `lastSeen`, `numComments`, `shortId`. The claim was true of the event
    list route and had been over-generalised, and a parser from the docstring would have produced
    `None` for every timestamp — which the high-water mark depends on, so the sweep would have
    re-ingested the whole list on every pass for ever.
    """
    issues = {i.external_id: i for i in _Answers(ROWS).list_unresolved("hullwork", limit=50)}
    twelve = issues["12"]

    assert twelve.first_seen == datetime(2026, 7, 29, 7, 28, 20, 224000, tzinfo=UTC)
    assert twelve.last_seen == datetime(2026, 7, 29, 18, 9, 10, 372000, tzinfo=UTC)


def test_the_count_is_a_string_on_this_route() -> None:
    """`"58"`, not `58`. An `int()` straight off the row is right; assuming a number is not."""
    issues = {i.external_id: i for i in _Answers(ROWS).list_unresolved("hullwork", limit=50)}

    assert issues["12"].occurrences == 58
    assert issues["15"].occurrences == 1


def test_the_location_comes_from_metadata_where_the_webhook_had_nothing() -> None:
    """**Why this route improves triage and not only coverage** (items 070, 071).

    `culprit` is `""` here and was `null` in every real webhook. The location lives in
    `metadata.filename` and `metadata.function`, and the lane decision depends on having one.
    """
    issues = {i.external_id: i for i in _Answers(ROWS).list_unresolved("hullwork", limit=50)}

    assert issues["15"].culprit == "sqlalchemy/engine/default.py:do_execute"
    assert all(row["culprit"] == "" for row in ROWS), "the fixture's own culprit is empty"


def test_a_row_missing_its_identity_is_skipped_not_fatal() -> None:
    """One unusable row must not cost the whole inventory — `drain_pending`'s rule."""
    broken = [{"title": "no id and no permalink"}, *ROWS]

    issues = _Answers(broken).list_unresolved("hullwork", limit=50)

    assert len(issues) == len(ROWS)


# --- the identity the whole design rests on -----------------------------------------------------


def test_the_fingerprint_matches_the_webhook_route() -> None:
    """**The single assertion DR-0011 depends on.**

    The same issue arriving by webhook and by sweep must produce the *same* item. It does because
    the fingerprint is derived from the issue id and both routes recover it from a permalink — but
    "because it should" is not evidence, so this computes both and compares the bytes.

    If it ever fails, the sweep stops being safe: every issue already known from a webhook would be
    filed a second time.
    """
    row = next(r for r in ROWS if r["id"] == "12")
    swept = _Answers([row]).list_unresolved("hullwork")[0]

    # What the webhook route does with the same issue: a Slack-style attachment whose `title_link`
    # is the permalink. Built here rather than fixtured, so the comparison is of the *functions*.
    payload = {
        "attachments": [
            {
                "title": row["title"],
                "title_link": row["permalink"],
                "text": None,
                "fields": [{"title": "Project", "value": "hullwork"}],
            }
        ]
    }
    from_webhook = webhook_adapter.parse(payload, datetime(2026, 7, 30, tzinfo=UTC))[0]

    from_sweep = webhook_adapter.fingerprint_for(
        issue_id=swept.external_id, title=swept.title, culprit=swept.culprit
    )

    assert from_sweep == from_webhook.fingerprint
    assert from_webhook.external_id == swept.external_id == "12"


def test_the_id_in_the_permalink_is_the_id_in_the_row() -> None:
    """The two routes agree about identity for a reason, not luck. Checked on every fixture row."""
    for row in ROWS:
        assert webhook_adapter.issue_id_in(row["permalink"]) == row["id"]


# --- the high-water mark ------------------------------------------------------------------------


def test_since_filters_on_last_activity() -> None:
    """The mark is on `lastSeen`, because that is what "has anything happened here" means."""
    cutoff = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)

    issues = _Answers(ROWS).list_unresolved("hullwork", since=cutoff, limit=50)

    assert {i.external_id for i in issues} == {"12", "15"}, "only the two active that afternoon"
    assert all(i.last_seen is not None and i.last_seen > cutoff for i in issues)


def test_results_are_oldest_first_so_advancing_the_mark_makes_progress() -> None:
    """**Ordering is a correctness property here, not presentation.**

    The `Link` header is unusable, so paging is by time: the caller advances `since` to the last
    issue it handled. Newest-first — the provider's own order — would hand back the same page for
    ever and starve everything behind it.
    """
    issues = _Answers(ROWS).list_unresolved("hullwork", limit=50)
    seen = [i.last_seen for i in issues if i.last_seen is not None]

    assert len(seen) == len(issues), "the fixture has a timestamp on every row"
    assert seen == sorted(seen), "oldest activity first"
    assert issues[0].external_id == "7", "the oldest row in the fixture"


def test_the_limit_bounds_one_pass_and_takes_the_oldest() -> None:
    """Three hundred open issues must not become three hundred forge issues in one afternoon."""
    issues = _Answers(ROWS).list_unresolved("hullwork", limit=3)

    assert len(issues) == 3
    assert [i.external_id for i in issues] == ["7", "8", "9"]


def test_an_issue_with_no_last_seen_sorts_first_rather_than_crashing() -> None:
    """A missing timestamp is somebody else's shape changing, not a reason to stop sweeping."""
    rows = [{**ROWS[0], "id": "999", "lastSeen": None}, *ROWS]

    issues = _Answers(rows).list_unresolved("hullwork", limit=50)

    assert issues[0].external_id == "999"


def test_it_satisfies_the_protocol() -> None:
    from hullwork.tracker import Tracker

    assert isinstance(_Answers(ROWS), Tracker)
    assert isinstance(
        TrackerIssue(external_id="1", title="t", permalink="p", status="unresolved"),
        TrackerIssue,
    )
