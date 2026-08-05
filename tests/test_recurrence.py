"""Does the fix hold? M9, and the last question DR-0005 asks that nothing answered.

A merged pull request is not evidence. The evidence is the error not coming back — and that cannot
arrive by webhook: the tracker speaks once per issue for that issue's whole life. The issue is open
and its notification already spent, so the returning error is invisible unless somebody asks.

**Asking is three answers, not two**, and the middle one is why this module exists. An occurrence
after the merge means the fix failed only if the code it came from *contains* the merge. Old code
still deployed and still reporting says nothing about the fix, and counting it as a regression would
make every instance's number worse the slower its own deploys are. So each verdict here is checked
against the release the occurrence carried, and a release that cannot be compared to a commit is
`undecidable` rather than either of the convenient answers.

Every test in this file was verified by reintroducing the defect it covers.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from hullwork import recurrence
from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.forge import ForgeIssue, MergeState, RetryableForgeError, Tree
from hullwork.manifest import parse_manifest
from hullwork.models import (
    Attempt,
    AttemptOutcome,
    AttemptPhase,
    Item,
    ItemState,
    Lane,
    Project,
)
from hullwork.recurrence import Verdict
from hullwork.tracker import FetchedEvent, RetryableTrackerError

ROOT = Path(__file__).resolve().parent.parent

MANIFEST = """
project: demo
git: {provider: forgejo, repo: acme/demo}
autofix:
  lanes:
    green: [typeerror]
    red: [payment]
"""

#: The merge. Everything in this file is decided against it.
MERGE_SHA = "3f7a1c9b2e4d6a8f0b1c3d5e7f9a1b3c5d7e9f0a"
MERGED_AT = datetime(2026, 7, 20, 10, 0, tzinfo=UTC)
#: A week after the merge: inside the watch window, so `quiet` stays `quiet`.
NOW = MERGED_AT + timedelta(days=7)
#: A deployed release, as a project that tags its builds with a commit reports one.
#:
#: Sha-shaped in every test that expects a *decision*, and that is not cosmetic: only a ref a forge
#: can resolve is comparable to a merge commit, so a project whose tracker reports `v2.1.0` gets
#: `undecidable` and can never get `recurred`. These tests used version strings and the doubles
#: answered `True` anyway, which let this file assert a capability the real system does not have.
DEPLOYED = "5c8e1a90b7d24f36e8a1c0b5d9f27a43e61c8b0d"


class FakeForge:
    """A forge that answers about one merge, and records what it was asked.

    `contains` is the interesting knob: `True` (the release carries the fix), `False` (it predates
    it) and `None` (the release is not a commit, so the question has no answer) are the three cases
    `_decide` exists to keep apart.
    """

    def __init__(
        self,
        *,
        merged: bool = True,
        commit: str | None = MERGE_SHA,
        contains: bool | None = False,
        fails: bool = False,
    ) -> None:
        self.merged = merged
        self.commit = commit
        #: Overridable, because a real forge answers in its own offset rather than in UTC.
        self.merged_at = MERGED_AT
        self.contains = contains
        self.fails = fails
        self.merge_asked: list[int] = []
        self.compare_asked: list[tuple[str, str]] = []

    def read_file(self, repo: str, path: str) -> str | None:  # pragma: no cover - not used here
        """On the `Forge` protocol since item 107. A double that drifts stops testing it."""
        return None

    def tree(self, repo: str) -> Tree:  # pragma: no cover - not used here
        """On the `Forge` protocol since M8. A double that drifts stops testing the protocol."""
        return Tree(())

    def merge_state(self, repo: str, number: int) -> MergeState:
        if self.fails:
            raise RetryableForgeError("the forge is not answering")
        self.merge_asked.append(number)
        return MergeState(
            merged=self.merged,
            commit=self.commit if self.merged else None,
            merged_at=self.merged_at if self.merged else None,
        )

    def release_contains(self, repo: str, release: str, commit: str) -> bool | None:
        self.compare_asked.append((release, commit))
        return self.contains

    # --- the rest of the protocol, unused here but part of being a `Forge` ---

    def get_issue(self, repo: str, number: int) -> ForgeIssue | None:  # pragma: no cover
        return None

    def head_commit(self, repo: str, branch: str) -> str:  # pragma: no cover
        return "0" * 40

    def read_manifest(self, repo: str) -> str:  # pragma: no cover
        return MANIFEST

    def ensure_labels(self, repo: str, names: dict[str, str]) -> dict[str, int]:  # pragma: no cover
        return {}

    def create_issue(  # pragma: no cover
        self, repo: str, title: str, body: str, label_ids: list[int] | None = None
    ) -> ForgeIssue:
        raise AssertionError("the watch does not file issues")

    def find_issue_by_marker(  # pragma: no cover
        self, repo: str, fingerprint: str
    ) -> ForgeIssue | None:
        return None

    def comment(self, repo: str, number: int, body: str) -> None:  # pragma: no cover
        return None

    def set_issue_state(  # pragma: no cover
        self, repo: str, number: int, state: str
    ) -> ForgeIssue:
        raise AssertionError("the watch does not close issues")

    def close(self) -> None:  # pragma: no cover
        return None


class FakeTracker:
    """A tracker with a fixed list of occurrences, newest first, as the real one returns them."""

    def __init__(
        self, samples: list[tuple[str | None, datetime | None]], *, fails: bool = False
    ) -> None:
        self.samples = samples
        self.fails = fails
        self.asked: list[str] = []

    def fetch_samples(self, permalink: str, limit: int = 2) -> list[FetchedEvent]:
        if self.fails:
            raise RetryableTrackerError("the tracker is not answering")
        self.asked.append(permalink)
        return [
            FetchedEvent(
                provider_event_id=f"e{index}",
                release=release,
                occurred_at=when,
                exception_type="TypeError",
            )
            for index, (release, when) in enumerate(self.samples)
        ]

    def fetch_latest(self, permalink: str) -> FetchedEvent | None:  # pragma: no cover
        return None


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'recurrence.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")

    with make_session_factory(make_engine(url))() as db:
        db.add(
            Project(
                slug="demo",
                forge="forgejo",
                repo="acme/demo",
                webhook_secret_hash="not-a-real-hash",  # noqa: S106 - fixture
                manifest=parse_manifest(MANIFEST).model_dump(mode="json"),
            )
        )
        db.commit()
        yield db
    get_settings.cache_clear()


def _merged_fix(
    session: Session,
    *,
    state: ItemState = ItemState.DONE,
    ref: str = "https://forge/acme/demo/pulls/13",
    permalink: str | None = "https://tracker/issues/900",
) -> Item:
    """An item that reached a pull request, which is the only kind this watch looks at."""
    item = Item(
        project_id=1,
        fingerprint="fp-900",
        title="TypeError: NoneType is not subscriptable",
        state=state,
        lane=Lane.GREEN,
        permalink=permalink,
    )
    session.add(item)
    session.flush()
    session.add(
        Attempt(
            item_id=item.id,
            phase_reached=AttemptPhase.PUBLISH,
            outcome=AttemptOutcome.PR_OPEN,
            pull_request_ref=ref,
            consumed=True,
        )
    )
    session.commit()
    return item


# --- the gate, positively -------------------------------------------------------------------


def test_a_recurrence_from_code_that_contains_the_fix_reopens_the_item(session: Session) -> None:
    """M9's gate. The merge commit and the release that carried it are both named in the verdict."""
    item = _merged_fix(session)
    forge = FakeForge(contains=True)
    tracker = FakeTracker([(DEPLOYED, NOW - timedelta(hours=2))])

    watched = recurrence.watch(session, forge, tracker, now=NOW)

    assert [w.verdict for w in watched] == [Verdict.RECURRED]
    session.refresh(item)
    assert item.state is ItemState.REOPENED
    assert item.recurrence_verdict == Verdict.RECURRED.value
    # Both halves of "with the merge commit named and the release that carried it".
    assert MERGE_SHA[:12] in (item.recurrence_note or "")
    assert DEPLOYED in (item.recurrence_note or "")
    # And the fix's own commit is on the attempt, so the count does not depend on the tracker.
    attempt = session.query(Attempt).one()
    assert attempt.merge_commit == MERGE_SHA
    assert attempt.merged_at == MERGED_AT


def test_a_forge_answering_in_its_own_offset_is_recorded_and_reported_in_utc(
    session: Session,
) -> None:
    """Found on the live instance, where the column read 17:03 and the note said "19:03 UTC".

    Forgejo answers `2026-07-30T19:03:17+02:00` — the offset the instance runs in. `UtcDateTime`
    converts on the way to the database, so before the round trip the value in memory disagreed with
    the value on disk, and the note was written from the value in memory. Both are the same moment,
    which is precisely why the mismatch costs an operator time rather than announcing itself.
    """
    item = _merged_fix(session)
    madrid = timezone(timedelta(hours=2))
    forge = FakeForge()
    # 19:03 at +02:00 is 17:03 UTC.
    forge.merged_at = MERGED_AT.astimezone(madrid).replace(
        hour=19, minute=3, second=17, tzinfo=madrid
    )

    recurrence.watch(session, forge, FakeTracker([]), now=NOW)

    session.refresh(item)
    stored = session.query(Attempt).one().merged_at
    assert stored is not None
    assert stored.astimezone(UTC).hour == 17
    assert "17:03 UTC" in (item.recurrence_note or "")
    assert "19:03" not in (item.recurrence_note or "")


def test_a_fix_quiet_for_the_whole_window_is_counted_as_holding(session: Session) -> None:
    """The other half of the gate: one that does not recur is counted, once it is earned."""
    item = _merged_fix(session)
    tracker = FakeTracker([])

    # A week after the merge nothing has come back — and nothing has been demonstrated either.
    recurrence.watch(session, FakeForge(), tracker, now=NOW)
    session.refresh(item)
    assert item.recurrence_verdict == Verdict.QUIET.value
    assert recurrence.counted(session) == (1, 0, 0)

    # Past the window, the same silence becomes a claim.
    later = MERGED_AT + timedelta(days=recurrence.WATCH_DAYS, hours=1)
    recurrence.watch(session, FakeForge(), tracker, now=later)
    session.refresh(item)
    assert item.recurrence_verdict == Verdict.HELD.value
    assert recurrence.counted(session) == (1, 1, 0)


def test_the_instance_can_print_both_numbers(session: Session) -> None:
    """`status` is where the gate's "can print both numbers" is discharged."""
    from hullwork.cli import main

    item = _merged_fix(session)
    item.recurrence_verdict = Verdict.HELD.value
    # A held verdict implies the watch recorded the merge, which is what makes it a *merged* fix.
    session.query(Attempt).one().merge_commit = MERGE_SHA
    session.commit()

    out: list[str] = []

    class Sink:
        def write(self, text: str) -> int:
            out.append(text)
            return len(text)

        def flush(self) -> None:
            return None

    main(["status"], out=Sink())  # type: ignore[arg-type]
    printed = "".join(out)
    assert "merged fixes: 1" in printed
    assert f"held the {recurrence.WATCH_DAYS}-day window: 1" in printed
    assert "came back: 0" in printed


# --- the gate, negatively ------------------------------------------------------------------


def test_an_occurrence_from_a_release_that_predates_the_merge_is_not_a_regression(
    session: Session,
) -> None:
    """The negative half of M9's gate, and the reason the verdict is three-valued.

    Old code still deployed and still reporting is the normal state of a project between deploys. An
    instance that counted this as its fix failing would score worse the slower its own release
    cadence is, which measures the wrong thing entirely.
    """
    item = _merged_fix(session)
    forge = FakeForge(contains=False)
    tracker = FakeTracker([(DEPLOYED, NOW - timedelta(hours=1))])

    watched = recurrence.watch(session, forge, tracker, now=NOW)

    assert [w.verdict for w in watched] == [Verdict.QUIET]
    session.refresh(item)
    assert item.state is ItemState.DONE
    assert "predate" in (item.recurrence_note or "")
    assert recurrence.counted(session) == (1, 0, 0)
    # It did ask — a `quiet` reached without comparing anything would be the same word for a
    # different, unearned conclusion.
    assert forge.compare_asked == [(DEPLOYED, MERGE_SHA)]


def test_the_crashes_that_opened_the_issue_are_not_read_as_the_fix_failing(
    session: Session,
) -> None:
    """The other negative, and the one this file missed until a reintroduction found it green.

    The tracker returns an issue's last events, and for a fix that just merged those are all from
    *before* the merge — the crashes that opened the issue in the first place. They decide nothing,
    whatever release they carry.

    The ordering is enforced here rather than left to the release comparison, because the comparison
    answers a different question: "does this code contain the merge", not "did this happen after
    it". A pre-merge occurrence tagged with a ref that does contain the merge is exactly the case a
    forge would honestly call `True` — and without this filter every issue Hullwork ever fixed would
    be counted as recurred, for ever, on the strength of the crashes that made it file the issue.
    """
    item = _merged_fix(session)
    forge = FakeForge(contains=True)
    # Before the merge, and carrying a ref that does contain it.
    tracker = FakeTracker([(DEPLOYED, MERGED_AT - timedelta(hours=3))])

    watched = recurrence.watch(session, forge, tracker, now=NOW)

    assert [w.verdict for w in watched] == [Verdict.QUIET]
    session.refresh(item)
    assert item.state is ItemState.DONE
    # And it did not spend a comparison on an occurrence that could not decide anything.
    assert forge.compare_asked == []


def test_a_release_that_cannot_be_compared_to_a_commit_is_undecidable(session: Session) -> None:
    """A version string is not a ref. Neither answer is available, and saying so is the answer."""
    item = _merged_fix(session)
    forge = FakeForge(contains=None)
    tracker = FakeTracker([("2026.7.1-hotfix", NOW - timedelta(hours=1))])

    watched = recurrence.watch(session, forge, tracker, now=NOW)

    assert [w.verdict for w in watched] == [Verdict.UNDECIDABLE]
    session.refresh(item)
    assert item.state is ItemState.DONE
    # The reason, and it is the reason that was measured — a version string is refused before the
    # forge is asked, so this note must not blame the forge for failing to resolve anything.
    assert "version string" in (item.recurrence_note or "")
    assert forge.compare_asked == []
    # Not folded into either number: `undecidable` is neither holding nor recurred.
    assert recurrence.counted(session) == (1, 0, 0)


def test_an_unmerged_pull_request_is_not_watched_and_leaves_no_verdict(session: Session) -> None:
    item = _merged_fix(session, state=ItemState.PR_OPEN)
    tracker = FakeTracker([(DEPLOYED, NOW)])

    watched = recurrence.watch(session, FakeForge(merged=False), tracker, now=NOW)

    assert [w.verdict for w in watched] == [Verdict.SKIPPED]
    session.refresh(item)
    assert item.state is ItemState.PR_OPEN
    # The tracker was never asked: there is nothing yet to ask about, and the request would be spent
    # on every open pull request on every pass.
    assert tracker.asked == []
    assert session.query(Attempt).one().merge_commit is None


# --- the cost of asking --------------------------------------------------------------------


def test_an_item_just_asked_about_is_not_asked_again_this_pass(session: Session) -> None:
    """The backoff, which is item 083's lesson applied before it could be relearned.

    `fetch_context` shipped without one and asked twenty times a minute for ever.
    """
    _merged_fix(session)
    forge = FakeForge()
    tracker = FakeTracker([])

    recurrence.watch(session, forge, tracker, now=NOW)
    recurrence.watch(session, forge, tracker, now=NOW + timedelta(minutes=1))

    assert forge.merge_asked == [13], "asked twice inside the backoff window"

    # And it does come back, once the interval has passed.
    after_backoff = NOW + timedelta(seconds=recurrence.RECHECK_SECONDS + 1)
    recurrence.watch(session, forge, tracker, now=after_backoff)
    assert forge.merge_asked == [13, 13]


def test_a_settled_verdict_stops_costing_requests(session: Session) -> None:
    """`held` and `recurred` are done. `quiet` and `undecidable` are not — that is the point."""
    item = _merged_fix(session)
    item.recurrence_verdict = Verdict.HELD.value
    session.commit()
    forge = FakeForge()

    recurrence.watch(session, forge, FakeTracker([]), now=NOW + timedelta(days=90))

    assert forge.merge_asked == []


def test_a_forge_that_cannot_answer_still_records_having_asked(session: Session) -> None:
    """Otherwise the pass repeats in sixty seconds, for ever, against a forge already failing."""
    item = _merged_fix(session)

    watched = recurrence.watch(session, FakeForge(fails=True), FakeTracker([]), now=NOW)

    assert [w.verdict for w in watched] == [Verdict.SKIPPED]
    session.refresh(item)
    assert item.merge_checked_at == NOW
    assert item.recurrence_verdict is None, "a failure to ask is not a verdict"


def test_a_tracker_that_cannot_answer_leaves_the_merge_recorded(session: Session) -> None:
    """The merge is known from the forge alone, so a tracker having a bad minute cannot lose it."""
    item = _merged_fix(session)

    recurrence.watch(session, FakeForge(), FakeTracker([], fails=True), now=NOW)

    session.refresh(item)
    assert session.query(Attempt).one().merge_commit == MERGE_SHA
    assert item.merge_checked_at == NOW
    assert item.recurrence_verdict is None


def test_an_item_with_no_permalink_is_skipped_with_a_reason(session: Session) -> None:
    """Item 086's gap, from the other side: no permalink means no occurrences to read."""
    item = _merged_fix(session, permalink=None)

    watched = recurrence.watch(session, FakeForge(), FakeTracker([]), now=NOW)

    assert [w.verdict for w in watched] == [Verdict.SKIPPED]
    session.refresh(item)
    assert "permalink" in (item.recurrence_note or "")


def test_holding_is_not_merged_minus_recurred(session: Session) -> None:
    """A number that flatters itself is worse than no number.

    Three merged fixes: one held, one came back, one nobody has asked about yet. The third belongs
    in neither column — and "merged minus recurred" would put it in the good one.
    """
    for index, verdict in enumerate((Verdict.HELD.value, Verdict.RECURRED.value, None)):
        item = Item(
            project_id=1,
            fingerprint=f"fp-{index}",
            title="boom",
            state=ItemState.DONE,
            lane=Lane.GREEN,
            recurrence_verdict=verdict,
        )
        session.add(item)
        session.flush()
        session.add(
            Attempt(
                item_id=item.id,
                phase_reached=AttemptPhase.PUBLISH,
                outcome=AttemptOutcome.PR_OPEN,
                pull_request_ref="#7",
                merge_commit=MERGE_SHA,
                merged_at=MERGED_AT,
                consumed=True,
            )
        )
    session.commit()

    assert recurrence.counted(session) == (3, 1, 1)


def test_a_stale_pr_open_item_still_reopens_when_the_fix_comes_back(session: Session) -> None:
    """An item whose pull request was merged without a closing keyword never reached `done`.

    Its fix is in production all the same, so a recurrence against it is a regression. This is why
    `pr-open → reopened` is a legal transition; without the edge the verdict was recorded and the
    state was lost.
    """
    item = _merged_fix(session, state=ItemState.PR_OPEN)
    tracker = FakeTracker([(DEPLOYED, NOW - timedelta(hours=1))])

    recurrence.watch(session, FakeForge(contains=True), tracker, now=NOW)

    session.refresh(item)
    assert item.state is ItemState.REOPENED
    assert item.recurrence_verdict == Verdict.RECURRED.value


def test_a_merge_with_no_commit_decides_nothing(session: Session) -> None:
    """Squash-and-delete leaves a merged pull request the forge reports no commit for.

    Without the commit there is nothing to compare a release against, so every later occurrence
    would be either counted or dismissed on no evidence. Neither, and the note says which.
    """
    item = _merged_fix(session)
    tracker = FakeTracker([(DEPLOYED, NOW)])

    watched = recurrence.watch(session, FakeForge(commit=None), tracker, now=NOW)

    assert [w.verdict for w in watched] == [Verdict.SKIPPED]
    session.refresh(item)
    assert item.state is ItemState.DONE
    assert "cannot be decided" in (item.recurrence_note or "")


def test_a_reference_with_no_number_in_it_is_reported_not_guessed(session: Session) -> None:
    item = _merged_fix(session, ref="the pull request")

    watched = recurrence.watch(session, FakeForge(), FakeTracker([]), now=NOW)

    assert [w.verdict for w in watched] == [Verdict.SKIPPED]
    session.refresh(item)
    assert "no number" in (item.recurrence_note or "")


def test_an_item_that_never_published_is_never_watched(session: Session) -> None:
    """The watch is about merged fixes. An item with no pull request has none to ask about."""
    session.add(
        Item(
            project_id=1,
            fingerprint="fp-none",
            title="boom",
            state=ItemState.DONE,
            lane=Lane.GREEN,
            permalink="https://tracker/issues/1",
        )
    )
    session.commit()
    forge = FakeForge()

    assert recurrence.watch(session, forge, FakeTracker([]), now=NOW) == []
    assert forge.merge_asked == []


def test_the_watch_is_a_no_op_without_a_forge_or_a_tracker(session: Session) -> None:
    """`sweep` passes whatever it has. An instance with no tracker configured must not crash."""
    _merged_fix(session)

    assert recurrence.watch(session, None, FakeTracker([]), now=NOW) == []
    assert recurrence.watch(session, FakeForge(), None, now=NOW) == []
