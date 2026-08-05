"""A verdict that could not be posted is not lost. Item 077.

Attempt 11 on the live instance reached `not-reproducible` — which DR-0003 calls the honest headline
outcome — and its comment died with `POST /repos/easybyte/hullwork/issues/3/comments: HTTP 404`. The
attempt was consumed, the verdict existed in one SQLite file, `hullwork status` reported it and
exited 1, and **no command could ever clear that**: there was nothing that published an
already-reached verdict.

Two things every test here is built around:

* the retry must reach the forge, so the doubles record what body they were handed rather than
  answering `True`;
* the verdict and the publication failure live in **one column**, so every assertion about clearing
  one checks that the other survived.
"""

import io
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from hullwork import work
from hullwork.cli import main as cli_main
from hullwork.config import get_settings
from hullwork.forge import ForgePullRequest, PermanentForgeError, RetryableForgeError
from hullwork.models import (
    Attempt,
    AttemptOutcome,
    AttemptPhase,
    Base,
    Item,
    ItemState,
    Project,
)

VERDICT = "the agent wrote no test, so there is nothing to reproduce the bug with"
FAILURE = "POST /repos/easybyte/hullwork/issues/3/comments: HTTP 404"



class _Issues:
    """A forge that records the comment body it was handed. Never a `True`."""

    def __init__(self) -> None:
        self.comments: list[tuple[str, int, str]] = []

    def comment(self, repo: str, number: int, body: str) -> None:
        self.comments.append((repo, number, body))

    def close(self) -> None:
        pass


class _Refusing(_Issues):
    """The live 404: the issue is gone, so the retry can never succeed."""

    def comment(self, repo: str, number: int, body: str) -> None:
        raise PermanentForgeError(f"POST /repos/{repo}/issues/{number}/comments: HTTP 404", 404)


class _WouldPush(_Issues):
    """Records any attempt to write code. A `pr-open` retry must never reach this."""

    def __init__(self) -> None:
        super().__init__()
        self.pushes: list[str] = []

    def create_branch(self, repo: str, name: str, from_ref: str) -> None:
        self.pushes.append(f"branch {name}")

    def commit_files(self, *args: object, **kwargs: object) -> str:
        self.pushes.append("commit")
        return "deadbeef"


def _stranded(
    session: Session,
    *,
    outcome: AttemptOutcome = AttemptOutcome.NOT_REPRODUCIBLE,
    issue: str | None = "#3",
    verdict: str = VERDICT,
    failure: str | None = FAILURE,
    slug: str = "hullwork",
) -> Attempt:
    """The 2026-07-29 state: a spent attempt whose verdict and failure share one column."""
    project = session.query(Project).filter(Project.slug == slug).one_or_none()
    if project is None:
        project = Project(
            slug=slug,
            forge="forgejo",
            repo="easybyte/hullwork",
            webhook_secret_hash="x",  # noqa: S106
            manifest={"project": slug, "autofix": {"agent": "claude-code"}},
        )
        session.add(project)
        session.flush()
    item = Item(
        project_id=project.id,
        fingerprint=f"fp-{outcome.value}-{issue}-{failure is None}",
        title="ValueError: boom",
        state=ItemState.NOT_REPRODUCIBLE,
        forge_issue_ref=issue,
    )
    session.add(item)
    session.flush()
    error = verdict if failure is None else f"{verdict}\n{work.PUBLICATION_FAILED}{failure}"
    attempt = Attempt(
        item_id=item.id,
        outcome=outcome,
        phase_reached=AttemptPhase.REPRODUCE,
        consumed=True,
        error=error,
    )
    session.add(attempt)
    session.commit()
    return attempt


# --- finding them ------------------------------------------------------------------------------


def test_a_stranded_verdict_is_found_and_a_published_one_is_not(session: Session) -> None:
    stranded = _stranded(session)
    _stranded(session, failure=None)

    assert [a.id for a in work.unpublished_verdicts(session)] == [stranded.id]


def test_the_verdict_and_the_failure_are_read_apart(session: Session) -> None:
    """One column, two facts. Every clearing assertion below depends on this split being right."""
    attempt = _stranded(session)

    assert work.publication_failure(attempt) == FAILURE
    assert work.verdict_detail(attempt) == VERDICT


# --- the retry ---------------------------------------------------------------------------------


def test_the_retry_posts_the_verdict_and_not_the_publication_error(session: Session) -> None:
    """**The body is the point.** `_comment` renders `attempt.error` whole — correct at first
    publication, where the failure line does not yet exist, and wrong on every retry. A reader of
    the issue needs the verdict, not this instance's HTTP trouble from three days ago.
    """
    attempt = _stranded(session)
    forge = _Issues()

    where = work.republish(session, attempt, forge=forge, repo="easybyte/hullwork")

    assert where == "#3"
    assert len(forge.comments) == 1
    repo, number, body = forge.comments[0]
    assert (repo, number) == ("easybyte/hullwork", 3)
    assert VERDICT in body
    assert "publishing failed" not in body
    assert "HTTP 404" not in body


def test_a_successful_retry_clears_the_report_and_keeps_the_verdict(session: Session) -> None:
    """Both halves, because clearing too much and clearing too little are both wrong."""
    attempt = _stranded(session)

    before = work.readiness_notes(session, code_token_configured=True)
    assert any("could not publish" in note.text for note in before)

    work.republish(session, attempt, forge=_Issues(), repo="easybyte/hullwork")

    session.refresh(attempt)
    assert attempt.error == VERDICT, "the verdict must survive; only the failure goes"
    assert work.publication_failure(attempt) is None
    after = work.readiness_notes(session, code_token_configured=True)
    assert not any("could not publish" in note.text for note in after)


def test_a_retry_that_fails_again_changes_nothing(session: Session) -> None:
    """A command that loses the record of its own failure is worse than one that does nothing.

    This is attempt 11's real situation: issue `#3` does not exist, so the 404 is permanent.
    """
    attempt = _stranded(session)
    was = attempt.error

    with pytest.raises(work.PublicationError) as raised:
        work.republish(session, attempt, forge=_Refusing(), repo="easybyte/hullwork")

    assert "still cannot publish" in str(raised.value)
    assert "--give-up" in str(raised.value), "the message has to name the way out"
    session.refresh(attempt)
    assert attempt.error == was
    assert work.unpublished_verdicts(session) == [attempt]


def test_a_pr_open_verdict_is_refused_and_nothing_is_pushed(session: Session) -> None:
    """The files the agent wrote are process memory and `attempts` has no column for them.

    Attempting it would push two empty commits and open a pull request claiming a fix that is not in
    it — worse than the stranded verdict, because it would look finished.
    """
    attempt = _stranded(session, outcome=AttemptOutcome.PR_OPEN)
    forge = _WouldPush()

    with pytest.raises(work.PublicationError) as raised:
        work.republish(session, attempt, forge=forge, repo="easybyte/hullwork")

    assert "item 079" in str(raised.value)
    assert forge.pushes == [], "a refused publication must not touch the repository"
    assert forge.comments == []
    assert work.unpublished_verdicts(session) == [attempt]


def test_an_attempt_with_nothing_to_publish_is_refused(session: Session) -> None:
    attempt = _stranded(session, failure=None)

    with pytest.raises(work.PublicationError) as raised:
        work.republish(session, attempt, forge=_Issues(), repo="easybyte/hullwork")

    assert "no failed publication" in str(raised.value)


def test_an_item_with_no_issue_says_the_verdict_has_no_destination(session: Session) -> None:
    attempt = _stranded(session, issue=None)

    with pytest.raises(work.PublicationError) as raised:
        work.republish(session, attempt, forge=_Issues(), repo="easybyte/hullwork")

    assert "no destination" in str(raised.value)


def test_no_forge_configured_is_refused_before_anything_is_touched(session: Session) -> None:
    attempt = _stranded(session)

    with pytest.raises(work.PublicationError) as raised:
        work.republish(session, attempt, forge=None, repo="easybyte/hullwork")

    assert "HULLWORK_FORGE_TOKEN" in str(raised.value)
    session.refresh(attempt)
    assert work.publication_failure(attempt) == FAILURE


# --- giving up ---------------------------------------------------------------------------------


def test_giving_up_records_the_decision_and_stops_the_report(session: Session) -> None:
    """Attempt 11's real remedy: the issue does not exist, so the 404 is for ever.

    The verdict stays and the failure stays readable **inside** the sentence. A deletion would leave
    nobody able to tell a written-off verdict from one that was never reached.
    """
    attempt = _stranded(session)

    work.give_up_publishing(session, attempt, why="issue #3 does not exist")

    session.refresh(attempt)
    recorded = attempt.error or ""
    assert VERDICT in recorded
    assert "issue #3 does not exist" in recorded
    assert FAILURE in recorded, "what failed must still be readable"
    assert work.publication_failure(attempt) is None
    assert work.unpublished_verdicts(session) == []
    assert not any(
        "could not publish" in note.text
        for note in work.readiness_notes(session, code_token_configured=True)
    )


def test_giving_up_on_a_published_verdict_is_refused(session: Session) -> None:
    """Not a way to erase an inconvenient verdict."""
    attempt = _stranded(session, failure=None)

    with pytest.raises(work.PublicationError) as raised:
        work.give_up_publishing(session, attempt, why="inconvenient")

    assert "nothing to give up on" in str(raised.value)
    session.refresh(attempt)
    assert attempt.error == VERDICT


# --- the command -------------------------------------------------------------------------------


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[str]:
    """A database on disk the CLI will open for itself, with the 2026-07-29 state in it."""
    url = f"sqlite:///{tmp_path / 'republish.db'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        _stranded(db)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    get_settings.cache_clear()
    yield url
    get_settings.cache_clear()


def test_give_up_refuses_to_work_in_bulk(configured: str) -> None:
    """The refusal `approve` makes, for the same reason: one decision, named explicitly."""
    out = io.StringIO()
    code = cli_main(["republish", "--give-up", "--why", "whatever"], out=out)

    assert code == 1


def test_give_up_needs_a_reason(configured: str) -> None:
    out = io.StringIO()
    code = cli_main(["republish", "--attempt", "1", "--give-up"], out=out)

    assert code == 1


def test_give_up_through_the_command_clears_the_status_exit_code(configured: str) -> None:
    """The falsifiable gate, in miniature: reported before, gone after, and status agrees."""
    before = io.StringIO()
    assert cli_main(["status"], out=before) == 1
    assert "could not publish" in before.getvalue()

    done = io.StringIO()
    assert cli_main(
        ["republish", "--attempt", "1", "--give-up", "--why", "issue #3 does not exist"],
        out=done,
    ) == 0
    assert "given up" in done.getvalue()

    after = io.StringIO()
    # **Item 129 changed what the exit code is about, and this assertion is stronger for it.**
    # `status` now asks the forge instead of reporting `unknown` because nobody asked, and this
    # fixture's forge is a URL that does not resolve — so the instance is degraded, correctly, and
    # says which of the two things is wrong. What this test is about is the *other* one going away.
    assert cli_main(["status"], out=after) == 1
    assert "could not publish" not in after.getvalue(), "the verdict this test is about is gone"
    assert "the forge is" in after.getvalue(), "and the only remaining problem is the fake forge"


def test_naming_an_attempt_that_is_not_waiting_is_refused(configured: str) -> None:
    out = io.StringIO()
    assert cli_main(["republish", "--attempt", "999"], out=out) == 1


def test_status_says_whether_a_dispatcher_is_alive_even_when_all_is_well(configured: str) -> None:
    """**Measured in production the moment item 077 cleared its last note.**

    `loop_line` lived inside `if dispatcher:`, so whether anything picks work up was reported only
    when something else was already wrong. Clearing the stranded verdict took `status` to exit 0 and
    it stopped mentioning the dispatcher entirely — while the dispatcher was stopped. Item 075's
    fourth gate exists to stop exactly that, and this is the same failure reached from the other
    side: a quiet healthy instance and one with nothing running looked identical.
    """
    out = io.StringIO()
    assert cli_main(
        ["republish", "--attempt", "1", "--give-up", "--why", "issue #3 does not exist"],
        out=out,
    ) == 0

    clean = io.StringIO()
    # Item 129: exit 1 here is this fixture's unreachable forge, not the stranded verdict — and the
    # line below is what this test is about. Asserted apart, so the two cannot be confused again.
    assert cli_main(["status"], out=clean) == 1
    printed = clean.getvalue()

    assert "could not publish" not in printed, "the stranded verdict is what was cleared"
    assert "the forge is" in printed, "what remains is the fixture's URL, which does not resolve"
    assert "Dispatcher:" in printed
    assert "dispatcher has ever run" in printed, "silence is not an answer about liveness"


# --- a pr-open verdict whose branch is already on the forge. Item 079, option C -------------------


class _HasTheBranch:
    """A code forge that answers about a branch and records what was opened.

    Deliberately not a `_WouldPush`: this path must **not** create a branch or commit anything. The
    agent's work is already on the forge, which is the whole point — what was missing is one call.
    """

    def __init__(self, *, head: str | None = "c0ffee" * 6, fails: bool = False) -> None:
        self.head = head
        self.fails = fails
        self.asked: list[str] = []
        self.opened: list[dict[str, str]] = []
        self.pushes: list[str] = []

    def head_commit(self, repo: str, branch: str) -> str | None:
        if self.fails:
            raise RetryableForgeError("the forge is not answering")
        self.asked.append(branch)
        return self.head

    def default_branch(self, repo: str) -> str:
        return "main"

    def open_draft_pull_request(
        self, repo: str, *, head: str, base: str, title: str, body: str
    ) -> ForgePullRequest:
        self.opened.append({"head": head, "base": base, "title": title, "body": body})
        return ForgePullRequest(
            number=42,
            title=title,
            html_url="https://forge/easybyte/hullwork/pulls/42",
            draft=True,
        )

    def create_branch(self, repo: str, name: str, from_ref: str) -> None:  # pragma: no cover
        self.pushes.append(f"branch {name}")

    def commit_files(self, *args: object, **kwargs: object) -> str:  # pragma: no cover
        self.pushes.append("commit")
        return "deadbeef"


def _pr_open_with_a_branch(session: Session, **kwargs: object) -> Attempt:
    attempt = _stranded(session, outcome=AttemptOutcome.PR_OPEN, **kwargs)  # type: ignore[arg-type]
    attempt.branch = "hullwork/item-17"
    attempt.base_sha = "9e7fc2b9b2c9f5351b8989325e1b5007a306f762"
    session.commit()
    return attempt


def test_a_pr_open_verdict_is_finished_from_the_branch_the_forge_already_has(
    session: Session,
) -> None:
    """**Item 079, option C: ask the forge rather than rebuild from the database.**

    `publish` puts the durable thing first — create the branch, make both commits, and only then
    compose the body and open the pull request — so a publication that failed at the last step
    left the agent's work on the forge. `branch` and `base_sha` are columns. Nothing needs
    rebuilding: what was missing is one call, and the old refusal turned that into "re-run the item
    and spend another attempt".

    The body is rendered again from this database, which it can be: the brief is a function of the
    item and its fetched events, the steps and their output are rows, the seal is a column.
    """
    attempt = _pr_open_with_a_branch(session)
    code = _HasTheBranch()

    url = work.republish(
        session, attempt, forge=_Issues(), code_forge=code, repo="easybyte/hullwork"
    )

    assert url == "https://forge/easybyte/hullwork/pulls/42"
    assert code.asked == ["hullwork/item-17"], "it must ask before it acts"
    assert [o["head"] for o in code.opened] == ["hullwork/item-17"]
    assert code.opened[0]["base"] == "main"
    # Nothing was pushed: the commits were already there and this path must not make more.
    assert code.pushes == []
    session.refresh(attempt)
    assert attempt.pull_request_ref == "#42"
    # And it stops being reported, which is what item 077's fourth gate asks of any finish.
    assert work.unpublished_verdicts(session) == []


def test_a_branch_the_forge_does_not_have_is_still_refused(session: Session) -> None:
    """The half that is genuinely lost, and the only one worth storing files against.

    Publication failed before `create_branch`, so the agent's work never left the process. Opening a
    pull request now would claim a fix nobody made — the same failure the old refusal described, now
    reserved for the case it is true of.
    """
    attempt = _pr_open_with_a_branch(session)
    code = _HasTheBranch(head=None)

    with pytest.raises(work.PublicationError) as raised:
        work.republish(
            session, attempt, forge=_Issues(), code_forge=code, repo="easybyte/hullwork"
        )

    assert "does not exist" in str(raised.value)
    assert "item 079" in str(raised.value)
    assert code.opened == []
    assert code.pushes == []
    assert work.unpublished_verdicts(session) == [attempt]


def test_a_branch_still_at_the_base_commit_is_refused(session: Session) -> None:
    """Created and then nothing committed to it — which `publish` can leave behind, because it
    records the branch before the first commit (item 048).

    A pull request from a branch identical to its base is an empty diff wearing a claim.
    """
    attempt = _pr_open_with_a_branch(session)
    code = _HasTheBranch(head="9e7fc2b9b2c9f5351b8989325e1b5007a306f762")

    with pytest.raises(work.PublicationError) as raised:
        work.republish(
            session, attempt, forge=_Issues(), code_forge=code, repo="easybyte/hullwork"
        )

    assert "no commits on it" in str(raised.value)
    assert code.opened == []


def test_finishing_a_pr_open_verdict_needs_the_code_credential(session: Session) -> None:
    """Opening a pull request is a code write; commenting is the ingest one (spec M2 §1).

    Named exactly, because the remedy is a variable on the machine where the dispatcher runs and the
    receiver must never hold it.
    """
    attempt = _pr_open_with_a_branch(session)

    with pytest.raises(work.PublicationError) as raised:
        work.republish(session, attempt, forge=_Issues(), repo="easybyte/hullwork")

    assert "HULLWORK_FORGE_CODE_TOKEN" in str(raised.value)


def test_a_forge_that_cannot_answer_says_nothing_about_the_branch(session: Session) -> None:
    """Unknown is not "missing". A forge having a bad minute must not be reported as a lost fix."""
    attempt = _pr_open_with_a_branch(session)
    code = _HasTheBranch(fails=True)

    with pytest.raises(work.PublicationError) as raised:
        work.republish(
            session, attempt, forge=_Issues(), code_forge=code, repo="easybyte/hullwork"
        )

    message = str(raised.value)
    assert "says nothing about the branch" in message
    assert "item 079" not in message, "a forge outage is not the missing-files case"
    assert work.unpublished_verdicts(session) == [attempt]
