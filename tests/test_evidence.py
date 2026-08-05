"""What a reviewer reads, and what must never be in it (item 027).

Half of these are about secrets, and that is the right proportion. This document is assembled from
the captured output of arbitrary commands and published under Hullwork's own account into a place a
human is meant to trust — a suite that dumps the environment on failure is not a rare event.
"""

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from hullwork import evidence
from hullwork.attempts import finish, record, start
from hullwork.models import (
    Attempt,
    AttemptOutcome,
    AttemptPhase,
    Item,
    Lane,
    Project,
)


@pytest.fixture
def item(session: Session) -> Item:
    project = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="x",  # noqa: S106
    )
    session.add(project)
    session.flush()
    row = Item(
        project_id=project.id, fingerprint="fp", lane=Lane.GREEN,
        title="ValueError: totals must not be negative", forge_issue_ref="#42",
    )
    session.add(row)
    session.flush()
    return row


SEAL = {
    "endpoint": "https://api.example.com",
    "model_requested": "big-model",
    "models_served": ["big-model"],
    "model_drift": False,
    "precision": "undisclosed",
    "input_tokens": 1200,
    "output_tokens": 300,
    "violations": [],
}


def _green(session: Session, item: Item) -> Attempt:
    attempt = start(session, item, base_sha="abc1234", image_tag="hullwork-sandbox:dead")
    record(session, attempt, AttemptPhase.BASELINE, "pytest", exit_code=0, output="12 passed",
           duration_ms=4200)
    record(session, attempt, AttemptPhase.RED_GATE, "pytest", exit_code=1,
           output="1 failed, 12 passed", duration_ms=4300)
    record(session, attempt, AttemptPhase.GREEN_GATE, "pytest", exit_code=0, output="13 passed",
           duration_ms=4100)
    return finish(session, attempt, AttemptOutcome.PR_OPEN, seal=SEAL)


def test_the_claim_is_the_first_thing_a_reviewer_reads(session: Session, item: Item) -> None:
    body = evidence.pull_request_body(item, _green(session, item))

    assert body.startswith("**A test that failed against unmodified code passes")


def test_merging_it_closes_the_issue(session: Session, item: Item) -> None:
    """The keyword both forges honour, verified against a live Forgejo."""
    body = evidence.pull_request_body(item, _green(session, item))

    assert "Closes #42" in body


def test_the_seal_is_rendered_and_precision_is_never_invented(
    session: Session, item: Item
) -> None:
    body = evidence.pull_request_body(item, _green(session, item))

    assert "big-model" in body
    assert "`undisclosed`" in body
    assert "abc1234" in body
    # **The row used to read `Context served | 1200 in`** and that was the defect item 133 fixed:
    # `input_tokens` counts only the input billed at full rate, so on a caching provider the row was
    # understating the context by orders of magnitude. The counts are now shown as what they are —
    # billing categories — and "context served" means the sum of what was actually served.
    assert "1,200 in, 300 out" in body, "the charged counts, each named"
    assert "Charged as" in body
    assert "Context served" in body
    assert "not reported" in body, "this fixture predates caching, and that is not zero"


def test_every_command_and_exit_code_is_shown(session: Session, item: Item) -> None:
    body = evidence.pull_request_body(item, _green(session, item))

    assert "`baseline`" in body and "`red-gate`" in body and "`green-gate`" in body
    assert "1 failed, 12 passed" in body


def test_it_says_it_is_a_draft_and_who_merges(session: Session, item: Item) -> None:
    body = evidence.pull_request_body(item, _green(session, item))

    assert "draft" in body
    assert "Nobody merges this but you" in body


# --- the outcomes that are not a pull request -------------------------------------------------


def test_not_reproducible_gets_a_comment_that_says_it_is_correct(
    session: Session, item: Item
) -> None:
    """DR-0003 calls it a first-class result, and a result nobody can see is not one."""
    attempt = start(session, item)
    record(session, attempt, AttemptPhase.RED_GATE, "pytest", exit_code=0, output="12 passed")
    finish(session, attempt, AttemptOutcome.NOT_REPRODUCIBLE, seal=SEAL)

    comment = evidence.issue_comment(item, attempt, detail="the candidate test passed")

    assert "could not be reproduced" in comment
    assert "correct outcome rather than a failure" in comment
    assert "one attempt" in comment


def test_an_abandoned_attempt_says_it_did_not_count(session: Session, item: Item) -> None:
    attempt = start(session, item)
    finish(session, attempt, AttemptOutcome.ABANDONED, not_consumed_reason="endpoint unreachable")

    comment = evidence.issue_comment(item, attempt)

    assert "did **not** use up the one attempt" in comment
    assert "endpoint unreachable" in comment


def test_already_fixed_says_there_is_something_to_deploy(session: Session, item: Item) -> None:
    attempt = start(session, item)
    finish(session, attempt, AttemptOutcome.ALREADY_FIXED)

    assert "something to deploy" in evidence.issue_comment(item, attempt)


# --- secrets, which is half the item ----------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "gto_abcdefghijklmnopqrstuvwxyz0123456789",
        "https://user:hunter2@errors.example.com/7",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ",
        "Bearer abcdefghijklmnopqrstuvwxyz012345",
    ],
)
def test_a_secret_in_captured_output_never_reaches_the_forge(
    session: Session, item: Item, secret: str
) -> None:
    """A suite that dumps the environment on failure is not a rare event."""
    attempt = start(session, item)
    record(
        session, attempt, AttemptPhase.GREEN_GATE, "pytest",
        exit_code=1, output=f"FAILED\nenv dump: TOKEN={secret}\n",
    )
    finish(session, attempt, AttemptOutcome.FAILED, seal=SEAL)

    body = evidence.pull_request_body(item, attempt, secrets=["a-known-value"])

    assert secret not in body


def test_a_known_credential_is_blanked_by_value(session: Session, item: Item) -> None:
    attempt = start(session, item)
    record(session, attempt, AttemptPhase.BASELINE, "pytest", exit_code=1,
           output="connecting with s3cret-forge-token")
    finish(session, attempt, AttemptOutcome.FAILED)

    body = evidence.pull_request_body(item, attempt, secrets=["s3cret-forge-token"])

    assert "s3cret-forge-token" not in body


def test_a_command_cannot_break_out_of_the_table(session: Session, item: Item) -> None:
    """The step table is markdown Hullwork's own account authors, same class as item 017's lanes."""
    attempt = start(session, item)
    record(session, attempt, AttemptPhase.BASELINE, "pytest | rm -rf / | echo", exit_code=1)
    finish(session, attempt, AttemptOutcome.FAILED)

    body = evidence.pull_request_body(item, attempt)

    assert "\\|" in body


def test_a_runaway_suite_cannot_produce_a_body_the_forge_refuses(
    session: Session, item: Item
) -> None:
    attempt = start(session, item)
    for phase in (AttemptPhase.BASELINE, AttemptPhase.RED_GATE, AttemptPhase.GREEN_GATE):
        record(session, attempt, phase, "pytest", exit_code=0, output="x" * 500_000)
    finish(session, attempt, AttemptOutcome.PR_OPEN, seal=SEAL)

    body = evidence.pull_request_body(item, attempt)

    assert len(body) <= evidence.MAX_BODY_CHARS + 100


def test_a_truncated_step_says_so(session: Session, item: Item) -> None:
    attempt = start(session, item)
    record(session, attempt, AttemptPhase.BASELINE, "pytest", exit_code=0, output="y" * 99_999)
    finish(session, attempt, AttemptOutcome.PR_OPEN, seal=SEAL)

    body = evidence.pull_request_body(item, attempt)

    assert "truncated when stored" in body


def test_the_tail_of_the_output_is_what_survives(session: Session, item: Item) -> None:
    """A test runner puts its verdict at the end; cutting the tail throws away the answer."""
    attempt = start(session, item)
    record(session, attempt, AttemptPhase.RED_GATE, "pytest", exit_code=1,
           output="start\n" + "z" * 20_000 + "\n1 failed in 4.2s")
    finish(session, attempt, AttemptOutcome.FAILED)

    body = evidence.pull_request_body(item, attempt)

    assert "1 failed in 4.2s" in body


# --- provenance findings go above the diff ----------------------------------------------------


def test_a_violation_is_shown_as_a_warning_not_a_footnote(session: Session, item: Item) -> None:
    seal = {
        **SEAL,
        "models_served": ["cheap-model"],
        "model_drift": True,
        "violations": [{"kind": "model-drift", "detail": "asked for big, cheap answered"}],
    }
    attempt = start(session, item)
    record(session, attempt, AttemptPhase.GREEN_GATE, "pytest", exit_code=0)
    finish(session, attempt, AttemptOutcome.PR_OPEN, seal=seal)

    body = evidence.pull_request_body(item, attempt)

    assert "[!warning]" in body
    assert body.index("model-drift") < body.index("### What ran")


# --- branch and commits -----------------------------------------------------------------------


def test_the_branch_is_namespaced_and_unique_per_attempt(session: Session, item: Item) -> None:
    """A second attempt reusing the branch would silently rewrite an open pull request."""
    first = start(session, item)
    second = start(session, item)

    assert evidence.branch_name(item, first).startswith("hullwork/")
    assert evidence.branch_name(item, first) != evidence.branch_name(item, second)


def test_the_first_commit_tells_you_to_check_it_out_and_watch_it_fail(item: Item) -> None:
    test_message, fix_message = evidence.commit_messages(item)

    assert test_message.startswith("test: reproduce ValueError")
    assert "expected to be red" in test_message
    assert fix_message.startswith("fix: ValueError")
    assert "smallest change" in fix_message


def test_every_outcome_has_something_to_say() -> None:
    """Every outcome yields a headline, at every phase it can occur at.

    Item 043's guarantee, asserted one level stronger since item 085. It used to check that every
    outcome had an entry in `_CLAIM`, which was a structural stand-in for the real property — and
    item 085 made the structure false on purpose: `failed` is deliberately absent from `_CLAIM`
    because it is two different sentences depending on the phase reached, chosen by `_claim`. The
    real property is that `_claim` never returns silence, so that is what is asserted, over the
    whole outcome-by-phase grid.
    """
    from hullwork.evidence import _claim

    silent = [
        (outcome.value, phase.value)
        for outcome in AttemptOutcome
        for phase in AttemptPhase
        if not _claim(
            Attempt(item_id=1, outcome=outcome, phase_reached=phase)
        ).strip()
    ]

    assert silent == []


def test_failed_at_the_red_gate_does_not_claim_a_reproduction() -> None:
    """**Measured on the live instance, attempt 13: the headline contradicted its own detail.**

    The first real dogfood bug failed at the red gate — the candidate broke two passing tests
    instead of reproducing anything — and the published comment opened with "The bug was
    reproduced" three lines above "the candidate test is not a reproduction". One sentence covered
    two different facts and lied about one of them. Item 085.
    """
    from hullwork.evidence import _claim

    at_red_gate = _claim(
        Attempt(item_id=1, outcome=AttemptOutcome.FAILED, phase_reached=AttemptPhase.RED_GATE)
    )
    assert "did not manage to reproduce" in at_red_gate
    assert "was reproduced and" not in at_red_gate

    # The other half must survive: failed past the red gate means the reproduction *stood*.
    past_it = _claim(
        Attempt(item_id=1, outcome=AttemptOutcome.FAILED, phase_reached=AttemptPhase.GREEN_GATE)
    )
    assert "The bug was reproduced" in past_it


# --- the artefact at a prompt (item 050) ---------------------------------------------------------


def _five_step_attempt(session: Session, item: Item) -> Attempt:
    """An attempt with the shape the measurement in DR-0006's amendment was taken on."""
    from hullwork import attempts as attempts_module

    attempt = start(session, item)
    noisy = "\n".join(f"tests/test_thing.py::test_{n} PASSED" for n in range(200))
    for phase, code in (
        (AttemptPhase.BASELINE, 0),
        (AttemptPhase.REPRODUCE, 0),
        (AttemptPhase.RED_GATE, 1),
        (AttemptPhase.FIX, 0),
        (AttemptPhase.GREEN_GATE, 0),
    ):
        attempts_module.record(
            session, attempt, phase, "pytest",
            exit_code=code, duration_ms=4200, output=noisy + "\n3 passed in 1.20s",
        )
    return attempts_module.finish(session, attempt, AttemptOutcome.PR_OPEN, seal=SEAL)


def test_the_terminal_report_fits_a_screen(session: Session, item: Item) -> None:
    """The measurement that motivated this item, turned into a test so it cannot come back.

    `pull_request_body` on this shape of attempt was 21,042 characters over 532 lines, with five
    `<details>` pairs that a terminal does not collapse.
    """
    attempt = _five_step_attempt(session, item)

    report = evidence.terminal_report(item, attempt, detail="a test that failed now passes")

    assert len(report.splitlines()) < 80
    assert "<details>" not in report


def test_the_terminal_report_carries_no_forge_only_text(session: Session, item: Item) -> None:
    """`Closes #42` means nothing locally, and neither does a sentence about drafts."""
    attempt = _five_step_attempt(session, item)

    report = evidence.terminal_report(item, attempt)

    assert "Closes" not in report
    assert "draft" not in report.lower()


def test_both_skins_quote_the_same_claim(session: Session, item: Item) -> None:
    """One assembly, two skins. A second copy of the claim would drift."""
    attempt = _five_step_attempt(session, item)

    body = evidence.pull_request_body(item, attempt)
    report = evidence.terminal_report(item, attempt)
    sentence = "A test that failed against unmodified code passes with this change applied."

    assert sentence in body.replace("**", "")
    assert sentence in report


def test_the_terminal_report_scrubs(session: Session, item: Item) -> None:
    """A terminal is not a safe place for a credential either."""
    from hullwork import attempts as attempts_module

    attempt = start(session, item)
    attempts_module.record(
        session, attempt, AttemptPhase.BASELINE, "pytest",
        exit_code=1, output="env: HULLWORK_FORGE_CODE_TOKEN=gto_secret_value_here",
    )
    attempts_module.finish(session, attempt, AttemptOutcome.FAILED)

    report = evidence.terminal_report(item, attempt, secrets=["gto_secret_value_here"])

    assert "gto_secret_value_here" not in report


def test_the_terminal_report_shows_refusals_and_a_refused_credential(
    session: Session, item: Item
) -> None:
    """The seal held both and the screen showed neither, which is half of item 056.

    A diagnosis that took four rounds had `refused_paths` sitting in the database the whole time.
    """
    from hullwork import attempts as attempts_module

    attempt = start(session, item)
    attempts_module.finish(
        session, attempt, AttemptOutcome.NOT_REPRODUCIBLE,
        seal={
            "models_served": [],
            "responses": 10,
            "statuses": {"401": 10},
            "completions": 0,
            "refused_paths": ["/v1/embeddings"],
            "violations": [],
        },
    )

    report = evidence.terminal_report(item, attempt)

    assert "401 x10" in report
    assert "/v1/embeddings" in report


def test_the_terminal_report_stays_quiet_when_the_wire_was_ordinary(
    session: Session, item: Item
) -> None:
    """Nothing to report costs nothing to read: a run where everything answered 200 says so by
    saying nothing, and the optional lines exist for the runs that need them."""
    attempt = _five_step_attempt(session, item)

    report = evidence.terminal_report(item, attempt)

    assert "answers" not in report
    assert "refused" not in report


def test_a_rehearsal_says_where_it_wrote(session: Session, item: Item, tmp_path: Path) -> None:
    """Through `finish`, not by setting the flag afterwards.

    Setting `rehearsal` by hand on a finished attempt produces a row saying the attempt was both
    spent and a rehearsal, and the report duly prints the contradiction — which is right: the
    invariant belongs to `finish` (item 049), and a renderer that tidied away inconsistent data
    would be hiding a bug in whatever wrote it.
    """
    from hullwork import attempts as attempts_module

    attempt = _five_step_attempt(session, item)
    attempts_module.finish(session, attempt, AttemptOutcome.PR_OPEN, rehearsal=True)
    where = str(tmp_path / "attempt-1")

    report = evidence.terminal_report(item, attempt, written_to=where)

    assert where in report
    assert "not spent" in report
    assert "rehearsal" in report


# --- what the agent was working from, outside its own prose. Item 100 ----------------------------


def test_the_artefact_says_how_much_evidence_the_brief_carried(
    session: Session, item: Item
) -> None:
    """**On attempt 20 the only mention of this was inside the agent's own prose.**

    The brief carried the issue title and nothing else — no exception type, no frames, no locals
    — and the agent said so honestly, in a collapsed block, in the middle of its report. So a
    reviewer who skimmed and one who read everything saw different documents, and only one of them
    knew they were looking at an inference rather than a located defect.

    First row of the provenance table, above the model and the image: what the agent had comes
    before what the agent did.
    """
    body = evidence.pull_request_body(
        item, _green(session, item), brief_evidence="the issue title only — the tracker was asked"
    )

    assert "| Evidence the agent had | the issue title only" in body
    # Above the model row, because a reviewer reads downward and this frames everything after it.
    assert body.index("Evidence the agent had") < body.index("Declared precision")


def test_an_artefact_with_nothing_to_say_about_evidence_grows_no_empty_row(
    session: Session, item: Item
) -> None:
    """The negative.

    A row saying nothing is worse than no row: it reads as "we checked and there was none" when the
    truth is that nobody passed it.
    """
    body = evidence.pull_request_body(item, _green(session, item))

    assert "Evidence the agent had" not in body
