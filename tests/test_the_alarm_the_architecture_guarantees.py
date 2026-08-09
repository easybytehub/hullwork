"""What `status` may claim about a credential it cannot see. Item 193.

Found on the live instance: a healthy deployment reporting a permanent degradation, in a sentence
where every clause was false. `hullwork status` runs in the receiver, DR-0005 requires the receiver
not to hold `HULLWORK_FORGE_CODE_TOKEN`, and the note read that absence as *nothing will ever pick
them up* — a claim about a **different process**, which had the credential all along.

`doctor.py` had solved this and `work.py` never learnt it. Item 073, in `doctor`'s own words: *a
signal that is permanently on is not a signal, and the day the credential really expires that line
is already red.*

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from sqlalchemy.orm import Session
from test_work import _item, _project

from hullwork import lease, work
from hullwork.models import ItemState


def _a_dispatcher_is_alive(session: Session) -> None:
    """The state the receiver is in whenever the deployment is working."""
    lease.acquire(session, lease.new_holder())


# --- the claim that could not be true ----------------------------------------------------------


def test_a_live_dispatcher_means_the_missing_credential_is_not_this_process_business(
    session: Session,
) -> None:
    """The whole finding. The receiver never holds this credential **by design**, so reading its own
    environment and announcing a consequence for another process is not a diagnosis.

    Measured on `atlas`, 2026-08-09: this note said nothing would ever pick the item up while
    `docker exec hullwork-dispatcher-1 hullwork doctor` said `ok code token → hullwork`.
    """
    _item(session, _project(session))
    _a_dispatcher_is_alive(session)

    notes = work.readiness_notes(session, code_token_configured=False)

    assert not any(n.degraded for n in notes), (
        "a healthy instance reported a degradation, which is how this was found"
    )
    said = " ".join(n.text for n in notes)
    assert "nothing will ever pick them up" not in said


def test_it_says_where_the_question_can_be_answered_rather_than_going_quiet(
    session: Session,
) -> None:
    """Not silence. Downgrading a false alarm into nothing loses a real question — *does the
    dispatcher have it?* — and the operator is the one who can go and ask."""
    _item(session, _project(session))
    _a_dispatcher_is_alive(session)

    said = " ".join(n.text for n in work.readiness_notes(session, code_token_configured=False))

    assert "dispatcher" in said
    assert "cannot" in said or "not from here" in said


def test_with_no_dispatcher_alive_the_degradation_is_kept_exactly(session: Session) -> None:
    """The true positive, and the reason the branch cannot simply be deleted.

    `doctor.py:956`: *with no dispatcher alive, nothing is downgraded — the absence of one is
    exactly when somebody needs to know what is missing.* This is also the shape `hullwork work`
    runs in, where the credential question is genuinely local and the answer must still exit 1.
    """
    _item(session, _project(session))

    notes = work.readiness_notes(session, code_token_configured=False)

    assert any("nothing will ever pick them up" in n.text for n in notes)
    assert any(n.degraded for n in notes)


def test_a_stale_lease_is_not_a_live_dispatcher(session: Session) -> None:
    """A dispatcher that died holding the lease must not silence the alarm for ever — that would
    turn one permanently-on signal into one permanently-off, which is worse."""
    _item(session, _project(session))
    _a_dispatcher_is_alive(session)
    lease.release(session, lease.holder_of(session) or "")

    notes = work.readiness_notes(session, code_token_configured=False)

    assert any(n.degraded for n in notes)


# --- the second defect in the same sentence -----------------------------------------------------


def test_an_item_of_an_inactive_project_is_not_counted_as_ready(session: Session) -> None:
    """The exact shape that produced the alarm: project `simplecheck`, `active = 0`, holding one
    item in `ready` that had already opened a pull request on 2026-07-30.

    A count that includes work nobody intends to do turns every other sentence built on it into a
    guess.
    """
    _item(session, _project(session, active=False, slug="parked"))

    said = " ".join(n.text for n in work.readiness_notes(session, code_token_configured=True))

    assert "ready for the dispatcher" not in said


def test_status_counts_exactly_what_the_dispatcher_would_attempt(session: Session) -> None:
    """**Asserted by construction**, because two lists of conditions kept equal by hand is what
    produced a four-condition drift in the first place.

    `eligible()` applies six conditions; this note applied two. Any future condition added to the
    dispatcher has to reach this sentence without anybody remembering to come here.

    **Two eligible items, not one**, and that is deliberate. `eligible` hands work out one at a time
    and defaults to `limit=1`; with a single eligible item this test passes against a count that
    stops at the first, which would report `1 item(s) are ready` on an instance with fifty.
    """
    live = _project(session, slug="live")
    first = _item(session, live)
    second = _item(session, live, fingerprint="fp2")
    _item(session, _project(session, active=False, slug="parked"), fingerprint="fp3")
    _item(session, _project(session, slug="done"), state=ItemState.DONE, fingerprint="fp4")

    counted = work.ready_for_the_dispatcher(session)

    assert [e.item.id for e in counted] == [first.id, second.id]
    assert [e.item.id for e in counted] == [e.item.id for e in work.eligible(session, limit=1000)]
