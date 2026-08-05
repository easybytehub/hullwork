"""What an operator may set and a reviewer may read. Item 137, M12.

Three questions somebody evaluating this for a team asks before connecting a repository, and
until this item none of them had an answer in the product.
"""


import pytest

from hullwork.config import Settings
from hullwork.doctor import policies
from hullwork.gateway import Recording
from hullwork.gateway.protocols import Observation
from hullwork.work import _allowed_models

# --- the ceiling ---------------------------------------------------------------------------------


def test_spending_is_one_number_where_the_seal_keeps_four() -> None:
    """Deliberately different acts: the seal keeps the billing categories apart because they are
    priced apart, and a ceiling is a stop that needs one quantity to compare."""
    recording = Recording(endpoint="x", max_tokens=1_000)
    recording.observe(
        Observation(input_tokens=100, output_tokens=200, cache_write_tokens=300,
                    cache_read_tokens=400)
    )

    assert recording.spent == 1_000
    assert recording.over_budget is True


def test_no_ceiling_means_nothing_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every instance that has ever run has no ceiling, and none of them may behave differently."""
    recording = Recording(endpoint="x")
    recording.observe(Observation(input_tokens=10_000_000))

    assert recording.over_budget is False
    assert Settings().max_attempt_tokens is None


def test_the_seal_records_the_ceiling_and_the_spend() -> None:
    """Evidence rather than a setting printed for tidiness: an attempt stopped by a ceiling looks
    like an abandoned one, and this is the difference."""
    recording = Recording(endpoint="x", max_tokens=500)
    recording.observe(Observation(output_tokens=600))

    sealed = recording.seal()

    assert sealed["max_tokens"] == 500
    assert sealed["tokens_spent"] == 600


# --- the allowlist -------------------------------------------------------------------------------


def test_an_allowed_model_answering_is_not_drift() -> None:
    """A different question from the pinned model: what may *answer*, not what is *asked for*."""
    recording = Recording(endpoint="x", pinned_model="opus", allowed_models=("sonnet",))

    recording.observe(Observation(model="sonnet"))

    assert recording.violations == []


def test_an_unlisted_model_is_still_a_violation() -> None:
    """DR-0002 untouched where the operator said nothing."""
    recording = Recording(endpoint="x", pinned_model="opus", allowed_models=("sonnet",))

    recording.observe(Observation(model="something-else"))

    assert [v.kind for v in recording.violations] == ["model-drift"]


def test_an_empty_allowlist_keeps_the_pinned_rule_exactly() -> None:
    recording = Recording(endpoint="x", pinned_model="opus")

    recording.observe(Observation(model="sonnet"))

    assert [v.kind for v in recording.violations] == ["model-drift"]


def test_the_allowlist_is_parsed_from_one_string() -> None:
    parsed = _allowed_models(Settings(model_allowed=" sonnet , kimi-k2 ,, "))

    assert parsed == ("sonnet", "kimi-k2"), "trimmed, and empties dropped"


# --- concurrency, which is stated rather than built ----------------------------------------------


def test_concurrency_is_declared_as_one_with_its_reason_and_its_alternative() -> None:
    """**The finding is that it is already one.** `lease.py` exists so exactly one dispatcher
    runs against one database, and a turn of that loop is a whole attempt — so one at a time is the
    design, not a limit waiting to be raised. Building parallelism nobody asked for is what DR-0013
    rules out; saying the number, and what to do for more, is the policy."""
    said = policies(Settings()).detail

    assert "attempts at once: 1" in said
    assert "lease" in said
    assert "HULLWORK_INSTANCE" in said, "the alternative, named"


def test_the_policies_say_what_is_set_and_what_is_not() -> None:
    open_instance = policies(Settings()).detail
    closed = policies(
        Settings(max_attempt_tokens=2_000_000, model_name="opus", model_allowed="sonnet")
    ).detail

    assert "none set" in open_instance
    assert "2,000,000 tokens" in closed
    assert "any of: sonnet" in closed


# --- the decision the ceiling makes about the item -----------------------------------------------


def test_the_ceiling_does_not_spend_the_items_one_attempt() -> None:
    """**The decision this item is built on.** DR-0003's accounting asks whether the *agent* could
    fix the bug; one cut off mid-flight by the operator's own budget never got to be right or
    wrong. A ceiling that silently spent items is one nobody would dare set."""
    from hullwork.models import AttemptOutcome
    from hullwork.work import ceiling_stopped

    recording = Recording(endpoint="x", max_tokens=100)
    recording.observe(Observation(output_tokens=500))

    reason = ceiling_stopped(recording, AttemptOutcome.FAILED)

    assert reason is not None
    assert "500 tokens" in reason and "100" in reason
    assert "does not count against the item" in reason


def test_a_published_pull_request_survives_its_own_last_call() -> None:
    """Crossing the ceiling after the work is published is not a stopped attempt, and discarding it
    would be the ceiling destroying the thing it exists to protect."""
    from hullwork.models import AttemptOutcome
    from hullwork.work import ceiling_stopped

    recording = Recording(endpoint="x", max_tokens=100)
    recording.observe(Observation(output_tokens=500))

    assert ceiling_stopped(recording, AttemptOutcome.PR_OPEN) is None


def test_without_a_ceiling_nothing_is_ever_stopped() -> None:
    from hullwork.models import AttemptOutcome
    from hullwork.work import ceiling_stopped

    recording = Recording(endpoint="x")
    recording.observe(Observation(output_tokens=10_000_000))

    assert ceiling_stopped(recording, AttemptOutcome.FAILED) is None
