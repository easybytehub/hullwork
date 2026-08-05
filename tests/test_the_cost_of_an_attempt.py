"""What an attempt cost, and the field that was not being read. Item 133.

The defect this covers came out of reading instance A's twenty stored seals: an attempt with 31
model responses recorded **936 input tokens**, which cannot happen to an agent that accumulates
context.

`usage.input_tokens` counts only the input billed at full rate; the cached remainder — almost all of
it — sat in two fields nobody read, and the artefact called the number `Context served`.

Every payload below is the shape the providers document, and the arithmetic is checked against
numbers taken from that live instance rather than invented.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest

from hullwork import spend
from hullwork.config import Settings
from hullwork.gateway import Recording
from hullwork.gateway.protocols import AnthropicReader, OpenAIReader
from hullwork.models import Attempt, AttemptOutcome, AttemptPhase
from hullwork.scrub import Scrubber

#: Anthropic's four counts, as its documentation describes them: two siblings of `input_tokens`.
ANTHROPIC_USAGE = {
    "input_tokens": 936,
    "output_tokens": 25_066,
    "cache_creation_input_tokens": 120_000,
    "cache_read_input_tokens": 4_200_000,
}


def _anthropic(usage: dict[str, int]) -> bytes:
    return json.dumps(
        {"model": "claude-opus-5", "usage": usage, "stop_reason": "end_turn"}
    ).encode()


# --- the two fields nobody was reading ------------------------------------------------------------


def test_the_cached_context_is_read_and_kept_apart_from_the_charged_input() -> None:
    """**The item.** The bulk of the context sits in the two cache fields, billed at different rates
    from `input_tokens`, so they are recorded separately rather than added in."""
    observed = AnthropicReader().read_json(_anthropic(ANTHROPIC_USAGE))

    assert observed is not None
    assert observed.input_tokens == 936, "the input charged at full rate, unchanged"
    assert observed.cache_write_tokens == 120_000
    assert observed.cache_read_tokens == 4_200_000


def test_a_provider_that_says_nothing_about_caching_reports_none_and_never_zero() -> None:
    """`None` and `0` are different facts: one is unmeasured, the other is a measurement. A zero
    would make every cost computed from it confidently too low."""
    observed = AnthropicReader().read_json(
        _anthropic({"input_tokens": 936, "output_tokens": 25_066})
    )

    assert observed is not None
    assert observed.cache_write_tokens is None
    assert observed.cache_read_tokens is None


def test_the_openai_family_reports_cache_reads_one_level_down() -> None:
    """The nesting is the trap: `usage.get("cached_tokens")` reads `None` for ever against a
    provider that puts the number in `prompt_tokens_details`. And this family has no cache-write
    count at all, so none is invented."""
    body = json.dumps(
        {
            "model": "gpt-9",
            "choices": [{"finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 8_000,
                "completion_tokens": 400,
                "prompt_tokens_details": {"cached_tokens": 7_680},
            },
        }
    ).encode()

    observed = OpenAIReader().read_json(body)

    assert observed is not None
    assert observed.cache_read_tokens == 7_680
    assert observed.cache_write_tokens is None, "this family does not report one"


# --- the seal -------------------------------------------------------------------------------------


def test_the_seal_reports_four_counts() -> None:
    recording = Recording(endpoint="https://api.anthropic.com", pinned_model="claude-opus-5")
    reader = AnthropicReader()
    for _ in range(2):
        observed = reader.read_json(_anthropic(ANTHROPIC_USAGE))
        assert observed is not None
        recording.observe(observed)

    sealed = recording.seal()

    assert sealed["input_tokens"] == 1_872
    assert sealed["output_tokens"] == 50_132
    assert sealed["cache_write_tokens"] == 240_000
    assert sealed["cache_read_tokens"] == 8_400_000


def test_a_seal_whose_responses_never_mentioned_caching_says_so() -> None:
    """The distinction survives into the stored seal, which is what a reader consults months
    later."""
    recording = Recording(endpoint="https://api.anthropic.com")
    observed = AnthropicReader().read_json(
        _anthropic({"input_tokens": 936, "output_tokens": 25_066})
    )
    assert observed is not None
    recording.observe(observed)

    sealed = recording.seal()

    assert sealed["cache_write_tokens"] is None
    assert sealed["cache_read_tokens"] is None


def test_the_new_names_are_not_redacted_as_secrets() -> None:
    """Item 057, one field name later: the scrubber redacts anything whose name contains `token`, so
    a count added without touching `MEASUREMENTS` becomes `***` in the logs and the seal stops being
    readable. That happened once already, to `input_tokens`."""
    scrubbed = Scrubber([], shapes=True).scrub(
        {"cache_read_tokens": 4_200_000, "cache_write_tokens": 120_000}
    )

    assert scrubbed["cache_read_tokens"] == 4_200_000
    assert scrubbed["cache_write_tokens"] == 120_000


# --- money, and only when somebody said what they pay ---------------------------------------------


def test_no_prices_configured_means_no_money_anywhere() -> None:
    """DR-0004: no price table ships. An instance that guessed would print a wrong number, which is
    worse than printing tokens."""
    assert spend.Prices.from_settings(Settings()) is None
    assert spend.cost_of(spend.tokens_of({"input_tokens": 936}), None) is None


def test_the_cost_is_the_four_counts_at_their_four_rates() -> None:
    """Arithmetic against the live instance's own numbers, at list prices for a large model."""
    prices = spend.Prices(input=3.0, output=15.0, cache_write=3.75, cache_read=0.30)
    tokens = spend.tokens_of(
        {
            "input_tokens": 936,
            "output_tokens": 25_066,
            "cache_write_tokens": 120_000,
            "cache_read_tokens": 4_200_000,
        }
    )

    money = spend.cost_of(tokens, prices)

    assert money is not None
    assert money.partial is False
    expected = (936 * 3.0 + 25_066 * 15.0 + 120_000 * 3.75 + 4_200_000 * 0.30) / 1_000_000
    assert money.amount == pytest.approx(expected)


def test_a_figure_missing_a_price_says_which_one() -> None:
    """**The half-priced instance.** An operator who priced input and output and not the cache gets
    a number computed from two of four counts, and a total presented as whole would be the same
    class of defect this item exists to fix."""
    tokens = spend.tokens_of(
        {"input_tokens": 936, "output_tokens": 25_066, "cache_read_tokens": 4_200_000}
    )

    money = spend.cost_of(tokens, spend.Prices(input=3.0, output=15.0))

    assert money is not None and money.partial is True
    assert "cache_read_tokens" in str(money)


def test_context_served_is_the_sum_and_input_tokens_is_not() -> None:
    """The two numbers the artefact now keeps apart. On this attempt they differ 4,600-fold."""
    tokens = spend.tokens_of(
        {
            "input_tokens": 936,
            "output_tokens": 25_066,
            "cache_write_tokens": 120_000,
            "cache_read_tokens": 4_200_000,
        }
    )

    assert tokens.input == 936
    assert tokens.context_served == 4_320_936


def test_an_old_seal_still_reads_and_declares_what_it_cannot_say() -> None:
    """Every seal stored before this item. Two keys absent is not two zeros."""
    tokens = spend.tokens_of({"input_tokens": 936, "output_tokens": 25_066})

    assert tokens.reported is True
    assert tokens.caching_unreported is True
    assert tokens.context_served == 936, "all that can be said from what was stored"


# --- time, which is only readable next to the spend -----------------------------------------------


def _attempt(
    *, seconds: int | None, seal: dict[str, object] | None, consumed: bool = True
) -> Attempt:
    started = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)
    return Attempt(
        id=1,
        item_id=1,
        started_at=started,
        finished_at=started + timedelta(seconds=seconds) if seconds is not None else None,
        phase_reached=AttemptPhase.PUBLISH,
        outcome=AttemptOutcome.PR_OPEN,
        consumed=consumed,
        seal=seal or {},
    )


def test_a_running_attempt_has_no_duration_rather_than_a_wrong_one() -> None:
    assert spend.elapsed(_attempt(seconds=None, seal={})) is None
    assert spend.spoken(None) == "—"


def test_the_hung_attempt_is_visible_as_time_without_spend() -> None:
    """**Attempt 18 on the live instance**: three hours forty-seven minutes, no seal at all, because
    the dispatcher was stopped mid-attempt (item 097). It is counted apart rather than averaged in —
    a mean that includes it describes no attempt that ever ran."""
    hung = _attempt(seconds=13_600, seal=None)
    worked = _attempt(seconds=775, seal={"input_tokens": 1_807, "output_tokens": 9_364})

    summary = spend.per_instance([hung, worked], None)

    assert summary.measured == 1, "only the one that reached a model"
    assert summary.no_model_answered == 1
    assert summary.slowest == timedelta(seconds=775), "the hung one is not the slowest attempt"


def test_the_invoice_includes_rehearsals_and_the_per_attempt_figure_does_not() -> None:
    """Item 119's rule applied to money: a rehearsal calls a model and publishes nothing, so it is
    on the bill and is not what "an attempt costs" means."""
    priced = spend.Prices(input=3.0, output=15.0)
    real = _attempt(seconds=600, seal={"input_tokens": 1_000, "output_tokens": 10_000})
    rehearsal = _attempt(seconds=600, seal={"input_tokens": 1_000, "output_tokens": 10_000},
                         consumed=False)

    summary = spend.per_instance([real, rehearsal], priced)

    assert summary.measured == 2
    assert summary.fair_try == 1
    assert summary.total_cost is not None and summary.fair_try_cost is not None
    assert summary.total_cost.amount == pytest.approx(2 * summary.fair_try_cost.amount)


def test_nothing_measured_prints_nothing_rather_than_zeros() -> None:
    """`outcomes.lines`'s rule: a row of zeros reads as free, which is a claim. Silence is not."""
    assert spend.lines(spend.per_instance([], None)) == []


def test_without_prices_the_report_says_why_there_is_no_money() -> None:
    """An absence with a reason, and it names the setting that fills it."""
    said = " ".join(
        spend.lines(
            spend.per_instance(
                [_attempt(seconds=600, seal={"input_tokens": 1_000, "output_tokens": 10_000})],
                None,
            )
        )
    )

    assert "no prices configured" in said
    assert "HULLWORK_MODEL_PRICE_INPUT" in said


def test_a_duration_reads_as_a_person_would_say_it() -> None:
    assert spend.spoken(timedelta(seconds=54)) == "54s"
    assert spend.spoken(timedelta(seconds=775)) == "12m 55s"
    assert spend.spoken(timedelta(seconds=13_600)) == "3h 46m"


def test_a_figure_built_from_old_seals_says_it_is_a_floor() -> None:
    """**Found by running the aggregate against the twenty real attempts.** Every seal stored before
    this item lacks the cache counts, so the money computed from them is too low — and unlike a
    missing price, it cannot be fixed later: the tokens were never recorded. A number that
    reassuring, presented plainly, would repeat the defect this item removed.
    """
    old = _attempt(seconds=600, seal={"input_tokens": 936, "output_tokens": 25_066})

    summary = spend.per_instance([old], spend.Prices(input=3.0, output=15.0))
    said = " ".join(spend.lines(summary))

    assert summary.caching_unreported == 1
    assert "no cached context" in said
    assert "floor" in said


def test_a_seal_of_zeros_is_not_traffic() -> None:
    """**Found by deploying it.** An attempt that never reached a model still stores a seal, with
    `input_tokens: 0` and `responses: 0` — a measurement of nothing. Built on "did the seal say
    anything", the summary announced *19 attempts with model traffic* about an instance where eleven
    had any. The zeros are honest; the label was not.
    """
    never_reached = _attempt(
        seconds=61, seal={"input_tokens": 0, "output_tokens": 0, "responses": 0}
    )
    answered = _attempt(seconds=775, seal={"input_tokens": 1_807, "output_tokens": 9_364})

    summary = spend.per_instance([never_reached, answered], None)

    assert summary.measured == 1, "one attempt had traffic"
    assert summary.no_model_answered == 1
    assert "never reached a model" in " ".join(spend.lines(summary))
