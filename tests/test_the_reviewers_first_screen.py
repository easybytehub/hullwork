"""What a reviewer reads before unfolding anything. Item 136, M12.

Three facts this instance already knew and put where nobody reading would find them: the seal inside
a collapsed block, the money on one surface and not the other, and the credential split explained to
whoever reads the source.
"""

from datetime import UTC, datetime, timedelta

from hullwork import page, spend
from hullwork.models import Attempt, AttemptOutcome, AttemptPhase

SEAL = {
    "endpoint": "https://api.anthropic.com",
    "models_served": ["claude-opus-5"],
    "input_tokens": 1_807,
    "output_tokens": 9_364,
    "cache_write_tokens": 40_000,
    "cache_read_tokens": 900_000,
}


def _attempt(seal: dict[str, object] | None = None) -> Attempt:
    started = datetime(2026, 8, 3, 9, tzinfo=UTC)
    return Attempt(
        id=1,
        item_id=1,
        started_at=started,
        finished_at=started + timedelta(seconds=775),
        phase_reached=AttemptPhase.PUBLISH,
        outcome=AttemptOutcome.PR_OPEN,
        consumed=True,
        seal=SEAL if seal is None else seal,
    )


def test_the_model_and_the_endpoint_need_no_click() -> None:
    """**DR-0004's whole argument**, and the one claim a reviewer cannot check any other way: the
    gateway read it off the wire rather than taking the harness's word. Item 123 put it on the page
    inside the artefact — correctly — and left it seven rows down behind a `<details>`."""
    header = page._above_the_fold(_attempt(), None)

    assert "claude-opus-5" in header
    assert "api.anthropic.com" in header
    assert "<details" not in header


def test_the_money_appears_when_the_operator_has_priced_it() -> None:
    """`page.artefact()` did not pass `prices`, so the page showed tokens and the pull request body
    showed a figure — two surfaces rendering one function and disagreeing."""
    priced = page._above_the_fold(_attempt(), spend.Prices(input=3.0, output=15.0))

    assert "cost" in priced and "USD" in priced


def test_without_prices_it_says_the_tokens_rather_than_nothing() -> None:
    """An absence with a number in it. A blank reads as free."""
    header = page._above_the_fold(_attempt(), None)

    assert "941,807 tokens served" in header, "input + cache write + cache read"
    assert "USD" not in header


def test_the_duration_is_there_because_cost_alone_cannot_be_judged() -> None:
    assert "12m 55s" in page._above_the_fold(_attempt(), None)


def test_an_attempt_that_reached_no_model_says_so_beside_its_clock() -> None:
    """**A duration on its own is the shape of a hung attempt** (item 133: three hours forty-seven
    minutes, no seal at all). The clock without the reason invites a reader to call it work."""
    header = page._above_the_fold(_attempt(seal={}), None)

    assert "no model answered" in header
    assert "12m 55s" in header


def test_everything_in_the_header_is_escaped() -> None:
    """An endpoint and a model name are strings from somebody else's configuration, and this page
    has no template engine on purpose (principle 6)."""
    hostile = _attempt(
        seal={
            "endpoint": "https://evil.example/<script>alert(1)</script>",
            "models_served": ['"><img src=x onerror=alert(1)>'],
        }
    )

    header = page._above_the_fold(hostile, None)

    # The tags, not the attribute text: `onerror=` inside escaped text is inert, and asserting on
    # the substring would fail a correct page and teach the next reader the wrong rule.
    assert "<script" not in header
    assert "<img" not in header
    assert "&lt;script&gt;" in header

