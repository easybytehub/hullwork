"""The instance report's counts are figures in a column. DR-0028, item 248.

Six sections of prose bullets were 500 of this view's 779 words, and every bullet was **a number
with a sentence wrapped around it**. A reader comparing this week to last had to parse eight of them
to find two figures — and the one section that was already a two-column table is the one that reads
at a glance.

What is under test is that nothing was lost on the way: every count and every caveat the sentences
carried is still on the page, and the skin that renders them agrees with the one the terminal
prints. Two skins of one structure is the item 050 pattern; two *computations* is what comes apart.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import pytest

from hullwork import outcomes, page
from hullwork.models import AttemptOutcome


def _desk(**fields: int) -> outcomes.Desk:
    return outcomes.Desk(**fields)


class TestAFigureAndWhatItCounts:
    def test_the_count_is_its_own_column(self) -> None:
        shown = page._figures([(28, "claims arrived", "")])

        assert '<td class="fig">28</td>' in shown
        assert "claims arrived" in shown

    def test_the_caveat_is_under_the_meaning_not_inside_it(self) -> None:
        """*3 baseline-red, 2 abandoned* used to be the second half of the same sentence, which is
        where a reader looking for the number has to read past it."""
        shown = page._figures([(5, "never counted against an item", "3 baseline-red")])

        assert '<span class="caveat">3 baseline-red</span>' in shown

    def test_no_rows_is_no_table(self) -> None:
        """Silence rather than an empty frame: `desk_lines`'s own rule, and the two skins have to
        agree on it or one of them reports a beginning as a failure."""
        assert page._figures([]) == ""

    def test_it_sits_in_a_container_that_scrolls_on_its_own(self) -> None:
        """Item 215's rule about every table on this page, and a two-column table being unable to
        overflow is a reason to believe it rather than to exempt it."""
        assert '<div class="wide">' in page._figures([(1, "a thing", "")])


class TestNothingTheSentencesCarriedIsLost:
    def test_every_figure_the_desk_reports_is_on_the_page(self) -> None:
        """**The two skins are checked against each other**, which is what keeps them from drifting
        without duplicating the arithmetic: every number the terminal prints has to be a figure."""
        counted = _desk(
            arrived=28, left_with_evidence=6, with_a_change=4, with_a_refusal=2,
            still_waiting=20, handed_over=2,
        )

        shown = page._desk_figures(counted)
        spoken = " ".join(outcomes.desk_lines(counted))

        for number in ("28", "20", "6", "4", "2"):
            assert number in shown, f"{number} is in the sentences and not in the figures"
        assert "28" in spoken

    def test_the_figure_that_can_embarrass_it_keeps_its_words(self) -> None:
        """*Put on* a desk rather than taken off it. Rounding this into good news is exactly how a
        report stops being one."""
        shown = page._desk_figures(_desk(arrived=3, handed_over=2))

        assert "went onto your desk rather than off it" in shown
        assert "red lane, or a pull request somebody read and refused" in shown

    def test_nothing_arrived_is_nothing_rendered(self) -> None:
        assert page._desk_figures(_desk()) == ""

    def test_the_funnel_keeps_its_denominator_and_its_exclusions(self) -> None:
        counted = outcomes.Funnel(
            fair_try=6, pull_requests=4, merged=4, not_reproducible=1, failed=1,
            rehearsals=10,
            never_counted={
                AttemptOutcome.BASELINE_RED: 3, AttemptOutcome.ABANDONED: 2,
            },
        )

        shown = page._funnel_figures(counted)

        assert "attempts got a fair try" in shown
        assert "of those 4 pull request(s) were merged" in shown
        assert "baseline-red" in shown and "abandoned" in shown
        # Rehearsals publish nothing, and an instance that has only rehearsed has done work that
        # produced no forge state to count. Dropping them reads as an instance that did nothing.
        assert "rehearsals" in shown

    def test_a_percentage_is_never_printed(self) -> None:
        """Item 119: four attempts are not a rate, and a percentage invites comparing instances
        running different code over different repositories."""
        shown = page._funnel_figures(
            outcomes.Funnel(fair_try=6, pull_requests=4, merged=4)
        )

        assert "%" not in shown


class TestWhatStaysProse:
    @pytest.mark.parametrize(
        "line", ["median time from first error to decision: 2h 1m"]
    )
    def test_a_duration_is_not_forced_into_a_column(self, line: str) -> None:
        """A figure goes in the column; prose that is genuinely prose stays prose. A median in a
        column of counts is a number that cannot be compared with the ones above it."""
        shown = page._review_figures(outcomes.Reviewed(merged=4), [line])

        assert '<td class="fig">4</td>' in shown
        assert line in shown
        assert f'<td class="fig">{line}' not in shown
