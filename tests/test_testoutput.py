"""Telling a reproduction apart from a broken test (spec §3.1, closed).

Both of these are "the command exited non-zero", which is all the red gate could see before, and the
dogfood produced both on the way to a single pull request.
"""

import pytest

from hullwork.testoutput import judge_red_gate, read

BASE = "..                                        [100%]\n2 passed in 0.01s"
REPRO = "F..                                       [100%]\n1 failed, 2 passed in 0.02s"
COLLECTION = "!!!! Interrupted: 1 error during collection !!!!\n1 error in 0.06s"


def test_a_clean_reproduction_is_recognised() -> None:
    """The real one from the dogfood: one new failure, the other tests still green."""
    verdict = judge_red_gate(BASE, REPRO, red_failed=True)

    assert verdict.reproduced
    assert not verdict.from_exit_code_alone
    assert "clean reproduction" in verdict.reason
    assert "2 test(s) that passed before still pass" in verdict.reason


def test_a_collection_error_is_not_a_reproduction() -> None:
    """The other real one: the candidate does not import, so nothing ran."""
    verdict = judge_red_gate(BASE, COLLECTION, red_failed=True)

    assert not verdict.reproduced
    assert "aborted before the tests executed" in verdict.reason


def test_breaking_the_other_tests_is_not_a_reproduction() -> None:
    """The survivors are the signal, and this is why."""
    verdict = judge_red_gate(BASE, "FF.\n2 failed, 1 passed in 0.02s", red_failed=True)

    assert not verdict.reproduced
    assert "broke tests that were working" in verdict.reason


def test_an_error_rather_than_a_failure_is_not_a_reproduction() -> None:
    verdict = judge_red_gate(BASE, "1 error, 2 passed in 0.02s", red_failed=True)

    assert not verdict.reproduced
    assert "error(s) rather than a clean test failure" in verdict.reason


def test_a_command_that_failed_with_no_failing_test_is_not_a_reproduction() -> None:
    """`pytest` exiting non-zero with everything green means something else went wrong."""
    verdict = judge_red_gate(BASE, "3 passed in 0.02s\nERROR: coverage below threshold",
                             red_failed=True)

    assert not verdict.reproduced
    assert "no test did" in verdict.reason


def test_an_unreadable_runner_falls_back_and_says_so() -> None:
    """A framework nobody here has met is not a reason to refuse; pretending to know would be."""
    verdict = judge_red_gate("all good", "something went wrong", red_failed=True)

    assert verdict.reproduced
    assert verdict.from_exit_code_alone
    assert "rests on the exit code alone" in verdict.reason


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("1 failed, 2 passed in 0.02s", (2, 1, None)),
        ("3 passed in 0.01s", (3, None, None)),
        ("1 error in 0.06s", (None, None, 1)),
        ("5 failed, 10 passed, 2 errors in 1.2s", (10, 5, 2)),
        ("nothing recognisable", (None, None, None)),
    ],
)
def test_counts_are_read_from_the_summary(
    output: str, expected: tuple[int | None, int | None, int | None]
) -> None:
    counts = read(output)

    assert (counts.passed, counts.failed, counts.errors) == expected


def test_the_last_summary_wins_over_per_file_lines() -> None:
    """Runners print per-file progress and then a summary; the summary is the answer."""
    counts = read("tests/a.py 1 passed\ntests/b.py 1 passed\n\n2 passed in 0.1s")

    assert counts.passed == 2
