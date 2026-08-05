"""The window the counts are read from. Item 117.

Found on production data while building item 116, not by reading the code:

```
acme#6, baseline step: 12,830 characters, exit 0
  what pytest said:   249 passed, 16 warnings in 64.90s
  what `read` said:   Counts(passed=None, failed=None, errors=None, aborted=False)
```

The suite prints alembic migration logs *after* pytest's summary — about a dozen lines of roughly a
thousand characters each — so the summary sat outside the last 4,000 characters while being well
inside the last dozen lines.

**The consequence is not a missing number.** The branch that catches a candidate which broke working
tests needs the baseline's counts, and skips itself when they are `None`; what a reviewer is told
instead is *"a clean reproduction"*.
"""

from __future__ import annotations

from hullwork import testoutput

#: The shape that was measured: few lines, each long. It defeats a byte window and not a line one.
EPILOGUE = "\n".join(
    f"INFO  [alembic.runtime.migration] Running upgrade {n:04d} -> {n + 1:04d}, {'x' * 1000}"
    for n in range(12)
)

BASELINE = f"........ [100%]\n========== 249 passed, 16 warnings in 64.90s ==========\n{EPILOGUE}"


def test_the_summary_survives_an_epilogue_that_defeats_a_byte_window() -> None:
    """The measurement, as an assertion. Both facts about the shape are asserted too, because a
    fixture that stopped having them would make this test pass for the wrong reason."""
    assert len(BASELINE) > 4_000, "outside the window that was there"
    assert len(BASELINE.splitlines()) < 20, "and inside any sane line window"

    assert testoutput.read(BASELINE).passed == 249


def test_a_candidate_that_broke_working_tests_is_caught_again() -> None:
    """**Why this is not cosmetic.** With the baseline unreadable, the survivors comparison skips
    itself and the verdict reads *"a clean reproduction"* — of a candidate that took 49 passing
    tests down with it. That is the exact confusion this module was written to end.
    """
    red = "========== 3 failed, 200 passed, 16 warnings in 61.02s =========="

    verdict = testoutput.judge_red_gate(BASELINE, red, red_failed=True)

    assert verdict.reproduced is False
    assert "249" in verdict.reason and "200" in verdict.reason
    assert verdict.from_exit_code_alone is False


def test_a_red_gate_summary_pushed_out_no_longer_costs_the_stronger_claim() -> None:
    """The other half: when it is the red gate's own summary that falls outside the window, nothing
    is `usable` and the verdict retreats to the exit code — on a run that printed the counts."""
    red = f"========== 2 failed, 249 passed in 60.11s ==========\n{EPILOGUE}"

    verdict = testoutput.judge_red_gate(BASELINE, red, red_failed=True)

    assert verdict.from_exit_code_alone is False
    assert "still pass" in verdict.reason, "the survivors, which is the strongest thing to say"


def test_the_last_summary_still_wins_when_a_runner_prints_several() -> None:
    """The property the byte window was protecting, and it has to survive the wider one: runners
    print a per-file line and then a total, and the total is the answer."""
    output = "tests/test_a.py 3 passed\ntests/test_b.py 4 passed\n===== 7 passed in 1.20s ====="

    assert testoutput.read(output).passed == 7


def test_the_window_is_still_a_window() -> None:
    """A runner that prints a megabyte is not scanned in full. The counts of a run whose summary is
    two hundred thousand characters and ten thousand lines ago are honestly unknown."""
    buried = "===== 5 passed in 0.10s =====\n" + "\n".join(f"line {n}" for n in range(10_000))

    assert testoutput.read(buried).passed is None


def test_widening_the_counts_did_not_widen_the_abort_phrases() -> None:
    """**Deliberately asymmetric.** The abort phrases are substring matches and `SyntaxError` is one
    of them, so a wider window would turn any run whose traceback prints that word — a test
    asserting one is raised, for instance — into "the candidate is broken", which throws away a good
    reproduction. The counts needed the room; these did not ask for it.

    It cuts both ways and that is accepted with open eyes: a *genuine* collection abort buried under
    the same epilogue is still missed, and it costs a run that would have been called broken being
    called unreadable instead. Of the two errors, that is the one that does not discard work.
    """
    summary = "===== 1 failed, 30 passed in 2.00s ====="
    output = f"E   SyntaxError: invalid syntax\n{EPILOGUE}\n{summary}"
    assert len(EPILOGUE) > 4_000, "the word is outside the abort window and inside the count one"

    counts = testoutput.read(output)

    assert counts.passed == 30, "the counts see past the traceback"
    assert counts.aborted is False, "and the abort test does not reach back to it"
