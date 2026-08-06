"""Telling "the test failed" apart from "the suite broke".

Spec M2 §3.1 left this open and said what the shape of the answer would have to be: *"If
per-framework output parsing is ever added it goes behind an adapter."* This is that adapter, and
the reason it exists now is that the dogfood produced both failures on the way to a pull request and
they were indistinguishable from an exit code:

```
1 error during collection · 1 error in 0.06s     ← the candidate does not even import
1 failed, 2 passed in 0.02s                      ← the candidate reproduces the bug
```

Both are "the command exited non-zero", which is all the red gate could see. The first is a broken
test being sold as a reproduction; the second is the claim the product makes.

**The signal that distinguishes them is not the failure, it is the survivors.** A candidate that
reproduces a bug leaves every previously-passing test passing and adds one failure of its own. A
candidate that breaks the suite takes the other tests down with it — or aborts collection so nothing
runs at all. Comparing the red gate against the baseline is therefore the whole method, and it needs
only counts.

**Unreadable output is not a failure.** A framework nobody here has met falls back to the exit code,
and the evidence trail says the claim is the weaker one. Refusing to run against an unrecognised
runner would be worse than saying what we do and do not know — and pretending to know is what this
module exists to stop.
"""

import logging
import re
from dataclasses import dataclass

log = logging.getLogger(__name__)

#: The counts, wherever they appear. Deliberately several small patterns rather than one clever one:
#: a regex that matches every runner matches things that are not runners.
_PATTERNS = (
    ("failed", re.compile(r"(\d+)\s+failed", re.IGNORECASE)),
    ("passed", re.compile(r"(\d+)\s+passed", re.IGNORECASE)),
    ("errors", re.compile(r"(\d+)\s+error(?:s)?\b", re.IGNORECASE)),
)

#: Phrases that mean the runner never got as far as running tests. Framework-specific on purpose:
#: this is the adapter, and being specific is what makes it trustworthy.
_ABORTED = (
    "error during collection",
    "errors during collection",
    "Interrupted:",
    "ImportError while loading conftest",
    "Cannot find module",
    "SyntaxError",
)


#: How a runner names the tests that failed. Item 116, and the same rule as everything else here:
#: several small patterns rather than one clever one, because a regex that matches every runner
#: matches things that are not runners.
#:
#: The list is short on purpose and **will not cover the runner most projects use**, which is the
#: point of DR-0007 — the artefact says the names could not be read rather than implying there were
#: none. A wrong name in a pull request body is worse than no name: it sends a reviewer to a test
#: that has nothing to do with the change.
_NAMES = (
    # pytest's `short test summary info`, which is the line that exists to be machine-read.
    re.compile(r"^(?:FAILED|ERROR)\s+(\S+)", re.MULTILINE),
    # go test
    re.compile(r"^\s*---\s+FAIL:\s+(\S+)", re.MULTILINE),
    # cargo test
    re.compile(r"^test\s+(\S+)\s+\.\.\.\s+FAILED", re.MULTILINE),
    # TAP, which is node:test and a dozen others
    re.compile(r"^not ok\s+\d+\s+-\s+(.+?)\s*$", re.MULTILINE),
)

#: How many names an artefact prints before saying "and N more". A reviewer needs to recognise the
#: reproduction, not to read a list.
MAX_NAMES = 5


def failing_tests(output: str) -> list[str]:
    """The names of the tests a runner said failed, or an empty list when it did not say.

    **Empty means "not read", never "none failed".** Every caller has the exit code and the counts
    to say whether something failed; this only answers *which*, and only for runners whose output
    names them in a shape that cannot be mistaken for prose.
    """
    for pattern in _NAMES:
        found = [match.strip() for match in pattern.findall(output)]
        # Order preserved, duplicates dropped: pytest names a parametrised test once per case.
        seen: dict[str, None] = {}
        for name in found:
            if name:
                seen.setdefault(name, None)
        if seen:
            return list(seen)
    return []


#: A line that is only a progress indicator: pytest's dots, and the same idea in other runners.
#: Anchored at both ends so a line that *contains* dots — a traceback's `_ _ _ _` separator, a path
#: with an ellipsis — is never mistaken for one. Item 116.
_PROGRESS = re.compile(r"^[.sFEXxPp!*]{4,}\s*(?:\[\s*\d+%\])?$")


def is_progress(line: str) -> bool:
    """Whether a line is a runner drawing a progress bar rather than saying anything."""
    return bool(_PROGRESS.match(line.strip()))


#: The characters a bare byte-window reads, kept for the abort phrases and **only** for them.
_ABORT_WINDOW_CHARS = 4_000

#: How much of the end the counts are read from, in **lines** — item 117.
#:
#: A byte window has a shape that defeats it, and it is not exotic. Measured on `acme#6`:
#: pytest printed `249 passed, 16 warnings in 64.90s` and the suite then printed twelve kilobytes of
#: alembic migration logs — a dozen lines, each about a thousand characters — so the summary sat
#: outside the last 4,000 characters while being well inside the last dozen lines. The counts came
#: back **empty from a run that had said them in plain sight**.
#:
#: That is not a cosmetic loss, and the consequence is worse than a missing number:
#:
#: * **A candidate that broke working tests is accepted as a reproduction.** The branch that catches
#:   it — *"249 passed on the untouched tree and only 200 did with the candidate added"* — needs the
#:   baseline's counts, and skips itself when they are `None`. What the reviewer is then told is
#:   *"a clean reproduction"*, which is the one sentence this module exists to be careful about.
#: * And when it is the **red gate's** own summary that gets pushed out, `usable` is false and the
#:   verdict falls back to *"the claim rests on the exit code alone"* — the weaker claim, on a run
#:   that printed the stronger one.
#:
#: Both bounds are still enforced, because a runner that prints a megabyte should not be scanned in
#: full: at most `_TAIL_LINES` lines out of at most `_TAIL_CHARS` characters.
_TAIL_LINES = 200
_TAIL_CHARS = 100_000


def _tail(output: str) -> str:
    """The end of a run's output, bounded by lines and by characters."""
    return "\n".join(output[-_TAIL_CHARS:].splitlines()[-_TAIL_LINES:])


#: The runner's own last word, for a summary a reviewer reads without expanding anything.
_VERDICT = re.compile(
    r"\d+\s+(?:passed|failed|error|errors|ok|tests?)\b|^(?:ok|FAIL|PASS)\b|^Tests?:",
    re.IGNORECASE,
)


def verdict_line(output: str, *, limit: int = 120) -> str | None:
    """The runner's own summary line — `904 passed in 61.26s` — or `None` when it did not print one.

    Read from the end, because that is where every runner puts it, and taken **verbatim**: this goes
    into a `<summary>` a reviewer trusts without opening the block, so it is the runner's sentence
    and not ours.

    There is deliberately no `is_progress` guard here, and the reason is worth keeping: the first
    version had one, and reintroducing its absence changed no test — a progress bar is characters
    from `.sFEXxPp!*` and `_VERDICT` needs a digit followed by a word, so no progress line can ever
    reach this branch. A guard that cannot fire reads like a hazard somebody measured.
    """
    for line in reversed(_tail(output.strip()).splitlines()):
        # pytest draws its summary inside a rule of `=`; the rule is decoration and the sentence is
        # the evidence. Only the runner's characters are removed, never any of its words.
        stripped = line.strip().strip("=-_ ").strip()
        if not stripped:
            continue
        if _VERDICT.search(stripped):
            return stripped[:limit]
    return None


@dataclass(frozen=True)
class Counts:
    """What a test run reported. `None` fields mean the output did not say."""

    passed: int | None = None
    failed: int | None = None
    errors: int | None = None
    aborted: bool = False

    @property
    def usable(self) -> bool:
        """Whether anything here can support a claim beyond the exit code."""
        return self.aborted or self.passed is not None or self.failed is not None


def read(output: str) -> Counts:
    """Read what a test runner said. Never raises; unreadable output produces empty counts."""
    tail = _tail(output)
    found: dict[str, int] = {}
    for name, pattern in _PATTERNS:
        matches = pattern.findall(tail)
        if matches:
            # The last one, because runners print a per-file line and then a summary.
            found[name] = int(matches[-1])
    return Counts(
        passed=found.get("passed"),
        failed=found.get("failed"),
        errors=found.get("errors"),
        # **The abort phrases keep the narrow window on purpose** (item 117). They are matched as
        # substrings anywhere, and `SyntaxError` is one of them: widening this twenty-five-fold
        # would turn any run whose traceback prints that word — a test asserting one is raised, for
        # instance — into "the candidate is broken", which refuses a good reproduction. The counts
        # needed a bigger window; these did not ask for one, and the cost of giving it is paid in
        # the direction that discards work.
        aborted=any(
            phrase.lower() in output[-_ABORT_WINDOW_CHARS:].lower() for phrase in _ABORTED
        ),
    )


@dataclass(frozen=True)
class RedGateVerdict:
    """Whether a failing red gate is a reproduction, and how confident that is."""

    reproduced: bool
    #: True when the answer came only from the exit code, so it is the weaker claim.
    from_exit_code_alone: bool
    reason: str


def judge_red_gate(baseline_output: str, red_output: str, *, red_failed: bool) -> RedGateVerdict:
    """Decide what a failing red gate means, by comparing it with the baseline.

    Called only when the command already exited non-zero — a red gate that passes is handled
    elsewhere and means the candidate reproduced nothing.
    """
    if not red_failed:  # pragma: no cover - the caller checks first
        return RedGateVerdict(False, True, "the candidate test did not fail")

    base = read(baseline_output)
    red = read(red_output)

    if not red.usable:
        # Honest rather than confident. This is every runner nobody here has met.
        return RedGateVerdict(
            True,
            True,
            "the test command failed, which is all this runner's output allows us to say — the "
            "claim rests on the exit code alone",
        )

    if red.aborted:
        return RedGateVerdict(
            False,
            False,
            "the run aborted before the tests executed — the candidate does not import or breaks "
            "collection, so it demonstrates nothing about the bug",
        )

    if red.errors:
        return RedGateVerdict(
            False,
            False,
            f"the run reported {red.errors} error(s) rather than a clean test failure, so the "
            f"candidate is broken rather than reproducing anything",
        )

    if not red.failed:
        return RedGateVerdict(
            False,
            False,
            "the command failed but no test did, so whatever went wrong was not the candidate "
            "reproducing the bug",
        )

    # The survivors are the signal. A reproduction adds one failure and leaves the rest green;
    # something that breaks the suite takes other tests down with it.
    if base.passed is not None and red.passed is not None and red.passed < base.passed:
        return RedGateVerdict(
            False,
            False,
            f"{base.passed} test(s) passed on the untouched tree and only {red.passed} did "
            f"with the candidate added, so it broke tests that were working rather than "
            f"reproducing a bug",
        )

    survivors = (
        f", and the {red.passed} test(s) that passed before still pass"
        if red.passed is not None
        else ""
    )
    return RedGateVerdict(
        True,
        False,
        f"{red.failed} test(s) failed with the candidate added{survivors} — a clean reproduction",
    )
