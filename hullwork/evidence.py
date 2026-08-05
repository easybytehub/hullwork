"""What a reviewer reads before deciding, and what must never be in it.

Item 027. DR-0003's most useful sentence is "this test failed at commit X and passes at commit Y",
and by the time the dispatcher is done it has already run both commands — so the artefact costs
nothing to produce and is the one thing in this product no competitor ships.

It is also the most dangerous document here, for a reason that is easy to miss: **it is assembled
from captured output of arbitrary commands, and it is published under Hullwork's own account into
a place a human is meant to trust.** Two consequences run through everything below.

* **Every string goes through the scrubber**, with the three defences item 015 built for the logs
  — by known value, by field name, by shape. A test suite that prints an environment dump on
  failure is not a rare event.
* **Everything is bounded, and a cut says so.** A forge rejects an oversized body, and an
  unannounced truncation turns evidence into a suggestion.

The honest outcomes get an artefact too. `not-reproducible` and `failed` are first-class results
under DR-0003, and a result nobody can see without opening a database is not a result.
"""

import json
import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from hullwork import spend, testoutput
from hullwork.models import Attempt, AttemptOutcome, AttemptPhase, AttemptStep, Item
from hullwork.scrub import Scrubber

if TYPE_CHECKING:
    from hullwork.spend import Prices

log = logging.getLogger(__name__)

#: Forges accept large bodies but not unlimited ones, and a reviewer reads the top anyway.
MAX_BODY_CHARS = 60_000

#: Per step. A suite that prints for a megabyte still has to fit next to five other steps.
MAX_STEP_OUTPUT_CHARS = 4_000

#: The tail, because a test runner's verdict is at the end.
_CUT = "… [earlier output omitted] …"

#: One line per outcome, written for somebody deciding whether to merge rather than for a log.
_CLAIM: dict[AttemptOutcome, str] = {
    AttemptOutcome.PR_OPEN: (
        "**A test that failed against unmodified code passes with this change applied.** Both runs "
        "are below, with the commands and their exit codes."
    ),
    AttemptOutcome.PR_OPEN_LINT_FAILED: (
        "**This change does not meet your lint standard, and the fix itself is verified.** The "
        "failing gate is named below, with its output. A test that failed against unmodified code "
        "passes with this applied — the red and green gates are in the table with their exit codes "
        "— so what is unresolved is the conformance of the file that proves it, not the fix.\n\n"
        "Leading with the failure is deliberate (item 067): an artefact whose shape hides its own "
        "weakest part is worse than none. Published rather than discarded because a reviewer fixes "
        "a lint diagnostic in seconds, and throwing this away costs the item its one attempt over "
        "something that is not about the bug."
    ),
    AttemptOutcome.NOT_REPRODUCIBLE: (
        "**The bug could not be reproduced, so no fix was attempted.** Under DR-0003 that is the "
        "correct outcome rather than a failure: a fix without a reproducing test is a guess, and "
        "nobody reviewing it could tell a correct guess from a plausible one."
    ),
    # FAILED deliberately has no entry here: it is two different sentences depending on how far
    # the attempt got, and `_claim` chooses. One text for both was measured lying in production —
    # see `_claim`.

    AttemptOutcome.ALREADY_FIXED: (
        "**This appears to be fixed already and not yet deployed.** The bug reproduces at the "
        "commit production was running and not at the tip of the default branch, so there is "
        "nothing to fix here — there is something to deploy."
    ),
    AttemptOutcome.ABANDONED: (
        "**The attempt did not reach a verdict**, so it did not count against this item. Something "
        "in the infrastructure got in the way; the agent was never given a fair try."
    ),
    AttemptOutcome.BASELINE_RED: (
        "**This project's own test suite does not pass on an untouched checkout**, so nothing was "
        "attempted and this item still has its attempt (item 043). No red-green claim can be made "
        "against a suite that is already failing: \"this test failed and now passes\" means "
        "nothing if other things were failing too.\n\n"
        "Two ways forward, and only a person can pick: make the suite pass and this item becomes "
        "available again, or fix the bug by hand. Nothing here is a judgement about the bug — it "
        "was never looked at."
    ),
}


def _scrubber(secrets: list[str] | None = None) -> Scrubber:
    """Shapes on, always. This text leaves the instance."""
    return Scrubber(secrets or [], shapes=True)


#: The two honest sentences behind `failed`, split by where the attempt stopped. Item 085.
#:
#: One sentence covered both and it was measured false on the live instance: the first real dogfood
#: bug failed **at the red gate** — the candidate test broke two passing tests instead of
#: reproducing anything — and the published comment opened with "The bug was reproduced" three
#: lines above a detail saying "the candidate test is not a reproduction". A verdict whose headline
#: contradicts its own evidence teaches the reader to trust neither.
_FAILED_AT_RED_GATE = (
    "**The attempt did not manage to reproduce the bug: its candidate test is not a valid "
    "reproduction.** Nothing was merged and nothing was hidden; what was tried is below."
)
_FAILED_PAST_RED_GATE = (
    "**The bug was reproduced and the attempt did not produce a passing suite.** Nothing was "
    "merged and nothing was hidden; what was tried is below."
)

#: Phases that run the project's own commands, so their output is a runner's and can be read as one.
_GATES = frozenset(
    {
        AttemptPhase.BASELINE,
        AttemptPhase.RED_GATE,
        AttemptPhase.GREEN_GATE,
        AttemptPhase.GREEN_GATE_RESTORED,
        AttemptPhase.LINT_GATE,
    }
)

#: Phases that run the agent. Their output belongs to its harness, not to a test runner.
_AGENT_PHASES = frozenset({AttemptPhase.REPRODUCE, AttemptPhase.FIX})

#: Phases at or before the red gate: the reproduction was never established there.
_BEFORE_FIX = frozenset(
    {AttemptPhase.BASELINE, AttemptPhase.REPRODUCE, AttemptPhase.RED_GATE}
)


def _claim(attempt: Attempt) -> str:
    """The headline sentence, chosen from what the attempt actually did.

    `failed` at the red gate means the reproduction was refused; `failed` after it means the
    reproduction stood and the fix did not. The reader a comment is for cannot see the phase table
    first — the headline is what they act on, so it is the part that must not overstate.
    """
    outcome = attempt.outcome or AttemptOutcome.ABANDONED
    if outcome is AttemptOutcome.FAILED:
        if attempt.phase_reached in _BEFORE_FIX:
            return _FAILED_AT_RED_GATE
        return _FAILED_PAST_RED_GATE
    return _CLAIM.get(outcome, "")


def pull_request_body(
    item: Item,
    attempt: Attempt,
    *,
    detail: str = "",
    brief_text: str = "",
    #: What the brief could carry, from `brief.evidence_level`. Item 100.
    brief_evidence: str = "",
    secrets: list[str] | None = None,
    #: What the operator pays, for the cost row. `None` prints tokens and no money (item 133).
    prices: "Prices | None" = None,
) -> str:
    """The body of the draft pull request.

    The claim goes first because it is what the reviewer is deciding about. The seal goes near the
    top because DR-0002 makes it the reason to trust any of this. The captured output goes last and
    collapsed, because it is long and only some of it gets read.
    """
    scrub = _scrubber(secrets)
    lines = [
        _claim(attempt),
        "",
    ]
    if detail:
        lines += [scrub.text(detail), ""]
    if item.forge_issue_ref:
        # The keyword Forgejo and GitHub both honour, verified against a live Forgejo on
        # 2026-07-27: merging this closes the issue, which is what makes the loop close itself.
        lines += [f"Closes {item.forge_issue_ref}", ""]

    lines += _what_was_checked(attempt, scrub)
    lines += _provenance(attempt, scrub, brief_evidence=brief_evidence, prices=prices)
    lines += _what_ran(attempt, scrub)
    if brief_text:
        lines += [
            "<details><summary>What the agent was told</summary>",
            "",
            "This is the operational memory Hullwork supplied. It is here so you can see the "
            "context the change was made from, including the parts that came from a stranger.",
            "",
            "```text",
            scrub.text(brief_text)[:MAX_STEP_OUTPUT_CHARS],
            "```",
            "",
            "</details>",
            "",
        ]
    lines += [
        "---",
        "",
        "Opened by Hullwork as a **draft**. Nobody merges this but you.",
    ]
    body = "\n".join(lines)
    if len(body) > MAX_BODY_CHARS:
        body = body[:MAX_BODY_CHARS] + "\n\n… [body truncated by Hullwork]"
    return body


def issue_comment(
    item: Item,
    attempt: Attempt,
    *,
    detail: str = "",
    secrets: list[str] | None = None,
    #: For the cost row (item 133).
    prices: "Prices | None" = None,
) -> str:
    """What goes on the issue when there is no pull request.

    `not-reproducible` and `failed` are first-class outcomes under DR-0003 — "the honest outcome is
    a first-class result rather than a failure to be papered over" — and a first-class result that
    only exists in a database is one nobody acts on.
    """
    scrub = _scrubber(secrets)
    lines = [_claim(attempt), ""]
    if detail:
        lines += [scrub.text(detail), ""]
    lines += [
        f"Got as far as: `{attempt.phase_reached.value}`.",
        "",
    ]
    if not attempt.consumed:
        lines += [
            f"This did **not** use up the one attempt this item gets: "
            f"{scrub.text(attempt.not_consumed_reason or 'the run did not reach a verdict')}.",
            "",
        ]
    else:
        lines += [
            "This item has now had its one attempt (DR-0003), so it is a human's from here.",
            "",
        ]
    # The same block as the pull request gets, for the same reason: a `failed` comment that does not
    # name which tests failed sends its reader into a collapsed block to find out (item 116).
    lines += _what_was_checked(attempt, scrub)
    lines += _provenance(attempt, scrub, prices=prices)
    lines += _what_ran(attempt, scrub)
    body = "\n".join(lines)
    return body[:MAX_BODY_CHARS]


def _what_was_checked(attempt: Attempt, scrub: Scrubber) -> list[str]:
    """The three facts a merge decision turns on, above everything else. Item 116.

    **Measured on all four published pull requests**: the reproduction's name, the count of tests
    that kept passing, and the green gate's verdict were in the *fourth of seven identically-shaped
    collapsed blocks*, below eleven lines of progress dots. Every one of them was already recorded
    on the attempt's own steps — the artefact simply never said them, and a reviewer who trusted the
    headline and a reviewer who opened the right block read different documents.

    Assembled from the recorded steps and never from prose: the agent's account of what it did is
    exactly the thing a reviewer is deciding whether to believe.
    """
    gates = {
        step.phase: step
        for step in attempt.steps
        if step.phase in (AttemptPhase.BASELINE, AttemptPhase.RED_GATE, AttemptPhase.GREEN_GATE)
    }
    red = gates.get(AttemptPhase.RED_GATE)
    green = gates.get(AttemptPhase.GREEN_GATE)
    if red is None and green is None:
        # Nothing to state. An attempt that never reached a gate is described by its claim and its
        # step table, and a section with one empty row in it is worse than no section.
        return []

    lines = ["### What was checked", "", "| | |", "|---|---|"]
    if red is not None:
        named = testoutput.failing_tests(red.output or "")
        if named:
            shown = ", ".join(f"`{scrub.text(name)}`" for name in named[:testoutput.MAX_NAMES])
            if len(named) > testoutput.MAX_NAMES:
                shown += f", and {len(named) - testoutput.MAX_NAMES} more"
            lines.append(f"| Reproduced by | {shown} |")
        else:
            # **Never silence.** An empty list means this runner's output was not read, and a body
            # that omits the row reads as "no test was named", which is a claim nobody made.
            lines.append(
                "| Reproduced by | this runner does not name its failures in a shape Hullwork "
                "reads — the counts below are what can be said |"
            )
        lines.append(f"| Before the fix | {_gate_cell(red, expected_to_fail=True)} |")
    if green is not None:
        lines.append(f"| After the fix | {_gate_cell(green, expected_to_fail=False)} |")
    baseline = gates.get(AttemptPhase.BASELINE)
    if baseline is not None:
        # The runner's own line rather than `testoutput.read`'s counts, and that is not a
        # preference: on `acme#6` the suite printed twelve kilobytes of migration logs
        # *after* pytest's summary, so the counts came back empty from a run that had said
        # `249 passed` in plain sight. The row would simply have vanished. (Why `read` cannot see
        # it is item 117, and it is not only cosmetic there.)
        cell = _gate_cell(baseline, expected_to_fail=False)
        lines.append(f"| The suite before any change | {cell} |")
    lines.append("")
    return lines


def _gate_cell(step: AttemptStep, *, expected_to_fail: bool) -> str:
    """One gate, in the words its runner used, with the exit code that is the actual claim."""
    verdict = testoutput.verdict_line(step.output or "")
    expected = "as it must" if (step.exit_code != 0) == expected_to_fail else "**unexpectedly**"
    said = f"`{verdict}`" if verdict else "the runner printed no summary line"
    return f"exit `{step.exit_code}` {expected} — {said}"


def _what_it_cost(
    attempt: "Attempt", seal: Mapping[str, Any], prices: "Prices | None"
) -> list[str]:
    """The rows for tokens, money and time. Item 133.

    **The row this replaces said `Context served | 936 in`** and had said it in every published pull
    request since item 116. It read `input_tokens`, which counts only the input billed at full rate;
    on a provider that caches, and with a harness that accumulates context, the rest of the context
    sits in two fields nobody read. So the row splits into what was actually served and what it was
    charged as, and neither is presented as the other.

    Money appears only when the operator has priced their own tokens, and a partial price says so.
    Duration always appears when the attempt has finished, because a spend without a clock cannot be
    judged — and a clock without a spend is how a hung attempt looks (item 097, attempt 18: three
    hours and forty-seven minutes, no seal at all).
    """
    tokens = spend.tokens_of(seal)
    rows: list[str] = []
    if tokens.reported:
        served = tokens.context_served
        detail = f"{served:,} tokens" if served is not None else "not reported"
        if tokens.caching_unreported:
            # Said rather than shown as zero: this is what every seal written before item 133 looks
            # like, and it is also what a provider without caching looks like.
            detail += " (whether any of it was cached was not reported)"
        rows.append(f"| Context served | {detail} |")
        rows.append(
            f"| Charged as | {_tokens_charged(tokens)} |"
        )
    money = spend.cost_of(tokens, prices)
    if money is not None:
        rows.append(f"| Cost | {money} |")
    elif tokens.reported:
        # An absence with a reason. A blank here reads as free.
        rows.append("| Cost | not priced on this instance |")
    duration = spend.elapsed(attempt)
    if duration is not None:
        rows.append(f"| Took | {spend.spoken(duration)} |")
    return rows


def _tokens_charged(tokens: spend.Tokens) -> str:
    """The counts as they are billed, each named, none summed."""
    parts = [
        f"{tokens.input:,} in" if tokens.input is not None else None,
        f"{tokens.output:,} out" if tokens.output is not None else None,
        f"{tokens.cache_write:,} cache write" if tokens.cache_write is not None else None,
        f"{tokens.cache_read:,} cache read" if tokens.cache_read is not None else None,
    ]
    return ", ".join(part for part in parts if part) or "not reported"


def _provenance(
    attempt: Attempt,
    scrub: Scrubber,
    *,
    brief_evidence: str = "",
    prices: "Prices | None" = None,
) -> list[str]:
    """The seal, rendered. DR-0002 §4: read off the wire, never copied from configuration."""
    seal = attempt.seal or {}
    if not seal and not attempt.base_sha and not brief_evidence:
        return []
    lines = ["### Provenance", "", "| | |", "|---|---|"]
    if brief_evidence:
        # **First row, above the model and the image** (item 100). A reviewer deciding whether to
        # believe a fix needs to know what the agent was working from before they read what it did.
        # On attempt 20 the answer was "the issue title" and the only place that appeared was inside
        # the agent's own prose, in a collapsed block — so a reviewer who trusted the fix and a
        # reviewer who read everything saw different documents.
        lines.append(f"| Evidence the agent had | {scrub.text(brief_evidence)} |")
    if attempt.base_sha:
        lines.append(f"| Gates ran against | `{attempt.base_sha}` |")
    if attempt.production_ref:
        lines.append(f"| Production was running | `{scrub.text(attempt.production_ref)}` |")
    if attempt.image_tag:
        lines.append(f"| Sandbox image | `{attempt.image_tag}` |")
    served = seal.get("models_served")
    if served:
        lines.append(f"| Model that answered | `{scrub.text(', '.join(map(str, served)))}` |")
    if seal.get("model_requested"):
        lines.append(f"| Model requested | `{scrub.text(str(seal['model_requested']))}` |")
    if seal.get("endpoint"):
        lines.append(f"| Endpoint | `{scrub.text(str(seal['endpoint']))}` |")
    # Always stated, never guessed: no endpoint in either protocol family discloses quantisation,
    # and inventing a value is the dishonesty DR-0002 was written against.
    lines.append(f"| Declared precision | `{seal.get('precision', 'undisclosed')}` |")
    lines += _what_it_cost(attempt, seal, prices)
    lines.append("")

    violations = seal.get("violations") or []
    if violations:
        # Above the diff on purpose. If the endpoint served a different model than was asked for,
        # or cut the context, that is the first thing a reviewer needs and not a footnote.
        lines += ["> [!warning] The endpoint did something worth knowing about", ">"]
        for violation in violations:
            if isinstance(violation, dict):
                detail_text = scrub.text(str(violation.get("detail")))
                lines.append(f"> - **{violation.get('kind')}** — {detail_text}")
        lines += [""]
    if seal.get("model_drift"):
        lines += [
            "> The model that answered was not the one requested for every response. DR-0002 "
            "treats that as a finding rather than a detail: it is the documented failure mode "
            "that `allow_fallbacks: false` asks a provider to avoid and cannot enforce.",
            "",
        ]
    return lines


def _environment_cell(step: AttemptStep) -> str:
    """What a reviewer sees in the environment column: three answers, all different. Item 106.

    * **`—`** — not recorded. Every step written before the column existed says this, and it must
      not read as "nothing was added": a trail that cannot tell an absent measurement from a
      measured zero is the defect item 105 was closed for, in the place a reviewer reads.
    * **`clean`** — nothing added, which is every gate. Item 099's whole shape was the gates
      running clean while the agent's phases carried five variables the watched project's settings
      loader rejected; a reviewer comparing two rows can now see that difference.
    * **the names** — sorted, names only. The values are in the step's own output block, and a
      table cell is not where anybody reads a path; what a reviewer checks here is *which*
      variables a phase was given, because that is what a strict project rejects.
    """
    if step.environment is None:
        return "—"
    try:
        given = json.loads(step.environment)
    except ValueError:  # pragma: no cover - written by `_environment`, which emits JSON
        return "unreadable"
    if not isinstance(given, dict) or not given:
        return "clean"
    return ", ".join(f"`{name}`" for name in sorted(given))


def _what_ran(attempt: Attempt, scrub: Scrubber) -> list[str]:
    """Every command, its exit code, and its output — collapsed, bounded, scrubbed."""
    if not attempt.steps:
        return []
    lines = [
        "### What ran", "",
        "| Step | Command | Exit | Took | Environment |", "|---|---|---|---|---|",
    ]
    for step in attempt.steps:
        command = scrub.text(step.command).replace("|", "\\|")[:200]
        took = f"{(step.duration_ms or 0) / 1000:.1f}s"
        lines.append(
            f"| `{step.phase.value}` | `{command}` | `{step.exit_code}` | {took} "
            f"| {_environment_cell(step)} |"
        )
    lines.append("")

    for step in attempt.steps:
        if not step.output.strip():
            continue
        text = _without_progress(scrub.text(step.output))
        if len(text) > MAX_STEP_OUTPUT_CHARS:
            text = _CUT + "\n" + text[-MAX_STEP_OUTPUT_CHARS:]
        note = " (truncated when stored)" if step.output_truncated else ""
        # **The verdict goes in the summary** (item 116). A forge collapses these, so a body whose
        # verdicts are only inside them asks a reviewer to open six blocks to learn six numbers
        # that fit on six lines.
        #
        # Gates only. An agent phase's output is the harness's own JSON transcript, and the first
        # version of this line put 120 characters of `{"is_error":false,"duration_api_ms":…}` where
        # a reviewer reads a verdict — a summary that looks like a measurement and is a stream
        # position. What that block is gets said instead, which is the true and useful thing.
        if step.phase in _GATES:
            verdict = testoutput.verdict_line(step.output or "")
            note += f" — {verdict}" if verdict else ""
        elif step.phase in _AGENT_PHASES:
            note += " — the agent's own transcript, as its harness printed it"
        lines += [
            f"<details><summary><code>{step.phase.value}</code> output{note}</summary>",
            "",
            "```text",
            text,
            "```",
            "",
            "</details>",
            "",
        ]
    return lines


def _without_progress(text: str) -> str:
    """Drop the lines a runner draws to show it is alive, and say how many. Item 116.

    Eleven of them sat above the failure a reviewer had come to read, in the block that carried the
    whole claim, and the `baseline` block was twenty-two of them wrapped around one sentence.

    **Removal is stated where it happened**, never silent: this text is the record of what a command
    printed, and evidence that has been edited without saying so is not evidence. The count is the
    honest form of the edit — anybody who wants the dots has the exit code, the counts, and a
    checkout.
    """
    kept: list[str] = []
    run = 0
    for line in text.splitlines():
        if testoutput.is_progress(line):
            run += 1
            continue
        if run:
            kept.append(f"… [{run} progress line(s) omitted] …")
            run = 0
        kept.append(line)
    if run:
        kept.append(f"… [{run} progress line(s) omitted] …")
    return "\n".join(kept)


def branch_name(item: Item, attempt: Attempt) -> str:
    """Where the change goes. Namespaced, so a repository's own branches are never at risk.

    The attempt id is in it because an item can be attempted again after a human releases it, and
    a second attempt reusing the first one's branch would silently rewrite an open pull request.
    """
    return f"hullwork/item-{item.id}-attempt-{attempt.id}"


def commit_messages(item: Item, phase: AttemptPhase = AttemptPhase.PUBLISH) -> tuple[str, str]:
    """Two commits, in this order, because the order is the evidence.

    A reviewer can check out the first and watch it fail. That is the whole claim, expressed as
    something they can run rather than something we assert.
    """
    subject = item.title.splitlines()[0][:68] if item.title else "an error from production"
    test = (
        f"test: reproduce {subject}\n\n"
        f"A failing test that reproduces the reported error. This commit is expected to be red: "
        f"check it out and run the project's test command to see the bug.\n\n"
        f"Reported by Hullwork from a production error."
    )
    fix = (
        f"fix: {subject}\n\n"
        f"The smallest change that makes the preceding test pass. Nothing else in the suite "
        f"regressed; the runs are in the pull request.\n\n"
        f"Reported by Hullwork from a production error."
    )
    return test, fix


#: How many lines of a command's captured output to show at a prompt. A test runner's verdict is
#: at the end, so it is the tail.
TERMINAL_OUTPUT_LINES = 4


def terminal_report(
    item: Item,
    attempt: Attempt,
    *,
    detail: str = "",
    written_to: str | None = None,
    secrets: list[str] | None = None,
) -> str:
    """The same attempt, for somebody reading a terminal. Item 050.

    DR-0006 promised "the same artefact the pull request would have carried, printed to the
    terminal",
    and its amendment measured that sentence: on an attempt with five recorded steps of realistic
    gate output, `pull_request_body` is **21,042 characters over 532 lines** — that is the fixture,
    and the four bodies actually published measure 148 to 171 lines (item 116) — with `<details>`
    pairs that do not collapse at a prompt, plus forge-only text: `Closes #42` and a draft sentence.
    A rehearsal nobody can read proves nothing.

    **One assembly, two skins.** The claim comes from `_CLAIM` and the scrubbing from the same
    shapes-on scrubber; only the presentation differs. A second copy of the claim would drift, which
    is the failure `_commit` and the publisher already have to be careful about.
    """
    scrub = _scrubber(secrets)
    outcome = attempt.outcome or AttemptOutcome.ABANDONED
    # The markdown emphasis reads well in the other skin and is noise here, so it comes off. The
    # words are the same words.
    claim = _CLAIM.get(outcome, "").replace("**", "")
    lines = [
        f"item {item.id}: {scrub.text(item.title.splitlines()[0])[:70]}",
        f"  verdict   {outcome.value}, at {attempt.phase_reached.value}",
        f"  attempt   {'spent' if attempt.consumed else 'not spent'}"
        + (" (rehearsal: nothing was published)" if attempt.rehearsal else ""),
        "",
        *_wrapped(claim),
        "",
    ]
    if detail:
        lines += [*_wrapped(scrub.text(detail)), ""]

    seal = attempt.seal or {}
    if seal:
        served = seal.get("models_served") or []
        lines += [
            "  model     "
            + (", ".join(str(m) for m in served) if served else "none answered")
            + f"   ({seal.get('responses', 0)} response(s) read off the wire)",
        ]
        # Item 056: the seal held both of these and the screen showed neither, which is the other
        # half of why one diagnosis took four rounds. Printed only when there is something to say —
        # a run where everything answered 200 and nothing was refused gains nothing from a line
        # saying so, and the fixed-shape rule is about the audit block, not about every line here.
        statuses = seal.get("statuses") or {}
        if isinstance(statuses, dict) and any(not str(code).startswith("2") for code in statuses):
            lines.append(
                "  answers   "
                + ", ".join(f"{code} x{count}" for code, count in sorted(statuses.items()))
            )
        refused = seal.get("refused_paths") or []
        if refused:
            lines.append(
                f"  refused   {len(refused)} request(s) the gateway would not forward: "
                + ", ".join(scrub.text(str(path)) for path in refused[:3])
            )
        violations = seal.get("violations") or []
        for violation in violations:
            lines.append(f"  ! {scrub.text(str(violation))}")
        lines.append("")

    lines.append("  what ran")
    for step in attempt.steps:
        code = "ok" if step.exit_code == 0 else f"exit {step.exit_code}"
        took = f"{(step.duration_ms or 0) / 1000:.1f}s"
        lines.append(f"    {step.phase.value:<20} {code:<9} {took:>7}  {scrub.text(step.command)}")
        tail = [ln for ln in scrub.text(step.output or "").splitlines() if ln.strip()]
        for shown in tail[-TERMINAL_OUTPUT_LINES:]:
            lines.append(f"      | {shown[:96]}")
    lines.append("")
    if written_to:
        lines += [f"  written to {written_to}", "  diff it against your own checkout: diff -ru", ""]
    return "\n".join(lines)


def _wrapped(text: str, width: int = 92) -> list[str]:
    """Fold a sentence to a terminal width, two spaces in. No dependency for four lines of code."""
    import textwrap

    return [f"  {line}" for line in textwrap.wrap(text, width=width)] if text.strip() else []
