"""What `hullwork init` asks, and what it says is still missing. Item 197.

Measured before anything was written: `init` produces a `deploy.env` of **120 lines and nineteen
empty variables**, then prints the same five numbered steps to everybody. The file is right and its
comments are good; what is absent is any way to address the *minimum*. An instance that only ingests
errors needs four of the nineteen, one that attempts fixes needs seven, and nothing in the output
says which reader is which.

The operator's direction on 2026-08-10: what a developer sees is the product, and it has to be
reachable with the minimum.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from pathlib import Path

from hullwork import scaffold


def _written(tmp_path: Path) -> str:
    scaffold.write(tmp_path, docker_gid=None)
    return (tmp_path / scaffold.ENVIRONMENT_FILE).read_text(encoding="utf-8")


# --- the three properties that must survive ------------------------------------------------------


def test_answering_nothing_writes_what_it_writes_today(tmp_path: Path) -> None:
    """**The default path stays the documented one.** `init` is documented as running from inside
    the image, before the package exists anywhere; an installer has no terminal to answer with, and
    a stranger pressing enter is following the same instructions as one who could not be asked.
    """
    silent = _written(tmp_path / "silent")

    answered = scaffold.filled(_written(tmp_path / "answered"), scaffold.Answers())

    assert answered == silent


def test_an_answer_reaches_the_file(tmp_path: Path) -> None:
    """The whole point of a harness: what you said is written where it goes, not repeated back to
    you as an instruction to type it yourself."""
    text = scaffold.filled(
        _written(tmp_path), scaffold.Answers(forge_url="https://forge.example.com")
    )

    assert "HULLWORK_FORGE_URL=https://forge.example.com" in text
    assert "\nHULLWORK_FORGE_URL=\n" not in text, "the blank it replaced is gone, not duplicated"


def test_it_never_writes_a_variable_it_was_not_given(tmp_path: Path) -> None:
    """Everything unanswered stays exactly as the scaffold wrote it — blank, above the comment that
    says what it is for. A shorter file is not the goal; an addressable minimum is."""
    text = scaffold.filled(_written(tmp_path), scaffold.Answers(forge_url="https://f.example"))

    assert "\nHULLWORK_TRACKER_TOKEN=\n" in text
    assert "\nHULLWORK_MODEL_KEY=\n" in text


# --- what it says is still missing ---------------------------------------------------------------


def test_it_names_what_is_missing_for_what_was_asked_for(tmp_path: Path) -> None:
    """Not the union. A reader who said they do not want fixes yet is not shown the two credentials
    that only fixing needs — that list is what made the minimum unaddressable."""
    answers = scaffold.Answers(forge_url="https://f.example", autofix=False)

    said = " ".join(scaffold.what_is_still_needed(answers, _written(tmp_path)))

    assert "HULLWORK_FORGE_TOKEN" in said, "it cannot file an issue without one"
    assert "HULLWORK_MODEL_KEY" not in said
    assert "HULLWORK_FORGE_CODE_TOKEN" not in said


def test_asking_for_fixes_puts_those_two_back(tmp_path: Path) -> None:
    """The other side of the same answer, so the report is a function of what was said rather than
    a shorter list that happens to be right once."""
    answers = scaffold.Answers(forge_url="https://f.example", autofix=True)

    said = " ".join(scaffold.what_is_still_needed(answers, _written(tmp_path)))

    assert "HULLWORK_MODEL_KEY" in said
    assert "HULLWORK_FORGE_CODE_TOKEN" in said


def test_every_missing_variable_says_what_it_buys(tmp_path: Path) -> None:
    """A name with no consequence beside it is the nineteen blanks again, one indentation deeper."""
    lines = scaffold.what_is_still_needed(scaffold.Answers(), _written(tmp_path))

    assert lines
    for line in lines:
        assert len(line) > 40, f"a variable named with no reason beside it: {line!r}"


def test_what_was_answered_is_not_reported_as_missing(tmp_path: Path) -> None:
    """Obvious, and it is the failure that would make the report noise: a harness that asks and then
    tells you to go and do it anyway."""
    answers = scaffold.Answers(forge_url="https://f.example")

    text = scaffold.filled(_written(tmp_path), answers)

    said = " ".join(scaffold.what_is_still_needed(answers, text))

    assert "HULLWORK_FORGE_URL" not in said


def test_an_answer_counts_before_the_file_is_written(tmp_path: Path) -> None:
    """**Found by mutation**: the test above passes the *filled* text, where an answered variable is
    no longer blank — so it cannot tell whether the report is reading the file or remembering the
    answer, and the guard that does the remembering was removable without failing anything.

    The contract is the stronger of the two: what somebody just said is not still missing, whether
    or not it has reached disk yet. That keeps the function honest away from its one caller, which
    happens to write the file first.
    """
    answers = scaffold.Answers(forge_url="https://f.example", base_url="https://h.example")

    said = " ".join(scaffold.what_is_still_needed(answers, _written(tmp_path)))

    assert "HULLWORK_FORGE_URL" not in said
    assert "HULLWORK_BASE_URL" not in said
    assert "HULLWORK_FORGE_TOKEN" in said, "and the ones nobody answered are still there"


def test_enter_at_every_question_is_the_same_as_not_being_asked() -> None:
    """**The link between the two paths**, and the reason the documentation stays true: the answer
    a hurried reader gives and the answer an installer cannot give have to arrive at the same
    place.
    """
    said = scaffold.ask(lambda question, hint: "")

    assert said == scaffold.Answers()


def test_a_question_that_changes_nothing_is_not_asked() -> None:
    """Every prompt has to change which variables are written or which sentence is printed. A
    question whose answer changes neither teaches its reader that the tool wastes their time."""
    fields = set(scaffold.Answers.__dataclass_fields__)

    asked = {name for name, _, _ in scaffold.QUESTIONS}

    assert asked == fields, "a question with no field behind it, or a field nobody is asked about"


# --- the bound on what it may ask ----------------------------------------------------------------


def test_no_secret_is_ever_written_by_an_answer(tmp_path: Path) -> None:
    """**Secrets stay the operator's to paste.** Nothing about a setup command is worth putting a
    token into a terminal's scrollback for, so the questions ask which things exist and never what
    they are.
    """
    for field in scaffold.Answers.__dataclass_fields__:
        assert "token" not in field and "key" not in field, (
            f"`{field}` invites a secret into an answer; ask whether one exists instead"
        )


def test_the_report_never_prints_a_value(tmp_path: Path) -> None:
    """It names variables and consequences. A report that echoed what it had just been told would
    put a forge URL — and one day something worse — into a log somebody pastes into an issue."""
    answers = scaffold.Answers(forge_url="https://forge.example.com")

    said = " ".join(scaffold.what_is_still_needed(answers, _written(tmp_path)))

    assert "forge.example.com" not in said
