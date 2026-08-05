"""`hullwork try`: the six phases with no forge, no deployment and no database. Item 140.

The subject of these tests is what a trial **does not need**. That is an unusual thing to assert and
it is the whole product claim of the command: an evaluator with a checkout and a stack trace can see
one red-green cycle without creating an account anywhere. A test that only proved the phases run
would pass just as well against a version that quietly required a token.
"""

from pathlib import Path

import pytest
from pydantic import SecretStr

from hullwork.config import Settings
from hullwork.manifest import parse_manifest
from hullwork.models import ItemState
from hullwork.trial import ephemeral_session, fact_from_trace, head_sha, stage

PYTHON_TRACE = '''Traceback (most recent call last):
  File "/app/api/views.py", line 88, in handle
    return parse(row)
  File "/app/api/parsing.py", line 12, in parse
    return int(row["amount"])
ValueError: invalid literal for int() with base 10: "1.234,00"
'''

MANIFEST = """
project: p
git: {provider: forgejo, repo: o/r}
autofix: {agent: claude-code, gates: [tests, human-merge]}
tests: "pytest"
test_path: tests
runtime: {base: python-3.12, install: none, dependencies: []}
"""

#: Declares the error green, so triage hands it to an agent. **Needed by any test that asserts on
#: what happens after triage**: with the manifest above, everything lands red and the run stops
#: before it reaches a credential — which would make a test of the credential path pass vacuously.
GREEN = MANIFEST.replace(
    "autofix: {agent: claude-code, gates: [tests, human-merge]}",
    "autofix:\n  agent: claude-code\n  gates: [tests, human-merge]\n"
    "  lanes:\n    green: [valueerror]",
)


def test_the_title_comes_from_the_line_that_names_the_error() -> None:
    """The line a person would read out loud if you asked them what broke."""
    fact = fact_from_trace(PYTHON_TRACE, project_ref="owner/repo")

    expected = 'ValueError: invalid literal for int() with base 10: "1.234,00"'
    assert fact.title == expected


def test_the_culprit_is_the_deepest_frame_not_the_first() -> None:
    """**The one derivation that changes a decision.** `triage.choose_lane` matches on the culprit,
    so taking the outermost frame would show the evaluator a lane a real instance would not choose —
    and the lane is the thing a trial exists to reproduce faithfully.
    """
    fact = fact_from_trace(PYTHON_TRACE, project_ref="owner/repo")

    assert fact.culprit == "/app/api/parsing.py", "the error happened in parse, not in handle"


def test_a_trace_that_is_not_python_is_accepted_rather_than_refused() -> None:
    """A Go panic, a Node stack, a log line. This command's job is to take what the evaluator has.

    Refusing anything without a CPython frame would fail exactly the person it is for — somebody
    trying it for the first time, with whatever their production actually printed.
    """
    fact = fact_from_trace(
        "panic: runtime error: index out of range [3] with length 2", project_ref="o/r"
    )

    assert fact.title.startswith("panic: runtime error")
    assert fact.culprit is None, "inventing a culprit would invent a lane decision"


def test_the_same_crash_twice_is_one_fact() -> None:
    """Fingerprinted over the derived title and culprit, not the raw text, so line numbers moving
    between two copies of the same crash do not make it two bugs."""
    other = PYTHON_TRACE.replace("line 88", "line 91").replace("line 12", "line 14")

    assert (
        fact_from_trace(PYTHON_TRACE, project_ref="o/r").fingerprint
        == fact_from_trace(other, project_ref="o/r").fingerprint
    )


def test_the_fact_says_it_came_from_a_paste() -> None:
    """`provider` is provenance, and a trial claiming to be a GlitchTip delivery would be a lie told
    to the one field whose whole job is saying where a thing came from."""
    fact = fact_from_trace(PYTHON_TRACE, project_ref="o/r")

    assert fact.provider == "trace"
    assert fact.fingerprint_derived is True, "no tracker grouped this; we did"
    assert fact.raw["trace"].startswith("Traceback"), "what the evaluator saw is kept whole"


def test_an_empty_trace_is_refused_with_a_sentence() -> None:
    with pytest.raises(ValueError, match="no error to reproduce"):
        fact_from_trace("   \n  ", project_ref="o/r")


def test_a_directory_that_is_not_a_repository_still_has_an_answer(tmp_path: Path) -> None:
    """Somebody trying this against an unpacked tarball is the person this command is for.

    `working tree` rather than `unknown`: the artefact says what it ran against, and an artefact
    claiming an unknown commit is one nobody can check.
    """
    assert head_sha(tmp_path) == "working tree"


def test_the_item_reaches_ready_through_the_real_triage_path(tmp_path: Path) -> None:
    """`dedup.resolve`, not a hand-built row: the lane is decided by the code that decides lanes.

    An evaluator whose error lands red should see that and see why — it is the product working.
    And the move to `ready` goes through `transition`: item 042's guard caught the first draft of
    this assigning the state directly, which is the defect that guard was written for.
    """
    session = ephemeral_session()

    project, item = stage(session, parse_manifest(MANIFEST), PYTHON_TRACE, repo="repo")

    assert item.lane is not None, "a lane was decided, by the code that decides lanes"
    assert item.state is not ItemState.NEW, "triage ran"
    assert item.title.startswith("ValueError")
    assert project.manifest, "the manifest travels on the project, where `_attempt` reads it"


def test_a_trial_needs_no_forge_credential_of_any_kind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The product claim of this command, asserted as an absence.** Item 140.

    Every `HULLWORK_FORGE_*` variable is unset and the run must get past wiring anyway. It will not
    finish — there is no Docker daemon in a unit test and the model credential is a fake — but the
    failure it reaches must not be *"HULLWORK_FORGE_TOKEN is not set"*, because that message is the
    security review this command exists to defer.

    Before item 140, `work --no-publish` raised exactly that: cloning is a read, and a read still
    needed a token. A trial is handed the checkout, so there is nothing left to read.

    **Raising is not part of the claim, and asserting it made this test pass for the wrong reason.**
    It read `pytest.raises(Exception)` on the reasoning that a unit test has no Docker daemon — but
    the machine that runs the suite is the machine that runs the product, so on a developer's laptop
    there *is* one, and what actually raised was the harness bundle failing on arm64 (2026-08-04).
    With that fixed the run reaches the model, whose fake credential ends the attempt as `abandoned`
    rather than as an exception, and this test failed while the property it names held perfectly.
    So the absence is asserted either way: raised or returned, no forge credential was asked for.
    """
    from hullwork import trial

    for name in ("FORGE_URL", "FORGE_TOKEN", "FORGE_CODE_TOKEN"):
        monkeypatch.delenv(f"HULLWORK_{name}", raising=False)
    # Green, or triage stops the run before a credential is asked for and this passes
    # vacuously — which is the shape of test item 136 called out.
    (tmp_path / "hullwork.yml").write_text(GREEN)
    settings = Settings(model_key=SecretStr("k"), database_url="sqlite://")

    outcome: object = None
    raised: BaseException | None = None
    try:
        outcome = trial.run(settings, tmp_path, PYTHON_TRACE, into=tmp_path / "out")
    except Exception as exc:  # what it is, is the assertion below
        raised = exc

    assert not isinstance(raised, trial.NotForAnAgentError), "fixture is not green"
    # The exact refusals, not a substring of the whole message: pytest's tmp_path carries the test's
    # own name, which contains "forge", and a crude check fails on its own filename.
    message = str(raised) if raised is not None else str(outcome)
    for refusal in ("HULLWORK_FORGE_TOKEN is not set", "HULLWORK_FORGE_CODE_TOKEN is not set"):
        assert refusal not in message, f"a trial asked for a forge credential: {message}"


def test_a_checkout_without_a_manifest_says_what_writes_one(tmp_path: Path) -> None:
    """The refusal names the next command, because the next command is already the answer."""
    from hullwork import trial, work

    settings = Settings(model_key=SecretStr("k"), database_url="sqlite://")

    with pytest.raises(work.WiringError, match="hullwork propose"):
        trial.run(settings, tmp_path, PYTHON_TRACE, into=tmp_path / "out")


def test_a_trial_writes_no_database_beside_the_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`HULLWORK_DATABASE_URL` defaults to `sqlite:///./hullwork.db`, so a command that opened the
    ordinary session would drop a file into the evaluator's working directory — to satisfy a command
    whose claim is that it leaves nothing behind. The trial brings its own, in memory.
    """
    from hullwork import trial

    (tmp_path / "hullwork.yml").write_text(MANIFEST)
    monkeypatch.chdir(tmp_path)
    settings = Settings(model_key=SecretStr("k"), database_url="sqlite://")

    with pytest.raises(Exception):  # noqa: B017 - no Docker here; the filesystem is the subject
        trial.run(settings, tmp_path, PYTHON_TRACE, into=tmp_path / "out")

    assert not (tmp_path / "hullwork.db").exists(), "a trial created a database"
