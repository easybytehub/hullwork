"""Which commit a reproduction is about (item 039).

The failure this prevents is quiet and expensive: a bug fixed on the default branch but not yet
deployed keeps reporting from production, the candidate test passes on the pristine tree, and the
item ends `not-reproducible` — terminal, one attempt consumed, for a bug that is entirely real.
It hits every project that merges more often than it deploys, which is all of them.
"""

import pytest
from sqlalchemy.orm import Session

from hullwork.attempts import finish, start
from hullwork.models import AttemptOutcome, Item
from hullwork.refs import RefQuality, classify, verdict_for


def test_a_real_commit_that_the_repository_has_is_usable() -> None:
    ref = classify("b292599", exists=True)

    assert ref.quality is RefQuality.RESOLVED
    assert ref.usable
    assert ref.sha == "b292599"


def test_a_missing_release_falls_back_to_the_tip_and_says_so() -> None:
    ref = classify(None)

    assert ref.quality is RefQuality.ABSENT
    assert not ref.usable
    assert "may not be what was running" in ref.note


@pytest.mark.parametrize("release", ["0.1.0.dev0", "v2.3.1", "main", "latest", "not-a-sha!"])
def test_a_version_string_is_not_a_commit(release: str) -> None:
    """Hullwork's own release is a version string, constant across every deploy between bumps.

    Parametrised with `0.1.0.dev0` rather than the current version on purpose: what is under test is
    that a *version-shaped* string is not mistaken for a commit, and pinning this to whatever
    `__version__` says today would make a release bump break a test about parsing.
    """
    ref = classify(release, exists=True)

    assert ref.quality is RefQuality.NOT_A_COMMIT
    assert not ref.usable
    assert ref.raw == release


def test_a_stale_sha_is_refused_rather_than_substituted() -> None:
    """A stale release is worse than a missing one: it points the reproduction confidently wrong."""
    ref = classify("deadbee", exists=False)

    assert ref.quality is RefQuality.UNKNOWN_TO_THE_REPOSITORY
    assert ref.sha is None
    assert "substituting a guess" in ref.note


def test_an_unverified_sha_is_not_trusted() -> None:
    """Nobody asked the forge, so nobody knows. Acting on it anyway is the same bug, later."""
    ref = classify("b292599")

    assert ref.quality is RefQuality.UNKNOWN_TO_THE_REPOSITORY
    assert not ref.usable
    assert "nothing confirmed it exists" in ref.note


def test_too_short_to_be_a_sha_is_not_a_sha() -> None:
    assert classify("abc123", exists=True).quality is RefQuality.NOT_A_COMMIT


def test_the_raw_value_is_always_kept_for_the_evidence_trail() -> None:
    assert classify("0.1.0.dev0", exists=True).raw == "0.1.0.dev0"


# --- what two gate runs mean together ---------------------------------------------------------


def test_present_at_the_tip_is_the_ordinary_case() -> None:
    assert verdict_for(reproduces_at_release=True, reproduces_at_tip=True) == "reproduced"


def test_present_in_production_and_absent_at_the_tip_is_already_fixed() -> None:
    """The cell this whole item exists for. A fact about the deployment, not about the bug."""
    assert verdict_for(reproduces_at_release=True, reproduces_at_tip=False) == "already-fixed"


def test_absent_in_both_is_genuinely_not_reproducible() -> None:
    assert verdict_for(reproduces_at_release=False, reproduces_at_tip=False) == "not-reproducible"


def test_already_fixed_does_not_spend_the_attempt(
    session_and_item: tuple[Session, Item],
) -> None:
    """The agent was never given a fair attempt, so it does not lose its only one."""
    session, item = session_and_item
    attempt = start(session, item)

    finish(session, attempt, AttemptOutcome.ALREADY_FIXED)

    assert attempt.consumed is False
    assert "not yet deployed" in (attempt.not_consumed_reason or "")


def test_already_fixed_explains_itself_without_being_told(
    session_and_item: tuple[Session, Item],
) -> None:
    """A caller that forgets the reason still leaves something a human can act on."""
    session, item = session_and_item

    attempt = finish(session, start(session, item), AttemptOutcome.ALREADY_FIXED)

    assert attempt.not_consumed_reason
    assert "fixed already" in attempt.not_consumed_reason


@pytest.fixture
def session_and_item() -> tuple[Session, Item]:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from hullwork.models import Base, Lane, Project

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    project = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
    )
    session.add(project)
    session.flush()
    item = Item(project_id=project.id, fingerprint="fp", title="t", lane=Lane.GREEN)
    session.add(item)
    session.flush()
    return session, item
