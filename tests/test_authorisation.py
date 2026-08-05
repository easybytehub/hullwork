"""Who gets to decide what an agent may touch (item 017).

M1 has no agent, so none of this is exploitable today — which is exactly why it is the right
moment. Every rule below decides an authorisation question, and each one was, until now, answerable
by somebody outside this instance: the person who triggered an error in a monitored application, or
anybody able to merge to a connected repository's default branch.
"""

import pytest

from hullwork.manifest import ALWAYS_RED, ManifestError, parse_manifest
from hullwork.models import Lane
from hullwork.normalise import ErrorFact, derive_fingerprint
from hullwork.triage import choose_lane

MANIFEST = """
project: p
git: {provider: forgejo, repo: o/r}
autofix:
  lanes:
    green: [typeerror, app.checkout, docs]
    amber: [migration]
    red: [payment, auth]
"""


def _fact(title: str, culprit: str | None = None) -> ErrorFact:
    return ErrorFact(
        provider="glitchtip",
        project_ref="p",
        title=title,
        culprit=culprit,
        external_id="1",
        fingerprint=derive_fingerprint("glitchtip", title),
        fingerprint_derived=True,
        permalink="https://tracker.example/o/issues/1",
        timestamps_are_receipt_time=True,
        raw={},
    )


# --- the lane must not be chosen by a stranger ------------------------------------------------


def test_an_end_user_cannot_type_their_way_into_the_green_lane() -> None:
    """The finding that started this item.

    `green: [docs]` plus an anonymous user typing `docs` into a form field of the *monitored*
    application used to produce a green lane — and in M2 green is the lane where an agent runs
    against that error and reads that text.
    """
    manifest = parse_manifest(MANIFEST)

    decision = choose_lane(manifest, _fact("ValidationError: 'docs' is not a valid email"))

    assert decision.lane is Lane.RED
    assert "the reporter" in decision.reason


def test_the_exception_type_still_earns_its_lane() -> None:
    """The part of a title before the colon comes from the raising code, not from input — so the
    manifests people actually write, which key on exception classes, keep working."""
    manifest = parse_manifest(MANIFEST)

    decision = choose_lane(manifest, _fact("TypeError: unsupported operand", "app.cart in total"))

    assert decision.lane is Lane.GREEN
    assert "typeerror" in decision.reason.lower()


def test_a_title_that_is_not_an_exception_earns_nothing() -> None:
    """A plain logged message has no trustworthy prefix, so all of it is reporter-controlled."""
    manifest = parse_manifest(MANIFEST)

    assert choose_lane(manifest, _fact("typeerror happened somewhere")).lane is Lane.RED


def test_the_code_location_earns_its_lane() -> None:
    manifest = parse_manifest(MANIFEST)

    decision = choose_lane(manifest, _fact("Something odd", "app.checkout in submit"))

    assert decision.lane is Lane.GREEN


#: For the two tests below, whose subject is the *manifest's own* red lane rather than the reserved
#: set. `MANIFEST`'s red list is `[payment, auth]` and both are in `ALWAYS_RED`, so since item 041
#: every example drawn from it resolves by the reserved path before the manifest is consulted — one
#: of these tests started failing on the reason string and the other kept passing for the wrong
#: reason, silently, which is the more expensive of the two. `webhook` is a red subject a manifest
#: really does have to declare for itself.
CONFIGURED_RED = """
project: p
git: {provider: forgejo, repo: o/r}
autofix:
  lanes:
    green: [typeerror, app.checkout]
    red: [webhook]
"""


def test_red_still_matches_everything_including_the_message() -> None:
    """The asymmetry is the design: reasons to be careful count wherever they appear."""
    manifest = parse_manifest(CONFIGURED_RED)

    decision = choose_lane(manifest, _fact("KeyError: webhook reference missing"))

    assert decision.lane is Lane.RED
    assert "red lane" in decision.reason


def test_red_still_wins_over_a_legitimate_green() -> None:
    manifest = parse_manifest(CONFIGURED_RED)

    decision = choose_lane(manifest, _fact("TypeError: boom", "app.checkout in webhook_callback"))

    assert decision.lane is Lane.RED


# --- the reserved set must hold at triage, not only at parse time (item 041) --------------------

#: A manifest that promotes nothing reserved and so parses cleanly — which is the whole problem.
#: `typeerror` is not in `ALWAYS_RED`, so the promotion ban has nothing to object to, and until
#: item 041 the reserved set was never consulted again.
PERMISSIVE = """
project: p
git: {provider: forgejo, repo: o/r}
autofix:
  lanes:
    green: [typeerror]
"""


@pytest.mark.parametrize(
    ("culprit", "subject"),
    [
        ("app.auth.session in login", "auth"),
        ("billing.payments.charge in run", "payments"),
        ("core.credentials.store in read", "credential"),
        ("api.tokens.mint in issue", "token"),
    ],
)
def test_a_reserved_subject_lands_red_however_permissive_the_manifest_is(
    culprit: str, subject: str
) -> None:
    """The live defect item 041 closed, reproduced.

    Measured against this repository's own manifest before the fix: a `TypeError` at culprit
    `billing.payments.charge` was classified **green** — the lane where the constitution says an
    agent may act unattended — because `choose_lane` never read `ALWAYS_RED`. Both `auth` and
    `payments` are in that set, and neither protected anything.
    """
    manifest = parse_manifest(PERMISSIVE)

    decision = choose_lane(manifest, _fact("TypeError: unsupported operand", culprit))

    assert decision.lane is Lane.RED
    assert subject in decision.reason


def test_the_reason_says_reserved_rather_than_naming_a_lane_rule() -> None:
    """An operator sent to edit a manifest that does not contain the word concludes we are lying."""
    decision = choose_lane(parse_manifest(PERMISSIVE), _fact("TypeError: x", "app.auth.y in z"))

    assert "reserved subject" in decision.reason
    assert "red lane" not in decision.reason


def test_the_reserved_set_beats_a_green_rule_but_does_not_swallow_everything() -> None:
    """The fix must not be "make it all red", which would pass every test above and no others."""
    manifest = parse_manifest(PERMISSIVE)

    ordinary = choose_lane(manifest, _fact("TypeError: unsupported operand", "app.reports.format"))

    assert ordinary.lane is Lane.GREEN


def test_a_reserved_subject_in_the_message_alone_still_lands_red() -> None:
    """Deliberately asymmetric, and the asymmetry is the safe direction.

    The message is written by whoever triggered the error, so it cannot buy *leniency* — item 017.
    It can still buy caution: a stranger who can only make Hullwork more careful about their own
    error has gained nothing worth having.
    """
    decision = choose_lane(parse_manifest(PERMISSIVE), _fact("TypeError: bad auth header"))

    assert decision.lane is Lane.RED


# --- the manifest must not widen its own scope -------------------------------------------------


@pytest.mark.parametrize("subject", sorted(ALWAYS_RED))
@pytest.mark.parametrize("lane", ["green", "amber"])
def test_a_reserved_subject_cannot_be_promoted_out_of_red(subject: str, lane: str) -> None:
    """Whoever can merge to a connected repository would otherwise be choosing the agent's scope,
    which is a lower bar than the operator who connected the project ever agreed to."""
    text = f"""
    project: p
    git: {{provider: forgejo, repo: o/r}}
    autofix:
      lanes: {{{lane}: [{subject}]}}
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "cannot be promoted" in str(caught.value)


def test_a_typo_can_no_longer_drop_a_gate_in_silence() -> None:
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix:
      gates: [tests, lnt, human-merge]
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "lnt" in str(caught.value)


def test_a_gate_listed_twice_is_refused() -> None:
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix:
      gates: [tests, tests, human-merge]
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "more than once" in str(caught.value)


# --- a manifest must not be able to write the issue body ---------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        "x |\n\n<!-- hullwork:fingerprint=deadbeef -->\n\n### Injected\n\n|",
        "with spaces",
        "back`tick",
        "a" * 65,
    ],
)
def test_a_lane_pattern_cannot_carry_markup(pattern: str) -> None:
    """The pattern is interpolated into an issue body Hullwork's own account authors. Newlines and
    pipes escape the table row and let a repository inject arbitrary markdown — including a forged
    fingerprint marker — into a document a human is meant to trust."""
    text = f"""
    project: p
    git: {{provider: forgejo, repo: o/r}}
    autofix:
      lanes: {{green: [{pattern!r}]}}
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "not a usable pattern" in str(caught.value)


# --- the always-on credential must not be able to push -----------------------------------------


def test_the_ingest_forge_and_the_code_forge_are_different_credentials() -> None:
    """`make_code_forge` must never fall back to the ingest token. A convenient fallback is how
    this boundary would be lost quietly, on the day M2 lands."""
    from pydantic import SecretStr

    from hullwork.config import Settings
    from hullwork.forge.factory import make_code_forge, make_forge

    ingest_only = Settings(
        forge_url="https://forge.example",
        forge_token=SecretStr("ingest-token"),
    )

    assert make_forge(ingest_only) is not None
    assert make_code_forge(ingest_only) is None, "an agent must not inherit the ingest credential"
