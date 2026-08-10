"""What is wrong before anything is built. Item 199.

Item 198 measured that `doctor` answers 26 checks against an in-memory session with no instance in
existence, and that it **touches no network at all** — it said `ok` to `https://forge.example.com`,
an address that does not resolve, because the question it asks is *which forge is this configured
for*. So the guidance already existed one `docker compose up --build` too late, and half of it was
about shape rather than reality.

This is the command that runs before the containers, and the layer that asks whether the things you
named actually answer.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from hullwork import preflight
from hullwork.config import Settings
from hullwork.doctor import Finding, State


class _UnreachableError(Exception):
    pass


def _nothing_answers(*_a: object, **_k: object) -> None:
    raise _UnreachableError


def _named(found: list[Finding], check: str) -> Finding:
    return next(one for one in found if one.check == check)


# --- it runs before there is anything to run against ---------------------------------------------


def test_it_writes_nothing_and_creates_no_database(tmp_path: Path) -> None:
    """**The trap item 115 exists for**, and the reason `init` opens no database: a stray session
    creates an empty `hullwork.db` in whatever directory the operator happens to be standing in.
    This command runs in exactly that directory, before there is a deployment at all.
    """
    before = sorted(p.name for p in tmp_path.iterdir())

    preflight.examine(Settings(database_url=f"sqlite:///{tmp_path}/hullwork.db"))

    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_a_missing_schema_is_the_expected_state_not_a_fault(tmp_path: Path) -> None:
    """A pre-flight whose first line is a red herring teaches its reader to skim the rest. There
    being no database yet is what a pre-flight is *for*, so `expected` is the honest state — which
    `State` already distinguishes from `ok` on purpose."""
    found = preflight.examine(Settings())

    database = _named(found, "database")

    assert database.state is State.EXPECTED


def test_every_check_the_doctor_makes_is_still_here() -> None:
    """It is the same command, earlier — not a smaller one somebody has to run twice.

    **Asserted against `doctor` itself rather than against a number.** The first version of this
    demanded twenty distinct checks, which came from a run whose `env_file` was a real `deploy.env`
    — that file contributes one finding per variable, so the threshold was measuring the fixture.
    A check added to `doctor` tomorrow has to reach here without anybody remembering.
    """
    settings = Settings(forge_url="https://forge.example.com")
    from hullwork.db import make_engine, make_session_factory
    from hullwork.doctor import examine as doctors

    with make_session_factory(make_engine("sqlite:///:memory:"))() as session:
        theirs = {
            one.check
            for one in doctors(
                session, settings, code_forge=None, env_file=preflight._NOWHERE, compose_file=None
            )
        }

    ours = {one.check for one in preflight.examine(settings)}

    assert theirs <= ours, f"the pre-flight lost: {sorted(theirs - ours)}"


def test_nothing_tells_the_reader_to_fix_a_database_that_does_not_exist() -> None:
    """**Found by running it, not by testing it.** The `database` check read correctly as `expected`
    and the two checks that depend on it still carried their instance-flavoured advice — *fix the
    database and run this again*, about a database the reader has not created yet and should not.

    A red herring one layer down is still a red herring: it is the first output a stranger sees, and
    the first instruction in it would have been to repair nothing.
    """
    said = " ".join(one.detail for one in preflight.examine(Settings()))

    assert "Fix the database" not in said
    assert "cannot be queried" not in said


# --- the layer that did not exist: does the thing you named answer -------------------------------


def test_a_forge_that_answers_is_reported_as_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    """The question `doctor` never asked. Reported apart from *which forge is configured*, because
    a URL that parses and a host that answers are different facts and only one of them was known."""
    monkeypatch.setattr(preflight, "_answers", lambda url, timeout=5.0: True)

    found = preflight.examine(Settings(forge_url="https://forge.example.com"))

    assert _named(found, "forge answers").state is State.OK


def test_a_forge_that_does_not_resolve_is_unknown_with_the_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**The distinction this repository has got wrong three times in two days.** Not `ok`, which
    would be the permanently-on signal inverted in the first output a stranger sees; and not
    `broken`, which asserts the forge is wrong when what is known is that this machine could not
    reach it — a laptop behind a VPN is the commonest cause and is nobody's defect.
    """
    monkeypatch.setattr(preflight, "_answers", lambda url, timeout=5.0: None)

    found = preflight.examine(Settings(forge_url="https://forge.example.com"))

    answer = _named(found, "forge answers")

    assert answer.state is State.UNKNOWN
    assert "could not" in answer.detail.lower()


def test_what_the_token_may_do_is_a_separate_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reachability and authority are two questions, and a token with the wrong scopes against a
    forge that answers perfectly is the failure `projects add` currently discovers for you."""
    monkeypatch.setattr(preflight, "_answers", lambda url, timeout=5.0: True)
    monkeypatch.setattr(preflight, "_may_push", lambda *a, **k: False)

    found = preflight.examine(
        Settings(forge_url="https://forge.example.com", forge_token=SecretStr("t"))
    )

    assert _named(found, "forge token").state is State.OK


def test_the_token_is_not_asked_about_when_the_host_did_not_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**Found by mutation, and it is the collapse this module exists to refuse.** Asking what a
    token may do of a host that never answered produces a network failure wearing an authorisation
    answer's clothes — and the honest reading of a refused connection is *nothing is known about
    this token*, not *this token is fine* and not *this token is wrong*.

    Covered by neither of the two tests either side of it: one has a reachable host with a token,
    the other an unreachable host with none.
    """
    monkeypatch.setattr(preflight, "_answers", lambda url, timeout=5.0: None)

    def never(*_a: object, **_k: object) -> bool:
        raise AssertionError("it asked the forge about a token it could not reach")

    monkeypatch.setattr(preflight, "_may_push", never)

    found = preflight.examine(
        Settings(forge_url="https://forge.example.com", forge_token=SecretStr("t"))
    )

    answer = _named(found, "forge token")
    assert answer.state is State.UNKNOWN
    assert "not asked" in answer.detail


def test_nothing_is_asked_of_the_network_without_a_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**Asserted by making every route out explode**, the way `features` does it. An unconfigured
    pre-flight is the commonest first contact there is, and a setup command that quietly starts
    making outbound calls is one somebody has to audit."""
    import socket
    import urllib.request

    monkeypatch.setattr(socket, "socket", _nothing_answers)
    monkeypatch.setattr(urllib.request, "urlopen", _nothing_answers)

    found = preflight.examine(Settings())

    assert found


def test_the_reachability_checks_are_absent_rather_than_guessed() -> None:
    """With nothing configured there is nothing to reach, and a row saying `unknown` about a forge
    nobody named would be noise dressed as rigour."""
    checks = {one.check for one in preflight.examine(Settings())}

    assert "forge answers" not in checks


# --- the exit code -------------------------------------------------------------------------------


def test_an_unknown_never_sets_the_exit_code() -> None:
    """Item 073's rule, and this command is the most likely place to break it: a warning wired into
    an exit code with no action available to clear it is not a signal. A laptop behind a VPN would
    otherwise fail somebody's install script for a fact about the laptop."""
    assert preflight.exit_code([_Finding(State.UNKNOWN), _Finding(State.OK)]) == 0
    assert preflight.exit_code([_Finding(State.EXPECTED)]) == 0
    assert preflight.exit_code([_Finding(State.BROKEN)]) == 1


def _Finding(state: State) -> Finding:  # noqa: N802 - reads as the type it stands for
    return Finding("x", state, "y")
