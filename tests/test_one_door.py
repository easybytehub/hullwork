"""One command answers *what is still missing*. Item 200.

Two functions answered it four hours apart, both written the same day: `what_is_still_needed` named
variables scoped to what the operator asked for, and `preflight.examine` named checks and could say
whether the forge answered. Neither contained the other and nothing made them agree — which is items
193 and 194 with different nouns, caught before it drifted rather than after.

`init` is the door. The `preflight` subcommand is gone.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import socket
import urllib.request
from io import StringIO
from pathlib import Path

import pytest

from hullwork import preflight, scaffold
from hullwork.cli import build_parser, main
from hullwork.config import Settings


def _init(tmp_path: Path, *extra: str) -> str:
    out = StringIO()
    assert main(["init", "--into", str(tmp_path), *extra], out=out) == 0
    return out.getvalue()


# --- one door ------------------------------------------------------------------------------------


def test_the_second_run_says_where_you_stand(tmp_path: Path) -> None:
    """**The run that matters, and it was the least useful output in the product.** It said
    *nothing to do: both files already exist* — at the exact moment somebody has pasted a token and
    wants to know whether it works.
    """
    _init(tmp_path)

    again = _init(tmp_path)

    assert "Nothing to do" not in again
    assert "HULLWORK_FORGE_TOKEN" in again, "the report, on a run that writes nothing"


def test_the_first_run_says_it_too(tmp_path: Path) -> None:
    """Both runs, or the report is a consolation prize for having done it twice."""
    assert "HULLWORK_FORGE_TOKEN" in _init(tmp_path)


def test_there_is_no_preflight_subcommand() -> None:
    """Nineteen subcommands is a lot; twenty is more. A second door to a room that already has one
    is surface, and this repository's own rule is that a subcommand is declared before it exists."""
    from hullwork import upstream

    with pytest.raises(SystemExit):
        build_parser().parse_args(["preflight"])

    assert "cli:preflight" not in upstream.OPERATIONS


def test_one_function_answers_what_is_missing() -> None:
    """**Asserted by construction**, because two lists kept equal by hand is what produced this.

    The capability table is where a variable's consequence is written. A second enumeration of
    variables and reasons — anywhere — is the defect coming back.
    """
    import inspect

    from hullwork.cli import _cmd_init

    source = inspect.getsource(_cmd_init)

    assert "preflight.examine" in source, "the report comes from the one place that assembles it"
    assert "HULLWORK_" not in source, (
        "a variable's consequence is written in the capability table and read from there"
    )


# --- what it costs, and the bound on it ----------------------------------------------------------


def test_nothing_configured_reaches_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The commonest first contact there is.** A setup command that quietly opens a socket is one
    somebody has to audit, so an unconfigured run must be able to say it contacted nobody — asserted
    by making every route out raise, the way `features` does it.
    """

    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("init reached the network with nothing configured")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)

    assert _init(tmp_path)


def test_the_help_says_it_reaches_the_network() -> None:
    """It reached nothing before this item. A behaviour change in the first command a stranger runs
    belongs in that command's own help, not in a release note nobody reads."""
    parser = build_parser()

    said = parser.parse_args(["init", "--into", "."])

    del said
    text = parser.format_help()
    assert "init" in text
    from hullwork.cli import _init_description

    assert "network" in _init_description().lower()


def test_no_sentinel_path_reaches_the_operator(tmp_path: Path) -> None:
    """**Found by running it.** The environment check named `/nonexistent/preflight/.env` — a
    sentinel this module uses when there is no file to compare against, printed at somebody who has
    a real one two lines above. A path nobody has is an instruction nobody can follow.
    """
    scaffold.write(tmp_path, docker_gid=None)

    found = preflight.examine(
        Settings(), environment_file=tmp_path / scaffold.ENVIRONMENT_FILE
    )

    assert "nonexistent" not in " ".join(one.detail for one in found)


def test_an_unknown_still_never_sets_the_exit_code() -> None:
    """Item 073's rule survives the move. A laptop that cannot reach the forge it is configuring
    must not fail somebody's install script for a fact about the laptop."""
    from hullwork.doctor import Finding, State

    assert preflight.exit_code([Finding("x", State.UNKNOWN, "y")]) == 0
    assert preflight.exit_code([Finding("x", State.BROKEN, "y")]) == 1


def test_the_report_names_the_capability_a_variable_belongs_to(tmp_path: Path) -> None:
    """One listing, not two sections repeating each other. A variable with no capability beside it
    is a name; the capability is what makes it a decision somebody can take."""
    scaffold.write(tmp_path, docker_gid=None)

    found = preflight.examine(
        Settings(),
        answers=scaffold.Answers(),
        environment_file=tmp_path / scaffold.ENVIRONMENT_FILE,
    )

    said = " ".join(one.detail for one in found)
    assert "become issues" in said, "the capability, in the same listing as the variable"
    assert any(one.check == "HULLWORK_FORGE_TOKEN" for one in found)
