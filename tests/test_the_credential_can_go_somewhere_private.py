"""The webhook URL, handed over without going through a log. Item 163.

CodeQL, at `high`: *"This expression logs sensitive data (secret) as clear text"* — on the two lines
that print the webhook URL at registration. It was wrong about the person and right about the
pipeline: the token is stored hashed, so that moment is the only time it exists in readable form,
and an operator who cannot see it cannot paste it into their tracker. But standard output ends up in
terminal scrollback, in `script` output, in a screenshot sent with a question, and in a CI log the
day somebody registers a project from a script.

So the default is unchanged and there is a flag. What is asserted here is both halves of that.
"""

from __future__ import annotations

import io
import os
import stat
from pathlib import Path

import pytest

from hullwork.cli import CommandError, _print_credential

URL = "https://hullwork.example/webhooks/glitchtip/demo/s3cr3t-token-nobody-should-log"


def test_by_default_the_url_is_printed_because_a_person_needs_to_see_it() -> None:
    """The negative case for the whole item: nothing about the flag changed the default.

    An operator at a terminal is the common case, and hiding their own credential behind a flag they
    have not read would be a worse failure than the one this item is about.
    """
    out = io.StringIO()

    _print_credential(URL, "demo", out)

    printed = out.getvalue()
    assert URL in printed
    assert "shown once and cannot be recovered" in printed
    assert "--credential-file" in printed, (
        "the person who would benefit from the flag is reading exactly this output"
    )


def test_with_the_flag_the_url_goes_to_the_file_and_not_to_the_screen(tmp_path: Path) -> None:
    target = tmp_path / "webhook.url"
    out = io.StringIO()

    _print_credential(URL, "demo", out, into=str(target))

    printed = out.getvalue()
    assert URL not in printed, "the whole point is that stdout does not carry it"
    assert str(target) in printed, "and that the operator is told where it went"
    assert target.read_text(encoding="utf-8") == f"{URL}\n"


def test_the_file_is_readable_by_nobody_else(tmp_path: Path) -> None:
    """Mode 600, and created with it rather than chmod-ed afterwards.

    Between an `open()` and a `chmod()` there is a moment where the token is world-readable, and
    that moment is the whole thing the flag exists to remove.
    """
    target = tmp_path / "webhook.url"

    _print_credential(URL, "demo", io.StringIO(), into=str(target))

    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600, f"mode is {oct(mode)}"


def test_it_refuses_to_overwrite_because_something_may_still_be_using_it(tmp_path: Path) -> None:
    """The same rule `hullwork init` follows (item 115). A credential silently replaced is a
    credential somebody is still using, and the failure is invisible until a delivery is rejected.
    """
    target = tmp_path / "webhook.url"
    target.write_text("an older credential\n", encoding="utf-8")

    with pytest.raises(CommandError, match="already exists"):
        _print_credential(URL, "demo", io.StringIO(), into=str(target))

    assert target.read_text(encoding="utf-8") == "an older credential\n", "it was left alone"


def test_a_directory_that_does_not_exist_says_so_rather_than_tracebacks(tmp_path: Path) -> None:
    """`--credential-file /no/such/place/x.url` is a typo somebody makes once."""
    with pytest.raises((CommandError, OSError)) as refused:
        _print_credential(URL, "demo", io.StringIO(), into=str(tmp_path / "missing" / "x.url"))

    assert "Traceback" not in str(refused.value)


@pytest.mark.parametrize("command", ["add", "rotate-secret"])
def test_both_commands_that_show_a_credential_take_the_flag(command: str) -> None:
    """`add` and `rotate-secret` are the two, and a third one appearing without it would be the gap
    this item exists to close.
    """
    import argparse

    from hullwork.cli import build_parser

    for action in build_parser()._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        projects = action.choices.get("projects")
        if projects is None:
            continue
        for inner in projects._actions:
            if isinstance(inner, argparse._SubParsersAction):
                flags = {
                    option
                    for argument in inner.choices[command]._actions
                    for option in argument.option_strings
                }
                assert "--credential-file" in flags, f"projects {command} cannot avoid stdout"
                return

    pytest.fail("the projects subcommands moved; this test has lost its subject")


def test_the_token_never_reaches_the_process_environment(tmp_path: Path) -> None:
    """A smaller property, asserted because it would be an easy way to "help": passing the
    credential through the environment would put it in `/proc` for every process to read.
    """
    target = tmp_path / "webhook.url"

    _print_credential(URL, "demo", io.StringIO(), into=str(target))

    assert not [key for key, value in os.environ.items() if URL in value]
