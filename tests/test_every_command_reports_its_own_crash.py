"""Error reporting covers every command, not the two long-running programs. Item 157.

**What was measured before this.** With a DSN configured in the published image,
`hullwork projects list` crashed with an unhandled `DatabaseError` and **nothing was sent** — not
scrubbed, not dropped upstream, never captured. `configure_error_reporting` was called from
`main.lifespan` and from the `work` command, and from nowhere else, so an operator reading
`error reporting: on` in `hullwork status` had been told something true about the service and false
about the tool.

`init`, `projects add` and `try` are the first three commands a stranger runs, before there is a
service to report anything. They were the silent ones.
"""

from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from hullwork import cli, telemetry, upstream
from hullwork.config import ConfigError, Settings

ROOT = Path(__file__).resolve().parent.parent

OURS = "https://clavepublica@errores.example.com/3"


# --------------------------------------------------------------------------------------------
# Which command a report is counted under
# --------------------------------------------------------------------------------------------


def test_every_command_gets_a_label_and_the_labels_are_enumerated() -> None:
    """A label the enumeration does not know becomes `unknown`, which is silent — so every command
    the parser accepts has to be in `upstream.OPERATIONS`, and that is checked elsewhere. This is
    the other half: the label is derived from the command rather than left at the default.
    """
    for subcommand in ("status", "doctor", "projects", "try", "init"):
        args = argparse.Namespace(group=subcommand)
        assert cli._label(args) == f"cli:{subcommand}"
        assert cli._label(args) in upstream.OPERATIONS

    assert cli._label(argparse.Namespace()) == f"cli:{upstream.UNKNOWN}"


# --------------------------------------------------------------------------------------------
# The cost, which is why the light path exists
# --------------------------------------------------------------------------------------------


def test_a_command_arms_reporting_without_importing_the_sdk() -> None:
    """**The measurement that changed the design.** Arming the SDK cost **+157 ms on the median
    `hullwork status`, 43%** — on a command people run in a loop, in a `watch`, in a script.

    What the SDK is for in the two long-running programs is catching what a framework already
    caught: an exception Starlette handles never reaches `sys.excepthook`. A command has no
    framework, so its crashes leave exactly one way, and `event_for_a_crash_here` already builds the
    event from a live traceback. The light path costs **+7 ms**.

    In a subprocess, because `sys.modules` in this one has the SDK from every other test.
    """
    snippet = (
        "import sys;"
        "from hullwork.config import get_settings;"
        "from hullwork import telemetry;"
        "telemetry.configure_error_reporting("
        "    get_settings(), operation='cli:status', brief=True);"
        "print('sentry_sdk' in sys.modules)"
    )
    done = subprocess.run(  # noqa: S603 - argv is this interpreter and a literal above
        [sys.executable, "-c", snippet],
        capture_output=True,
        text=True,
        check=True,
        env={
            **os.environ,
            "HULLWORK_UPSTREAM_DSN": OURS,
            "HULLWORK_DATABASE_URL": "sqlite://",
        },
    )

    assert done.stdout.strip() == "False", (
        f"a command imported the SDK: {done.stdout!r} {done.stderr[-400:]!r}"
    )
    assert "errores.example.com" in done.stderr, "the notice still has to be printed"


def test_the_operators_own_tracker_still_gets_the_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """The light path is for **our** destination only. Somebody who configured their own tracker
    asked for whole events, and whole events are what the SDK collects.
    """
    import sentry_sdk

    said = io.StringIO()
    try:
        assert telemetry.configure_error_reporting(
            Settings(
                database_url="sqlite://", error_dsn=SecretStr("https://k@tracker.example/1")
            ),
            brief=True,
            notify=said,
        )
        assert sentry_sdk.get_client().is_active(), "their tracker needs a live client"
    finally:
        sentry_sdk.init(dsn=None)


# --------------------------------------------------------------------------------------------
# What is reported and what is not
# --------------------------------------------------------------------------------------------


def test_the_light_path_installs_a_hook_that_reports_and_still_prints() -> None:
    """The two halves that make this safe: the report is attempted, and Python's own traceback is
    printed exactly as it was. A crash handler that swallows the crash is worse than no handler.
    """
    printed: list[str] = []
    sent: list[dict[str, Any]] = []

    original = sys.excepthook
    try:
        sys.excepthook = lambda *args: printed.append(str(args[1]))
        def record(event: Mapping[str, Any]) -> bool:
            sent.append(dict(event))
            return True

        destination = upstream.Destination(OURS, operation="cli:status")
        destination.offer = record  # type: ignore[method-assign]

        telemetry._report_crashes_without_the_sdk(destination, notify=io.StringIO())
        hook = sys.excepthook

        try:
            msg = "el proyecto acme/checkout-api de ana@cliente-real.es"
            raise RuntimeError(msg)
        except RuntimeError as raised:
            hook(type(raised), raised, raised.__traceback__)

        assert printed == ["el proyecto acme/checkout-api de ana@cliente-real.es"], (
            "the operator's own traceback must be untouched"
        )
        assert len(sent) == 1
    finally:
        sys.excepthook = original


@pytest.mark.parametrize("polite", [KeyboardInterrupt(), SystemExit(1)])
def test_ctrl_c_and_a_clean_exit_are_not_bug_reports(polite: BaseException) -> None:
    """Somebody pressing ctrl-c is not a defect, and neither is a command exiting non-zero on
    purpose. Both reach `sys.excepthook`; neither is ours to collect.
    """
    sent: list[object] = []
    original = sys.excepthook
    try:
        sys.excepthook = lambda *_: None
        def record(event: Mapping[str, Any]) -> bool:
            sent.append(event)
            return True

        destination = upstream.Destination(OURS, operation="cli:status")
        destination.offer = record  # type: ignore[method-assign]

        telemetry._report_crashes_without_the_sdk(destination, notify=io.StringIO())
        sys.excepthook(type(polite), polite, None)

        assert sent == []
    finally:
        sys.excepthook = original


def test_a_command_with_no_destination_installs_nothing() -> None:
    """No DSN, no hook, no notice, no cost. The default for anybody with a checkout."""
    before = sys.excepthook
    said = io.StringIO()

    plain = Settings(database_url="sqlite://")

    assert telemetry.configure_error_reporting(plain, brief=True, notify=said) is False
    assert sys.excepthook is before
    assert said.getvalue() == ""


def test_the_notice_is_one_line_for_a_command() -> None:
    """Ten lines on every `hullwork status` would be the wrong kind of honest — and a disclosure
    nobody can scroll past becomes a disclosure nobody reads.
    """
    line = upstream.notice_line("errores.example.com")

    assert "\n" not in line
    assert "errores.example.com" in line
    assert "HULLWORK_TELEMETRY=off" in line
    assert "hullwork config --telemetry" in line


# --------------------------------------------------------------------------------------------
# A refusal is not a defect, which is item 120's boundary and this must not undo it
# --------------------------------------------------------------------------------------------


def test_the_handled_failures_never_reach_an_excepthook() -> None:
    """**The boundary this item could have destroyed.** `CommandError`, the sandbox's declared
    failures, `ConfigError` and a database that will not answer are all *caught* in `main` and
    rendered as sentences — so they never reach a hook, whatever a hook does.

    Asserted on the source rather than by running sixteen commands: what matters is that the arming
    happens **inside** the same `try` whose `except` arms handle those four, so a future edit that
    moves it outside would be visible here.
    """
    text = (ROOT / "hullwork/cli.py").read_text(encoding="utf-8")

    armed = text.index('if getattr(args, "group", None) != "work":')
    for handled in ("except CommandError as exc:", "except SANDBOX_FAILURES as exc:",
                    "except SQLAlchemyError as exc:", "except ConfigError as exc:"):
        # Searched **from** the arming: `CommandError` is also handled in the scaffolding branch
        # above, and finding that one first made this assert the opposite of what it means.
        assert text.find(handled, armed) > 0, f"{handled} no longer follows the arming"


def test_work_is_not_armed_twice() -> None:
    """`work` arms its own further down, with a session, so its reports carry this installation's
    identifier. Arming it here as well would print the notice twice and label the same process two
    ways.
    """
    text = (ROOT / "hullwork/cli.py").read_text(encoding="utf-8")

    assert 'if getattr(args, "group", None) != "work":' in text
    assert 'operation="dispatcher"' in text, "the dispatcher's own arming is what this defers to"


def test_a_scaffolding_command_never_fails_because_of_its_own_telemetry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`init` writes a deployment's first two files, so it has to work when the environment is empty
    or wrong. Refusing it because *error reporting* could not be set up would invert that entirely.

    The honest consequence, stated in the code and here: `hullwork init` reports its crashes only
    when the environment is already valid.
    """
    def explode(*_args: object, **_kwargs: object) -> None:
        msg = "HULLWORK_SWEEP_INTERVAL_SECONDS is not a number"
        raise ConfigError(msg)

    monkeypatch.setattr(cli, "get_settings", explode)
    cli._arm_reporting_quietly(argparse.Namespace(group="init"))  # must not raise
