"""An operational refusal is not a defect. Item 120.

**Measured on this repository's own issue tracker, 2026-08-02**: seven open issues, `#16` to `#22`,
every one of them the sentence the dispatcher prints when the subscription token has expired — which
is item 096 working exactly as designed. `log.error` became an event, the event became a webhook,
the webhook became an issue, and all seven landed `human-only` because there was nothing to fix.

The boundary that decides which log line costs somebody an issue was an SDK default and appeared
nowhere in this repository. It does now, and these tests hold both halves of it.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import SecretStr

from hullwork import telemetry
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.models import Base

#: Not a real DSN, and it never reaches the network: `before_send` drops every event below.
DSN = "https://0123456789abcdef0123456789abcdef@example.invalid/1"


def test_a_warning_is_not_filed_and_an_error_is(monkeypatch: pytest.MonkeyPatch) -> None:
    """**Asserted against the SDK rather than argued.** The events are intercepted in
    `before_send`, which is where a real event goes before a real transport — so this measures the
    integration's behaviour and not our belief about its defaults.
    """
    sentry_sdk = pytest.importorskip("sentry_sdk")
    seen: list[dict[str, object]] = []

    def capture(event: dict[str, object], hint: object) -> None:
        seen.append(event)
        return None  # dropped: nothing leaves this process

    # `**_` so this double survives the hook growing an argument: it did on 2026-08-06, when
    # `upstream=` arrived (item 152), and a stand-in that mirrors a signature exactly fails on a
    # change that has nothing to do with what it is standing in for.
    monkeypatch.setattr(telemetry, "make_before_send", lambda _secrets, **_: capture)
    try:
        assert telemetry.configure_error_reporting(Settings(error_dsn=SecretStr(DSN))) is True

        log = logging.getLogger("hullwork.test.levels")
        log.warning("not claiming anything: the token expired 1h15m ago")
        log.error("something is actually broken")
        sentry_sdk.flush()
    finally:
        sentry_sdk.init(dsn=None)  # leave no live client behind for the rest of the suite

    messages = [
        str(cast("dict[str, Any]", event.get("logentry", {})).get("message", ""))
        for event in seen
    ]
    assert "something is actually broken" in messages
    assert not any("not claiming anything" in message for message in messages), (
        "the refusal became an event, which is how seven issues were filed about correct behaviour"
    )


def test_the_dispatcher_logs_its_refusal_at_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Through the real loop, because the level is only worth anything where it is emitted.

    The loop is stopped by the second call to `credential_expired`: the first turn logs, waits, and
    comes round again, which is exactly the shape that produced seven issues in two days.

    Read from the emitted JSON rather than from `caplog`: `configure_logging` installs this
    project's own handler and takes the records off the path a capturing fixture sits on, so
    `caplog` reports nothing while the line is plainly on the stream. Asserting the emitted record
    is also the truer test — that string is what a log reader and an SDK both see.
    """
    from hullwork import doctor
    from hullwork.cli import main as cli_main

    url = f"sqlite:///{tmp_path / 'loop.db'}"
    Base.metadata.create_all(make_engine(url))
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    monkeypatch.setenv("HULLWORK_MODEL_KEY", "sk-not-real")
    monkeypatch.setattr("hullwork.cli.LOOP_CEILING_SECONDS", 0)
    get_settings.cache_clear()

    turns = []

    def expired(_settings: Settings) -> str:
        turns.append(1)
        if len(turns) > 1:
            raise KeyboardInterrupt  # the operator stopping it, after one full turn
        return "the token in /home/hullwork/.claude/.credentials.json expired 1h15m ago"

    monkeypatch.setattr(doctor, "credential_expired", expired)

    try:
        with pytest.raises(KeyboardInterrupt):
            cli_main(["work", "--loop"])
    finally:
        get_settings.cache_clear()

    emitted = [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("{")
    ]
    refusals = [r for r in emitted if "not claiming anything" in r["message"]]
    assert len(refusals) == 1, "said once per spell, not once per turn (item 096)"
    assert refusals[0]["level"] == "WARNING"
    assert not [r for r in emitted if r["level"] in ("ERROR", "CRITICAL")], (
        "nothing about an expected, self-clearing condition is an error"
    )


def test_what_status_and_doctor_say_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """This removes an issue, not a warning. The condition still has to be visible where a person
    looks for a stopped instance — otherwise the fix would be silence."""
    import io

    from hullwork.cli import main as cli_main

    url = f"sqlite:///{tmp_path / 'quiet.db'}"
    Base.metadata.create_all(make_engine(url))
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    monkeypatch.delenv("HULLWORK_MODEL_KEY", raising=False)
    monkeypatch.delenv("HULLWORK_MODEL_CREDENTIALS_FILE", raising=False)
    get_settings.cache_clear()
    try:
        out = io.StringIO()
        cli_main(["status"], out=out)
        printed = out.getvalue()
    finally:
        get_settings.cache_clear()

    assert "no item will be claimed" in printed
    assert "HULLWORK_MODEL_KEY" in printed
