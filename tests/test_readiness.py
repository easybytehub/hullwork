"""Can this instance say that it has stopped working? (item 019)

Until now: no. `/health` cannot fail by construction, and every other consequence of every failure
was a log line inside `docker logs`. Each test below corresponds to a way the service kept
answering 200 with a subsystem dead behind it.
"""

import io
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.orm import Session

from hullwork import readiness
from hullwork.cli import main as cli_main
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.models import Delivery, Item, Project

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _fresh_process_state() -> Iterator[None]:
    """The heartbeat and forge state are process-global, so tests must not inherit each other's."""
    _reset()
    yield
    _reset()


def _reset() -> None:
    readiness._last_sweep_ok = None
    readiness._forge_state = "unknown"
    readiness._forge_checked = None


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'readiness.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")
    with make_session_factory(make_engine(url))() as db:
        yield db
    get_settings.cache_clear()


def _settings(**overrides: object) -> Settings:
    """An **ordinary** instance, which since 2026-08-04 means one with a forge.

    The forge pair was absent here, and every test asking whether some *other* thing is a problem
    was therefore asking it of an instance that could file nothing anywhere. That stayed invisible
    while "no forge at all" produced no problem — the defect those two lines now cover.
    """
    base: dict[str, object] = {
        "database_url": "sqlite:///./x.db",
        "sweep_interval_seconds": 60,
        "forge_url": "https://forge.example.com",
        "forge_token": SecretStr("t"),
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_no_forge_is_a_gap_that_says_so_and_still_serves(session: Session) -> None:
    """**Both halves of one defect, found by two strangers an hour apart on 2026-08-04.**

    The first started the stack with no forge variables and got `READY`, exit 0, from an instance
    that could not file an issue: this check caught a forge gone *unreachable* and said nothing
    about one never configured, so `hullwork status || mail me` could never fire on the likeliest
    misconfiguration an operator ships.

    The second found the fix overshooting. Putting it in `problems` made `/ready` answer 503, and
    the image's healthcheck probes `/ready` — so the documented first look produced a permanently
    **unhealthy** container ninety seconds in, which is a worse first impression than the silence.

    So both are asserted here together, and they are the two that must never drift apart: the gap is
    **named**, and `ready` stays **true**. Either one alone passes against a wrong implementation.
    """
    readiness.record_sweep_ok()
    report = readiness.check(
        session, _settings(forge_url=None, forge_token=None), error_reporting=False
    )

    assert any("no forge is configured" in gap for gap in report.gaps)
    assert report.problems == [], "nothing broke; something was never supplied"
    assert report.ready, "a receiver with no forge still accepts webhooks, so /ready must serve"


@pytest.mark.parametrize("as_json", [False, True])
def test_a_gap_still_exits_one_from_both_renderers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, as_json: bool
) -> None:
    """The exit code is the monitoring contract, and it is computed **twice** in `_cmd_status` —
    once for `--json` and once for the human rendering.

    Written because changing one and not the other is exactly what happened while fixing this: the
    verdict printed `NOT CONFIGURED` above an exit code of zero, the shape item 019 exists to end.
    Parametrised over both renderings so neither can drift from the other again.
    """
    from alembic import command
    from alembic.config import Config

    from hullwork.cli import main as cli_main

    url = f"sqlite:///{tmp_path / 'gap.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.delenv("HULLWORK_FORGE_URL", raising=False)
    monkeypatch.delenv("HULLWORK_FORGE_TOKEN", raising=False)
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")
    get_settings.cache_clear()

    argv = ["status", "--json"] if as_json else ["status"]
    out = io.StringIO()
    code = cli_main(argv, out=out)
    get_settings.cache_clear()

    assert code == 1, "an instance that can never file an issue must fail `status || mail me`"
    assert "no forge is configured" in out.getvalue()


def test_a_healthy_instance_is_ready(session: Session) -> None:
    readiness.record_sweep_ok()
    report = readiness.check(session, _settings(), error_reporting=False)

    assert report.ready
    assert report.problems == []


def test_a_configured_but_inert_sdk_is_not_ready(session: Session) -> None:
    """The failure that looked healthiest: `docker compose restart` does not re-read `env_file`,
    so the container came up green with error reporting switched off and nothing said so."""
    readiness.record_sweep_ok()
    report = readiness.check(
        session,
        _settings(error_dsn=SecretStr("https://k@tracker/1")),
        error_reporting=False,
    )

    assert not report.ready
    assert any("error reporting" in problem for problem in report.problems)


def test_an_unreachable_forge_is_not_ready(session: Session) -> None:
    """Recorded by the sweep, which talks to the forge anyway — the probe makes no network calls."""
    readiness.record_sweep_ok()
    readiness.record_forge("unreachable:401")

    report = readiness.check(session, _settings(), error_reporting=False)

    assert not report.ready
    assert report.forge == "unreachable:401"


def test_a_stopped_retry_clock_is_not_ready(session: Session) -> None:
    readiness.record_sweep_ok()
    readiness._last_sweep_ok -= 400  # type: ignore[operator]

    report = readiness.check(session, _settings(), error_reporting=False)

    assert not report.ready
    assert any("no sweep has completed" in problem for problem in report.problems)


def test_a_disabled_retry_clock_is_not_ready(session: Session) -> None:
    report = readiness.check(session, _settings(sweep_interval_seconds=0), error_reporting=False)

    assert not report.ready
    assert any("retry clock is disabled" in problem for problem in report.problems)


def test_a_stuck_backlog_is_not_ready(session: Session) -> None:
    readiness.record_sweep_ok()
    session.add(
        Project(slug="p", forge="forgejo", repo="o/r", webhook_secret_hash="x")  # noqa: S106
    )
    session.commit()
    session.add(
        Item(
            project_id=1,
            fingerprint="f",
            title="owed an issue since yesterday",
            forge_sync_pending=True,
            updated_at=datetime.now(UTC) - timedelta(hours=2),
        )
    )
    session.commit()

    report = readiness.check(session, _settings(), error_reporting=False)

    assert not report.ready
    assert report.backlog == 1
    assert any("still owed an issue" in problem for problem in report.problems)


def test_delivery_silence_is_reported_but_never_fatal(session: Session) -> None:
    """A tracker notifies once per issue, so deliveries are rare by design. Any threshold on this
    would either cry wolf constantly or never fire — it is a number to read, not a gate."""
    readiness.record_sweep_ok()
    session.add(
        Project(slug="p", forge="forgejo", repo="o/r", webhook_secret_hash="x")  # noqa: S106
    )
    session.commit()
    session.add(
        Delivery(
            project_id=1,
            payload_hash="h",
            received_at=datetime.now(UTC) - timedelta(days=30),
        )
    )
    session.commit()

    report = readiness.check(session, _settings(), error_reporting=False)

    assert report.ready
    assert report.last_delivery_age_s is not None
    assert report.last_delivery_age_s > 60 * 60 * 24


# --- the endpoint -------------------------------------------------------------------------------


def test_the_endpoint_answers_503_when_something_is_wrong(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A healthcheck or an uptime monitor must be able to act without parsing anything."""
    url = f"sqlite:///{tmp_path / 'endpoint.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_SWEEP_INTERVAL_SECONDS", "0")  # a disabled clock is a problem
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")

    from hullwork.main import app

    with TestClient(app) as client:
        assert client.get("/health").status_code == 200, "liveness must not depend on readiness"
        response = client.get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert any("retry clock" in problem for problem in body["problems"])
    get_settings.cache_clear()


# --- the command --------------------------------------------------------------------------------


def test_the_status_command_exits_nonzero_when_degraded(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`hullwork status || mail me` in a cron line is the whole monitoring story for one container.

    So the exit code has to mean something.
    """
    monkeypatch.setenv("HULLWORK_SWEEP_INTERVAL_SECONDS", "0")
    get_settings.cache_clear()

    printed = io.StringIO()
    code = cli_main(["status"], out=printed)

    assert code == 1
    assert "DEGRADED" in printed.getvalue()


def test_the_status_command_shows_what_no_probe_could_carry(session: Session) -> None:
    """`deliveries.error` and `items.forge_error` were written faithfully and read by nothing."""
    readiness.record_sweep_ok()
    session.add(
        Project(slug="p", forge="forgejo", repo="o/r", webhook_secret_hash="x")  # noqa: S106
    )
    session.commit()
    session.add(
        Delivery(project_id=1, payload_hash="h", error="ValueError: nothing understood this")
    )
    session.add(
        Item(
            project_id=1,
            fingerprint="f",
            title="stuck",
            forge_sync_pending=True,
            forge_attempts=9,
            forge_error="PermanentForgeError: HTTP 404",
        )
    )
    session.commit()

    buffer = io.StringIO()
    cli_main(["status"], out=buffer)

    printed = buffer.getvalue()
    assert "nothing understood this" in printed
    assert "HTTP 404" in printed
    assert "after 9 attempt(s)" in printed


def test_the_disk_gate_actually_measures_a_disk() -> None:
    """It reported `null` in production for the whole of its first deployment.

    `sqlite:///x` is relative and `sqlite:////x` is absolute, one slash apart, and stripping them
    all turned `/data/hullwork.db` into `data/hullwork.db` — a directory that does not exist, so
    `statvfs` raised, the value became None and the gate silently measured nothing. A check that
    does not check is the failure this whole item is about.
    """
    from hullwork.readiness import sqlite_path

    assert sqlite_path("sqlite:////data/hullwork.db") == "/data/hullwork.db"
    assert sqlite_path("sqlite:///./hullwork.db") == "./hullwork.db"


def test_a_quiet_instance_still_learns_the_forge_is_there(session: Session) -> None:
    """Without this the state sits at `unknown` for ever on a healthy idle instance, and a revoked
    token is discovered on the day something finally needs filing."""
    from hullwork.readiness import forge_unchecked_for, record_forge

    assert forge_unchecked_for(600) is True
    record_forge("ok")
    assert forge_unchecked_for(600) is False
