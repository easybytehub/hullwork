"""Why an instance that is running will not work. Item 074.

Every test here corresponds to a failure that actually happened while deploying, and to how long it
took to find. The expensive part was never the fix — it was that the symptom appeared several layers
away from the cause, so each test asserts that the cause is named **where an operator is looking**.

Asserted by effect throughout: a real empty database, a real file on disk, a real `PATH` lookup. A
mocked reader would prove that this module can be told what to say.
"""

import io
import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr
from sqlalchemy.orm import Session

from hullwork import doctor
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.forge import PermanentForgeError
from hullwork.models import Item, ItemState, Project

ROOT = Path(__file__).resolve().parent.parent

MANIFEST = {
    "version": 1,
    "project": "demo",
    "git": {"provider": "forgejo", "repo": "acme/demo"},
    "errors": {"provider": "glitchtip"},
    "autofix": {"agent": "claude-code", "lanes": {"green": ["valueerror"]}},
}


def _migrated(path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """`migrations/env.py` takes the URL from `HULLWORK_DATABASE_URL` and nowhere else.

    Deliberately so, per `alembic.ini`: one place decides which database is in use. Setting
    `sqlalchemy.url` on the Config is therefore ignored, and the migration lands on whatever the
    environment says — which is how the first version of this file migrated one database and then
    inspected another.
    """
    url = f"sqlite:///{path}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")
    return url


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = _migrated(tmp_path / "doctor.db", monkeypatch)
    with make_session_factory(make_engine(url))() as db:
        yield db
    get_settings.cache_clear()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(database_url=f"sqlite:///{tmp_path / 'doctor.db'}")


# --- git ---------------------------------------------------------------------------------------


def test_git_missing_from_path_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    """The dispatcher runs on the host *because* it needs git, and the `api` image has none."""
    monkeypatch.setenv("PATH", "")
    finding = doctor.git_on_path()
    assert finding.state is doctor.State.BROKEN
    assert "PATH" in finding.detail


def test_git_present_is_reported_with_where(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negatively: on a machine that has git, this check is quiet. Otherwise it is decoration."""
    finding = doctor.git_on_path()
    assert finding.state is doctor.State.OK
    assert finding.detail.endswith("git")


# --- docker ------------------------------------------------------------------------------------


def test_a_missing_docker_binary_and_a_dead_daemon_are_different_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """**The measurement that cost the most time, twice.**

    A client on `PATH` whose socket refuses the connection is the ordinary Docker failure, and
    conflating it with a missing binary sends an operator to reinstall software that is already
    there. The two must produce different sentences, and the daemon's own refusal has to survive
    into the message — it is the part that says whether this is permissions or a stopped service.
    """
    absent = doctor.docker_daemon("docker-that-is-not-installed")
    assert absent.state is doctor.State.BROKEN
    assert "PATH" in absent.detail

    fake = tmp_path / "docker"
    fake.write_text(
        "#!/bin/sh\n"
        'echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock." >&2\n'
        "exit 1\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    # A socket that exists and a daemon that will not answer: the ordinary Docker failure, and the
    # one this check is for. Passed explicitly since item 135, because a process with **no** socket
    # is answering about somebody else's resource and now says so instead.
    present = tmp_path / "docker.sock"
    present.touch()

    dead = doctor.docker_daemon("docker", socket=str(present))
    assert dead.state is doctor.State.BROKEN
    assert "Cannot connect to the Docker daemon" in dead.detail
    # And it must not be the missing-binary sentence, or the two are one check with two names.
    assert "PATH" not in dead.detail


def test_a_daemon_that_answers_is_quiet(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = tmp_path / "docker"
    fake.write_text('#!/bin/sh\necho "28.1.1"\n', encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    finding = doctor.docker_daemon("docker")
    assert finding.state is doctor.State.OK
    assert "28.1.1" in finding.detail


def test_a_docker_that_hangs_does_not_hang_the_doctor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A daemon that accepts the connection and never answers is a hang, not an error.

    The stand-in sleeps through Python rather than through `sleep`, because `PATH` is replaced below
    and a `sh` script cannot find `sleep` without it — which produced a script that failed instantly
    and a test that passed for the wrong reason.
    """
    import sys

    fake = tmp_path / "docker"
    fake.write_text(
        f"#!{sys.executable}\nimport time\ntime.sleep(60)\n", encoding="utf-8"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(doctor, "DOCKER_TIMEOUT_SECONDS", 1)

    finding = doctor.docker_daemon("docker")
    assert finding.state is doctor.State.BROKEN
    assert "did not answer" in finding.detail


# --- the database ------------------------------------------------------------------------------


def test_an_empty_database_that_answers_everything_is_reported_unbuilt(tmp_path: Path) -> None:
    """**2026-07-29, and `readiness` passes it perfectly.**

    A dispatcher started without `HULLWORK_DATABASE_URL` made itself a SQLite file beside the real
    one. That file is writable, has disk behind it and answers `SELECT 1` — so every check asking
    whether the database is *alive* said yes, while the queue it was reading was empty by
    construction. The check has to be about the tables.
    """
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    with make_session_factory(make_engine(url))() as db:
        finding = doctor.database_built(db, Settings(database_url=url))

    assert finding.state is doctor.State.BROKEN
    assert "no tables at all" in finding.detail
    assert "HULLWORK_DATABASE_URL" in finding.detail
    assert "entrypoint" in finding.detail, "item 076: name who migrates, not only the command"


def test_a_migrated_database_is_quiet(session: Session, settings: Settings) -> None:
    """Negatively: the real database passes. Without this the test above proves nothing."""
    finding = doctor.database_built(session, settings)
    assert finding.state is doctor.State.OK


def test_a_database_missing_one_table_names_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A migration not applied is not the same failure as no database, and says which table."""
    url = _migrated(tmp_path / "partial.db", monkeypatch)
    engine = make_engine(url)
    with engine.begin() as connection:
        from sqlalchemy import text

        connection.execute(text("DROP TABLE attempt_steps"))

    with make_session_factory(engine)() as db:
        finding = doctor.database_built(db, Settings(database_url=url))

    assert finding.state is doctor.State.BROKEN
    assert "attempt_steps" in finding.detail
    # Item 076 strengthened this. It used to assert only that the command was named, and
    # `alembic upgrade head` is a dead end from the wheel installation the dispatcher is becoming:
    # measured, the wheel holds no `migrations/` and no `alembic.ini`, because
    # `docker-entrypoint.sh` copies them separately and migrates there — "the app should not be
    # deciding to alter its own database". So the remedy has to name **who** migrates, and the
    # command alone is not enough.
    assert "alembic upgrade head" in finding.detail
    assert "entrypoint" in finding.detail
    assert "the dispatcher never does" in finding.detail


# --- the code token ---------------------------------------------------------------------------


class _Reachable:
    """A code forge that can see everything."""

    def default_branch(self, repo: str) -> str:
        return "main"


class _Refusing:
    """The live 2026-07-29 refusal, verbatim: the account may push and the token may not."""

    def default_branch(self, repo: str) -> str:
        raise PermanentForgeError(
            f"{repo}: token does not have at least one of required scope(s): [write:repository]",
            403,
        )


def _project(session: Session, slug: str, repo: str) -> None:
    session.add(
        Project(
            slug=slug,
            forge="forgejo",
            repo=repo,
            webhook_secret_hash="x" * 64,
            manifest=MANIFEST,
        )
    )
    session.commit()


def test_a_repository_the_code_token_cannot_read_is_named_with_its_slug(session: Session) -> None:
    """The 403 that cost an attempt, reported at the moment the token is configured instead.

    Asked as a **read**, which is what makes it compatible with item 073's open question: no
    exception to `refuse_unless_ingest_may_write` is needed, because this is the client that is
    supposed to be able to push.
    """
    _project(session, "demo", "acme/demo")
    findings = doctor.code_token_reaches_repositories(session, _Refusing())

    assert [f.state for f in findings] == [doctor.State.BROKEN]
    assert "demo" in findings[0].check
    assert "acme/demo" in findings[0].detail
    assert "403" in findings[0].detail


def test_a_reachable_repository_is_quiet(session: Session) -> None:
    _project(session, "demo", "acme/demo")
    findings = doctor.code_token_reaches_repositories(session, _Reachable())
    assert [f.state for f in findings] == [doctor.State.OK]


def test_no_code_token_is_unknown_and_never_broken(session: Session) -> None:
    """Item 073's lesson applied. A rehearsing instance is a supported configuration (item 049).

    Reporting every repository as unreachable because a credential is deliberately absent is an
    alarm that fires on a correct deployment, which is the signal that gets ignored.
    """
    _project(session, "demo", "acme/demo")
    findings = doctor.code_token_reaches_repositories(session, None)

    assert [f.state for f in findings] == [doctor.State.UNKNOWN]
    assert not doctor.failed(findings)


def test_a_disabled_project_is_not_asked_about(session: Session) -> None:
    _project(session, "demo", "acme/demo")
    project = session.query(Project).one()
    project.active = False
    session.commit()

    findings = doctor.code_token_reaches_repositories(session, _Refusing())
    assert [f.state for f in findings] == [doctor.State.OK]
    assert "no active project" in findings[0].detail


# --- the model credential ---------------------------------------------------------------------


def _credentials_file(
    path: Path, *, expires_ms: int | None, token: str = "sk-secret"  # noqa: S107 - a fixture
) -> Path:
    oauth: dict[str, object] = {"accessToken": token}
    if expires_ms is not None:
        oauth["expiresAt"] = expires_ms
    path.write_text(json.dumps({"claudeAiOauth": oauth}), encoding="utf-8")
    return path


def test_an_expired_subscription_token_is_reported_expired(tmp_path: Path) -> None:
    """`401 OAuth access token has expired` names neither the file nor the clock. This does both."""
    import time

    path = _credentials_file(
        tmp_path / "creds.json", expires_ms=int((time.time() - 7200) * 1000)
    )
    finding = doctor.model_credential(
        Settings(model_credentials_file=str(path))
    )

    assert finding.state is doctor.State.BROKEN
    assert "expired" in finding.detail
    assert "2h00m ago" in finding.detail
    assert "claude -p ok" in finding.detail


def test_a_valid_subscription_token_says_when_it_expires(tmp_path: Path) -> None:
    """Negatively: valid is quiet. And it still says the path is not supported."""
    import time

    path = _credentials_file(
        tmp_path / "creds.json", expires_ms=int((time.time() + 4 * 3600) * 1000)
    )
    finding = doctor.model_credential(Settings(model_credentials_file=str(path)))

    assert finding.state is doctor.State.OK
    assert "3h5" in finding.detail or "4h00m" in finding.detail
    assert "Not a supported configuration" in finding.detail


def test_the_token_is_never_printed(tmp_path: Path) -> None:
    """**The file holds a live credential.** Every branch of this check reads it and none may echo.

    Asserted on all three outcomes rather than one, because the leak would be added by whichever
    branch somebody edits next.
    """
    import time

    for expires in (int((time.time() - 60) * 1000), int((time.time() + 3600) * 1000), None):
        path = _credentials_file(
            tmp_path / "creds.json",
            expires_ms=expires,
            token="sk-ant-live-do-not-print",  # noqa: S106 - the string this test forbids printing
        )
        finding = doctor.model_credential(Settings(model_credentials_file=str(path)))
        assert "sk-ant-live-do-not-print" not in finding.detail


def test_a_credentials_file_with_no_expiry_is_unknown(tmp_path: Path) -> None:
    """Somebody else owns that document's shape. Unknown, and never a failed cron."""
    path = _credentials_file(tmp_path / "creds.json", expires_ms=None)
    finding = doctor.model_credential(Settings(model_credentials_file=str(path)))

    assert finding.state is doctor.State.UNKNOWN
    assert not doctor.failed([finding])


def test_a_missing_credentials_file_is_broken_not_a_traceback(tmp_path: Path) -> None:
    finding = doctor.model_credential(
        Settings(model_credentials_file=str(tmp_path / "nope.json"))
    )
    assert finding.state is doctor.State.BROKEN
    assert "unusable" in finding.detail


def test_an_api_key_is_present_and_not_validated() -> None:
    """Calling the provider to check a key spends somebody's quota to learn what attempt 1 says."""
    finding = doctor.model_credential(Settings(model_key=SecretStr("sk-whatever")))
    assert finding.state is doctor.State.OK
    assert "sk-whatever" not in finding.detail


def test_no_model_credential_at_all_is_broken() -> None:
    finding = doctor.model_credential(Settings())
    assert finding.state is doctor.State.BROKEN
    assert "HULLWORK_MODEL_KEY" in finding.detail


# --- the effective configuration ---------------------------------------------------------------


def test_variables_in_file_reads_names_and_never_values(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "# a comment\n"
        "HULLWORK_FORGE_URL=https://forge.example\n"
        "export HULLWORK_FORGE_TOKEN=super-secret-value\n"
        "\n"
        "NOT_OURS=ignored\n"
        'HULLWORK_TRACKER_TOKEN="quoted-secret"\n',
        encoding="utf-8",
    )
    names = doctor.variables_in_file(env)

    assert names == [
        "HULLWORK_FORGE_TOKEN",
        "HULLWORK_FORGE_URL",
        "HULLWORK_TRACKER_TOKEN",
    ]
    assert "NOT_OURS" not in names


def test_an_unreadable_environment_file_reports_that_it_did_not_look(tmp_path: Path) -> None:
    """A container with no visible env file is the normal case for anybody not deploying as we do.

    **The original form asserted silence, and its reasoning was sound**: a noisy failure here
    would teach operators to ignore the whole check, which is the one outcome that makes it worse
    than not existing.

    Item 144 kept the reasoning and removed the silence, because silence had a cost nobody had
    priced: `[]` meant *no gaps* and *I could not look* at the same time, and on every containerised
    deployment the second was the true one — so the check that exists to catch *configured and never
    arrived* reported a clean bill while three of those shipped.

    `unknown` is what satisfies both. It says what happened and, by item 073's rule, never touches
    the exit code: a warning wired into an exit code with no action available to clear it is not a
    signal, and this one has an action — name the files.
    """
    assert doctor.variables_in_file(tmp_path / "absent") == []

    findings = doctor.environment_gaps(Settings(), env_file=tmp_path / "absent")

    assert [f.state for f in findings] == [doctor.State.UNKNOWN], "reported, never alarming"


def test_a_variable_the_compose_never_passes_on_is_named(tmp_path: Path) -> None:
    """**The falsifiable gate of item 074: the 2026-07-28 tracker failure, both halves.**

    Reproduced by its own mechanism — the compose lists variables one at a time — with no network
    and no container involved. Item 036's enrichment had never once run in production while both
    variables were correctly set in the file, and `tracker_configured: false` was the only signal.
    """
    env = tmp_path / ".env"
    env.write_text(
        "HULLWORK_FORGE_URL=https://forge.example\n"
        "HULLWORK_TRACKER_URL=https://tracker.example\n"
        "HULLWORK_TRACKER_TOKEN=secret\n",
        encoding="utf-8",
    )
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  api:\n"
        "    environment:\n"
        '      HULLWORK_FORGE_URL: "${HULLWORK_FORGE_URL:-}"\n',
        encoding="utf-8",
    )
    # Configured, so half one is silent and only the compose gap can speak.
    configured = Settings(
        forge_url="https://forge.example",
        tracker_url="https://tracker.example",
        tracker_token=SecretStr("secret"),
    )

    gaps = doctor.environment_gaps(configured, env_file=env, compose_file=compose)
    named = {gap.check for gap in gaps if gap.state is doctor.State.BROKEN}
    assert named == {"HULLWORK_TRACKER_URL", "HULLWORK_TRACKER_TOKEN"}
    assert all("one at a time" in gap.detail for gap in gaps)

    # The other half of the gate: listed in the compose, and the report is silent about them.
    compose.write_text(
        "services:\n"
        "  api:\n"
        "    environment:\n"
        '      HULLWORK_FORGE_URL: "${HULLWORK_FORGE_URL:-}"\n'
        '      HULLWORK_TRACKER_URL: "${HULLWORK_TRACKER_URL:-}"\n'
        '      HULLWORK_TRACKER_TOKEN: "${HULLWORK_TRACKER_TOKEN:-}"\n',
        encoding="utf-8",
    )
    assert doctor.environment_gaps(configured, env_file=env, compose_file=compose) == []


def test_the_code_token_gap_is_expected_and_never_broken(tmp_path: Path) -> None:
    """**2026-07-29: this gap was 'fixed' and the service refused to boot.**

    Its absence from the service is correct (spec M2 §1, item 017), so the report has to be able to
    say "meant to be missing" without an operator silencing the whole check to get past it. If this
    ever becomes `broken`, somebody will close it and stop the service starting.
    """
    env = tmp_path / ".env"
    env.write_text("HULLWORK_FORGE_CODE_TOKEN=push-capable-secret\n", encoding="utf-8")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    environment: {}\n", encoding="utf-8")

    gaps = doctor.environment_gaps(Settings(), env_file=env, compose_file=compose)

    assert gaps, "the gap must be reported, not omitted — omission is how it gets re-added"
    assert {gap.state for gap in gaps} == {doctor.State.EXPECTED}
    assert not doctor.failed(gaps)
    assert any("refuses to start" in gap.detail for gap in gaps)
    assert all("push-capable-secret" not in gap.detail for gap in gaps)


def test_a_variable_in_neither_place_is_silent(tmp_path: Path) -> None:
    """The check adds information about what *is* configured. Absent from both is not news."""
    env = tmp_path / ".env"
    env.write_text("HULLWORK_FORGE_URL=https://forge.example\n", encoding="utf-8")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        'services:\n  api:\n    environment:\n      HULLWORK_FORGE_URL: "x"\n', encoding="utf-8"
    )

    gaps = doctor.environment_gaps(
        Settings(forge_url="https://forge.example"), env_file=env, compose_file=compose
    )
    assert gaps == []
    # HULLWORK_ERROR_DSN is in neither file, and nothing may be said about it.
    assert all(gap.check != "HULLWORK_ERROR_DSN" for gap in gaps)


def test_a_configured_process_reading_its_own_env_file_is_silent(tmp_path: Path) -> None:
    """**The false positive this check was rewritten to avoid.**

    `Settings` reads `.env` itself, so a variable can be absent from `os.environ` and present in the
    configuration — the normal case for the CLI run from the deployment directory. Comparing names
    against the environment reported all eight production variables as missing while every one of
    them had arrived. An alarm that fires on a correct deployment is the always-on signal item 073
    deleted; this asserts it cannot come back.
    """
    env = tmp_path / ".env"
    env.write_text(
        "HULLWORK_FORGE_URL=https://forge.example\nHULLWORK_FORGE_TOKEN=secret\n",
        encoding="utf-8",
    )
    configured = Settings(
        forge_url="https://forge.example", forge_token=SecretStr("secret")
    )

    assert doctor.environment_gaps(configured, env_file=env) == []


def test_a_variable_whose_value_equals_the_default_is_not_reported_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Measured wrong against the live instance before it was measured right.**

    production's `.env` assigns `HULLWORK_LOG_FORMAT=json` and `json` is the field's default, so the
    first version of this check — which compared each value against its default — reported a
    variable as never having arrived while it was sitting in that very process's environment. On a
    correctly configured production instance, with no action available to clear it.

    `model_fields_set` is the fix and this is the test that pins it: assigned, equal to the default,
    and silent.
    """
    env = tmp_path / ".env"
    env.write_text("HULLWORK_LOG_FORMAT=json\n", encoding="utf-8")
    monkeypatch.setenv("HULLWORK_LOG_FORMAT", "json")

    arrived = Settings()
    assert arrived.log_format == "json", "the default, which is the whole point of this test"
    assert doctor.environment_gaps(arrived, env_file=env) == []

    # Negatively: with nothing in the environment, the same file and the same default do speak.
    monkeypatch.delenv("HULLWORK_LOG_FORMAT")
    gaps = doctor.environment_gaps(Settings(), env_file=env)
    assert [gap.check for gap in gaps] == ["HULLWORK_LOG_FORMAT"]


def test_a_process_running_without_what_the_file_assigns_is_broken(tmp_path: Path) -> None:
    """And the other direction: the file says one thing, the process is running on another."""
    env = tmp_path / ".env"
    env.write_text("HULLWORK_TRACKER_URL=https://tracker.example\n", encoding="utf-8")

    gaps = doctor.environment_gaps(Settings(), env_file=env)

    assert [gap.state for gap in gaps] == [doctor.State.BROKEN]
    assert gaps[0].check == "HULLWORK_TRACKER_URL"
    assert "working directory" in gaps[0].detail


def test_an_unmapped_variable_is_left_to_config(tmp_path: Path) -> None:
    """`config._unknown_variables` already stops the process for a typo. Not said twice."""
    env = tmp_path / ".env"
    env.write_text("HULLWORK_TYPOED_SETTING=1\n", encoding="utf-8")
    assert doctor.environment_gaps(Settings(), env_file=env) == []


# --- the whole examination and its exit code --------------------------------------------------


def test_unknown_never_fails_the_exit_code(session: Session, settings: Settings) -> None:
    """Item 073, stated as an invariant rather than as prose."""
    findings = [
        doctor.Finding("a", doctor.State.OK, ""),
        doctor.Finding("b", doctor.State.UNKNOWN, ""),
        doctor.Finding("c", doctor.State.EXPECTED, ""),
    ]
    assert not doctor.failed(findings)
    assert doctor.failed([*findings, doctor.Finding("d", doctor.State.BROKEN, "")])


def test_an_unbuilt_database_does_not_kill_the_examination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Measured by running the command, not by running the suite.**

    `database_built` reported the empty database correctly and the very next check asked that
    database for its projects, so `hullwork doctor` died with a `sqlite3.OperationalError` traceback
    — in the exact situation it exists to diagnose, where the operator has nothing else to go on.
    `CommandError`'s docstring says it: printed as a message, never as a traceback.

    The skipped check must be **named** rather than omitted: "no projects to check" and "could not
    look" are different answers, and silently returning the first would be a lie.
    """
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    settings = Settings(database_url=url)
    with make_session_factory(make_engine(url))() as db:
        findings = doctor.examine(
            db,
            settings,
            code_forge=_Reachable(),
            env_file=tmp_path / "absent",
            compose_file=None,
        )

    by_check = {finding.check: finding for finding in findings}
    assert by_check["database"].state is doctor.State.BROKEN
    assert by_check["code token"].state is doctor.State.UNKNOWN
    assert "not asked" in by_check["code token"].detail
    # Everything that does not need the database still answered.
    assert by_check["git"].state is not doctor.State.UNKNOWN
    assert "model credential" in by_check


def test_examine_reports_every_check_even_when_the_first_is_broken(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A doctor that stops at the first problem is a doctor you have to run five times."""
    monkeypatch.setenv("PATH", "")
    _project(session, "demo", "acme/demo")

    findings = doctor.examine(
        session,
        settings,
        code_forge=_Refusing(),
        env_file=tmp_path / "absent",
        compose_file=None,
    )
    checks = [finding.check for finding in findings]

    assert "git" in checks
    assert "docker" in checks
    assert "database" in checks
    assert "model credential" in checks
    assert any(check.startswith("code token") for check in checks)
    assert doctor.failed(findings)


# --- the inventory ------------------------------------------------------------------------------


class _IssuesThatExist:
    def get_issue(self, repo: str, number: int) -> object | None:
        return object()


class _IssuesThatDoNot:
    """The live state of issue #3 and #4: gone."""

    def __init__(self, missing: set[int]) -> None:
        self.missing = missing
        self.asked: list[tuple[str, int]] = []

    def get_issue(self, repo: str, number: int) -> object | None:
        self.asked.append((repo, number))
        return None if number in self.missing else object()


def _item(
    session: Session, *, state: ItemState, issue: str | None, fingerprint: str
) -> Item:
    project = session.query(Project).filter(Project.slug == "demo").one_or_none()
    if project is None:
        _project(session, "demo", "acme/demo")
        project = session.query(Project).filter(Project.slug == "demo").one()
    item = Item(
        project_id=project.id,
        fingerprint=fingerprint,
        title="ValueError: boom",
        state=state,
        forge_issue_ref=issue,
    )
    session.add(item)
    session.commit()
    return item


def test_an_item_that_is_not_ready_and_points_at_a_missing_issue_is_named(
    session: Session,
) -> None:
    """**The gap item 7 sat in.**

    `status` asks this question only about `ready` items, because that is where it protects an
    attempt. Item 7 was `not-reproducible`, pointed at issue `#3`, which does not exist, and nothing
    ever said so — its verdict was exactly as unpublishable, and item 077 had to deal with it by
    hand. The operator's rule is a clean inventory, so the question is asked about every open item.
    """
    stranded = _item(
        session, state=ItemState.NOT_REPRODUCIBLE, issue="#3", fingerprint="fp-stranded"
    )
    forge = _IssuesThatDoNot({3})

    findings = doctor.items_point_at_real_issues(session, forge)

    assert [f.state for f in findings] == [doctor.State.BROKEN]
    assert f"item {stranded.id}" in findings[0].detail
    assert "not-reproducible" in findings[0].detail, "the state is what makes it findable"
    assert "acme/demo#3" in findings[0].detail
    assert doctor.failed(findings)


def test_an_inventory_whose_issues_all_exist_is_quiet(session: Session) -> None:
    """Negatively. Without this the check above only proves it can complain."""
    _item(session, state=ItemState.READY, issue="#1", fingerprint="fp-ok")
    _item(session, state=ItemState.FAILED, issue="#2", fingerprint="fp-ok2")

    findings = doctor.items_point_at_real_issues(session, _IssuesThatExist())

    assert [f.state for f in findings] == [doctor.State.OK]
    assert not doctor.failed(findings)


def test_a_closed_item_is_not_asked_about(session: Session) -> None:
    """A `done` item whose issue was deleted afterwards is history, not a problem with now."""
    _item(session, state=ItemState.DONE, issue="#9", fingerprint="fp-done")
    forge = _IssuesThatDoNot({9})

    findings = doctor.items_point_at_real_issues(session, forge)

    assert forge.asked == [], "a closed item costs no request and no warning"
    assert [f.state for f in findings] == [doctor.State.OK]


def test_a_forge_that_blinks_reports_nothing_rather_than_everything(session: Session) -> None:
    """Item 073's lesson again: one bad request must not strand every item in the report."""
    _item(session, state=ItemState.READY, issue="#1", fingerprint="fp-blink")

    class _Blinking:
        def get_issue(self, repo: str, number: int) -> object | None:
            raise PermanentForgeError("boom", 500)

    findings = doctor.items_point_at_real_issues(session, _Blinking())

    assert not doctor.failed(findings)


def test_no_forge_is_unknown_not_a_clean_inventory(session: Session) -> None:
    """"Nothing was asked" and "everything is fine" must not be the same sentence."""
    _item(session, state=ItemState.READY, issue="#1", fingerprint="fp-noforge")

    findings = doctor.items_point_at_real_issues(session, None)

    assert [f.state for f in findings] == [doctor.State.UNKNOWN]
    assert "cannot be asked" in findings[0].detail


def test_truncation_is_said_out_loud(session: Session) -> None:
    """An inventory reported clean after looking at part of it is worse than one that says so."""
    for index in range(4):
        _item(
            session, state=ItemState.READY, issue=f"#{index + 1}", fingerprint=f"fp-many{index}"
        )

    findings = doctor.items_point_at_real_issues(session, _IssuesThatExist(), limit=2)

    assert any("only the first 2" in f.detail for f in findings)
    assert any(f.state is doctor.State.UNKNOWN for f in findings)


# --- a resource this process does not own. Item 091 -----------------------------------------------


def test_a_dispatcher_resource_that_fails_here_is_unknown_when_a_dispatcher_is_running(
    session: Session,
) -> None:
    """**Measured the moment the dispatcher became a container, on a healthy instance.**

    From the host: `model credential` BROKEN, exit 1. Inside the container: the same check `ok`.
    Both right — the configured path is the bind mount's destination. A red line on a correct
    installation is the shape item 073 deleted a whole check for.
    """
    from hullwork import lease

    lease.acquire(session, "somebody-else-1")

    findings = doctor.not_from_here(
        [
            doctor.Finding(
                "model credential", doctor.State.BROKEN, "is set and unusable: no such file"
            ),
            doctor.Finding("docker", doctor.State.BROKEN, "no daemon answered"),
        ],
        session,
    )

    assert [f.state for f in findings] == [doctor.State.UNKNOWN, doctor.State.UNKNOWN]
    assert all("not from here" in f.detail for f in findings)
    # What was measured survives the downgrade: an operator who *is* on the right machine still
    # needs to read it.
    assert "no such file" in findings[0].detail
    assert "docker compose exec dispatcher" in findings[0].detail, "it must say where to ask"


def test_nothing_is_downgraded_when_no_dispatcher_is_running(session: Session) -> None:
    """The absence of a dispatcher is exactly when somebody needs to know what is missing.

    Without this half the rule would hide the whole diagnosis on a fresh install, which is the one
    time the doctor is the only thing an operator has.
    """
    findings = doctor.not_from_here(
        [doctor.Finding("model credential", doctor.State.BROKEN, "is set and unusable: no file")],
        session,
    )

    assert findings[0].state is doctor.State.BROKEN
    assert findings[0].detail == "is set and unusable: no file"


def test_a_check_that_passes_is_left_alone_and_so_is_one_that_is_not_the_dispatchers(
    session: Session,
) -> None:
    """Only failures, and only the dispatcher's resources.

    A precondition satisfied in two places is not a puzzle, and the database is *both* programs' —
    downgrading it would hide the empty-database-beside-the-real-one failure that `database_built`
    exists for.
    """
    from hullwork import lease

    lease.acquire(session, "somebody-else-1")

    findings = doctor.not_from_here(
        [
            doctor.Finding("git", doctor.State.OK, "/usr/bin/git"),
            doctor.Finding("database", doctor.State.BROKEN, "opened and holds no tables at all"),
        ],
        session,
    )

    assert findings[0].state is doctor.State.OK
    assert findings[1].state is doctor.State.BROKEN, "the database is not the dispatcher's alone"


def test_an_unqueryable_database_downgrades_nothing_rather_than_raising(tmp_path: Path) -> None:
    """Asking the lease is asking the database, in the one case where it may have no tables.

    The doctor died with a traceback once for exactly this reason, in the single situation it exists
    to diagnose. Caught here by an existing test the first time this function was written.
    """
    from hullwork.db import make_engine, make_session_factory

    factory = make_session_factory(make_engine(f"sqlite:///{tmp_path / 'empty.db'}"))
    with factory() as session:
        findings = doctor.not_from_here(
            [doctor.Finding("docker", doctor.State.BROKEN, "no daemon answered")], session
        )

    assert findings[0].state is doctor.State.BROKEN, "cannot tell whose → report the measurement"


# --- a failure that travels with the thing, not with the reader. Item 105 -------------------------


def test_an_expired_token_is_reported_wherever_the_doctor_runs(
    session: Session, tmp_path: Path
) -> None:
    """**Eleven hours of an idle instance hid behind the downgrade this refuses.**

    On 2026-07-31 the dispatcher's token had expired and `hullwork doctor`, run **inside the
    dispatcher** with `docker compose exec dispatcher`, answered:

        unknown — not from here: the token … expired 11h12m ago … Run the doctor where the
        dispatcher runs — with the compose deployment that is
        `docker compose exec dispatcher hullwork doctor`

    That command *was* what had been run. `not_from_here` downgraded whenever any dispatcher was
    alive, without asking whether this process was that dispatcher — its own docstring states the
    correct test and the code implemented half of it.

    The fix is not "detect the dispatcher": the lease holder is deliberately random and names no
    machine, so there is nothing to compare against. It is a better question. A missing file is a
    fact about *this filesystem* and reading it elsewhere may legitimately differ; **an expiry is a
    fact about the token's contents** and is the same number in every process that can open it.
    Downgrading that does not merely lose information — it asserts a reason that cannot be true.
    """
    from hullwork import lease

    lease.acquire(session, "the-real-dispatcher")

    expired = doctor.model_credential(_credential(tmp_path, expires_in_hours=-3))
    assert expired.state is doctor.State.BROKEN
    assert expired.local is False, "an expiry is not a fact about this machine"

    survived = doctor.not_from_here([expired], session)[0]

    assert survived.state is doctor.State.BROKEN, "the expiry was blamed on the reader's location"
    assert "not from here" not in survived.detail
    assert "expired" in survived.detail


def test_a_credential_this_process_does_not_hold_is_still_somebody_else_s(session: Session) -> None:
    """The half that must not regress: item 091's failure is still downgraded.

    The receiver holds no model credential by design (DR-0009), so "there is no file at this path"
    is an answer about the receiver's filesystem and not about the instance. If this stopped being
    downgraded, every `status` on a healthy two-process deployment would report a broken instance —
    the shape item 073 deleted a whole check for: a signal permanently on is not a signal.
    """
    from hullwork import lease

    lease.acquire(session, "the-real-dispatcher")

    missing = doctor.model_credential(Settings(model_credentials_file="/no/such/path.json"))
    assert missing.state is doctor.State.BROKEN
    assert missing.local is True

    downgraded = doctor.not_from_here([missing], session)[0]

    assert downgraded.state is doctor.State.UNKNOWN
    assert "not from here" in downgraded.detail
    # And what was measured survives, for whoever *is* on the right machine.
    assert "/no/such/path.json" in downgraded.detail


# --- the question the loop asks before claiming. Item 096 ----------------------------------------


def _credential(tmp_path: Path, *, expires_in_hours: float) -> Settings:
    """A subscription credential file with a chosen expiry, in the shape the CLI writes."""
    from datetime import UTC, datetime, timedelta

    when = datetime.now(UTC) + timedelta(hours=expires_in_hours)
    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "sk-ant-oat01-x" * 4,
                    "expiresAt": int(when.timestamp() * 1000),
                }
            }
        ),
        encoding="utf-8",
    )
    return Settings(model_credentials_file=str(path))


def test_an_expired_credential_is_a_reason_not_to_claim(tmp_path: Path) -> None:
    """**Measured on the live instance**: 21 model calls, all 401, to rediscover a printed fact.

    The expiry had been printed two hours earlier by the doctor. The attempt still spent a clone, an
    image, a network, a gateway and the model calls — and then claimed the same item again a minute
    later, because `abandoned` does not consume the attempt.
    """
    reason = doctor.credential_expired(_credential(tmp_path, expires_in_hours=-0.5))

    assert reason, "an expired credential must stop the loop from claiming"
    assert "expired" in reason
    # The clock, both ends: an operator who reads "expired 30m ago (at 14:07 UTC)" fixes the
    # credential; one who reads "401" goes looking at the network.
    assert "UTC" in reason
    assert "claude -p" in reason, "and it must say how to refresh it"


def test_a_live_credential_is_no_reason_at_all(tmp_path: Path) -> None:
    """The positive half, or the test above only proves it can refuse."""
    assert doctor.credential_expired(_credential(tmp_path, expires_in_hours=3)) == ""


def test_an_api_key_is_never_treated_as_expirable() -> None:
    """`HULLWORK_MODEL_KEY` has no expiry to read, and asking a provider costs a request.

    The supported configuration must not be grounded by a check written for the unsupported one.
    """
    from pydantic import SecretStr

    assert doctor.credential_expired(Settings(model_key=SecretStr("sk-ant-api-real"))) == ""


def test_a_token_whose_shape_declares_no_expiry_does_not_ground_the_instance(
    tmp_path: Path,
) -> None:
    """`unknown` is not `broken`, and this is where that distinction earns its keep.

    A credential file in a shape this build does not recognise — somebody else's provider, or a
    future version of this one — must not stop an instance from working. The doctor already reports
    it as unknown rather than broken, and item 073's rule applies: unknown never fails anything.
    """
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"someOtherProvider": {"token": "x" * 40}}), encoding="utf-8")

    assert doctor.credential_expired(Settings(model_credentials_file=str(path))) == ""


def test_a_credential_that_cannot_be_read_is_a_reason(tmp_path: Path) -> None:
    """Unreadable is not the same as unknown-shape: there is nothing to work with either way.

    Measured on 2026-07-30, twice over: the refresh rewrote the file mode 600 and the dispatcher —
    which reads it through a group — got `Permission denied`. Identical consequence to an expired
    token, so identical answer.
    """
    absent = Settings(model_credentials_file=str(tmp_path / "absent.json"))
    reason = doctor.credential_expired(absent)

    assert reason, "a credential that cannot be read is a credential that cannot be used"


# --- and `status` learns the same lesson. Item 105 ------------------------------------------------


def test_status_does_not_announce_the_dispatcher_s_missing_credential(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """**The receiver said "no item will be claimed" about a dispatcher that was claiming fine.**

    Every `status` on the live instance carried that line, because the receiver holds no model
    credential by design (DR-0009) and this check read `credential_expired` directly instead of
    going through the ownership test. Item 091 taught the doctor to say "not from here"; `status`
    never learned it, and what it printed instead was a prediction about another process, wrong for
    as long as the instance ran.

    Asserted through the command rather than the function, because the defect was in the wiring: the
    measurement was right and nothing consulted the thing that knows whose it is.
    """
    from hullwork import lease
    from hullwork.cli import main as cli_main
    from hullwork.models import Base

    url = f"sqlite:///{tmp_path / 'status.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as session:
        lease.acquire(session, "the-dispatcher-that-holds-it")

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

    assert "no item will be claimed" not in printed, (
        "the receiver announced a verdict about the dispatcher's credential"
    )
    # And the dispatcher is still reported as running, so this is not silence about the loop.
    assert "a dispatcher is running" in printed


def test_status_still_reports_a_missing_credential_when_nothing_is_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The half that keeps the change from becoming a gag.

    With no dispatcher alive there is nobody whose business it could be, and an operator staring at
    an instance that does nothing needs to be told what is missing. `not_from_here` already draws
    that line; this asserts `status` inherits it rather than reimplementing it.
    """
    from hullwork.cli import main as cli_main
    from hullwork.models import Base

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


def test_a_check_that_cannot_look_says_so_rather_than_passing(tmp_path: Path) -> None:
    """Item 144, and it is why every defect of 2026-08-04 got through.

    `environment_gaps` returned `[]` for *no gaps* and for *I could not read the file*, which are
    opposite facts — and on every containerised deployment the second was the true one: the paths
    defaulted to the working directory and the real files live on the host. So the mechanism written
    to catch *configured and never arrived* reported a clean bill instead of reporting that it had
    not run.

    Same category error as item 133's `None` versus `0`, in a check instead of a measurement.
    """
    settings = Settings(database_url="sqlite://")

    findings = doctor.environment_gaps(
        settings, env_file=tmp_path / "absent.env", compose_file=None
    )

    assert findings, "a check that could not look must not answer with silence"
    assert findings[0].state is doctor.State.UNKNOWN, "not broken — nothing is known to be wrong"
    assert "HULLWORK_DEPLOYMENT_ENV_FILE" in findings[0].detail, "it names the way out"


def test_an_empty_file_and_a_missing_one_are_different_problems(tmp_path: Path) -> None:
    """Both are *not checked*, and an operator acts on them differently: one is a path, one is a
    file with nothing in it. A single message for both sends somebody looking in the wrong place."""
    settings = Settings(database_url="sqlite://")
    empty = tmp_path / "empty.env"
    empty.write_text("# nothing assigned here\n")

    absent = doctor.environment_gaps(settings, env_file=tmp_path / "gone.env", compose_file=None)
    present = doctor.environment_gaps(settings, env_file=empty, compose_file=None)

    assert absent[0].detail != present[0].detail
    assert "no environment file" in absent[0].detail
    assert "assigns no HULLWORK_" in present[0].detail


@pytest.mark.skipif(os.getuid() == 0, reason="root reads mode-000 files, so nothing here can fail")
def test_a_file_it_cannot_read_is_not_reported_as_a_file_with_nothing_in_it(tmp_path: Path) -> None:
    """The third of the three, and the one that was collapsed into the second until 2026-08-05.

    Found on this project's own deployment rather than here: `deploy.env` mounted read-only, mode
    600 because it holds credentials, and a container running as uid 10001. Both halves right, and
    the operator was told the file *assigns no HULLWORK_ variable* — a sentence that is false and
    points nowhere. An operator who reads it goes to look at the file's contents, which are fine.

    The distinction has to survive a message rewrite, so this asserts the two are different **and**
    that the remedy is named, not merely that some words changed.
    """
    settings = Settings(database_url="sqlite://")
    unreadable = tmp_path / "locked.env"
    unreadable.write_text("HULLWORK_FORGE_URL=https://forge.example\n")
    unreadable.chmod(0o000)
    empty = tmp_path / "empty.env"
    empty.write_text("# nothing assigned here\n")

    locked = doctor.environment_gaps(settings, env_file=unreadable, compose_file=None)
    nothing_in_it = doctor.environment_gaps(settings, env_file=empty, compose_file=None)

    assert locked[0].state is doctor.State.UNKNOWN, "not a failure: other deployments hit this"
    assert locked[0].detail != nothing_in_it[0].detail
    assert "cannot read it" in locked[0].detail
    assert "assigns no HULLWORK_" not in locked[0].detail, "the sentence that was false"
    assert str(os.getuid()) in locked[0].detail, "name the uid that failed or the reader cannot act"
    assert "640" in locked[0].detail, "and the fix, which is not chmod 644 on a credential file"


def test_the_drift_of_2026_08_04_is_caught_in_one_line(tmp_path: Path) -> None:
    """The defect this whole item exists for, reproduced deliberately.

    A variable assigned in the environment file and enumerated nowhere in the compose is set, and
    the process never sees it. That is how items 133 and 137 shipped a cost ceiling no installation
    could reach, and it is one line of `doctor` output away from being obvious.
    """
    settings = Settings(database_url="sqlite://")
    env = tmp_path / "deploy.env"
    env.write_text("HULLWORK_MAX_ATTEMPT_TOKENS=4000000\n")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        'services:\n  api:\n    environment:\n      HULLWORK_FORGE_URL: "${HULLWORK_FORGE_URL:-}"\n'
    )

    findings = doctor.environment_gaps(settings, env_file=env, compose_file=compose)

    named = [f for f in findings if "named nowhere" in f.detail]
    assert named, "the variable the compose never passes on was not reported"
    assert named[0].check == "HULLWORK_MAX_ATTEMPT_TOKENS"


def test_an_unbuilt_schema_does_not_make_the_credential_check_lie(tmp_path: Path) -> None:
    """**One broken check must not make a second check lie.** Found on the golden path, 2026-08-04.

    `hullwork init` in a clean directory, then `doctor` — which is step 4 of what `init` itself
    prints. It said `AILING`, 2 broken, and one of them claimed a receiver-only deployment had no
    model credential and therefore *"every attempt fails before the sandbox starts"*. There were no
    projects, no agent, and nothing that would ever ask for a model.

    The cause was a `bool` where the honest answer was *cannot tell*: with no schema, nothing can be
    read about projects, and the fallback claimed something needed a key. Third instance today of
    item 133's rule — a measurement of nothing is not a measurement of zero.

    Item 135 fixed the readable case and left this one, which is the first `doctor` a stranger runs.
    """
    url = f"sqlite:///{tmp_path / 'unbuilt.db'}"
    with make_session_factory(make_engine(url))() as db:
        cannot_tell = doctor._any_project_names_an_agent(db)

    assert cannot_tell is None, "an unbuilt schema establishes nothing about projects"

    finding = doctor.model_credential(
        Settings(database_url=url), anything_uses_it=cannot_tell
    )

    assert finding.state is doctor.State.UNKNOWN, "it must not claim the deployment is broken"
    assert "cannot yet tell" in finding.detail
    # And by item 073's rule an `unknown` never fails the exit code, so a fresh install does not
    # report a failure it does not have.
    assert not finding.is_failure


def test_a_project_that_names_no_agent_still_reads_as_expected(session: Session) -> None:
    """Item 135's case, unchanged: a readable database where nothing wants a model.

    Kept beside the test above because the two are one decision with three answers — yes, no, and
    cannot tell — and collapsing any two of them is how this defect happened twice.
    """
    settings = Settings(database_url="sqlite://")

    finding = doctor.model_credential(settings, anything_uses_it=False)

    assert finding.state is doctor.State.EXPECTED
    assert not finding.is_failure


def test_a_deployment_check_that_ran_and_found_nothing_says_so(
    tmp_path: Path, session: Session
) -> None:
    """Armed and clean, and absent, printed identically until 2026-08-05: as nothing.

    Measured on this project's own instance, and the direction is what gives it away. The check was
    reporting `unknown` for want of a readable file; fixing the file mode **armed** it, and its line
    vanished from the report. Good news that removes a line is indistinguishable from a check that
    was never written, and the whole subject of item 144 is a check nobody could see had not run.

    The `UNKNOWN` cases stay `UNKNOWN` — this speaks only for a comparison that actually happened.
    """
    env = tmp_path / "deploy.env"
    env.write_text("HULLWORK_FORGE_URL=https://forge.example\nHULLWORK_FORGE_TOKEN=\n")
    settings = Settings(
        database_url="sqlite://",
        forge_url="https://forge.example",
        forge_token=SecretStr("not-a-real-token"),
    )

    report = doctor.examine(session, settings, code_forge=None, env_file=env, compose_file=None)
    deployment = [finding for finding in report if finding.check == "deployment"]

    assert deployment, "an armed check with nothing to report still owes the reader a line"
    assert deployment[0].state is doctor.State.OK
    assert "no gaps" in deployment[0].detail
    assert "2 variable" in deployment[0].detail, "say how much was compared, or this proves nothing"


def test_a_deliberate_absence_is_not_a_reason_to_go_quiet(tmp_path: Path, session: Session) -> None:
    """The first version of the line above never appeared on a correct instance, which is worse.

    A right deployment reports `HULLWORK_FORGE_CODE_TOKEN` as deliberately absent from the receiver
    (DR-0009): the service refuses to start holding a credential that can push. That is an
    `EXPECTED` finding, so the gaps list is not empty, so a summary keyed on emptiness goes quiet on
    the one deployment where everything is right. Measured on this project's own instance.
    """
    env = tmp_path / "deploy.env"
    env.write_text(
        "HULLWORK_FORGE_URL=https://forge.example\n"
        "HULLWORK_FORGE_CODE_TOKEN=push-token\n"
    )
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    environment:\n      HULLWORK_FORGE_URL: x\n")
    settings = Settings(
        database_url="sqlite://",
        forge_url="https://forge.example",
        forge_token=SecretStr("not-a-real-token"),
    )

    report = doctor.examine(session, settings, code_forge=None, env_file=env, compose_file=compose)
    deployment = [finding for finding in report if finding.check == "deployment"]
    absences = [finding for finding in report if finding.state is doctor.State.EXPECTED]

    assert absences, "the fixture has to reach the deliberate-absence branch or this proves nothing"
    assert deployment, "one deliberate absence must not silence the line that says the check ran"
    assert "deliberate absence" in deployment[0].detail


def test_a_variable_only_one_half_reads_is_a_deliberate_absence_not_a_failure(
    tmp_path: Path, session: Session
) -> None:
    """**Four false failures on a correct instance, and `doctor` exiting 1.** Item 144, 2026-08-05.

    Arming the deployment check is what exposed this. `deploy.env` assigns every model variable
    because the dispatcher needs them; the receiver must not hold them; so from inside the receiver
    four variables are *assigned in the file and absent from this process* — the exact shape the
    check calls `BROKEN`. It was reporting a design decision as a defect, on the one deployment that
    follows the design, and a permanently red line is not a line anybody reads (item 073).

    One hardcoded exception for the push token is what made the other four wrong. `scaffold.REACH`
    already knows who reads what — it writes the compose file from it — so the check consults that.
    """
    env = tmp_path / "deploy.env"
    env.write_text(
        "HULLWORK_FORGE_URL=https://forge.example\n"
        "HULLWORK_MODEL_KEY=k\n"
        "HULLWORK_MAX_TURNS=8\n"
        "HULLWORK_SWEEP_INTERVAL_SECONDS=60\n"
    )
    settings = Settings(
        database_url="sqlite://",
        forge_url="https://forge.example",
        forge_token=SecretStr("not-a-real-token"),
    )

    report = doctor.examine(session, settings, code_forge=None, env_file=env, compose_file=None)
    by_check = {finding.check: finding for finding in report}

    for dispatcher_only in ("HULLWORK_MODEL_KEY", "HULLWORK_MAX_TURNS"):
        assert by_check[dispatcher_only].state is doctor.State.EXPECTED, dispatcher_only
        assert "one of the two halves" in by_check[dispatcher_only].detail
    assert not doctor.failed(report), "a correct instance must not exit 1"


def test_the_check_and_the_generator_cannot_disagree_about_who_reads_what() -> None:
    """The reach map writes the compose file **and** now decides what counts as a gap.

    Which is the point: two authorities for one question is how the four false failures above
    happened — a hardcoded name in the check, a map in the generator. This asserts the check reads
    the map rather than a copy of it, by asking about a variable the map calls `BOTH`.
    """
    from hullwork import scaffold

    assert scaffold.belongs_to_one_half("HULLWORK_MODEL_KEY") is scaffold.Reach.DISPATCHER
    assert scaffold.belongs_to_one_half("HULLWORK_BASE_URL") is scaffold.Reach.RECEIVER
    assert scaffold.belongs_to_one_half("HULLWORK_DATABASE_URL") is None, "both halves read it"
    assert scaffold.belongs_to_one_half("HULLWORK_NOT_A_SETTING") is None, "unknown names: not gaps"


def test_a_variable_commented_out_of_the_compose_is_missing_not_present(tmp_path: Path) -> None:
    """**Measured on the live instance, and it is how item 144's own gate first came back empty.**

    Reproducing the 2026-07-28 failure by commenting `HULLWORK_BASE_URL` out of the deployment's
    compose file produced no finding: the name is still in the file, inside the comment, and this
    check reads text rather than YAML on purpose. So the one edit an operator is most likely to make
    while debugging — comment it out, restart, forget — was the one edit the check could not see.

    The trailing-comment case is asserted alongside, because dropping everything after a `#` would
    fix this by breaking the ordinary annotated line.
    """
    commented = tmp_path / "docker-compose.yml"
    commented.write_text(
        "services:\n"
        "  api:\n"
        "    environment:\n"
        "#     HULLWORK_BASE_URL: \"${HULLWORK_BASE_URL:-}\"\n"
        "      HULLWORK_FORGE_URL: \"${HULLWORK_FORGE_URL:-}\"  # the ingest side\n"
    )

    names = doctor.variables_in_compose(commented)

    assert "HULLWORK_BASE_URL" not in names, "a commented-out line is not a variable that arrives"
    assert "HULLWORK_FORGE_URL" in names, "and a trailing comment does not delete the assignment"
