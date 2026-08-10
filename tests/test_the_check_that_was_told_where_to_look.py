"""Where `status` looks for the deployment's own files. Item 194.

Item 144 added `deployment_env_file` so a containerised instance could point the environment check
at the host's files — inside a container the working directory holds neither, so the check silently
never ran on any real deployment. It was wired into `doctor` and into nothing else.

Measured on the live instance, 2026-08-09: `HULLWORK_DEPLOYMENT_ENV_FILE=/deployment/deploy.env`,
the file mounted read-only at that path, the compose setting it for both services — and `status`
printing *not checked: no environment file at `.env`*, which is the default it never replaced.

That is worse than the two alarms fixed the same day. Those claimed more than they knew; this one
goes quiet with the answer in front of it, and what stays dark is the mechanism that caught the
2026-07-28 tracker failure, where enrichment had never once run in production.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from pathlib import Path

from hullwork import cli
from hullwork.config import Settings

ENV = "HULLWORK_TRACKER_URL=https://tracker.example\n"


def _configured(tmp_path: Path, compose: Path | None = None) -> tuple[Settings, Path]:
    """A deployment that has done everything the error message asks for."""
    env = tmp_path / "deployment" / "deploy.env"
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text(ENV)
    settings = Settings(
        deployment_env_file=str(env),
        deployment_compose_file=str(compose) if compose else None,
    )
    return settings, env


# --- the finding ---------------------------------------------------------------------------------


def test_the_configured_path_is_the_one_that_is_read(tmp_path: Path) -> None:
    """The whole item. A setting that two of three call sites ignore is not a setting."""
    settings, env = _configured(tmp_path)

    resolved, _ = cli.where_the_deployment_files_are(settings)

    assert resolved == env


def test_status_reports_the_comparison_rather_than_not_checked(tmp_path: Path) -> None:
    """What the operator actually reads. `doctor` was right about this file all along, so an
    instance where the two disagree is one where the useful answer is in the command nobody runs on
    a bad morning."""
    settings, env = _configured(tmp_path)

    resolved, _ = cli.where_the_deployment_files_are(settings)
    from hullwork import doctor

    gaps = doctor.environment_gaps(settings, env_file=resolved)

    assert [f.state for f in gaps] != [doctor.State.UNKNOWN], (
        f"the file at {env} exists and was read; nothing here is unknown"
    )


def test_nothing_configured_still_falls_back_to_the_default(tmp_path: Path) -> None:
    """**`cannot look` is a finding and has to stay one** (item 144). The failure mode of this fix
    is inventing a path that exists, which would turn a true `unknown` into a false `ok`."""
    resolved, _ = cli.where_the_deployment_files_are(Settings())

    assert resolved == cli.DEFAULT_ENV_FILE


def test_the_compose_path_travels_the_same_way(tmp_path: Path) -> None:
    """Both halves or neither. Half one is *file → this process*; half two is *file → the
    neighbouring compose*, and half two is the one that caught the 2026-07-28 tracker failure — the
    host process read the file correctly and it was the container that was not configured.
    """
    compose = tmp_path / "deployment" / "docker-compose.yml"
    compose.parent.mkdir(parents=True, exist_ok=True)
    compose.write_text("services: {}\n")
    settings, _ = _configured(tmp_path, compose)

    _, resolved = cli.where_the_deployment_files_are(settings)

    assert resolved == compose


def test_a_named_file_beats_the_setting(tmp_path: Path) -> None:
    """`doctor --env-file` is the only place a person names the file by hand, and a person standing
    in front of the machine outranks what the machine was configured with."""
    settings, _ = _configured(tmp_path)
    named = tmp_path / "elsewhere.env"
    named.write_text(ENV)

    resolved, _ = cli.where_the_deployment_files_are(settings, env_file=str(named))

    assert resolved == named


def test_every_command_that_runs_the_check_resolves_it_the_same_way() -> None:
    """**Asserted by construction**, which is item 193's lesson arriving in a second place.

    Three call sites resolved this pair by hand and two were wrong. A fourth command added later
    must not be able to get it wrong by omitting something, so there is one function and the test
    is that nobody calls the check with a hand-built path.
    """
    source = Path(cli.__file__).read_text(encoding="utf-8")
    calls = source.count("environment_gaps(")
    resolved_by_hand = source.count("env_file=DEFAULT_ENV_FILE")

    assert calls >= 2, "this test is watching a call site that no longer exists"
    assert resolved_by_hand == 0, (
        "a call site resolves the deployment's env file by hand again; "
        "use cli.where_the_deployment_files_are so the three commands cannot disagree"
    )
