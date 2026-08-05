"""Configuration must fail loudly and readably, or not at all."""

from pathlib import Path
from types import NoneType, UnionType
from typing import Union, get_args, get_origin

import pytest

from hullwork.config import ConfigError, Settings, get_settings


def test_somebody_elses_dotenv_is_inert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**Any `hullwork` command run from a directory with a foreign `.env` died.** Measured on
    2026-08-04 while trying to run `hullwork try` from a working directory whose `.env` held Odoo
    credentials, a Cloudflare token and an FTP password: twenty lines of `Extra inputs are not
    permitted`, as a raw pydantic traceback.

    `try` is documented as the thing you run **on your host, in your own project**, and a project
    directory with a `.env` in it is the ordinary case. So `extra="forbid"` was costing the golden
    path in exchange for a property it was not the only source of — see the test below.
    """
    (tmp_path / ".env").write_text(
        "ODOO_URL=https://odoo.example\nCLOUDFLARE_API_TOKEN=secret\nFTP_DEPLOY_PASS=hunter2\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.log_level == "INFO", "a foreign .env changes nothing and breaks nothing"
    get_settings.cache_clear()


def test_a_misspelled_setting_of_ours_still_refuses_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The half of `extra="forbid"` that mattered, and it never depended on it.

    A misspelled security variable must not read as *not configured* — `HULLWORK_FORGE_TOKN` is the
    difference between an instance with a credential and one without, and silence there is the whole
    reason the strict setting was chosen. `get_settings` refuses it through `_unknown_variables`,
    which reads the environment and not the model, so relaxing `extra` left it untouched.

    Asserted **together with** the test above, because the two are the trade: neither is safe
    without the other, and a future edit reintroducing `forbid` fails the first and passes this one.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HULLWORK_FORGE_TOKN", "x")
    get_settings.cache_clear()

    with pytest.raises(ConfigError, match="HULLWORK_FORGE_TOKN"):
        get_settings()
    get_settings.cache_clear()


def test_a_configuration_error_reaches_the_operator_as_a_sentence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`get_settings`'s docstring says it fails "with a message instead of a stack trace", and
    **nothing caught it**, so the careful sentence was reachable only through twelve frames of
    pydantic.

    The same shape as item 144's check that never ran and `ManifestError` reaching `try` uncaught:
    the work was done and the last connection was missing. Asserted on `main`, because that is where
    the missing connection was — a test of `get_settings` alone passed throughout.
    """
    import io

    from hullwork.cli import main as cli_main

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HULLWORK_FORGE_TOKN", "x")
    get_settings.cache_clear()

    err = io.StringIO()
    monkeypatch.setattr("sys.stderr", err)
    code = cli_main(["config"], out=io.StringIO())
    get_settings.cache_clear()

    assert code == 1
    assert "Traceback" not in err.getvalue()
    assert "HULLWORK_FORGE_TOKN" in err.getvalue()


def test_defaults_are_safe_and_present() -> None:
    settings = Settings()

    assert settings.log_level == "INFO"
    assert settings.log_format == "json"


def test_reads_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HULLWORK_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("HULLWORK_LOG_FORMAT", "console")
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.log_level == "DEBUG"
    assert settings.log_format == "console"
    get_settings.cache_clear()


def test_a_malformed_setting_is_reported_readably_not_as_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HULLWORK_LOG_LEVEL", "BANANA")
    get_settings.cache_clear()

    with pytest.raises(ConfigError) as caught:
        get_settings()

    message = str(caught.value)
    # The operator needs the variable name to fix it — not a pydantic dump.
    assert "HULLWORK_LOG_LEVEL" in message
    assert "Fix the environment" in message
    get_settings.cache_clear()


def test_an_unknown_setting_is_an_error_rather_than_silently_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A typo in a security-relevant variable must not look like it took effect.
    monkeypatch.setenv("HULLWORK_LOG_LEVELL", "DEBUG")
    get_settings.cache_clear()

    with pytest.raises(ConfigError):
        get_settings()

    get_settings.cache_clear()


def test_an_empty_numeric_variable_means_absent_not_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**The compose file cannot express absence.** Item 082.

    Every variable there is `"${HULLWORK_X:-}"`, which passes an empty string when the operator has
    not set it — harmless for a `str | None` field and a hard start-up failure for a numeric one.
    Measured as a restart loop the first time the dispatcher was containerised.
    """
    monkeypatch.setenv("HULLWORK_MAX_TURNS", "")
    get_settings.cache_clear()

    assert get_settings().max_turns is None, "unset means: leave the engine's own ceiling alone"


def test_every_numeric_setting_treats_empty_as_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Item 082's rule, for the whole class rather than the field it was found on.

    **Measured in production on 2026-08-04**, plumbing items 133 and 137 into a live
    instance. Both added numeric settings, neither reached the validator, and writing them into a
    compose file the ordinary way — `"${HULLWORK_X:-}"` — put the containers into the restart loop
    the validator exists to prevent. The ceiling of item 137 was therefore unreachable from any
    installation: the first operator to configure it could not start the process.

    So this asks the model rather than a list. A numeric setting added tomorrow and forgotten in
    that decorator fails here, which is the only version of this test that survives the next item.
    """
    numeric = sorted(
        name
        for name, field in Settings.model_fields.items()
        if _accepts_only_numbers(field.annotation)
    )
    assert numeric, "no numeric settings found — this test has lost its subject"

    for name in numeric:
        monkeypatch.setenv(f"HULLWORK_{name.upper()}", "")
    get_settings.cache_clear()

    settings = get_settings()
    for name in numeric:
        assert getattr(settings, name) is None, f"{name}: an empty variable is unset, not malformed"


def _accepts_only_numbers(annotation: object) -> bool:
    """Whether a field is `int | None` or `float | None` — the shape a compose blank breaks."""
    if get_origin(annotation) not in (Union, UnionType):
        return False
    args = set(get_args(annotation))
    return args <= {int, float, NoneType} and bool(args & {int, float})


def test_a_malformed_numeric_variable_still_stops_the_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other half, and the one the module's opening rule is actually about.

    Treating `""` as absent must not become treating anything unparseable as absent: a value that is
    *present and wrong* is a typo in a setting the operator believes took effect.
    """
    monkeypatch.setenv("HULLWORK_MAX_TURNS", "sixty")
    get_settings.cache_clear()

    with pytest.raises(ConfigError):
        get_settings()

    monkeypatch.setenv("HULLWORK_MAX_TURNS", "0")
    get_settings.cache_clear()
    with pytest.raises(ConfigError):
        get_settings()


def test_deployment_only_variables_stay_out_of_the_settings_namespace() -> None:
    """`HULLWORK_*` is `Settings`' namespace, and the guard refuses anything in it that is not one.

    Measured: the compose file grew three variables it needs for interpolation — the Docker socket's
    gid, the credential's gid and its host path — named `HULLWORK_…`, and the dispatcher refused to
    start with *"unknown variable(s), likely a typo"*. The guard was right; the names were wrong.

    **Read from the generator** (2026-08-04), for the reason `_shipped_compose` is: this used to
    load a hand-written compose describing the host this project runs on, so it proved the
    property for our deployment and nobody else's. Item 145 made the file every installer gets
    come out of `scaffold.compose`, and that is where the mistake is now easy to repeat.
    """
    import re

    import yaml

    from hullwork.config import Settings
    from hullwork.scaffold import compose

    text = compose(docker_gid="989")
    yaml.safe_load(text)  # it must still parse

    known = {f"HULLWORK_{name.upper()}" for name in Settings.model_fields}
    referenced = set(re.findall(r"\$\{(HULLWORK_[A-Z0-9_]+)", text))

    assert referenced <= known, (
        f"these are in the settings namespace and are not settings, so the process refuses to "
        f"start: {sorted(referenced - known)}"
    )
