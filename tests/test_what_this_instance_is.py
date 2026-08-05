"""`hullwork config`: what the instance is set to. Item 146, last of DR-0014's four.

`doctor` says what is broken and `status` says what has happened. This says what the instance
**is**,
and on 2026-08-04 answering that took a session of reading a compose file, an environment file and a
container's environment side by side — which is how three defects of the shape *the code supports it
and no installation can use it* got as far as they did.

The test that matters is the second one. A configuration report that printed a credential would
be worse than no report, because it would be run in front of people.
"""

from pydantic import SecretStr

from hullwork import settings_report
from hullwork.config import Settings


def _by_variable(settings: Settings) -> dict[str, dict[str, str]]:
    """The report keyed by variable, so a test names the column it asserts on."""
    return {
        variable: {"value": value, "from": source, "reaches": reach}
        for variable, value, source, reach in settings_report.rows(settings)
    }


def test_every_setting_appears() -> None:
    """Counted against `Settings`, never a literal — a literal is what went stale in item 145."""
    reported = {variable for variable, _, _, _ in settings_report.rows(Settings())}

    assert reported == {f"HULLWORK_{name.upper()}" for name in Settings.model_fields}


def test_no_credential_is_ever_printed() -> None:
    """**The one that would matter.** A configuration screen is run in front of other people.

    Asserted on the rendered text rather than on the redaction helper: a test of the helper passes
    against a renderer that reaches around it, which is item 136's defect and it has already
    happened twice in this repository.
    """
    secret = "sk-or-v1-3f9a-this-must-never-be-rendered"  # noqa: S105 - the subject, not a key
    settings = Settings(
        model_key=SecretStr(secret),
        forge_token=SecretStr(secret),
        forge_code_token=SecretStr(secret),
        tracker_token=SecretStr(secret),
    )

    rendered = "\n".join(settings_report.lines(settings))

    assert secret not in rendered
    assert "sk-or-v1" not in rendered, "not even a prefix: a prefix identifies the provider"
    assert "set" in rendered, "…and it still says the credential is there, which is the question"


def test_a_credential_that_is_absent_reads_differently_from_one_that_is_present() -> None:
    """*Set* and *not set* are the whole value of this screen for a credential. If they rendered the
    same, the column would be decoration."""
    with_key = _by_variable(Settings(model_key=SecretStr("x")))
    without = _by_variable(Settings())

    assert with_key["HULLWORK_MODEL_KEY"]["value"] == "set"
    assert without["HULLWORK_MODEL_KEY"]["value"] == "not set"


def test_a_value_typed_by_hand_is_distinguished_from_a_default() -> None:
    """`model_fields_set`, not a comparison against the default.

    A value that happens to equal its default was still set, and an operator who typed it is asking
    whether it took effect. Reporting *default* there would answer a question nobody asked.
    """
    typed = _by_variable(Settings(model_endpoint="https://api.anthropic.com"))
    untouched = _by_variable(Settings())

    assert typed["HULLWORK_MODEL_ENDPOINT"]["from"] == "environment"
    assert untouched["HULLWORK_MODEL_ENDPOINT"]["from"] == "default"
    assert (
        typed["HULLWORK_MODEL_ENDPOINT"]["value"]
        == untouched["HULLWORK_MODEL_ENDPOINT"]["value"]
    ), "the value is the same; only where it came from differs"


def test_every_setting_says_which_half_gets_it() -> None:
    """The column is item 145's classification, surfaced.

    A reader debugging *why does the dispatcher not see this* needs to know it was never sent.
    """
    reaches = {variable: reach for variable, _, _, reach in settings_report.rows(Settings())}

    assert reaches["HULLWORK_FORGE_CODE_TOKEN"] == "dispatcher"  # noqa: S105 - a name, not a key
    assert reaches["HULLWORK_BASE_URL"] == "receiver"
    # **`both`, and it read `neither` until 2026-08-04.** The old classification rested on "a
    # container told about the host's filesystem learns nothing", which is true and led to the wrong
    # conclusion: `doctor` runs *inside* a container, so item 144's drift check could never read the
    # files it compares. They are now mounted read-only into both halves and named in both, so the
    # check that exists to catch missing settings had stopped being one of them.
    assert reaches["HULLWORK_DEPLOYMENT_ENV_FILE"] == "both"
    assert set(reaches.values()) <= {"both", "receiver", "dispatcher", "neither"}
