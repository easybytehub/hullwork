"""What leaves the process when Hullwork reports its own errors.

The whole risk of watching yourself, in this particular tool, is that the credential is in the URL.
An unhandled error in the receiver puts that URL into the event, and from there into breadcrumbs,
transaction names and exception messages. These tests are about the token never getting out.
"""

import json
import logging
from pathlib import Path

import pytest
from pydantic import SecretStr

from hullwork.config import ConfigError, Settings
from hullwork.telemetry import configure_error_reporting, make_before_send, scrub

TOKEN = "IiJc7regy96LTav7yCCSYasejVYZx44EuQt_Z5IFHiw"  # noqa: S105 - shape of a real one
URL = f"http://hullwork.internal:8000/webhooks/glitchtip/acme/{TOKEN}"


def test_the_webhook_token_never_leaves_the_process() -> None:
    assert TOKEN not in scrub(URL)
    assert scrub(URL).endswith("/webhooks/glitchtip/acme/***")


@pytest.mark.parametrize(
    "carrier",
    [
        f"POST {URL} returned 500",
        f'{{"url": "{URL}?retry=1"}}',
        f"RetryableForgeError at {URL} after 3 attempts",
        f"see {URL}, then give up",
    ],
)
def test_it_is_caught_wherever_the_url_ended_up(carrier: str) -> None:
    """Not only in `request.url`: by the time an event is built, the URL has been copied around."""
    assert TOKEN not in scrub(carrier)


def test_it_is_caught_however_deeply_nested() -> None:
    event = {
        "request": {"url": URL, "headers": {"Authorization": "token abc123"}},
        "breadcrumbs": {"values": [{"message": f"calling {URL}"}]},
        "transaction": "/webhooks/glitchtip/acme/{token}",
        "exception": {"values": [{"value": f"connection refused: {URL}"}]},
    }
    cleaned = make_before_send()(event, {})

    # `before_send` can now decline to send at all (item 090's ceiling), so the first assertion is
    # that this event was *not* declined — a scrubbing test that silently passed on a dropped event
    # would prove nothing about the scrubbing.
    assert cleaned is not None, "an event well under the ceiling must still be sent"
    assert TOKEN not in repr(cleaned), "the token got out somewhere in the structure"
    assert cleaned["request"]["headers"]["Authorization"] == "***"
    # The shape survives, so the event is still worth reading.
    assert cleaned["request"]["url"].endswith("/acme/***")


def test_an_ordinary_message_is_left_alone() -> None:
    """Scrubbing that mangles innocent events makes the tracker useless."""
    message = "forge did not accept the item, still queued"
    assert scrub(message) == message
    assert scrub({"item_id": 4, "attempts": 2}) == {"item_id": 4, "attempts": 2}


def test_no_dsn_means_nothing_is_switched_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """Not merely quiet: no SDK is imported and nothing is initialised."""
    assert configure_error_reporting(Settings(error_dsn=None)) is False


def test_a_dsn_switches_it_on_with_the_scrubber_attached() -> None:
    """The positive path, run for real: an SDK configured but not wired to `before_send` would
    scrub nothing, and every test above would still pass."""
    sentry_sdk = pytest.importorskip("sentry_sdk")
    forge_token = "forge-cred-9f3a2b"  # noqa: S105 - the value the scrubber must learn
    try:
        enabled = configure_error_reporting(
            Settings(
                error_dsn=SecretStr("https://k@tracker.invalid/1"),
                forge_token=SecretStr(forge_token),
            )
        )
        assert enabled is True
        options = sentry_sdk.get_client().options

        # Behaviour, not identity: a before_send that is wired but never told the secrets would
        # pass an identity check and leak everything. This is also the by-value defence — the forge
        # credential is in no URL and under no telling field name.
        cleaned = options["before_send"](
            {"extra": {"note": f"PUT /issues with {forge_token} failed"}}, {}
        )
        assert forge_token not in repr(cleaned)

        assert options["send_default_pii"] is False
        assert options["max_request_body_size"] == "never"
        assert options["traces_sample_rate"] == 0.0
        # Observed leaking before this was set: the receiver's frames hold the raw token.
        assert options["include_local_variables"] is False
    finally:
        sentry_sdk.init(dsn=None)  # leave no live client behind for the rest of the suite


def test_a_dsn_without_the_extra_installed_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    """An instance that believes it is watched and is not is worse than one that knows it is not."""
    import builtins

    real_import = builtins.__import__

    def refuse(name: str, *args: object, **kwargs: object) -> object:
        if name == "sentry_sdk":
            raise ImportError("no module named sentry_sdk")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", refuse)

    with pytest.raises(ConfigError, match=r"hullwork\[telemetry\]"):
        configure_error_reporting(Settings(error_dsn=SecretStr("https://k@tracker.example/1")))

# --- the dispatcher's half, which reported nothing at all until item 090 -------------------------

#: What the dispatcher actually holds, in the shapes the real ones have. The receiver holds two of
#: these; the dispatcher holds all of them at once, which is why the scrubber's list being short
#: stayed invisible until now.
CODE_TOKEN = "16759fbc9fd281a479bbc8cb6eafc42c39c57bba"  # noqa: S105 - shape of a real one
TRACKER_TOKEN = "14ba21344ca5f76b88a763243188208a4e887594edb31b8365e0a7e333e"  # noqa: S105
MODEL_TOKEN = "sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # noqa: S105
DB_PASSWORD = "aVeryRealPassword"  # noqa: S105
DB_URL = f"postgresql://hullwork:{DB_PASSWORD}@db.internal:5432/hullwork"


def _dispatcher_settings(credentials_file: str | None = None) -> Settings:
    """Every credential the dispatcher runs with, set at once. That is the point."""
    return Settings(
        database_url=DB_URL,
        forge_url="https://forge.internal",
        forge_token=SecretStr("aaaa1111bbbb2222cccc3333"),
        forge_code_token=SecretStr(CODE_TOKEN),
        tracker_token=SecretStr(TRACKER_TOKEN),
        error_dsn=SecretStr("http://key@tracker.internal:8010/2"),
        model_credentials_file=credentials_file,
    )


def test_every_credential_the_dispatcher_holds_is_scrubbed() -> None:
    """**The divergence item 090 found: two lists, and the shorter one guarded the tracker.**

    `main._known_secrets` gave the log redactor five values and `configure_error_reporting`
    gave the scrubber two. In the same process, the same token was blanked in the logs and
    publishable to the tracker — and the one missing from the short list was
    `forge_code_token`, the credential that can write to repositories.

    Asserted against what a **dispatcher** traceback carries, because that is the process
    holding them all: it clones with one token, pushes with another, asks the tracker with a
    third and hands a fourth to a gateway.
    """
    from hullwork.telemetry import known_secrets

    push_failed = "git push to https://x-access-token:" + CODE_TOKEN + "@forge/o/r failed"
    asked = "GET /api/0/issues with Bearer " + TRACKER_TOKEN
    cleaned = make_before_send(known_secrets(_dispatcher_settings()))(
        {
            "exception": {"values": [{"value": push_failed}]},
            "breadcrumbs": {"values": [{"message": asked}]},
            "extra": {"database_url": DB_URL},
        },
        {},
    )

    assert cleaned is not None
    printed = repr(cleaned)
    assert CODE_TOKEN not in printed, "the credential that can write to repositories got out"
    assert TRACKER_TOKEN not in printed
    assert DB_PASSWORD not in printed, "a Postgres password lives inside the database URL"


def test_the_model_credentials_file_is_scrubbed_by_its_contents(tmp_path: Path) -> None:
    """A subscription token has no telling field name and appears in no URL.

    It reaches a traceback as the *contents* of a file — a `read_text` frame, or an HTTP layer
    quoting the header it built. So the file is read and everything in it becomes a known
    secret, rather than one field name being guessed at: providers disagree about the shape,
    and a credential file holds nothing that is safe to publish anyway.
    """
    from hullwork.telemetry import known_secrets

    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps({"claudeAiOauth": {"accessToken": MODEL_TOKEN, "expiresAt": 1}}),
        encoding="utf-8",
    )

    cleaned = make_before_send(known_secrets(_dispatcher_settings(str(path))))(
        {
            "exception": {"values": [{"value": "401 from the endpoint using " + MODEL_TOKEN}]},
            "extra": {"whole_file": path.read_text(encoding="utf-8")},
        },
        {},
    )

    assert cleaned is not None
    assert MODEL_TOKEN not in repr(cleaned), "the model credential got out"


def test_an_unreadable_credentials_file_is_not_an_error(tmp_path: Path) -> None:
    """Nothing to blank is the same answer as no file, and this runs at start-up.

    Raising here would be a dispatcher refusing to start because of a file it has not needed
    yet — trading the whole loop for a scrubbing entry it does not need.
    """
    from hullwork.telemetry import known_secrets

    secrets = known_secrets(_dispatcher_settings(str(tmp_path / "absent.json")))
    assert CODE_TOKEN in secrets, "the rest of the list still has to be built"


def test_a_crash_loop_cannot_spend_an_unbounded_number_of_events(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The ceiling is about cost, not noise, and the difference decides the design.

    GlitchTip groups by fingerprint, so a dispatcher crashing in the same place a thousand
    times is one issue with a rising count — one issue is one item, one item gets one attempt,
    so Hullwork filing bugs about Hullwork cannot run away. What *is* unbounded is the events,
    with `restart: unless-stopped` behind them. Dropped past the ceiling, and **said once**: a
    limit that is silent is indistinguishable from reporting that stopped working.
    """
    send = make_before_send(ceiling=3)
    event = {"exception": {"values": [{"value": "the same crash again"}]}}

    with caplog.at_level(logging.WARNING):
        answers = [send(dict(event), {}) for _ in range(10)]

    assert sum(1 for answer in answers if answer is not None) == 3
    assert sum(1 for answer in answers if answer is None) == 7
    said = [record for record in caplog.records if "ceiling" in record.message]
    assert len(said) == 1, f"the ceiling must be said once, not per dropped event: {said}"


def test_the_deployed_commit_is_what_the_reports_are_tagged_with() -> None:
    """M9's precondition, and it was measured wrong before it was fixed.

    The recurrence watch decides whether a fix held by asking the forge whether the release an
    occurrence came from contains the merge commit. A release of `0.1.0.dev0` cannot be compared to
    a commit, so on the live instance every error Hullwork reported about *itself* — seven events
    against four merged fixes — was permanently `undecidable`.

    Both halves are asserted, because the fallback is the part an operator relies on: an instance
    that does not set this keeps reporting its version rather than failing to start.
    """
    sentry_sdk = pytest.importorskip("sentry_sdk")
    from hullwork import __version__

    sha = "9e7fc2b9b2c9f5351b8989325e1b5007a306f762"
    try:
        configure_error_reporting(
            Settings(error_dsn=SecretStr("https://k@tracker.invalid/1"), release=sha)
        )
        assert sentry_sdk.get_client().options["release"] == sha

        configure_error_reporting(Settings(error_dsn=SecretStr("https://k@tracker.invalid/1")))
        assert sentry_sdk.get_client().options["release"] == __version__
    finally:
        sentry_sdk.init(dsn=None)
