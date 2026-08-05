"""Reporting Hullwork's own errors, if the operator asks for it.

Off by default and not even installed by default (`pip install hullwork[telemetry]`). A self-hosted
tool that ships an error-reporting SDK whether you want one or not is the posture this product
exists to argue against.

**The reason this module is not three lines.** Hullwork's webhook token lives in the URL path, so an
unhandled error in the receiver would put a project's capability credential into the event — in
`request.url`, and from there into breadcrumbs, transaction names and sometimes the exception
message. `send_default_pii=False` does not help: a URL is not personal data, so the SDK keeps it.
Anything leaving this process is scrubbed first, by shape, by field name and by known value.

**What that scrubbing is worth is measured, not assumed.** Pointing this at itself and then reading
the tracker's database found the token in two places the design had not accounted for: uvicorn's
access log, and the local variables the SDK attaches to every stack frame. Both are closed here or
in the Dockerfile. The lesson kept: an event is scrubbed where you looked, and the SDK collects
from places you did not.
"""

import json
import logging
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any, cast

from hullwork import __version__
from hullwork.config import ConfigError, Settings
from hullwork.logging import REDACTED, SENSITIVE_NAME, TOKEN_IN_URL

log = logging.getLogger(__name__)

#: Shared with the logging layer, so the two defences cannot drift apart.
_URL_TOKEN = TOKEN_IN_URL

#: How many events one run of one program may send. See `make_before_send` for why this is a cost
#: control and not a noise control.
EVENT_CEILING = 50


def scrub(value: Any, secrets: Sequence[str] = ()) -> Any:  # noqa: ANN401 - events are arbitrary
    """Blank credentials anywhere in a structure, however deeply nested.

    Three independent defences, because each one misses what the others catch:

    * **by shape** — the token segment of a `/webhooks/…` URL, which is the credential this service
      handles most often and the one no name or value lookup would recognise;
    * **by name** — a field called `token`, `secret`, `dsn`…, whatever it holds;
    * **by value** — the secrets this process actually knows, wherever they turn up, including
      inside a sentence. This is the one that catches the leak nobody predicted.
    """
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, REDACTED)
        return _URL_TOKEN.sub(rf"\1{REDACTED}", value)
    if isinstance(value, dict):
        return {
            key: REDACTED if SENSITIVE_NAME.search(str(key)) else scrub(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return type(value)(scrub(item, secrets) for item in value)
    return value


def known_secrets(settings: Settings) -> list[str]:
    """Every credential this process holds, whichever program it is. Item 090.

    **This used to exist twice and the two copies did not agree.** `main._known_secrets` gave the
    log redactor five values; `configure_error_reporting` gave the scrubber two. So in the same
    process, the same token was blanked in the logs and publishable to the tracker — and the
    missing one was `forge_code_token`, the credential that can write to repositories.

    The divergence was invisible because the receiver holds few of these in a traceback. The
    dispatcher holds all of them: it clones with one token, pushes with another, asks the tracker
    with a third, and hands a fourth to a gateway.

    The model credential is read from disk rather than named, because that file's *contents* are
    the secret — an expired-token traceback from the gateway can carry the token itself, and no
    field name or URL shape would recognise it. Unreadable is not an error here: nothing to blank
    is the same answer as no file.

    The database URL is in here because a Postgres password lives inside it, and nothing about the
    name `HULLWORK_DATABASE_URL` suggests to a redactor that it is sensitive.
    """
    values = [settings.database_url]
    for secret in (
        settings.forge_token,
        settings.forge_code_token,
        settings.tracker_token,
        settings.error_dsn,
        settings.model_key,
    ):
        if secret is not None:
            values.append(secret.get_secret_value())
    if settings.model_credentials_file:
        try:
            values.append(Path(settings.model_credentials_file).read_text(encoding="utf-8"))
            payload = json.loads(values[-1])
        except (OSError, ValueError):
            pass
        else:
            # The whole file *and* the token inside it: the file is what a `read_text` traceback
            # carries, the token alone is what an HTTP layer carries.
            values.extend(_strings_in(payload))
    return [value for value in values if value]


def _strings_in(value: object) -> list[str]:
    """Every string anywhere in a parsed credential file, so none has to be named.

    Providers disagree about the shape — `accessToken`, `access_token`, nested under
    `claudeAiOauth`. Naming the field means the next provider leaks, and a credential file holds
    nothing that is safe to publish anyway.
    """
    if isinstance(value, str):
        return [value] if len(value) > 8 else []
    if isinstance(value, dict):
        return [found for item in value.values() for found in _strings_in(item)]
    if isinstance(value, list):
        return [found for item in value for found in _strings_in(item)]
    return []


def make_before_send(
    secrets: Iterable[str] = (), *, ceiling: int = EVENT_CEILING
) -> Callable[..., dict[str, Any] | None]:
    """Build the last thing that runs before an event leaves the process.

    Longest secret first, so one secret containing another does not leave a fragment behind.

    **The ceiling is about cost, not about noise** (item 090). GlitchTip groups by fingerprint, so a
    dispatcher crashing in the same place a thousand times is one issue with a rising count — and
    one issue is one item, and one item gets one attempt, so the loop of Hullwork filing bugs
    about Hullwork cannot run away. What is unbounded without a ceiling is the *events*: a crash
    loop with `restart: unless-stopped` behind it would spend somebody's quota to say the same
    sentence. Past the ceiling the event is dropped and the fact is logged once, which is the
    difference between a limit and a silence.
    """
    known = tuple(sorted({s for s in secrets if s}, key=len, reverse=True))
    sent = 0

    def before_send(event: dict[str, Any], _hint: dict[str, Any]) -> dict[str, Any] | None:
        nonlocal sent
        if sent >= ceiling:
            if sent == ceiling:
                sent += 1  # log the refusal once, not once per dropped event
                log.warning(
                    "error reporting has hit its per-process ceiling and is dropping events; the "
                    "tracker already holds this instance's failures grouped by fingerprint",
                    extra={"ceiling": ceiling},
                )
            return None
        sent += 1
        scrubbed: dict[str, Any] = scrub(event, known)
        return scrubbed

    return before_send


def configure_error_reporting(settings: Settings) -> bool:
    """Point Hullwork's own errors at a tracker. Returns whether it was switched on.

    Refuses to start rather than reporting nothing when the DSN is set and the extra is missing:
    an instance that believes it is being watched and is not is worse than one that knows it is not.
    """
    if settings.error_dsn is None:
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.argv import ArgvIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration
    except ImportError as exc:  # pragma: no cover - depends on how the package was installed
        raise ConfigError(
            "HULLWORK_ERROR_DSN is set but the error-reporting SDK is not installed.\n"
            "  Install it with: pip install 'hullwork[telemetry]'\n"
            "  Or unset HULLWORK_ERROR_DSN to run without error reporting."
        ) from exc

    sentry_sdk.init(
        dsn=settings.error_dsn.get_secret_value(),
        environment=settings.environment,
        # The deployed commit when the deployment says so, the package version otherwise. Only a
        # sha can be compared against a merge commit, which is what decides whether a fix held.
        release=settings.release or __version__,
        send_default_pii=False,
        # The SDK types this against its own private `Event` TypedDict. Ours is written against
        # plain dicts on purpose — that is what an event is at runtime, and it keeps the scrubbing
        # testable without the SDK installed, which is the part that must never break.
        # Every credential this process holds, not the two somebody thought of. The dangerous one
        # appears in no URL and has no telling field name, so only knowing its value catches it —
        # and the list used to be shorter here than in the log redactor. See `known_secrets`.
        before_send=cast("Any", make_before_send(known_secrets(settings))),
        # `sys.argv` in every event. This service's command line holds nothing secret, but that is
        # a property of how we happen to run it, not a guarantee, and the information is worth
        # nothing here — the command is always the same one.
        disabled_integrations=[ArgvIntegration()],
        # **Which log line becomes an issue somebody has to close** (item 120). This is the SDK's
        # default and it was nowhere in this repository, which is how seven copies of a *correct*
        # refusal — the dispatcher declining to claim while its token is expired, once per spell,
        # exactly as item 096 built it — arrived here as bug reports and sat `human-only` because
        # there was nothing to fix.
        #
        # `ERROR` and above is a defect or damage. `WARNING` is an operational condition: real,
        # worth a log line and a breadcrumb, reported by `status` and `doctor`, and **not** a
        # filed defect. Stated explicitly so the boundary is readable where it is decided.
        integrations=[
            LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
        ],
        # The body of a delivery is somebody else's production error. Forwarding it to our tracker
        # would copy their data into a system they never agreed to.
        max_request_body_size="never",
        # No local variables in stack frames. The receiver holds the raw token, the raw body and
        # the forge credential in locals, and scrubbing by variable name only catches the ones
        # named obviously enough — `raw` and `expected` hold secrets too. Verified leaking before
        # this line existed. Source context stays on: this source is published and holds no
        # secrets, and without it a stack trace is much harder to read.
        include_local_variables=False,
        # Hullwork does not consume traces, and turning them on is a cost decision nobody made.
        traces_sample_rate=0.0,
    )
    log.info("error reporting enabled", extra={"environment": settings.environment})
    return True
