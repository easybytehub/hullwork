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

import atexit
import json
import logging
import sys
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any, TextIO, cast

from hullwork import __version__
from hullwork import upstream as upstream_module
from hullwork.config import ConfigError, Settings
from hullwork.logging import REDACTED, SENSITIVE_NAME, TOKEN_IN_URL
from hullwork.upstream import Destination

log = logging.getLogger(__name__)

#: The destination this process configured, so shutdown can wait for what is in flight. Module-level
#: because `configure_error_reporting` is called once per process and its caller has nowhere to keep
#: this — the same reason `main._reporting_enabled` exists beside it.
_upstream: Destination | None = None

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
    secrets: Iterable[str] = (),
    *,
    ceiling: int = EVENT_CEILING,
    upstream: Destination | None = None,
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
        # **Before the ceiling, because the two destinations count separately.** This one is about
        # somebody else's tracker quota; the upstream destination has its own, lower bound. A crash
        # loop that exhausted the operator's ceiling must not also decide what we hear about.
        if upstream is not None:
            upstream.offer(event)
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


def _report_crashes_without_the_sdk(
    destination: Destination, *, notify: TextIO | None = None
) -> None:
    """Report a command's unhandled crash upstream, with no SDK in the process.

    **What it does not do** is the reason this is safe to be so small: it does not touch the
    traceback Python prints, it does not swallow anything, and it does not run for a `SystemExit` or
    a `KeyboardInterrupt` — neither is a defect, and somebody pressing ctrl-c is not a bug report.
    """
    global _upstream
    _upstream = destination
    print(upstream_module.notice_line(destination.host), file=notify or sys.stderr)

    previous = sys.excepthook

    def report_then_print(kind: type[BaseException], value: BaseException, tb: Any) -> None:  # noqa: ANN401
        if not isinstance(value, KeyboardInterrupt | SystemExit):
            try:
                destination.offer(upstream_module.event_for_a_crash_here(value))
            # Reporting a crash must not replace it.
            except Exception:
                log.debug("could not report this crash upstream", exc_info=True)
        previous(kind, value, tb)

    sys.excepthook = report_then_print
    # The same reason as the SDK path: a daemon thread dies with the interpreter, and a command's
    # interpreter exits the moment the traceback is printed.
    atexit.register(destination.close)


def _a_transport_that_sends_nothing() -> Any:  # noqa: ANN401 - a Transport, imported lazily
    """A transport for the client that exists only to *build* events.

    When the operator has no tracker of their own, the SDK client is still needed — it is what turns
    an unhandled exception and an `ERROR` log line into an event dict — but it must not be the thing
    that sends. With no working transport there are no sessions, no client reports and no
    connection, so the only traffic this process makes is the envelope `Destination` posts itself.

    **A real subclass, and that is the whole reason this is a function.** The first version was
    duck-typed, on the reasoning that this class must exist whether or not the SDK is installed —
    and `make_transport` decides by `isinstance(ref_transport, Transport)`, so a plausible object
    with the right methods fell through every branch and the SDK quietly built its **default HTTP
    transport** instead. Measured against a local ingest on 2026-08-06: the full event went
    upstream — hostname, `modules`, breadcrumbs, the interpolated message, all of it. The leak this
    module exists to prevent, arriving through the argument meant to prevent it.

    So the class is built here, after the import, where `Transport` is a name that exists.
    """
    from sentry_sdk.transport import Transport

    class SendsNothing(Transport):
        def capture_envelope(self, *_args: object, **_kwargs: object) -> None:
            return None

    return SendsNothing()


def configure_error_reporting(
    settings: Settings,
    *,
    operation: str = upstream_module.UNKNOWN,
    session_factory: Callable[[], Any] | None = None,
    notify: TextIO | None = None,
    brief: bool = False,
) -> bool:
    """Point Hullwork's own errors at a tracker. Returns whether reporting was switched on.

    Refuses to start rather than reporting nothing when the DSN is set and the extra is missing:
    an instance that believes it is being watched and is not is worse than one that knows it is not.

    **Two destinations, two policies, and neither silences the other** (item 152):

    * `HULLWORK_ERROR_DSN` — the operator's tracker, the whole event, scrubbed. Theirs.
    * the DSN baked into a published image — a constructed payload, ours. Nothing in a checkout.

    `brief` picks which notice is printed: the paragraph for a program that starts once, one line
    for a command that runs in a loop (item 157).

    `operation` and `session_factory` only feed the second one: the label an upstream report is
    counted under, and where its installation identifier is read from. A caller that passes neither
    still reports upstream — with `unknown` and no identifier, which is worse than the truth and
    much better than silence.
    """
    destination: Destination | None = None
    upstream_dsn = upstream_module.destination(settings)
    if upstream_dsn is not None:
        destination = upstream_module.Destination(
            upstream_dsn, operation=operation, session_factory=session_factory
        )

    if settings.error_dsn is None and destination is None:
        return False

    if brief and settings.error_dsn is None and destination is not None:
        # **A command does not need an SDK to report its own crash** (item 157, and this is what its
        # cost criterion bought). Measured: arming the SDK added **157 ms to the median
        # `hullwork status`, 43%** — on a command people run in a loop, in a `watch`, in a script.
        #
        # What the SDK is for in the two long-running programs is catching what a framework already
        # caught: an exception Starlette handles never reaches `sys.excepthook`, and its
        # `LoggingIntegration` sees it through `log.exception`. A command has no framework, so its
        # crashes leave exactly one way — and `upstream.event_for_a_crash_here` already builds the
        # event from a live traceback for `config --telemetry`.
        #
        # So the light path: no import, no client, the same constructor, the same payload.
        _report_crashes_without_the_sdk(destination, notify=notify)
        return True

    try:
        import sentry_sdk
        from sentry_sdk.integrations.argv import ArgvIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration
    except ImportError as exc:  # pragma: no cover - depends on how the package was installed
        if settings.error_dsn is None:
            # **The published image always has the SDK** (item 150 put it there), so this is anybody
            # who built their own without the extra and inherited a destination — which cannot
            # happen, because a checkout has no destination to inherit. It stays a log line rather
            # than a refusal: nobody asked for this reporting, so nobody is owed a failure over it.
            log.debug("no error-reporting SDK, so nothing can be reported upstream either")
            return False
        raise ConfigError(
            "HULLWORK_ERROR_DSN is set but the error-reporting SDK is not installed.\n"
            "  Install it with: pip install 'hullwork[telemetry]'\n"
            "  Or unset HULLWORK_ERROR_DSN to run without error reporting."
        ) from exc

    global _upstream
    _upstream = destination

    if destination is not None:
        # **A short process dies before its own crash report leaves** (item 157). `offer` posts from
        # a daemon thread so a crash handler never blocks, and a daemon thread is killed the instant
        # the interpreter exits — which for a command is immediately after the traceback prints.
        # Measured: a real crash in `hullwork projects list`, a real SDK, a real ingest, **zero**
        # envelopes received. The service survives this because its shutdown calls `close`; the
        # fifteen commands had nothing to call it.
        #
        # `atexit` rather than another call site, because the correct place to wait is *wherever the
        # process ends* and no caller can be relied on to know where that is. Two seconds, then not:
        # a report is a convenience for us and a delay is a cost to them.
        atexit.register(destination.close)

    # **Before the SDK is armed, so nothing can have been sent when this returns** (item 153). On
    # `stderr` and not through the logger: a `json` formatter turns this into a field somebody has
    # to go looking for, and the point is that it is in front of the person starting the process.
    if destination is not None:
        said = (
            upstream_module.notice_line(destination.host)
            if brief
            else upstream_module.notice(destination.host)
        )
        print(said, file=notify or sys.stderr)

    sentry_sdk.init(
        # **The DSN here is only ever the operator's.** When they have none, the client still has to
        # exist — it is what turns an unhandled exception into an event at all — so it is pointed at
        # the upstream destination and given a transport that sends nothing. Every upstream report
        # leaves through `Destination`, measured, and never through this client: handing it a
        # constructed event put `environment` and `server_name` on the wire, because the client adds
        # both *after* `before_send`.
        dsn=(
            settings.error_dsn.get_secret_value()
            if settings.error_dsn is not None
            else upstream_dsn
        ),
        transport=(None if settings.error_dsn is not None else _a_transport_that_sends_nothing()),
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
        before_send=cast("Any", make_before_send(known_secrets(settings), upstream=destination)),
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
    if settings.error_dsn is not None:
        log.info("error reporting enabled", extra={"environment": settings.environment})
    if destination is not None:
        # **Named, at INFO, on every start.** Item 153 is the notice a person reads before the first
        # event; this is the line an operator finds in the log they already have — and the host is
        # there so nobody has to take our word for where it goes.
        log.info(
            "this build reports its own crashes upstream; HULLWORK_TELEMETRY=off stops it",
            extra={"upstream_host": destination.host},
        )
    return True


def upstream_destination() -> Destination | None:
    """The upstream destination this process configured, if any. For `close` at shutdown."""
    return _upstream
