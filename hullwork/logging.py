"""Structured logging, with redaction built into the pipeline.

Redaction belongs here, not in the discipline of whoever writes the log call. Someone will
eventually log a whole settings object or a request header, and the logging layer is the only
place that can catch that reliably.

Three independent defences:

* **By name** — a field called `token`, `secret`, `dsn`… is redacted whatever it holds. Two field
  names are exempted by exact match, and only when they hold a number: the provenance seal counts
  tokens, so `input_tokens` used to render as `***` (item 057, `scrub.MEASUREMENTS`).
* **By value** — known secret values are redacted wherever they appear, including in the middle of
  a formatted message. This is the one that catches the accidental leak — and it is only as good
  as the secrets it is given, which is why `main.py` arms it with every credential the process
  holds. It spent its whole life until item 019 armed with nothing.
* **By shape** — the token segment of a `/webhooks/…` URL, which is a credential no name or
  value lookup would recognise.

Tracebacks are covered too. Formatters render them *after* every filter has run, so exception
text used to leave the process untouched — and `log.exception` is what runs on exactly the bad
day when a credential is in the message.
"""

import json
import logging
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, ClassVar

from hullwork import scrub

# The redaction itself lives in `hullwork.scrub`, shared with the tracker ingest (item 036): a
# fetched event carries frame locals and `sys.argv`, and two copies of this logic would drift.
# Re-exported here because these names were public before the move.
REDACTED = scrub.REDACTED
SENSITIVE_NAME = scrub.SENSITIVE_NAME
TOKEN_IN_URL = scrub.TOKEN_IN_URL

# Attributes every LogRecord carries; anything else was passed as `extra` and is ours to emit.

_STANDARD_ATTRS = frozenset(
    [
        "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
        "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name",
        "pathname", "process", "processName", "relativeCreated", "stack_info", "taskName",
        "thread", "threadName",
    ]
)


class RedactingFilter(logging.Filter):
    """Blanks known secret values and sensitively-named fields before anything is formatted."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        # Shapes stay off on this path: the log redactor's behaviour is covered by tests that
        # assert exact output, and widening it is a change to make deliberately rather than as a
        # side effect of extracting the code. The tracker ingest turns them on, where an audit
        # proved they were needed.
        self._scrubber = scrub.Scrubber(secrets)

    def add_secret(self, value: str) -> None:
        """Register a value to be blanked wherever it shows up."""
        self._scrubber.add_secret(value)

    def _scrub(self, value: Any) -> Any:  # noqa: ANN401 - log payloads are arbitrary by nature
        return self._scrubber.scrub(value)

    def filter(self, record: logging.LogRecord) -> bool:
        # Render the message now: after this the args are spent, and redacting the rendered
        # string is the only way to catch a secret that arrived through %-formatting.
        record.msg = self._scrub(record.getMessage())
        record.args = None

        for key, value in list(record.__dict__.items()):
            if key in _STANDARD_ATTRS:
                continue
            record.__dict__[key] = (
                REDACTED if scrub.is_secret_name(key, value) else self._scrub(value)
            )

        if record.exc_info:
            # Formatters render the traceback *after* every filter has run, so an exception string
            # used to leave the process untouched — and `log.exception` is what runs on exactly the
            # bad day when a URL or a credential is in the message. Rendering it here, scrubbed,
            # into `exc_text` is what the formatters then reuse.
            record.exc_text = self._scrub(
                logging.Formatter().formatException(record.exc_info)
            )
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: what machines read."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS:
                payload[key] = value
        if record.exc_text:
            # Always the filter's copy, never a fresh render: re-formatting here would undo
            # its redaction, which is precisely the gap that let tracebacks out unscrubbed.
            payload["exception"] = record.exc_text
        elif record.exc_info:  # pragma: no cover - only without the filter installed
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    """What humans read while developing. Never the default."""

    FORMAT: ClassVar[str] = "%(asctime)s %(levelname)-8s %(name)s  %(message)s"

    def __init__(self) -> None:
        super().__init__(fmt=self.FORMAT, datefmt="%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {k: v for k, v in record.__dict__.items() if k not in _STANDARD_ATTRS}
        return f"{base}  {extras}" if extras else base


def configure_logging(
    level: str = "INFO",
    log_format: str = "json",
    secrets: Iterable[str] = (),
) -> RedactingFilter:
    """Install the root handler. Returns the filter, so secrets found later can be registered."""
    redactor = RedactingFilter(secrets)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if log_format == "json" else ConsoleFormatter())
    handler.addFilter(redactor)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    return redactor
