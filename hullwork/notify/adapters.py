"""The channels a digest can go to.

Two ship today: `none` and `console`. **Telegram and email are deliberately absent**, not
forgotten — writing a transport that cannot be exercised produces code whose first real run happens
in front of a user. They are declared in the manifest and refused here with a message saying so,
which is honest and takes ten minutes to change once there are credentials to test against.
"""

import logging
import sys
from typing import TextIO

from hullwork.notify import Digest, Notifier

log = logging.getLogger(__name__)

#: Channels the manifest may name but this build cannot deliver to yet.
NOT_YET_IMPLEMENTED = ("telegram", "email")


class NullNotifier:
    """Sends nothing, and does so correctly.

    A real no-op rather than a crash: `none` is the default, and the majority of installations will
    never configure anything else.
    """

    def send(self, digest: Digest) -> None:
        return


class ConsoleNotifier:
    """Writes the digest to a stream: useful in development, and in a cron that mails its output."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

    def send(self, digest: Digest) -> None:
        if digest.is_empty:
            # Never send a digest of zeros. Silence is information too.
            return
        print(digest.render(), file=self._stream)


class UnsupportedChannelError(ValueError):
    """A channel this build cannot deliver to."""


def make_notifier(channel: str, stream: TextIO | None = None) -> Notifier:
    """Build the configured notifier, or say plainly that it does not exist yet."""
    if channel == "none":
        return NullNotifier()
    if channel == "console":
        return ConsoleNotifier(stream)
    if channel in NOT_YET_IMPLEMENTED:
        msg = (
            f"the '{channel}' channel is not implemented in this version; "
            f"use 'none' or 'console' for now"
        )
        raise UnsupportedChannelError(msg)
    msg = f"unknown notification channel {channel!r}"
    raise UnsupportedChannelError(msg)


def notify_safely(notifier: Notifier, digest: Digest) -> None:
    """Deliver, and never let a delivery problem touch the ingest path.

    Notification is best-effort by design: losing a message must not lose an event. The
    alternative — a failing Telegram token making the webhook endpoint return errors — would turn
    a cosmetic problem into data loss.
    """
    if digest.is_empty:
        return
    try:
        notifier.send(digest)
    except Exception:
        log.exception("could not deliver the digest")
