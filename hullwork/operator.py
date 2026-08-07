"""Who may change something on the page, and for how long. Item 166.

**Two credentials, and the split is the point.** `page.opens` answers *may this request read*, and
its credential is a bearer token in a URL. This module answers *may this request act*, and its
credential never appears in a URL at all: it is pasted into a form once, exchanged for a session,
and after that only a cookie travels. A reader handed the read link stays safe to hand it to.

Nothing here enumerates. A wrong key, an expired session, and an instance with no operator key
configured all produce the same `None`, so a caller can only answer `404` — the same answer as a
wrong page token — and probing learns nothing about whether this instance can be acted on at all.
"""

from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from hullwork.models import OperatorKey, OperatorSession
from hullwork.security import generate_token, hash_token, verify_token

#: The cookie the browser sends back. Scoped to the page prefix rather than to `/`: nothing else
#: this application serves has any use for it, and the webhook endpoint least of all.
COOKIE = "hullwork_operator"

#: How long a session lasts. Long enough that an operator working through a morning's queue does not
#: log in twice; short enough that a browser left open on a train stops being a key by tomorrow.
LIFETIME = timedelta(hours=12)


def configured(session: Session) -> bool:
    """Whether this instance has an operator key at all — which is whether the buttons exist."""
    return session.scalars(select(OperatorKey).limit(1)).first() is not None


def issue_key(session: Session) -> str:
    """Generate the operator key, store its hash, and **end every session that exists**.

    Rotating is overwriting the one row, which is why there is one. Dropping the sessions with it is
    not tidiness: the reason to rotate is that the old key might be in somebody else's hands, and a
    live session issued by it would outlive the rotation by up to `LIFETIME`.
    """
    key = generate_token()
    row = session.scalars(select(OperatorKey).limit(1)).first()
    if row is None:
        session.add(OperatorKey(id=1, key_hash=hash_token(key)))
    else:
        row.key_hash = hash_token(key)
        row.created_at = datetime.now(UTC)
    session.execute(delete(OperatorSession))
    session.commit()
    return key


def log_in(session: Session, key: str) -> tuple[str, str] | None:
    """Exchange the operator key for `(cookie value, csrf token)`, or `None` if it is not the key.

    `None` covers both *wrong key* and *no key configured*, deliberately: the caller cannot tell
    them apart and so cannot leak the difference.
    """
    row = session.scalars(select(OperatorKey).limit(1)).first()
    if row is None or not verify_token(key, row.key_hash):
        return None

    token = generate_token()
    csrf = generate_token()
    session.add(
        OperatorSession(
            token_hash=hash_token(token),
            csrf=csrf,
            expires_at=datetime.now(UTC) + LIFETIME,
        )
    )
    session.commit()
    return token, csrf


def _row_for(session: Session, token: str | None) -> OperatorSession | None:
    if not token:
        return None
    row = session.scalars(
        select(OperatorSession).where(OperatorSession.token_hash == hash_token(token))
    ).first()
    if row is None:
        return None
    expires = row.expires_at
    if expires.tzinfo is None:  # SQLite hands back naïve datetimes on some drivers.
        expires = expires.replace(tzinfo=UTC)
    if expires <= datetime.now(UTC):
        # Expired rows are deleted on the way past rather than by a sweep: this is the only moment
        # anything is known to be looking at them, and a table of dead sessions is a table somebody
        # eventually has to explain.
        session.delete(row)
        session.commit()
        return None
    return row


def acting(session: Session, token: str | None) -> str | None:
    """The session's CSRF token if this cookie may act, else `None`.

    The one authorisation question this module answers, and the only one a route has to ask.
    """
    row = _row_for(session, token)
    return None if row is None else row.csrf


def csrf_ok(expected: str | None, supplied: str | None) -> bool:
    """Constant-time comparison of the CSRF pair, and `False` if either side is missing."""
    if not expected or not supplied:
        return False
    return hmac.compare_digest(expected, supplied)


def log_out(session: Session, token: str | None) -> None:
    """End this one session.

    A missing or unknown token is not an error: logging out twice is fine, and so is logging out of
    a session that expired while the page was open.
    """
    row = _row_for(session, token)
    if row is not None:
        session.delete(row)
        session.commit()
