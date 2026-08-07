"""Who may change something on the page, and for how long. Items 166, 167 and 168.

**Two credentials, and the split is the point.** `page.opens` answers *may this request read*, and
its credential is a bearer token in a URL — which is why it may not act: a URL is a thing that gets
saved, screenshotted and forwarded. This module answers *may this request act*, and its credential
is a password that never appears in a URL.

## Three designs, and what the first two got wrong

Item 166 stored 32 random bytes and asked the operator to paste them into a form. Item 167 replaced
that with a one-time link printed by the CLI. Both were secure and **neither was usable**, which the
operator said out loud about the second: to press a button you opened the page, ssh'd to the host,
ran a command, copied a link, opened it, went back and reloaded. Eight steps, every twelve hours,
against the single command the whole exercise meant to improve on. The friction moved, it did not
go away.

A password is what every self-hosted tool does, and the reason is mechanical rather than
conventional: **the browser's password manager fills it in.** One visit to the host, ever.

**The argument I used to reject it was false**, and it cost a milestone: I said a chosen password
needs scrypt or argon2, therefore a new dependency in the half of Hullwork that listens on the
network.
`hashlib.scrypt` is in the standard library. At `n=2**14` it costs 37 ms per attempt here — which is
the work factor *and* most of the answer to online guessing, with a lockout for the rest.

Nothing here enumerates. A wrong password, a locked instance, and one with no password set at all
produce the same `None`.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from hullwork.models import OperatorPassword, OperatorSession
from hullwork.security import generate_token, hash_token

#: The cookie the browser sends back. Scoped to the page prefix rather than to `/`: nothing else
#: this application serves has any use for it, and the webhook endpoint least of all.
COOKIE = "hullwork_operator"

#: How long a session lasts, and it is long on purpose. Item 167's twelve hours meant signing in
#: twice a day, which is what made it unusable; thirty days with renewal on use means an operator
#: who opens the page most weeks signs in once and forgets this exists.
LIFETIME = timedelta(days=30)

#: scrypt's cost. `n=2**14, r=8, p=1` is the parameter set Python's own documentation suggests for
#: interactive use, measured at 37 ms on the deployment host. Stored per row so raising this later
#: keeps old passwords verifiable instead of locking their owners out.
COST = {"n": 2**14, "r": 8, "p": 1}

#: Failures before the door closes, and for how long. Ten is past any plausible typo and far short
#: of a dictionary; fifteen minutes turns a guessing rate of 27 per second into four per hour.
MAX_FAILURES = 10
LOCKOUT = timedelta(minutes=15)


def _aware(when: datetime) -> datetime:
    """SQLite hands back naïve datetimes on some drivers; every comparison here needs UTC."""
    return when.replace(tzinfo=UTC) if when.tzinfo is None else when


def _derive(password: str, salt: str, *, n: int, r: int, p: int) -> str:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=bytes.fromhex(salt), n=n, r=r, p=p, dklen=32
    ).hex()


def configured(session: Session) -> bool:
    """Whether a password has been set, which is whether the page can offer a login."""
    return session.scalars(select(OperatorPassword).limit(1)).first() is not None


def set_password(session: Session, password: str) -> None:
    """Set or replace the password, and **end every session that exists**.

    Ending them is not tidiness: the reason to change a password is usually that the old one may be
    in somebody else's hands, and a session issued under it would outlive the change by a month.
    """
    salt = secrets.token_hex(16)
    row = session.scalars(select(OperatorPassword).limit(1)).first()
    values = {
        "salt": salt,
        "key": _derive(password, salt, **COST),
        "n": COST["n"],
        "r": COST["r"],
        "p": COST["p"],
        "failures": 0,
        "locked_until": None,
    }
    if row is None:
        session.add(OperatorPassword(id=1, **values))
    else:
        for name, value in values.items():
            setattr(row, name, value)
        row.created_at = datetime.now(UTC)
    session.execute(delete(OperatorSession))
    session.commit()


def locked_for(session: Session) -> timedelta | None:
    """How long the door stays shut, or `None`. What the page says instead of a silent refusal."""
    row = session.scalars(select(OperatorPassword).limit(1)).first()
    if row is None or row.locked_until is None:
        return None
    left = _aware(row.locked_until) - datetime.now(UTC)
    return left if left > timedelta(0) else None


def sign_in(session: Session, password: str) -> tuple[str, str] | None:
    """Exchange the password for `(cookie value, csrf token)`, or `None`.

    `None` covers a wrong password, a locked instance and one with no password set, deliberately:
    the caller cannot tell them apart and so cannot leak the difference. The page does report a
    lockout, because an operator who is locked out needs to know — and it reads that from
    `locked_for`, a question about this instance rather than about the guess just made.
    """
    row = session.scalars(select(OperatorPassword).limit(1)).first()
    if row is None:
        return None
    if row.locked_until is not None and _aware(row.locked_until) > datetime.now(UTC):
        return None

    # Always derive, even when a lockout has just expired: the cost is the point, and skipping it on
    # any path would make a wrong password measurably faster than a right one.
    supplied = _derive(password, row.salt, n=row.n, r=row.r, p=row.p)
    if not hmac.compare_digest(supplied, row.key):
        row.failures += 1
        if row.failures >= MAX_FAILURES:
            row.locked_until = datetime.now(UTC) + LOCKOUT
            row.failures = 0
        session.commit()
        return None

    row.failures = 0
    row.locked_until = None
    cookie = generate_token()
    csrf = generate_token()
    session.add(
        OperatorSession(
            token_hash=hash_token(cookie),
            csrf=csrf,
            expires_at=datetime.now(UTC) + LIFETIME,
        )
    )
    session.commit()
    return cookie, csrf


def _row_for(session: Session, token: str | None) -> OperatorSession | None:
    if not token:
        return None
    row = session.scalars(
        select(OperatorSession).where(OperatorSession.token_hash == hash_token(token))
    ).first()
    if row is None:
        return None
    if _aware(row.expires_at) <= datetime.now(UTC):
        session.delete(row)
        session.commit()
        return None
    # **Renewed past the halfway mark and not before.** A write on every request would turn reading
    # the page into a database write, and the receiver's sweep already contends for that lock.
    if _aware(row.expires_at) - datetime.now(UTC) < LIFETIME / 2:
        row.expires_at = datetime.now(UTC) + LIFETIME
        session.commit()
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
    """End this one session. Signing out twice is not an error, and neither is signing out of one
    that expired while the page was open."""
    row = _row_for(session, token)
    if row is not None:
        session.delete(row)
        session.commit()


def end_every_session(session: Session) -> int:
    """End every session there is, and say how many.

    The lever for the morning a laptop goes missing, and the argument for storing sessions rather
    than signing them: this is a `DELETE`, not a key rotation that happens to log everybody out.
    """
    open_now = list(session.scalars(select(OperatorSession)).all())
    session.execute(delete(OperatorSession))
    session.commit()
    return len(open_now)
