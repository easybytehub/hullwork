"""The inbound webhook surface — the only door this service opens to the outside.

Three properties, in this order:

1. **Authenticate before parsing.** The parser is the attack surface; authentication is the door.
2. **Answer fast.** Store the delivery, return 200, do the work afterwards.
3. **Be idempotent.** Providers retry by design; the same delivery *will* arrive twice.

Threat model in the m1 specification. Two things worth restating here, at the code:

* The error text in a payload is **data, never instruction**. It is stored and rendered, and when it
  eventually reaches a prompt it must be fenced — this is the known attack class in CI-triggered
  agents.
* A caller who guesses a project slug must not be able to tell it apart from one who does not, so an
  unknown project still pays the cost of a token comparison before its 404.
"""

import hashlib
import json
import logging
from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from hullwork.config import Settings, get_settings
from hullwork.db import get_engine, make_session_factory
from hullwork.forge.factory import make_forge
from hullwork.ingest import adapters_available, sweep
from hullwork.models import Delivery, Project
from hullwork.security import hash_token, verify_token

log = logging.getLogger(__name__)

router = APIRouter(tags=["ingest"])

#: A generous ceiling for an error payload. Anything larger is rejected whole, never truncated:
#: a half-read body is a body whose meaning we are guessing at.
MAX_BODY_BYTES = 1_000_000

#: Deep nesting is a cheap way to exhaust a parser. Checked before parsing, not after.
MAX_JSON_DEPTH = 40

#: Used when the project does not exist, so a wrong slug costs the same as a wrong token.
_DECOY_HASH = hash_token("decoy")


def _session(settings: Annotated[Settings, Depends(get_settings)]) -> Iterator[Session]:
    """One session per request, from the one engine, closed whichever way the request ends.

    A **generator** on purpose: FastAPI only runs cleanup for generator dependencies, so the plain
    `return factory()` this replaces never closed anything on any error path. Combined with a fresh
    engine per call it meant an unauthenticated request — dependencies resolve before the handler —
    opened a connection nobody ever closed. See `get_engine` for what that measured.
    """
    session = make_session_factory(get_engine(settings.database_url))()
    try:
        yield session
    finally:
        session.close()


def json_depth(raw: bytes) -> int:
    """Maximum nesting depth, measured without parsing.

    Scans the bytes tracking string state, because a `{` inside a string is text, not structure —
    counting it would reject perfectly ordinary stack traces full of JSON-looking noise.
    """
    depth = maximum = 0
    in_string = escaped = False
    for byte in raw:
        char = chr(byte)
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            maximum = max(maximum, depth)
        elif char in "}]":
            depth -= 1
    return maximum


@router.post("/webhooks/{provider}/{slug}/{token}", status_code=status.HTTP_200_OK)
async def receive(
    provider: str,
    slug: str,
    token: str,
    request: Request,
    background: BackgroundTasks,
    session: Annotated[Session, Depends(_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str]:
    """Accept one delivery from an error tracker.

    Returns 200 as soon as the delivery is safely stored. Everything after that runs in the
    background and, if it dies, is picked up by the next drain.
    """
    if provider not in adapters_available():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown endpoint")

    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "payload too large")

    project = session.scalars(
        select(Project).where(Project.slug == slug, Project.active.is_(True))
    ).one_or_none()

    # Unknown slug still pays for a comparison, so timing does not reveal which slugs exist.
    expected = project.webhook_secret_hash if project else _DECOY_HASH
    authenticated = _authenticate(provider, token, raw, expected)

    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown endpoint")
    if not authenticated:
        log.warning("rejected webhook", extra={"project": slug, "provider": provider})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthorised")

    if json_depth(raw) > MAX_JSON_DEPTH:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "payload too deeply nested")

    try:
        payload: Any = json.loads(raw)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "body is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "body must be a JSON object")

    delivery = Delivery(
        project_id=project.id,
        provider=provider,
        provider_delivery_id=_delivery_id(request),
        payload_hash=hashlib.sha256(raw).hexdigest(),
        payload_json=raw.decode("utf-8", errors="replace"),
    )
    session.add(delivery)
    try:
        session.commit()
    except IntegrityError:
        # The unique constraint did its job: this exact delivery is already stored. Providers retry
        # by design, so this is an ordinary Tuesday, not an error.
        session.rollback()
        return {"status": "duplicate"}

    background.add_task(_drain, session, settings)
    return {"status": "accepted"}


def _authenticate(provider: str, token: str, raw: bytes, expected_hash: str) -> bool:
    """Per provider, because they do not offer the same thing.

    GlitchTip cannot sign its webhooks — no header, no secret, no setting — so the token in the path
    is the credential. Sentry does sign, and its route is not enabled yet: verifying an HMAC means
    holding its client secret in a **reversible** form, which is a different storage decision from
    the one-way hash used here and deserves to be made deliberately rather than in passing.
    """
    if provider == "glitchtip":
        return verify_token(token, expected_hash)
    if provider == "sentry":
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            "the Sentry route is not enabled in this version; use GlitchTip",
        )
    return False


def _delivery_id(request: Request) -> str:
    """Whatever the provider gives us to recognise a redelivery by.

    Empty string when there is nothing — never NULL, because two NULLs are not equal in SQL and the
    unique constraint would quietly stop protecting anything.
    """
    for header in ("request-id", "x-request-id", "sentry-hook-signature"):
        value = request.headers.get(header)
        if value:
            return value[:200]
    return ""


def _drain(session: Session, settings: Settings) -> None:
    """Background processing. Never lets an exception escape into the request path."""
    try:
        sweep(session, make_forge(settings))
    except Exception:  # the response is already sent; log it and move on
        log.exception("drain failed")
    finally:
        session.close()
