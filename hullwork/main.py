"""HTTP entry point for the Hullwork service."""

import asyncio
import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, suppress
from typing import Annotated, Any, Literal
from urllib.parse import parse_qsl

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session, sessionmaker

from hullwork import __version__, operator, page, readiness
from hullwork import decisions as decide
from hullwork.config import ConfigError, Settings, get_settings
from hullwork.db import get_engine, make_session_factory
from hullwork.forge.factory import make_forge
from hullwork.ingest import sweep
from hullwork.logging import configure_logging
from hullwork.models import Item
from hullwork.readiness import record_sweep_ok
from hullwork.telemetry import (
    configure_error_reporting,
    known_secrets,
    upstream_destination,
)
from hullwork.tracker.factory import make_inventory, make_tracker
from hullwork.webhooks import router as webhooks_router

log = logging.getLogger(__name__)

#: Set once at start-up. `/ready` reports it, because a DSN configured and nothing listening
#: to it is the shape of failure that looked healthiest.
_reporting_enabled = False


def _readiness_session(
    settings: Annotated[Settings, Depends(get_settings)],
) -> Iterator[Session]:
    """A session for the probe, closed however the request ends."""
    session = make_session_factory(get_engine(settings.database_url))()
    try:
        yield session
    finally:
        session.close()


def _sweep_once(factory: sessionmaker[Session], settings: Settings) -> None:
    """One pass over everything outstanding. Sync, so it runs in a worker thread."""
    with factory() as session:
        result = sweep(
            session,
            make_forge(settings),
            recheck_after=settings.forge_recheck_seconds,
            tracker=make_tracker(settings),
            inventory=make_inventory(settings),
        )
    if not result.skipped:
        record_sweep_ok()
    if result.deliveries or result.filed or result.resolved or result.fetched or result.swept:
        log.info(
            "sweep finished outstanding work",
            extra={
                "deliveries": result.deliveries,
                "filed": result.filed,
                "resolved": result.resolved,
                "fetched": result.fetched,
                "swept": result.swept,
            },
        )


async def _sweep_forever(factory: sessionmaker[Session], settings: Settings) -> None:
    """A clock of our own, because nothing upstream keeps one for us.

    An error tracker notifies once per issue and never again, so an item whose issue could not be
    filed will not be reminded of by a redelivery — there will not be one. Retrying only when the
    next delivery happens to arrive would leave that item waiting for an event that may never
    come.

    Failures here are logged and the loop continues: a sweep that dies quietly would restore the
    exact silence this exists to end.
    """
    while True:
        await asyncio.sleep(settings.sweep_interval_seconds)
        try:
            await asyncio.to_thread(_sweep_once, factory, settings)
        except Exception:
            log.exception("periodic sweep failed")


def _refuse_the_credential_this_process_must_not_hold(settings: Settings) -> None:
    """Stop the service if it has been given the token that can push (spec M2 §1).

    Hullwork is two programs with different privileges. This one listens on the network and holds
    the ingest credential for as long as it is up; the dispatcher holds the code credential, needs
    the Docker daemon, and exits. Putting `HULLWORK_FORGE_CODE_TOKEN` in *this* process's
    environment puts both in one address space, which makes the split item 017 drew nominal — one
    flaw in the receiver would then reach the repository.

    Refused rather than warned about, because the failure it guards against is invisible: a variable
    that is present and unused looks exactly like a boundary that has quietly been removed, and
    compose files get copied between projects and pasted into issues. There is no environment in
    which this process needs the value, so there is no case to weigh.

    The value never appears in the message. Naming the variable is the actionable part; echoing a
    live credential into a start-up log is the thing item 015 was spent removing.
    """
    if settings.forge_code_token is None:
        return
    raise ConfigError(
        "HULLWORK_FORGE_CODE_TOKEN is set for the service, and it must never be.\n"
        "  That credential can push code. This process listens on the network and holds it for as\n"
        "  long as it runs; the two are kept apart on purpose.\n"
        "  Move it to the environment of the `hullwork work` dispatcher, which runs on a schedule\n"
        "  and exits. See docs/deployment-notes.md, 'The two credentials'."
    )


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Validate the environment and install logging before serving anything.

    A bad setting stops startup here, which is the point: an instance that boots with a broken
    configuration is one whose failure surfaces later, in production, disguised as something else.
    """
    settings = get_settings()
    # The redactor is armed with the values this process actually holds. Without them its
    # by-value defence — the one its own docstring calls "the one that catches the accidental
    # leak" — was inert for the life of the process.
    configure_logging(
        level=settings.log_level,
        log_format=settings.log_format,
        secrets=known_secrets(settings),
    )
    _refuse_the_credential_this_process_must_not_hold(settings)

    # Before anything else that can fail, so a start-up error is itself reported.
    #
    # The session factory is built here rather than below so an upstream report can be attributed to
    # this installation. Building it opens nothing — the engine connects on first use — and the
    # identifier is read lazily, at most once, the first time there is something to report. A crash
    # before then still travels, uncounted: item 151's `installation: None`.
    factory = make_session_factory(get_engine(settings.database_url))
    reporting = configure_error_reporting(settings, operation="receiver", session_factory=factory)
    global _reporting_enabled
    _reporting_enabled = reporting

    # Unconditional, and it names the *effective* configuration rather than the intended one.
    # `docker compose restart` does not re-read `env_file`, which once produced a healthy container
    # with an inert SDK and nothing anywhere to suggest it — the absence of a success line is not a
    # signal anybody reads.
    log.info(
        "hullwork starting",
        extra={
            "service_version": __version__,
            "error_reporting": reporting,
            "forge_configured": bool(settings.forge_url and settings.forge_token),
            "tracker_configured": bool(settings.tracker_url and settings.tracker_token),
            "sweep_interval_s": settings.sweep_interval_seconds,
            "database": settings.database_url.split("://", 1)[0],
        },
    )
    if settings.model_credentials_file:
        # Loud on purpose. The supported configuration is an API key (DR-0004, amended); reading a
        # subscription's credentials file is how *our* dogfood runs at no marginal cost, and the
        # difference between a convenience and a supported path has to be visible from the log.
        log.warning(
            "using the development credential path: reading a subscription's credentials file. "
            "The supported configuration is an API key in HULLWORK_MODEL_KEY — this one expires in "
            "hours and depends on something else refreshing it"
        )
    if settings.error_dsn is not None and not reporting:
        log.error("error reporting is configured but not running")
    if settings.sweep_interval_seconds == 0:
        log.warning(
            "the retry clock is disabled; nothing will finish work that a pass could not, "
            "unless something external calls the sweep"
        )

    # Anything accepted before the last shutdown is finished now. A delivery we answered 200 to and
    # then dropped on restart would be a promise quietly broken, and nobody would ever find out.
    try:
        _sweep_once(factory, settings)
    except Exception:  # a cold database must not stop the service from booting
        log.exception("could not sweep at startup")

    ticker = (
        asyncio.create_task(_sweep_forever(factory, settings))
        if settings.sweep_interval_seconds
        else None
    )
    try:
        yield
    finally:
        if ticker is not None:
            ticker.cancel()
            with suppress(asyncio.CancelledError):
                await ticker
        # Whatever was posted upstream in the last moments gets two seconds to leave, and then does
        # not. A shutdown that waits on our ingest is a shutdown we made slower on somebody else's
        # machine — and the crash that mattered is the one that caused the shutdown, which was
        # already sent.
        destination = upstream_destination()
        if destination is not None:
            destination.close()


app = FastAPI(
    title="Hullwork",
    version=__version__,
    summary="Self-hosted maintenance loop: production errors in, reviewable pull requests out.",
    lifespan=lifespan,
)


app.include_router(webhooks_router)


class Health(BaseModel):
    """Liveness payload: that the service is up, and which build answered."""

    status: Literal["ok"]
    version: str


@app.get("/health", tags=["ops"])
def health() -> Health:
    """Report liveness.

    Deliberately depends on nothing: no settings, no database, no network. A probe that can fail
    for reasons unrelated to the service being alive is worse than no probe at all.

    Which is exactly why it is not enough on its own — see `/ready`, which can fail, and which is
    what a container healthcheck and an uptime monitor should be pointed at.
    """
    return Health(status="ok", version=__version__)


@app.get("/ready", tags=["ops"])
def ready(
    response: Response,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Report whether this instance is doing its job, with the numbers behind the verdict.

    503 when something is wrong, so a healthcheck or an uptime monitor can act on it without
    parsing anything. **Point the tracker's own uptime monitor at this**: the check then travels
    the identical path a webhook does — tracker, network, firewall, this address — which is the
    path that silently dropped deliveries for three hours. Send that alert somewhere other than
    the Hullwork webhook, or it dies on the road it is reporting.
    """
    report = readiness.check(session, settings, error_reporting=_reporting_enabled)
    if not report.ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return report.as_dict()


@app.get(
    f"{page.PREFIX}/{{token}}",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_instance(
    token: str,
    session: Annotated[Session, Depends(_readiness_session)],
) -> RedirectResponse:
    """The door. Item 122, and everything about it is in `hullwork.page`.

    **`404` for a wrong token, never `403`**, and the same `404` when this instance has no page at
    all: a `403` would confirm that there is something here to guess at. Out of the schema for the
    same reason — `/docs` should not advertise a door whose whole design is not being findable.

    `GET` only, and that is asserted by walking the application's routes rather than by trusting
    this decorator to stay a `get`.
    """
    if not page.opens(session, token):
        # **The same body Starlette gives an unknown path**, not a friendlier one: a distinct
        # message is a yes. Measured while writing the test — the default is `{"detail":"Not
        # Found"}` and `"not found"` would have told a prober that this route exists.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    # **To the same URL with a slash, and the reason is the token.** Under `/page/{token}/` every
    # link between views is relative — `items`, `../items` — so the credential never has to be
    # written into the HTML to get from one page to the next. Saved HTML, a screenshot of the
    # source, a page mailed to a colleague: none of them carry the key to the instance. The
    # redirect's `Location` does, but that is the URL the client just sent.
    return RedirectResponse(
        f"{page.PREFIX}/{token}/",
        status_code=status.HTTP_308_PERMANENT_REDIRECT,
        headers=page.HEADERS,
    )


@app.get(
    f"{page.PREFIX}/{{token}}/",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_instance_index(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """The instance view itself. Everything about it is in `hullwork.page`."""
    if not page.opens(session, token):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    return HTMLResponse(
        page.instance(
            session,
            settings,
            error_reporting=_reporting_enabled,
            acting=_acting(session, request),
        ),
        headers=page.HEADERS,
    )


@app.get(
    f"{page.PREFIX}/{{token}}/items",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_items(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    in_: Annotated[str | None, Query(alias="in")] = None,
) -> HTMLResponse:
    """Every item, most recent first. Item 123."""
    if not page.opens(session, token):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    return HTMLResponse(
        page.items(session, only=in_, acting=_acting(session, request)), headers=page.HEADERS
    )


@app.get(
    f"{page.PREFIX}/{{token}}/projects",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_projects(
    token: str,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """Every project this instance serves. Item 142, the level the tree was missing."""
    if not page.opens(session, token):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    return HTMLResponse(page.projects(session, settings), headers=page.HEADERS)


@app.get(
    f"{page.PREFIX}/{{token}}/projects/{{slug}}",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_project(
    token: str,
    slug: str,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """One project. Item 142.

    **The same `404` for an unknown slug as for a wrong token**, and for the same reason: a distinct
    body would let somebody with a valid token enumerate which clients an instance serves — a fact
    about a consultancy's customers as much as about this deployment.
    """
    if not page.opens(session, token):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    rendered = page.project(session, settings, slug)
    if rendered is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    return HTMLResponse(rendered, headers=page.HEADERS)


@app.get(
    f"{page.PREFIX}/{{token}}/items/{{item_id}}",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_item(
    token: str,
    item_id: int,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """One item and the artefact of every attempt on it. Item 123.

    An item that does not exist gets the **same** `404` a wrong token gets, so the page cannot be
    used to count an instance's items from outside — though anyone who has got this far holds the
    token and could simply read the list.
    """
    if not page.opens(session, token):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    rendered = page.item(session, settings, item_id, acting=_acting(session, request))
    if rendered is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    return HTMLResponse(rendered, headers=page.HEADERS)


#: The most a form on this page can be. Both fields are 43-character tokens; anything approaching
#: this is not a browser filling in the login.
_FORM_CEILING = 4096


async def _field(request: Request, name: str) -> str | None:
    """One field out of an `application/x-www-form-urlencoded` body, or `None`.

    **Hand-parsed to keep a dependency out of the receiver.** FastAPI's `Form()` requires
    `python-multipart`, and this is the half of Hullwork that listens on a network — every package
    it imports is surface. The forms here are written in this file and post urlencoded, which
    `urllib.parse` has always understood, so the dependency would buy nothing but multipart support
    that nothing here sends.

    The body is read after the length check rather than before it, for the reason the webhook
    endpoint does the same: a declared length is refusable without allocating what it declares.
    """
    if "application/x-www-form-urlencoded" not in request.headers.get("content-type", ""):
        return None
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > _FORM_CEILING:
        return None
    body = await request.body()
    if len(body) > _FORM_CEILING:
        return None
    for key, value in parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True):
        if key == name:
            return value
    return None


def _acting(session: Session, request: Request) -> page.Acting:
    """What this request may do, from the cookie it brought. Item 166.

    Called by every page view, and it is the only place authority is decided. The renderer receives
    the answer and never the cookie, so a view cannot accidentally treat a *read* token as
    authority.
    """
    return page.Acting(
        csrf=operator.acting(session, request.cookies.get(operator.COOKIE)),
        offered=operator.configured(session),
    )


def _to_page(token: str, tail: str = "") -> RedirectResponse:
    """Back where the operator was, as a `303`. Item 166.

    **`303` and not `302`**, because the browser must turn a POST into a GET: a `302` leaves some
    clients re-posting the form on refresh, which for `approve` would mean a second attempt.
    """
    return RedirectResponse(
        f"{page.PREFIX}/{token}/{tail}",
        status_code=status.HTTP_303_SEE_OTHER,
        headers=page.HEADERS,
    )


@app.post(f"{page.PREFIX}/{{token}}/login", tags=["page"], include_in_schema=False)
async def page_login(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
) -> RedirectResponse:
    """Exchange the operator key for a session cookie. Item 166.

    **The one route that accepts a secret in a body, and it answers the same either way.** A wrong
    key redirects to the page exactly as a right one does: an attacker with the read link learns
    nothing from the response about whether a key was right, and the operator finds out by whether
    the buttons are there. No error page, because an error page is an oracle.

    `Secure` is read off the request rather than hardcoded. Hardcoding it on would silently break
    the plain-HTTP tailnet deployment this runs on — the cookie would never be sent and the login
    would look broken; hardcoding it off would be wrong the day a TLS proxy is put in front. On the
    tailnet the transport is encrypted by WireGuard even without it.
    """
    if not page.opens(session, token):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")

    key = await _field(request, "key")
    issued = operator.log_in(session, key) if key else None
    redirect = _to_page(token)
    if issued is not None:
        cookie, _csrf = issued
        redirect.set_cookie(
            operator.COOKIE,
            cookie,
            max_age=int(operator.LIFETIME.total_seconds()),
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path=page.PREFIX,
        )
    return redirect


@app.post(f"{page.PREFIX}/{{token}}/logout", tags=["page"], include_in_schema=False)
async def page_logout(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
) -> RedirectResponse:
    """End this session. Item 166.

    CSRF-protected like the decisions are: a forced logout is a nuisance rather than a breach, but a
    route that skips the check is a route somebody later copies.
    """
    if not page.opens(session, token):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    cookie = request.cookies.get(operator.COOKIE)
    if operator.csrf_ok(operator.acting(session, cookie), await _field(request, "csrf")):
        operator.log_out(session, cookie)
    redirect = _to_page(token)
    redirect.delete_cookie(operator.COOKIE, path=page.PREFIX)
    return redirect


def _decide(
    token: str,
    item_id: int,
    session: Session,
    csrf: str | None,
    what: str,
    *,
    cookie: str | None,
) -> RedirectResponse:
    """The shared body of the two decisions: authorise, act, and go back to the item. Item 166.

    **Four guards, in this order, and each one is the whole of a different threat:**

    1. the page token, or `404` — the same answer an unknown path gets;
    2. a session, or `404` **again** rather than `401`: an instance with no operator key and one
       whose cookie is wrong must be indistinguishable, or the read link becomes a way to ask
       whether this instance can be acted on at all;
    3. the CSRF token, or `403` — reachable only by something that already holds a valid session
       cookie, so there is nothing left to hide from it;
    4. the state machine, in `decisions`, which is what refuses an item that is not amber.
    """
    if not page.opens(session, token):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")

    expected = operator.acting(session, cookie)
    if expected is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    if not operator.csrf_ok(expected, csrf):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Forbidden")

    found = session.get(Item, item_id)
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    act = decide.approve if what == "approve" else decide.hand_to_human
    try:
        act(session, found.project, item_id)
    except decide.DecisionError as exc:
        # The item's own page is where the reason belongs, and it is already rendering the state
        # that caused this. `409` says the request was well formed and the world disagreed.
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    log.info("decided from the page", extra={"item": item_id, "decision": what})
    return _to_page(token, f"items/{item_id}")


@app.post(
    f"{page.PREFIX}/{{token}}/items/{{item_id}}/approve", tags=["page"], include_in_schema=False
)
async def page_approve(
    token: str,
    item_id: int,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
) -> RedirectResponse:
    """Let the agent attempt this item. `POST` only, and that is asserted by a test.

    A `GET` that approves is a URL that approves — from an image tag, a prefetch, a chat unfurling a
    link somebody pasted. This costs money and opens a pull request, so it cannot be a link.
    """
    return _decide(token, item_id, session, await _field(request, "csrf"), "approve",
                   cookie=request.cookies.get(operator.COOKIE))


@app.post(
    f"{page.PREFIX}/{{token}}/items/{{item_id}}/human", tags=["page"], include_in_schema=False
)
async def page_hand_to_human(
    token: str,
    item_id: int,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
) -> RedirectResponse:
    """Take this item away from the agent: a person will do it. `POST` only, same reasoning."""
    return _decide(token, item_id, session, await _field(request, "csrf"), "human",
                   cookie=request.cookies.get(operator.COOKIE))
