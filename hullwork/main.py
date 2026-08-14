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
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from hullwork import __version__, operator, page, readiness
from hullwork import decisions as decide
from hullwork.config import ConfigError, Settings, get_settings
from hullwork.db import get_engine, make_session_factory
from hullwork.forge.factory import make_forge
from hullwork.ingest import sweep, sweep_inventory
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


def _measure_what_the_ingest_credential_may_do(
    factory: sessionmaker[Session], settings: Settings
) -> None:
    """Ask the forge whether the ingest credential can push, on this instance's own clock. Item 228.

    **The most important thing a project's page can say was waiting for a person.** DR-0009 forbids
    the receiver holding a credential that can push, `credentials.audit` measures it, and its
    docstring says *only ever run on request* — so an instance running for weeks answered *not asked
    yet*. Worse: the key the page read was written by nothing at all, so asking would not have
    helped either.

    **A signal that depends on somebody remembering is not a signal.** That is item 073's rule
    arriving from the other side: it deleted a check that was permanently on; this one was
    permanently unknown.

    Throttled by `forge_recheck_seconds`, the number this instance already uses for *how often may I
    ask the forge about a thing again*. The cost is two calls per active project per interval — 12
    an hour for two projects at the default — and it is spent by the clock, never by a page render.
    """
    from datetime import UTC, datetime, timedelta

    from hullwork import credentials
    from hullwork.cli import _scope_probe
    from hullwork.forge.factory import make_permission_reader
    from hullwork.models import Project as ProjectRow

    if not settings.forge_url or not settings.forge_token:
        return
    due = datetime.now(UTC) - timedelta(seconds=max(settings.forge_recheck_seconds, 60))
    with factory() as session:
        waiting = [
            one
            for one in session.scalars(
                select(ProjectRow).where(ProjectRow.active.is_(True))
            ).all()
            if one.ingest_checked_at is None or one.ingest_checked_at < due
        ]
        if not waiting:
            return
        try:
            found = credentials.audit(
                session, make_permission_reader(settings), probe=_scope_probe(settings)
            )
        except Exception:  # a forge having a bad minute is not this loop's problem
            log.debug("could not measure the ingest credential", exc_info=True)
            return
        answered = {one.slug: one for one in found}
        now = datetime.now(UTC)
        for project in waiting:
            verdict = answered.get(project.slug)
            if verdict is None:
                continue
            # **Both fields together, or neither.** A verdict with no timestamp is the
            # permanently-on signal again, and a timestamp with no verdict is worse: it says the
            # question was answered when it was not.
            # **The conclusion, not one field.** `credentials.audit` only probes the token where
            # the account can push, because a project whose account cannot has nothing for the
            # probe to disprove — so `token_can_push` is `None` there and it is not *unknown*, it
            # is *not in question*. `None` survives only when the forge would not say at all.
            project.ingest_token_can_push = (
                verdict.token_can_push
                if verdict.token_can_push is not None
                else (False if verdict.can_push is False else None)
            )
            project.ingest_checked_at = now
        session.commit()


#: How often a project's dependencies are asked about. **Not `forge_recheck_seconds`**: advisories
#: are published on a human's schedule, and asking OSV every ten minutes would be spending somebody
#: else's public API to learn nothing. Six hours is four answers a day, which is more than the
#: publication rate of the thing being asked about.
ADVISORIES_EVERY_SECONDS = 6 * 60 * 60


def _ask_what_is_published_against_what_they_pin(
    factory: sessionmaker[Session], settings: Settings
) -> None:
    """Read what each project pins and ask OSV what is published against it. DR-0024, item 230.

    **The receiver may do this and the dispatcher must do the rest.** Reading a lock file is the
    same forge call `projects refresh` already makes, and OSV takes no credential — so this needs
    nothing DR-0005 withholds. Applying an upgrade and running a suite needs the Docker socket, and
    that half stays where it is.

    **Stored with when it was asked, and with whether it was asked at all.** Those are the two
    conditions the operator put on accepting DR-0024, and they are the same sentence: a report
    rendered without its timestamp is a claim about a moment presented as a standing fact, and an
    empty advisory list from a failed request says *you are fine* on no evidence.
    """
    from datetime import UTC, datetime, timedelta

    from hullwork import advisories, upgrades
    from hullwork.models import DependencyReport
    from hullwork.models import Project as ProjectRow

    if not settings.forge_url or not settings.forge_token:
        return
    due = datetime.now(UTC) - timedelta(seconds=ADVISORIES_EVERY_SECONDS)
    with factory() as session:
        waiting = [
            one
            for one in session.scalars(
                select(ProjectRow).where(ProjectRow.active.is_(True))
            ).all()
            if (report := session.get(DependencyReport, one.id)) is None
            or report.taken_at < due
        ]
        if not waiting:
            return
        forge = make_forge(settings)
        if forge is None:
            return
        ask = advisories.asking()
        try:
            for project in waiting:
                found = advisories.about(project.repo, forge, ask)
                session.merge(
                    DependencyReport(
                        project_id=project.id,
                        taken_at=datetime.now(UTC),
                        asked=found.asked,
                        note=found.note,
                        pinned=found.pinned,
                        findings=found.findings,
                    )
                )
                if found.asked:
                    # **A new report is the only event that can make a kept artefact stale** (item
                    # 245), so this is the only place the forgetting can go. Guarded on `asked`
                    # because a request that never reached OSV answers nothing: dropping artefacts
                    # on an empty finding list would forget everything whenever the network blinked.
                    upgrades.forget_stale(session, project.id, found.findings)
        finally:
            forge.close()
        session.commit()


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
    _measure_what_the_ingest_credential_may_do(factory, settings)
    _ask_what_is_published_against_what_they_pin(factory, settings)
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
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
) -> RedirectResponse:
    """The door. Item 122, and everything about it is in `hullwork.page`.

    **`404` for a wrong token, never `403`**, and the same `404` when this instance has no page at
    all: a `403` would confirm that there is something here to guess at. Out of the schema for the
    same reason — `/docs` should not advertise a door whose whole design is not being findable.

    `GET` only, and that is asserted by walking the application's routes rather than by trusting
    this decorator to stay a `get`.
    """
    _may_read(session, request, token)
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
    """The front door, which is the work rather than the arithmetic about it (item 212, DR-0023).

    It was the instance report until this item: 357 words, 11 numbers and 14 sentences before a
    person could do anything. The report is a noun in the rail now, with every number it had.

    **The one route where a refusal is not a `404`** (DR-0021): with a password configured and no
    session, this is where somebody acquires one, or the door that replaces the token has no handle.
    What that discloses is that this host runs something with a login, and nothing else — and an
    instance that never set a password is `404` here like everywhere else.
    """
    shut = _the_login_if_offered(session, request, token)
    if shut is not None:
        return shut
    acting = _may_read(session, request, token)
    # **The door answers a question and lists the projects** (item 237). It was every item on the
    # instance in one table, which with two projects is two projects' bugs interleaved and *whose*
    # as the column to scan for. The list of every item is still `/items`.
    return HTMLResponse(
        page.front_door(
            session, settings, acting=acting, error_reporting=_reporting_enabled
        ),
        headers=page.HEADERS,
    )


@app.get(
    f"{page.PREFIX}/{{token}}/instance",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_instance_report(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """Every number this instance keeps. Moved off the front door by item 212, not dropped."""
    acting = _may_read(session, request, token)
    return HTMLResponse(
        page.instance(
            session,
            settings,
            error_reporting=_reporting_enabled,
            acting=acting,
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
    _may_read(session, request, token)
    return HTMLResponse(
        page.items(session, only=in_, acting=_acting(session, request)), headers=page.HEADERS
    )


#: The five views a project has, by the last segment of the URL each is served from. **A `POST`
#: answers with the document for the URL it posted to** (item 250), so the handler that acts needs
#: the same map the handlers that read use.
_THE_VIEWS: dict[str, Any] = {
    "errors": page.errors,
    "fixes": page.fixes,
    "dependencies": page.dependencies,
    "deliveries": page.deliveries,
    "settings": page.settings_for,
}


def _a_project_view(
    view: object, session: Session, settings: Settings, slug: str, acting: page.Acting,
    **answered: str | tuple[str, str | None] | None,
) -> HTMLResponse:
    """Render one of a project's feature pages, or `404` for a slug that is not one.

    The `404` is the same one an unknown path gets, on purpose: a distinct body would let somebody
    with a valid read token enumerate the slugs this instance serves.

    `answered` is what the last press said — a sentence, a refusal, a rotated secret — and it is
    passed through rather than composed here, for the reason `_outcome` gives.
    """
    shown = view(session, settings, slug, acting=acting, **answered)  # type: ignore[operator]
    if shown is None:
        raise HTTPException(status_code=404)
    return HTMLResponse(shown, headers=page.HEADERS)


@app.get(
    f"{page.PREFIX}/{{token}}/projects/{{slug}}/errors",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_project_errors(
    token: str,
    slug: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """This project's bugs, newest first. Item 237."""
    _may_read(session, request, token)
    return _a_project_view(page.errors, session, settings, slug, _acting(session, request))


@app.get(
    f"{page.PREFIX}/{{token}}/projects/{{slug}}/fixes",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_project_fixes(
    token: str,
    slug: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """What this instance attempted on this project, and what it cost. Item 237."""
    _may_read(session, request, token)
    return _a_project_view(page.fixes, session, settings, slug, _acting(session, request))


@app.get(
    f"{page.PREFIX}/{{token}}/projects/{{slug}}/dependencies",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_project_dependencies(
    token: str,
    slug: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """What is published against what this project pins. Item 237, DR-0024.

    **Inside the project** (item 237), because a page holding every project's advisories one after
    another is a wall at two projects and unusable at ten: nobody works by feature across clients.
    """
    _may_read(session, request, token)
    return _a_project_view(page.dependencies, session, settings, slug, _acting(session, request))


@app.get(
    f"{page.PREFIX}/{{token}}/projects/{{slug}}/deliveries",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_project_deliveries(
    token: str,
    slug: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """What this project's tracker sent, and whether it was understood. Item 237."""
    _may_read(session, request, token)
    return _a_project_view(page.deliveries, session, settings, slug, _acting(session, request))


@app.get(
    f"{page.PREFIX}/{{token}}/projects/{{slug}}/settings",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_project_settings(
    token: str,
    slug: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """Everything this instance will do to this project on command. Item 237."""
    _may_read(session, request, token)
    return _a_project_view(page.settings_for, session, settings, slug, _acting(session, request))


@app.get(
    f"{page.PREFIX}/{{token}}/projects",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_projects(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """Every project this instance serves. Item 142, the level the tree was missing."""
    _may_read(session, request, token)
    acting = _acting(session, request)
    return HTMLResponse(page.projects(session, settings, acting=acting), headers=page.HEADERS)


@app.get(
    f"{page.PREFIX}/{{token}}/projects/{{slug}}",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_project(
    token: str,
    request: Request,
    slug: str,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """One project. Item 142.

    **The same `404` for an unknown slug as for a wrong token**, and for the same reason: a distinct
    body would let somebody with a valid token enumerate which clients an instance serves — a fact
    about a consultancy's customers as much as about this deployment.
    """
    _may_read(session, request, token)
    rendered = page.project(session, settings, slug, acting=_acting(session, request))
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
    _may_read(session, request, token)
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


def _may_read(session: Session, request: Request, token: str) -> page.Acting:
    """The one gate every page route asks, and it returns what the renderer needs. Item 204.

    **One place, not nine.** Each route used to decide this for itself, and DR-0021 gives the answer
    a second input — a session may read at the reserved path — so nine copies would be nine chances
    to add it in eight of them. That is the defect items 193, 194, 200 and 203 each cost a day to,
    and this is auth, where the cost of getting it wrong is not a wrong number on a page.

    Raises the `404` itself, with the body Starlette gives an unknown path: a distinct message is a
    yes.
    """
    acting = _acting(session, request)
    if not page.opens(session, token, acting=acting):
        # **A `404` on the operator's own path locks them out of every URL but one** (item 224).
        # The reason the refusals here are indistinguishable is DR-0021's: a distinct answer would
        # tell somebody holding a *read link* which doors exist. `me` is not a read link — it is a
        # literal anybody can type, and the front door already answers it with a login. So on that
        # path, and only there, the answer is the login rather than a wall.
        if page.offers_a_login(token, acting):
            raise _NeedsTheLoginError(request.url.path)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    return acting


class _NeedsTheLoginError(Exception):
    """Not a failure: a request that may sign in and has not. Item 224.

    An exception rather than a return, because `_may_read` is called by nine routes as a gate and
    turning it into something every one of them has to inspect is the *one place, not nine* problem
    its own docstring is about.
    """

    def __init__(self, going_to: str) -> None:
        super().__init__(going_to)
        self.going_to = going_to


@app.exception_handler(_NeedsTheLoginError)
def _answer_with_the_login(request: Request, exc: Exception) -> HTMLResponse:
    """The login, for a request that may sign in and has not. Item 224.

    **Where they were going travels with it**, so signing in lands on the view they opened rather
    than on the front door — `page.where_it_may_land` decides what that may be, from a list.
    """
    return HTMLResponse(
        page.just_the_login(
            page.Acting(csrf=None, offered=True), going_to=getattr(exc, "going_to", "")
        ),
        headers=page.HEADERS,
    )


def _the_login_if_offered(
    session: Session, request: Request, token: str
) -> HTMLResponse | None:
    """The login, when this request may not read yet and may be told how to. Item 204.

    Returned rather than raised so the route reads as what it is, and kept here rather than in the
    route so that **no route asks `page.opens` itself** — the three gates in this module are the
    only callers, which is what `test_there_is_one_gate_and_not_ten` asserts.
    """
    acting = _acting(session, request)
    if page.opens(session, token, acting=acting) or not page.offers_a_login(token, acting):
        return None
    return HTMLResponse(page.just_the_login(acting), headers=page.HEADERS)


def _the_operators(session: Session, request: Request, token: str) -> page.Acting:
    """A view only the operator sees: the session, never a read link. Item 208.

    `404` rather than `403`, like everything else here — a distinct refusal would tell somebody
    holding a read link which doors exist behind it.

    It returns who that is, because item 212's rail is drawn from it: these two views rendered with
    the default `Acting` showed a signed-in operator the reader's three nouns, so opening *why it
    will not work* took away the way to *what it received*.
    """
    acting = _may_read(session, request, token)
    if operator.acting(session, request.cookies.get(operator.COOKIE)) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    return acting


def _may_sign_in(session: Session, request: Request, token: str) -> None:
    """The gate the **login** asks, which is not the one every other route asks. Item 204's defect.

    Found in use on the first attempt: the login was put behind `_may_read`, and at the session door
    that requires a session — so signing in required already being signed in, and the form answered
    `{"detail":"Not Found"}`. A door with a handle you can only reach from inside is a door nobody
    opens.

    Two ways through, and they are the two kinds of person who sign in: somebody holding a read link
    who wants the buttons, and somebody at the session door who has the password. Everything else is
    the same `404` an unknown path gets, so an instance with no password configured has nothing to
    post to — the property DR-0021 spends nothing of.
    """
    acting = _acting(session, request)
    if page.opens(session, token, acting=acting) or page.offers_a_login(token, acting):
        return
    raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")


def _acting(session: Session, request: Request) -> page.Acting:
    """What this request may do, from the cookie it brought. Item 166.

    Called by every page view, and it is the only place authority is decided. The renderer receives
    the answer and never the cookie, so a view cannot accidentally treat a *read* token as
    authority.
    """
    locked = operator.locked_for(session)
    return page.Acting(
        csrf=operator.acting(session, request.cookies.get(operator.COOKIE)),
        offered=operator.configured(session),
        locked_minutes=None if locked is None else max(1, int(locked.total_seconds() // 60)),
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


@app.get(
    f"{page.PREFIX}/{{token}}/doctor",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_doctor(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """Why an instance that is running will not work. Item 208, DR-0022.

    **The operator's, not a reader's.** DR-0021 gives a link reading and the password administering;
    this and `config` are the two somebody opens when something is wrong, and they belong on the
    second side of that line.
    """
    acting = _the_operators(session, request, token)
    return HTMLResponse(
        page.why_it_will_not_work(session, settings, acting=acting), headers=page.HEADERS
    )


@app.get(
    f"{page.PREFIX}/{{token}}/config",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
def page_config(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """What this process actually received. Item 208."""
    acting = _the_operators(session, request, token)
    return HTMLResponse(page.what_it_received(settings, acting=acting), headers=page.HEADERS)


@app.post(f"{page.PREFIX}/{{token}}/login", tags=["page"], include_in_schema=False)
async def page_login(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
) -> RedirectResponse:
    """Exchange the password for a session cookie. Item 168.

    **The one route that accepts a secret in a body, and it answers the same either way.** A wrong
    password redirects to the page exactly as a right one does: somebody with the read link learns
    nothing from the response, and the operator finds out by whether the buttons are there. No error
    page, because an error page is an oracle.

    `Secure` is read off the request rather than hardcoded. Hardcoding it on would silently break a
    deployment served over plain HTTP behind a VPN — the cookie would never be sent and the login
    would look broken; hardcoding it off would be wrong the day a TLS proxy is put in front.
    """
    _may_sign_in(session, request, token)

    supplied = await _field(request, "password")
    issued = operator.sign_in(session, supplied) if supplied else None
    redirect = _to_page(token, page.where_it_may_land(await _field(request, "going_to")))
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


@app.post(f"{page.PREFIX}/{{token}}/projects", tags=["page"], include_in_schema=False)
async def page_connect_project(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """Register a project from the page. Item 206, DR-0022.

    **The same function the terminal calls.** `cli.add_project` reads `hullwork.yml` from the
    default branch with the receiver's own credential — *issue write and content read*, which is
    exactly what that takes — validates it, and mints the webhook token. A route that registered a
    project its own way would drift from the command, and items 193, 194, 200 and 203 each cost a
    day to that.

    The guards are the ones every write route here already has: a session or `404`, a matching CSRF
    pair or `403`. Nothing new is trusted.
    """
    from hullwork import cli

    _may_read(session, request, token)
    expected = operator.acting(session, request.cookies.get(operator.COOKIE))
    if expected is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    if not operator.csrf_ok(expected, await _field(request, "csrf")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Forbidden")

    asked = {name: (await _field(request, name) or "") for name in ("slug", "repo", "forge")}
    try:
        made = cli.add_project(
            session,
            settings,
            slug=asked["slug"],
            forge_kind=asked["forge"] or "forgejo",
            repo=asked["repo"],
        )
    except Exception as exc:  # every refusal already carries its own sentence
        # **The command's own words, not a generic failure.** A manifest that does not parse, a
        # repository the token cannot read and a slug already taken are the three things a person
        # gets wrong, and each has a sentence written for it — showing "something went wrong" here
        # would send them to the shell to find out what this page already knew.
        session.rollback()
        shown = page.projects(
            session, settings, acting=_acting(session, request), refused=str(exc)
        )
        return HTMLResponse(shown, headers=page.HEADERS)
    shown = page.projects(
        session, settings, acting=_acting(session, request), just_made=made
    )
    return HTMLResponse(shown, headers=page.HEADERS)


@app.post(
    f"{page.PREFIX}/{{token}}/projects/{{slug}}/{{feature}}", tags=["page"], include_in_schema=False
)
async def page_project_action(
    token: str,
    slug: str,
    feature: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """The rest of a project's life, from its own page. Item 207, DR-0022.

    **One route with an action rather than four routes.** The guard that keeps the write surface
    readable is a list a person reads, and four names for one page's worth of buttons is how a list
    stops being read. Each action calls what the terminal calls; none of them is implemented here.

    **No default branch.** An action nobody recognises does nothing and says so — a form field that
    fell through to whichever branch was last is how a typo becomes a disabled project.

    **`feature` names the document that comes back, and nothing else** (item 250). A `POST` answers
    at the URL its form posted to, and every relative link in that answer resolves against that URL
    — so the document has to be the one that URL serves. This route used to be `projects/<slug>`
    and answered three of its four branches with a document written for somewhere else: the list of
    projects on a refusal and on `rotate-secret`, the dependency view on `open-upgrade`. Eight of
    the page's thirty-five buttons came back with navigation that 404'd.

    It moved rather than five routes being added, so the write surface is the same size. `feature`
    is checked against the five views a project has, for the reason `_a_project_view` gives: an
    unknown one is the same `404` an unknown path gets.
    """
    from hullwork import cli

    if feature not in _THE_VIEWS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    _may_read(session, request, token)
    expected = operator.acting(session, request.cookies.get(operator.COOKIE))
    if expected is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    if not operator.csrf_ok(expected, await _field(request, "csrf")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Forbidden")

    what = await _field(request, "action")
    rotated: str | None = None
    swept: str | None = None
    try:
        # **Each of them says what it did** (item 223). Three completed in silence: a control that
        # appears to do nothing is a control somebody presses again, which on `refresh` is a second
        # forge request and on `disable` is a moment of wondering whether the first one worked.
        if what == "disable-preview":
            # **The second control here that quietly changes what the instance does** (item 226).
            # It deletes nothing, which is what made it feel safe to put beside `refresh` — and
            # then there was no way back, so reversible in principle was irreversible in practice.
            swept = (
                f"Stopping means no error from '{slug}' becomes an item, no issue is filed for it, "
                f"and the sweep skips it. Nothing is deleted, and watching it again is one button."
            )
        elif what == "enable":
            watched = cli.enable_project(session, slug)
            swept = (
                f"Watching '{watched.slug}' again. Nothing was re-validated: its manifest, its "
                f"secret and every item are where they were."
            )
        elif what == "disable":
            stopped = cli.disable_project(session, slug)
            swept = (
                f"'{stopped.slug}' is no longer watched. Nothing was deleted — its items, "
                f"fingerprints and issue references are all still here, and connecting it again "
                f"picks them up."
            )
        elif what == "refresh":
            cli.refresh_manifest(session, settings, slug)
            swept = f"Read {slug}'s manifest again from its repository. It validates."
        elif what == "set-tracker":
            named = cli.set_tracker(session, slug, await _field(request, "tracker_project"))
            swept = (
                f"'{named.slug}' is {named.tracker_project!r} in the tracker."
                if named.tracker_project
                else f"'{named.slug}' has no name in the tracker now, so nothing sweeps it."
            )
        elif what == "open-upgrade":
            # **The button DR-0026 always described** (item 245). It opens nothing here: this
            # process refuses to hold a credential that can push, so what this does is write down
            # that a person asked, and the dispatcher acts on it. The sentence says so.
            asked = await _field(request, "verdict")
            if asked is None or not asked.isdigit():
                raise ValueError(
                    f"{asked!r} is not a verdict this page offered. Nothing was asked for."
                )
            swept = cli.ask_to_open(session, slug, int(asked))
        elif what == "rotate-secret":
            rotated = cli.rotate_secret(session, slug)
        elif what in ("sweep", "sweep-confirm"):
            swept = _sweep_one(session, settings, slug, confirm=what == "sweep-confirm")
        elif what == "propose":
            # **In a `pre`, because the whole value of it is copying it** (item 223). A `<p>`
            # collapses newlines, and forty-one lines of YAML arrived as one run-on blob.
            swept = page.as_a_block(_propose_one(session, settings, slug))
        elif what == "lanes":
            swept = _lanes_of(session, settings, slug)
        else:
            raise ValueError(
                f"{what!r} is not something this page does. Nothing was changed."
            )
    except Exception as exc:  # every refusal already carries its own sentence
        session.rollback()
        # **The view they were on, carrying the reason** (item 250). This answered with the list of
        # projects, rendered at this project's URL — so a forge that had just gone down was
        # reported on a page whose every link 404'd. The refusal is the common path here, not the
        # exotic one.
        return _a_project_view(
            _THE_VIEWS[feature], session, settings, slug, _acting(session, request),
            refused=str(exc),
        )

    # **The document for the URL this posted to**, which is the view the button is on. Answering
    # with any other one leaves the URL saying one view and the body showing another, and — because
    # every link here is relative on purpose — resolves all of them from the wrong depth.
    return _a_project_view(
        _THE_VIEWS[feature], session, settings, slug, _acting(session, request),
        said=swept,
        # **The whole token, not `rotated[1]`** (item 250). This passed `(slug, rotated[1])` into a
        # parameter typed `tuple[str, str | None]`, and `rotated` is the token itself — so the one
        # answer in this product that can never be repeated printed **a single character of it**
        # and type-checked. Only the hash is kept, so the secret was gone: the button stopped the
        # tracker's working URL and gave nothing back to replace it with.
        **({"rotated": (slug, rotated)} if rotated is not None else {}),
    )


def _propose_one(session: Session, settings: Settings, slug: str) -> str:
    """A manifest read from the repository's own CI configuration. Item 107, on the page (item 222).

    **It prints and does not write**, here as in the terminal: a manifest belongs in the project's
    repository, committed by somebody who read it, and DR-0006's rule that what was inferred stays
    commented only means anything if a person is the one who uncomments it.

    One forge read, when a person asks for it. Item 142 forbids a request per *render* — a reader
    refreshing would spend one each time — and says nothing about an action somebody pressed, which
    is the same shape `projects refresh` has had since item 206.
    """
    from hullwork.cli import _forge_for, propose_from_ci
    from hullwork.models import Project as ProjectRow

    project = session.scalars(select(ProjectRow).where(ProjectRow.slug == slug)).one_or_none()
    if project is None:
        raise ValueError(f"no project called {slug!r}.")
    forge = _forge_for(settings, project.forge)
    try:
        proposed = propose_from_ci(forge, project.repo)
    finally:
        forge.close()
    if proposed is None:
        raise ValueError(
            f"nothing in {project.repo} proposes a manifest: no CI configuration was found, or "
            f"the one there says nothing this reader recognises. That is not a refusal to connect "
            f"the project — it means the manifest has to be written by hand, and the field that "
            f"decides whether anything can be built is `runtime.base`: an image your tests already "
            f"run in."
        )
    return proposed


def _lanes_of(session: Session, settings: Settings, slug: str) -> str:
    """The lane policy, applied to this repository's own directories. M8, item 104, on the page.

    **An operator who cannot see the policy applied to their code is being asked to trust a
    paragraph**, and this product's first principle is that trust is the product.

    Read-only and stores nothing, deliberately: a derived policy kept on disk would be a snapshot of
    *which code is dangerous*, and `territory.py` explains why that fails in the direction that
    matters. So this is an action and never a cache.
    """
    from hullwork import territory
    from hullwork.cli import _forge_for
    from hullwork.models import Project as ProjectRow

    project = session.scalars(select(ProjectRow).where(ProjectRow.slug == slug)).one_or_none()
    if project is None:
        raise ValueError(f"no project called {slug!r}.")
    forge = _forge_for(settings, project.forge)
    try:
        listing = forge.tree(project.repo)
    except Exception as exc:
        raise ValueError(f"could not read the tree of {project.repo}: {exc}") from exc
    finally:
        forge.close()

    claimed = territory.sensitive_tree(list(listing.paths))
    said = [
        f"{project.repo} at {listing.ref[:12]} — {len(listing.paths)} file(s), "
        f"{len(claimed)} that this instance keeps a human on."
    ]
    if listing.truncated:
        said.append(
            "The forge did not serve the whole tree, so this list is incomplete — what is missing "
            "is unclassified here, not classified as ordinary."
        )
    by_rule: dict[str, list[str]] = {}
    for path, rule in claimed:
        by_rule.setdefault(rule.pattern, []).append(path)
    for pattern, paths in by_rule.items():
        said.append(f"`{pattern}` — {len(paths)} file(s): {', '.join(sorted(paths)[:4])}")
    return " · ".join(said)


def _sweep_one(session: Session, settings: Settings, slug: str, *, confirm: bool) -> str:
    """Read the tracker's unresolved list for one project. DR-0011, item 219.

    **The count comes before the writing and the number you confirm is the number you were shown.**
    A project with three hundred open issues becomes three hundred forge issues in one pass, and a
    tool that does that on a first afternoon is uninstalled that evening — which is the whole reason
    `sweep` has a `--confirm` in the terminal. On a page that is two submissions, and computing the
    preview from a different query than the write would let them disagree.
    """
    inventory = make_inventory(settings)
    if inventory is None:
        raise ValueError(
            "no tracker inventory is configured. It needs HULLWORK_TRACKER_URL, "
            "HULLWORK_TRACKER_TOKEN and HULLWORK_TRACKER_ORG — the organisation cannot be "
            "discovered, because the least-privilege token is refused the route that would list it."
        )
    results = sweep_inventory(
        session, inventory, slug=slug, first_pass=True, dry_run=not confirm
    )
    if not results:
        return f"'{slug}' has no tracker project set, so there is nothing to sweep."

    said = []
    for result in results:
        if result.error:
            said.append(f"{result.project}: could not read the tracker — {result.error}")
        elif confirm:
            said.append(
                f"{result.project}: filed {result.created} issue(s); "
                f"{result.deduplicated} were already known."
            )
        else:
            said.append(
                f"{result.project}: {result.created} issue(s) would be filed and "
                f"{result.deduplicated} are already known. Nothing was written."
            )
    return " · ".join(said)


@app.post(
    f"{page.PREFIX}/{{token}}/instance",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def page_instance_action(
    token: str,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """The instance's own housekeeping, from its own view. Item 219, item 218 §1.

    **One route with an action rather than three names**, which is item 207's rule applied to the
    second noun that needed one. Each action calls what the terminal calls; none is implemented
    here.

    **`prune` is the only destructive control on this page**, so it has two submissions and the
    first one writes nothing: `prune-preview` says how many bodies it would clear, and the number a
    person confirms is the number they were just shown.
    """
    from hullwork import cli

    acting = _the_operators(session, request, token)
    if not operator.csrf_ok(
        operator.acting(session, request.cookies.get(operator.COOKIE)),
        await _field(request, "csrf"),
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Forbidden")

    what = await _field(request, "action")
    said: str | None = None
    try:
        if what == "lease-release":
            said = cli.release_lease(session)
        elif what == "prune-preview":
            days = _days(await _field(request, "older_than_days"))
            said = (
                f"{cli.prune(session, days, dry_run=True)} delivery body(s) and fetched event(s) "
                f"older than {days} days would be cleared. Every row, fingerprint and issue "
                f"reference stays. Nothing has been cleared yet."
            )
            session.rollback()
        elif what == "prune":
            days = _days(await _field(request, "older_than_days"))
            said = (
                f"Cleared {cli.prune(session, days)} delivery body(s) older than {days} days. "
                f"Every row, fingerprint and issue reference is intact."
            )
        elif what == "republish":
            said = _republish_all(session, settings)
        elif what == "page-token":
            # **The read link, re-keyed from the page** (DR-0025, item 229). Strictly less than what
            # this session already does: it revokes a URL rather than granting anything. The
            # password is the other half of that decision and is deliberately not here.
            from hullwork.security import generate_token, hash_token

            minted = generate_token()
            page.issue(session, hash_token(minted))
            # **Including the page this answer is on, when it is one of them** (item 250). Read at
            # a minted URL, this button revokes the URL the answer is served from: every link on
            # the page that comes back is correctly written and every one of them answers `404`.
            # Read through a session it is not the token that opens the door, so nothing here
            # breaks — and saying so unconditionally would be false half the time.
            here_too = (
                " That includes the URL you are reading this on, so every link on this page "
                "answers 404 now: open the one above."
                if page.the_url_is_the_credential(token)
                else ""
            )
            said = page.as_a_block(
                f"{settings.base_url.rstrip('/')}{page.PREFIX}/{minted}/\n\n"
                f"This URL is the credential and it is shown once — only its hash is kept, so no "
                f"later view can print it again. Every URL handed out before this moment has "
                f"stopped working.{here_too}"
            )
        else:
            raise ValueError(f"{what!r} is not something this page does. Nothing was changed.")
    except Exception as exc:  # every refusal already carries its own sentence
        session.rollback()
        said = str(exc)
    else:
        session.commit()

    return HTMLResponse(
        page.instance(
            session,
            settings,
            error_reporting=_reporting_enabled,
            acting=acting,
            said=said,
        ),
        headers=page.HEADERS,
    )


def _days(raw: str | None) -> int:
    """The retention window, refused rather than defaulted when it is not a number.

    A blank field becoming `0` would clear everything, which is the one mistake this control must
    not make quietly.
    """
    try:
        days = int(raw or "")
    except (TypeError, ValueError):
        raise ValueError(f"{raw!r} is not a number of days. Nothing was changed.") from None
    if days < 1:
        raise ValueError("the window has to be at least one day. Nothing was changed.")
    return days


def _republish_all(session: Session, settings: Settings) -> str:
    """Finish every verdict the dispatcher reached and could not send. Item 077, on the page.

    The receiver has the forge credential this needs and provably not the one that can push, so a
    `pr-open` verdict is refused here exactly as it is refused in the terminal: it needs the files
    the agent wrote and nothing stores them (item 079).
    """
    from hullwork import work as work_module
    from hullwork.cli import _redactions
    from hullwork.models import Item as ItemRow
    from hullwork.models import Project as ProjectRow

    stranded = work_module.unpublished_verdicts(session)
    if not stranded:
        return "No verdict is waiting to be published."

    forge = make_forge(settings)
    done: list[str] = []
    try:
        for attempt in stranded:
            item = session.get(ItemRow, attempt.item_id)
            project = session.get(ProjectRow, item.project_id) if item else None
            if project is None:  # pragma: no cover - a foreign key makes this unreachable
                continue
            try:
                where = work_module.republish(
                    session,
                    attempt,
                    forge=forge,
                    repo=project.repo,
                    secrets=_redactions(settings),
                )
            except work_module.PublicationError as exc:
                done.append(f"attempt {attempt.id}: {exc}")
                continue
            done.append(f"attempt {attempt.id}: published to {project.repo}{where}")
    finally:
        if forge is not None:
            forge.close()
    return " · ".join(done)


@app.post(
    f"{page.PREFIX}/{{token}}/items/{{item_id}}",
    tags=["page"],
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def page_item_action(
    token: str,
    item_id: int,
    request: Request,
    session: Annotated[Session, Depends(_readiness_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """What an operator does to one item that is not a decision about it. Item 219.

    The two decisions — approve, human-only — keep their own routes: they are the product's gate and
    they are pressed by somebody who may be reading nothing else. This is the housekeeping beside
    them, and it takes an action field for item 207's reason.
    """
    from hullwork import cli
    from hullwork.models import Item as ItemRow
    from hullwork.models import Project as ProjectRow

    acting = _the_operators(session, request, token)
    if not operator.csrf_ok(
        operator.acting(session, request.cookies.get(operator.COOKIE)),
        await _field(request, "csrf"),
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Forbidden")

    found = session.get(ItemRow, item_id)
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")

    what = await _field(request, "action")
    said: str | None = None
    try:
        if what == "requeue":
            project = session.get(ProjectRow, found.project_id)
            back = cli.requeue(session, project.slug if project else "", item_id)
            said = (
                f"Item {back.id} ({back.lane.value}) is now '{back.state.value}'. Its attempt was "
                f"never spent, so it still has one."
            )
        else:
            raise ValueError(f"{what!r} is not something this page does. Nothing was changed.")
    except Exception as exc:  # every refusal already carries its own sentence
        session.rollback()
        said = str(exc)
    else:
        session.commit()

    shown = page.item(session, settings, item_id, acting=acting, said=said)
    if shown is None:  # pragma: no cover - it existed a line ago
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    return HTMLResponse(shown, headers=page.HEADERS)

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
    _may_read(session, request, token)
    cookie = request.cookies.get(operator.COOKIE)
    if operator.csrf_ok(operator.acting(session, cookie), await _field(request, "csrf")):
        operator.log_out(session, cookie)
    redirect = _to_page(token)
    redirect.delete_cookie(operator.COOKIE, path=page.PREFIX)
    return redirect


def _decide(
    token: str,
    request: Request,
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
    _may_read(session, request, token)

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
    return _decide(token, request, item_id, session, await _field(request, "csrf"), "approve",
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
    return _decide(token, request, item_id, session, await _field(request, "csrf"), "human",
                   cookie=request.cookies.get(operator.COOKIE))
