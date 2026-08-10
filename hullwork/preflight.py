"""What is wrong before anything is built. Item 199.

Item 198 measured that `doctor` already answers twenty-six checks against an in-memory session, with
no instance in existence — so the guidance was there and arrived one `docker compose up --build` too
late. Two things stood between it and the operator, and this module is both of them.

**One: a session, without a deployment.** `doctor.examine` takes one, `init` deliberately opens
none, and nobody had noticed that an in-memory engine satisfies both — a real database file would be
created in whatever directory the operator is standing in, which is the trap item 115 exists for.

**Two: reachability, which existed nowhere.** `doctor` touches no network in any check. It reports
`ok` for `https://forge.example.com`, an address that does not resolve, because the question it asks
is *which forge is this configured for*. That is right for what it is, and it is why a pre-flight
built only from it would send somebody to `projects add` to discover their token is wrong.

The three states are the whole discipline here. *Reached it and it was fine*, *reached it and it is
wrong*, and **could not reach it** are three different facts, and collapsing the third into either
of the others is item 073's permanently-on signal in the first output a stranger ever sees.
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from hullwork import credentials
from hullwork.config import Settings
from hullwork.db import make_engine, make_session_factory
from hullwork.doctor import Finding, State
from hullwork.doctor import examine as _examine_an_instance
from hullwork.scaffold import Answers

#: Long enough for a forge behind a slow link, short enough that a pre-flight run on a laptop with
#: no route out is over before anybody reaches for the interrupt.
TIMEOUT_SECONDS = 5.0

#: A repository nobody has: the token probe needs one, and the interesting answers — 401, 403, and
#: *this token cannot write code* — do not depend on it existing. Asking about a real repository
#: would make the result depend on which one, which is a question this command has no way to ask.
_ANY_REPOSITORY = "hullwork/preflight"


def _answers(url: str, timeout: float = TIMEOUT_SECONDS) -> bool | None:
    """Whether the host at `url` accepts a connection. `None` means the question could not be put.

    Deliberately a socket rather than an HTTP request: this asks *is there something there*, and a
    forge that answers `404` to an unauthenticated `GET /` is answering. Anything HTTP-shaped would
    mix reachability with a second question that has its own check below.
    """
    parsed = urlparse(url)
    if not parsed.hostname:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((parsed.hostname, port), timeout=timeout):
            return True
    except (TimeoutError, OSError):
        return None


def _may_push(url: str, token: str, repo: str, declared: str | None) -> bool | None:
    """What the **token** may do, or `None` when the forge would not say.

    Item 073's probe, reused rather than rewritten.
    """
    try:
        return credentials.token_may_write_code(url, token, repo, declared_kind=declared)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def _reachability(settings: Settings) -> list[Finding]:
    """The layer `doctor` does not have. **Absent rather than guessed** when nothing is configured.

    A row reading `unknown` about a forge nobody named would be noise dressed as rigour, and this is
    the command somebody runs before they have configured anything at all.
    """
    found: list[Finding] = []
    if not settings.forge_url:
        return found

    reached = _answers(settings.forge_url)
    if reached:
        found.append(Finding("forge answers", State.OK, "the host accepted a connection."))
    else:
        found.append(
            Finding(
                "forge answers",
                State.UNKNOWN,
                "could not reach it from here. That is a fact about this machine as much as about "
                "the forge — a VPN, a private address, or a name this host does not resolve — so "
                "it is not counted against you. Run this again from where the instance will live.",
            )
        )

    if not settings.forge_token:
        return found

    # **Only when the host answered.** Asking a token question of an unreachable host produces a
    # network failure dressed as an authorisation answer, which is the collapse this module exists
    # to refuse.
    if not reached:
        found.append(
            Finding(
                "forge token",
                State.UNKNOWN,
                "not asked: the forge did not answer, so nothing here knows what it may do.",
            )
        )
        return found

    may = _may_push(
        settings.forge_url,
        settings.forge_token.get_secret_value(),
        _ANY_REPOSITORY,
        settings.forge_kind,
    )
    if may is None:
        found.append(
            Finding(
                "forge token",
                State.UNKNOWN,
                "the forge answered but would not say what this token may do. Nothing is claimed "
                "about it either way.",
            )
        )
    elif may:
        found.append(
            Finding(
                "forge token",
                State.BROKEN,
                "this token can push code. The always-on service must not hold one that can — "
                "issue write and content read is the whole of what it needs, and DR-0005 splits "
                "them so that a compromise of the receiver cannot reach your branches.",
            )
        )
    else:
        found.append(
            Finding(
                "forge token", State.OK, "accepted, and it cannot push code. That is the shape."
            )
        )
    return found


def _what_the_file_is_missing(answers: Answers | None, text: str | None) -> list[Finding]:
    """The capability question, in the same listing as everything else. Item 200.

    `scaffold.what_is_still_needed` is where a variable's consequence is written, and it stays the
    only place: this reads it and gives each line a `Finding` so one report can hold *this variable
    is empty and here is what it buys* beside *the forge answered*. Two sections repeating each
    other is how the two answers drifted apart in the first place.
    """
    if answers is None or text is None:
        return []
    from hullwork.scaffold import what_is_still_needed

    said: list[Finding] = []
    capability = ""
    for line in what_is_still_needed(answers, text):
        if not line.startswith("  "):
            capability = line.rstrip(":").removeprefix("For ")
            continue
        name, _, why = line.strip().partition(" — ")
        said.append(Finding(name, State.BROKEN, f"{why} Needed for: {capability}."))
    return said


def examine(
    settings: Settings,
    *,
    answers: Answers | None = None,
    environment_file: Path | None = None,
) -> list[Finding]:
    """Every check `doctor` makes, before there is anything to make them against, plus reachability.

    The database check is rewritten rather than dropped: there being no schema is the **expected**
    state of a pre-flight, and `State.EXPECTED` exists for exactly this — a gap that is real,
    deliberate, and must not be closed. Leaving it `broken` would put a red herring on the first
    line and teach the reader to skim the rest.
    """
    # **The real file when there is one** (item 200). `_NOWHERE` is a sentinel and it was reaching
    # the operator: the `deployment` check named `/nonexistent/preflight/.env` in its own output,
    # which is a path nobody has and an instruction nobody can follow. `init` knows where the file
    # it just wrote lives, so it says so.
    factory = make_session_factory(make_engine("sqlite:///:memory:"))
    with factory() as session:
        found = _examine_an_instance(
            session,
            settings,
            code_forge=None,
            env_file=environment_file or _NOWHERE,
            compose_file=None,
            before_there_is_an_instance=True,
        )
    text = None
    if environment_file is not None and environment_file.exists():
        text = environment_file.read_text(encoding="utf-8")
    return [
        *found,
        *_what_the_file_is_missing(answers, text),
        *_reachability(settings),
    ]


def exit_code(found: list[Finding]) -> int:
    """`1` when something is broken, and **never for an `unknown`** (item 073).

    A warning wired into an exit code with no action available to clear it is not a signal. The
    likeliest `unknown` here is a laptop that cannot reach the forge it is configuring, and failing
    somebody's install script over a fact about their laptop is how a check gets ignored for ever.
    """
    return 1 if any(one.state is State.BROKEN for one in found) else 0


#: `environment_gaps` wants a path; there is no deployment file to compare against yet, and a path
#: that does not exist is the honest input — the check itself reports *not checked* for it, which is
#: the right answer here and the one item 194 made sure it gives.
_NOWHERE = __import__("pathlib").Path("/nonexistent/preflight/.env")
