"""What may leave somebody else's machine on its way to us. Item 151.

**There is no destination in this file, and there may never be one** (item 152). The published
image carries one, baked in by the release workflow from a repository secret; a build made from a
checkout has nowhere to send anything, which is a property of this repository rather than a promise
about our intentions — `test_no_destination_is_hidden_in_the_source_tree` checks it by reading.
`HULLWORK_TELEMETRY=off` declines in any build.

## The distinction the rest of this file exists to hold

`HULLWORK_ERROR_DSN` sends Hullwork's own failures to a tracker **the operator chose**, and the
whole event goes: message, locals, request, the lot, scrubbed by `telemetry.scrub` on the way out.
That is right, because everything in it belongs to the person receiving it.

Upstream is the other direction. The error is ours; the context is theirs. Measured on a real event
captured through the product's own `before_send` — a crash raised while processing a fabricated
customer payload, **4,826 bytes** — and all six of these were in it:

| in the event | where it came from |
|---|---|
| a customer's email address | a frame local |
| their repository, `owner/name` | the interpolated exception message |
| their tracker's hostname | the same message |
| an item title naming their module | a frame local |
| the text of their `hullwork.yml` | a frame local |
| their machine's hostname | `server_name` |

`send_default_pii=False` was already set and stops none of it: `include_local_variables` defaults to
`True`, and a URL is not personal data as far as the SDK is concerned.

## Construct, never filter

A filter is a blacklist and every blacklist leaks. This repository has the receipts — `scrub`'s own
docstring is about a leak nobody predicted, found by pointing the thing at itself and reading the
tracker's database afterwards. So the payload here is **built out of an enumerated set of fields**
and cannot contain anything else: a future SDK version that adds a field adds it to an event this
module does not read. The same crash, constructed, is **339 bytes**.

The signature survives the cut, which is the point. A crash inside `hullwork/` still arrives as
`ManifestError` at `hullwork.manifest.parse_manifest:707` — what breaks, and where in our code, on
a machine we will never see. Dropping `vars` is what cuts the size; keeping
`module`/`function`/`lineno` is what keeps it useful.

**No message.** It is where the diagnosis lives and where the leakage lives, and it is ours only
until the first `f"...{project.slug}..."`. If type-plus-frame proves too thin, the next step is a
code per raise site — a number we control — and not redaction, which is the blacklist again.

**No module list.** The SDK sends every installed dependency with its version: useful to us, and a
fingerprint of somebody's environment. Python's own version is enough to tell a `3.11` bug from a
`3.13` one.

**No release string from the event.** `HULLWORK_RELEASE` is operator-supplied text — a fork's branch
name, an internal build number — so the version reported upstream is read from this package. The
consequence is stated rather than hidden: a patched fork reports the version it forked from.
"""

from __future__ import annotations

import json
import logging
import platform
import re
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from hullwork import __version__

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

# **Nothing heavy at module scope, and that is load-bearing** (item 154). The relay that receives
# these payloads imports `why_not_a_payload` from here to enforce the same enumeration, and it runs
# on the public interface — so it installs this package with `--no-deps` and must not need an ORM to
# check the shape of a dict. `installation_id` and `census` import theirs where they use them.

log = logging.getLogger(__name__)

#: The payload's shape, so a relay can refuse one it does not know (item 154) instead of storing
#: something it cannot read. Bumped when a key is added or removed, never for a value's meaning.
SCHEMA = 1

#: **The enumerated set.** Equality against this is a test, not a comment: a key that appears in a
#: payload and not here is a leak, and a key here that no payload carries is a lie.
KEYS = frozenset(
    {"schema", "exception", "frames", "release", "python", "platform", "operation",
     "installation", "counts"}
)

#: Everything a frame is allowed to be. `abs_path` and `filename` are deliberately absent: a path is
#: `/Users/ana/src/…` often enough that it identifies a person, and a module name never is.
FRAME_KEYS = frozenset({"module", "function", "lineno"})

#: What is being counted, and the four are the whole of it. Sizes, not contents.
COUNT_KEYS = frozenset({"projects", "items", "attempts", "outcomes"})

#: Which of the two programs, or which subcommand. A coarse answer to *where in Hullwork's life did
#: this happen*, which turns out to matter more than the stack: a crash in `init` is somebody who
#: never got started, and a crash in `work` is somebody who did.
#:
#: A whitelist rather than a pattern, because a pattern accepts whatever a future caller
#: interpolates into it. `test_every_subcommand_the_parser_accepts_has_an_operation` stops drift.
OPERATIONS = frozenset(
    {"receiver", "dispatcher", "gateway"}
    | {
        f"cli:{name}"
        for name in (
            "approve", "config", "doctor", "gateway", "init", "lease",
            "page-token", "password", "projects", "propose", "prune", "republish",
            "requeue", "status", "sweep", "try", "work",
        )
    }
)

#: What an operation that is not on the list becomes. Not an exception: refusing to report a crash
#: because the label for it was wrong would lose the crash to protect the label.
UNKNOWN = "unknown"

#: The package prefix a frame has to be inside to travel. `hullwork` and `hullwork.*`, and nothing
#: that merely starts with the letters — `hullworkish.plugin` is somebody else's code.
OURS = "hullwork"

#: How many of our frames travel. Twenty is far past the deepest raise site in this codebase and
#: still bounds the payload: an unbounded list is an unbounded upload, on somebody else's bandwidth.
FRAME_CEILING = 20

#: What an installation identifier looks like: `secrets.token_hex(16)` and nothing else.
_HEX_32 = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True)
class Instance:
    """What an installation is willing to say about itself, gathered by its caller.

    Not read out of the event, and not read out of the environment here: every field is passed in by
    whoever builds the payload, so this module has no way to learn anything it was not handed.
    """

    #: From `installation_id`. The only field that identifies anything, and `None` is allowed: a
    #: crash before the database is reachable — the first run, a broken volume, a failed migration —
    #: is the one most worth having, and it arrives uncounted rather than not at all.
    installation: str | None
    #: One of `OPERATIONS`, or anything else — which becomes `UNKNOWN` rather than an error.
    operation: str
    projects: int = 0
    items: int = 0
    attempts: int = 0
    outcomes: int = 0


def installation_id(session: Session, *, mint: bool = True) -> str | None:
    """Read this installation's name, minting one the first time anybody asks.

    Written on first use rather than at migration time, so an upgrade enrols nobody and a deployment
    that never reports never acquires one.

    **`mint=False` is for looking.** `hullwork config --telemetry` exists so somebody can decide
    whether to allow this, and creating the row that identifies them at the moment they ask *what
    would be sent* would be enrolling them for the act of checking. So inspecting reads, and only
    reporting writes.

    Two processes can ask at once — the receiver and the dispatcher share one database and start
    together under compose — so the insert races. Losing the race is not an error: the winner's row
    is the answer, which is why this re-reads instead of retrying.
    """
    from sqlalchemy.exc import IntegrityError

    from hullwork.models import Installation

    row = session.get(Installation, 1)
    if row is not None:
        return row.identifier
    if not mint:
        return None

    session.add(Installation(id=1, identifier=secrets.token_hex(16)))
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        row = session.get(Installation, 1)
        if row is None:  # pragma: no cover - the insert failed for a reason that was not the race
            raise
        return row.identifier

    row = session.get(Installation, 1)
    assert row is not None  # noqa: S101 - just committed it in this session
    return row.identifier


def census(session: Session) -> dict[str, int]:
    """How much this installation holds. Four numbers, no names.

    **Why sizes are worth sending at all**: a crash at 40,000 items and the same crash at 3 are
    usually different defects, and the second is somebody's first afternoon. Without them every
    report reads as if it came from an empty instance.

    Four `COUNT(*)`s, read once per process at the first report — not per event. On Postgres a count
    is a scan, so *once* is the part that matters; an instance where four counts are slow is an
    instance whose crash we want to hear about anyway.
    """
    from sqlalchemy import func, select

    from hullwork.models import Attempt, Item, Project

    return {
        "projects": int(session.scalar(select(func.count()).select_from(Project)) or 0),
        "items": int(session.scalar(select(func.count()).select_from(Item)) or 0),
        "attempts": int(session.scalar(select(func.count()).select_from(Attempt)) or 0),
        # Attempts that reached a verdict, which is the number that says whether this instance is
        # *working* rather than merely installed.
        "outcomes": int(
            session.scalar(
                select(func.count()).select_from(Attempt).where(Attempt.outcome.is_not(None))
            )
            or 0
        ),
    }


def event_for_a_crash_here(exception: BaseException) -> dict[str, Any]:
    """An SDK-shaped event for a real exception, without the SDK.

    For `hullwork config --telemetry`, which has to print **the payload this instance would send**
    rather than an example somebody typed. The frames come from the live traceback, so what is shown
    is what the machinery would actually read.

    `module` from the frame's own globals, exactly as the SDK derives it — and a frame that cannot
    say which module it is gets `None` here, so `_ours` drops it there.
    """
    frames: list[dict[str, Any]] = []
    traceback = exception.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        frames.append(
            {
                "module": frame.f_globals.get("__name__"),
                "function": frame.f_code.co_name,
                "lineno": traceback.tb_lineno,
            }
        )
        traceback = traceback.tb_next

    return {
        "exception": {
            "values": [
                {
                    "type": type(exception).__name__,
                    "value": str(exception),
                    "stacktrace": {"frames": frames},
                }
            ]
        }
    }


def _ours(frames: Any) -> list[dict[str, Any]]:  # noqa: ANN401 - events are arbitrary
    """Our frames, as three fields each, oldest first.

    **A frame that will not say which module it is does not travel.** The SDK fills `module` from
    the import path and `abs_path` from the file, and only one of those is safe: dropping a frame
    with no `module` costs a line of a stack trace, while falling back to a path would put
    somebody's home directory in the payload the first time a zipimport confused the SDK.
    """
    kept: list[dict[str, Any]] = []
    if not isinstance(frames, list):
        return kept

    for frame in frames:
        if not isinstance(frame, Mapping):
            continue
        module = frame.get("module")
        if not isinstance(module, str):
            continue
        if module != OURS and not module.startswith(f"{OURS}."):
            continue
        lineno = frame.get("lineno")
        function = frame.get("function")
        kept.append(
            {
                "module": module,
                "function": function if isinstance(function, str) else None,
                "lineno": lineno if isinstance(lineno, int) else None,
            }
        )
    return kept[-FRAME_CEILING:]


def upstream_payload(event: Mapping[str, Any], instance: Instance) -> dict[str, Any] | None:
    """Build what may travel, or answer `None` when nothing may.

    `None` in two cases, and both are refusals rather than failures:

    * **the event has no exception** — a `log.error` becomes an event whose only content is its
      message, and the message is the one field that cannot travel. There is no code for it yet, so
      there is nothing to say;
    * **no frame is ours** — a crash entirely inside somebody's tracker client, or their code
      calling us wrongly, is not our defect and not ours to collect.

    The second is the more important one. It is the difference between reporting Hullwork's failures
    and reporting failures near Hullwork.
    """
    values = (event.get("exception") or {}).get("values")
    if not isinstance(values, list) or not values:
        return None

    last = values[-1] if isinstance(values[-1], Mapping) else {}
    kind = last.get("type")
    if not isinstance(kind, str) or not kind:
        return None

    frames: list[dict[str, Any]] = []
    for value in values:
        if isinstance(value, Mapping):
            frames.extend(_ours((value.get("stacktrace") or {}).get("frames")))
    if not frames:
        return None

    operation = instance.operation if instance.operation in OPERATIONS else UNKNOWN

    return {
        "schema": SCHEMA,
        # The class name only. `str(exc)` is the message and lives on the other side of the line.
        "exception": kind,
        "frames": frames[-FRAME_CEILING:],
        "release": __version__,
        # `3.12.7`, not `sys.version`, which carries the compiler and the build date of whoever
        # built the interpreter — a fingerprint of a distribution, for no diagnostic gain.
        "python": platform.python_version(),
        # `linux` or `darwin`. Not `platform.uname()`, whose `node` is the hostname.
        "platform": sys.platform,
        "operation": operation,
        "installation": instance.installation,
        # Sizes, so a crash at 40,000 items reads differently from one at 3. Never names.
        "counts": {
            "projects": max(0, instance.projects),
            "items": max(0, instance.items),
            "attempts": max(0, instance.attempts),
            "outcomes": max(0, instance.outcomes),
        },
    }


# --------------------------------------------------------------------------------------------
# Where it goes. Item 152: the destination lives in the artefact, not in this file.
# --------------------------------------------------------------------------------------------

#: What `HULLWORK_TELEMETRY` may say to mean *no*. Generous on purpose: somebody switching this off
#: is declining, and a decline that does not take effect because they wrote `false` instead of `off`
#: is the worst outcome available here.
DECLINED = frozenset({"off", "0", "false", "no", "none", "disabled", ""})

#: How many upstream events one process may send. Lower than the operator's ceiling because these
#: leave somebody else's network and arrive at ours: a crash loop under `restart: unless-stopped`
#: would otherwise spend their bandwidth and our ingest on one sentence. Item 154 rate-limits the
#: other end too: a ceiling in the sender is a promise, and a limit in the receiver is a fact.
UPSTREAM_CEILING = 20


def destination(settings: Any) -> str | None:  # noqa: ANN401 - Settings, without the import cycle
    """The upstream DSN, or `None` when there is nowhere to send anything.

    `None` in three cases, and only the first is ours: no DSN was baked into this build (a checkout,
    a fork, our own CI and our own machines), the operator declined with `HULLWORK_TELEMETRY=off`,
    or they emptied the variable.
    """
    if str(getattr(settings, "telemetry", "on")).strip().lower() in DECLINED:
        return None
    dsn = getattr(settings, "upstream_dsn", None)
    if dsn is None:
        return None
    value = str(dsn.get_secret_value() if hasattr(dsn, "get_secret_value") else dsn).strip()
    return value or None


#: The longest any string in a payload may be. Every one of them is a class name, a module path, a
#: version or a hex identifier; nothing legitimate comes near this, and a sentence would.
STRING_CEILING = 200

#: **What each string field is shaped like, and a length ceiling is not enough.** Found by the test
#: that tries to smuggle a message: `"KeyError: 'currency' in acme.billing"` is forty characters, so
#: it passed a *"short string"* check while carrying a customer's module and an interpolated value.
#:
#: A class name has no spaces, no colons and no quotes; a version has no spaces; a platform is one
#: word. Each field is matched against the thing it is, and prose fails every one of them.
_SHAPES = {
    # `type(exc).__name__`, so a Python identifier, optionally dotted for a nested class.
    "exception": re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}(\.[A-Za-z_][A-Za-z0-9_]{0,62}){0,4}"),
    # A version from the package, or a commit sha if a fork's build says so.
    "release": re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}"),
    # `platform.python_version()`.
    "python": re.compile(r"\d{1,2}\.\d{1,2}\.\d{1,3}[a-z0-9+.]{0,12}"),
    # `sys.platform`: `linux`, `darwin`, `win32`.
    "platform": re.compile(r"[a-z][a-z0-9]{0,15}"),
    # Checked against `OPERATIONS` below as well; this only bounds what the check has to look at.
    "operation": re.compile(r"[a-z][a-z0-9:_-]{0,31}"),
}

#: What to call each of those in a refusal, because `_SHAPES` reads as noise in a message.
_WHAT_IT_IS = {
    "exception": "class name",
    "release": "version",
    "python": "Python version",
    "platform": "platform",
    "operation": "operation",
}


def why_not_a_payload(payload: object) -> str | None:
    """Why this is not a payload this project would have produced, or `None` if it is one.

    **The same enumeration, enforced twice** (item 154). `upstream_payload` builds the payload in
    the sender, and the sender is code strangers run and can edit — so the whitelist is checked
    again where events arrive. Without this, *"the payload cannot contain your data"* is a property
    of a client, and a hand-made envelope full of somebody's email addresses could be laundered
    through our ingest into our own tracker.

    Here rather than in the relay so there is **one** enumeration. Two copies of a whitelist are two
    whitelists, and the one nobody looks at is the one that drifts.

    Returns a reason rather than a bool: the relay counts drops by reason, and *"why did that get
    dropped"* is the question a counter has to answer to be worth keeping.
    """
    if not isinstance(payload, dict):
        return f"not an object: {type(payload).__name__}"
    if set(payload) != KEYS:
        unexpected = sorted(set(payload) - KEYS)
        missing = sorted(KEYS - set(payload))
        return f"keys do not match: unexpected {unexpected}, missing {missing}"
    if payload["schema"] != SCHEMA:
        return f"schema {payload['schema']!r} is not {SCHEMA}"

    for field, shape in _SHAPES.items():
        value = payload[field]
        if not isinstance(value, str) or not shape.fullmatch(value):
            return f"{field} is not shaped like a {_WHAT_IT_IS[field]}: {value!r:.60}"
    if payload["operation"] not in OPERATIONS and payload["operation"] != UNKNOWN:
        return f"operation {payload['operation']!r} is not one of ours"

    identifier = payload["installation"]
    if identifier is not None and (
        not isinstance(identifier, str) or not _HEX_32.fullmatch(identifier)
    ):
        return "installation is neither null nor 32 hexadecimal characters"

    frames = payload["frames"]
    if not isinstance(frames, list) or not frames or len(frames) > FRAME_CEILING:
        return f"frames is not a list of 1 to {FRAME_CEILING}"
    for frame in frames:
        if not isinstance(frame, dict) or set(frame) != FRAME_KEYS:
            return "a frame does not have exactly the three allowed keys"
        module = frame["module"]
        if not isinstance(module, str) or (module != OURS and not module.startswith(f"{OURS}.")):
            # The rule that makes this worth enforcing here: a frame from outside our package is
            # somebody else's code, and its module path is somebody else's business.
            return f"a frame is not inside {OURS}: {module!r}"
        if frame["function"] is not None and not isinstance(frame["function"], str):
            return "a frame's function is neither null nor a string"
        if frame["lineno"] is not None and not isinstance(frame["lineno"], int):
            return "a frame's lineno is neither null nor an integer"

    counts = payload["counts"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        return "counts does not have exactly the four allowed keys"
    for name, count in counts.items():
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            return f"counts.{name} is not a non-negative integer"

    return None


def notice(host: str) -> str:
    """What this build says about itself, before it says anything to us. Item 153.

    **On the terminal, and every start rather than the first one.** A container is recreated, not
    started once; a "first run" flag would need a row, and a row somebody has to trust is exactly
    the kind of claim this notice avoids making. Six lines on `stderr` per process is the price.

    **Printed before `sentry_sdk.init`**, so the ordering is structural rather than remembered: at
    the moment this returns, nothing has been armed that could send anything.

    The pattern that survives and the one that does not: Next.js, Homebrew and the .NET CLI report
    by default and are broadly accepted; Gatsby and Audacity did the same and were not. What
    differed was never the default. It is whether the terminal tells you *before* anything is sent,
    and whether one variable stops it — and this can go further than any of them, because the exact
    bytes are printable: `hullwork config --telemetry`.
    """
    return (
        f"\nThis build reports Hullwork's own crashes to {host}.\n"
        f"  What is sent: the exception class, Hullwork's own stack frames, this version, your\n"
        f"  Python version, a random identifier for this installation, and how many projects,\n"
        f"  items and attempts it holds. About 600 bytes.\n"
        f"  What is never sent: the error message, local variables, URLs, your hostname, your\n"
        f"  repository names, anything from the errors your own software reports.\n"
        f"  See it exactly: hullwork config --telemetry\n"
        f"  Stop it: HULLWORK_TELEMETRY=off\n"
        f"  An image you build yourself reports nowhere; the destination exists only in the\n"
        f"  published one. PRIVACY.md is the whole of it, and it is short.\n"
    )


def notice_line(host: str) -> str:
    """The notice, in one line, for a command rather than a service. Item 157.

    **Ten lines on every `hullwork status` would be the wrong kind of honest.** The two long-running
    programs start once and print the paragraph; a command runs in a loop, in a script, in a
    `watch`, and a disclosure nobody can scroll past becomes a disclosure nobody reads.

    So: where it goes, how to see exactly what, and how to stop it — which is the whole of what
    somebody needs in the moment, with the paragraph one command away.
    """
    return (
        f"reporting this command's own crashes to {host} "
        f"(see: hullwork config --telemetry · stop: HULLWORK_TELEMETRY=off)"
    )


def named_host(dsn: str) -> str:
    """The host a DSN points at, for `hullwork config` to print. **Never the key.**

    An operator is entitled to know where their instance talks to without being handed a credential
    to read out. The key is public and write-only, and printing it anyway would put it in every
    screenshot and support paste for no gain.
    """
    without_scheme = dsn.split("://", 1)[-1]
    authority = without_scheme.split("@")[-1]
    return authority.split("/")[0] or UNKNOWN


def as_event(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Render a constructed payload in the vocabulary a tracker groups by.

    Every value here comes from `payload`, which came from the enumerated set — so this is a
    translation and not a second chance to add anything. The exception's `value` is built from the
    type and the crash site rather than left empty: a tracker with a blank title is one nobody
    reads, and *"ManifestError in hullwork.manifest.parse_manifest"* is two fields already present.
    """
    frames = [dict(frame) for frame in payload.get("frames") or []]
    site = ""
    if frames:
        last = frames[-1]
        site = f" in {last.get('module')}.{last.get('function')}"

    return {
        "event_id": uuid.uuid4().hex,
        "timestamp": datetime.now(UTC).isoformat(),
        "platform": "python",
        "level": "error",
        "logger": "hullwork.upstream",
        "release": payload.get("release"),
        "exception": {
            "values": [
                {
                    "type": payload.get("exception"),
                    "value": f"{payload.get('exception')}{site}",
                    "stacktrace": {"frames": frames},
                }
            ]
        },
        # Tags, because these are the axes a crash gets counted along: how many installations, which
        # program, which Python. All of them enumerated fields; none of them a name.
        "tags": {
            "installation": payload.get("installation") or UNKNOWN,
            "operation": payload.get("operation"),
            "python": payload.get("python"),
            "os": payload.get("platform"),
            "schema": payload.get("schema"),
        },
        "extra": {"counts": payload.get("counts")},
    }


class Destination:
    """The upstream tracker, with its own client and its own ceiling.

    **Its own client on purpose.** The operator's client — when they have one — carries their whole
    event, scrubbed, to a tracker they chose; this one carries a constructed payload to ours. One
    client cannot do both, and giving them separate ones is what makes the difference readable in
    the code rather than argued about in a comment.

    Nothing here may raise. It runs inside `before_send`, which runs inside somebody else's crash:
    an exception from here would replace their error with ours, in their logs, on their machine.
    """

    def __init__(
        self,
        dsn: str,
        *,
        operation: str,
        session_factory: Callable[[], Any] | None = None,
        ceiling: int = UPSTREAM_CEILING,
    ) -> None:
        self.dsn = dsn
        self.operation = operation
        self._session_factory = session_factory
        self._ceiling = ceiling
        self._sent = 0
        self._instance: Instance | None = None
        self._asked_the_database = False
        #: Set by a 429 or a 413. One refusal is enough: the relay rate-limits (item 154) and a
        #: sender that argues with a rate limit is why the limit had to be there.
        self._refused = False
        self._threads: list[threading.Thread] = []

    @property
    def host(self) -> str:
        return named_host(self.dsn)

    def instance(self, *, mint: bool = True) -> Instance:
        """This installation, resolved once and then remembered — failures included.

        **The database is asked at most once per process, and never twice after it failed.** Item
        150 measured what a broken database does to a running instance: `/ready` answers 503 and new
        connections raise. Retrying here, inside a crash handler, would turn one failure into a
        connection attempt per event.
        """
        if self._instance is not None:
            return self._instance

        identifier: str | None = None
        counts: dict[str, int] = {}
        if self._session_factory is not None and not self._asked_the_database:
            self._asked_the_database = True
            try:
                with self._session_factory() as session:
                    identifier = installation_id(session, mint=mint)
                    counts = census(session)
            # A crash report is not the place to raise.
            except Exception:
                log.debug("could not read this installation's identifier", exc_info=True)

        self._instance = Instance(
            installation=identifier, operation=self.operation, **counts
        )
        return self._instance

    def rendered(self, event: Mapping[str, Any]) -> dict[str, Any] | None:
        """What may travel, ready for the wire — or `None` when nothing may.

        **This is the whole of what an upstream event can be.** One method, one ceiling, whether or
        not the operator also has a tracker of their own.
        """
        if self._sent >= self._ceiling:
            return None
        try:
            payload = upstream_payload(event, self.instance())
            if payload is None:
                return None
            rendered = as_event(payload)
        # Never replace somebody's crash with ours.
        except Exception:
            log.debug("could not build an upstream report for this crash", exc_info=True)
            return None
        self._sent += 1
        return rendered

    def offer(self, event: Mapping[str, Any]) -> bool:
        """Send this crash upstream. Returns whether anything left, which is what tests assert on.

        Every failure — no payload, a ceiling, a network, a refusal — answers `False` and is silent
        past a debug line. On somebody else's machine, a reporting problem is not their problem.
        """
        rendered = self.rendered(event)
        if rendered is None:
            return False
        if self._refused:
            return False

        thread = threading.Thread(target=self._post, args=(rendered,), daemon=True)
        self._threads.append(thread)
        thread.start()
        return True

    def _post(self, rendered: Mapping[str, Any]) -> None:
        """The envelope, by hand, because the SDK's client sends more than it is given.

        **Measured 2026-08-06, and this method exists because of it.** Handing a constructed event
        to `sentry_sdk.Client.capture_event` put `environment` and `server_name` on the wire: the
        client adds both *after* `before_send`, so what arrived was our payload **plus the
        operator's environment name and their machine's hostname**. Two init arguments —
        `server_name=""` and leaving `environment` unset — stood between a hostname and our ingest,
        and neither is visible from the code that builds the payload.

        A POST cannot add anything. It also drops a dependency: this path does not need
        `hullwork[telemetry]` at all, because `urllib` is in the standard library.

        No retries, and one attempt with a short timeout. A crash report that arrives is a
        convenience for us; a crash report that blocks somebody's process is a defect we caused.
        """
        try:
            body = json.dumps(rendered, separators=(",", ":")).encode()
            envelope = b"".join(
                (
                    json.dumps({"event_id": rendered.get("event_id")}).encode(),
                    b'\n{"type":"event","length":',
                    str(len(body)).encode(),
                    b"}\n",
                    body,
                    b"\n",
                )
            )
            request = urllib.request.Request(  # noqa: S310 - the scheme is checked below
                self._ingest_url(),
                data=envelope,
                method="POST",
                headers={
                    "Content-Type": "application/x-sentry-envelope",
                    # The key travels in the header and not in the envelope, so a stored envelope
                    # holds no credential.
                    "X-Sentry-Auth": (
                        f"Sentry sentry_version=7, sentry_client=hullwork/{__version__}, "
                        f"sentry_key={self._key()}"
                    ),
                },
            )
            with urllib.request.urlopen(request, timeout=5) as answer:  # noqa: S310 - as above
                if answer.status == 429:  # pragma: no cover - the relay's rate limit, item 154
                    self._refused = True
        except urllib.error.HTTPError as refused:
            # **A refusal is final for this process.** Item 154's relay rate-limits, and a sender
            # that keeps trying past a 429 is the reason rate limits have to exist twice.
            if refused.code in (413, 429):
                self._refused = True
            log.debug("the upstream ingest refused this report", exc_info=True)
        # A background thread must not take the process with it.
        except Exception:
            log.debug("could not report this crash upstream", exc_info=True)

    def _parts(self) -> urllib.parse.SplitResult:
        return urllib.parse.urlsplit(self.dsn)

    def _key(self) -> str:
        return self._parts().username or ""

    def _ingest_url(self) -> str:
        """`https://host/api/<project>/envelope/`, the endpoint every Sentry-protocol tracker has.

        Refuses anything that is not HTTP: a DSN is configuration, and a `file:` URL reaching
        `urlopen` would make a crash report read a path instead of sending one.
        """
        parts = self._parts()
        if parts.scheme not in ("http", "https"):
            msg = f"an upstream DSN must be http or https, not {parts.scheme!r}"
            raise ValueError(msg)
        port = f":{parts.port}" if parts.port else ""
        project = parts.path.strip("/").rsplit("/", 1)[-1]
        return f"{parts.scheme}://{parts.hostname}{port}/api/{project}/envelope/"

    def close(self, timeout: float = 2.0) -> None:
        """Wait briefly for what is in flight. Safe when nothing was ever sent.

        Briefly, and then not: a shutdown that waits on our ingest is a shutdown we made slower on
        somebody else's machine.
        """
        for thread in self._threads:
            thread.join(timeout=timeout)
