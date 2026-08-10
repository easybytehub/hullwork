"""Why an instance that is running will not work. Item 074.

`readiness` answers "is this instance working?" from state the pipeline already keeps, calls no
forge, and is cheap enough to serve on every probe. That is correct for what it is, and it is the
wrong shape for the failures that actually cost time on the first two days of real deployment:

* a `docker` binary present and its daemon unreachable;
* a database that answers every liveness question and holds no tables, because the process was
  started without `HULLWORK_DATABASE_URL` and made itself an empty one beside the real one;
* the *code* token unable to see a repository, discovered four layers down when an attempt had
  already been spent;
* a subscription credential file whose token expired hours ago, arriving as `401 OAuth access token
  has expired` with nothing pointing at the file;
* a variable correct in `.env`, correctly read by `config.py`, and never delivered — because the
  deployment's compose file lists variables one at a time and a missing line is silent.

Each is cheap to check and expensive to find, so this module checks them. **It is deliberately
allowed to be expensive**: it spends a subprocess, a forge call per repository and a file read,
because it is typed by a person who already knows something is wrong. `status` may not — it is in
people's crons.

Two rules the whole module obeys:

* **A value is never printed, only a name.** The environment file holds four credentials.
* **`unknown` never fails the exit code.** Item 073's lesson, learned by wiring an always-on warning
  into an exit code and losing the signal entirely: a check that cannot answer says so and stands
  aside.
"""

import itertools
import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from hullwork.config import Settings
from hullwork.forge import ForgeError
from hullwork.models import Base, Delivery, Item, ItemState, Project
from hullwork.scaffold import belongs_to_one_half


class RepositoryReader(Protocol):
    """A credential seen only as "can this reach that repository at all?".

    The same narrowing `make_permission_reader` applies to the ingest token, for the same reason: a
    check that only needs to read must not be handed an object that can commit. `ForgeCode`
    satisfies it structurally, so the caller passes the real code forge and this module cannot push
    with it even by accident.
    """

    def default_branch(self, repo: str) -> str: ...


class IssueReader(Protocol):
    """A credential seen only as "does this issue still exist?". Narrowed for the same reason."""

    def get_issue(self, repo: str, number: int) -> object | None: ...


#: How long a `docker version` may take before the daemon counts as not answering. Generous: a
#: cold Docker Desktop takes seconds, and a false "your daemon is down" is worse than waiting.
DOCKER_TIMEOUT_SECONDS = 30

#: Where the daemon listens, and the one thing that tells a process whether the question is even
#: its own to answer (item 135). Same constant the scaffold writes into the compose file.
DOCKER_SOCKET = "/var/run/docker.sock"

#: The variable whose absence from the service is **correct** (spec M2 §1, enforced by
#: `main._refuse_the_credential_this_process_must_not_hold`). Named here so the inventory can say
#: "this one is meant to be missing" instead of reporting a gap somebody would close — which is
#: exactly what happened on 2026-07-29, and the service then refused to boot.
CODE_TOKEN = "HULLWORK_FORGE_CODE_TOKEN"  # noqa: S105 - a variable's name, never its value

#: Who applies migrations, named in the remedy rather than only the command. Item 076.
#:
#: `alembic upgrade head` on its own is a dead end from a wheel installation, which is what the
#: dispatcher is meant to become: measured, the wheel holds the package and **nothing else** — no
#: `migrations/`, no `alembic.ini` — because `docker-entrypoint.sh` copies them separately and
#: migrates there, *"the app should not be deciding to alter its own database, and with more than
#: one replica they would race each other doing it."* So the receiver owns the schema and the
#: dispatcher only uses it — and an operator sent to a command their installation does not have will
#: either give up, or add the migrations to the wheel to satisfy the message and undo that decision.
WHO_MIGRATES = (
    "The receiver applies migrations in its entrypoint (`docker compose up` runs `alembic upgrade "
    "head` there); the dispatcher never does. From a checkout, `alembic upgrade head` by hand."
)


class State(StrEnum):
    """What a check concluded.

    `expected` is not a synonym for `ok`: it marks a gap that is real, deliberate, and must not be
    closed. Folding it into `ok` would hide the fact; folding it into `broken` would send somebody
    to fix it.
    """

    OK = "ok"
    BROKEN = "broken"
    UNKNOWN = "unknown"
    EXPECTED = "expected"


@dataclass(frozen=True)
class Finding:
    """One check, its verdict, and what to do about it.

    `detail` says what was measured before it says what to do, because the measurement is the part
    an operator can disagree with.
    """

    check: str
    state: State
    detail: str
    #: Whether this verdict is about **this machine** rather than about the thing itself. Item 105.
    #:
    #: The distinction exists for `not_from_here`, and it took an eleven-hour outage to find. A
    #: failure like "there is no file at this path" or "git is not installed" is a fact about the
    #: filesystem the check ran on, so a *different* process can legitimately give a different
    #: answer — that is what makes it safe to downgrade when somebody else owns the resource. A
    #: failure like "the token expired" is a fact about the token's contents: every process that can
    #: read the file sees the same expiry, and attributing it to the reader's location hides a real
    #: problem behind an explanation that cannot be true.
    #:
    #: `True` by default because most checks are about this machine, and because the safe error for
    #: a new check is to be downgradable rather than to shout from the wrong process.
    local: bool = True

    @property
    def is_failure(self) -> bool:
        return self.state is State.BROKEN


def failed(findings: Iterable[Finding]) -> bool:
    """Whether any of these should make the command exit non-zero."""
    return any(finding.is_failure for finding in findings)


# --- preconditions: assert by doing, never by reading configuration --------------------------


def git_on_path() -> Finding:
    """`git` is how the dispatcher gets a tree at all.

    Worth a check of its own because of where it fails: the `api` image has no `git`, the dispatcher
    runs on the host precisely because it needs it, and a deployment that moves the dispatcher into
    a container reproduces the whole class silently.
    """
    found = shutil.which("git")
    if found is None:
        return Finding(
            "git",
            State.BROKEN,
            "not on PATH. The dispatcher clones and builds a worktree with it, so no attempt can "
            "start. This is also why the dispatcher runs on the host rather than in the `api` "
            "image, which has no git.",
        )
    return Finding("git", State.OK, found)


def docker_daemon(docker: str = "docker", *, socket: str = DOCKER_SOCKET) -> Finding:
    """Ask the daemon its version, and take the answer as the check.

    **The binary and the daemon are different failures with different remedies**, and conflating
    them is how an operator spends an afternoon reinstalling a client that was already there. A
    socket that refuses the connection, and a socket whose permissions refuse *this user*, both
    arrive here as a non-zero exit with the reason on stderr — so the reason is what gets printed.

    `docker version` rather than `docker ps`: it is the cheapest call that requires the daemon to
    answer, and it needs no permission to list anything.
    """
    binary = shutil.which(docker)
    if binary is None:
        return Finding(
            "docker",
            State.BROKEN,
            f"no {docker!r} on PATH. The sandbox is the only place an attempt may run "
            "(DR-0004), so nothing can be attempted without it.",
        )
    try:
        probe = subprocess.run(  # noqa: S603 - argv list, no shell, binary resolved above
            [binary, "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=DOCKER_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Finding(
            "docker",
            State.BROKEN,
            f"{binary} is installed and did not answer within {DOCKER_TIMEOUT_SECONDS}s: {exc}",
        )
    if probe.returncode != 0:
        why = (probe.stderr or probe.stdout or "").strip().splitlines()
        reason = why[0] if why else f"exit {probe.returncode} with nothing on stderr"
        if not Path(socket).exists():
            # **A process with no socket is not the process that runs sandboxes** (item 135). The
            # receiver never has one — spec M2 §1 keeps the socket on the dispatcher, which is the
            # same rule that keeps the push credential there — so "the daemon does not answer" is
            # true here and is a fact about the wrong process.
            #
            # Deliberately not routed through `not_from_here`: that asks whether a dispatcher is
            # alive, and on a first installation none is, which is exactly when this fired. The
            # answer does not depend on anybody being alive. It depends on this process not being
            # able to hold the resource at all.
            # **Two corrections here, both from strangers evaluating the product on 2026-08-04.**
            #
            # The advice named a service that need not exist. `docker compose --profile autofix exec
            # dispatcher …` answers `service "dispatcher" is not running` in the README's evaluation
            # stack, which has one service and says at length why it deliberately has no second one.
            # Both agents who ran it reported a diagnostic sending them to a dead end — and the dead
            # end reported success, since this finding is `UNKNOWN` and item 073 keeps that out of
            # the exit code. The advice is now conditional in its wording, so it cannot be wrong in
            # either deployment.
            #
            # And the path is not where every platform looks. On Docker Desktop the client reaches
            # the daemon through `~/.docker/run/docker.sock` or whatever `DOCKER_HOST` names, so "no
            # socket at /var/run/docker.sock" is true and reads as "no daemon". One agent claimed
            # this made `doctor` wrong on every Mac; another measured this host and got `ok`, which
            # is correct — `docker info` succeeds, so this branch is never reached. The claim was
            # wrong and was not taken at face value. The branch still must not mislead whoever does
            # reach it.
            return Finding(
                "docker",
                State.UNKNOWN,
                f"no socket at {socket} in this process, so nothing here can ask the daemon "
                f"anything. Two ordinary reasons, and neither is a broken daemon. This may be the "
                f"receiver, which never mounts it — the sandbox is built by the dispatcher, and if "
                f"this deployment has that half (`hullwork init` writes it behind an `autofix` "
                f"profile; the README's evaluation stack deliberately has no such service) then "
                f"ask it instead: `docker compose --profile autofix exec dispatcher hullwork "
                f"doctor`. Or the client reaches the daemon somewhere else — Docker Desktop uses a "
                f"socket under your home directory — in which case `docker context inspect` says "
                f"where, and it is not this path.",
                local=True,
            )
        return Finding(
            "docker",
            State.BROKEN,
            f"the client at {binary} works and the daemon does not answer it: {reason[:200]}",
        )
    return Finding("docker", State.OK, f"daemon {probe.stdout.strip() or 'answering'}")


def database_built(session: Session, settings: Settings) -> Finding:
    """Whether the database this process opened has this build's tables in it.

    **The check `readiness` cannot make.** It asks whether the database is writable and how much
    disk is left, and a SQLite file created seconds ago by a process missing
    `HULLWORK_DATABASE_URL` passes both perfectly: it is writable, it is nearly empty, and it holds
    no tables at all. Measured on 2026-07-29, where the dispatcher was reading an empty database
    beside the real one and every report said the instance was fine.

    Compares against what the models declare rather than against a hard-coded list, so a table added
    in a future migration is covered by this check the day it is added.
    """
    expected = set(Base.metadata.tables)
    try:
        present = set(inspect(session.get_bind()).get_table_names())
    except Exception as exc:  # any failure here is the answer, whatever its class
        return Finding("database", State.BROKEN, f"could not be inspected: {exc}")

    where = settings.database_url.split("://", 1)[0]
    if not present:
        return Finding(
            "database",
            State.BROKEN,
            f"{where}: opened and holds no tables at all. Either this process is pointed at the "
            f"wrong database — the usual cause is HULLWORK_DATABASE_URL unset, which makes SQLite "
            f"create an empty file beside the real one — or the schema has never been built. "
            f"{WHO_MIGRATES}",
        )
    missing = sorted(expected - present)
    if missing:
        return Finding(
            "database",
            State.BROKEN,
            f"{where}: {len(present)} table(s) present and these are absent: {missing}. "
            f"A migration has not been applied. {WHO_MIGRATES}",
        )
    return Finding("database", State.OK, f"{where}: all {len(expected)} table(s) present")


def code_token_reaches_repositories(
    session: Session, code_forge: RepositoryReader | None
) -> list[Finding]:
    """Ask the **code** credential to read each active repository, and believe the refusal.

    This is the check that would have caught the 2026-07-29 `403 token does not have at least one of
    required scope(s)` at the moment the token was configured, rather than four layers down inside a
    spent attempt.

    A **read** on purpose, and it is what keeps this compatible with item 073's open question. That
    item is stuck because probing a *write* scope with the *ingest* token would need an exception to
    `refuse_unless_ingest_may_write` — the guard that makes spec M2 §1 a property of this program.
    Nothing of the kind is needed here: `default_branch` is a `GET`, the client is the one that is
    *supposed* to be able to push, and a token that cannot even see the repository can certainly not
    open a pull request in it. It answers a strictly weaker question than item 073's, and answers it
    for certain.

    No code token is `unknown`, never `broken`: a rehearsing instance is a supported configuration
    (item 049), and reporting every repository as unreachable because a credential is deliberately
    absent is the always-on signal item 073 removed.
    """
    projects = session.execute(
        select(Project).where(Project.active.is_(True)).order_by(Project.slug)
    ).scalars().all()
    if not projects:
        return [Finding("code token", State.OK, "no active project to reach")]
    if code_forge is None:
        return [
            Finding(
                "code token",
                State.UNKNOWN,
                f"{CODE_TOKEN} is not set in this process, so whether it can reach "
                f"{len(projects)} active repositor(y/ies) cannot be asked. Rehearsals "
                f"(`hullwork work --no-publish`) need no such credential; publishing does.",
            )
        ]

    findings: list[Finding] = []
    for project in projects:
        try:
            branch = code_forge.default_branch(project.repo)
        except ForgeError as exc:
            status = f" (HTTP {exc.status})" if exc.status is not None else ""
            findings.append(
                Finding(
                    f"code token → {project.slug}",
                    State.BROKEN,
                    f"cannot read {project.repo}{status}: {exc}. Nothing will be published for "
                    f"this project. The code token needs `repository: Read and Write`, limited to "
                    f"the repositories it is named for — and it must not be the ingest token.",
                )
            )
        else:
            findings.append(
                Finding(f"code token → {project.slug}", State.OK, f"{project.repo} @ {branch}")
            )
    return findings


#: How many open items the inventory check asks the forge about in one run. Bounded because it is
#: one
#: request each, and said out loud when it truncates rather than reporting a clean inventory it did
#: not finish looking at.
INVENTORY_LIMIT = 50


def items_point_at_real_issues(
    session: Session, forge: IssueReader | None, *, limit: int = INVENTORY_LIMIT
) -> list[Finding]:
    """Whether every open item's issue still exists. The operator's rule: a clean inventory.

    `status` already reports this **for `ready` items only** (item 069), because that is where it
    stops a dispatcher spending an attempt on a verdict with nowhere to go. That left a gap and item
    7 sat in it: `not-reproducible`, pointing at issue `#3`, which does not exist. Nothing
    complained, because nothing asks about an item that is not waiting for the dispatcher — and its
    verdict was just as unpublishable, which is what item 077 then had to deal with by hand.

    So this asks about **every item that is not closed**. A `done` item whose issue was deleted
    afterwards is history and says nothing about now; anything else is either waiting for a verdict
    it cannot receive, or holding one it could not deliver.
    """
    open_items = session.execute(
        select(Item)
        .where(Item.forge_issue_ref.is_not(None), Item.state != ItemState.DONE)
        .order_by(Item.id)
        .limit(limit + 1)
    ).scalars().all()
    if not open_items:
        return [Finding("inventory", State.OK, "no open item points at an issue")]
    if forge is None:
        return [
            Finding(
                "inventory",
                State.UNKNOWN,
                f"{len(open_items)} open item(s) point at an issue and no forge is configured, so "
                f"whether those issues still exist cannot be asked.",
            )
        ]

    truncated = len(open_items) > limit
    checked = list(open_items[:limit])
    stranded: list[str] = []
    for item in checked:
        try:
            number = int(str(item.forge_issue_ref).lstrip("#"))
        except ValueError:
            stranded.append(f"item {item.id} → {item.forge_issue_ref!r} (not a number)")
            continue
        try:
            issue = forge.get_issue(item.project.repo, number)
        except ForgeError:
            # A forge that blinks is not news about an issue, and reporting every item as stranded
            # because of one bad request is the always-on signal item 073 removed.
            continue
        if issue is None:
            stranded.append(f"item {item.id} ({item.state.value}) → {item.project.repo}#{number}")

    findings: list[Finding] = []
    if stranded:
        findings.append(
            Finding(
                "inventory",
                State.BROKEN,
                f"{len(stranded)} open item(s) point at an issue that does not exist, so a verdict "
                f"about them has nowhere to go: {'; '.join(stranded)}. Point each at a real issue, "
                f"or close it. `hullwork republish --give-up` is for a verdict already reached.",
            )
        )
    else:
        findings.append(
            Finding(
                "inventory", State.OK, f"all {len(checked)} open item(s) point at a real issue"
            )
        )
    if truncated:
        # Never a silent cap: an inventory reported clean after looking at part of it is worse than
        # one that says it did not finish.
        findings.append(
            Finding(
                "inventory",
                State.UNKNOWN,
                f"only the first {limit} open item(s) were checked, of {len(open_items) - 1}+ — "
                f"one request each. Run it again after clearing these, or raise the bound.",
            )
        )
    return findings


def _unreadable(source: str, exc: Exception) -> str:
    """Why a credential file cannot be read, in an operator's words not a parser's. Item 103.

    **The state comes first and the exception second**, because the exception is a parser talking
    about column numbers in a file the operator has never opened. Measured against all four
    reachable states: an empty file raises `Expecting value: line 1 column 1 (char 0)`, a truncated
    one `Unterminated string`, a missing one `FileNotFoundError`, a directory `IsADirectoryError`.
    Only the last two say anything useful, and they say it by accident.

    The empty case names `MODEL_CREDENTIALS_HOST` because that is what it almost always is: the
    compose defaults that variable to `/dev/null`, which **is** an empty file. On 2026-07-30 that
    cost forty minutes of an instance that looked healthy — the message an operator had was
    `Expecting value: line 1 column 1 (char 0)`, and the file they went to inspect was fine.
    """
    # **"unusable" stays in every one of these**, and not to satisfy a test. The word is what the
    # existing message got right: this is a finding about a credential being unusable, and an
    # operator scanning `doctor` output looks for it. What the old message got wrong was that the
    # word was *all* there was, followed by a parser's sentence about column numbers. The state and
    # the likely cause go after it.
    head = "HULLWORK_MODEL_CREDENTIALS_FILE is set and unusable"
    tail = f" (the underlying error: {exc})"
    if isinstance(exc, IsADirectoryError):
        return (
            f"{head} — {source} is a directory, not a file. Docker creates one at the "
            f"destination when a "
            f"bind mount's source does not exist on the host, so check the path the deployment "
            f"mounts from{tail}"
        )
    if isinstance(exc, FileNotFoundError):
        return f"{head}: there is no file at {source}, so there is nothing to read{tail}"
    if isinstance(exc, json.JSONDecodeError):
        # **Emptiness is asked by reading, not by `is_file()` and a size**, and the first version of
        # this got it wrong in the one case it exists for. `/dev/null` is a **character device**:
        # `is_file()` is False for it, so the empty branch never fired in production and the message
        # fell through to "not valid JSON — it may have been read while the CLI was rewriting it",
        # which blames a write race that is not happening. Found by provoking the real failure on
        # the live instance; the unit tests used a regular empty file and agreed with the bug.
        try:
            empty = not Path(source).read_bytes().strip()
        except OSError:  # pragma: no cover - the read that raised is already in `exc`
            empty = False
        if empty:
            return (
                f"{head}: there is nothing to read at {source} — it is empty. If this deployment "
                f"left MODEL_CREDENTIALS_HOST unset, the compose binds /dev/null here, and that is "
                f"what an empty credential almost always is{tail}"
            )
        return (
            f"{head}: {source} is not valid JSON — it may have been read while the CLI that "
            f"owns it was rewriting it{tail}"
        )
    return f"{head}: {source} cannot be used: {exc}"


def credential_never_works(settings: Settings) -> str:
    """Why the model credential can **never** work without a person, or `""`. Items 096 and 103.

    The distinction `credential_expired` does not draw, and the one that decides whether a
    dispatcher should keep running or stop:

    * **expired** — the token was well-formed and its clock ran out. It comes back by itself: the
      CLI refreshes it on use, and on this deployment a cron does it every four hours. A dispatcher
      that exited for this would flap several times a day and be wrong every time, which is why
      item 096 made the loop refuse to *claim* and keep *running*.
    * **never works** — there is no credential configured, or the file cannot be read or parsed.
      Nothing about that resolves on its own. A dispatcher in this state is a process that cannot do
      the one thing it exists to do, and it stays "Up" while not working — measured on 2026-07-30,
      for forty minutes, and it ended because somebody read the tracker by hand.

    The same rule `configure_error_reporting` already follows for the error DSN: *an instance that
    believes it is being watched and is not is worse than one that knows it is not.* Applied to the
    resource without which every attempt fails before the sandbox starts.
    """
    if settings.model_key:
        return ""
    if not settings.model_credentials_file:
        return (
            "neither HULLWORK_MODEL_KEY nor HULLWORK_MODEL_CREDENTIALS_FILE is set, so an agent "
            "would have nothing to think with and every attempt would fail before the sandbox "
            "starts."
        )
    from hullwork.gateway import GatewayError, subscription_payload

    try:
        subscription_payload(settings.model_credentials_file)
    except (GatewayError, OSError, json.JSONDecodeError) as exc:
        return _unreadable(settings.model_credentials_file, exc)
    return ""


def credential_expired(settings: Settings) -> str:
    """Why the model credential cannot be used right now, or `""` when it can. Item 096.

    **A separate entry point for the loop, over the same measurement the doctor prints.** The loop
    needs a decision per pass and the doctor needs a sentence for a person; two copies of the expiry
    arithmetic would be two things to keep in step, so this asks `model_credential` and reads its
    verdict.

    Only `broken` counts. `unknown` is a token whose shape declares no expiry — somebody else's
    format, possibly a future one — and refusing to work over that would ground an instance for a
    field that was never promised. `ok` includes an API key, which has no expiry to read at all.

    What this prevents, measured on 2026-07-30: the instance had printed *"valid until 14:07 UTC"*
    two hours earlier, then at 14:31 spent an attempt, a clone, an image, a network, a gateway and
    **21 model calls** rediscovering it — and since `abandoned` does not consume the item's attempt,
    claimed the same item again a minute later, and would have kept going for as long as the
    credential stayed dead.
    """
    finding = model_credential(settings)
    return finding.detail if finding.state is State.BROKEN else ""


def model_credential(
    settings: Settings, *, anything_uses_it: bool | None = True
) -> Finding:
    """Present is not enough: a subscription token expires in hours.

    An API key is the supported configuration (DR-0004, amended 2026-07-28) and its validity cannot
    be established without calling somebody's paid endpoint, so a key present is reported as present
    and nothing more. The development path can be checked properly, and needs to be: it is how this
    project's own dogfood runs, the token lives about five hours, and its refresh belongs to the CLI
    that wrote it. An expired one arrives as `401 OAuth access token has expired` from inside a
    sandbox, which names neither the file nor the clock.
    """
    if settings.model_key:
        return Finding(
            "model credential",
            State.OK,
            "HULLWORK_MODEL_KEY is set — the supported path. Whether the provider accepts it is "
            "not asked here: that would spend somebody's quota to answer a question the first "
            "attempt answers anyway.",
        )
    if not settings.model_credentials_file:
        if anything_uses_it is None:
            # **Cannot tell, so it does not claim.** The schema is unbuilt, so nothing here can ask
            # whether any project names an agent — and the first `doctor` of a fresh install is
            # exactly that moment. Answering `broken` there tells a stranger their correct
            # receiver-only deployment is failing, which is the defect item 135 was written for.
            return Finding(
                "model credential",
                State.UNKNOWN,
                "not set, and this process cannot yet tell whether anything needs one: the schema "
                "is not built, so no project can be read. Bring the receiver up — its entrypoint "
                "migrates — and ask again. Ingest-only deployments never need a model credential.",
            )
        if not anything_uses_it:
            # **An ingest-only installation is finished, not broken** (item 135). Measured on a
            # first installation that followed the document exactly: `doctor`'s first run said
            # `AILING` about a deployment that was doing precisely what `init` had just described —
            # ingest, dedup, triage, issues — because no project had an agent and nothing was ever
            # going to ask for a model. `expected` is the state this module already defines for a
            # gap that is real, deliberate and must not be closed.
            return Finding(
                "model credential",
                State.EXPECTED,
                "not set, and nothing here needs one: no active project names an agent, so no "
                "attempt will ever be made. Set HULLWORK_MODEL_KEY when you turn autofix on for a "
                "project — `hullwork.yml`'s `autofix.agent`, and the dispatcher behind "
                "`--profile autofix`.",
            )
        return Finding(
            "model credential",
            State.BROKEN,
            "neither HULLWORK_MODEL_KEY nor HULLWORK_MODEL_CREDENTIALS_FILE is set, so an agent "
            "would have nothing to think with and every attempt fails before the sandbox starts.",
        )

    source = settings.model_credentials_file
    from hullwork.gateway import GatewayError, subscription_payload

    try:
        payload = subscription_payload(source)
    except (GatewayError, OSError, json.JSONDecodeError) as exc:
        return Finding("model credential", State.BROKEN, _unreadable(source, exc))

    oauth = payload.get("claudeAiOauth")
    expires_ms = oauth.get("expiresAt") if isinstance(oauth, dict) else None
    if not isinstance(expires_ms, int | float):
        # A token with no expiry recorded is not an error: the shape is somebody else's and it may
        # change. Reported as unknown so it never fails a cron, and named so it is not mistaken for
        # a check that passed.
        return Finding(
            "model credential",
            State.UNKNOWN,
            f"read a token from {source} and it declares no expiry, so whether it is still valid "
            f"cannot be told from here. The supported path is an API key in HULLWORK_MODEL_KEY.",
        )

    expires = datetime.fromtimestamp(expires_ms / 1000, tz=UTC)
    seconds = (expires - datetime.now(UTC)).total_seconds()
    if seconds <= 0:
        return Finding(
            "model credential",
            State.BROKEN,
            # `local=False`: read the file from anywhere and the expiry is the same number. On
            # 2026-07-31 this was downgraded to `unknown` by `not_from_here` **inside the dispatcher
            # itself**, with the advice to run the doctor where the dispatcher runs — where it
            # already was — and eleven hours of an idle instance went undiagnosed behind it.
            local=False,
            detail=f"the token in {source} expired {_span(-seconds)} ago "
            f"(at {expires:%Y-%m-%d %H:%M} "
            f"UTC). Every attempt will fail with `401 OAuth access token has expired`, which says "
            f"nothing about this file. Refreshing it belongs to the CLI that wrote it: "
            f"`claude -p ok --max-turns 1` as the user who owns it.",
        )
    return Finding(
        "model credential",
        State.OK,
        f"a development-only subscription token from {source}, valid for another {_span(seconds)} "
        f"(until {expires:%Y-%m-%d %H:%M} UTC). Not a supported configuration: it expires in hours "
        f"and its refresh belongs to the CLI that wrote it.",
    )


def _span(seconds: float) -> str:
    """A duration a human reads without converting. Never negative — callers pick the sign."""
    seconds = abs(seconds)
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h{int((seconds % 3600) // 60):02d}m"
    return f"{int(seconds // 86400)}d{int((seconds % 86400) // 3600)}h"


# --- the effective configuration: which variable is set where -------------------------------


#: Matches a Hullwork variable name and nothing else. Used on both the environment file and the
#: compose file, so a name is recognised the same way in each.
_VARIABLE = re.compile(r"\bHULLWORK_[A-Z0-9_]+\b")

#: `KEY=` at the start of a line, with `export ` tolerated because the file is sourced by a shell
#: in `docs/deployment-notes.md`. The value is never captured — this module reads names.
_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?(HULLWORK_[A-Za-z0-9_]+)\s*=")


def variables_in_file(path: Path) -> list[str]:
    """The Hullwork variable **names** an environment file assigns. Never the values.

    An unreadable or absent file is an empty list rather than an error. This check exists to add
    information: a container that cannot see the host's `.env` is the normal case for anybody not
    deploying the way we do, and a noisy failure there would teach operators to ignore it.

    **The deployment check does not rely on that leniency and must not.** Measured on this project's
    own instance, 2026-08-05: the file was mounted, mode 600 as a credential file should be, and the
    container runs as uid 10001 — so this returned `[]` and the operator was told the file *assigns
    nothing*, which was false. The caller therefore establishes readability itself before asking
    this question. Silence is the right answer to *"which names are in here"*; it is the wrong
    answer to *"could you look"*.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    matches = (_ASSIGNMENT.match(line) for line in text.splitlines())
    return sorted({match.group(1) for match in matches if match})


def variables_in_compose(path: Path) -> list[str]:
    """The Hullwork variable names a compose file mentions anywhere.

    Read as text with a regular expression rather than parsed as YAML, and that is the right call
    twice over: the file interpolates (`${HULLWORK_TRACKER_URL:-}`), so a name appears both as a key
    and inside a value; and the question being asked is "is this name in this file at all", for
    which a parse adds a dependency on the exact shape of somebody's deployment and buys nothing.

    An absent file is an empty list, and the caller reports nothing rather than everything.

    **Commented-out lines do not count, and they used to.** Measured 2026-08-05 by reproducing the
    2026-07-28 failure on the live instance: commenting out `HULLWORK_BASE_URL` in the deployment's
    compose file produced **no finding at all**, because the name is still in the text — inside the
    comment. A variable somebody commented out while testing and forgot is the same outage as one
    that was never there, and it is more likely, since the line looks present to a reader too.

    Only whole-line comments are dropped. A trailing `# note` after a real assignment leaves the
    assignment standing, which is why this is not a blanket strip of everything after a `#`.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    live = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    return sorted(set(_VARIABLE.findall("\n".join(live))))


def unset_in(settings: Settings, names: Iterable[str]) -> list[str]:
    """Of these variable names, the ones that never reached this process's configuration.

    Asked of `Settings` and **never of `os.environ`**, and that distinction is half the correctness
    of this check. `Settings` reads `.env` itself (`env_file=".env"` in `config.py`), so a variable
    can be absent from the environment and present in the configuration — the normal case for
    anybody running the CLI from the deployment directory. Comparing names against the environment
    reported all eight of production's variables as missing while every one had arrived.

    The other half is `model_fields_set` rather than a comparison against the field's default, and
    that one was measured wrong on the live instance before it was measured right. `.env` assigns
    `HULLWORK_LOG_FORMAT=json`, `json` **is** the default, and comparing values cannot tell "never
    arrived" from "arrived and agrees with the default" — so the doctor's first run against a
    correctly configured production instance reported a variable as missing that was sitting in its
    own environment. `model_fields_set` answers the question actually being asked: was this field
    set from a source, or is the process running on a default nobody chose?

    It is also the safer of the two: no value is compared, so nothing here can read a credential
    even by accident.
    """
    fields = Settings.model_fields
    unset: list[str] = []
    for name in names:
        field = name.removeprefix("HULLWORK_").lower()
        if field not in fields:
            # An unmapped `HULLWORK_*` name is already a hard start-up failure in
            # `config._unknown_variables`. Not this module's job to say it twice.
            continue
        if field not in settings.model_fields_set:
            unset.append(name)
    return unset


def environment_gaps(
    settings: Settings,
    *,
    env_file: Path,
    compose_file: Path | None = None,
) -> list[Finding]:
    """What the machine holds that a process does not. Item 074, both halves.

    The mechanism is the same in each and it is worth naming once: a variable can be **correct in
    the file, correctly read by `config.py`, and never arrive**. `readiness` then says the feature
    is unconfigured, which is true of the process and false of the machine — and that is the
    sentence that sends somebody looking in the wrong place for a day.

    Half one, **file → this process's configuration**: what the file assigns and this process is
    not running on. See `unset_in` for why it is asked of `Settings` and not of the environment.

    Half two, **file → the neighbouring compose**: what the file assigns and the compose never
    passes on. This is the 2026-07-28 tracker failure caught by its own mechanism, with no network
    and no container involved: `HULLWORK_TRACKER_URL` and `HULLWORK_TRACKER_TOKEN` were both set,
    item 036's enrichment had never once run in production, and the compose simply had no line for
    them. **Half one cannot catch this one** — the host process reads the file and is configured
    correctly; it is the container that is not — which is why there are two halves and not one.

    `env_file:` is the fix that must not be used, and the reason is `CODE_TOKEN`: the service
    refuses to start holding it, the host's file has to hold it for the dispatcher, so passing the
    whole file through would stop the service booting. The one-at-a-time list is load-bearing, which
    is why this reports the gap rather than closing it.
    """
    # **Not being able to look is a finding.** Item 144. This returned `[]` for *no gaps* and for
    # *I could not read the file*, which are opposite facts, and the second one was the true one on
    # every containerised deployment: the paths default to the working directory and the real files
    # live on the host. So the mechanism that would have caught every defect of 2026-08-04 reported
    # a clean bill instead of reporting that it had not run. Same category error as item 133's
    # `None` versus `0`, in a check rather than in a measurement.
    if not env_file.exists():
        return [
            Finding(
                "deployment",
                State.UNKNOWN,
                f"not checked: no environment file at {env_file}, so nothing here can compare what "
                f"you configured against what arrived. Point HULLWORK_DEPLOYMENT_ENV_FILE and "
                f"HULLWORK_DEPLOYMENT_COMPOSE_FILE at the deployment's own files, bind-mounted "
                f"read-only — inside a container the working directory holds neither.",
            )
        ]
    # **Mounted and unreadable is not the same as mounted and empty**, and until 2026-08-05 this
    # reported the second when the first was true. `variables_in_file` answers *which names are in
    # here* and answers `[]` to *I could not look*, which is the right leniency for its own question
    # and the wrong one for this check — so readability is established here, once, before asking.
    #
    # Found by arming this very check on the deployment it was written for. `deploy.env` holds
    # credentials and is mode 600 on the host, which is correct; the container runs as uid 10001,
    # which is also correct; and the two correct decisions meet in a mount the process cannot read.
    # Nobody would have guessed that from *"assigns no HULLWORK_* variable"*.
    try:
        env_file.read_text(encoding="utf-8")
    except OSError as cannot_read:
        return [
            Finding(
                "deployment",
                State.UNKNOWN,
                f"not checked: {env_file} exists and this process cannot read it "
                f"({cannot_read.strerror or cannot_read}). It is mounted and it is not readable, "
                f"which is a different problem from an empty file and from a missing one. Almost "
                f"always this: the file holds credentials and is mode 600 on the host, this "
                f"process runs as uid {os.getuid()}, and neither of those is wrong on its own. "
                f"Give the file a group this uid is in — `chown :{os.getuid()} <file>` and "
                f"`chmod 640` — rather than making a file of credentials world-readable.",
            )
        ]
    declared = variables_in_file(env_file)
    if not declared:
        return [
            Finding(
                "deployment",
                State.UNKNOWN,
                f"not checked: {env_file} exists and assigns no HULLWORK_* variable, so there is "
                f"nothing to compare. An empty file and a missing one are different problems; this "
                f"is the first.",
            )
        ]

    findings: list[Finding] = []

    for name in unset_in(settings, declared):
        half = belongs_to_one_half(name)
        if name == CODE_TOKEN:
            findings.append(
                Finding(
                    name,
                    State.EXPECTED,
                    f"assigned in {env_file} and not in this process's configuration. **Correct "
                    f"for the service** — it refuses to start holding a credential that can push "
                    f"(spec M2 §1) — and a failure for the dispatcher, the only program that needs "
                    f"it. Which of the two this process is, this check does not claim to know; the "
                    f"`code token` check asks the forge instead. Do not add it to the service.",
                )
            )
        elif half is not None:
            # **The same reasoning as the push token, and it took the check being armed to see it.**
            # Item 144, 2026-08-05. Hardcoding one exception made four correct absences read as
            # failures on this project's own instance — every model variable, in the receiver, which
            # is the half that must never hold them. The reach map that writes the compose file is
            # the authority for who reads what, so it is the authority here too.
            #
            # Deliberately not "and this process is the receiver": this check cannot know which half
            # it is (the push-token message above says so in as many words), and the checks that
            # *can* — `model credential`, `code token` — already report a genuinely missing
            # credential as `BROKEN`. So nothing is hidden by declining to guess.
            findings.append(
                Finding(
                    name,
                    State.EXPECTED,
                    f"assigned in {env_file} and not in this process's configuration, which is "
                    f"correct in one of the two halves: only the {half.value} reads it. If this "
                    f"process is the other half, nothing is wrong. If it is the {half.value} and "
                    f"the value matters, the check for that resource says so on its own line — "
                    f"this one will not guess which program it is running inside.",
                )
            )
        else:
            findings.append(
                Finding(
                    name,
                    State.BROKEN,
                    f"assigned in {env_file} and this process is running without it, so anything "
                    f"reading it behaves as though it were never configured. The file is read "
                    f"relative to the working directory: check that this process was started from "
                    f"the one holding it.",
                )
            )

    if compose_file is not None:
        passed_on = variables_in_compose(compose_file)
        if passed_on:
            for name in declared:
                if name in passed_on:
                    continue
                if name == CODE_TOKEN:
                    findings.append(
                        Finding(
                            name,
                            State.EXPECTED,
                            f"in {env_file} and deliberately absent from {compose_file.name}: the "
                            f"service refuses to start holding a credential that can push (spec "
                            f"M2 §1, item 017). Adding the line here is the 2026-07-29 boot "
                            f"failure. It belongs in the dispatcher's environment only.",
                        )
                    )
                    continue
                findings.append(
                    Finding(
                        name,
                        State.BROKEN,
                        f"assigned in {env_file} and named nowhere in {compose_file.name}, which "
                        f"lists variables one at a time — so the service never receives it and "
                        f"reports the feature as unconfigured. This is the shape of the "
                        f"2026-07-28 tracker failure.",
                    )
                )
    return findings


# --- the whole examination ---------------------------------------------------------------------


#: The checks whose subject is a resource **the dispatcher** uses, rather than the instance as a
#: whole. Run from anywhere else, a failure in one of these says nothing about whether attempts work
#: — see `not_from_here`.
DISPATCHER_RESOURCES = frozenset({"git", "docker", "model credential"})

WHERE_TO_ASK = (
    "Run the doctor where the dispatcher runs — with the compose deployment that is "
    "`docker compose exec dispatcher hullwork doctor`."
)


def not_from_here(findings: list[Finding], session: Session) -> list[Finding]:
    """Downgrade `broken` to `unknown` for resources this process does not own. Item 091.

    **The failure this fixes, measured the moment the dispatcher became a container.** From the
    host, `model credential` reported the file missing and the exit code was 1 — on an instance
    where the same check, inside the container, was `ok`. Both answers were right: the configured
    path is the bind mount's *destination*, so it exists there and not here. A path means
    different things in the two places it can be read from.

    That is the shape item 073 deleted an entire check for: a signal that is permanently on is not a
    signal, and the day the credential really expires that line is already red.

    The test is **ownership, not location**. The holder of the lease is deliberately random and
    names no machine (`lease.new_holder`), so there is nothing to compare a hostname against — and
    nothing should be. What can be established is simpler and enough: a dispatcher is alive, and it
    is not this process. Then git, Docker and the model credential are its business, and where they
    are is a question for the machine that has them. With **no** dispatcher alive, nothing is
    downgraded: the absence of one is exactly when somebody needs to know what is missing.

    Only failures are downgraded. A check that passes here is reported as passing, because a
    precondition satisfied in two places is not a puzzle.
    """
    from hullwork import lease

    try:
        state, _ = lease.state(session)
    except Exception:  # any failure here means "cannot tell", whatever its class
        # **Asking the lease is asking the database**, and this function runs in the one situation
        # where the database may have no tables in it. The doctor died with a traceback once for
        # exactly this reason (see `examine`), in the single case it exists to diagnose. Cannot tell
        # whose the resources are → downgrade nothing, and let the checks speak for themselves.
        return findings
    if state != "alive":
        return findings
    return [
        Finding(
            finding.check,
            State.UNKNOWN,
            f"not from here: {finding.detail} — but a dispatcher is running and this is a resource "
            f"it uses, not one this process does. {WHERE_TO_ASK}",
        )
        # **And only failures that are about this machine** (item 105). `local=False` marks a
        # verdict whose cause travels with the thing rather than with the reader — a token's expiry
        # is the same number from every process that can open the file. Downgrading one of those
        # does not merely lose information: it asserts a reason that is false, and points the
        # operator at a location when the location was never the problem.
        if finding.state is State.BROKEN
        and finding.local
        and finding.check in DISPATCHER_RESOURCES
        else finding
        for finding in findings
    ]


def nothing_was_left_behind(docker: str, *, asked: bool) -> Finding:
    """Whether an attempt that never ran its `finally` left objects on this host. Item 106, part 4.

    **Broken rather than a warning, and the reason is a rule this repository already states**: a
    warning wired into nothing is not a signal. Debris does not stop the next attempt — every name
    carries a random per-attempt tag, so nothing collides — but one of these volumes holds a copy of
    the model credential, and the operator's standing rule is *inventory always clean after every
    build*. There is an action that clears it, named in the message, so the verdict can afford to
    insist. In steady state this is `ok` on its own: the dispatcher reaps at start-up.

    **`asked` is not a convenience.** Where Docker cannot be reached — the receiver, by design —
    "nothing was left behind" and "nobody looked" are different answers, and the check that
    conflates them is the one item 105 was closed for.
    """
    if not asked:
        return Finding(
            "host inventory",
            State.UNKNOWN,
            "not asked: the check above could not reach the Docker daemon, so whether an "
            "interrupted attempt left anything on this host is unknown from here.",
        )
    from hullwork.sandbox import inventory

    left = inventory.find(docker)
    # **Who this instance is, said whether or not anything was found** (item 125). Every sandbox
    # object carries this label and the reaper removes only its own; on a host with two instances
    # that value is the difference between collecting debris and killing somebody else's live
    # attempt, so it belongs in the report rather than only in a compose file.
    whose = f"instance `{inventory.instance_id()}`"
    others = inventory.unclaimed(docker)
    aside = (
        f" Also on this host, left alone because it is not this instance's: {others.summary()}."
        if others
        else ""
    )
    if not left:
        return Finding(
            "host inventory",
            State.OK,
            f"nothing left behind by an earlier attempt of {whose}.{aside}",
        )
    return Finding(
        "host inventory",
        State.BROKEN,
        f"an interrupted attempt of {whose} left {left.summary()}. Starting the dispatcher clears "
        f"it, and so does removing them by name: "
        f"{', '.join([*left.containers, *left.networks, *left.volumes])}.{aside}",
    )


def which_forge(settings: Settings) -> Finding:
    """Which forge this instance can serve, said before anybody hits the wall. Item 124.

    The forge is chosen per instance, from `HULLWORK_FORGE_URL`, and every project registered here
    has to belong to it. That is a fact an operator needs *before* running `projects add` — it was
    only ever discoverable inside a refusal, and until item 124 the refusal blamed the repository.
    """
    from hullwork.forge.factory import configured_kind

    kind = configured_kind(settings)
    if kind is None or settings.forge_url is None:
        # The same condition twice — `configured_kind` answers `None` exactly when the URL is
        # unset — and both are named so the type below is provable rather than asserted.
        return Finding(
            "forge",
            State.UNKNOWN,
            "no forge configured: HULLWORK_FORGE_URL is unset, so this instance can file no issues "
            "and register no project. Ingest, deduplication and triage work without one.",
        )
    # Three forges since item 132, so "the other one" stopped being a thing: what an operator needs
    # is the two this instance cannot serve, named.
    others = {
        "github": "a self-hosted Forgejo or Gitea, or a GitLab",
        "forgejo": "GitHub, or a GitLab",
        "gitlab": "GitHub, or a self-hosted Forgejo or Gitea",
    }
    from hullwork.forge import declaration_disagrees

    conflict = declaration_disagrees(settings.forge_url, settings.forge_kind)
    if conflict is not None:
        # **`BROKEN`, and it costs nobody a night's sleep.** The pipeline works — `kind_of` resolves
        # the contradiction in the URL's favour — but two settings that cannot both be true is an
        # installation an operator did not mean to write, and it clears the moment they agree. This
        # finding reaches `hullwork doctor` only; the exit code wired into crons is `status`, which
        # reads `environment_gaps` and is untouched.
        return Finding("forge", State.BROKEN, conflict)
    return Finding(
        "forge",
        State.OK,
        f"{settings.forge_url} ({kind}). Every project registered here belongs to it; a repository "
        f"on {others.get(kind, 'another forge')} needs its own instance, with its own "
        f"HULLWORK_INSTANCE.",
    )


def model_route(settings: Settings, engine_name: str = "claude-code") -> Finding:
    """Which harness speaks what, and where its calls will go. Item 134.

    **Said before anybody hits it**, because the failure it prevents is unreadable when it arrives:
    the gateway forwards without translating, so a harness speaking one protocol family against an
    endpoint that serves another gets every call refused *by Hullwork's own gateway*, and the
    operator sees a 404 about a path they never chose.

    **No hostname table.** Whether an endpoint serves a family is a question about somebody else's
    deployment, and a built-in list of who serves what is the provider-privileging DR-0004 forbids —
    it would also be wrong within a quarter. So this reports the two sides and the rule that binds
    them, and lets a person read their own provider's documentation.
    """
    from hullwork.engine import REGISTRY

    engine = REGISTRY.get(engine_name)
    if engine is None:  # pragma: no cover - the registry ships with this name in it
        return Finding(
            "model route", State.UNKNOWN, f"no engine named {engine_name!r} is registered"
        )
    # **Only stated when this process can see it.** The receiver holds no model credential by
    # design (spec M2 §1), so saying "authenticated with nothing" there is true of this process and
    # false about the deployment — the same trap `not_from_here` exists for. Run in the dispatcher,
    # it says which path is in use; run in the receiver, it says nothing about credentials at all.
    if settings.model_key:
        credential = ", authenticated with an API key (the supported path)"
    elif settings.model_credentials_file:
        credential = (
            ", authenticated with a subscription token (development only — the plan promises not "
            "to support it)"
        )
    else:
        credential = " (no model credential in this process, which is correct for the receiver)"
    return Finding(
        "model route",
        State.OK,
        f"{engine.name} speaks the {engine.protocol} protocol family, so every call goes to "
        f"{settings.model_endpoint} in that shape{credential}. **The harness fixes the protocol**: "
        f"the gateway observes and forwards, it does not translate, so the endpoint has to serve "
        f"that family — most providers publish a compatible route, and one that does not cannot "
        f"serve this harness whatever the key.",
    )


def _any_project_names_an_agent(session: Session) -> bool | None:
    """Whether any active project would ever ask for a model. Item 135.

    The manifest is the authority (`Project.manifest`, adopted rather than followed by DR-0012), and
    `autofix.agent: none` is both the default and the whole product for a project that wants nothing
    else. So an instance where every project says `none` has no use for a model credential, and
    reporting one missing is reporting a gap nobody should close.

    **`None` when it cannot be read**, and that is a correction to this function's first form. It
    returned `True` on any failure, arguing that not knowing is not the same as knowing there is
    nothing and that the safe direction keeps telling an operator what is missing. The argument is
    right and the return type was wrong: `True` says *something needs a key*, which is a claim,
    and on an unbuilt database nothing had been established at all.

    Measured on 2026-08-04 by walking the golden path in a clean directory: the very first `doctor`
    of a fresh install — before `docker compose up`, which is what migrates — reported `AILING` with
    two broken, and one of them was a lie about a receiver-only deployment doing exactly what `init`
    had just described. **That is the failure item 135 exists to have fixed**; it fixed the readable
    case and left the first run, which is the one a stranger sees.

    One broken check must not make a second check lie. Third instance of item 133's rule today: a
    measurement of nothing is not a measurement of zero, and here it was not a measurement of *one*.
    """
    try:
        projects = session.query(Project).filter(Project.active.is_(True)).all()
    except Exception:  # a database with no tables is exactly when the doctor is typed
        return None
    for project in projects:
        manifest = project.manifest or {}
        autofix = manifest.get("autofix") if isinstance(manifest.get("autofix"), dict) else {}
        if str((autofix or {}).get("agent", "none")) != "none":
            return True
    return False


def policies(settings: Settings) -> Finding:
    """What this instance allows an attempt to do. Item 137, M12.

    Three questions somebody evaluating this for a team asks before connecting a repository, and
    until now none of them had an answer in the product: what can one attempt cost, how many run at
    once, and which models may answer.

    **Concurrency is stated rather than built, and that is the finding.** `lease.py` exists so that
    exactly one dispatcher runs against one database — two loops would both claim the same items —
    and a turn of that loop is a whole attempt. So one at a time is a property of the design, not a
    limit waiting to be raised, and the honest thing is to say so and name the alternative (a second
    instance, which item 125 made safe with per-instance labels) rather than to build parallelism
    nobody has asked for.
    """
    ceiling = (
        f"{settings.max_attempt_tokens:,} tokens" if settings.max_attempt_tokens else "none set"
    )
    allowed = settings.model_allowed or ""
    models = (
        f"{settings.model_name or 'unpinned'} only"
        if not allowed
        else f"{settings.model_name or 'unpinned'}, or any of: {allowed}"
    )
    return Finding(
        "policies",
        State.OK,
        f"cost ceiling per attempt: {ceiling} · attempts at once: 1, by design — one dispatcher "
        f"holds the lease and a turn of its loop is a whole attempt, so more means a second "
        f"instance with its own HULLWORK_INSTANCE · models that may answer: {models}.",
    )


def examine(
    session: Session,
    settings: Settings,
    *,
    code_forge: RepositoryReader | None,
    issue_reader: IssueReader | None = None,
    env_file: Path,
    compose_file: Path | None,
    docker: str = "docker",
    before_there_is_an_instance: bool = False,
) -> list[Finding]:
    """Every check, in the order an attempt needs them.

    Preconditions first and configuration second, because a broken precondition explains a
    configuration gap far more often than the other way round. The forge call is last of the
    preconditions so that an instance with no network still gets everything above it.

    **An unbuilt database stops the checks that query it, and says so.** Found by running this
    command against exactly the failure it was written to diagnose: `database_built` correctly
    reported an empty database, and then the next check asked it for `projects` and the whole
    examination died with a traceback — in the one situation where the operator has nothing else to
    go on. Skipped and named, never skipped and silent: "no projects to check" and "could not look"
    are different answers and only one of them is true here.
    """
    database = database_built(session, settings)
    if before_there_is_an_instance:
        # **The pre-flight's own state, said here rather than patched afterwards** (item 199). There
        # being no schema is what a pre-flight is *for*, so `expected` is the honest answer — and
        # the branch below, which tells a reader to fix the database, is false advice when there is
        # nothing yet to fix. One flag, one source of truth, rather than a caller rewriting strings.
        database = Finding(
            "database",
            State.EXPECTED,
            "there is no instance yet, which is what this command is for. `docker compose up` "
            "creates it and runs the migrations; `hullwork doctor` from inside says whether it "
            "worked.",
        )
    docker_says = docker_daemon(docker)
    findings = [
        git_on_path(),
        docker_says,
        database,
        which_forge(settings),
        model_credential(settings, anything_uses_it=_any_project_names_an_agent(session)),
        model_route(settings),
        policies(settings),
        nothing_was_left_behind(docker, asked=docker_says.state is State.OK),
    ]
    if database.state is not State.OK:
        why = (
            "there is no instance yet, so nothing knows which repositories it will watch. This "
            "one is answered after `docker compose up`, by `hullwork doctor` from inside."
            if before_there_is_an_instance
            else "the database above cannot be queried for the active projects, so which "
            "repositories this instance watches is unknown. Fix the database and run this again."
        )
        findings.append(Finding("code token", State.UNKNOWN, f"not asked: {why}"))
        findings.append(
            Finding(
                "inventory",
                State.UNKNOWN,
                "not asked: there is no instance yet."
                if before_there_is_an_instance
                else "not asked: the database cannot be queried.",
            )
        )
        findings.append(
            Finding(
                "deliveries",
                State.UNKNOWN,
                "not asked: when the last webhook arrived is a row in the database above.",
            )
        )
    else:
        findings.extend(code_token_reaches_repositories(session, code_forge))
        findings.extend(items_point_at_real_issues(session, issue_reader))
        findings.extend(deliveries_are_still_arriving(session, settings))
    # **A check that ran and found nothing has to say so**, or the operator cannot tell it from a
    # check that is not there. `environment_gaps` returns gaps — an empty list means *compared, and
    # clean*, and every unreadable or absent file comes back as its own `UNKNOWN` finding above. So
    # emptiness here is knowledge, and until 2026-08-05 it printed as no line at all, next to a
    # `docker` and a `database` line that always print. That is item 144's own category error one
    # step out: the first version could not tell *no gaps* from *I could not look*, and the surface
    # could not tell *checked* from *absent*. Measured on this instance — arming the check by fixing
    # a file mode made its line **disappear**, which is the wrong direction for good news.
    before = len(findings)
    findings.extend(environment_gaps(settings, env_file=env_file, compose_file=compose_file))
    # **`EXPECTED` counts as nothing wrong**, and missing that is how this line failed to appear on
    # the deployment it was written for: a correct instance still reports the push token as
    # deliberately absent from the receiver (DR-0009), so the list was not empty, so the summary
    # stayed silent on an instance with nothing wrong with it. Two different questions — *is
    # anything wrong* and *did this run* — and only the first is about the count.
    trouble = [finding for finding in findings[before:] if finding.state is not State.EXPECTED]
    if not trouble:
        declared = variables_in_file(env_file)
        against = f" and against {compose_file.name}" if compose_file else ""
        deliberate = len(findings) - before
        named = f", {deliberate} deliberate absence(s) named above" if deliberate else ""
        findings.append(
            Finding(
                "deployment",
                State.OK,
                f"{len(declared)} variable(s) assigned in {env_file} compared against this "
                f"process{against}: no gaps{named}. This is the check that would have caught the "
                f"2026-07-28 tracker failure, and it is running.",
            )
        )
    # Last, so every check has already answered for itself and this only reinterprets. Item 091.
    return not_from_here(findings, session)


# --- the input nobody watches: deliveries ---------------------------------------------------


#: How many past deliveries to read when deciding how quiet is too quiet. Enough to see a pattern,
#: few enough to be one indexed query.
_DELIVERY_HISTORY = 30

#: The floor under any derived threshold. A project can legitimately go a week without an error, and
#: an alarm that fires on a good week is an alarm somebody switches off.
_QUIET_FLOOR_SECONDS = 7 * 86400

#: The ceiling. Past a month, *"it used to arrive and now it does not"* is worth saying even for a
#: project whose errors are rare — by then a rotation, a moved address or a broken route has had
#: plenty of time to look like nothing at all.
_QUIET_CEILING_SECONDS = 30 * 86400


def _how_quiet_is_too_quiet(gaps: list[float]) -> float:
    """The longest silence that would still be normal for this project, from its own history.

    **Derived rather than chosen**, because a fixed number is wrong in both directions at once: a
    project with an error an hour is broken after a day of silence, and one with an error a month is
    fine after three weeks. The longest gap this project has actually shown, doubled, then bounded.
    """
    if not gaps:
        return _QUIET_FLOOR_SECONDS
    return min(max(max(gaps) * 2, _QUIET_FLOOR_SECONDS), _QUIET_CEILING_SECONDS)


def deliveries_are_still_arriving(session: Session, settings: Settings) -> list[Finding]:
    """Whether the webhook path is still delivering, per project. Item 158.

    **Nothing watched this, and it had been dead for a week.** Found on 2026-08-06 by following an
    event that had reached the tracker and never became an item: the token the tracker held answered
    `401`, and the tracker's container could not route to the receiver's address at all. Two
    independent faults, and the last delivery on the instance was eight days old.

    It was invisible because the **inventory sweep** covers for it — the sweep polls the tracker's
    unresolved issues per project and had been filing items all along. So the loop kept working with
    half its input gone, which is the shape this whole module exists to end: `status` says what has
    happened, `doctor` says what is broken, and neither knew.

    **Three answers, and the middle one is why this is not two.**

    * *No tracker configured* → `expected`. Nothing is supposed to arrive, and saying so is not the
      same as saying nothing is wrong.
    * *Configured and nothing has ever arrived* → `unknown`. A project registered ten minutes ago
      and one whose webhook was never pasted into the tracker look identical from here, and guessing
      which would be inventing an answer.
    * *Arrived, and then stopped for longer than this project's own history explains* → `broken`,
      with both dates, because the useful sentence is *"it used to work"*.
    """
    projects = session.execute(
        select(Project).where(Project.active.is_(True)).order_by(Project.slug)
    ).scalars().all()
    if not projects:
        return [Finding("deliveries", State.OK, "no active project, so nothing is expected")]

    tracker_configured = bool(settings.tracker_url)
    now = datetime.now(UTC)
    findings: list[Finding] = []

    for project in projects:
        received = list(
            session.execute(
                select(Delivery.received_at)
                .where(Delivery.project_id == project.id)
                .order_by(Delivery.received_at.desc())
                .limit(_DELIVERY_HISTORY)
            ).scalars().all()
        )

        if not tracker_configured and project.tracker_project is None:
            findings.append(
                Finding(
                    "deliveries",
                    State.EXPECTED,
                    f"{project.slug}: no tracker configured, so no webhook is expected. Items "
                    f"can still arrive through `hullwork` normalisers.",
                )
            )
            continue

        if not received:
            findings.append(
                Finding(
                    "deliveries",
                    State.UNKNOWN,
                    f"{project.slug}: a tracker is configured and **no delivery has ever "
                    f"arrived**. Either the webhook URL was never pasted into the tracker, or this "
                    f"project was registered recently. `hullwork projects rotate-secret "
                    f"{project.slug}` prints the URL again — the token cannot be shown twice.",
                )
            )
            continue

        # **No defence against naive datetimes here, and that is deliberate.** `UtcDateTime` refuses
        # to *store* one — *"refusing to store a naive datetime; attach a timezone at the source"* —
        # so a reader cannot be handed one, and a branch for it would be code that can never run
        # pretending to be care. Found by a test written to exercise that branch, which could not
        # create the row.
        latest = received[0]
        silence = (now - latest).total_seconds()
        gaps = [(a - b).total_seconds() for a, b in itertools.pairwise(received)]
        allowed = _how_quiet_is_too_quiet(gaps)

        if silence > allowed:
            findings.append(
                Finding(
                    "deliveries",
                    State.BROKEN,
                    f"{project.slug}: deliveries stopped. The last one arrived "
                    f"{_span(silence)} ago ({latest.date()}), and this project has never been "
                    f"quiet for more than {_span(allowed / 2)}. Two usual causes: a webhook token "
                    f"rotated without updating the tracker, and a tracker that cannot reach this "
                    f"address at all — check both, in that order. The inventory sweep keeps filing "
                    f"items either way, which is why nothing else complained.",
                )
            )
        else:
            findings.append(
                Finding(
                    "deliveries",
                    State.OK,
                    f"{project.slug}: last delivery {_span(silence)} ago, within the "
                    f"{_span(allowed)} this project's own history explains",
                )
            )
    return findings
