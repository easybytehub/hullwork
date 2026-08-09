"""`hullwork work` — the second program, and the only one that may push.

Item 029, and the piece the whole of M2 has been assembling towards. It ties the parts together and
owns every credential the service is forbidden from holding:

```
claim the item → clone → build the image → start the gateway → dispatch → publish → record
```

Spec M2 §1 makes this a separate process for two reasons that are both about blast radius. It holds
the credential that can push, and the service — which listens on the network and runs for weeks —
must not. And it needs the Docker daemon, which is root-equivalent on its host, so it exits rather
than lingering with that reachable.

**Claiming happens in a committed transaction before anything else.** Two dispatchers on one item
would otherwise produce two attempts, two branches and two pull requests for one bug — the same
shape of bug item 018 found in the sweep, where selecting was mistaken for claiming.
"""

import base64
import logging
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from hullwork import attempts, spend
from hullwork.config import Settings
from hullwork.gateway import Recording
from hullwork.manifest import RuntimeConfig
from hullwork.models import Attempt, AttemptOutcome, Item, ItemKind, ItemState, Lane, Project
from hullwork.scrub import instance_secrets
from hullwork.states import can, transition

log = logging.getLogger(__name__)

#: An item that has been `in-progress` longer than this had its dispatcher killed. Generous: an
#: attempt is two model phases and up to four suite runs, and declaring a live one dead would
#: produce exactly the double dispatch claiming exists to prevent.
STALE_AFTER = timedelta(hours=3)

#: A clone that has not finished by now is a repository too large for one attempt to be worth it.
CLONE_TIMEOUT_SECONDS = 600

#: Attributed to the tool, not to a person. A plausible human identity on these commits would
#: imply somebody reviewed them, which is the claim the whole product exists not to make.
#: `.invalid` is reserved by RFC 6761 precisely so an address can be honest about not being one.
COMMIT_AUTHOR = "Hullwork"
COMMIT_EMAIL = "hullwork@hullwork.invalid"

#: How a failed publication is recorded on the attempt, and how it is found again. Item 077.
#:
#: One constant because four places must agree about it: `publish` writes it, `readiness_notes`
#: searches for it, `republish` clears it, and the comment `republish` posts must **not** carry it.
#: They were three separate literals and one `LIKE` pattern, which is a defect waiting for somebody
#: to reword the message.
PUBLICATION_FAILED = "publishing failed: "


def publication_failure(attempt: "Attempt") -> str | None:
    """The publication failure recorded on this attempt, or `None`. Item 077."""
    for line in (attempt.error or "").splitlines():
        if line.startswith(PUBLICATION_FAILED):
            return line[len(PUBLICATION_FAILED) :].strip()
    return None


def verdict_detail(attempt: "Attempt") -> str:
    """The attempt's error **without** the publication failures. Item 077.

    `attempt.error` holds two different facts in one column: what the run concluded, and what went
    wrong sending it somewhere. A retried comment must carry the first and never the second — the
    reader of an issue needs the verdict, not this instance's HTTP trouble from three days ago.
    """
    kept = [
        line for line in (attempt.error or "").splitlines()
        if not line.startswith(PUBLICATION_FAILED)
    ]
    return "\n".join(kept).strip()


class WiringError(RuntimeError):
    """The dispatcher could not build what an attempt needs.

    Never the agent's fault, so `run_one` turns it into an abandoned attempt that leaves the item
    its one try. A missing dependency file and an unreachable forge are the same kind of fact here:
    something on this side is not ready.
    """


@dataclass(frozen=True)
class Checkout:
    """A clone the host made, at the exact commit the gates will run against.

    The `sha` matters more than the path. Everything the evidence trail claims — this test failed
    here and passes there — is a claim about this commit, and the branch the pull request is rooted
    at is this commit rather than wherever the default branch has moved to since (spec M2 §5.1).
    """

    path: Path
    sha: str


def clone_url(settings: Settings, project: Project) -> str:
    """Where to clone from, from the operator's configuration rather than the repository's claim.

    Registration already refuses a manifest whose provider disagrees with the instance (item 017),
    so these cannot drift — and if they ever did, the operator's value is the one to believe.
    """
    if project.forge == "github":
        return f"https://github.com/{project.repo}.git"
    if not settings.forge_url:
        msg = "HULLWORK_FORGE_URL is not set, so there is nothing to clone from"
        raise WiringError(msg)
    # GitLab included: its clone URL is the project path under the instance host, subgroups and
    # all, which is the one place a nested path needs **no** encoding — git wants the slashes.
    return f"{settings.forge_url.rstrip('/')}/{project.repo}.git"


def checkout(url: str, token: str, *, into: Path, ref: str | None = None) -> Checkout:
    """Clone with the code credential, at `ref` or the default branch, and leave no credential.

    **The credential goes in the environment, not in the URL.** Spec M2 §4.6 measured that a token
    in a clone URL persists verbatim in `.git/config`, in clear text. `GIT_CONFIG_COUNT` sets the
    header for this process only: verified 2026-07-28 against a live Forgejo *and* GitHub with the
    same `Authorization: Basic base64("x-access-token:<token>")` — one code path for both — and the
    token searched for afterwards in every file of the resulting tree, absent from all of them. It
    is also not on the command line, where `ps` would show it to any user on the host.

    The operator's own git configuration is switched off for the same reason the sandbox exists.
    Aliases, `core.pager`, `credential.helper` and hooks are all commands git will run, and a
    dispatcher that inherits them is a dispatcher whose behaviour depends on whoever set up the
    account it runs as.

    A full clone rather than `--depth 1`: the ref the gates run against may be any commit, and a
    shallow clone that then cannot check it out has to be thrown away and made again.
    """
    credential = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {credential}",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
    }
    _git(["clone", "--quiet", url, str(into)], env=env, secret=token)
    if ref:
        _git(["-C", str(into), "checkout", "--quiet", "--detach", ref], env=env, secret=token)
    head = _git(["-C", str(into), "rev-parse", "HEAD"], env=env, secret=token).strip()
    _sanitise(into, env=env, secret=token)
    log.info("checked out", extra={"sha": head, "ref": ref or "default branch"})
    return Checkout(path=into, sha=head)


def _sanitise(clone: Path, *, env: dict[str, str], secret: str) -> None:
    """Strip everything from the clone that could later run as us, before anything else runs.

    Spec M2 §4.6. The worktree that reaches the sandbox is a copy without `.git` at all
    (`dispatch.prepare_worktree`), so this is the second of two controls rather than the only one —
    and it is the one that still holds if somebody ever mounts a checkout directly. Removing the
    remote also means an agent that somehow obtained a credential has nowhere to push it.

    Every step tolerates "it was not set": `--unset-all` on an absent key exits 5, which is the
    answer we wanted, not a failure.
    """
    _git(["-C", str(clone), "remote", "remove", "origin"], env=env, secret=secret, check=False)
    for key in ("credential.helper", "http.extraHeader"):
        _git(
            ["-C", str(clone), "config", "--local", "--unset-all", key],
            env=env, secret=secret, check=False,
        )
    _git(
        ["-C", str(clone), "config", "--local", "core.hooksPath", os.devnull],
        env=env, secret=secret, check=False,
    )
    hooks = clone / ".git" / "hooks"
    if hooks.is_dir():
        shutil.rmtree(hooks, ignore_errors=True)


def _git(
    argv: list[str], *, env: dict[str, str], secret: str, check: bool = True
) -> str:
    """Run git on the host, with the credential redacted out of anything it says.

    Legitimate here and nowhere near the agent's tree: §4.1's rule is that no host process runs git
    in a tree the agent has had access to, and this runs before the agent exists.
    """
    binary = shutil.which("git")
    if binary is None:
        msg = "git is not on PATH; the dispatcher clones the repository itself"
        raise WiringError(msg)
    completed = subprocess.run(  # noqa: S603 - argv list, no shell, binary resolved above
        [binary, *argv],
        capture_output=True, text=True, timeout=CLONE_TIMEOUT_SECONDS,
        check=False, env=env, stdin=subprocess.DEVNULL,
    )
    if check and completed.returncode != 0:
        said = (completed.stderr or completed.stdout).replace(secret, "[redacted]").strip()
        msg = f"git {argv[0]} failed: {said[-500:]}"
        raise WiringError(msg)
    return completed.stdout


def dependency_files(clone: Path, runtime: RuntimeConfig) -> dict[str, bytes]:
    """The files the sandbox image is built from, read out of the checkout.

    They are the image's cache key (item 037), so a missing one is refused rather than skipped: an
    image built from *some* of the declared dependencies would be reused under a tag that claims to
    describe all of them.
    """
    files: dict[str, bytes] = {}
    for declared in runtime.dependencies:
        target = clone / declared
        if not target.is_file():
            msg = (
                f"the manifest declares the dependency file {declared!r} and it is not in the "
                f"repository, so the sandbox image would be built from an incomplete set"
            )
            raise WiringError(msg)
        files[declared] = target.read_bytes()
    return files


@dataclass(frozen=True)
class Note:
    """One thing to tell the operator, and whether it means the instance is not working.

    The flag exists because the first version of this printed a perfectly clear sentence — "items
    are ready and no credential is configured, so nothing will ever pick them up" — and then exited
    zero. A monitoring line reading the exit code would have called that healthy for ever, which is
    the shape of failure item 019 was written to end.
    """

    text: str
    degraded: bool = False


@dataclass(frozen=True)
class Eligible:
    """An item the dispatcher may work on, and why it may."""

    item: Item
    project: Project


def _enrichment_is_pending(item: Item, *, tracker_configured: bool) -> bool:
    """Whether this item is still owed a pass that would give the agent frames. Item 100.

    **A sixth condition, and the operator decided its shape.** Measured on attempt 20: the item was
    filed by `sweep_inventory`, which reads the tracker's *list* route — issue metadata, no frames —
    and the dispatcher claimed it within the minute, before `fetch_context` had run on its own
    clock. So the brief carried the issue title and nothing else: no exception type, no frames, no
    locals, no release, where the three attempts before it had all had them. The agent located the
    defect anyway and bounded its own claim honestly. On a bigger repository it would have guessed.

    **`context_checked_at IS NULL` is the whole test**, and the distinction is between *dispatching
    early* and *dispatching without evidence*:

    * never asked → wait. One pass of `fetch_context` costs one HTTP request and arrives within a
      minute; an attempt costs a clone, an image, a container and a model.
    * asked and the tracker had nothing → **go**, with the title. That is a legitimate outcome and
      `not-reproducible` on a title alone is the correct answer, which the brief says out loud.

    **The condition is "a pass is pending", not "nobody has asked", and the difference is a
    deadlock.**
    The first version of this asked only `context_checked_at IS NULL` — and `fetch_context` returns
    immediately when no tracker is configured, which is a supported configuration (DR-0008:
    *"Without
    `errors.tracker` configured there are no frames"*). On such an instance nothing would ever set
    the
    timestamp, so nothing would ever become eligible and the whole product would stop, quietly, for
    everybody who connected a forge and no tracker. Six existing tests failed on exactly that and
    were
    right to: their fixtures configure no tracker, which is the case that would have hung.

    So the wait applies only where there is something to wait *for*. With no tracker, an item that
    will
    never be enriched is dispatched with what it has, which is the same answer as an enrichment that
    came back empty.
    """
    if not tracker_configured:
        return False
    return item.context_checked_at is None


def eligible(
    session: Session,
    *,
    limit: int = 1,
    slug: str | None = None,
    tracker_configured: bool = False,
) -> list[Eligible]:
    """Items ready to be attempted, oldest first. All five of item 025's conditions.

    Red is excluded by the query **and** refused by the state machine. Item 017's whole point is
    that a guardrail depending on every caller remembering it is not a guardrail, so this is the
    convenient filter and `states.can` is the real one.

    Item 044 added the three that were missing, and the third is the one that matters:

    * **`kind` must be `bug`.** The red-green gate is about bugs; an agent handed a chore has
      nothing to reproduce.
    * **The project's manifest must name an agent.** `route()` refuses to move an item out of
      `triaged` when it does not, so an item sitting in `ready` on such a project can only be a
      leftover from a manifest edited since — exactly the case a dispatcher must not act on.
    * **The item must have an attempt left.** `has_attempt_left` was written, tested, and called
      from nowhere, so DR-0003's one-attempt rule held only as a side effect of `failed` and
      `not-reproducible` being terminal states. Item 042 declared `in-progress → ready`, item 043
      added a non-consuming outcome, and DR-0006's dry run wants to return items to `ready` too —
      any one of those turns a side effect into a retry loop, and no test would have caught it.
    """
    query = (
        select(Item, Project)
        .join(Project, Project.id == Item.project_id)
        .where(
            Item.state == ItemState.READY,
            Item.lane != Lane.RED,
            Item.kind == ItemKind.BUG,
            Project.active.is_(True),
        )
        .order_by(Item.id)
    )
    if slug:
        query = query.where(Project.slug == slug)

    out: list[Eligible] = []
    for item, project in session.execute(query).all():
        if not can(item, ItemState.IN_PROGRESS):
            continue
        if not attempts.has_attempt_left(session, item):
            continue
        if not _names_an_agent(project):
            continue
        # Item 100's sixth condition. `False` by default so a caller that does not know cannot hang
        # an
        # instance by omission — the failure this guards against is a brief with no evidence, and
        # the
        # failure of getting it wrong the other way is an instance that never works at all.
        if _enrichment_is_pending(item, tracker_configured=tracker_configured):
            continue
        out.append(Eligible(item=item, project=project))
        if len(out) >= limit:
            break
    return out


def _names_an_agent(project: Project) -> bool:
    """Whether this project's own rules permit an agent at all.

    Through `ingest._manifest_for` rather than by reading the JSON column, so one place decides what
    a project's rules are — and that place already degrades to a lanes-less manifest, loudly, when a
    cached copy stops validating. Reading the column here would be a second interpretation that
    disagreed with the first on exactly the day the schema changed.

    Imported locally because `run_one` below does the same for the same helper; a module-level
    import would be the only one in this file and would read as an accident.
    """
    from hullwork.ingest import _manifest_for

    try:
        return _manifest_for(project).autofix.agent != "none"
    except ValueError:
        # No cached manifest at all. Not eligible, and not this function's business to decide what
        # that means — `_manifest_for` has already said so where somebody will see it.
        return False


def claim(session: Session, item: Item) -> bool:
    """Take the item, or say somebody else has it. Committed before the caller does anything.

    The commit is the point. Item 018 found the sweep filing two issues for one item because
    selecting rows is not claiming them, and the window between "decide to act" and "record that I
    am acting" is a whole container start here.
    """
    if not can(item, ItemState.IN_PROGRESS):
        return False
    transition(item, ItemState.IN_PROGRESS)
    session.commit()
    log.info("claimed item", extra={"item": item.id})
    return True


def release(
    session: Session, item: Item, outcome: AttemptOutcome, *, rehearsal: bool = False
) -> None:
    """Put the item where the outcome says it belongs.

    **A rehearsal settles nothing** (item 049). Measured before this existed: a dry run reaching a
    `pr-open` verdict parked the item in `pr-open`, asserting a pull request that did not exist,
    with no legal edge back to `ready`. The verdict is still recorded; the item goes back in the
    queue, because nothing about it has actually been dealt with.

    The mapping is DR-0003's, and the two outcomes that go back to `ready` are the ones where the
    agent was never given a fair try. Everything else is terminal until a human moves it, because
    an item gets one attempt.
    """
    if rehearsal:
        transition(item, _somewhere_it_may_go(item))
        session.commit()
        return
    if outcome in (AttemptOutcome.PR_OPEN, AttemptOutcome.PR_OPEN_LINT_FAILED):
        # Both open a pull request, so both leave the item where a human has something to read. The
        # difference between them is what the artefact says, not what the item is waiting for.
        transition(item, ItemState.PR_OPEN)
    elif outcome is AttemptOutcome.NOT_REPRODUCIBLE:
        transition(item, ItemState.NOT_REPRODUCIBLE)
    elif outcome is AttemptOutcome.FAILED:
        transition(item, ItemState.FAILED)
    elif outcome is AttemptOutcome.BASELINE_RED:
        # Item 043. The one outcome that neither consumes the attempt nor returns the item to the
        # queue: the suite was red before anything was touched and will still be red next pass, so
        # requeueing it is a loop and settling it is a lie. A person decides.
        transition(item, ItemState.HUMAN_ONLY)
    else:
        # `abandoned` and `already-fixed`. Neither is about the bug, so neither settles it: the item
        # goes back in the queue with its try intact.
        #
        # Item 042: this used to assign `item.state` directly, because the edge did not exist. A
        # module whose reason for existing is that a guardrail depending on every caller is not a
        # guardrail had exactly one caller going around it, and DR-0006's dry run was about to need
        # the same edge — which would have made the hole load-bearing for the mode that runs on
        # other people's machines first.
        transition(item, _somewhere_it_may_go(item))
    session.commit()


def _somewhere_it_may_go(item: Item) -> ItemState:
    """Back to the queue, unless the item is red — in which case a human, not an exception.

    `ready` is an agent state and the machine refuses those to the red lane. An item can only be
    red *and* in progress if its lane changed underneath a running attempt, which nothing does
    today; but raising here would abort after work that has already been done and recorded, and the
    correct answer for a red item was never `ready` anyway.
    """
    return ItemState.READY if can(item, ItemState.READY) else ItemState.HUMAN_ONLY


def release_stale(
    session: Session, *, now: datetime | None = None, took_the_lease: bool = False
) -> list[int]:
    """Free items whose dispatcher died mid-attempt, and say which.

    Without this an operator has to edit the database by hand after a power cut, which is the sort
    of instruction that ends up in a wiki nobody finds. The attempt row stays: it happened, it
    reached whatever phase it reached, and deleting it would erase the evidence that this item has
    already cost something.

    **`took_the_lease` skips the clock, and it is sound because of what `acquire` refuses**
    (item 097). A lease only changes hands when the previous holder released it or let it expire, so
    a *different* holder now owning it is proof the old one is gone — stronger proof than any
    timeout, and available immediately.

    Without it, `STALE_AFTER` is three hours. Measured on the live instance: a `docker compose
    stop` during an attempt left the item `in-progress`, `hullwork work --release-stale` said
    *"no item has been in-progress long enough to be stale"*, and the recovery was to call this
    function with `now` pushed past the cutoff. The three hours are right for a dispatcher that
    died unnoticed and wrong for the case an operator is in every time they stop the service.
    """
    cutoff = (now or datetime.now(UTC)) - STALE_AFTER
    freed: list[int] = []
    claimed = select(Item).where(Item.state == ItemState.IN_PROGRESS)
    stuck = session.execute(
        claimed if took_the_lease else claimed.where(Item.updated_at < cutoff)
    ).scalars()
    for item in stuck:
        latest = session.execute(
            select(Attempt)
            .where(Attempt.item_id == item.id, Attempt.finished_at.is_(None))
            .order_by(Attempt.started_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if latest is not None:
            # Through `attempts.finish`, not by assigning the three fields here. Its docstring
            # says it decides "in one place whether it spent the item's one shot", and this was the
            # second place — a copy that would have gone on agreeing with the original right up
            # until the day one of them changed (item 042).
            attempts.finish(
                session,
                latest,
                AttemptOutcome.ABANDONED,
                not_consumed_reason=(
                    "the dispatcher that claimed this did not finish, and a different dispatcher "
                    "now holds the lease — so the first one is gone and this item still has its try"
                    if took_the_lease
                    else "the dispatcher did not finish; the attempt was released as stale, so "
                    "this item still has its try"
                ),
            )
            latest.finished_at = now or datetime.now(UTC)
        transition(item, _somewhere_it_may_go(item))
        freed.append(item.id)
    if freed:
        session.commit()
        log.warning("released stale attempts", extra={"items": freed})
    return freed


def unpublished_verdicts(session: Session) -> list[Attempt]:
    """Attempts that reached a verdict and could not send it anywhere. Item 077.

    One query in one place, because `status` reads it to report and `republish` reads it to act, and
    two `LIKE` patterns that drift apart would give an operator a warning with no command that
    matches it.
    """
    return list(
        session.execute(
            select(Attempt)
            .where(Attempt.error.like(f"%{PUBLICATION_FAILED}%"))
            .order_by(Attempt.id)
        ).scalars().all()
    )


#: Written to the attempt when an operator decides a verdict has no destination. Item 077.
#:
#: Kept as a recorded fact rather than a deletion: the verdict stays, the publication failure stays
#: readable in the sentence, and what changes is that a human has looked at it. DR-0003 forbids
#: quietly dropping a first-class result; it says nothing against writing down a decision.
GAVE_UP_PUBLISHING = "publication given up by the operator: "


class PublicationError(RuntimeError):
    """A republication that cannot honestly be attempted. Carries what to do instead."""


def republish(
    session: Session,
    attempt: Attempt,
    *,
    forge: object | None,
    repo: str,
    code_forge: object | None = None,
    secrets: list[str] | None = None,
    #: For the cost row of the rebuilt body (item 133). Defaulting to `None` keeps every existing
    #: caller printing exactly what it printed before.
    prices: "spend.Prices | None" = None,
) -> str | None:
    """Send an already-reached verdict where it was always meant to go. Item 077.

    **Nothing is re-run and no model is called.** The verdict is a fact in this database and the
    attempt is already spent; what failed was the last step, and DR-0003 calls the result
    first-class, so there has to be a way to finish it. `publish` records the failure instead of
    raising on purpose — a lost comment must not turn a recorded verdict into an abandoned attempt —
    and until now nothing could act on what it recorded.

    **A `pr-open` verdict is finished by asking the forge, not by rebuilding it** (item 079, option
    C). The refusal this used to make was wider than the facts: *"the files the agent wrote are not
    stored anywhere"* is true, and it only matters when the branch was never created. `publish` puts
    the durable thing first — create the branch, make both commits, and only then compose the body
    and
    open the pull request — so a publication that failed at the last step left both commits on the
    forge, and `branch` and `base_sha` are columns on the attempt. Nothing needs rebuilding: what is
    missing is one API call.

    So the two cases are told apart, and only one of them is refused:

    * **the branch is there** — the pull request is opened from what is already stored, with the
    body
      rendered again from this database (the brief is derived from the item, the steps and their
      output are rows, the seal is a column). This needs the **code** credential, because opening a
      pull request is a code write; commenting is the ingest one (spec M2 §1).
    * **the branch is not there** — the fix is genuinely gone, and that is said exactly rather than
      as a claim about the database. Attempting it would push two empty commits and open a pull
      request claiming a fix nobody made.

    The second case has never happened: a forge that refuses `create_branch` and accepts everything
    else a day later is not a failure this instance has seen. Storing the file bodies against it is
    the shape this repository has been wrong about before — `openhands` parsed and resolved to
    nothing, the lint gate shipped on with nothing behind it — so item 079 keeps that half open,
    waiting for a real occurrence rather than for an argument.

    On success the publication failure is removed and **the verdict text is kept**: they share one
    column, and leaving the failure there would keep `status` reporting a publication that has
    happened.
    """
    failure = publication_failure(attempt)
    if failure is None:
        msg = (
            f"attempt {attempt.id} has no failed publication to retry. "
            f"`hullwork status` lists the ones that do."
        )
        raise PublicationError(msg)

    item = session.get(Item, attempt.item_id)
    if item is None:  # pragma: no cover - a foreign key makes this unreachable
        msg = f"attempt {attempt.id} points at item {attempt.item_id}, which is not there"
        raise PublicationError(msg)

    if attempt.outcome in (AttemptOutcome.PR_OPEN, AttemptOutcome.PR_OPEN_LINT_FAILED):
        return _open_the_pull_request_the_branch_is_waiting_for(
            session, attempt, item, code_forge=code_forge, repo=repo, secrets=secrets,
            prices=prices,
        )
    if forge is None:
        msg = (
            "no forge is configured, so there is nowhere to publish to. Set HULLWORK_FORGE_URL and "
            "HULLWORK_FORGE_TOKEN — the ingest credential is the one that comments (spec M2 §1)."
        )
        raise PublicationError(msg)
    if not item.forge_issue_ref:
        msg = (
            f"item {item.id} has no issue, so its verdict has no destination. It was never filed — "
            f"`hullwork status` reports items still owed an issue."
        )
        raise PublicationError(msg)

    # The detail is the verdict and never the publication failure. Rendered here rather than inside
    # `_comment`, which reads `attempt.error` whole — correct at first publication, when the failure
    # line does not exist yet, and wrong on every retry.
    from hullwork import evidence
    from hullwork.forge import ForgeError

    number = int(item.forge_issue_ref.lstrip("#"))
    body = evidence.issue_comment(item, attempt, detail=verdict_detail(attempt), secrets=secrets)
    try:
        forge.comment(repo, number, body)  # type: ignore[attr-defined]
    except ForgeError as exc:
        # Left exactly as it was, still reported. A command that swallowed its own failure would be
        # worse than one that does nothing: the operator would believe the verdict is out.
        log.warning(
            "republishing failed again",
            extra={"attempt": attempt.id, "issue": number, "error": str(exc)},
        )
        msg = (
            f"still cannot publish attempt {attempt.id} to {repo}{item.forge_issue_ref}: {exc}\n"
            f"  The attempt is unchanged and `hullwork status` still reports it. If the issue does "
            f"not exist the retry will never succeed — `--give-up` records that this verdict has "
            f"nowhere to go."
        )
        raise PublicationError(msg) from exc

    attempt.error = verdict_detail(attempt) or None
    session.commit()
    log.info(
        "republished a stranded verdict",
        extra={"attempt": attempt.id, "item": item.id, "issue": number},
    )
    return item.forge_issue_ref


def _open_the_pull_request_the_branch_is_waiting_for(
    session: Session,
    attempt: Attempt,
    item: Item,
    *,
    code_forge: object | None,
    repo: str,
    secrets: list[str] | None,
    #: Passed in rather than read from settings here: this module takes its configuration from its
    #: caller, and a function that reaches for `get_settings()` is one that cannot be tested with
    #: two price lists. `None` means the body prints tokens and no money (item 133).
    prices: "spend.Prices | None" = None,
) -> str | None:
    """Finish a `pr-open` verdict whose branch is already on the forge. Item 079, option C.

    Everything the pull request body needs is in this database or derived from it: the brief is a
    function of the item and its fetched events, the steps and their output are rows, the seal and
    the
    base commit are columns. The two commits are on the forge. What was missing was the last call.
    """
    from hullwork import evidence
    from hullwork.brief import build as build_brief
    from hullwork.brief import evidence_level as brief_evidence_level
    from hullwork.forge import ForgeError

    if not attempt.branch or not attempt.base_sha:
        msg = (
            f"attempt {attempt.id} reached `pr-open` and recorded no branch, so publication failed "
            f"before anything reached the forge. The files the agent wrote are not stored anywhere "
            f"(item 079), so there is nothing to open a pull request from — what is available is "
            f"the record, and a decision about re-running the item, which costs its attempt again."
        )
        raise PublicationError(msg)
    if code_forge is None:
        msg = (
            "opening a pull request needs the code credential, and only the ingest one is "
            "configured. Set HULLWORK_FORGE_CODE_TOKEN where the dispatcher runs — the receiver "
            "must never hold it (spec M2 §1)."
        )
        raise PublicationError(msg)

    # **Asked, not assumed.** This is the whole of option C: the branch is either there with the
    # agent's work in it, or publication failed before it existed, and those two have different
    # answers. Guessing either way is how the old refusal came to be wider than the facts.
    try:
        head = code_forge.head_commit(repo, attempt.branch)  # type: ignore[attr-defined]
    except ForgeError as exc:
        msg = (
            f"could not ask {repo} whether branch {attempt.branch!r} exists: {exc}\n"
            f"  The attempt is unchanged. This says nothing about the branch — try again when the "
            f"forge answers."
        )
        raise PublicationError(msg) from exc

    if head is None or head == attempt.base_sha:
        # The branch is missing, or it is still sitting at the base with no commits on it. Either
        # way the agent's work is not on the forge and cannot be put there from here.
        where = (
            "does not exist"
            if head is None
            else "is still at the base commit with no commits on it"
        )
        msg = (
            f"attempt {attempt.id} reached `pr-open` but branch {attempt.branch!r} {where}, so "
            f"publication failed before the agent's work reached the forge. The files it wrote are "
            f"not stored anywhere (item 079). Opening a pull request now would claim a fix nobody "
            f"made."
        )
        raise PublicationError(msg)

    body = evidence.pull_request_body(
        item,
        attempt,
        detail=verdict_detail(attempt),
        brief_text=build_brief(session, item),
        brief_evidence=brief_evidence_level(session, item),
        secrets=secrets,
        prices=prices,
    )
    try:
        pull = code_forge.open_draft_pull_request(  # type: ignore[attr-defined]
            repo,
            head=attempt.branch,
            base=code_forge.default_branch(repo),  # type: ignore[attr-defined]
            title=f"fix: {item.title.splitlines()[0][:68]}" if item.title else "fix from Hullwork",
            body=body,
        )
    except ForgeError as exc:
        log.warning(
            "republishing a pull request failed again",
            extra={"attempt": attempt.id, "branch": attempt.branch, "error": str(exc)},
        )
        msg = (
            f"still cannot open a pull request for attempt {attempt.id} on {repo}: {exc}\n"
            f"  Branch {attempt.branch!r} is intact with the agent's commits on it, so this is "
            f"retryable. `--give-up` records that this verdict has nowhere to go."
        )
        raise PublicationError(msg) from exc

    attempt.pull_request_ref = str(pull.ref)
    attempt.error = verdict_detail(attempt) or None
    if not pull.draft:
        # The same read-back `publish` makes, for the same reason: Forgejo derives draft from a
        # title
        # prefix the instance can reconfigure, and a merge-ready pull request from a bot is the one
        # artefact this product must never leave behind.
        log.error("the forge did not mark it a draft", extra={"pull": pull.ref})
    session.commit()
    log.info(
        "opened the pull request a stranded verdict was waiting for",
        extra={"attempt": attempt.id, "item": item.id, "pull": pull.ref, "branch": attempt.branch},
    )
    return str(pull.html_url)


def give_up_publishing(session: Session, attempt: Attempt, *, why: str) -> None:
    """Record that a verdict has no destination, and stop reporting it. Item 077.

    For the case a retry can never fix: attempt 11's issue `#3` does not exist, so its 404 is
    permanent and the warning would stand for the life of the instance — a non-zero exit code in a
    cron line with no action available to clear it, which is the always-on signal item 073 removed.

    **A human types this, one attempt at a time.** There is deliberately no `--all`, for the reason
    `approve` has none. And it writes down what happened rather than erasing it: the verdict stays,
    the failure stays readable inside the sentence, and what is added is that somebody decided.
    """
    failure = publication_failure(attempt)
    if failure is None:
        msg = (
            f"attempt {attempt.id} has no failed publication, so there is nothing to give up on. "
            f"This is not a way to remove a verdict that was published."
        )
        raise PublicationError(msg)

    verdict = verdict_detail(attempt)
    attempt.error = "\n".join(
        part for part in (verdict, f"{GAVE_UP_PUBLISHING}{failure} — {why}") if part
    )
    session.commit()
    log.warning(
        "publication given up",
        extra={"attempt": attempt.id, "why": why, "failure": failure},
    )


def readiness_notes(
    session: Session, *, code_token_configured: bool, forge: object | None = None
) -> list[Note]:
    """What `hullwork status` should say about the dispatcher half.

    Spec §8 promised this and there was nowhere for the numbers to come from until item 038 existed.
    Written as sentences rather than counters because the useful ones are conditional: "three items
    are ready and no engine is configured" is actionable, and "ready: 3" is not.

    **Reads a built schema and says so rather than defending itself** (2026-08-04). This queries
    unguarded, and against a database with no tables it raises — which was the *second* of three
    causes of one symptom, `hullwork status` printing a raw `OperationalError`. Guarding each of the
    three was the wrong shape: the fact is singular, *this database has no schema*, and the caller
    establishes it once through `doctor.database_built`, which exists for exactly this and compares
    against what the models declare.
    """
    notes: list[Note] = []
    ready = session.execute(
        select(Item).where(Item.state == ItemState.READY, Item.lane != Lane.RED)
    ).scalars().all()
    in_progress = session.execute(
        select(Item).where(Item.state == ItemState.IN_PROGRESS)
    ).scalars().all()

    if ready and not code_token_configured:
        # A degradation, not a note. Items only reach `ready` when a manifest names an agent, so
        # this state means somebody configured one and never gave the dispatcher a credential —
        # work that will sit there for ever while everything reports fine.
        notes.append(
            Note(
                f"{len(ready)} item(s) are ready to attempt and HULLWORK_FORGE_CODE_TOKEN is not "
                f"set anywhere the dispatcher can see it, so nothing will ever pick them up",
                degraded=True,
            )
        )
    elif ready:
        notes.append(Note(f"{len(ready)} item(s) are ready for the dispatcher"))

    cutoff = datetime.now(UTC) - STALE_AFTER
    stale = [item.id for item in in_progress if item.updated_at < cutoff]
    if stale:
        notes.append(
            Note(
                f"item(s) {stale} have been in-progress for over {STALE_AFTER}; their dispatcher "
                f"probably died. `hullwork work --release-stale` frees them without losing the "
                f"record",
                degraded=True,
            )
        )
    elif in_progress:
        notes.append(Note(f"{len(in_progress)} attempt(s) are running now"))

    # A publish that failed lives only in a log line today, and item 019 exists because a clear
    # sentence followed by exit 0 is indistinguishable from health. `publish` records it on the
    # attempt rather than raising — deliberately, so a lost comment cannot turn a recorded verdict
    # into an abandoned attempt — so the database has the fact and nothing surfaced it (item 069).
    unpublished = unpublished_verdicts(session)
    if unpublished:
        notes.append(
            Note(
                f"attempt(s) {[a.id for a in unpublished]} reached a verdict and could not publish "
                f"it, so a result DR-0003 calls first-class is where only this database sees it. "
                f"The attempt was spent. `hullwork republish` finishes the job without re-running "
                f"the agent",
                degraded=True,
            )
        )

    # One read per eligible item, and only when a forge is at hand. The guard in `_attempt` already
    # refuses to spend an attempt on an unreachable verdict; this is so the operator hears about it
    # before the dispatcher does, which is the difference between a warning and a post-mortem.
    if forge is not None and ready:
        stranded = [
            item.forge_issue_ref
            for item in ready
            if item.forge_issue_ref and not _issue_resolves(forge, item)
        ]
        if stranded:
            notes.append(
                Note(
                    f"item(s) point at issue(s) {stranded} that do not exist in their project's "
                    f"repository, so they will never be attempted — a verdict about them could not "
                    f"be posted anywhere. Point them at a real issue, or close them by hand",
                    degraded=True,
                )
            )

    unfinished = session.execute(
        select(Attempt).where(Attempt.outcome.is_(None))
    ).scalars().all()
    orphans = [a.id for a in unfinished if a.item_id not in {i.id for i in in_progress}]
    if orphans:
        notes.append(
            Note(
                f"attempt(s) {orphans} were never finished and their item is not in progress — a "
                f"dispatcher was killed between claiming and recording",
                degraded=True,
            )
        )
    return notes


@dataclass
class Outcome:
    """What one `hullwork work` invocation did, for the command's own output."""

    item_id: int
    outcome: AttemptOutcome
    detail: str
    pull_request: str | None = None
    #: The seal exactly as it was stored, so the caller's own log reports what the attempt recorded
    #: rather than reading the journal a second time and possibly disagreeing with it.
    seal: dict[str, object] | None = None


def run_one(
    session: Session,
    candidate: Eligible,
    *,
    engine: object,
    box_factory: object,
    publisher: object,
    recording: "Recording | Callable[[], Recording] | None" = None,
    rehearsal: bool = False,
    image_tag: str | None = None,
    base_sha: str | None = None,
    production_ref: str | None = None,
    #: Which sequence to run in the box. `None` is `dispatch.dispatch`, the six steps. Item 179
    #: passes `dispatch.refit`, which is three — and everything around it here is the same, which
    #: is the point: the claim, the seal, the ceiling checks, publication and release are about an
    #: attempt rather than about what the attempt was for.
    sequence: object = None,
) -> Outcome:
    """Claim, dispatch, publish, record. The order is the whole design.

    Everything replaceable is passed in — the engine, the thing that makes a sandbox, the thing
    that talks to the forge — so this function is the sequence and nothing else. That is not
    fashion: it is the only way to exercise the sequence without a Docker daemon and a live forge,
    and an untested sequence is where the double-dispatch and lost-attempt bugs live.

    **`recording` may be a provider, and in production it is one** (item 056). It used to be a live
    object that filled up by reference while the phases ran; since item 054 the gateway is a
    container and what comes back is a journal read from disk. Passed as a value it is therefore
    read *before* the baseline runs and is empty for ever — which made `never_reached_a_model`
    overrule every real verdict the gates produced. A value is still accepted, because a caller with
    the finished recording in hand is the degenerate case, as `Gateway` does with a credential.
    """
    from hullwork import attempts as attempts_module
    from hullwork import dispatch as dispatch_module
    from hullwork.ingest import _manifest_for

    item = candidate.item
    if not claim(session, item):
        return Outcome(item.id, AttemptOutcome.ABANDONED, "another dispatcher holds this item")

    manifest = _manifest_for(candidate.project)
    attempt = attempts_module.start(
        session, item, image_tag=image_tag, base_sha=base_sha, production_ref=production_ref
    )
    session.commit()

    try:
        box = box_factory(manifest)  # type: ignore[operator]
        run = sequence or dispatch_module.dispatch
        verdict = run(  # type: ignore[operator]
            session, item, manifest, engine,
            box=box, attempt=attempt,
        )
    except dispatch_module.Abandoned as stop:
        # The attempt does not count. This is the path that keeps "the network was bad" from
        # looking like "the agent could not fix this".
        seen = _observed(recording)
        attempts_module.finish(
            session, attempt, AttemptOutcome.ABANDONED,
            not_consumed_reason=stop.reason, seal=_seal(seen), rehearsal=rehearsal,
        )
        release(session, item, AttemptOutcome.ABANDONED, rehearsal=rehearsal)
        return Outcome(item.id, AttemptOutcome.ABANDONED, stop.reason, seal=_seal(seen))
    except Exception as exc:  # anything unforeseen is also not the agent's fault
        log.exception("dispatch failed", extra={"item": item.id})
        seen = _observed(recording)
        attempts_module.finish(
            session, attempt, AttemptOutcome.ABANDONED,
            not_consumed_reason=_dispatcher_failed(exc),
            seal=_seal(seen), rehearsal=rehearsal,
        )
        release(session, item, AttemptOutcome.ABANDONED, rehearsal=rehearsal)
        return Outcome(item.id, AttemptOutcome.ABANDONED, str(exc), seal=_seal(seen))

    # **Read once, here, after every phase has run** (item 056). Once rather than at each use: the
    # journal grows while the attempt does, so two reads can disagree — and then the stored seal
    # describes something other than what the decision below was made on.
    seen = _observed(recording)
    attempt.phase_reached = verdict.phase
    if ran_out_of_turns(seen, verdict, limit=getattr(engine, "max_turns", 0)):
        # Item 059. Measured three times on one item: the agent used all thirty turns every time
        # and wrote a test in one of the three. The two runs where it did not were recorded
        # `not-reproducible` — terminal, consuming, printing a sentence about the bug — when what
        # had happened was that we gave it thirty turns and the work needed more.
        reason = _out_of_turns_reason(seen, getattr(engine, "max_turns", 0))
        attempts_module.finish(
            session, attempt, AttemptOutcome.ABANDONED,
            not_consumed_reason=reason, seal=_seal(seen), rehearsal=rehearsal,
        )
        release(session, item, AttemptOutcome.ABANDONED, rehearsal=rehearsal)
        return Outcome(item.id, AttemptOutcome.ABANDONED, reason, seal=_seal(seen))

    stopped_by_ceiling = ceiling_stopped(seen, verdict.outcome)
    if stopped_by_ceiling is not None:
        reason = stopped_by_ceiling
        attempts_module.finish(
            session, attempt, AttemptOutcome.ABANDONED,
            not_consumed_reason=reason, seal=_seal(seen), rehearsal=rehearsal,
        )
        release(session, item, AttemptOutcome.ABANDONED, rehearsal=rehearsal)
        return Outcome(item.id, AttemptOutcome.ABANDONED, reason, seal=_seal(seen))

    if never_reached_a_model(seen, verdict.outcome):
        # Spec §8: an attempt is not consumed by anything that happened to the infrastructure. The
        # gates ran and reached an honest verdict, but the verdict is about an agent that never got
        # an answer — and `not-reproducible` is terminal, so accepting it here would spend the
        # item's one try on an expired credential.
        #
        # **Found by running it.** The subscription token had expired; the gateway forwarded 22
        # requests and every one came back 401, so the seal recorded 22 responses with
        # `models_served: []` while Claude Code reported `is_error: true` alongside
        # `subtype: success` and answered `model: <synthetic>`. Nothing in the agent's own account
        # of itself could be trusted to tell us that — the seal could, and was not being asked.
        attempts_module.finish(
            session, attempt, AttemptOutcome.ABANDONED,
            not_consumed_reason=_no_completion_reason(seen), seal=_seal(seen), rehearsal=rehearsal,
        )
        release(session, item, AttemptOutcome.ABANDONED, rehearsal=rehearsal)
        return Outcome(
            item.id, AttemptOutcome.ABANDONED, _no_completion_reason(seen), seal=_seal(seen)
        )

    # The seal goes on with the verdict, not after it. DR-0002 §4 makes provenance the reason to
    # trust any of this, and a pull request whose body has to say "the model that answered is
    # unknown" is one nobody can act on — the recording is in hand right here.
    attempts_module.finish(
        session, attempt, verdict.outcome, error=verdict.detail or None,
        seal=_seal(seen), rehearsal=rehearsal,
    )

    # Published after the verdict is recorded, never before: a crash between the two must leave a
    # database that knows what happened rather than a forge that does and a database that does not.
    reference = publisher(item, attempt, verdict)  # type: ignore[operator]
    release(session, item, verdict.outcome, rehearsal=rehearsal)
    return Outcome(
        item.id, verdict.outcome, verdict.detail, pull_request=reference, seal=_seal(seen)
    )


def _dispatcher_failed(exc: Exception) -> str:
    """Say what went wrong on this side, in the words the thing that failed used.

    A bare exception class name is what this said before, and item 056 is a record of what that
    costs: `ServiceError` on the screen tells whoever is reading it nothing about *which* service
    would not start, so the diagnosis starts from scratch. Sandbox failures carry a sentence written
    for exactly this, so it is used; anything else keeps the class name, because an arbitrary
    exception's `str()` is not a message anybody wrote for a reader.
    """
    from hullwork.sandbox.docker import SandboxError

    if isinstance(exc, SandboxError):
        return f"the attempt could not be set up: {exc}"
    return f"the dispatcher itself failed: {type(exc).__name__}"


def _observed(recording: "Recording | Callable[[], Recording] | None") -> Recording | None:
    """Whatever the wire showed, resolved **now**.

    The whole of item 056's first half is that this used to happen in argument position at
    `work.py:997`, so it happened before the baseline ran. A provider resolved at the point of use
    cannot be resolved too early; a value handed in already can only be as fresh as its caller made
    it, and that is the caller's business.
    """
    if recording is None or not callable(recording):
        return recording
    return recording()


def _protocol_mismatch(recording: Recording | None) -> str | None:
    """Whether this attempt died because the endpoint cannot serve the harness's protocol. Item 134.

    **The one failure whose cause is written in the recording and was never read out.** The gateway
    forwards rather than translates, so a harness speaking one family against an endpoint serving
    another produces refusals from *our* process — `refused_paths` on the seal, and nothing else
    that a person could act on. Left as it was, the operator reads "the agent never reached a model"
    about a configuration they can fix in one variable.

    Only refusals, and only when nothing was observed: a run that reached a model and also had a
    metadata path refused (item 066's `count_tokens`) is not this, and saying so would send somebody
    to change a working endpoint.
    """
    if recording is None or recording.observations or not recording.refused:
        return None
    paths = ", ".join(sorted(set(recording.refused))[:3])
    return (
        f"the endpoint was reached and refused every call this harness made ({paths}) — the "
        f"gateway forwards without translating, so the harness fixes the protocol and the endpoint "
        f"has to serve that family. Either point HULLWORK_MODEL_ENDPOINT at a route that serves it "
        f"(most providers publish one) or register a harness that speaks the endpoint's shape. "
        f"`hullwork doctor` prints both sides"
    )


def _no_completion_reason(recording: Recording | None) -> str:
    """Say what was actually seen, not that nothing was.

    The old wording — "the endpoint answered 0 time(s) and not one was a completion" — was printed
    on a run where the endpoint had answered ten times, every one a 401, and it sent three of four
    diagnostic rounds into the network. The decision it explains is unchanged and correct; only its
    account of the evidence was wrong.
    """
    mismatch = _protocol_mismatch(recording)
    if mismatch is not None:
        return mismatch
    if recording is None or not recording.observations:  # pragma: no cover - guarded by the caller
        return (
            "nothing was observed on the wire at all, so the agent never reached a model — this "
            "says nothing about whether the bug is reproducible"
        )
    statuses = recording.statuses
    # Omitted when every response predates statuses being recorded: "unknown x22" tells a reader
    # nothing they can act on, and a line that adds nothing is a line that dilutes the ones that do.
    breakdown = (
        ""
        if set(statuses) == {"unknown"}
        else " (" + ", ".join(f"{code} x{count}" for code, count in statuses.items()) + ")"
    )
    return (
        f"the endpoint answered {len(recording.observations)} time(s){breakdown} and not one was a "
        f"completion, so the agent never reached a model — this says nothing about whether the bug "
        f"is reproducible"
    )


def _seal(recording: Recording | None) -> dict[str, object] | None:
    return recording.seal() if recording is not None else None


def ran_out_of_turns(
    recording: Recording | None, verdict: object, *, limit: int
) -> bool:
    """Whether the agent was cut off by our own ceiling before it produced anything. Item 059.

    **Read off the wire, never from the harness's own account of itself.** `AgentReport` is advisory
    for a measured reason — Claude Code has returned `subtype: success` alongside `is_error: true` —
    so this compares the completions the *gateway* counted against the `--max-turns` this dispatcher
    passed into the container. An observation and a number we chose, which is DR-0004's distinction
    applied to a second question.

    **Exactly one shape qualifies**, and the narrowness is the point:

    * `not-reproducible` reached at the **reproduce** phase means `dispatch` found no candidate test
      at all — the agent produced nothing. Combined with a spent ceiling, that is a statement about
      the ceiling.
    * `not-reproducible` reached at the **red gate** means the agent *did* write a test and the test
      passes against unmodified code. That is a real verdict under DR-0003 and it settles the item,
      however many turns it took.
    * `failed` means a gate ruled on something the agent produced. Also a verdict.

    The asymmetry is what makes trusting this safe at all: a run that reached the ceiling gets its
    item put back in the queue, and nothing about the gates changes. It cannot be used to land a bad
    fix, only to ask for a human — the direction `ALWAYS_RED`'s over-matching also errs in.
    """
    from hullwork.models import AttemptPhase

    if recording is None or limit <= 0:
        # Nobody was watching the wire, or no ceiling was set. Silence is not evidence.
        return False
    if getattr(verdict, "outcome", None) is not AttemptOutcome.NOT_REPRODUCIBLE:
        return False
    if getattr(verdict, "phase", None) is not AttemptPhase.REPRODUCE:
        return False
    return recording.completions >= limit


def _out_of_turns_reason(recording: Recording | None, limit: int) -> str:
    """Say it was the ceiling, in a sentence nobody can read as being about the bug."""
    served = recording.completions if recording is not None else 0
    return (
        f"the agent used every one of the {limit} turns it was given ({served} completions read "
        f"off the wire) and had not written a test yet, so it was cut off rather than finished — "
        f"this says nothing about whether the bug is reproducible, and the attempt was not spent"
    )


def ceiling_stopped(recording: Recording | None, outcome: AttemptOutcome) -> str | None:
    """Whether the operator's own cost ceiling ended this attempt, and the sentence saying so.

    Item 137, and the decision inside it is why this is a function rather than three lines inline —
    its neighbours `never_reached_a_model` and `ran_out_of_turns` answer the same shape of question
    and are tested the same way.

    **An attempt the ceiling stopped is not the agent's to lose.** DR-0003's one-attempt
    accounting asks whether the agent could fix the bug; one cut off mid-flight never got to be
    right or wrong, so it is `abandoned` and does not consume — the reasoning item 039 gives for
    `already-fixed`. A ceiling that silently spent items is one nobody would dare set.

    **A finished pull request is exempt.** Crossing the ceiling on the last call, after the work is
    published, is not a stopped attempt, and discarding it would be the ceiling destroying the thing
    it exists to protect.
    """
    if recording is None or not recording.over_budget:
        return None
    if outcome is AttemptOutcome.PR_OPEN:
        return None
    return (
        f"the attempt spent {recording.spent} tokens and this instance's ceiling is "
        f"{recording.max_tokens} (HULLWORK_MAX_ATTEMPT_TOKENS), so the gateway stopped. "
        f"The agent was working when it was cut off, so this does not count against the item."
    )


def never_reached_a_model(recording: Recording | None, outcome: AttemptOutcome) -> bool:
    """Whether a terminal verdict is really about the bug, or about the endpoint.

    The gateway is the only party that knows. It sees every response, so "the endpoint answered and
    none of the answers was a completion" is a fact available here and nowhere else — the harness's
    own report cannot be used for it, because a harness that never reached a model still reports a
    run (measured: `subtype: success` with `is_error: true`, and a response whose model is the
    literal `<synthetic>`).

    Only terminal outcomes are rescued. `abandoned` is already not consumed, and `pr-open` cannot
    happen without a model having written something.
    """
    if recording is None:
        # Nobody was watching the wire, so there is nothing to conclude. Silence is not evidence.
        return False
    if outcome not in {AttemptOutcome.NOT_REPRODUCIBLE, AttemptOutcome.FAILED}:
        return False
    return not recording.models_served


# --- publishing what the attempt decided --------------------------------------------------------


def publish(
    code_forge: object,
    forge: object,
    *,
    repo: str,
    item: Item,
    attempt: Attempt,
    verdict: object,
    base_sha: str,
    brief_text: str = "",
    brief_evidence: str = "",
    secrets: list[str] | None = None,
    #: What the operator pays, for the cost row (item 133). `None` prints tokens and no money.
    prices: "spend.Prices | None" = None,
) -> str | None:
    """Turn a verdict into something a human can look at, and return where it went.

    Two shapes, because DR-0003 has two kinds of answer and only one of them is a diff:

    * `pr-open` — a branch rooted at the tested sha, the test commit, the fix commit, a draft pull
      request. In that order, because the order *is* the evidence: a reviewer checks out the first
      commit and watches it fail.
    * anything else — a comment on the issue, and **no branch and no pull request**.
      `not-reproducible` is a first-class result under DR-0003, and a first-class result that only
      exists in a database is one nobody acts on.

    Publishing is the last thing that happens and the only thing here that can fail after a verdict
    exists, so it never raises at the caller: a lost comment must not turn a recorded outcome into
    an abandoned attempt.
    """
    from hullwork import evidence
    from hullwork.forge import BranchExistsError, ForgeError

    outcome = attempt.outcome
    try:
        if outcome not in (AttemptOutcome.PR_OPEN, AttemptOutcome.PR_OPEN_LINT_FAILED):
            return _comment(
                forge, repo=repo, item=item, attempt=attempt, secrets=secrets,
                claim=str(getattr(verdict, "claim", "")),
            )

        branch = evidence.branch_name(item, attempt)
        try:
            code_forge.create_branch(repo, branch, base_sha)  # type: ignore[attr-defined]
            # Written before the first commit, so a dispatcher killed mid-publish leaves a record of
            # what it had already made on the forge (item 048). Without it the `BranchExistsError`
            # path below logs a warning about a branch it has no record of creating.
            attempt.branch = branch
        except BranchExistsError:
            # A previous attempt was killed between creating the branch and finishing. Reusing it
            # would rewrite whatever that one left, so this one stands aside — the attempt is
            # already recorded and a human can see both.
            log.warning("branch already exists", extra={"branch": branch})
            return None

        test_message, fix_message = evidence.commit_messages(item)
        # `.written` and `.deleted`, because item 045 landed in parallel and made a `Verdict`'s file
        # set a `Changes` rather than a dict. This read `verdict.changes.items()` and
        # `path not in candidate`, both of which raise on the new shape — so publishing crashed
        # on every real pull request while the suite stayed green, because the double passed dicts.
        # Fixed in both places: the double now builds what production builds.
        candidate = verdict.candidate.written  # type: ignore[attr-defined]
        changes = verdict.changes  # type: ignore[attr-defined]
        first = _commit(code_forge, repo, branch, test_message, candidate, base_sha)
        # The fix commit carries everything the fix phase touched **except** the candidate test,
        # which is already in. Sending it twice makes an empty diff for those paths, and the forge
        # answers 201 with an empty commit rather than saying so.
        fix_only = {path: body for path, body in changes.written.items() if path not in candidate}
        second = _commit(
            code_forge, repo, branch, fix_message, fix_only, first, deleted=changes.deleted
        )

        body = evidence.pull_request_body(
            item, attempt, detail=str(getattr(verdict, "detail", "")),
            brief_text=brief_text, brief_evidence=brief_evidence, secrets=secrets,
            prices=prices,
            # Item 179: a sequence whose claim is not the ordinary one carries its own, and both
            # publishers read it from the same place so the page and the pull request cannot come
            # to disagree about what was measured.
            claim=str(getattr(verdict, "claim", "")),
        )
        pull = code_forge.open_draft_pull_request(  # type: ignore[attr-defined]
            repo,
            head=branch,
            base=code_forge.default_branch(repo),  # type: ignore[attr-defined]
            title=f"fix: {item.title.splitlines()[0][:68]}" if item.title else "fix from Hullwork",
            body=body,
        )
        attempt.pull_request_ref = str(pull.ref)
        if not pull.draft:
            # Forgejo derives draft from a title prefix that the instance can reconfigure and no
            # API exposes (spec §5.1), so the response is read back rather than assumed. A
            # merge-ready pull request from a bot is the one artefact this product must never
            # leave behind.
            log.error("the forge did not mark it a draft", extra={"pull": pull.ref})
        log.info(
            "published", extra={"pull": pull.ref, "first": first[:12], "second": second[:12]}
        )
        return str(pull.html_url)
    except ForgeError as exc:
        # The verdict is already in the database. Saying where it failed is all that is left here —
        # `hullwork republish` is what finishes the job later (item 077).
        log.exception("could not publish", extra={"item": item.id})
        attempt.error = f"{attempt.error or ''}\n{PUBLICATION_FAILED}{exc}".strip()
        return None



def write_locally(root: Path) -> "Callable[[Item, Attempt, object], str | None]":
    """A publisher that writes what the attempt produced to disk and opens nothing. Item 049.

    **A publisher implementation, not a branch in `run_one`.** `Verdict.changes` reaches only the
    publisher, so a flag that merely skipped the call could not produce anything to look at — the
    code forces the right shape here, which is the good news in DR-0006's amendment.

    Files, not a unified diff, and the reason is worth stating rather than glossing over: a diff
    needs the before-image, and a `Verdict` carries only what the phases produced. Threading the
    whole pristine snapshot through the verdict to render a diff at the far end costs more than it
    buys, because whoever runs a rehearsal already has the checkout — `diff -ru` against it is one
    command and it is theirs, not ours. Item 049's criterion said "one patch per commit"; this is
    the honest substitute, and the item's Progress records the swap.
    """
    from hullwork import evidence

    def publisher(item: Item, attempt: Attempt, verdict: object) -> str | None:
        into = root / f"attempt-{attempt.id}"
        candidate = getattr(verdict, "candidate", None)
        changes = getattr(verdict, "changes", None)
        for name, produced in (("candidate", candidate), ("fix", changes)):
            for path, content in sorted(getattr(produced, "written", {}).items()):
                target = into / name / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        deleted = tuple(getattr(changes, "deleted", ()))
        if deleted:
            (into / "deleted.txt").parent.mkdir(parents=True, exist_ok=True)
            (into / "deleted.txt").write_text("\n".join(deleted) + "\n", encoding="utf-8")
        into.mkdir(parents=True, exist_ok=True)
        (into / "artefact.md").write_text(
            evidence.pull_request_body(
                item, attempt, detail=str(getattr(verdict, "detail", "")),
                claim=str(getattr(verdict, "claim", "")),
            ),
            encoding="utf-8",
        )
        log.info("rehearsal written", extra={"item": item.id, "into": str(into)})
        return str(into)

    return publisher


def _commit(
    code_forge: object,
    repo: str,
    branch: str,
    message: str,
    files: dict[str, bytes],
    ref: str,
    *,
    deleted: tuple[str, ...] = (),
) -> str:
    """One commit for a whole file set, choosing create or update per file from the forge's answer.

    **Asking the forge rather than the worktree, and that was found by running it** (item 030): a
    file the worktree had may still be absent from the repository, and `FileChange` needs the
    pre-image blob sha for an update — without it the forge refuses, and with the wrong one it
    refuses with a 409 that quotes the right one back.
    """
    from hullwork.forge import FileChange

    changes = []
    for path, content in sorted(files.items()):
        sha = code_forge.file_sha(repo, path, ref)  # type: ignore[attr-defined]
        changes.append(
            FileChange(
                path=path,
                operation="update" if sha else "create",
                content=content,
                sha=sha,
            )
        )
    # Item 045: a fix that removes a validation by deleting a file was tested as one tree and
    # published as another. This is the half that makes the published tree the tested one, and it is
    # the first caller of `FileChange(operation="delete")` — declared in the protocol and until now
    # unreachable, which was the same defect seen from the other end.
    for path in sorted(deleted):
        sha = code_forge.file_sha(repo, path, ref)  # type: ignore[attr-defined]
        if sha is None:
            # Already absent upstream. Asking the forge to delete it would be a 404, and the tree
            # the gates ran against and the tree being published already agree about this path.
            continue
        changes.append(FileChange(path=path, operation="delete", sha=sha))
    return str(
        code_forge.commit_files(  # type: ignore[attr-defined]
            repo, branch, message, changes, author=COMMIT_AUTHOR, email=COMMIT_EMAIL
        )
    )


def _allowed_models(settings: Settings) -> tuple[str, ...]:
    """The operator's allowlist, parsed once. Item 137.

    Empty means DR-0002's rule untouched: only `model_name` is acceptable and anything else that
    answers is a recorded violation. A list widens what is acceptable to have *answered* without
    changing what is *asked for*, which stays one model.
    """
    raw = settings.model_allowed or ""
    return tuple(name.strip() for name in raw.split(",") if name.strip())


def _model_credential(settings: Settings) -> "str | Callable[[], str]":
    """The credential the gateway will hold, and never the sandbox (DR-0004).

    An API key is the supported answer and the amendment of 2026-07-28 made it the only one. The
    subscription path stays because Hullwork's own dogfood runs on it at no marginal cost, and it
    warns, because a convenience that looks like a configuration is how it ends up in somebody's
    production deployment.
    """
    from hullwork.gateway import subscription_credential

    if settings.model_key:
        return settings.model_key.get_secret_value()
    if settings.model_credentials_file:
        log.warning(
            "using a development-only model credential",
            extra={"path": settings.model_credentials_file},
        )
        return subscription_credential(settings.model_credentials_file)
    msg = (
        "no model credential is configured, so an agent would have nothing to think with. Set "
        "HULLWORK_MODEL_KEY to an API key from any provider (DR-0004)"
    )
    raise WiringError(msg)


def run(
    session: Session,
    settings: Settings,
    *,
    limit: int = 1,
    slug: str | None = None,
    rehearse_into: Path | None = None,
) -> list[Outcome]:
    """What `hullwork work` does: build an attempt's world, run the sequence, tear it all down.

    The order is not arbitrary. Everything that can fail without costing the item its one attempt
    fails **before** `run_one` claims it — the forge is asked for the base commit, the image is
    built, the network is proved. What is left inside the claim is the part that is genuinely about
    the bug.

    One item at a time even when `--limit` is higher, because each one gets its own network, its
    own gateway and its own recording (DR-0002: one recording per attempt, or the seal describes
    the wrong run).
    """
    from hullwork.forge.factory import make_code_forge, make_forge

    # A rehearsal publishes nothing, so it must not require the credential that could (item 049).
    # That refusal is the largest single obstacle DR-0006 set out to remove: needing a push-capable
    # token to *evaluate* the fix half is a security review before the tool has done anything.
    rehearsal = rehearse_into is not None
    code_forge = None if rehearsal else make_code_forge(settings)
    if code_forge is None and not rehearsal:
        msg = (
            "HULLWORK_FORGE_CODE_TOKEN is not set, so nothing here could open a pull request. The "
            "dispatcher is the only program that holds it (spec M2 §1)"
        )
        raise WiringError(msg)
    forge = make_forge(settings)
    credential = _model_credential(settings)
    # Redacted out of every published string. The evidence trail is assembled from the captured
    # output of arbitrary commands and then posted under our own account (item 027). The read-only
    # page renders the same artefact back out of the database and asks the same function for the
    # same list, so the two surfaces cannot come to disagree about what a credential is (item 123).
    secrets = instance_secrets(settings)

    outcomes: list[Outcome] = []
    for candidate in eligible(
        session,
        limit=limit,
        slug=slug,
        # The dispatcher is the one caller that knows, so it is the one that says.
        tracker_configured=settings.tracker_url is not None and settings.tracker_token is not None,
    ):
        outcomes.append(
            _attempt(
                session, settings, candidate,
                code_forge=code_forge, forge=forge, credential=credential, secrets=secrets,
                rehearse_into=rehearse_into,
            )
        )
    return outcomes


def _attempt(
    session: Session,
    settings: Settings,
    candidate: Eligible,
    *,
    code_forge: object,
    forge: object,
    credential: "str | Callable[[], str]",
    secrets: list[str],
    rehearse_into: Path | None = None,
    local_checkout: "Checkout | None" = None,
    #: The dependency upgrade this attempt is about, when it is one (item 179). It changes three
    #: things and nothing else: which sequence runs, what the brief says, and what the artefact
    #: can claim about the evidence the agent had. One parameter rather than three, because those
    #: three have to agree and a caller that sets two of them has built a lie.
    upgrade: object = None,
) -> Outcome:
    """Build one attempt's world, run the sequence in it, and take the world down again.

    A function rather than the body of a loop, and not for tidiness: the sandbox factory and the
    publisher are closures over the checkout, the cable and the project, and closures over a loop
    variable are how the second item in a run ends up dispatched into the first one's container.
    """
    from contextlib import ExitStack
    from functools import partial

    from hullwork import dispatch as dispatch_module
    from hullwork import engine as engine_module
    from hullwork.brief import build as build_brief
    from hullwork.brief import evidence_level as brief_evidence_level
    from hullwork.forge import ForgeError
    from hullwork.ingest import _manifest_for
    from hullwork.sandbox import image as image_module
    from hullwork.sandbox.net import Cable
    from hullwork.sandbox.run import Sandbox

    item, project = candidate.item, candidate.project
    manifest = _manifest_for(project)
    if manifest.runtime is None:
        msg = (
            f"{project.slug} declares an agent and no `runtime:`, so no image can be built and the "
            f"project's own test command could not even start (item 037)"
        )
        raise WiringError(msg)
    rehearsal = rehearse_into is not None
    # A rehearsal clones with the **read** credential. Cloning is a read, and the whole point of the
    # mode is that nothing it needs can write anywhere (DR-0006 §1).
    #
    # **A trial does not clone at all** (item 140): it was handed a checkout that already exists on
    # the host, so there is no repository to read and no credential that could read one. That is
    # the last forge credential on the evaluation path, and removing it is the difference between
    # "no token that can push" and "no account anywhere".
    reading_only = rehearsal or local_checkout is not None
    token = None if local_checkout is not None else (
        settings.forge_token if reading_only else settings.forge_code_token
    )
    if token is None and local_checkout is None:
        msg = (
            "HULLWORK_FORGE_TOKEN is not set, so the repository cannot even be read"
            if rehearsal
            else "HULLWORK_FORGE_CODE_TOKEN is not set"
        )
        raise WiringError(msg)

    with ExitStack() as stack:
        # Everything before the claim can fail without costing the item its one attempt.
        # **Before the claim, so it cannot cost the item its attempt** (item 069). Measured on the
        # first publishing run: the item pointed at issue #3 and the project's repo has none — M1's
        # probes filed theirs elsewhere — so the comment 404'd *after* the verdict was recorded and
        # consumed. `publish`'s own docstring is the indictment: "a first-class result that only
        # exists in a database is one nobody acts on."
        #
        # One read, before the model is called, and it is not only about stale data: a human can
        # delete or transfer an issue at any time.
        if not rehearsal and item.forge_issue_ref:
            _the_issue_must_still_exist(forge, project.repo, item.forge_issue_ref)

        if local_checkout is not None:
            # **Handed a checkout, so no forge is asked anything** (item 140). Everything below
            # here is identical: the same image, the same six phases, the same seal. What a trial
            # removes is upstream of the work, which is why it can be this small.
            checked_out = local_checkout
        else:
            reader = forge if rehearsal else code_forge
            # Same treatment as the guard above, and for the same reason: a forge that cannot be
            # reached — a host that does not resolve is the one we have actually seen — is wiring,
            # not a verdict. Unguarded, a `ForgeError` here has no handler between this line and
            # `main`, which catches `CommandError` alone, so it reaches the operator as a traceback.
            try:
                base_branch = reader.default_branch(project.repo)  # type: ignore[attr-defined]
                base_sha = reader.head_commit(project.repo, base_branch)  # type: ignore[attr-defined]
            except ForgeError as exc:
                msg = (
                    f"could not read the base commit of {project.repo} from the forge, so there is "
                    f"nothing to check out and no attempt was started: {exc}"
                )
                raise WiringError(msg) from exc

            clone_root = Path(tempfile.mkdtemp(prefix="hullwork-clone-"))
            stack.callback(shutil.rmtree, clone_root, ignore_errors=True)
            assert token is not None  # noqa: S101 - the guard above raises when it is not
            checked_out = checkout(
                clone_url(settings, project),
                token.get_secret_value(),
                into=clone_root / "repo",
                ref=base_sha,
            )

        # The engine is resolved before the image because the image now contains it: the harness is
        # installed on top of the project's base, so the agent sees the same environment the gate
        # will run in (operator decision, 2026-07-28).
        # The operator's ceiling wins over the engine's default when set (item 062).
        engine = engine_module.resolve(
            manifest.autofix.agent, max_turns=settings.max_turns, model=settings.model_name
        )
        # Built once per instance and reused (item 065). Before the claim, like everything else that
        # can fail without costing the item its one attempt.
        bundle: str | None = None
        if engine.mounted:
            from hullwork.sandbox.harness import ensure_bundle

            bundle = ensure_bundle(
                str(engine.bundle_from), str(engine.bundle_bin),
                entrypoint=engine_module.AGENT_ENTRYPOINT,
                install=engine.bundle_install,
            )
        built = image_module.build(
            manifest.runtime, dependency_files(checked_out.path, manifest.runtime), engine,
            # **The checkout, and the commit that names it** (item 113). Both are `None` for every
            # project that does not ask for the source in its image, which is the default and stays
            # the cheap path: the tag does not move and the image is reused between attempts.
            source=checked_out.path if manifest.runtime.install_needs_source else None,
            source_ref=base_sha if manifest.runtime.install_needs_source else None,
        )

        contract_dir = Path(tempfile.mkdtemp(prefix="hullwork-contract-"))
        stack.callback(shutil.rmtree, contract_dir, ignore_errors=True)
        sequence: object = None
        if upgrade is None:
            dispatch_module.build_brief_file(session, item, contract_dir)
            brief_text = build_brief(session, item)
            # Read from the same event the brief was built from, before the attempt runs —
            # enrichment can happen while it does, and the artefact has to say what the agent
            # *had* (item 100).
            brief_evidence = brief_evidence_level(session, item)
        else:
            # Item 179. Everything below this block is untouched: same image, same gates, same
            # seal, same publisher. What a refit replaces is what the agent is told and which
            # sequence reads its work — the two halves that are about a bug rather than about an
            # attempt.
            from hullwork import refit as refit_module

            brief_text = refit_module.brief(upgrade)  # type: ignore[arg-type]
            dispatch_module.write_brief(brief_text, contract_dir)
            # **Not `brief.evidence_level`**, which reads a `FetchedEvent` this item does not have
            # and would answer "the issue title only — the tracker was never asked". That sentence
            # exists to warn a reviewer that an attempt ran on almost nothing; here it would
            # understate the best evidence this product produces (item 100's rule, held to).
            brief_evidence = (
                f"the upgrade, and the {len(brief_text.splitlines())}-line brief naming the tests "
                f"your own suite failed on with it applied"
            )
            sequence = partial(
                dispatch_module.refit,
                package=upgrade.package,  # type: ignore[attr-defined]
                to=upgrade.to,  # type: ignore[attr-defined]
                guarded=upgrade.guarded,  # type: ignore[attr-defined]
                version_now=lambda tree: refit_module.version_now(
                    upgrade, tree  # type: ignore[arg-type]
                ),
            )

        # The gateway runs **in** the attempt's own network, not on this host (item 054). A
        # container on an `--internal` network cannot reach a listener on the host — measured on a
        # Linux box with a default-deny firewall, which is most of them — and the answer was never
        # to ask every self-hoster to open a port to the Docker bridge. Docker already expresses
        # the property; the firewall was being asked to permit a hop the design did not need.
        #
        # Resolved once here rather than passed as a callable: the container gets a file, and a
        # subscription token good for hours outlives an attempt bounded to one.
        cable_dir = Path(tempfile.mkdtemp(prefix="hullwork-cable-"))
        stack.callback(shutil.rmtree, cable_dir, ignore_errors=True)
        cable = stack.enter_context(
            Cable(
                settings.model_endpoint,
                credential() if callable(credential) else credential,
                work_dir=cable_dir,
                pinned_model=settings.model_name,
                allowed_models=_allowed_models(settings),
                max_tokens=settings.max_attempt_tokens,
                auth_style=settings.model_auth_style,
            )
        )
        # Before the model is called, and it raises rather than warns.
        cable.self_test()

        worktree = dispatch_module.prepare_worktree(checked_out.path)
        stack.callback(shutil.rmtree, worktree, ignore_errors=True)

        def box(_manifest: object) -> Sandbox:
            sandbox = Sandbox(
                image=built.tag,
                worktree=worktree,
                contract_dir=contract_dir,
                gateway_url=cable.url,
                network=cable.network,
                # Item 052. Names, not images: `Sandbox` starts and stops them around each phase,
                # because a database shared between the red gate and the green gate makes those two
                # gates a comparison of different databases. Registration has already refused any
                # name this build cannot provide, so nothing here can be surprised by one.
                services=list(manifest.runtime.services) if manifest.runtime else [],
                harness_bundle=bundle,
            )
            # A named volume rather than a bind mount of the worktree (item 055). The host copy
            # stays the working set every guard in `dispatch` reads; what the container sees is a
            # volume owned by the uid that runs it. Registered for cleanup before it is seeded, so
            # a failure while seeding still takes the volume with it.
            stack.callback(sandbox.cleanup)
            suffix = cable.network.rsplit("-", 1)[-1]
            sandbox.ensure_volume(
                f"hullwork-worktree-{suffix}",
                # Only where the build put something in the tree that the checkout does not have
                # (item 114). For every other project this is the path it has always taken.
                seed_from_image=manifest.runtime.install_needs_source
                if manifest.runtime else False,
            )
            # The contract goes on a volume too (item 082), so the dispatcher can run inside a
            # container: a bind mount is resolved by the daemon, and a path that exists only in
            # this process's filesystem yields an empty directory and exit 0. Registered for
            # cleanup before it is seeded, like the worktree above.
            stack.callback(sandbox.cleanup_contract)
            sandbox.ensure_contract(f"hullwork-contract-{suffix}")
            # **After the volumes and before any phase** (item 094). The first attempt to reach a
            # pull request ran both agent phases with a broken shell — `EACCES` creating the agent's
            # own config directory, because a `--tmpfs` is mounted with the options Docker picks and
            # not with the user the image runs as. It produced a correct fix by reading source and
            # said so; the next one could produce a plausible fix and say the same. This raises, and
            # `run_one` turns that into an abandoned attempt, so the item keeps its try.
            sandbox.self_test()
            return sandbox

        local = write_locally(rehearse_into) if rehearse_into is not None else None

        def publisher(published: Item, attempt: Attempt, verdict: object) -> str | None:
            if local is not None:
                return local(published, attempt, verdict)
            return publish(
                code_forge, forge,
                repo=project.repo, item=published, attempt=attempt, verdict=verdict,
                base_sha=base_sha, brief_text=brief_text, brief_evidence=brief_evidence,
                secrets=secrets,
                # Item 133: read here, where the settings are, so the body a reviewer receives
                # carries what this attempt cost on this instance.
                prices=spend.Prices.from_settings(settings),
            )

        outcome = run_one(
            session,
            candidate,
            engine=engine,
            box_factory=box,
            publisher=publisher,
            # **A provider, not a value** (item 056). `Cable.recording` replays a journal from disk,
            # so calling it here would read it before the baseline ran and hand `run_one` an empty
            # recording for every attempt — which made `never_reached_a_model` overrule real
            # verdicts and report that a model which had answered twice was never reached.
            recording=lambda: cable.recording(
                settings.model_endpoint, pinned_model=settings.model_name
            ),
            image_tag=built.tag,
            base_sha=checked_out.sha,
            production_ref=_production_ref(session, item),
            rehearsal=rehearsal,
            sequence=sequence,
        )
        # The seal that was stored, not a third read of the journal. Two reads of a growing file are
        # two chances to print something the database does not say.
        log.info(
            "attempt finished",
            extra={
                "item": item.id,
                "outcome": outcome.outcome.value,
                "seal": outcome.seal,
            },
        )
        return outcome


def _issue_resolves(forge: object, item: Item) -> bool:
    """Whether this item's issue can still be commented on. For the status report only.

    Swallows every failure and answers `True`, which is the opposite of what the dispatcher's own
    guard does — and deliberately. A status command that reported every project as stranded because
    the forge blinked would be worse than one that missed a case: the guard is what protects the
    attempt, and this is what tries to warn earlier.
    """
    from hullwork.forge import ForgeError

    project = item.project
    try:
        return forge.get_issue(  # type: ignore[attr-defined]
            project.repo, int(str(item.forge_issue_ref).lstrip("#"))
        ) is not None
    except (ForgeError, ValueError, AttributeError):
        return True


def _the_issue_must_still_exist(forge: object, repo: str, ref: str) -> None:
    """Refuse to dispatch an item whose verdict would have nowhere to go. Item 069.

    DR-0003 makes `not-reproducible` and `failed` first-class results, and the reason they get an
    issue comment is that a result only a database knows is one nobody acts on. So an item that
    cannot be commented on must not be attempted: the attempt is scarce, and spending it to produce
    something unreadable is the worst available trade.

    A `WiringError`, so `run_one` never sees it and the item keeps its try. Not a `ForgeError`: this
    is not the forge failing — it answered, and the answer was that the issue is gone.

    Only in publishing mode. A rehearsal publishes to disk and has no issue to reach; requiring one
    would reintroduce the obstacle DR-0006 exists to remove.
    """
    from hullwork.forge import ForgeError

    try:
        number = int(ref.lstrip("#"))
    except ValueError:  # pragma: no cover - written by `dedup`, never by a user
        msg = f"the item's issue reference {ref!r} is not a number, so nothing can be posted to it"
        raise WiringError(msg) from None
    try:
        found = forge.get_issue(repo, number)  # type: ignore[attr-defined]
    except ForgeError as exc:
        # The forge being unreachable is a different fact from the issue being gone, and it will
        # succeed on retry where a missing issue never will. Say which.
        msg = (
            f"could not check whether issue {ref} still exists in {repo}, so this attempt would "
            f"risk producing a verdict nobody can read: {exc}"
        )
        raise WiringError(msg) from exc
    if found is None:
        msg = (
            f"issue {ref} does not exist in {repo}, so a verdict about this item could not be "
            f"posted anywhere, and DR-0003 makes that verdict a first-class result. The item keeps "
            f"its attempt; point it at a real issue or close it by hand"
        )
        raise WiringError(msg)


def _production_ref(session: Session, item: Item) -> str | None:
    """What the tracker said production was running, verbatim, for the evidence trail.

    Recorded rather than acted on. Item 039 built `refs.classify` to tell a usable commit from a
    stale release, and using it properly means running the reproduction against *two* trees — the
    release and the tip — which is a change to the dispatcher's sequence and not to its wiring. So
    the gates run at the tip (fix-where-it-merges, the ordinary case item 039 names), and the
    deployed ref is on the attempt where a reviewer can see the two are not the same commit.
    """
    from hullwork.models import FetchedEvent

    latest = session.execute(
        select(FetchedEvent)
        .where(FetchedEvent.item_id == item.id)
        .order_by(FetchedEvent.fetched_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    return latest.release if latest is not None else None


def _comment(
    forge: object, *, repo: str, item: Item, attempt: Attempt, secrets: list[str] | None,
    claim: str = "",
) -> str | None:
    """Say on the issue what happened, with the ingest credential rather than the code one.

    Spec §1: the dispatcher holds both tokens precisely because of this call — measured on GitHub, a
    `contents`+`pull_requests` token gets 403 commenting on an issue, and DR-0003 makes this comment
    a first-class outcome rather than a nicety.
    """
    from hullwork import evidence

    if forge is None or not item.forge_issue_ref:
        log.info("no issue to report to", extra={"item": item.id})
        return None
    number = int(item.forge_issue_ref.lstrip("#"))
    body = evidence.issue_comment(
        item, attempt, detail=attempt.error or "", secrets=secrets, claim=claim
    )
    forge.comment(repo, number, body)  # type: ignore[attr-defined]
    log.info("commented on the issue", extra={"item": item.id, "issue": number})
    return item.forge_issue_ref
