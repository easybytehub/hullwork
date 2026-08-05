"""Claiming, releasing, and telling an operator what the dispatcher half is doing (item 029).

Claiming is the part with teeth. Item 018 found the sweep filing two issues for one item because
selecting rows is not claiming them, and here the window between deciding to act and recording it
is a whole container start — so two dispatchers on one item would mean two branches and two pull
requests for one bug.
"""

import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from hullwork import work
from hullwork.attempts import consumed_count, finish, has_attempt_left, start
from hullwork.engine import Engine
from hullwork.models import (
    Attempt,
    AttemptOutcome,
    AttemptPhase,
    Base,
    Item,
    ItemKind,
    ItemState,
    Lane,
    Project,
)

#: The smallest manifest that permits an agent at all. Item 044 made "the manifest names an agent"
#: one of `eligible`'s conditions — `route()` has always refused to move an item out of `triaged`
#: without it, so an item in `ready` on an agent-less project can only be a leftover — which means a
#: project fixture with no manifest no longer describes a project the dispatcher would ever look at.
AGENT_MANIFEST: dict[str, object] = {
    "project": "p",
    "git": {"provider": "forgejo", "repo": "o/r"},
    "autofix": {"agent": "claude-code", "gates": ["tests", "human-merge"]},
    "tests": "pytest",
    "runtime": {"base": "python-3.12", "install": "none", "dependencies": []},
}


def _project(
    session: Session,
    *,
    active: bool = True,
    slug: str = "p",
    manifest: dict[str, object] | None = None,
) -> Project:
    project = Project(
        slug=slug, forge="forgejo", repo="o/r", active=active,
        webhook_secret_hash="x",  # noqa: S106
        manifest=dict(AGENT_MANIFEST) if manifest is None else manifest,
    )
    session.add(project)
    session.flush()
    return project


def _item(
    session: Session, project: Project, *, state: ItemState = ItemState.READY,
    lane: Lane = Lane.GREEN, fingerprint: str = "fp", kind: ItemKind = ItemKind.BUG,
) -> Item:
    item = Item(
        project_id=project.id, fingerprint=fingerprint, title="ValueError: boom",
        lane=lane, state=state, kind=kind,
    )
    session.add(item)
    session.commit()
    return item


def test_a_ready_green_item_is_eligible(session: Session) -> None:
    item = _item(session, _project(session))

    assert [e.item.id for e in work.eligible(session)] == [item.id]


@pytest.mark.parametrize(
    "state",
    [ItemState.TRIAGED, ItemState.WAITING_APPROVAL, ItemState.IN_PROGRESS, ItemState.DONE],
)
def test_only_ready_items_are_eligible(session: Session, state: ItemState) -> None:
    _item(session, _project(session), state=state)

    assert work.eligible(session) == []


def test_a_red_item_is_never_eligible(session: Session) -> None:
    """Excluded by the query and refused by the state machine, on purpose.

    Item 017: a guardrail that depends on every caller remembering it is not a guardrail.
    """
    item = _item(session, _project(session), lane=Lane.RED, state=ItemState.READY)

    assert work.eligible(session) == []
    assert work.claim(session, item) is False


def test_an_inactive_project_is_left_alone(session: Session) -> None:
    _item(session, _project(session, active=False))

    assert work.eligible(session) == []


def test_the_limit_and_the_project_filter_work(session: Session) -> None:
    first = _project(session, slug="a")
    second = _project(session, slug="b")
    _item(session, first, fingerprint="f1")
    _item(session, second, fingerprint="f2")

    assert len(work.eligible(session, limit=1)) == 1
    assert [e.project.slug for e in work.eligible(session, slug="b")] == ["b"]


def test_claiming_is_committed_before_anything_else_happens(session: Session) -> None:
    """The commit is the point: the window to a container start is long enough to lose a race in."""
    item = _item(session, _project(session))

    assert work.claim(session, item) is True

    session.rollback()  # anything the caller does afterwards cannot undo the claim
    reloaded = session.get(Item, item.id)
    assert reloaded is not None
    assert reloaded.state is ItemState.IN_PROGRESS


def test_a_second_dispatcher_cannot_claim_the_same_item(session: Session) -> None:
    item = _item(session, _project(session))
    work.claim(session, item)

    assert work.claim(session, item) is False


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (AttemptOutcome.PR_OPEN, ItemState.PR_OPEN),
        (AttemptOutcome.NOT_REPRODUCIBLE, ItemState.NOT_REPRODUCIBLE),
        (AttemptOutcome.FAILED, ItemState.FAILED),
    ],
)
def test_a_verdict_settles_the_item(
    session: Session, outcome: AttemptOutcome, expected: ItemState
) -> None:
    item = _item(session, _project(session))
    work.claim(session, item)

    work.release(session, item, outcome)

    assert item.state is expected


@pytest.mark.parametrize(
    "outcome", [AttemptOutcome.ABANDONED, AttemptOutcome.ALREADY_FIXED]
)
def test_an_outcome_that_is_not_about_the_bug_returns_the_item(
    session: Session, outcome: AttemptOutcome
) -> None:
    """Neither is about the bug, so neither settles it — the agent never had a fair try."""
    item = _item(session, _project(session))
    work.claim(session, item)

    work.release(session, item, outcome)

    assert item.state is ItemState.READY


# --- a dispatcher that died -------------------------------------------------------------------


def test_a_stale_attempt_is_released_and_the_record_survives(session: Session) -> None:
    """Deleting the attempt would erase the evidence that this item already cost something."""
    item = _item(session, _project(session))
    work.claim(session, item)
    attempt = start(session, item)
    session.commit()

    freed = work.release_stale(session, now=datetime.now(UTC) + timedelta(hours=4))

    assert freed == [item.id]
    assert item.state is ItemState.READY
    assert attempt.outcome is AttemptOutcome.ABANDONED
    assert attempt.consumed is False
    assert "still has its try" in (attempt.not_consumed_reason or "")


def test_a_live_attempt_is_not_declared_dead(session: Session) -> None:
    """Declaring a running attempt stale would cause the double dispatch claiming prevents."""
    item = _item(session, _project(session))
    work.claim(session, item)
    start(session, item)
    session.commit()

    assert work.release_stale(session) == []
    assert item.state is ItemState.IN_PROGRESS


# --- what the operator is told ------------------------------------------------------------------


def test_ready_items_with_no_credential_say_nothing_will_pick_them_up(session: Session) -> None:
    """"three items are ready and no token is configured" is actionable; "ready: 3" is not."""
    _item(session, _project(session))

    notes = work.readiness_notes(session, code_token_configured=False)

    assert any("nothing will ever pick them up" in n.text for n in notes)
    # And it is a degradation, not a remark: the first version printed this and exited zero.
    assert any(n.degraded for n in notes)


def test_ready_items_with_a_credential_are_merely_reported(session: Session) -> None:
    _item(session, _project(session))

    notes = work.readiness_notes(session, code_token_configured=True)

    assert any("ready for the dispatcher" in n.text for n in notes)
    assert not any(n.degraded for n in notes)


def test_a_stuck_item_is_reported_with_the_command_that_frees_it(session: Session) -> None:
    item = _item(session, _project(session))
    work.claim(session, item)
    item.updated_at = datetime.now(UTC) - timedelta(hours=5)
    session.commit()

    notes = work.readiness_notes(session, code_token_configured=True)

    assert any("--release-stale" in n.text for n in notes)
    assert any(n.degraded for n in notes)


def test_a_quiet_instance_says_nothing(session: Session) -> None:
    _project(session)

    assert work.readiness_notes(session, code_token_configured=True) == []


# --- the sequence of one invocation -------------------------------------------------------------


def test_the_sequence_records_before_it_publishes(session: Session) -> None:
    """A crash between the two must leave a database that knows, not a forge that knows alone."""
    project = _project(session)
    project.manifest = {
        "project": "p",
        "git": {"provider": "forgejo", "repo": "o/r"},
        "autofix": {"agent": "claude-code", "gates": ["tests", "human-merge"]},
        "tests": "pytest",
        "runtime": {"base": "python-3.12", "install": "none", "dependencies": []},
    }
    item = _item(session, project)
    seen: list[str] = []

    class _Box:
        worktree = None

        def run(self, command: str, timeout: int, env: dict[str, str] | None = None) -> object:
            from hullwork.sandbox.run import RunResult

            seen.append(command)
            return RunResult(command=command, exit_code=1, output="red", duration_ms=1)
        # Item 058: production has two entries — `run` (no route out) and `run_with_model`
        # (the gateway reachable). A double that answers only the old single method would
        # send the agent phases down whichever one it happens to have, so it must have both.
        run_with_model = run

    tmp = Path(tempfile.mkdtemp())
    (tmp / "src.py").write_text("1")
    box = _Box()
    box.worktree = tmp  # type: ignore[assignment]

    published: list[object] = []

    def _record_publish(i: Item, a: Attempt, v: object) -> str:
        published.append((i.id, a.outcome))
        return "#7"

    result = work.run_one(
        session,
        work.Eligible(item=item, project=project),
        engine=object(),
        box_factory=lambda manifest: box,
        publisher=_record_publish,
    )

    # The baseline failed, so no model was called. The item goes to a human with its attempt intact
    # (item 043) — this test used a red baseline only as a cheap way to reach a verdict, and until
    # 043 that verdict was `failed`, which consumed.
    assert result.outcome is AttemptOutcome.BASELINE_RED
    assert item.state is ItemState.HUMAN_ONLY
    attempt = session.query(Attempt).one()
    assert attempt.outcome is AttemptOutcome.BASELINE_RED
    assert attempt.phase_reached is AttemptPhase.BASELINE
    assert attempt.consumed is False
    # And the publisher saw an attempt that was already recorded — the point of this test.
    assert published == [(item.id, AttemptOutcome.BASELINE_RED)]


def test_an_unforeseen_failure_never_costs_the_attempt(session: Session) -> None:
    """Anything the dispatcher itself gets wrong is not the agent's fault."""
    project = _project(session)
    project.manifest = {
        "project": "p",
        "git": {"provider": "forgejo", "repo": "o/r"},
        "autofix": {"agent": "claude-code", "gates": ["tests", "human-merge"]},
        "tests": "pytest",
        "runtime": {"base": "python-3.12", "install": "none", "dependencies": []},
    }
    item = _item(session, project)

    def _explode(manifest: object) -> object:
        raise RuntimeError("docker is not running")

    result = work.run_one(
        session,
        work.Eligible(item=item, project=project),
        engine=object(),
        box_factory=_explode,
        publisher=lambda i, a, v: None,
    )

    assert result.outcome is AttemptOutcome.ABANDONED
    assert item.state is ItemState.READY  # still has its try
    assert session.query(Attempt).one().consumed is False


def test_an_item_somebody_else_holds_is_left_alone(session: Session) -> None:
    item = _item(session, _project(session))
    work.claim(session, item)

    held_project = session.get(Project, item.project_id)
    assert held_project is not None
    result = work.run_one(
        session,
        work.Eligible(item=item, project=held_project),
        engine=object(),
        box_factory=lambda m: None,
        publisher=lambda i, a, v: None,
    )

    assert "another dispatcher holds this item" in result.detail


# --- the state machine is the only thing that moves an item (item 042) --------------------------


def test_an_abandoned_attempt_returns_the_item_to_ready_through_the_machine(
    session: Session,
) -> None:
    """`release` used to assign `item.state` directly, because `in-progress → ready` was undeclared.

    The bypass is the finding: `states.py` exists because "a guardrail that depends on every caller
    remembering it is not a guardrail", and this was its only caller going around it.
    """
    project = _project(session)
    item = _item(session, project, state=ItemState.IN_PROGRESS)

    work.release(session, item, AttemptOutcome.ABANDONED)

    assert item.state is ItemState.READY


def test_a_red_item_that_abandons_goes_to_a_human_rather_than_raising(session: Session) -> None:
    """`ready` is an agent state and the machine refuses those to red.

    Declaring the edge without this would turn a lane that changed underneath a running attempt into
    an exception thrown after the work was already done and recorded.
    """
    project = _project(session)
    item = _item(session, project, state=ItemState.IN_PROGRESS, lane=Lane.RED)

    work.release(session, item, AttemptOutcome.ABANDONED)

    assert item.state is ItemState.HUMAN_ONLY


def test_releasing_a_stale_attempt_decides_consumption_in_one_place(session: Session) -> None:
    """It set `outcome`, `consumed` and `not_consumed_reason` by hand — a second copy of the rule
    `attempts.finish` says it owns, which would agree with the original until one of them changed.
    """
    project = _project(session)
    item = _item(session, project, state=ItemState.IN_PROGRESS)
    attempt = start(session, item)
    item.updated_at = datetime.now(UTC) - timedelta(hours=4)
    session.flush()

    freed = work.release_stale(session)

    assert freed == [item.id]
    assert item.state is ItemState.READY
    assert attempt.outcome is AttemptOutcome.ABANDONED
    assert attempt.consumed is False
    assert attempt.not_consumed_reason is not None
    assert "still has its try" in attempt.not_consumed_reason


# --- a red baseline must not cost the item its attempt (item 043) --------------------------------


def test_a_red_baseline_leaves_the_item_its_attempt(session: Session) -> None:
    """It used to return `failed`, which consumes.

    So an item spent its one and only try on the project's own state, before any model was called,
    and the message blamed the project's suite. Item 025's own ticked criterion said this must end
    the item `human-only`, and DR-0003 had already decided the class.
    """
    project = _project(session)
    item = _item(session, project, state=ItemState.IN_PROGRESS)
    attempt = start(session, item)

    finish(session, attempt, AttemptOutcome.BASELINE_RED)
    work.release(session, item, AttemptOutcome.BASELINE_RED)

    assert attempt.consumed is False
    assert consumed_count(session, item) == 0
    assert has_attempt_left(session, item) is True


def test_a_red_baseline_settles_with_a_human_rather_than_requeueing(session: Session) -> None:
    """The one outcome that neither consumes nor returns to the queue.

    `abandoned` goes back to `ready` because the obstacle was transient. A red suite is not: it will
    be red on the next pass too, so requeueing would be a loop and an item cycling through a
    dispatcher for ever is worse than one waiting for a person.
    """
    project = _project(session)
    item = _item(session, project, state=ItemState.IN_PROGRESS)

    work.release(session, item, AttemptOutcome.BASELINE_RED)

    assert item.state is ItemState.HUMAN_ONLY


# --- all five conditions, not three (item 044) ---------------------------------------------------


def test_a_chore_is_not_eligible(session: Session) -> None:
    """The red-green gate is about bugs. An agent handed a chore has nothing to reproduce."""
    project = _project(session)
    _item(session, project, kind=ItemKind.OTHER)

    assert work.eligible(session) == []


def test_an_item_on_a_project_with_no_agent_is_not_eligible(session: Session) -> None:
    """`route()` refuses to leave `triaged` without an agent, so this can only be a leftover.

    A manifest edited since the item was routed is exactly the case a dispatcher must not act on:
    the project's own rules now say no agent, and the manifest is the law.
    """
    without = dict(AGENT_MANIFEST)
    without["autofix"] = {"agent": "none"}
    project = _project(session, manifest=without)
    _item(session, project)

    assert work.eligible(session) == []


def test_an_item_whose_attempt_is_spent_is_not_eligible_even_from_ready(session: Session) -> None:
    """The guarantee that used to be a side effect.

    `has_attempt_left` was written, tested and called from nowhere, so DR-0003's one-attempt rule
    held only because `failed` and `not-reproducible` are terminal. Item 042 declared
    `in-progress → ready` and item 043 added a non-consuming outcome; any path back to `ready`
    turned that side effect into a retry loop with no test to catch it. So this puts a spent
    item *in* `ready` on purpose — the state the old rule depended on never happening.
    """
    project = _project(session)
    item = _item(session, project, state=ItemState.IN_PROGRESS)
    attempt = start(session, item)
    finish(session, attempt, AttemptOutcome.FAILED)
    item.state = ItemState.READY  # the state the old rule relied on never happening
    session.flush()

    assert has_attempt_left(session, item) is False
    assert work.eligible(session) == []


def test_an_item_meeting_all_five_conditions_is_still_eligible(session: Session) -> None:
    """The fix must not be "return nothing", which would pass every test above and no others."""
    project = _project(session)
    item = _item(session, project)

    assert [e.item.id for e in work.eligible(session)] == [item.id]

# --- the checkout the gates run against (item 047) -----------------------------------------------


def _origin(tmp_path: Path, files: dict[str, str]) -> tuple[str, str]:
    """A real repository to clone from, and the sha of its only commit."""
    origin = tmp_path / "origin"
    origin.mkdir()
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.invalid",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.invalid",
    }
    git = shutil.which("git") or "git"

    def run(*argv: str) -> str:
        done = subprocess.run(  # noqa: S603 - argv list, no shell, binary resolved above
            [git, *argv], cwd=origin, env=env, check=True, capture_output=True, text=True
        )
        return done.stdout.strip()

    run("init", "--quiet", "-b", "main")
    for name, body in files.items():
        target = origin / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    run("add", "-A")
    run("commit", "--quiet", "-m", "seed")
    return f"file://{origin}", run("rev-parse", "HEAD")


def test_the_checkout_is_at_the_sha_it_was_asked_for(tmp_path: Path) -> None:
    """Everything the evidence trail claims is a claim about this commit (spec §5.1)."""
    url, sha = _origin(tmp_path, {"billing.py": "x = 1\n"})

    result = work.checkout(url, "tok", into=tmp_path / "clone", ref=sha)

    assert result.sha == sha
    assert (result.path / "billing.py").read_text() == "x = 1\n"


def test_the_credential_is_nowhere_in_the_checkout(tmp_path: Path) -> None:
    """§4.6 measured a token in a clone URL persisting verbatim in `.git/config`, in clear text.

    Asserted over every file rather than over `.git/config` alone: the point is that it is not on
    disk, not that one known hiding place is empty.
    """
    url, _ = _origin(tmp_path, {"a.py": "1\n"})

    result = work.checkout(url, "s3cret-token", into=tmp_path / "clone")

    for path in result.path.rglob("*"):
        if path.is_file():
            assert b"s3cret-token" not in path.read_bytes(), path


def test_the_checkout_cannot_run_anything_as_us_afterwards(tmp_path: Path) -> None:
    """§4.1's vector, closed on the clone as well as by the worktree copy.

    A hook in the tree executes on the host, as the user holding the code token, the next time any
    git command touches it. So the hooks go, `core.hooksPath` points at nothing, and there is no
    remote left to push to either.
    """
    url, _ = _origin(tmp_path, {"a.py": "1\n"})

    result = work.checkout(url, "tok", into=tmp_path / "clone")

    config = (result.path / ".git" / "config").read_text(encoding="utf-8")
    assert "remote" not in config
    assert "hooksPath" in config
    assert not (result.path / ".git" / "hooks").exists()


def test_a_repository_that_is_not_there_is_the_dispatcher_s_problem(tmp_path: Path) -> None:
    """`WiringError`, so `run_one` abandons rather than spending the item's one attempt."""
    with pytest.raises(work.WiringError) as err:
        work.checkout(f"file://{tmp_path}/nope", "tok", into=tmp_path / "clone")

    assert "git clone failed" in str(err.value)


def test_the_credential_is_redacted_out_of_what_git_says(tmp_path: Path) -> None:
    """git echoes URLs back in its errors, and this message ends up in a log or an issue."""
    with pytest.raises(work.WiringError) as err:
        work.checkout(f"file://{tmp_path}/nope", "s3cret-token", into=tmp_path / "clone")

    assert "s3cret-token" not in str(err.value)


def test_the_image_is_never_built_from_half_the_dependencies(tmp_path: Path) -> None:
    """The declared files are the image's cache key (item 037), so a missing one is refused.

    Building from some of them would cache an image under a tag claiming to describe all of them.
    """
    from hullwork.manifest import RuntimeConfig

    (tmp_path / "requirements.txt").write_text("pytest\n", encoding="utf-8")
    runtime = RuntimeConfig(base="python-3.12", install="pip", dependencies=["requirements.txt"])

    assert work.dependency_files(tmp_path, runtime) == {"requirements.txt": b"pytest\n"}

    missing = RuntimeConfig(
        base="python-3.12", install="pip", dependencies=["requirements.txt", "constraints.txt"]
    )
    with pytest.raises(work.WiringError) as err:
        work.dependency_files(tmp_path, missing)

    assert "constraints.txt" in str(err.value)


def test_where_to_clone_from_is_the_operator_s_setting(session: Session) -> None:
    """The manifest is the law about lanes and gates, never about what this host connects to."""
    from hullwork.config import Settings

    project = _project(session)
    settings = Settings(forge_url="https://forgejo.example/")

    assert work.clone_url(settings, project) == "https://forgejo.example/o/r.git"

    project.forge = "github"
    assert work.clone_url(settings, project) == "https://github.com/o/r.git"


# --- publishing what the attempt decided (item 047) ----------------------------------------------


class _CodeForge:
    """A `ForgeCode` that writes down what it was asked to do."""

    def __init__(self, *, exists: set[str] | None = None, draft: bool = True) -> None:
        self.calls: list[str] = []
        self.commits: list[tuple[str, dict[str, str]]] = []
        self.exists = exists or set()
        self.draft = draft
        self.branch: str | None = None

    def default_branch(self, repo: str) -> str:
        return "main"

    def head_commit(self, repo: str, branch: str) -> str:
        return "basesha"

    def create_branch(self, repo: str, name: str, from_ref: str) -> None:
        self.calls.append(f"create_branch {name} from {from_ref}")
        self.branch = name

    def file_sha(self, repo: str, path: str, ref: str) -> str | None:
        return "preimage" if path in self.exists else None

    def commit_files(
        self, repo: str, branch: str, message: str, changes: object, *, author: str, email: str
    ) -> str:
        listed = {c.path: c.operation for c in changes}  # type: ignore[attr-defined]
        self.calls.append(f"commit {message.splitlines()[0]} {sorted(listed)}")
        self.commits.append((message.splitlines()[0], listed))
        return f"sha{len(self.commits)}"

    def open_draft_pull_request(
        self, repo: str, head: str, base: str, title: str, body: str,
        label_ids: list[int] | None = None,
    ) -> object:
        self.calls.append(f"pull {head} -> {base}")
        self.body = body
        return SimpleNamespace(
            number=7, title=title, html_url="https://forge/pulls/7", draft=self.draft, ref="#7"
        )


class _Issues:
    def __init__(self) -> None:
        self.comments: list[tuple[int, str]] = []

    def comment(self, repo: str, number: int, body: str) -> None:
        self.comments.append((number, body))


def _verdict(
    outcome: AttemptOutcome,
    *,
    candidate: dict[str, bytes] | None = None,
    changes: dict[str, bytes] | None = None,
    deleted: tuple[str, ...] = (),
    **kwargs: object,
) -> object:
    """A verdict shaped like the one `dispatch` actually returns.

    It used to take `candidate=` and `changes=` as bare dicts, with a `type: ignore` covering the
    mismatch. Item 045 made both fields a `Changes`, and because this double kept passing dicts the
    publisher's `changes.items()` went on working here and crashed on every real pull request. A
    double that does not build what production builds is not a test of production.
    """
    from hullwork.dispatch import Verdict
    from hullwork.sandbox.run import Changes

    return Verdict(
        outcome=outcome,
        phase=AttemptPhase.PUBLISH,
        candidate=Changes(written=candidate or {}),
        changes=Changes(written=changes or {}, deleted=deleted),
        **kwargs,  # type: ignore[arg-type]
    )


def _attempt_for(session: Session, item: Item, outcome: AttemptOutcome) -> Attempt:
    from hullwork import attempts

    attempt = start(session, item)
    attempts.finish(session, attempt, outcome)
    session.commit()
    return attempt


def test_the_test_commit_lands_before_the_fix_commit(session: Session) -> None:
    """The order *is* the evidence: a reviewer checks out the first commit and watches it fail."""
    item = _item(session, _project(session))
    attempt = _attempt_for(session, item, AttemptOutcome.PR_OPEN)
    code, issues = _CodeForge(exists={"billing.py"}), _Issues()

    url = work.publish(
        code, issues, repo="o/r", item=item, attempt=attempt,
        verdict=_verdict(
            AttemptOutcome.PR_OPEN,
            candidate={"tests/test_regression.py": b"assert False"},
            changes={"tests/test_regression.py": b"assert False", "billing.py": b"fixed"},
        ),
        base_sha="basesha",
    )

    assert url == "https://forge/pulls/7"
    assert code.calls[0] == "create_branch hullwork/item-1-attempt-1 from basesha"
    first, second = code.commits
    assert first[0].startswith("test: reproduce")
    assert list(first[1]) == ["tests/test_regression.py"]
    assert second[0].startswith("fix:")
    # The candidate is already committed; sending it again would be an empty diff the forge accepts
    # by moving the branch head with an empty commit rather than by complaining.
    assert list(second[1]) == ["billing.py"]
    assert second[1]["billing.py"] == "update"  # it exists in the repository, so update


def test_a_file_the_repository_does_not_have_is_created(session: Session) -> None:
    """Create-or-update is the forge's answer, not the worktree's — found on the first real run."""
    item = _item(session, _project(session))
    attempt = _attempt_for(session, item, AttemptOutcome.PR_OPEN)
    code = _CodeForge(exists=set())

    work.publish(
        code, _Issues(), repo="o/r", item=item, attempt=attempt,
        verdict=_verdict(
            AttemptOutcome.PR_OPEN,
            candidate={"tests/t.py": b"x"}, changes={"tests/t.py": b"x", "new.py": b"y"},
        ),
        base_sha="basesha",
    )

    assert code.commits[0][1] == {"tests/t.py": "create"}
    assert code.commits[1][1] == {"new.py": "create"}


@pytest.mark.parametrize(
    "outcome", [AttemptOutcome.NOT_REPRODUCIBLE, AttemptOutcome.FAILED, AttemptOutcome.ABANDONED]
)
def test_anything_but_a_pull_request_goes_on_the_issue(
    session: Session, outcome: AttemptOutcome
) -> None:
    """DR-0003: `not-reproducible` is a first-class result, and one nobody can see is not a result.

    And **no branch and no pull request**. A pipeline that always produces one produces guesses.
    """
    item = _item(session, _project(session))
    item.forge_issue_ref = "#42"
    attempt = _attempt_for(session, item, outcome)
    code, issues = _CodeForge(), _Issues()

    reference = work.publish(
        code, issues, repo="o/r", item=item, attempt=attempt,
        verdict=_verdict(outcome), base_sha="basesha",
    )

    assert reference == "#42"
    assert code.calls == []
    assert issues.comments[0][0] == 42


def test_a_branch_left_by_a_dead_dispatcher_is_not_overwritten(session: Session) -> None:
    """Reusing it would silently rewrite whatever that attempt left in an open pull request."""
    from hullwork.forge import BranchExistsError

    item = _item(session, _project(session))
    attempt = _attempt_for(session, item, AttemptOutcome.PR_OPEN)

    class _Taken(_CodeForge):
        def create_branch(self, repo: str, name: str, from_ref: str) -> None:
            raise BranchExistsError("already there")

    code = _Taken()
    reference = work.publish(
        code, _Issues(), repo="o/r", item=item, attempt=attempt,
        verdict=_verdict(AttemptOutcome.PR_OPEN, candidate={"tests/t.py": b"x"},
                         changes={"tests/t.py": b"x"}),
        base_sha="basesha",
    )

    assert reference is None
    assert code.commits == []


def test_a_forge_that_fails_does_not_undo_a_recorded_verdict(session: Session) -> None:
    """The verdict is already in the database; publishing is the last thing that can go wrong.

    Raising here would turn a decided attempt into an abandoned one and hand the item back for a
    second try it has already spent.
    """
    from hullwork.forge import ForgeError

    item = _item(session, _project(session))
    attempt = _attempt_for(session, item, AttemptOutcome.PR_OPEN)

    class _Broken(_CodeForge):
        def commit_files(self, *args: object, **kwargs: object) -> str:
            raise ForgeError("the forge is down")

    reference = work.publish(
        _Broken(), _Issues(), repo="o/r", item=item, attempt=attempt,
        verdict=_verdict(AttemptOutcome.PR_OPEN, candidate={"tests/t.py": b"x"},
                         changes={"tests/t.py": b"x"}),
        base_sha="basesha",
    )

    assert reference is None
    assert "publishing failed" in (attempt.error or "")


def test_a_pull_request_the_forge_did_not_mark_draft_is_shouted_about(
    session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    """Forgejo derives draft from a title prefix an instance can reconfigure, exposed by no API.

    So the response is read back. A merge-ready pull request from a bot is the one artefact this
    product must never leave behind.
    """
    item = _item(session, _project(session))
    attempt = _attempt_for(session, item, AttemptOutcome.PR_OPEN)

    with caplog.at_level("ERROR"):
        work.publish(
            _CodeForge(draft=False), _Issues(), repo="o/r", item=item, attempt=attempt,
            verdict=_verdict(AttemptOutcome.PR_OPEN, candidate={"tests/t.py": b"x"},
                             changes={"tests/t.py": b"x"}),
            base_sha="basesha",
        )

    assert "did not mark it a draft" in caplog.text


def test_the_seal_is_stored_with_the_verdict(session: Session) -> None:
    """DR-0002 §4 makes provenance the reason to trust any of this, and the recording is in hand.

    Before this, `run_one` finished the attempt without it and the pull request body had to say the
    model was unknown.
    """
    from hullwork.gateway import Recording
    from hullwork.gateway.protocols import Observation

    project = _project(session)
    project.manifest = {
        "project": "p",
        "git": {"provider": "forgejo", "repo": "o/r"},
        "autofix": {"agent": "claude-code", "gates": ["tests", "human-merge"]},
        "tests": "pytest",
        "runtime": {"base": "python-3.12", "install": "none", "dependencies": []},
    }
    item = _item(session, project)
    recording = Recording(endpoint="https://api.example", pinned_model="pinned-1")
    recording.observe(Observation(model="served-2", input_tokens=11))

    class _Box:
        worktree = Path(tempfile.mkdtemp())

        def run(self, command: str, timeout: int, env: dict[str, str] | None = None) -> object:
            from hullwork.sandbox.run import RunResult

            return RunResult(command=command, exit_code=1, output="red", duration_ms=1)
        # Item 058: production has two entries — `run` (no route out) and `run_with_model`
        # (the gateway reachable). A double that answers only the old single method would
        # send the agent phases down whichever one it happens to have, so it must have both.
        run_with_model = run

    work.run_one(
        session,
        work.Eligible(item=item, project=project),
        engine=object(),
        box_factory=lambda m: _Box(),
        publisher=lambda i, a, v: None,
        recording=recording,
        image_tag="hullwork-sandbox:abc",
        base_sha="deadbeef",
        production_ref="1.2.3",
    )

    attempt = session.query(Attempt).one()
    assert attempt.seal["models_served"] == ["served-2"]
    assert attempt.seal["model_requested"] == "pinned-1"
    # The endpoint served something other than what was pinned, and the seal says so rather than
    # leaving it to be noticed (DR-0002's documented failure mode).
    assert attempt.seal["violations"][0]["kind"] == "model-drift"
    assert attempt.image_tag == "hullwork-sandbox:abc"
    assert attempt.base_sha == "deadbeef"
    assert attempt.production_ref == "1.2.3"


# --- an endpoint that never answered is not the agent's fault (item 047, found by running it) -----


def _run_with_recording(session: Session, recording: object) -> work.Outcome:
    """One dispatch that ends `not-reproducible`, which is the outcome the rescue exists for.

    This used a failing baseline, "so the verdict is terminal and cheap to produce". Item 043 landed
    in parallel and made a red baseline `baseline-red`, which does **not** consume and which
    `never_reached_a_model` deliberately does not rescue — a red baseline happens before any model
    is called, so "no model answered" is expected there and is evidence of nothing. The vehicle had
    therefore stopped exercising the rescue at all, and two of the three tests below would have gone
    on passing without touching it.

    So the suite passes and the agent writes no test: `not-reproducible`, which consumes, and which
    is the outcome the real incident in the docstrings below actually produced.
    """
    project = _project(session)
    project.manifest = {
        "project": "p",
        "git": {"provider": "forgejo", "repo": "o/r"},
        "autofix": {"agent": "claude-code", "gates": ["tests", "human-merge"]},
        "tests": "pytest",
        "runtime": {"base": "python-3.12", "install": "none", "dependencies": []},
    }
    item = _item(session, project)

    class _Box:
        worktree = Path(tempfile.mkdtemp())
        # The agent phase runs now that the baseline is green, and it looks for its report here.
        contract_dir = None

        def run(self, command: str, timeout: int, env: dict[str, str] | None = None) -> object:
            from hullwork.sandbox.run import RunResult

            # Green: the point is a genuine agent verdict, not a broken project.
            return RunResult(command=command, exit_code=0, output="1 passed", duration_ms=1)
        # Item 058: production has two entries — `run` (no route out) and `run_with_model`
        # (the gateway reachable). A double that answers only the old single method would
        # send the agent phases down whichever one it happens to have, so it must have both.
        run_with_model = run

    return work.run_one(
        session,
        work.Eligible(item=item, project=project),
        engine=Engine(name="fake", image="img", protocol="anthropic", command="agent {phase}"),
        box_factory=lambda m: _Box(),
        publisher=lambda i, a, v: None,
        recording=recording,  # type: ignore[arg-type]
    )


def test_an_endpoint_that_never_completed_does_not_spend_the_attempt(session: Session) -> None:
    """Spec §8: infrastructure never consumes an attempt. Found by running it, on a 401.

    The subscription token had expired. The gateway forwarded 22 requests, every one came back
    401, and the harness then reported `subtype: success` with `is_error: true` and answered with
    `model: <synthetic>` — so its own account of itself was useless. The seal knew: 22 responses,
    no model. The item had been marked `not-reproducible`, which is terminal, over an expired
    credential.
    """
    from hullwork.gateway import Recording
    from hullwork.gateway.protocols import Observation

    recording = Recording(endpoint="https://api.example")
    for _ in range(22):
        recording.observe(Observation())  # a response, carrying no model: not a completion

    result = _run_with_recording(session, recording)

    assert result.outcome is AttemptOutcome.ABANDONED
    assert "never reached a model" in result.detail
    attempt = session.query(Attempt).one()
    assert attempt.consumed is False
    assert session.query(Item).one().state is ItemState.READY  # still has its try


def test_a_real_answer_still_settles_the_item(session: Session) -> None:
    """The rescue must not swallow a genuine verdict — that would make every failure retryable."""
    from hullwork.gateway import Recording
    from hullwork.gateway.protocols import Observation

    recording = Recording(endpoint="https://api.example")
    recording.observe(Observation(model="claude-opus-5", input_tokens=100))

    result = _run_with_recording(session, recording)

    assert result.outcome is AttemptOutcome.NOT_REPRODUCIBLE
    assert session.query(Attempt).one().consumed is True


def test_with_nobody_watching_the_wire_nothing_is_concluded(session: Session) -> None:
    """Silence is not evidence: without a recording there is no basis to overrule the verdict."""
    result = _run_with_recording(session, None)

    assert result.outcome is AttemptOutcome.NOT_REPRODUCIBLE


def test_the_reason_names_the_statuses_it_saw(session: Session) -> None:
    """"The endpoint answered 0 time(s)" was printed on a run where it answered ten times, all 401.

    The decision is unchanged and correct; its account of the evidence sent three of four diagnostic
    rounds into the network while the endpoint was answering promptly and refusing the credential.
    """
    from hullwork.gateway import Recording
    from hullwork.gateway.protocols import Observation

    recording = Recording(endpoint="https://api.example")
    for _ in range(10):
        recording.observe(Observation(status=401))

    result = _run_with_recording(session, recording)

    assert result.outcome is AttemptOutcome.ABANDONED
    assert "10 time(s)" in result.detail
    assert "401 x10" in result.detail
    assert session.query(Attempt).one().seal["statuses"] == {"401": 10}


# --- the recording is read after the phases run, not before them (item 056) -----------------------


def test_the_seal_covers_what_happened_during_the_attempt(session: Session) -> None:
    """The defect this item exists for, tested the only way it can fail: by effect, over time.

    `work._attempt` built the recording in **argument position**, so Python resolved it before
    `run_one` was entered — before the baseline, before the agent, before anything could be written
    to the journal. Since item 054 `Cable.recording` replays a file rather than handing over a live
    object, so the snapshot was empty on every attempt and empty for ever.

    That is not a missing field. `never_reached_a_model` reads `models_served`, saw nothing, and
    overruled real verdicts: measured on this repository with a real model, an attempt that failed
    the lint gate was recorded as `abandoned` saying "the agent never reached a model" after talking
    to `claude-opus-5` twice.

    **Every other test in this file populates the recording before the call**, which is the
    production bug expressed as a fixture, so none of them can fail on it. This one writes the
    observation from inside the sandbox double — the same order the real thing has.

    Driven through a **real journal** rather than a shared `Recording`, and that detail is the test.
    A live object handed in as a value goes on filling up by reference, so mutating one would pass
    against the defect too — verified by reintroducing the early read, which this test survived
    until it was rewritten this way. `Cable.recording` builds a new `Recording` from a file on every
    call, so a snapshot taken early stays empty, and only a provider resolved late can see anything.
    """
    from hullwork.gateway.journal import Journal, read
    from hullwork.gateway.protocols import Observation

    project = _project(session)
    item = _item(session, project)

    journal_path = Path(tempfile.mkdtemp()) / "journal.jsonl"
    journal = Journal(journal_path)

    def wire() -> object:
        return read(
            journal_path, endpoint="https://api.example", pinned_model="claude-opus-5"
        ).recording

    class _Box:
        worktree = Path(tempfile.mkdtemp())
        contract_dir = None

        def run(self, command: str, timeout: int, env: dict[str, str] | None = None) -> object:
            from hullwork.sandbox.run import RunResult

            # The model answers while the phases run, which is when it answers in production.
            journal.observed(Observation(model="claude-opus-5", status=200, input_tokens=10))
            return RunResult(command=command, exit_code=0, output="1 passed", duration_ms=1)
        # Item 058: production has two entries — `run` (no route out) and `run_with_model`
        # (the gateway reachable). A double that answers only the old single method would
        # send the agent phases down whichever one it happens to have, so it must have both.
        run_with_model = run

    result = work.run_one(
        session,
        work.Eligible(item=item, project=project),
        engine=Engine(name="fake", image="img", protocol="anthropic", command="agent {phase}"),
        box_factory=lambda m: _Box(),
        publisher=lambda i, a, v: None,
        recording=wire,  # type: ignore[arg-type]
    )

    # Against the old code this is `abandoned` with an empty seal, because the recording was read
    # before `_Box.run` ever fired.
    assert result.outcome is AttemptOutcome.NOT_REPRODUCIBLE
    attempt = session.query(Attempt).one()
    assert attempt.seal["models_served"] == ["claude-opus-5"]
    assert attempt.consumed is True
    # And the caller's own log reports the seal that was stored rather than reading the journal a
    # second time, which could disagree with the database.
    assert result.seal == attempt.seal


def test_a_deletion_reaches_the_forge_as_a_delete(session: Session) -> None:
    """Item 045's other half, and the first caller `FileChange(operation="delete")` has ever had.

    The gates ran against a tree with the file gone. Publishing everything *except* that fact would
    put the untested tree in the pull request, which is the red-green claim being false about the
    thing a reviewer is looking at.
    """
    item = _item(session, _project(session))
    attempt = _attempt_for(session, item, AttemptOutcome.PR_OPEN)
    code, issues = _CodeForge(exists={"billing.py", "validate.py"}), _Issues()

    work.publish(
        code, issues, repo="o/r", item=item, attempt=attempt,
        verdict=_verdict(
            AttemptOutcome.PR_OPEN,
            candidate={"tests/test_regression.py": b"assert False"},
            changes={"billing.py": b"fixed"},
            deleted=("validate.py",),
        ),
        base_sha="basesha", brief_text="", secrets=[],
    )

    _, fix_commit = code.commits
    assert fix_commit[1] == {"billing.py": "update", "validate.py": "delete"}


def test_a_file_already_absent_upstream_is_not_deleted_again(session: Session) -> None:
    """No pre-image sha means the forge does not have it, and asking it to delete is a 404."""
    item = _item(session, _project(session))
    attempt = _attempt_for(session, item, AttemptOutcome.PR_OPEN)
    code, issues = _CodeForge(exists={"billing.py"}), _Issues()

    work.publish(
        code, issues, repo="o/r", item=item, attempt=attempt,
        verdict=_verdict(
            AttemptOutcome.PR_OPEN,
            candidate={"tests/test_regression.py": b"assert False"},
            changes={"billing.py": b"fixed"},
            deleted=("never-there.py",),
        ),
        base_sha="basesha", brief_text="", secrets=[],
    )

    _, fix_commit = code.commits
    assert "never-there.py" not in fix_commit[1]


def test_the_attempt_remembers_what_it_pushed(session: Session) -> None:
    """Item 048. `branch` and `pull_request_ref` were declared and written by nothing.

    So the database could not answer "which branch did attempt 12 push?" — the first question
    anybody debugging a half-published attempt asks — and it is what the `BranchExistsError`
    path reads as a symptom of while having no record of ever creating one.
    """
    item = _item(session, _project(session))
    attempt = _attempt_for(session, item, AttemptOutcome.PR_OPEN)
    code, issues = _CodeForge(exists={"billing.py"}), _Issues()

    work.publish(
        code, issues, repo="o/r", item=item, attempt=attempt,
        verdict=_verdict(
            AttemptOutcome.PR_OPEN,
            candidate={"tests/test_regression.py": b"assert False"},
            changes={"billing.py": b"fixed"},
        ),
        base_sha="basesha", brief_text="", secrets=[],
    )

    assert attempt.branch == code.branch
    assert attempt.pull_request_ref == "#7"


def test_the_branch_is_recorded_even_when_publishing_then_fails(session: Session) -> None:
    """It exists on the forge either way, and a record of it is the difference between being able to
    clean up and having to go looking."""
    from hullwork.forge import ForgeError

    item = _item(session, _project(session))
    attempt = _attempt_for(session, item, AttemptOutcome.PR_OPEN)
    code, issues = _CodeForge(exists={"billing.py"}), _Issues()

    def boom(*args: object, **kwargs: object) -> str:
        raise ForgeError("the forge went away")

    code.commit_files = boom  # type: ignore[method-assign]

    result = work.publish(
        code, issues, repo="o/r", item=item, attempt=attempt,
        verdict=_verdict(
            AttemptOutcome.PR_OPEN,
            candidate={"tests/test_regression.py": b"assert False"},
            changes={"billing.py": b"fixed"},
        ),
        base_sha="basesha", brief_text="", secrets=[],
    )

    assert result is None
    assert attempt.branch is not None
    assert attempt.pull_request_ref is None


# --- a rehearsal costs nothing (item 049) --------------------------------------------------------


def _one_run(session: Session, *, rehearsal: bool, into: Path | None = None) -> work.Outcome:
    """One `run_one` over a scripted sandbox that reaches a real `pr-open` verdict."""
    project = _project(session)
    item = _item(session, project)
    tmp = Path(tempfile.mkdtemp())
    (tmp / "src.py").write_text("x = 1\n")
    (tmp / "tests").mkdir()
    counts: dict[str, int] = {}

    class _Box:
        worktree = tmp
        contract_dir = None

        def run(self, command: str, timeout: int, env: dict[str, str] | None = None) -> object:
            from hullwork.sandbox.run import RunResult

            nth = counts.get(command, 0)
            counts[command] = nth + 1
            if command == "agent reproduce":
                (tmp / "tests" / "test_repro.py").write_text("def test_x():\n    assert False\n")
            if command == "agent fix":
                (tmp / "src.py").write_text("x = 2\n")
            # The second `pytest` is the red gate and must fail; the rest pass.
            code = 1 if (command == "pytest" and nth == 1) else 0
            return RunResult(command=command, exit_code=code, output="out", duration_ms=1)
        # Item 058: production has two entries — `run` (no route out) and `run_with_model`
        # (the gateway reachable). A double that answers only the old single method would
        # send the agent phases down whichever one it happens to have, so it must have both.
        run_with_model = run

    published: list[object] = []

    def forge_publisher(i: Item, a: Attempt, v: object) -> str | None:
        published.append(i.id)
        return "#9"

    return work.run_one(
        session,
        work.Eligible(item=item, project=project),
        engine=Engine(name="fake", image="img", protocol="anthropic", command="agent {phase}"),
        box_factory=lambda m: _Box(),
        publisher=work.write_locally(into) if into is not None else forge_publisher,
        rehearsal=rehearsal,
    )


def test_a_rehearsal_reaches_the_verdict_and_keeps_the_attempt(
    session: Session, tmp_path: Path
) -> None:
    """The trap DR-0006's amendment measured.

    A dry run that reached `pr-open` used to park the item in `pr-open` — asserting a pull request
    that does not exist — spend its one attempt, and leave no legal edge back to `ready`.
    """
    result = _one_run(session, rehearsal=True, into=tmp_path)

    assert result.outcome is AttemptOutcome.PR_OPEN
    attempt = session.query(Attempt).one()
    assert attempt.rehearsal is True
    assert attempt.consumed is False
    assert "rehearsal" in (attempt.not_consumed_reason or "")
    item = session.query(Item).one()
    assert item.state is ItemState.READY
    assert has_attempt_left(session, item) is True


def test_a_real_run_still_spends_the_attempt(session: Session) -> None:
    """The mode must not leak into the default."""
    result = _one_run(session, rehearsal=False)

    assert result.outcome is AttemptOutcome.PR_OPEN
    attempt = session.query(Attempt).one()
    assert attempt.rehearsal is False
    assert attempt.consumed is True
    assert session.query(Item).one().state is ItemState.PR_OPEN


def test_the_gates_cannot_differ_by_mode(session: Session, tmp_path: Path) -> None:
    """Dry-run changes the destination, never the rigour (DR-0006 §1).

    Asserted over the recorded trail rather than trusted: a mode that skipped a gate to look better
    would be demonstrating the wrong product, and the trail is the only place that can prove it did
    not.
    """
    _one_run(session, rehearsal=False)
    real = [(s.phase, s.command, s.exit_code) for s in session.query(Attempt).one().steps]

    engine2 = create_engine("sqlite://")
    Base.metadata.create_all(engine2)
    second = sessionmaker(bind=engine2)()
    _one_run(second, rehearsal=True, into=tmp_path)
    rehearsed = [(s.phase, s.command, s.exit_code) for s in second.query(Attempt).one().steps]

    assert rehearsed == real


def test_a_rehearsal_writes_what_it_produced(session: Session, tmp_path: Path) -> None:
    """A rehearsal nobody can look at proves nothing."""
    _one_run(session, rehearsal=True, into=tmp_path)

    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())

    assert any(p.endswith("candidate/tests/test_repro.py") for p in written)
    assert any(p.endswith("fix/src.py") for p in written)
    assert any(p.endswith("artefact.md") for p in written)


# --- our own ceiling is not a verdict about the bug (item 059) ------------------------------------


def _run_with_journal(
    session: Session,
    *,
    completions: int,
    candidate: bytes | None,
    max_turns: int = 30,
) -> tuple[work.Outcome, Path]:
    """One dispatch where the model answers `completions` times **during** the phases.

    Through a real journal replayed per call, as item 056's test does: a live `Recording` handed in
    already populated is the production defect expressed as a fixture, and passes either way.
    """
    from hullwork.gateway.journal import Journal, read
    from hullwork.gateway.protocols import Observation

    project = _project(session)
    item = _item(session, project)
    journal_path = Path(tempfile.mkdtemp()) / "journal.jsonl"
    journal = Journal(journal_path)
    worktree = Path(tempfile.mkdtemp())

    class _Box:
        contract_dir = None

        def __init__(self) -> None:
            self.worktree = worktree

        def run(self, command: str, timeout: int, env: dict[str, str] | None = None) -> object:
            from hullwork.sandbox.run import RunResult

            return RunResult(command=command, exit_code=0, output="1 passed", duration_ms=1)

        def run_with_model(
            self, command: str, timeout: int, env: dict[str, str] | None = None
        ) -> object:
            from hullwork.sandbox.run import RunResult

            for _ in range(completions):
                journal.observed(Observation(model="claude-opus-5", status=200))
            if candidate is not None:
                (worktree / "tests").mkdir(parents=True, exist_ok=True)
                (worktree / "tests" / "test_regression.py").write_bytes(candidate)
            # `exit 1` is what the harness returns when the ceiling cuts it off. It decides nothing.
            return RunResult(command=command, exit_code=1, output="cut off", duration_ms=1)

    outcome = work.run_one(
        session,
        work.Eligible(item=item, project=project),
        engine=Engine(
            name="fake", image="img", protocol="anthropic",
            command="agent {phase}", max_turns=max_turns,
        ),
        box_factory=lambda m: _Box(),
        publisher=lambda i, a, v: None,
        recording=lambda: read(
            journal_path, endpoint="https://api.example", pinned_model="claude-opus-5"
        ).recording,
    )
    return outcome, journal_path


def test_a_spent_ceiling_with_nothing_written_does_not_settle_the_item(session: Session) -> None:
    """Measured three times on one item, and twice it published a false claim about the bug.

    `--max-turns 30`, and all three rehearsals used all thirty. In two of them the agent had written
    no test when it was cut off — `stop_reason: tool_use` — and the attempt was recorded
    `not-reproducible`: terminal, consuming, and printing "the bug could not be reproduced… that is
    the correct outcome rather than a failure". What actually happened is that this dispatcher gave
    it thirty turns and the work needed more.
    """
    outcome, _ = _run_with_journal(session, completions=31, candidate=None, max_turns=30)

    assert outcome.outcome is AttemptOutcome.ABANDONED
    assert "every one of the 30 turns" in outcome.detail
    assert "says nothing about whether the bug is reproducible" in outcome.detail
    attempt = session.query(Attempt).one()
    assert attempt.consumed is False
    assert session.query(Item).one().state is ItemState.READY  # back in the queue


def test_a_spent_ceiling_that_did_produce_a_test_still_settles_the_item(session: Session) -> None:
    """The narrowness is the point: a real verdict must survive having been expensive.

    Here the agent wrote a candidate and the red gate passes against unmodified code — which under
    DR-0003 means the test reproduces nothing. That is a verdict about the *bug*, so it is terminal
    and it consumes, whatever the run cost to produce.
    """
    outcome, _ = _run_with_journal(
        session, completions=31, candidate=b"def test_x():\n    pass\n", max_turns=30
    )

    assert outcome.outcome is AttemptOutcome.NOT_REPRODUCIBLE
    assert session.query(Attempt).one().consumed is True


def test_stopping_short_of_the_ceiling_is_a_real_verdict(session: Session) -> None:
    """An agent that gave up with turns to spare wrote no test because it could not, not because it
    was cut off. That is the verdict `not-reproducible` exists to record."""
    outcome, _ = _run_with_journal(session, completions=4, candidate=None, max_turns=30)

    assert outcome.outcome is AttemptOutcome.NOT_REPRODUCIBLE
    assert session.query(Attempt).one().consumed is True


# --- an item whose verdict has nowhere to go is not attempted (item 069) -------------------------


def test_a_missing_issue_is_refused_before_the_attempt_is_spent() -> None:
    """Measured on the first publishing run: the item pointed at issue #3, the project's repo had
    none, and the comment 404'd *after* the verdict was recorded and consumed.

    So the item's one and only attempt was spent producing a first-class result that no human could
    read — which is precisely what `work.publish`'s docstring says must not happen: *"a first-class
    result that only exists in a database is one nobody acts on."*

    A `WiringError`, raised before the claim, so `run_one` never runs and the attempt survives.
    """

    class _Gone:
        def get_issue(self, repo: str, number: int) -> None:
            return None

    with pytest.raises(work.WiringError) as caught:
        work._the_issue_must_still_exist(_Gone(), "o/r", "#3")

    assert "#3" in str(caught.value)
    assert "keeps " in str(caught.value)  # it says the attempt is not lost


def test_an_unreachable_forge_is_not_the_same_fact_as_a_missing_issue() -> None:
    """One will succeed on retry and the other never will, so the message has to say which.

    Conflating them either retries a permanent condition for ever or gives up on a transient one.
    """
    from hullwork.forge import RetryableForgeError

    class _Down:
        def get_issue(self, repo: str, number: int) -> None:
            raise RetryableForgeError("the forge timed out")

    with pytest.raises(work.WiringError) as caught:
        work._the_issue_must_still_exist(_Down(), "o/r", "#3")

    assert "could not check" in str(caught.value)
    assert "timed out" in str(caught.value)


def test_an_issue_that_exists_is_dispatched_exactly_as_before() -> None:
    """The negative half. A guard that refuses everything would be worse than the defect."""

    class _There:
        def get_issue(self, repo: str, number: int) -> object:
            return object()

    work._the_issue_must_still_exist(_There(), "o/r", "#42")  # must not raise


def test_the_guard_is_actually_called_before_the_claim(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The three tests above exercise the function and **not the call site**, which is the gap this
    project keeps finding: a check nothing invokes is a knob wired to nothing.

    Verified by effect: with the guard raising, `work.run` must not reach the claim — so no attempt
    row exists and the item is still `ready`.
    """
    from pydantic import SecretStr

    from hullwork.config import Settings

    project = _project(session)
    item = _item(session, project)
    item.forge_issue_ref = "#3"
    session.commit()

    called: list[tuple[str, str]] = []

    def _refuse(forge: object, repo: str, ref: str) -> None:
        called.append((repo, ref))
        msg = f"issue {ref} does not exist in {repo}; the item keeps its attempt"
        raise work.WiringError(msg)

    monkeypatch.setattr(work, "_the_issue_must_still_exist", _refuse)
    monkeypatch.setattr(
        work, "_model_credential", lambda settings: "sk-not-used-because-we-refuse-first"
    )

    class _Forge:
        def default_branch(self, repo: str) -> str:  # pragma: no cover - never reached
            raise AssertionError("the guard must refuse before anything is read from the forge")

        def close(self) -> None:
            pass

    monkeypatch.setattr("hullwork.forge.factory.make_forge", lambda s: _Forge())
    monkeypatch.setattr("hullwork.forge.factory.make_code_forge", lambda s: _Forge())

    settings = Settings(
        forge_url="https://forge.example",
        forge_token=SecretStr("read"),
        forge_code_token=SecretStr("write"),
    )

    with pytest.raises(work.WiringError, match="#3"):
        work.run(session, settings)

    assert called == [("o/r", "#3")]
    assert session.query(Attempt).count() == 0
    assert session.query(Item).one().state is ItemState.READY


def test_a_failed_publish_is_visible_in_status(session: Session) -> None:
    """It was only in a log line, and item 019 exists because a clear sentence followed by exit 0 is
    indistinguishable from health.

    `publish` records the failure on the attempt instead of raising — deliberately, so a lost
    comment cannot turn a recorded verdict into an abandoned attempt — so the database had the fact
    and nothing surfaced it. Measured on the first publishing run: the comment 404'd, the attempt
    was consumed, and the operator's only signal scrolled past.
    """
    item = _item(session, _project(session))
    work.claim(session, item)
    attempt = start(session, item)
    finish(session, attempt, AttemptOutcome.NOT_REPRODUCIBLE)
    attempt.error = "publishing failed: POST /repos/o/r/issues/3/comments: HTTP 404"
    session.commit()

    notes = work.readiness_notes(session, code_token_configured=True)

    say = [n for n in notes if "could not publish" in n.text]
    assert say, [n.text for n in notes]
    assert say[0].degraded is True  # so `hullwork status` exits non-zero


def test_status_names_items_whose_issue_no_longer_exists(session: Session) -> None:
    """So the operator hears about it before the dispatcher does — a warning, not a post-mortem."""
    item = _item(session, _project(session))
    item.forge_issue_ref = "#3"
    session.commit()

    class _Gone:
        def get_issue(self, repo: str, number: int) -> None:
            return None

    notes = work.readiness_notes(session, code_token_configured=True, forge=_Gone())

    stranded = [n for n in notes if "#3" in n.text]
    assert stranded and stranded[0].degraded is True


def test_a_blinking_forge_does_not_report_every_project_as_stranded(session: Session) -> None:
    """The opposite of the dispatcher's guard, and deliberately so.

    `_attempt` refuses on an unreachable forge because it must not spend an attempt on a verdict
    that may be unpostable. `status` answers "fine" instead: a status command that cried wolf every
    time the forge blinked would be worse than one that misses a case, because the guard is what
    actually protects the attempt.
    """
    from hullwork.forge import RetryableForgeError

    item = _item(session, _project(session))
    item.forge_issue_ref = "#3"
    session.commit()

    class _Down:
        def get_issue(self, repo: str, number: int) -> None:
            raise RetryableForgeError("timed out")

    notes = work.readiness_notes(session, code_token_configured=True, forge=_Down())

    assert not [n for n in notes if "#3" in n.text]


# --- the sixth condition: an item nobody has asked about waits. Item 100 -------------------------


def test_an_item_nobody_has_enriched_waits_when_a_tracker_could_still_answer(
    session: Session,
) -> None:
    """**Measured on attempt 20, and the race gets likelier the faster the dispatcher is.**

    The item was filed by `sweep_inventory`, which reads the tracker's *list* route — issue
    metadata, no frames — and was claimed within the minute, before `fetch_context` had run on its
    own clock. The brief carried the issue title and nothing else: no exception type, no frames, no
    locals, no release, where the three attempts before it had all had them.

    One enrichment pass costs one HTTP request and arrives within a minute. An attempt costs a
    clone, an image, a container and a model. So the wait is between *dispatching early* and
    *dispatching without evidence*, the distinction the operator chose on 2026-07-31.
    """
    project = _project(session)
    item = _item(session, project)
    assert item.context_checked_at is None

    assert work.eligible(session, tracker_configured=True) == []
    # And the same item, once anybody has asked, goes.
    item.context_checked_at = datetime.now(UTC)
    session.flush()
    assert [e.item.id for e in work.eligible(session, tracker_configured=True)] == [item.id]


def test_an_enrichment_that_came_back_empty_still_dispatches(session: Session) -> None:
    """The negative that keeps this from becoming a gate on evidence rather than on asking.

    An issue whose event the tracker cannot serve must still be attemptable, and
    `not-reproducible` on a title alone is a legitimate outcome — the brief says so in those words.
    `fetch_context` sets the timestamp on every branch including the empty ones, so "asked and got
    nothing" is indistinguishable here from "asked and got frames", on purpose.
    """
    project = _project(session)
    item = _item(session, project)
    item.context_checked_at = datetime.now(UTC)
    session.flush()

    assert [e.item.id for e in work.eligible(session, tracker_configured=True)] == [item.id]


def test_with_no_tracker_configured_nothing_waits(session: Session) -> None:
    """**The deadlock the first version of this would have caused, on a supported configuration.**

    `fetch_context` returns immediately when no tracker is configured (DR-0008: *"Without
    `errors.tracker` configured there are no frames"*), so `context_checked_at` would stay null for
    ever. A rule that waited for it unconditionally would make every item permanently ineligible —
    the whole product stopping, quietly, for everybody who connected a forge and no tracker.

    Six existing tests failed on exactly that when this condition was first written, and they were
    right: their fixtures configure no tracker, which is the case that would have hung.
    """
    project = _project(session)
    item = _item(session, project)
    assert item.context_checked_at is None

    assert [e.item.id for e in work.eligible(session, tracker_configured=False)] == [item.id]
    # And the default is the safe one: a caller that does not know cannot hang an instance.
    assert [e.item.id for e in work.eligible(session)] == [item.id]
