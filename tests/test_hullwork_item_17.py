"""A forge whose hostname does not resolve kills `hullwork work` with a traceback.

Reported by this instance's own error tracker as:

    ConnectError: [Errno -2] Name or service not known

That is the root of an exception chain, not a bare httpx error: `_ForgejoAPI._request` catches
`httpx2.TransportError` and re-raises `RetryableForgeError(...) from exc`, so what the tracker
grouped on is the `ConnectError` underneath. `[Errno -2]` is `getaddrinfo` refusing a name — the
forge's host did not resolve, which is what a dispatcher container on the wrong Docker network sees.

**Where it escapes.** `work._attempt` reads the base commit before it claims the item:

    reader = forge if rehearsal else code_forge
    base_branch = reader.default_branch(project.repo)
    base_sha = reader.head_commit(project.repo, base_branch)

Neither call is guarded, and no caller between there and the operator handles `ForgeError`:

* `cli._cmd_work` converts `WiringError`, `SandboxError` and `ImageBuildError` into `CommandError`
  and nothing else;
* `cli.main` catches `CommandError` alone, under a docstring promising it *"never raises at an
  operator"*, and `CommandError`'s own says it is *"printed as a message, never as a traceback"*.

So a name that does not resolve reaches the terminal as a stack trace, and the tracker as an issue.
The neighbouring guard shows the intended shape: `_the_issue_must_still_exist` deliberately turns a
forge failure into a `WiringError` — *"so `run_one` never sees it and the item keeps its try"* — and
the two reads immediately after it were never given the same treatment. `_work_loop` only survives
this by a broader `except Exception` further down, while the comment on its narrow handler already
claims to cover *"a forge that is down"*.

Driven through `MockTransport`, so the suite still never opens a socket, and the failure is raised
by the real adapter rather than by a stub standing in for it.
"""

import io
from typing import Any

import httpx2
import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from hullwork import cli
from hullwork.config import Settings
from hullwork.forge import factory as forge_factory
from hullwork.forge.forgejo import ForgejoCodeForge, ForgejoForge
from hullwork.models import (
    Attempt,
    Item,
    ItemKind,
    ItemState,
    Lane,
    Project,
)

#: What `getaddrinfo` says when a name does not resolve, verbatim from the reported event.
NAME_DOES_NOT_RESOLVE = "[Errno -2] Name or service not known"

#: The smallest manifest that lets an item be attempted at all: an agent, and a runtime for the
#: image. Without `runtime` the dispatcher raises `WiringError` and never reaches the forge.
AGENT_MANIFEST: dict[str, Any] = {
    "project": "p",
    "git": {"provider": "forgejo", "repo": "o/r"},
    "autofix": {"agent": "claude-code", "gates": ["tests", "human-merge"]},
    "tests": "pytest",
    "runtime": {"base": "python-3.12", "install": "none", "dependencies": []},
}



@pytest.fixture
def ready_item(session: Session) -> Item:
    """One green item the dispatcher would pick up, pointing at no issue.

    No `forge_issue_ref` on purpose: with one, `_the_issue_must_still_exist` reaches the forge
    first and converts the failure correctly. The unguarded reads are what this is aimed at.
    """
    project = Project(
        slug="p", forge="forgejo", repo="o/r", active=True,
        webhook_secret_hash="x",  # noqa: S106 - a fixture's hash, not a credential
        manifest=dict(AGENT_MANIFEST),
    )
    session.add(project)
    session.flush()
    item = Item(
        project_id=project.id, fingerprint="fp", title="ValueError: boom",
        lane=Lane.GREEN, state=ItemState.READY, kind=ItemKind.BUG,
    )
    session.add(item)
    session.commit()
    return item


def _unresolvable_transport() -> httpx2.MockTransport:
    """A transport that fails the way a name that does not resolve fails."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError(NAME_DOES_NOT_RESOLVE)

    return httpx2.MockTransport(handler)


@pytest.fixture
def unreachable_forge(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both credentials pointed at a forge whose hostname does not resolve.

    Patched on the factory rather than on the adapters, because `work.run` imports the two
    constructors from there at call time — which is also the only seam that lets the real
    `_ForgejoAPI._request` do the translating.
    """
    transport = _unresolvable_transport()
    monkeypatch.setattr(
        forge_factory,
        "make_code_forge",
        lambda settings: ForgejoCodeForge("https://forge.example", "code", transport=transport),
    )
    monkeypatch.setattr(
        forge_factory,
        "make_forge",
        lambda settings: ForgejoForge("https://forge.example", "ingest", transport=transport),
    )


def _settings() -> Settings:
    return Settings(
        forge_url="https://forge.example",
        forge_token=SecretStr("ingest"),
        forge_code_token=SecretStr("code"),
        model_key=SecretStr("sk-test"),
    )


def _run_work(session: Session) -> int:
    args = cli.build_parser().parse_args(["work"])
    return int(cli._cmd_work(args, session, _settings(), io.StringIO()))


@pytest.mark.usefixtures("ready_item", "unreachable_forge")
def test_a_forge_whose_name_does_not_resolve_is_a_message_and_not_a_traceback(
    session: Session,
) -> None:
    """The reported crash. `main` handles `CommandError` and nothing else, so it has to be one.

    Fails today with the production exception itself: `RetryableForgeError: GET /repos/o/r:
    [Errno -2] Name or service not known`, chained from the `ConnectError` the tracker grouped on.
    """
    with pytest.raises(cli.CommandError) as raised:
        _run_work(session)

    # The reason has to survive the conversion. A `CommandError` that swallowed it would send an
    # operator looking at the dispatcher for a problem that is entirely in name resolution.
    assert NAME_DOES_NOT_RESOLVE in str(raised.value)


@pytest.mark.usefixtures("unreachable_forge")
def test_a_forge_that_cannot_be_reached_costs_the_item_nothing(
    session: Session, ready_item: Item
) -> None:
    """It failed before the claim, so the item keeps its one try and no attempt was opened.

    The order in `_attempt` is deliberate — *"Everything before the claim can fail without costing
    the item its one attempt"* — and that promise is only worth anything if the failure is reported
    rather than thrown: an unhandled exception leaves this state true by accident and tells nobody.
    """
    with pytest.raises(cli.CommandError):
        _run_work(session)

    session.expire_all()
    reloaded = session.get(Item, ready_item.id)
    assert reloaded is not None
    assert reloaded.state is ItemState.READY, "an unreachable forge must not consume the item"
    assert session.execute(select(Attempt)).scalars().all() == []
