"""Whether the ingest credential is the one `config.py` says it is.

The finding this exists for was made by trying it on the live deployment, not by reading: the
production ingest token created a branch and committed to the default branch, while `config.py`
promised in writing that it could not (item 031). The protocols were right and the token was wrong.
"""

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from hullwork import credentials
from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.forge import PermissionReader, RetryableForgeError
from hullwork.models import Project

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'credentials.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")

    with make_session_factory(make_engine(url))() as db:
        yield db


class _Says:
    """A forge that answers the one question this module asks."""

    def __init__(self, answer: bool | Exception | None) -> None:
        self._answer = answer
        self.asked: list[str] = []

    def can_write_code(self, repo: str) -> bool | None:
        self.asked.append(repo)
        if isinstance(self._answer, Exception):
            raise self._answer
        return self._answer


def _project(session: Session, slug: str, *, agent: str = "none", active: bool = True) -> Project:
    project = Project(
        slug=slug,
        forge="forgejo",
        repo=f"easybyte/{slug}",
        webhook_secret_hash="x" * 64,
        manifest={
            "project": slug,
            "git": {"provider": "forgejo", "repo": f"easybyte/{slug}"},
            "autofix": {"agent": agent},
        },
        active=active,
    )
    session.add(project)
    session.commit()
    return project


def test_the_fake_satisfies_the_protocol() -> None:
    # Otherwise this whole file could pass while the real call signature has drifted.
    assert isinstance(_Says(True), PermissionReader)


def test_a_pushable_account_is_reported_as_the_account_and_not_the_token(session: Session) -> None:
    """Item 073. This asserted `"CAN write code"`, and that claim was measured false.

    `permissions.push` describes the **account**. On 2026-07-29 the live instance reported it as the
    credential being able to write code, while the token — scoped to reads and issues — was refused
    with `token does not have at least one of required scope(s): [write:repository]`. The split was
    real and this module could not see it, so the old wording turned a correctly narrowed token into
    a warning its owner could never clear.

    The replacement claims are stronger than the one they replace: the message must attribute the
    capability to the account, must admit the scope is unreadable from here, and must offer the
    token scope as the first remedy — the old text prescribed a second identity for something one
    scope already gives.
    """
    _project(session, "hullwork")

    findings = credentials.audit(session, _Says(True))

    assert [f.can_push for f in findings] == [True]
    described = credentials.describe(findings[0])
    assert described is not None
    assert "**account**" in described, "the capability belongs to the account, not the token"
    assert "not readable from here" in described, "it must not claim to know the token's scope"
    assert "CAN write code" not in described, "the false claim must not come back"
    # The message has to be actionable: naming the scopes is the difference between a warning and
    # an instruction. And the cheap remedy comes before the expensive one.
    assert "write:issue" in described
    assert "never write:repository" in described
    assert described.index("Cheapest fix first") < described.index("push access")


def test_a_credential_that_cannot_push_says_nothing(session: Session) -> None:
    # Silence is the correct output for a correctly configured instance.
    _project(session, "hullwork")

    findings = credentials.audit(session, _Says(False))

    assert credentials.describe(findings[0]) is None
    assert not findings[0].is_degradation


def test_an_unanswered_question_is_unknown_and_never_safe(session: Session) -> None:
    """`None` must not read as "no".

    A token's scope is a layer underneath the account's permissions and no endpoint discloses it, so
    an optimistic reading here would turn "the forge did not say" into "your credential is fine" —
    which is the failure this module exists to stop, repeated one level up.
    """
    _project(session, "hullwork")

    findings = credentials.audit(session, _Says(None))

    described = credentials.describe(findings[0])
    assert described is not None
    assert "unknown, not as safe" in described


def test_an_unreachable_forge_is_unknown_rather_than_an_exception(session: Session) -> None:
    # `hullwork status` exists to work when things are broken. It must not be the thing that breaks.
    _project(session, "hullwork")

    findings = credentials.audit(session, _Says(RetryableForgeError("timed out")))

    assert findings[0].can_push is None


def test_with_no_agent_it_is_a_warning_and_not_a_degradation(session: Session) -> None:
    """The exit code of `hullwork status` is wired into people's crons as "is the pipeline working".

    With `agent: none` nothing in the instance writes code, so a push-capable ingest token guards a
    door nobody is standing at: worth fixing, not worth waking anyone. Sharing one exit code between
    a posture warning and an outage makes both mean less.
    """
    _project(session, "hullwork", agent="none")

    findings = credentials.audit(session, _Says(True))

    assert not findings[0].is_degradation
    assert credentials.describe(findings[0]) is not None  # still said out loud


def test_with_an_agent_named_it_is_said_out_loud_but_is_not_a_degradation(
    session: Session,
) -> None:
    """Item 073. This asserted `is_degradation`, on an inference that does not hold.

    `can_push` is the **account's** access. A token scoped to reads and issues is refused whatever
    the account can do, so the flag fired on the live instance for both projects while the
    configuration was correct — permanently, with nothing an operator could do to clear it. The exit
    code of `hullwork status` is wired into crons as "is the pipeline working", and a signal that is
    always on is not a signal.

    The claim that replaces it is stronger, because it covers both halves at once: the warning must
    still print on every run, **and** it must not fail the instance on evidence that cannot support
    the conclusion. A test asserting only the second would pass against a `describe` gone silent,
    which is the worse failure of the two.
    """
    _project(session, "hullwork", agent="claude-code")

    findings = credentials.audit(session, _Says(True))

    assert not findings[0].is_degradation, "an inference must not fail the instance"
    described = credentials.describe(findings[0])
    assert described is not None, "and it must still be said, every run"
    assert "fiction" in described


def test_a_disabled_project_is_not_asked_about(session: Session) -> None:
    _project(session, "gone", active=False)

    forge = _Says(True)
    assert credentials.audit(session, forge) == []
    assert forge.asked == []


def test_no_forge_configured_is_not_an_error(session: Session) -> None:
    # An instance still being set up has no forge, and that is a supported state, not a failure.
    _project(session, "hullwork")

    assert credentials.audit(session, None) == []


def test_a_manifest_with_no_autofix_block_reads_as_no_agent(session: Session) -> None:
    project = Project(
        slug="bare",
        forge="forgejo",
        repo="easybyte/bare",
        webhook_secret_hash="x" * 64,
        manifest={"project": "bare", "git": {"provider": "forgejo", "repo": "easybyte/bare"}},
    )
    session.add(project)
    session.commit()

    findings = credentials.audit(session, _Says(True))

    assert findings[0].agent == "none"
    assert not findings[0].is_degradation


@pytest.mark.parametrize(
    "manifest", [None, {}, {"autofix": None}, {"autofix": "nonsense"}]
)
def test_a_missing_or_broken_manifest_does_not_crash_the_audit(
    session: Session, manifest: dict[str, Any] | None
) -> None:
    # `status` runs when things are already wrong; a malformed cached snapshot must not be the
    # reason an operator cannot see the report.
    project = Project(
        slug="odd", forge="forgejo", repo="easybyte/odd", webhook_secret_hash="x" * 64
    )
    project.manifest = manifest
    session.add(project)
    session.commit()

    findings = credentials.audit(session, _Says(True))

    assert findings[0].agent == "none"


def test_the_audit_is_not_part_of_the_readiness_probe() -> None:
    """`readiness` states it calls no forge, and depends on that.

    A probe that makes network calls fails for reasons unrelated to what it is probing, and can be
    pointed at somebody else's server by anyone who can reach it. This check belongs to the command
    a human runs, and the import graph is what keeps that true.
    """
    import inspect

    from hullwork import readiness

    source = inspect.getsource(readiness)
    assert "credentials" not in source
    assert "can_write_code" not in source


def test_one_token_in_both_variables_is_reported_without_asking_anybody() -> None:
    """Item 073. The one failure this module can prove, and it went unchecked.

    Two protocols, two classes and a request-time guard exist to keep the ingest client away from
    code, and every one of them is bypassed by pasting one value into two variables. `audit` was
    going to the network on every project to *infer* a permission it cannot see, while the case it
    can settle for free was not looked at.
    """
    message = credentials.the_two_tokens_must_differ("same-token", "same-token")

    assert message is not None
    assert "no credential split at all" in message
    assert "same-token" not in message, "the value must never reach a terminal or a log"


def test_two_different_tokens_say_nothing() -> None:
    """Silence is the right output. Otherwise the check is noise and gets ignored."""
    assert credentials.the_two_tokens_must_differ("ingest", "code") is None


def test_a_missing_code_token_is_not_a_collision() -> None:
    """The receiver is *supposed* to lack it (DR-0005), which is the normal deployment.

    Without this the check would fire on every correctly configured instance, which is exactly the
    unclearable warning item 073 was written about.
    """
    assert credentials.the_two_tokens_must_differ("ingest", None) is None
    assert credentials.the_two_tokens_must_differ(None, None) is None


# --- the probe: what the TOKEN may do, not the account. Item 073 ----------------------------------


def _client_factory(
    handler: Callable[[httpx2.Request], httpx2.Response],
) -> Callable[..., httpx2.Client]:
    """Stand in for `httpx2.Client` so the probe's own client is served by `handler`.

    The probe **builds its own client** on purpose — sharing one with the ingest client is what
    would put code capable of pushing back into the repository — so there is nothing to inject and
    the class is replaced instead. The suite still opens no socket.
    """

    # **The real class, captured before the patch replaces the name.** Reading `httpx2.Client`
    # inside `make` reads the patched one — infinite recursion, which the probe's `except Exception`
    # turns into `None` and reports as "cannot tell". Two tests failed with a verdict that looked
    # like the probe's own answer: the cost of a broad except that is right in production.
    real = httpx2.Client

    def make(*args: object, **kwargs: object) -> httpx2.Client:
        kwargs.pop("timeout", None)
        return real(*args, transport=httpx2.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    return make


def test_a_scope_refusal_means_the_token_cannot_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forgejo checks the scope **before** the body, which is what makes this probe non-destructive.

    Measured against the live forge on 2026-07-31, on both projects:
    `403 token does not have at least one of required scope(s): [write:repository]`.
    """
    asked: list[tuple[str, str]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        asked.append((request.method, request.url.path))
        return httpx2.Response(
            403, json={"message": "token does not have at least one of required scope(s)"}
        )

    monkeypatch.setattr(httpx2, "Client", _client_factory(handler))
    assert credentials.token_may_write_code("https://forge.example", "t", "o/r") is False
    assert asked == [("POST", "/api/v1/repos/o/r/branches")]


def test_a_missing_ref_means_the_token_can_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """Past the scope check and into the body, where the ref does not exist. That is a `True`.

    And nothing was created: the request that would have created a branch cannot, because its
    `old_ref_name` names a ref no repository has.
    """
    sent: list[object] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(json.loads(request.content))
        return httpx2.Response(404, json={"message": "reference does not exist"})

    monkeypatch.setattr(httpx2, "Client", _client_factory(handler))
    assert credentials.token_may_write_code("https://forge.example", "t", "o/r") is True
    # The body is fixed in the module, not taken from a caller. That is the property that makes this
    # safe to have: there is no argument that turns it into a request which could succeed.
    assert sent == [
        {"new_branch_name": credentials._PROBE_BRANCH, "old_ref_name": credentials._PROBE_FROM}
    ]


@pytest.mark.parametrize("status", [200, 201, 401, 422, 500])
def test_any_other_answer_is_undecidable_never_safe(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    """Guessing "probably fine" is how the original defect was introduced.

    An unreadable answer is not a pass — including `201`, which would mean a forge that creates
    branches from refs that do not exist and whose answers cannot be reasoned about at all.
    """
    monkeypatch.setattr(
        httpx2, "Client", _client_factory(lambda request: httpx2.Response(status, json={}))
    )
    assert credentials.token_may_write_code("https://forge.example", "t", "o/r") is None


def test_a_forge_that_cannot_be_reached_is_undecidable(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("no route")

    monkeypatch.setattr(httpx2, "Client", _client_factory(handler))
    assert credentials.token_may_write_code("https://forge.example", "t", "o/r") is None


def test_the_probe_takes_no_path_and_no_body() -> None:
    """**The property that makes this safe, asserted rather than described.**

    Item 073's blocker was that implementing the probe *"needs either an exception to that guard or
    a second HTTP client, and both put code capable of pushing with the ingest token back into the
    repository."* This is the second, and it is not that: a caller supplies where to ask and with
    what credential, and cannot choose the method, the route or the body. Reintroduce a `path` or
    `json` parameter and this fails.

    **Both shapes, since item 131.** A property that holds for the entry point and not for the
    function it delegates to is not a property of this module.

    **Three shapes, and one more parameter, since item 132.** `declared_kind` is how the entry point
    learns which forge it is talking to now that a URL cannot say — configuration, arriving the same
    way `forge_url` always has. It does not let a caller choose a request: the two assertions below
    say that separately, and the second one is the one that survives the next parameter. Only the
    entry point may take it; a shape that accepted it could be steered into another forge's request.
    """
    import inspect

    assert set(inspect.signature(credentials.token_may_write_code).parameters) == {
        "forge_url", "token", "repo", "declared_kind", "timeout",
    }
    assert set(inspect.signature(credentials._forgejo_may_write_code).parameters) == {
        "forge_url", "token", "repo", "timeout",
    }
    assert set(inspect.signature(credentials._github_may_write_code).parameters) == {
        "token", "repo", "timeout",
    }
    assert set(inspect.signature(credentials._gitlab_may_write_code).parameters) == {
        "forge_url", "token", "repo", "timeout",
    }

    # The property itself, rather than a list that happens to encode it: no caller of any of these
    # names a route, a method or a body. Add `path=` to any one of them and this fails, whatever
    # else the signature grew in the meantime.
    forbidden = {"path", "route", "endpoint", "method", "json", "data", "body", "params", "content"}
    for probe in (
        credentials.token_may_write_code,
        credentials._forgejo_may_write_code,
        credentials._github_may_write_code,
        credentials._gitlab_may_write_code,
    ):
        named = set(inspect.signature(probe).parameters)
        assert not named & forbidden, f"{probe.__name__} lets a caller choose the request"


# --- the same question, asked of GitHub. Item 131 -------------------------------------------------


GITHUB = "https://github.com"


def test_on_github_a_refusal_means_the_token_cannot_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**Measured on 2026-08-03** against `FlagshipDev/personal-dashboard`, from inside the
    receiver that holds the ingest token: `403 Resource not accessible by personal access token`.
    """
    asked: list[tuple[str, str, str]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        asked.append((request.method, str(request.url.host), request.url.path))
        return httpx2.Response(
            403, json={"message": "Resource not accessible by personal access token"}
        )

    monkeypatch.setattr(httpx2, "Client", _client_factory(handler))

    assert credentials.token_may_write_code(GITHUB, "t", "o/r") is False
    assert asked == [("POST", "api.github.com", "/repos/o/r/git/refs")]


def test_on_github_a_missing_object_means_the_token_can_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other half of the same measurement, from inside the dispatcher that holds the code
    token: `422 Object does not exist`. Past the permission check, into validation.

    **And nothing was created, because nothing could be.** GitHub has no endpoint that branches
    from a ref by name — it takes a commit to point at — so the impossibility lives in the object:
    forty zeros is not a commit in any repository that has ever existed. The `heads` of the real
    repository were identical before and after.
    """
    sent: list[object] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(json.loads(request.content))
        return httpx2.Response(422, json={"message": "Object does not exist"})

    monkeypatch.setattr(httpx2, "Client", _client_factory(handler))

    assert credentials.token_may_write_code(GITHUB, "t", "o/r") is True
    assert sent == [
        {"ref": f"refs/heads/{credentials._PROBE_BRANCH}", "sha": credentials._PROBE_SHA}
    ]
    assert set(credentials._PROBE_SHA) == {"0"}, "a sha that could exist would be a branch created"


def test_on_github_a_404_is_undecidable_and_never_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    """**The one that must never become `False`.**

    GitHub answers `404` rather than `403` when a token cannot see a repository at all, precisely so
    that probing cannot enumerate private repositories. So a `404` here is *"no permission, or no
    such repository"* — two facts with opposite meanings for this audit. Reading it as a refusal
    would report a credential as verified-safe on the strength of a typo in a repository name.

    On Forgejo the identical status code means the opposite (past the scope check, into the body),
    which is exactly why the two shapes cannot share a table of status codes.
    """
    monkeypatch.setattr(
        httpx2, "Client", _client_factory(lambda _: httpx2.Response(404, json={}))
    )

    assert credentials.token_may_write_code(GITHUB, "t", "o/r") is None
    assert credentials.token_may_write_code("https://forge.example", "t", "o/r") is True, (
        "the same code, the opposite meaning — the reason for two shapes"
    )


@pytest.mark.parametrize("status", [200, 201, 401, 500])
def test_on_github_any_other_answer_is_undecidable(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    monkeypatch.setattr(
        httpx2, "Client", _client_factory(lambda _: httpx2.Response(status, json={}))
    )

    assert credentials.token_may_write_code(GITHUB, "t", "o/r") is None


def test_the_forge_chooses_the_shape_and_the_caller_cannot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**The defect this item is about, stated as a test.** For three days the GitHub instance sent
    Forgejo's request at `github.com/api/v1/…`, a path GitHub does not serve, and read the answer
    as "cannot tell" — which is honest and useless. One caller, one argument, two shapes.
    """
    paths: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        paths.append(f"{request.url.host}{request.url.path}")
        return httpx2.Response(403, json={})

    monkeypatch.setattr(httpx2, "Client", _client_factory(handler))

    credentials.token_may_write_code(GITHUB, "t", "o/r")
    credentials.token_may_write_code("https://forge.example", "t", "o/r")

    assert paths == ["api.github.com/repos/o/r/git/refs", "forge.example/api/v1/repos/o/r/branches"]
    assert "/api/v1/" not in paths[0], "the path GitHub does not serve, which is the whole bug"


def test_a_narrow_token_clears_the_warning_and_the_exit_code(session: Session) -> None:
    """**The falsifiable gate, first direction.** Item 073.

    The instance this was written on had the correct configuration — a token scoped to reads and
    issues, on an account with push access — and was told on every `status`, for two days, that its
    credential split was a fiction. A warning that cannot be cleared by doing the right thing
    teaches
    people to ignore warnings, and `status`'s exit code is wired into people's crons as *"is the
    pipeline working"*.

    The account still says `push: True`. The token says otherwise, and the token is what travels
    with
    every request.
    """
    _project(session, "demo", agent="claude-code")

    findings = credentials.audit(session, _Says(True), probe=lambda repo: False)

    assert [f.can_push for f in findings] == [True], "the account's answer is unchanged"
    assert [f.token_can_push for f in findings] == [False]
    assert credentials.describe(findings[0]) is None, "a correct installation is silent"
    assert findings[0].is_degradation is False


def test_a_broad_token_is_named_as_measured_and_degrades(session: Session) -> None:
    """**The falsifiable gate, second direction, and without it the change only proves silence.**

    A token that really can write code, on a project with an agent, is the fiction the split exists
    to
    prevent — and now it is a measurement rather than an inference, so the sentence says so.
    """
    _project(session, "demo", agent="claude-code")

    findings = credentials.audit(session, _Says(True), probe=lambda repo: True)

    assert [f.token_can_push for f in findings] == [True]
    described = credentials.describe(findings[0])
    assert described is not None
    assert "**token**" in described
    assert "measured, not inferred" in described
    assert findings[0].is_degradation is True


def test_a_broad_token_with_no_agent_does_not_degrade(session: Session) -> None:
    """The narrower half of the same rule: nothing here writes code yet, so nothing is a fiction."""
    _project(session, "demo", agent="none")

    findings = credentials.audit(session, _Says(True), probe=lambda repo: True)

    assert findings[0].is_degradation is False


def test_without_a_probe_the_audit_says_what_it_used_to(session: Session) -> None:
    """The behaviour for a caller that cannot ask — an unreachable forge, or a test.

    `token_can_push` stays `None` and the message reverts to the account's answer with its honest
    hedge. Silence would be the wrong default: not having asked is not the same as having cleared
    it.
    """
    _project(session, "demo", agent="claude-code")

    findings = credentials.audit(session, _Says(True))

    assert findings[0].token_can_push is None
    described = credentials.describe(findings[0])
    assert described is not None
    assert "not readable from here" in described


def test_the_probe_is_not_run_where_the_account_cannot_push_anyway(session: Session) -> None:
    """One request per project is not free, and there is nothing for it to disprove there."""
    _project(session, "demo", agent="claude-code")
    asked: list[str] = []

    def probe(repo: str) -> bool | None:
        asked.append(repo)
        return None

    credentials.audit(session, _Says(False), probe=probe)

    assert asked == []
