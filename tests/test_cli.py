"""The registration command.

Tests call the command functions directly rather than spawning a subprocess: same code path, no
process startup per assertion, and failures point at a line instead of at a shell.
"""

import argparse
import base64
import io
import re
from collections.abc import Iterator
from pathlib import Path

import httpx2
import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr
from sqlalchemy.orm import Session

from hullwork import __version__
from hullwork.cli import (
    CommandError,
    _cmd_work,
    add_project,
    build_parser,
    disable_project,
    main,
    rotate_secret,
)
from hullwork.cli import refresh_manifest as cli_refresh_manifest
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.forge import forgejo as forgejo_module
from hullwork.models import Project
from hullwork.security import generate_token, hash_token, verify_token

ROOT = Path(__file__).resolve().parent.parent
REPO = "easybyte/hullwork-sandbox"

MANIFEST = """project: sandbox
git:
  provider: forgejo
  repo: easybyte/hullwork-sandbox
errors:
  provider: glitchtip
autofix:
  lanes:
    green: [typeerror]
    red: [payment]
"""


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")
    with make_session_factory(make_engine(url))() as db:
        yield db
    get_settings.cache_clear()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cli.db'}",
        base_url="https://hullwork.example",
        forge_url="https://forge.example",
        forge_token=SecretStr("tok_not_real"),
    )


@pytest.fixture(autouse=True)
def fake_forge(monkeypatch: pytest.MonkeyPatch) -> None:
    """Serve the manifest over a mock transport, so no test opens a socket."""
    manifest_body = {
        "encoding": "base64",
        "content": base64.b64encode(MANIFEST.encode()).decode(),
    }

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith(f"/repos/{REPO}"):
            return httpx2.Response(200, json={"default_branch": "main"})
        if "contents" in request.url.path:
            return httpx2.Response(200, json=manifest_body)
        return httpx2.Response(404)

    original = forgejo_module.ForgejoForge.__init__

    def patched(
        self: forgejo_module.ForgejoForge, base_url: str, token: str, **kwargs: object
    ) -> None:
        original(self, base_url, token, transport=httpx2.MockTransport(handler))

    monkeypatch.setattr(forgejo_module.ForgejoForge, "__init__", patched)


def test_registering_a_project_validates_the_manifest_first(
    session: Session, settings: Settings
) -> None:
    registration = add_project(
        session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO
    )

    assert registration.project.slug == "sandbox"
    assert registration.manifest.autofix.lanes.red == ["payment"]
    assert registration.project.manifest_fetched_at is not None


def test_the_token_is_stored_hashed_never_in_the_clear(
    session: Session, settings: Settings
) -> None:
    registration = add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO)

    stored = session.query(Project).one().webhook_secret_hash
    assert registration.token not in stored
    assert stored == hash_token(registration.token)
    assert verify_token(registration.token, stored)


def test_the_webhook_url_carries_the_error_provider_not_the_forge(
    session: Session, settings: Settings
) -> None:
    registration = add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO)

    url = registration.webhook_url(settings.base_url)
    # The route is keyed by who *sends* the webhook, which is the error tracker.
    assert url.startswith("https://hullwork.example/webhooks/glitchtip/sandbox/")
    assert url.endswith(registration.token)


def test_a_duplicate_slug_is_refused(session: Session, settings: Settings) -> None:
    add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO)

    with pytest.raises(CommandError, match="already registered"):
        add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO)


def test_an_invalid_manifest_is_refused_and_nothing_is_written(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A project registered in a broken state looks connected and silently is not."""
    monkeypatch.setattr(
        forgejo_module.ForgejoForge, "read_manifest", lambda self, repo: "git: {provider: nope}"
    )

    with pytest.raises(CommandError) as caught:
        add_project(session, settings, slug="broken", forge_kind="forgejo", repo=REPO)

    assert "git.provider" in str(caught.value)
    assert session.query(Project).count() == 0


def test_a_forge_nothing_can_serve_is_refused_clearly_rather_than_accepted_and_ignored(
    session: Session, settings: Settings
) -> None:
    """The property this protects: a name with no adapter behind it fails with a sentence.

    **It used to be spelled `github`, and item 068 is why it is not.** GitHub was in this position
    because `forge/github.py` was 936 exercised lines with no project that could reach them — but
    `README` principle 3 promises GitHub from day one, item 034's ticked criterion says *"a manifest
    declaring `provider: github` registers and works end to end"*, and the plan lists the
    refusal as one of the false claims in the public surface. So the *name* moved; the property did
    not. A forge nothing can serve must be refused here, where the message is one line, rather than
    four layers down as an adapter mismatch.
    """
    with pytest.raises(CommandError, match="not supported"):
        add_project(session, settings, slug="bb", forge_kind="bitbucket", repo="owner/name")


def test_missing_forge_credentials_say_which_variables(session: Session) -> None:
    bare = Settings(base_url="https://hullwork.example")

    with pytest.raises(CommandError) as caught:
        add_project(session, bare, slug="x", forge_kind="forgejo", repo=REPO)

    assert "HULLWORK_FORGE_URL" in str(caught.value)


def test_rotating_issues_a_new_token_and_invalidates_the_old_one(
    session: Session, settings: Settings
) -> None:
    first = add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO).token

    second = rotate_secret(session, "sandbox")

    stored = session.query(Project).one().webhook_secret_hash
    assert second != first
    assert verify_token(second, stored)
    assert not verify_token(first, stored)


def test_rotating_does_not_touch_anything_else(session: Session, settings: Settings) -> None:
    add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO)
    before = session.query(Project).one()
    repo, manifest = before.repo, before.manifest

    rotate_secret(session, "sandbox")

    after = session.query(Project).one()
    assert (after.repo, after.manifest) == (repo, manifest)


def test_disabling_keeps_the_row(session: Session, settings: Settings) -> None:
    add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO)

    disable_project(session, "sandbox")

    assert session.query(Project).one().active is False


def test_acting_on_an_unknown_project_says_so(session: Session) -> None:
    with pytest.raises(CommandError, match="no project called"):
        rotate_secret(session, "ghost")


def test_the_credential_is_printed_exactly_once(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Shown once, never recoverable. Printing it twice would be two chances to leak it."""
    monkeypatch.setenv("HULLWORK_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("HULLWORK_BASE_URL", settings.base_url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "tok_not_real")
    get_settings.cache_clear()

    out = io.StringIO()
    code = main(["projects", "add", "--slug", "sandbox", "--repo", REPO], out=out)

    assert code == 0
    printed = out.getvalue()
    token = session.query(Project).one().webhook_secret_hash
    # Find the token in the URL and confirm it appears once and only once.
    prefix = "https://hullwork.example/webhooks/"
    urls = [word for word in printed.split() if word.startswith(prefix)]
    assert len(urls) == 1
    emitted_token = urls[0].rsplit("/", 1)[1]
    assert printed.count(emitted_token) == 1
    assert verify_token(emitted_token, token)
    get_settings.cache_clear()


def test_the_token_never_reaches_a_log_line() -> None:
    """The redaction filter must cover it: the URL is a credential and logs outlive terminals."""
    import logging

    from hullwork.logging import REDACTED, RedactingFilter

    token = generate_token()
    redactor = RedactingFilter([token])
    record = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=f"registered with https://hullwork.example/webhooks/glitchtip/sandbox/{token}",
        args=None,
        exc_info=None,
    )

    redactor.filter(record)

    assert token not in record.getMessage()
    assert REDACTED in record.getMessage()


def test_prune_reaches_the_biggest_table_and_spares_the_evidence(tmp_path: Path) -> None:
    """`fetched_events` is now the largest thing here, and the attempt record must outlive it.

    Item 036 made Hullwork a reader of the tracker, so every item carries frames with source
    context and 33-71 dependency versions — the same growth `events.raw` had, by a new door. And
    the attempt steps are the claim an open pull request makes about itself: pruning those would
    leave a pull request asserting "this test failed and now passes" with nothing behind it.
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from hullwork.attempts import finish, record, start
    from hullwork.cli import prune
    from hullwork.models import (
        AttemptOutcome,
        AttemptPhase,
        Base,
        FetchedEvent,
        Item,
        Lane,
        Project,
    )

    engine = create_engine(f"sqlite:///{tmp_path / 'p.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    project = Project(
        slug="p", forge="forgejo", repo="o/r",
        webhook_secret_hash="h",  # noqa: S106
    )
    session.add(project)
    session.flush()
    item = Item(project_id=project.id, fingerprint="fp", title="t", lane=Lane.GREEN)
    session.add(item)
    session.flush()

    old = datetime.now(UTC) - timedelta(days=200)
    session.add(
        FetchedEvent(
            item_id=item.id, provider_event_id="e1", exception_type="ValueError",
            message="keep me", release="b292599", fetched_at=old,
            frames=[{"abs_path": "/app/x.py", "lineno": 3}],
            packages={"fastapi": "0.140.1"}, extra={"sys.argv": ["x"]},
        )
    )
    attempt = start(session, item)
    record(session, attempt, AttemptPhase.RED_GATE, "pytest", exit_code=1, output="1 failed")
    finish(session, attempt, AttemptOutcome.PR_OPEN)
    session.commit()

    prune(session, older_than_days=90)

    context = session.query(FetchedEvent).one()
    assert context.frames == []          # the bulk is gone
    assert context.packages == {}
    assert context.extra == {}
    assert context.exception_type == "ValueError"  # the identity stays
    assert context.release == "b292599"

    # And the evidence a pull request rests on is untouched.
    assert [(s.phase, s.exit_code, s.output) for s in attempt.steps] == [
        (AttemptPhase.RED_GATE, 1, "1 failed")
    ]
    assert attempt.outcome is AttemptOutcome.PR_OPEN
    assert attempt.consumed is True


# --- the second program, invocable at last (item 047) --------------------------------------------


def test_work_is_a_command(capsys: pytest.CaptureFixture[str]) -> None:
    """The whole point of item 047.

    `work.readiness_notes` tells the operator to run `hullwork work --release-stale`, and
    `hullwork approve` says the next `hullwork work` run may attempt the item. Neither sentence was
    true: the parser had no such subcommand. A program that exists only in prose.
    """
    parser = build_parser()

    args = parser.parse_args(["work", "--limit", "3", "--project", "sandbox"])

    assert args.limit == 3
    assert args.project == "sandbox"
    assert args.release_stale is False


def test_work_says_what_it_needs_that_the_service_does_not_have(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Spec §1's install step, where somebody typing `--help` will actually meet it.

    "Opting into fixes is an install step, not a config flag" is a sentence in the spec and was
    nowhere a user would see. Three things the service deliberately lacks — the code token, a model
    credential, the Docker daemon — and discovering them one traceback at a time is the experience
    this replaces.
    """
    with pytest.raises(SystemExit):
        build_parser().parse_args(["work", "--help"])

    printed = capsys.readouterr().out
    assert "HULLWORK_FORGE_CODE_TOKEN" in printed
    assert "HULLWORK_MODEL_KEY" in printed
    assert "Docker" in printed
    assert "--release-stale" in printed


def test_work_without_the_code_token_refuses_and_exits_non_zero(
    session: Session, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The dispatcher is the only program that holds it, so without it there is nothing to do.

    Non-zero because a cron line reading the exit code has to be able to tell "nothing was ready"
    from "this instance cannot ever do the thing it was scheduled for" (item 019).
    """
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "tok_not_real")
    get_settings.cache_clear()

    code = main(["work"], out=io.StringIO())

    assert code == 1
    assert "HULLWORK_FORGE_CODE_TOKEN" in capsys.readouterr().err


def test_work_with_nothing_ready_is_a_quiet_zero(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty queue is not a failure — the sweep may simply have nothing for it."""
    monkeypatch.setattr("hullwork.work.run", lambda *a, **k: [])
    out = io.StringIO()

    code = _cmd_work(
        argparse.Namespace(limit=1, project=None, release_stale=False, no_publish=False),
        session, settings, out,
    )

    assert code == 0
    assert "Nothing is ready to attempt" in out.getvalue()


def test_work_reports_a_pull_request_and_the_claim_behind_it(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hullwork.models import AttemptOutcome
    from hullwork.work import Outcome

    monkeypatch.setattr(
        "hullwork.work.run",
        lambda *a, **k: [
            Outcome(
                item_id=4,
                outcome=AttemptOutcome.PR_OPEN,
                detail="a test that failed against unmodified code passes with the change applied",
                pull_request="https://forge/pulls/9",
            )
        ],
    )
    out = io.StringIO()

    code = _cmd_work(
        argparse.Namespace(limit=1, project=None, release_stale=False, no_publish=False),
        session, settings, out,
    )

    assert code == 0
    printed = out.getvalue()
    assert "item 4: pr-open → https://forge/pulls/9" in printed
    assert "passes with the change applied" in printed


def test_an_abandoned_attempt_is_not_a_successful_run(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It did not count against the item, and it did not do what it was scheduled to do either."""
    from hullwork.models import AttemptOutcome
    from hullwork.work import Outcome

    monkeypatch.setattr(
        "hullwork.work.run",
        lambda *a, **k: [
            Outcome(item_id=4, outcome=AttemptOutcome.ABANDONED, detail="docker is not running")
        ],
    )

    code = _cmd_work(
        argparse.Namespace(limit=1, project=None, release_stale=False, no_publish=False),
        session, settings, io.StringIO(),
    )

    assert code == 1


def test_release_stale_frees_items_and_keeps_the_record(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The documented way out of a killed dispatcher, and the sentence `status` prints."""
    monkeypatch.setattr("hullwork.work.release_stale", lambda s: [3, 5])
    out = io.StringIO()

    code = _cmd_work(
        argparse.Namespace(limit=1, project=None, release_stale=True, no_publish=False),
        session, settings, out,
    )

    assert code == 0
    assert "Released 2 stale item(s): [3, 5]" in out.getvalue()
    assert "none of them counted" in out.getvalue()


def test_a_sandbox_that_cannot_run_is_an_operator_message_not_a_traceback(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`docker` missing is the most likely first-run failure of this command, by a distance."""
    from hullwork.sandbox.run import SandboxError

    def _explode(*a: object, **k: object) -> None:
        raise SandboxError("'docker' is not on PATH")

    monkeypatch.setattr("hullwork.work.run", _explode)

    with pytest.raises(CommandError) as err:
        _cmd_work(
            argparse.Namespace(limit=1, project=None, release_stale=False, no_publish=False),
            session, settings, io.StringIO(),
        )

    assert "the sandbox is not usable" in str(err.value)


# --- an engine is named at registration, not at dispatch (item 048) ------------------------------

#: Valid in every other respect, so the refusal below is about the engine name and not about the
#: parser: naming an agent also requires a test command and a runtime.
NAMES_AN_UNKNOWN_ENGINE = """project: sandbox
git:
  provider: forgejo
  repo: easybyte/hullwork-sandbox
errors:
  provider: glitchtip
tests: "pytest"
runtime:
  base: python-3.12
  install: none
  dependencies: []
autofix:
  agent: openhands
  lanes:
    green: [typeerror]
    red: [payment]
"""


def test_a_manifest_naming_an_unregistered_engine_is_refused_here(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DR-0004 says the registry is consulted at registration. It was consulted at dispatch instead.

    `openhands` parses — `AgentSpec` admits it — and resolves to nothing, so it used to register
    cleanly, wait in the queue, and fail only after the item was claimed, an attempt row started
    and a container image built. The refusal existed, in the most expensive place available.
    """
    monkeypatch.setattr(
        forgejo_module.ForgejoForge, "read_manifest", lambda self, repo: NAMES_AN_UNKNOWN_ENGINE
    )

    with pytest.raises(CommandError) as caught:
        add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO)

    assert "openhands" in str(caught.value)
    assert "claude-code" in str(caught.value)
    assert session.query(Project).count() == 0


def test_refreshing_onto_an_unregistered_engine_is_refused_too(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`projects refresh` re-reads the manifest, so it is the same door."""
    add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO)
    monkeypatch.setattr(
        forgejo_module.ForgejoForge, "read_manifest", lambda self, repo: NAMES_AN_UNKNOWN_ENGINE
    )

    with pytest.raises(CommandError) as caught:
        cli_refresh_manifest(session, settings, "sandbox")

    assert "openhands" in str(caught.value)


# --- a service is named at registration too (item 052, half one) ---------------------------------

#: Valid in every other respect, so the refusal is about the service name. `kafka-3` is chosen
#: because it is the long tail the plan M10 says a closed set will never cover.
NEEDS_A_SERVICE_THIS_BUILD_LACKS = """project: sandbox
git:
  provider: forgejo
  repo: easybyte/hullwork-sandbox
errors:
  provider: glitchtip
tests: "pytest"
runtime:
  base: python-3.12
  install: none
  dependencies: []
  services: [postgres-16, kafka-3]
"""

#: The same manifest with only services this build has.
NEEDS_A_SERVICE_THIS_BUILD_HAS = NEEDS_A_SERVICE_THIS_BUILD_LACKS.replace(
    "  services: [postgres-16, kafka-3]\n", "  services: [postgres-16]\n"
)


def test_a_manifest_naming_a_service_this_build_lacks_is_refused_here(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Half one of item 052, and the plan M10 says it is worth shipping alone.

    Without it, an item on such a project reaches `ready`, is claimed, starts an attempt row, builds
    an image, and only then finds out — where item 043 correctly sends it to `human-only` with a
    message about the project's own suite. Measured on `acme`: `128 failed, 117 passed`, all
    of them a `psycopg.OperationalError`. Refused here, nothing reaches `ready` and no attempt is
    consumed, because none is ever started.
    """
    monkeypatch.setattr(
        forgejo_module.ForgejoForge,
        "read_manifest",
        lambda self, repo: NEEDS_A_SERVICE_THIS_BUILD_LACKS,
    )

    with pytest.raises(CommandError) as caught:
        add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO)

    assert "kafka-3" in str(caught.value)
    # And it says what it does have, or the operator has to go and read the source.
    assert "postgres-16" in str(caught.value)
    assert session.query(Project).count() == 0


def test_a_service_this_build_has_registers(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal must be about the name, not about declaring services at all."""
    monkeypatch.setattr(
        forgejo_module.ForgejoForge,
        "read_manifest",
        lambda self, repo: NEEDS_A_SERVICE_THIS_BUILD_HAS,
    )

    registration = add_project(
        session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO
    )

    assert registration.manifest.runtime is not None
    assert registration.manifest.runtime.services == ["postgres-16"]


def test_refreshing_onto_a_service_this_build_lacks_is_refused_too(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same door as the engine check: `projects refresh` re-reads the manifest."""
    add_project(session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO)
    monkeypatch.setattr(
        forgejo_module.ForgejoForge,
        "read_manifest",
        lambda self, repo: NEEDS_A_SERVICE_THIS_BUILD_LACKS,
    )

    with pytest.raises(CommandError) as caught:
        cli_refresh_manifest(session, settings, "sandbox")

    assert "kafka-3" in str(caught.value)


def test_the_default_agent_needs_no_engine(session: Session, settings: Settings) -> None:
    """`none` means no engine at all, so it never reaches the registry."""
    registration = add_project(
        session, settings, slug="sandbox", forge_kind="forgejo", repo=REPO
    )

    assert registration.manifest.autofix.agent == "none"
    assert session.query(Project).count() == 1


def test_rehearsing_does_not_need_the_credential_that_could_publish(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole point of the mode (item 049, DR-0006 §1).

    `hullwork work` refuses without `HULLWORK_FORGE_CODE_TOKEN`, and that refusal is the largest
    single obstacle DR-0006 set out to remove: needing a push-capable token to *evaluate* the fix
    half means a security review before the tool has done anything. So the refusal must not fire
    here — asserted rather than assumed, because it is one `if` away from firing again.
    """
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "tok_not_real")
    monkeypatch.delenv("HULLWORK_FORGE_CODE_TOKEN", raising=False)
    get_settings.cache_clear()

    out = io.StringIO()
    code = main(["work", "--no-publish"], out=out)
    printed = out.getvalue()

    assert "HULLWORK_FORGE_CODE_TOKEN is not set" not in printed
    assert "Rehearsing" in printed
    # It still refuses, on the model credential, and that is correct rather than a shortfall: a
    # rehearsal runs the agent. DR-0006's amendment already struck "zero risk" and "twenty minutes"
    # from the promise for exactly this reason — what the mode removes is the credential that could
    # *write*, not every credential.
    assert code != 0


# --- GitHub is a forge this instance can register. Item 068 -----------------------------------


def test_github_registers_and_uses_the_github_adapter(
    session: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The claim README principle 3 makes, made true.**

    `forge/github.py` was 936 exercised lines with no project that could reach them: argparse
    refused `--forge github`, and `_forge_for` built a `ForgejoForge` whatever it was handed. So
    item 034's ticked criterion — *"a manifest declaring `provider: github` registers and works end
    to end"* — was false against the shipped command.

    Asserted through the **adapter that was used**, not through the return value: routing this to a
    Forgejo client pointed at a GitHub URL would also produce a registration, and it would fail
    later in a way that reads like a credential problem. The paths differ (`/contents/` on GitHub
    carries base64 in a JSON body; the header set differs too), so recording which client served
    the request is the only assertion that distinguishes them.
    """
    from hullwork.forge import github as github_module

    served: list[str] = []
    manifest = MANIFEST.replace("provider: forgejo", "provider: github")

    def handler(request: httpx2.Request) -> httpx2.Response:
        served.append(f"{request.method} {request.url.path}")
        # The header GitHub requires and Forgejo does not send: proof of which client this is.
        assert request.headers.get("X-GitHub-Api-Version") == "2022-11-28"
        if "contents" in request.url.path:
            return httpx2.Response(
                200,
                json={
                    "encoding": "base64",
                    "content": base64.b64encode(manifest.encode()).decode(),
                },
            )
        return httpx2.Response(200, json={"default_branch": "main"})

    original = github_module._GitHubAPI.__init__

    def patched(self: object, token: str, **kwargs: object) -> None:
        original(self, token, **kwargs)  # type: ignore[arg-type]
        self._client = httpx2.Client(  # type: ignore[attr-defined]
            base_url="https://api.github.test",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            transport=httpx2.MockTransport(handler),
        )

    monkeypatch.setattr(github_module._GitHubAPI, "__init__", patched)
    # A GitHub URL, because `factory.make_forge` selects on it — the operator's value, not the
    # manifest's claim (see `factory._is_github`).
    on_github = settings.model_copy(update={"forge_url": "https://api.github.com"})

    # `sandbox`, because `_the_manifest_must_agree` compares every field and the manifest is the
    # law — which is a guard doing its job, not an inconvenience.
    registration = add_project(
        session, on_github, slug="sandbox", forge_kind="github", repo="easybyte/hullwork-sandbox"
    )

    assert registration.project.forge == "github"
    assert session.query(Project).count() == 1
    assert served, "no request reached the GitHub adapter, so something else served this"
    assert any("contents" in call for call in served), (
        f"the manifest was not read through the GitHub adapter: {served}"
    )


def test_the_version_is_reachable_without_a_configured_instance(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`hullwork --version` printed a usage error until 2026-08-05, and the string already existed.

    It was reachable only through `status`, which opens the database — so the one moment somebody
    needs the version, filing a report about an instance that will not start, was the moment they
    could not get it. `action="version"` answers before any configuration is read.
    """
    with pytest.raises(SystemExit) as exited:
        main(["--version"])

    assert exited.value.code == 0, "asking the version is not an error"
    assert __version__ in capsys.readouterr().out


def test_the_boundary_renders_every_declared_sandbox_failure_as_a_sentence(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`main`'s docstring says it "never raises at an operator", and on 2026-08-05 it did.

    Measured against the published wheel: a base image Docker cannot resolve reaches `image.build`,
    which raises `ImageBuildError`, which nothing caught — so a stranger's first five minutes
    ended in eleven frames of Python. Every one of the sandbox's declared failures now prints as a
    sentence and exits 1.

    Walked over the tuple rather than a list written here, so adding an error class to the boundary
    is the only way to make this test cover it — and the test below makes adding it unavoidable.
    """
    from hullwork import cli as cli_module

    for failure in cli_module.SANDBOX_FAILURES:
        def explode(*_args: object, _failure: type[Exception] = failure, **_kwargs: object) -> int:
            raise _failure("the sandbox said no")

        monkeypatch.setattr(cli_module, "get_settings", explode)
        code = main(["status"])
        printed = capsys.readouterr().err

        assert code == 1, f"{failure.__name__} must exit 1"
        assert printed.startswith("error: "), f"{failure.__name__} printed {printed!r}"
        assert "the sandbox said no" in printed
        assert "Traceback" not in printed


def test_no_sandbox_error_can_arrive_at_the_boundary_unhandled() -> None:
    """The drift guard, and the reason the first one arrived unhandled at all.

    `ImageBuildError` existed for weeks, was raised on the busiest path, and was in no `except` at
    all. A tuple written by hand goes stale the day somebody adds the seventh error class — so this
    walks the package and asserts every `*Error` in it is handled.
    """
    import pkgutil

    from hullwork import cli as cli_module
    from hullwork import sandbox

    handled = {failure.__name__ for failure in cli_module.SANDBOX_FAILURES}
    declared: set[str] = set()
    for module in pkgutil.iter_modules(sandbox.__path__):
        source = (Path(sandbox.__path__[0]) / f"{module.name}.py").read_text(encoding="utf-8")
        declared |= set(re.findall(r"^class (\w*Error)\(", source, re.M))

    assert declared, "this test has lost its subject"
    assert declared <= handled, (
        f"declared in hullwork/sandbox/ and not rendered as a sentence at the boundary: "
        f"{sorted(declared - handled)}"
    )
