"""Connecting a project without committing to it. Item 128, DR-0012.

The question that produced the decision was asked while connecting the first project this instance
does not own: *does `hullwork.yml` have to be in the repository?* The answer turned on a sentence
principle 4 already contained — **the manifest is adopted, not followed** — which means the runtime
authority is already a copy in `Project.manifest`, written at `add` and at `refresh`. The repository
is the source of that copy, not the arbiter.

So this is not a new mechanism. It is the existing one with a second door, and everything below is
about the door being narrower rather than wider: same parser, same refusals, same forge check, and
the row remembers which door it came through so `refresh` and `projects list` can tell the truth.

"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import httpx2
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from hullwork.cli import CommandError, add_project, refresh_manifest
from hullwork.cli import main as cli_main
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.forge import forgejo as forgejo_module
from hullwork.models import Project

ROOT = Path(__file__).resolve().parent.parent
REPO = "easybyte/undeclared"

HELD = """project: undeclared
git: {provider: forgejo, repo: easybyte/undeclared}
errors: {provider: glitchtip}
runtime: {base: python:3.12-slim}
tests: pytest
"""


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'held.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_BASE_URL", "https://hullwork.example")
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")
    with make_session_factory(make_engine(url))() as db:
        yield db
    get_settings.cache_clear()


@pytest.fixture
def settings() -> Settings:
    return get_settings()


@pytest.fixture(autouse=True)
def a_repository_with_no_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    """The case this exists for: the repository is there, and it declares nothing.

    `contents` answers 404 for `hullwork.yml` and the tree answers, so "no manifest" and "no
    repository" are distinguishable — which they were not until this item needed them to be.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        if path.endswith(f"/repos/{REPO}"):
            return httpx2.Response(200, json={"default_branch": "main"})
        if "contents" in path:
            return httpx2.Response(404, json={"errors": ["no such file"]})
        if "/branches/" in path:
            return httpx2.Response(200, json={"commit": {"id": "a" * 40}})
        if "git/trees" in path:
            return httpx2.Response(
                200, json={"tree": [{"path": "README.md", "type": "blob"}], "total_count": 1}
            )
        return httpx2.Response(404)

    original = forgejo_module.ForgejoForge.__init__

    def patched(self: forgejo_module.ForgejoForge, base_url: str, token: str, **kw: object) -> None:
        original(self, base_url, token, **kw)
        self._client = httpx2.Client(
            base_url=base_url, transport=httpx2.MockTransport(handler)
        )

    monkeypatch.setattr(forgejo_module.ForgejoForge, "__init__", patched)


def _file(tmp_path: Path, text: str = HELD) -> str:
    path = tmp_path / "undeclared.yml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_a_repository_that_declares_nothing_can_still_be_connected(
    session: Session, settings: Settings, tmp_path: Path
) -> None:
    """**The item.** Registering used to require a commit to the repository; for one you cannot
    write to, that is the whole wall."""
    registration = add_project(
        session, settings, slug="undeclared", forge_kind="forgejo", repo=REPO,
        manifest_file=_file(tmp_path),
    )

    assert registration.manifest.tests == "pytest"
    stored = session.query(Project).one()
    assert stored.manifest is not None
    assert stored.manifest_origin == "operator"
    assert stored.manifest_fetched_at is not None, "when this instance took it, which is true here"


def test_every_validation_still_runs(
    session: Session, settings: Settings, tmp_path: Path
) -> None:
    """A manifest that arrives by hand is not a manifest that is trusted more. Three refusals that
    have nothing to do with where the text came from, asserted through the new door."""
    disagrees = _file(tmp_path, HELD.replace("project: undeclared", "project: something-else"))
    with pytest.raises(CommandError, match="manifest says"):
        add_project(session, settings, slug="undeclared", forge_kind="forgejo", repo=REPO,
                    manifest_file=disagrees)

    unknown_engine = _file(tmp_path, HELD + "autofix: {agent: nonesuch}\n")
    with pytest.raises(CommandError):
        add_project(session, settings, slug="undeclared", forge_kind="forgejo", repo=REPO,
                    manifest_file=unknown_engine)

    wrong_forge = _file(tmp_path, HELD.replace("provider: forgejo", "provider: github"))
    with pytest.raises(CommandError):
        add_project(session, settings, slug="undeclared", forge_kind="github", repo=REPO,
                    manifest_file=wrong_forge)

    assert session.query(Project).count() == 0, "nothing is written until it validates"


def test_a_path_that_is_not_there_says_where_it_looked(
    session: Session, settings: Settings, tmp_path: Path
) -> None:
    """The likeliest mistake is handing over a path inside the repository rather than on this
    machine, and the message says which one it means."""
    with pytest.raises(CommandError, match="not in the repository") as refused:
        add_project(session, settings, slug="undeclared", forge_kind="forgejo", repo=REPO,
                    manifest_file=str(tmp_path / "absent.yml"))

    assert "absent.yml" in str(refused.value)


def test_refresh_refuses_and_names_the_flag(
    session: Session, settings: Settings, tmp_path: Path
) -> None:
    """**Refusing rather than fetching, and rather than doing nothing.** Going to the forge would
    either fail or adopt a file nobody registered; silence is what item 105 was closed for."""
    add_project(session, settings, slug="undeclared", forge_kind="forgejo", repo=REPO,
                manifest_file=_file(tmp_path))
    before = dict(session.query(Project).one().manifest or {})

    with pytest.raises(CommandError, match="nothing in") as refused:
        refresh_manifest(session, settings, "undeclared")

    assert "--manifest FILE" in str(refused.value)
    session.expire_all()
    assert dict(session.query(Project).one().manifest or {}) == before, "and it changed nothing"


def test_refresh_with_a_file_replaces_the_held_copy(
    session: Session, settings: Settings, tmp_path: Path
) -> None:
    """The other half: the copy is replaceable, through the same door it arrived by, with the same
    runtime diff printed that the forge path prints."""
    add_project(session, settings, slug="undeclared", forge_kind="forgejo", repo=REPO,
                manifest_file=_file(tmp_path))

    changed = _file(tmp_path, HELD.replace("python:3.12-slim", "python:3.13-slim"))
    out = io.StringIO()
    manifest = refresh_manifest(session, settings, "undeclared", manifest_file=changed, out=out)

    assert manifest.runtime is not None
    assert manifest.runtime.base == "python:3.13-slim"
    assert "3.13" in out.getvalue(), "what changed in the build environment, as the forge path does"
    assert session.query(Project).one().manifest_origin == "operator"


def test_a_project_registered_before_this_existed_is_not_assumed(session: Session) -> None:
    """`NULL` is a third answer. Writing `repository` for the projects that predate this column
    would be inferring it, and `refresh` treats not-recorded as the old behaviour — go and read the
    forge — which is exactly what those projects have always done."""
    session.add(
        Project(
            slug="older", forge="forgejo", repo="easybyte/older",
            webhook_secret_hash="x",  # noqa: S106
        )
    )
    session.commit()

    assert session.query(Project).filter_by(slug="older").one().manifest_origin is None


def test_projects_list_says_which_repositories_declare_nothing(
    session: Session, settings: Settings, tmp_path: Path
) -> None:
    """DR-0012 accepts a governance cost — the repository no longer says it is watched — on the
    condition that the instance says it instead, where projects are listed."""
    add_project(session, settings, slug="undeclared", forge_kind="forgejo", repo=REPO,
                manifest_file=_file(tmp_path))

    out = io.StringIO()
    assert cli_main(["projects", "list"], out=out) == 0

    assert "manifest held here" in out.getvalue()


def test_a_red_issue_does_not_send_a_reader_to_a_file_that_does_not_exist(
    session: Session, settings: Settings, tmp_path: Path
) -> None:
    """**A false sentence this decision created, found in the first issue it filed.**

    A red item's issue said *"Reclassify it in `hullwork.yml`"*, and the whole point of DR-0012 is
    that this repository has no such file. Measured on GitHub issue #2 of the first project
    connected this way, an hour after the decision was accepted.
    """
    from hullwork.ingest import _issue_body
    from hullwork.models import Item, Lane

    add_project(session, settings, slug="undeclared", forge_kind="forgejo", repo=REPO,
                manifest_file=_file(tmp_path))
    project = session.query(Project).one()
    item = Item(
        project_id=project.id, fingerprint="fp", lane=Lane.RED, title="ValueError: something",
    )
    session.add(item)
    session.commit()

    stored = session.get(Item, item.id)
    assert stored is not None
    body = _issue_body(stored)

    assert "`hullwork.yml`" not in body
    assert "the manifest this instance holds" in body
    assert "--manifest FILE" in body


def test_a_repository_that_does_declare_one_is_still_sent_to_it(session: Session) -> None:
    """The other half, unchanged: most projects keep their manifest where it versions with the code,
    and the issue keeps pointing there."""
    from hullwork.ingest import _issue_body
    from hullwork.models import Item, Lane

    project = Project(
        slug="declared", forge="forgejo", repo="easybyte/declared",
        webhook_secret_hash="x",  # noqa: S106
        manifest_origin="repository",
    )
    session.add(project)
    session.flush()
    item = Item(project_id=project.id, fingerprint="fp2", lane=Lane.RED, title="ValueError: x")
    session.add(item)
    session.commit()

    stored = session.get(Item, item.id)
    assert stored is not None
    assert "`hullwork.yml`" in _issue_body(stored)


def test_a_repository_with_no_manifest_is_not_a_forge_that_is_down(
    session: Session, settings: Settings, tmp_path: Path
) -> None:
    """**The instance called itself degraded for ever, minutes after filing an issue.**

    `confirm_forge` asked for `hullwork.yml` and `read_manifest` raises on a missing file, so a
    project whose manifest this instance holds — which by definition has none — made the health
    check record `unreachable:404`. Measured on the live second instance: `/ready` answered 503
    with `the forge is 404` while the same credential had just created GitHub issue #2.

    `read_file` answers `None` for a missing file and raises only when the forge or the credential
    is the problem, which is the question this check is asking.
    """
    from hullwork import readiness
    from hullwork.ingest import confirm_forge

    add_project(session, settings, slug="undeclared", forge_kind="forgejo", repo=REPO,
                manifest_file=_file(tmp_path))
    readiness.record_forge("unknown")

    from hullwork.forge.factory import make_forge

    forge = make_forge(settings)
    assert forge is not None
    try:
        confirm_forge(session, forge, stale_after=0)
    finally:
        forge.close()

    assert readiness.check(session, settings, error_reporting=False).forge == "ok"
