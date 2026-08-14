"""`propose` and `projects lanes`, on the page. Item 222, item 218 §3 — minus its decision.

**These were parked behind DR-0024 and never needed it.** I read item 142 — *a page render must not
spend a forge request, and a reader refreshing would spend one each time* — as a ban on the receiver
reading a repository at all, and put both commands in the list waiting on a decision about OSV.

The rule is about a **render**. These are actions somebody pressed, which is the shape
`projects refresh` has had since item 206: one read, when asked, because they asked. Nothing here
needs a new credential, a new host or a table, and the only thing that was blocking them was my
reading of a sentence.

What is left waiting on DR-0024 is `deps` alone, which genuinely needs OSV and somewhere to keep a
report.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import operator, page
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import Base, Project
from hullwork.security import generate_token, hash_token


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/repo.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "t")
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    session.add(
        Project(
            slug="shop", forge="forgejo", repo="acme/shop",
            webhook_secret_hash="x",  # noqa: S106 - a fixture, not a credential
            manifest={
                "project": "shop",
                "git": {"provider": "forgejo", "repo": "acme/shop"},
                "errors": {"provider": "glitchtip"},
            },
        )
    )
    session.commit()
    yield session
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    from hullwork.main import app

    return TestClient(app)


def _signed_in(db: Session, client: TestClient) -> None:
    operator.set_password(db, "correct horse")
    db.commit()
    client.post("/page/me/login", data={"password": "correct horse"})


def _csrf(client: TestClient) -> str:
    found = re.search(r'name="csrf" value="([^"]+)"', client.get("/page/me/instance").text)
    assert found is not None, "no CSRF field on the instance report"
    return found.group(1)


#: **Patched where they are defined, not where they are used.** `_propose_one` and `_lanes_of`
#: import from `hullwork.cli` inside the function, so a name bound on `hullwork.main` is a name
#: nothing looks at — the first version of these tests patched that and every one errored.
class _Tree:
    """What a forge answers when asked for a tree. Named fields, because a hand-built double that
    drifts from its protocol is a mistake this project has now made four times."""

    def __init__(self, paths: tuple[str, ...], *, truncated: bool = False) -> None:
        self.paths = paths
        self.ref = "0123456789abcdef"
        self.truncated = truncated


class _Forge:
    def __init__(self, tree: _Tree | None = None) -> None:
        self._tree = tree
        self.closed = False

    def tree(self, repo: str) -> _Tree:
        assert self._tree is not None
        return self._tree

    def close(self) -> None:
        self.closed = True


# --- the lane policy, applied to their code ---------------------------------------------------


def test_the_lane_policy_is_shown_over_the_projects_own_tree(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**An operator who cannot see the policy applied to their code is being asked to trust a
    paragraph**, and this product's first principle is that trust is the product."""
    from hullwork import cli as cli_module

    forge = _Forge(_Tree(("app/checkout.py", "app/payments/charge.py", "README.md")))
    monkeypatch.setattr(cli_module, "_forge_for", lambda settings, kind: forge)
    _signed_in(db, client)

    shown = client.post(
        "/page/me/projects/shop/settings", data={"action": "lanes", "csrf": _csrf(client)}
    )

    assert shown.status_code == 200
    assert "3 file(s)" in shown.text
    assert "keeps a human on" in shown.text
    assert forge.closed, "the forge connection was left open"


def test_a_truncated_tree_says_so_rather_than_reading_as_clean(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**What is missing is unclassified, not classified as ordinary.** A partial listing rendered
    without that sentence is a page claiming a repository has no sensitive files because the forge
    stopped talking halfway."""
    from hullwork import cli as cli_module

    forge = _Forge(_Tree(("app/checkout.py",), truncated=True))
    monkeypatch.setattr(cli_module, "_forge_for", lambda settings, kind: forge)
    _signed_in(db, client)

    shown = client.post(
        "/page/me/projects/shop/settings", data={"action": "lanes", "csrf": _csrf(client)}
    )

    assert "did not serve the whole tree" in shown.text
    assert "not classified as ordinary" in shown.text


def test_the_lane_policy_is_never_stored(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**A derived policy kept on disk is a snapshot of which code is dangerous**, and
    `territory.py` explains why that fails in the direction that matters: the tree moves, the
    snapshot does not, and the file that became sensitive last week reads as ordinary.

    So this is an action and never a cache — asserted, because *read-only and stores nothing* was
    a sentence in a docstring and nothing was checking it on this path."""
    from hullwork import cli as cli_module

    monkeypatch.setattr(
        cli_module, "_forge_for",
        lambda settings, kind: _Forge(_Tree(("app/payments/charge.py", "README.md"))),
    )
    _signed_in(db, client)
    before = db.query(Project).one().manifest

    client.post("/page/me/projects/shop/settings", data={"action": "lanes", "csrf": _csrf(client)})

    db.rollback()
    assert db.query(Project).one().manifest == before, "the derived policy was written down"


def test_a_forge_that_will_not_answer_says_which_repository(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal naming nothing sends somebody to check every project they have."""
    from hullwork import cli as cli_module

    class _Refuses(_Forge):
        def tree(self, repo: str) -> _Tree:
            raise RuntimeError("404 Not Found")

    monkeypatch.setattr(cli_module, "_forge_for", lambda settings, kind: _Refuses())
    _signed_in(db, client)

    shown = client.post(
        "/page/me/projects/shop/settings", data={"action": "lanes", "csrf": _csrf(client)}
    )

    assert "acme/shop" in shown.text
    assert "404 Not Found" in shown.text


# --- the manifest read from their CI ----------------------------------------------------------


def test_a_manifest_is_proposed_and_not_written(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**It prints and does not write**, here as in the terminal. A manifest belongs in the
    project's repository, committed by somebody who read it — and DR-0006's rule that what was
    inferred stays commented only means anything if a person uncomments it."""
    from hullwork import cli as cli_module

    forge = _Forge()
    monkeypatch.setattr(cli_module, "_forge_for", lambda settings, kind: forge)
    monkeypatch.setattr(
        cli_module, "propose_from_ci", lambda forge_, repo: "project: shop\nruntime:\n  base: x"
    )
    _signed_in(db, client)
    before = db.query(Project).one().manifest

    shown = client.post(
        "/page/me/projects/shop/settings", data={"action": "propose", "csrf": _csrf(client)}
    )

    assert "runtime:" in shown.text
    assert forge.closed, "the forge connection was left open"
    # **`rollback` and not `expire_all`.** This session opened a transaction reading the row above,
    # and SQLite serves it that snapshot until the transaction ends — so an expiry re-reads the
    # same view and a write by the application looks like no write at all. A mutation that stored
    # the proposal on the project escaped exactly here.
    db.rollback()
    assert db.query(Project).one().manifest == before, "it wrote the proposal to the project"


def test_a_repository_with_no_ci_says_what_to_do_instead(
    db: Session, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """*Nothing proposes a manifest* is not a refusal to connect the project, and the page has to
    say the field that decides whether anything can be built at all."""
    from hullwork import cli as cli_module

    monkeypatch.setattr(cli_module, "_forge_for", lambda settings, kind: _Forge())
    monkeypatch.setattr(cli_module, "propose_from_ci", lambda forge, repo: None)
    _signed_in(db, client)

    shown = client.post(
        "/page/me/projects/shop/settings", data={"action": "propose", "csrf": _csrf(client)}
    )

    assert "written by hand" in shown.text
    assert "runtime.base" in shown.text


# --- and the line every action on this page holds ----------------------------------------------


@pytest.mark.parametrize("what", ["lanes", "propose"])
def test_a_read_link_is_offered_neither(db: Session, client: TestClient, what: str) -> None:
    """DR-0021. Each of these spends a forge request; a control that does that for anybody holding
    a saved URL is a control that spends somebody else's rate limit."""
    minted = generate_token()
    page.issue(db, hash_token(minted))
    db.commit()

    seen = client.get(f"/page/{minted}/projects").text
    assert "Which files keep a human on" not in seen
    assert "Read a manifest from its CI" not in seen

    refused = client.post(f"/page/{minted}/projects/shop/settings", data={"action": what})
    assert refused.status_code == 404
