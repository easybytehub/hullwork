"""`status` and `/ready` say the same thing about the same forge. Item 129.

**Measured on the second instance, minutes apart, about one forge and one credential:**

```
$ hullwork status        forge: unknown
$ GET /ready             ready: True | forge: ok | problems: []
```

Neither was misbehaving. `readiness._forge_state` is module-level state in whichever process last
spoke to the forge; `/ready` is served by the receiver, which asks every few minutes, and `status`
is a **different process** whose module state is the import-time default. What was wrong is that
`unknown` reads as a state of the forge when it is a fact about who is asking — the distinction the
doctor learned in item 091 and this line never did.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import httpx2
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import readiness
from hullwork.cli import main as cli_main
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.forge import forgejo as forgejo_module
from hullwork.ingest import forge_answers
from hullwork.models import Base, Project

REPO = "easybyte/watched"


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'forge.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    get_settings.cache_clear()
    session = sessionmaker(bind=engine)()
    session.add(
        Project(
            slug="watched", forge="forgejo", repo=REPO,
            webhook_secret_hash="x",  # noqa: S106
        )
    )
    session.commit()
    readiness.record_forge("unknown")
    yield session
    readiness.record_forge("unknown")
    get_settings.cache_clear()


def _forge_that(status: int, monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith(f"/repos/{REPO}"):
            return httpx2.Response(200, json={"default_branch": "main"})
        return httpx2.Response(status, json={"content": "", "encoding": "base64"})

    original = forgejo_module.ForgejoForge.__init__

    def patched(self: forgejo_module.ForgejoForge, base_url: str, token: str, **kw: object) -> None:
        original(self, base_url, token, **kw)
        self._client = httpx2.Client(
            base_url=base_url, transport=httpx2.MockTransport(handler)
        )

    monkeypatch.setattr(forgejo_module.ForgejoForge, "__init__", patched)


def test_both_answers_come_from_one_question(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The item, and the division of labour it settles.**

    `/ready` is a probe a container runs every thirty seconds: it reports the **last** measurement
    and must not spend a forge request per call — its own docstring says *cheap enough to serve on
    every probe*. `status` is a person asking now, so it **measures**. The defect was not that they
    play different roles; it was that `status` reported the import-time default of a module it had
    never populated, and called it `unknown` as if that described the forge.

    So: once anybody has asked — here, the receiver's own health check, exactly as its sweep does —
    the two say the same thing about the same forge.
    """
    _forge_that(200, monkeypatch)
    from hullwork.forge.factory import make_forge
    from hullwork.ingest import confirm_forge
    from hullwork.main import app

    # **Nobody has asked yet** — which is the production situation exactly: a fresh CLI process,
    # against a receiver that may or may not have swept since it started.
    assert readiness.check(db, get_settings(), error_reporting=False).forge == "unknown"

    printed = io.StringIO()
    cli_main(["status"], out=printed)

    assert "forge: ok" in printed.getvalue(), (
        "this is the defect: it used to report the module's import-time default as a state"
    )

    # And the probe still answers from the last measurement, which is its job — it is called every
    # thirty seconds and must not spend a forge request doing it.
    with TestClient(app) as client:
        assert client.get("/ready").json()["forge"] == "unknown"

    # Once the receiver asks, exactly as its sweep does, the two agree about one forge.
    forge = make_forge(get_settings())
    assert forge is not None
    try:
        confirm_forge(db, forge, stale_after=0)
    finally:
        forge.close()

    with TestClient(app) as client:
        served = client.get("/ready").json()
    again = io.StringIO()
    cli_main(["status"], out=again)

    assert served["forge"] == "ok"
    assert "forge: ok" in again.getvalue()


def test_a_forge_that_refuses_is_reported_as_refusing(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other direction, which is the one that matters for trusting the first: `status` used to
    exit 0 while the forge was unreachable, because it had never asked."""
    _forge_that(500, monkeypatch)

    printed = io.StringIO()
    code = cli_main(["status"], out=printed)

    assert code == 1
    assert "the forge is 500" in printed.getvalue()


def test_the_question_is_asked_through_the_function_the_sweep_uses(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One definition of "the forge is answering", so the two reports cannot drift apart again —
    which is the failure this item is about, not the wording of either one."""
    _forge_that(200, monkeypatch)
    from hullwork.forge.factory import make_forge

    forge = make_forge(get_settings())
    assert forge is not None
    try:
        assert forge_answers(db, forge) == "ok"
    finally:
        forge.close()


def test_measuring_does_not_write_anything_down(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**`status` reports and exits.** Recording its answer in module state that outlives the
    report is how the two came to disagree — and, when this was first written that way, how one
    test's status call started leaking into another's."""
    _forge_that(200, monkeypatch)
    from hullwork.forge.factory import make_forge

    forge = make_forge(get_settings())
    assert forge is not None
    try:
        assert forge_answers(db, forge) == "ok"
    finally:
        forge.close()

    assert readiness.check(db, get_settings(), error_reporting=False).forge == "unknown", (
        "measuring is not remembering"
    )


def test_with_no_forge_configured_it_says_that(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A different fact with a different remedy, and `unknown` is the honest word for it here:
    nobody asked because there is nobody to ask."""
    url = f"sqlite:///{tmp_path / 'bare.db'}"
    Base.metadata.create_all(make_engine(url))
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.delenv("HULLWORK_FORGE_URL", raising=False)
    monkeypatch.delenv("HULLWORK_FORGE_TOKEN", raising=False)
    get_settings.cache_clear()
    try:
        printed = io.StringIO()
        cli_main(["status"], out=printed)
    finally:
        get_settings.cache_clear()

    assert "forge: unknown" in printed.getvalue()


def test_nothing_to_ask_about_is_not_an_unreachable_forge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An instance with a forge and no projects yet has nothing to probe with. `None` says so, and
    the report keeps whatever it knew — rather than inventing a refusal nobody received."""
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    Base.metadata.create_all(make_engine(url))
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    get_settings.cache_clear()
    _forge_that(500, monkeypatch)
    from hullwork.forge.factory import make_forge

    session = sessionmaker(bind=make_engine(url))()
    forge = make_forge(get_settings())
    assert forge is not None
    try:
        assert forge_answers(session, forge) is None
    finally:
        forge.close()
        session.close()
        get_settings.cache_clear()
