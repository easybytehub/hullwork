"""`doctor` and `config`, on the page. Item 208, DR-0022.

The two an operator reaches for when something is wrong, and the two that still required a shell.
Both already produce structured output — `doctor.examine` returns findings, `settings_report.rows`
yields `(variable, value, source, reaches)` — so this is a page and not a line of new logic.

The disclosure question is answered upstream, which is the opposite of what it looks like:
`config`'s own first line is *no credential is printed: a secret reads `set` or `not set`*, and that
redaction lives in `settings_report`. A page rendering those rows inherits the property.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from hullwork import operator, page
from hullwork.config import get_settings
from hullwork.db import make_engine
from hullwork.models import Base
from hullwork.security import generate_token, hash_token

#: A value no prose could contain, so finding it in the page means the page leaked it and not that
#: the page happened to use the word. The precedent is `test_page_surface`'s own token.
A_SECRET = "tok-forge-must-never-render"  # noqa: S105 - a fixture value, never a credential


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path}/page.db"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_BASE_URL", "https://hullwork.example")
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", A_SECRET)
    monkeypatch.setenv("HULLWORK_TRACKER_TOKEN", A_SECRET)
    get_settings.cache_clear()
    yield sessionmaker(bind=engine)()
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    from hullwork.main import app

    return TestClient(app)


def _signed_in(db: Session, client: TestClient) -> None:
    operator.set_password(db, "correct horse")
    db.commit()
    client.post("/page/me/login", data={"password": "correct horse"})


# --- the two views --------------------------------------------------------------------------------


def test_the_doctor_is_on_the_page(db: Session, client: TestClient) -> None:
    """Why an instance that is running will not work, without a shell.

    **What is not fine, and a count of what is** — item 203's lesson, applied here: a reader opens
    this looking for what is wrong, and fourteen green rows with one red among them is fourteen
    green rows. So the assertion is on the shape, not on a check that happens to be failing in a
    test environment.
    """
    _signed_in(db, client)

    shown = client.get("/page/me/doctor")

    assert shown.status_code == 200
    assert "check(s)" in shown.text, "it says how many were asked"
    assert "Why it will not work" in shown.text


def test_the_configuration_is_on_the_page(db: Session, client: TestClient) -> None:
    """What this process actually received, which is a different question from what you wrote in a
    file — and the one `environment_gaps` exists because people get wrong."""
    _signed_in(db, client)

    shown = client.get("/page/me/config")

    assert shown.status_code == 200
    assert "HULLWORK_BASE_URL" in shown.text
    assert "receiver" in shown.text, "which half receives it is half the answer"


# --- what neither may do --------------------------------------------------------------------------


@pytest.mark.parametrize("where", ["doctor", "config"])
def test_no_secret_reaches_either(db: Session, client: TestClient, where: str) -> None:
    """**Rendered with real credentials set and searched for them.** The redaction is
    `settings_report`'s, and this asserts the page did not undo it — a value that reads `set` in a
    terminal and prints itself in HTML would be this product leaking on the page it built to be
    trusted."""
    _signed_in(db, client)

    shown = client.get(f"/page/me/{where}")

    assert A_SECRET not in shown.text
    assert "set" in shown.text or where == "doctor"


@pytest.mark.parametrize("where", ["doctor", "config"])
def test_a_read_link_does_not_reach_them(db: Session, client: TestClient, where: str) -> None:
    """DR-0021's line: the token reads the instance, the password administers it. These two are the
    operator's, and a link handed to a colleague is not the operator."""
    minted = generate_token()
    page.issue(db, hash_token(minted))
    db.commit()

    shown = client.get(f"/page/{minted}/{where}")

    assert shown.status_code == 404


@pytest.mark.parametrize("where", ["doctor", "config"])
def test_neither_accepts_a_post(db: Session, client: TestClient, where: str) -> None:
    """They are reads. The guard that keeps the write surface readable stays untouched by this
    item, and this is that guard restated where the routes are added."""
    _signed_in(db, client)

    assert client.post(f"/page/me/{where}").status_code == 405


def test_the_doctor_does_not_report_the_other_half_as_broken(
    db: Session, client: TestClient
) -> None:
    """**`not_from_here`'s downgrade has to survive the move.** The receiver is not the dispatcher,
    and a page that reported the model credential missing — on an instance where it is present in
    the half that uses it — would send somebody to fix a working machine. Item 091 built that
    downgrade; item 199 relied on it; this asserts a page does not undo it.

    **Asserted by comparing to `doctor` rather than by looking for a phrase.** The first version
    searched for *not from here*, which only appears when there is a local failure to downgrade —
    so in an environment with none it passed while proving nothing, and would have kept passing if
    the page had re-classified everything itself.
    """
    from hullwork import doctor as doctor_module
    from hullwork import lease
    from hullwork.config import get_settings as settings_now

    lease.acquire(db, lease.new_holder())
    db.commit()
    _signed_in(db, client)
    settings = settings_now()

    shown = client.get("/page/me/doctor")

    theirs = doctor_module.examine(
        db,
        settings,
        code_forge=None,
        env_file=Path(settings.deployment_env_file or ".env"),
        compose_file=None,
    )
    for one in theirs:
        if one.state is doctor_module.State.OK:
            continue
        assert one.check in shown.text, one.check
        assert one.state.value in shown.text, f"{one.check} is not {one.state.value} on the page"
