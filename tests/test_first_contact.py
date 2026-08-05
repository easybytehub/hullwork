"""What `projects add` leaves an operator knowing. Item 118.

The roadmap's last code-shaped obstacle in "somebody else can install it": a newly connected project
is skipped by the clock until `hullwork sweep <slug> --confirm`, **the gate is right**, and it took
an hour to notice on this project's own instance with everything else working.

`set-tracker` and `sweep` both explain it already — to somebody who knew to run them. These tests
are about first contact, which is the one moment an operator is definitely reading.
"""

from __future__ import annotations

import base64
import io
from collections.abc import Iterator
from pathlib import Path

import httpx2
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from hullwork.cli import main
from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.forge import forgejo as forgejo_module

ROOT = Path(__file__).resolve().parent.parent
REPO = "easybyte/hullwork-sandbox"

MANIFEST = """project: sandbox
git:
  provider: forgejo
  repo: easybyte/hullwork-sandbox
errors:
  provider: glitchtip
runtime:
  base: python:3.12-slim
tests: pytest
autofix:
  agent: {agent}
  lanes:
    green: [typeerror]
"""


@pytest.fixture
def session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Session]:
    url = f"sqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_BASE_URL", "https://hullwork.example")
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "tok_not_real")
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")
    with make_session_factory(make_engine(url))() as db:
        yield db
    get_settings.cache_clear()


@pytest.fixture
def agent() -> str:
    return "none"


@pytest.fixture(autouse=True)
def fake_forge(monkeypatch: pytest.MonkeyPatch, agent: str) -> None:
    """The manifest over a mock transport, so no test opens a socket."""
    body = {
        "encoding": "base64",
        "content": base64.b64encode(MANIFEST.format(agent=agent).encode()).decode(),
    }

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith(f"/repos/{REPO}"):
            return httpx2.Response(200, json={"default_branch": "main"})
        if "contents" in request.url.path:
            return httpx2.Response(200, json=body)
        return httpx2.Response(404)

    original = forgejo_module.ForgejoForge.__init__

    def patched(
        self: forgejo_module.ForgejoForge, base_url: str, token: str, **kwargs: object
    ) -> None:
        original(self, base_url, token, **kwargs)
        self._client = httpx2.Client(
            base_url=base_url, transport=httpx2.MockTransport(handler)
        )

    monkeypatch.setattr(forgejo_module.ForgejoForge, "__init__", patched)


def _register() -> str:
    out = io.StringIO()
    assert main(["projects", "add", "--slug", "sandbox", "--repo", REPO], out=out) == 0
    return out.getvalue()


def test_it_says_what_is_live_and_what_is_deliberately_not(session: Session) -> None:
    """**The item.** An operator holding a fresh webhook URL has two questions, and before this the
    command answered neither: new errors are handled from now, and the backlog already in their
    tracker is not — which is a gate, not an oversight.
    """
    printed = _register()

    assert "What is live from this moment" in printed
    assert "deduplicated, triaged and filed as issues" in printed
    assert "backlog already in your tracker is untouched" in printed
    assert "three" in printed and "first afternoon" in printed, "the reason, not just the rule"


def test_it_names_both_commands_the_backlog_needs_in_order(session: Session) -> None:
    """Two commands, and the order is not optional: a sweep of a project with no tracker name has
    nothing to read. Printing them out of order would be a bug report waiting to happen."""
    printed = _register()

    set_tracker = printed.index("hullwork projects set-tracker sandbox")
    sweep = printed.index("hullwork sweep sandbox --confirm")
    assert set_tracker < sweep
    assert "--from-now" in printed, "the other way through the gate"


@pytest.mark.parametrize(
    ("agent", "expected"),
    [
        ("none", "Nothing will be attempted"),
        ("claude-code", "Fixes will be attempted by `claude-code`"),
    ],
)
def test_it_says_what_the_agent_setting_means_rather_than_printing_it(
    session: Session, expected: str
) -> None:
    """`Agent: none` is a value. *"Nothing will be attempted, and that is the default"* is an
    answer — and the difference matters most to the reader who has not read `hullwork-yml.md`."""
    printed = _register()

    assert expected in printed


def test_nothing_here_repeats_the_credential(session: Session) -> None:
    """The webhook URL is shown once and cannot be recovered, so every line added to this command
    is a chance to print it twice. Asserted here as well as in `test_cli.py`, because that test
    guards the command as it was and this one guards what was appended to it."""
    printed = _register()

    urls = [word for word in printed.split() if word.startswith("https://hullwork.example/webhooks/")]
    assert len(urls) == 1
