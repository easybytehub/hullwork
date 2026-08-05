"""One instance, one forge — said out loud. Item 124.

**Measured by running the documented flow against the first third-party project anybody pointed
this at**: a finance dashboard on GitHub, watched by an instance configured for Forgejo.

```
$ hullwork propose FlagshipDev/personal-dashboard --forge github
error: nothing in FlagshipDev/personal-dashboard proposes a manifest: no CI configuration
was found at …

$ hullwork projects add --forge github --repo FlagshipDev/personal-dashboard
error: could not read hullwork.yml … GET /repos/FlagshipDev/personal-dashboard: HTTP 404
```

Both sentences are false about that repository: it has `.github/workflows/deploy.yml`, and this
project's own reader parses it. Neither command ever asked GitHub. `--forge github` was validated
against the supported list and then thrown away, and the factory chose the adapter from the
configured URL — so the 404 is Forgejo's, about a repository that does not exist there.

The design is right and stays: registration must go through the same path every later request
takes, or a project could be registered against a forge the pipeline would then fail to reach
(item 068). What was missing is one sentence, and these are the tests for it.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from pydantic import SecretStr

from hullwork import doctor
from hullwork.cli import CommandError, _forge_for
from hullwork.cli import main as cli_main
from hullwork.config import Settings, get_settings
from hullwork.db import make_engine
from hullwork.forge.factory import configured_kind, serves
from hullwork.models import Base

SELF_HOSTED = Settings(
    forge_url="https://forgejo.example", forge_token=SecretStr("ingest")
)
GITHUB = Settings(
    forge_url="https://github.com", forge_token=SecretStr("ingest")
)


def test_github_and_not_github_is_the_distinction_that_matters() -> None:
    """`forgejo` and `gitea` are one adapter against one API, so asking for either on the other is
    fine and refusing it would be pedantry. GitHub is a different API on a different host."""
    assert serves(SELF_HOSTED, "forgejo") is True
    assert serves(SELF_HOSTED, "gitea") is True, "same adapter, same API"
    assert serves(SELF_HOSTED, "github") is False

    assert serves(GITHUB, "github") is True
    assert serves(GITHUB, "forgejo") is False


def test_the_refusal_names_both_and_makes_no_request() -> None:
    """**The item.** What the operator asked for, what this instance is, and the fact that their
    repository was never consulted — which is the part the old message got exactly backwards."""
    with pytest.raises(CommandError) as refused:
        _forge_for(SELF_HOSTED, "github")

    said = str(refused.value)
    # **`forgejo`, where this used to say `self-hosted`.** Item 132: with GitLab registrable, "not
    # GitHub" stopped identifying anything, and item 124's whole sentence is that the instance says
    # *which* forge it serves. The refusal still has to name that and the URL.
    assert "forgejo" in said and "https://forgejo.example" in said
    assert "'github'" in said
    assert "Nothing was asked of github" in said


def test_it_says_what_the_operator_can_actually_do() -> None:
    """A refusal that names no way out is a dead end. There are exactly two, and the second one is
    a command that exists since item 115."""
    with pytest.raises(CommandError) as refused:
        _forge_for(SELF_HOSTED, "github")

    said = str(refused.value)
    assert "HULLWORK_FORGE_URL" in said, "point this instance at that forge"
    assert "hullwork init" in said, "or run a second instance for it"
    assert "HULLWORK_INSTANCE" in said, "and the second instance needs its own, or they collide"


def test_a_forge_this_instance_does_serve_is_untouched() -> None:
    """The change must be invisible to everybody it does not concern."""
    forge = _forge_for(SELF_HOSTED, "forgejo")

    assert forge is not None
    forge.close()


def test_no_forge_configured_still_says_that_instead(monkeypatch: pytest.MonkeyPatch) -> None:
    """A different problem with a different remedy, and it already had a sentence. Item 124 must
    not swallow it: `serves` returns True when nothing is configured precisely so that the older,
    more specific refusal is the one the operator reads."""
    bare = Settings()
    assert configured_kind(bare) is None
    assert serves(bare, "github") is True

    with pytest.raises(CommandError, match="HULLWORK_FORGE_URL and HULLWORK_FORGE_TOKEN"):
        _forge_for(bare, "github")


def test_doctor_says_which_forge_before_anybody_hits_the_wall() -> None:
    """Inside a refusal is too late: the operator has already written a manifest by then."""
    finding = doctor.which_forge(SELF_HOSTED)

    assert finding.state is doctor.State.OK
    assert "https://forgejo.example" in finding.detail
    assert "GitHub" in finding.detail, "and names what would need its own instance"
    assert "HULLWORK_INSTANCE" in finding.detail

    unset = doctor.which_forge(Settings())
    assert unset.state is doctor.State.UNKNOWN
    assert "no forge configured" in unset.detail


def test_the_check_is_wired_into_the_examination(tmp_path: Path) -> None:
    """**A function nobody calls is a check nobody gets.** Removing it from `examine`'s list left
    the test above green, which is how this one came to exist.
    """
    from sqlalchemy.orm import sessionmaker

    engine = make_engine(f"sqlite:///{tmp_path / 'wired.db'}")
    Base.metadata.create_all(engine)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'wired.db'}",
        forge_url="https://forgejo.example",
        forge_token=SecretStr("ingest"),
    )

    with sessionmaker(bind=engine)() as db:
        findings = doctor.examine(
            db,
            settings,
            code_forge=None,
            env_file=tmp_path / "absent",
            compose_file=None,
            docker="/nonexistent/docker",
        )

    named = {finding.check: finding for finding in findings}
    assert "forge" in named, "the check exists and nothing runs it"
    assert "https://forgejo.example" in named["forge"].detail


def test_end_to_end_the_command_refuses_before_the_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Through the command an operator types, which is where the false sentence was printed."""
    url = f"sqlite:///{tmp_path / 'forge.db'}"
    Base.metadata.create_all(make_engine(url))
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forgejo.example")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "ingest")
    get_settings.cache_clear()
    try:
        out = io.StringIO()
        code = cli_main(
            ["projects", "add", "--slug", "dash", "--forge", "github", "--repo", "owner/repo"],
            out=out,
        )
    finally:
        get_settings.cache_clear()

    assert code == 1
    # And nothing about the repository being empty, which is what it used to say.
    assert "no CI configuration" not in out.getvalue()
