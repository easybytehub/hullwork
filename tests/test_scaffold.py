"""`hullwork init`, and the one line whose absence is the product. Item 115.

Connecting a project became one command with item 107. Standing up the instance that runs it stayed
an 820-line document read in the right order — the first obstacle in the roadmap's first section,
because an instance nobody can install cannot be trusted, used or judged by anybody.

**What is asserted here is mostly what the scaffold refuses to do**, because that is where a
scaffold does damage: it writes into somebody's deployment directory, and the two files it writes
encode a credential boundary that a stranger has no way to check.

Measured end to end on the deployment host before this file existed: `hullwork init` in a clean
checkout, three values filled in by hand, `docker compose up -d --build`, and `/health` answering —
with the dispatcher refusing to start for the one honest reason (no model credential) and
`hullwork doctor` naming exactly that. Every test here was verified by reintroducing its defect.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
import yaml

from hullwork import scaffold
from hullwork.cli import main


def test_the_code_token_reaches_the_dispatcher_and_nowhere_else() -> None:
    """**The one line whose absence is the product** (DR-0009, spec M2 §1).

    The receiver answers webhooks from the internet and refuses to start holding a credential that
    can push. A scaffold that put this variable in both services would hand a stranger, in writing,
    the single mistake this design exists to prevent — and it would look like thoroughness.
    """
    services = yaml.safe_load(scaffold.compose(docker_gid="999"))["services"]

    assert "HULLWORK_FORGE_CODE_TOKEN" in services["dispatcher"]["environment"]
    assert "HULLWORK_FORGE_CODE_TOKEN" not in services["api"]["environment"]
    # And the reason is in the file, where somebody editing it will read it.
    assert "refuses to start" in scaffold.compose(docker_gid="999")


def test_the_dispatcher_listens_on_nothing() -> None:
    """The property that makes it safe for it to hold a push credential is that it is not
    reachable — not that it holds the socket. So: no ports, and no HTTP healthcheck either, which
    would be a listener by another name and would sit `unhealthy` for ever (item 087)."""
    services = yaml.safe_load(scaffold.compose(docker_gid="999"))["services"]

    assert "ports" not in services["dispatcher"]
    assert services["dispatcher"]["healthcheck"] == {"disable": True}
    assert "ports" in services["api"], "the receiver is the half that answers webhooks"


def test_the_dispatcher_does_not_migrate_and_is_given_time_to_stop() -> None:
    """Two lines that each cost a measured failure: the image's entrypoint migrates and two
    processes migrating one database race each other (item 076), and ten seconds is not enough for
    a stop that is honoured between turns — the default killed the process before it released its
    lease, orphaning a gateway, a network and three volumes (item 097)."""
    dispatcher = yaml.safe_load(scaffold.compose(docker_gid="999"))["services"]["dispatcher"]

    assert dispatcher["entrypoint"] == ["hullwork"]
    assert dispatcher["command"] == ["work", "--loop"]
    assert dispatcher["stop_grace_period"] == "20m"


def test_the_socket_group_is_read_from_the_host_and_said_when_it_cannot_be() -> None:
    """A constant here is a wrong constant: the group differs between distributions, and getting it
    wrong looks like a daemon that does not answer rather than like a bad group (item 074).

    Measured in production, which answered **989** — not the 999 a Debian-shaped guess
    would have written.
    """
    assert scaffold.docker_socket_group("/definitely/not/a/socket") is None

    with_socket = yaml.safe_load(scaffold.compose(docker_gid="989"))["services"]["dispatcher"]
    assert with_socket["group_add"] == ["989"]

    without = scaffold.compose(docker_gid=None)
    assert "REPLACE-ME" in without
    assert "stat -c %g" in without, "it has to say how to find the right number"


def test_nothing_is_ever_overwritten(tmp_path: Path) -> None:
    """**Measured on this project's own deployment, hours before this existed**: a compose file
    copied over another silently dropped `HULLWORK_ERROR_DSN`, the instance came up healthy, and
    its own error reporting was off. Nothing failed; a capability went quiet.

    A scaffold is precisely the tool that would do that to somebody's configuration.
    """
    (tmp_path / scaffold.COMPOSE_FILE).write_text("# mine, and it took me a week\n")

    done = scaffold.write(tmp_path, docker_gid="999")

    assert (tmp_path / scaffold.COMPOSE_FILE).read_text() == "# mine, and it took me a week\n"
    assert scaffold.COMPOSE_FILE in done.kept
    assert scaffold.ENVIRONMENT_FILE in done.created


def test_the_environment_file_is_private_and_holds_no_secret(tmp_path: Path) -> None:
    """Private **before** anybody fills it in: the window where a credential sits in a
    world-readable file is the one nobody remembers to close.

    And it carries no value that matters — every credential is minted by a person in a web
    interface, once, and a token typed into a terminal is a token in a shell history.

    **640 since 2026-08-05, and it was 600.** The compose mounts this file so `doctor` can compare
    what it assigns against what reached the container (item 144), and 600 makes that mount
    unreadable to the uid the image runs as — so the check written to catch a variable that never
    arrived could not run on any deployment `init` writes. Measured on this project's own instance,
    where it reported the file as assigning nothing at all.

    What is asserted here is the part that must not drift: **not** group- or world-*writable*, and
    **not** world-readable. The group read bit is the whole point of the change, so a test that
    pinned the mode to one number would now be pinning the defect.
    """
    scaffold.write(tmp_path, docker_gid="999")
    written = tmp_path / scaffold.ENVIRONMENT_FILE

    mode = stat.S_IMODE(written.stat().st_mode)
    assert not mode & stat.S_IRWXO, f"a file of credentials must not be world-readable: {mode:o}"
    assert not mode & (stat.S_IWGRP | stat.S_IXGRP), f"and not group-writable either: {mode:o}"
    assert mode & stat.S_IRGRP, "the image's group must read it, or item 144's check cannot run"
    credentials = ("HULLWORK_FORGE_TOKEN", "HULLWORK_FORGE_CODE_TOKEN",
                   "HULLWORK_TRACKER_TOKEN", "HULLWORK_MODEL_KEY", "HULLWORK_ERROR_DSN")
    for line in written.read_text().splitlines():
        if line.startswith(credentials):
            assert line.endswith("="), f"a credential was given a value: {line}"


def test_init_says_what_only_a_person_can_do(tmp_path: Path, capsys: object) -> None:
    """A scaffold that stops at "files written" leaves the reader where the 820-line document did.

    The three things it cannot do are the three that need a human: mint a token that can file
    issues and not push, choose an address the error tracker can actually reach, and decide whether
    fixes are attempted at all — which is per project, in the project's own manifest.

    **Rewritten by substance in item 197, and the wording it used to pin is deliberately gone.** It
    asserted `"Mint a forge token"` from a numbered list printed identically to everybody, which was
    the union of every capability's requirements — nineteen variables' worth of instruction for a
    reader who needed four. The three properties above are what mattered and all three survive; the
    sentences carrying them are now per-variable and per-capability. A test that pinned the copy
    would have made improving it look like breaking it.
    """
    from io import StringIO

    out = StringIO()
    assert main(["init", "--into", str(tmp_path)], out=out) == 0
    said = out.getvalue()

    assert "HULLWORK_FORGE_TOKEN" in said
    assert "not** push" in said
    assert "reachable from your tracker" in said
    assert "opted into per project" in said, "attempting fixes is a per-project decision"
    assert "Attempting fixes is off" in said, "and it is off until somebody says otherwise"


def test_init_touches_no_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """**It runs where there is no instance yet.** Opening the database would create an empty
    `hullwork.db` in whatever directory the operator is standing in — the exact trap
    `deployment-notes.md` warns about, sprung by the command that exists to spare them the reading.

    So the operator's directory is where this looks: `main` is entered from inside it, exactly as
    a person standing in their deployment directory would.
    """
    from io import StringIO

    monkeypatch.chdir(tmp_path)
    main(["init", "--into", str(tmp_path)], out=StringIO())

    assert not list(tmp_path.glob("*.db"))
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(
        [scaffold.COMPOSE_FILE, scaffold.ENVIRONMENT_FILE],
    )


def test_a_blank_variable_means_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """**The defect the gate found on the first boot**, and it is not the scaffold's alone.

    A compose file cannot express absence: every variable is `"${HULLWORK_X:-}"`, which passes an
    empty string. Item 082 fixed that for `max_turns` and its docstring claimed the rest were
    *"fine"* — but pydantic turns `""` into `SecretStr("")`, which is **truthy as an object**. So
    `HULLWORK_ERROR_DSN=`, written by this very scaffold, stopped the receiver from starting:
    *"HULLWORK_ERROR_DSN is set but the error-reporting SDK is not installed"*, on a deployment
    that had never asked for it. The same shape hands the forge an empty token and turns "not
    configured" into a 401 four layers away.
    """
    from hullwork.config import Settings

    # Through the environment, because that is the path compose uses: `"${HULLWORK_X:-}"`.
    monkeypatch.chdir(tmp_path)  # so no development `.env` answers instead
    for name in ("ERROR_DSN", "FORGE_URL", "MODEL_KEY", "TRACKER_TOKEN"):
        monkeypatch.setenv(f"HULLWORK_{name}", "")
    monkeypatch.setenv("HULLWORK_FORGE_TOKEN", "   ")

    settings = Settings()

    assert settings.error_dsn is None
    assert settings.forge_token is None, "a SecretStr('') is truthy, which is the whole defect"
    assert settings.tracker_token is None
    assert settings.forge_url is None
    assert settings.model_key is None
    # And a value that is actually set still arrives.
    monkeypatch.setenv("HULLWORK_FORGE_URL", "https://forge.example")
    assert Settings().forge_url == "https://forge.example"


def test_every_setting_is_classified() -> None:
    """**This test is item 145.** Not the generator — the generator is a loop over this mapping.

    The scaffold used to enumerate variables as a string literal, and a literal has no relation to
    the model it mirrors. Measured on 2026-08-04 it named 16 of 35: nineteen settings, including
    every one added by items 133, 137 and 144, could not reach a container in a deployment written
    by our own command. That was not two hosts misconfigured: it shipped as the default, and
    nothing was going to notice.

    A field added tomorrow and forgotten fails here, by name. That is the difference between making
    the omission visible (item 144) and making it impossible.
    """
    from hullwork.config import Settings
    from hullwork.scaffold import REACH

    unclassified = sorted(set(Settings.model_fields) - set(REACH))
    assert not unclassified, (
        f"settings with no place in the deployment: {unclassified}. "
        f"Add each to `scaffold.REACH` — which half needs it?"
    )
    stale = sorted(set(REACH) - set(Settings.model_fields))
    assert not stale, f"classified and no longer a setting: {stale}"


def test_the_receiver_never_gets_the_credential_that_can_push() -> None:
    """DR-0009, asserted on the generated YAML rather than on the mapping that produced it.

    A test of the classification would pass against a generator that ignored it. This parses what
    `hullwork init` actually writes, because the receiver refuses to start holding this credential
    (item 032) and a scaffold that hands it over produces a deployment that cannot boot — with the
    boundary lost quietly if it ever could.
    """
    import yaml

    from hullwork.scaffold import compose

    services = yaml.safe_load(compose(docker_gid="999"))["services"]

    assert "HULLWORK_FORGE_CODE_TOKEN" not in services["api"]["environment"]
    assert "HULLWORK_FORGE_CODE_TOKEN" in services["dispatcher"]["environment"]


def test_the_generated_compose_can_deliver_every_setting() -> None:
    """Counted against `Settings`, never against a literal — a literal is what went stale.

    The two `deployment_*` paths are deliberately absent: they name files on the host, and a
    container told about the host's filesystem learns nothing. They are `Reach.NEITHER`, which is a
    decision recorded rather than an omission.
    """
    import yaml

    from hullwork.config import Settings
    from hullwork.scaffold import REACH, Reach, compose

    services = yaml.safe_load(compose(docker_gid="999"))["services"]
    delivered = set(services["api"]["environment"]) | set(services["dispatcher"]["environment"])
    expected = {
        f"HULLWORK_{name.upper()}"
        for name, where in REACH.items()
        if where is not Reach.NEITHER
    }

    assert expected - delivered == set(), "classified for a service and not passed to one"
    assert delivered - expected == set(), "passed to a service and not a setting"
    # **Every field, with nothing excluded** — this read `- 2` until 2026-08-04, for the two
    # deployment paths classified `NEITHER` because they name files on the host. They do,
    # and `doctor` runs inside a container, so item 144's drift check could never open them. The
    # files are mounted read-only now and both halves are told where, which makes `NEITHER` an empty
    # class: nothing in `Settings` is deliberately withheld from every service.
    assert len(expected) == len(Settings.model_fields), "every setting reaches a service"


def test_generating_twice_is_byte_identical() -> None:
    """A regenerated file has to diff cleanly against the one it replaces, or nobody will regenerate
    it — and an operator who will not regenerate is back to maintaining it by hand."""
    from hullwork.scaffold import compose

    assert compose(docker_gid="999") == compose(docker_gid="999")


def test_the_environment_file_names_every_setting_that_can_be_set() -> None:
    """The other half of item 145, and the one that faces the operator.

    The compose *delivers* settings; this file is where somebody **discovers one exists**.
    Measured on 2026-08-04 by walking the golden path as a stranger would: the compose could deliver
    33 and this file named 15 — including `MAX_ATTEMPT_TOKENS`, the ceiling that protects a prepaid
    balance, which is the setting a first-time evaluator most needs and had no way to hear about.
    """
    import re

    from hullwork.config import Settings
    from hullwork.scaffold import _NOT_IN_ENVIRONMENT, environment

    text = environment(docker_gid="999")
    named = set(re.findall(r"HULLWORK_[A-Z_]+", text))
    expected = {f"HULLWORK_{name.upper()}" for name in Settings.model_fields}
    excluded = {f"HULLWORK_{name.upper()}" for name in _NOT_IN_ENVIRONMENT}

    assert expected - named - excluded == set(), "a setting nobody could discover"


def test_no_setting_is_listed_twice_in_the_environment_file() -> None:
    """A name that appears with a value **and** commented out invites uncommenting the dead copy.

    The generated block filters against the prose above it rather than against a list, so a setting
    promoted into the prose stops being duplicated without anybody maintaining anything.
    """
    from hullwork.config import Settings
    from hullwork.scaffold import environment

    text = environment(docker_gid="999")
    twice = [
        f"HULLWORK_{name.upper()}"
        for name in Settings.model_fields
        if text.count(f"HULLWORK_{name.upper()}=") > 1
    ]

    assert twice == []
