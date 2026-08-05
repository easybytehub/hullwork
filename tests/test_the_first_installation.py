"""What the first installation does when nobody arranged it in advance. Item 135.

Found by following `deployment-notes.md` line by line on a machine that had never run this, changing
nothing that was not written down. Three defects, all of them between a stranger and a working
instance, and all three in what `hullwork init` writes or what it tells them to do next.
"""

from pathlib import Path

import pytest

from hullwork import scaffold
from hullwork.doctor import State, docker_daemon


def _written(tmp_path: Path, docker_gid: str | None = None) -> str:
    scaffold.write(tmp_path, docker_gid=docker_gid)
    return (tmp_path / scaffold.COMPOSE_FILE).read_text()


def test_up_starts_the_half_that_needs_only_a_forge_token(tmp_path: Path) -> None:
    """**The item.** `init` closes by saying "attempting fixes needs two more credentials… nothing
    here turns it on", and the compose file it wrote turned it on: with no model key the dispatcher
    refuses to start — correctly — and `restart: unless-stopped` restarted it four times a minute
    for ever. A profile makes the sentence true by not starting that container at all.
    """
    compose = _written(tmp_path)

    dispatcher = compose.split("dispatcher:", 1)[1]
    assert "profiles: [autofix]" in dispatcher
    assert "profiles:" not in compose.split("dispatcher:", 1)[0], "the receiver always starts"


def test_the_operator_is_told_the_command_that_starts_the_other_half(tmp_path: Path) -> None:
    """A profile nobody knows about is a container that never runs."""
    compose = _written(tmp_path)

    assert "--profile autofix" in compose


def test_a_missing_socket_says_it_is_probably_the_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deployment notes run `init` inside a container, and one without the socket mounted cannot
    see the host's — so this note fired on **every** documented installation, under a first
    paragraph promising the group would be read off the host. Measured: with the mount it wrote
    the real gid, without it a placeholder.

    Platform pinned rather than inherited, so both this branch and the macOS one below are exercised
    wherever the suite runs — the defect they cover is precisely a note that was right on one
    platform and wrong on the other.
    """
    monkeypatch.setattr("sys.platform", "linux")
    done = scaffold.write(tmp_path, docker_gid=None)

    said = " ".join(done.notes)
    assert "container" in said
    assert "--volume /var/run/docker.sock:/var/run/docker.sock:ro" in said
    assert "stat -c %g" in said, "GNU stat, because that is what a Linux host has"


def test_on_macos_it_says_what_is_actually_wrong(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stranger ran `init` on macOS on 2026-08-04 and was told they were probably in a container,
    given a GNU `stat` that errors there, and handed a compose file whose autofix half cannot start
    on that machine at all — because it hard-mounts a socket Docker Desktop does not create unless
    the operator opts in, and `group_add` means nothing to it either.

    Three wrong answers, none marked as a guess. The note now names the setting, the platform, and
    the limit.
    """
    monkeypatch.setattr("sys.platform", "darwin")
    done = scaffold.write(tmp_path, docker_gid=None)

    said = " ".join(done.notes)
    assert "macOS" in said
    # GNU `stat`, deliberately: the number is read on the Linux host that will run the dispatcher,
    # never on this one, which is the whole point the note now makes.
    assert "stat -c %g" in said
    assert "cannot run on this machine" in said
    assert "container" not in said, "the container guess is a Linux answer and misleads here"


def test_a_real_gid_is_written_when_there_is_one(tmp_path: Path) -> None:
    compose = _written(tmp_path, docker_gid="989")

    assert '- "989"' in compose


def test_the_receiver_does_not_report_the_dispatchers_socket_as_broken(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**The false positive that made a correct first installation say `AILING`.** The receiver
    never holds the Docker socket (spec M2 §1), so "the daemon does not answer" is a fact about the
    wrong process — and `not_from_here` could not help: it asks whether a dispatcher is alive, and
    on a first installation none is. That is exactly when this fired.
    """
    # A client that cannot reach a daemon — the receiver's situation, where the socket was never
    # mounted. The fake stands in for it so the test says the same thing on a laptop with Docker
    # Desktop running as on a host without it.
    fake = tmp_path / "docker"
    fake.write_text(
        "#!/bin/sh\necho 'Cannot connect to the Docker daemon.' >&2\nexit 1\n", encoding="utf-8"
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    finding = docker_daemon("docker", socket=str(tmp_path / "no-socket-here"))

    assert finding.state is State.UNKNOWN, "unknown never fails the exit code"
    assert "dispatcher" in finding.detail


def test_an_ingest_only_installation_is_finished_rather_than_broken(tmp_path: Path) -> None:
    """**The last thing between a stranger and a green first run.** With no project naming an agent,
    nothing will ever ask for a model — so a missing model credential is a gap that is real,
    deliberate and must not be closed, which is what `expected` means here. Reported as `broken`, it
    made `doctor`'s first run say `AILING` about a deployment doing exactly what `init` described.
    """
    from hullwork.config import Settings
    from hullwork.doctor import failed, model_credential

    ingest_only = model_credential(Settings(), anything_uses_it=False)
    with_an_agent = model_credential(Settings(), anything_uses_it=True)

    assert ingest_only.state is State.EXPECTED
    assert failed([ingest_only]) is False, "a finished installation does not fail the exit code"
    assert with_an_agent.state is State.BROKEN, "and it is still broken where something needs it"
