"""The services a project's suite needs, and the two properties that are easy to lose (item 052).

Driven through a fake `docker` on `PATH` that records its own argument lists, because every claim
here is about what is asked of the daemon: which networks a phase joins, what the suite is told, and
whether the database the green gate reads is the one the red gate wrote to. A real daemon would test
Docker; this tests the decisions.
"""

import os
import stat
from pathlib import Path

import pytest

from hullwork.manifest import RuntimeConfig
from hullwork.sandbox.run import Sandbox
from hullwork.sandbox.services import SERVICES, ServiceError, Services, unknown

#: A `docker` that answers every call successfully and appends its argv to a log the test reads.
#: `run --detach` has to print a container id, and the readiness probe has to succeed.
_FAKE_DOCKER = """#!/bin/sh
printf '%s\\n' "$*" >> "$HULLWORK_TEST_DOCKER_LOG"
case "$1 $2" in
  "run --detach") echo "container-$$" ;;
  "run --rm") exit 0 ;;
esac
exit 0
"""


@pytest.fixture
def docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake `docker` on `PATH`, and the file it writes its calls to."""
    binary = tmp_path / "bin" / "docker"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text(_FAKE_DOCKER)
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "docker.log"
    log.touch()
    monkeypatch.setenv("HULLWORK_TEST_DOCKER_LOG", str(log))
    monkeypatch.setenv("PATH", f"{binary.parent}{os.pathsep}{os.environ['PATH']}")
    return log


def _calls(log: Path) -> list[str]:
    return [line for line in log.read_text().splitlines() if line.strip()]


# --- the registry belongs to the instance --------------------------------------------------------


def test_a_service_this_build_does_not_know_is_named(docker: Path) -> None:
    """The refusal that makes half one worth shipping alone."""
    assert unknown(["postgres-16", "kafka-3"]) == ["kafka-3"]
    assert unknown([]) == []


def test_every_registry_entry_can_be_probed_and_exports_something() -> None:
    """A service with no probe would be slept on, and one with no exports could not be reached.

    Asserted over the whole table rather than per entry, so adding a fifth service cannot ship
    half-configured — which is exactly how `openhands` shipped as a name that resolved to nothing.
    """
    for name, service in SERVICES.items():
        assert service.probe, f"{name} has no readiness probe"
        assert service.exports, f"{name} tells the suite nothing"
        assert all("{host}" in part or not part.startswith("{") for part in service.probe)


def test_the_manifest_can_declare_a_service_and_nothing_more() -> None:
    """A project names a service. It cannot name an image, a port or an environment variable."""
    runtime = RuntimeConfig(base="python-3.12", install="none", services=["postgres-16"])

    assert runtime.services == ["postgres-16"]
    assert not hasattr(runtime, "service_images")


def test_a_service_outside_the_closed_set_does_not_parse() -> None:
    """The same argument as `SandboxBase`: a free-form string here is an image reference from an
    untrusted file going to `docker run` on the operator's host."""
    with pytest.raises(ValueError, match="services"):
        # The ignore is the point: the type forbids it and the parser must refuse it at runtime too,
        # because a manifest arrives as text from a repository and never through this constructor.
        RuntimeConfig(
            base="python-3.12", install="none", services=["kafka-3"],  # type: ignore[list-item]
        )


# --- what a phase actually joins -----------------------------------------------------------------


def test_a_gate_phase_joins_the_services_and_not_the_gateway(tmp_path: Path) -> None:
    """The two rules meeting: item 052 gives the gate a database, item 058 denies it the gateway."""
    box = Sandbox(
        image="img", worktree=tmp_path, volume="v",
        gateway_url="http://172.20.0.2:8080", network="hullwork-attempt-abc",
        services=["postgres-16"],
    )

    argv = box._argv("pytest", None, model=False, service_network="hullwork-services-t1")
    joined = [argv[i + 1] for i, flag in enumerate(argv) if flag == "--network"]

    assert joined == ["hullwork-services-t1"]
    assert not [flag for flag in argv if "BASE_URL" in flag]


def test_an_agent_phase_joins_both(tmp_path: Path) -> None:
    """Two `--network` flags, measured legal on 2026-07-29. The agent needs the model to think and
    the database to run the test it just wrote — writing one blind is how it reproduces nothing."""
    box = Sandbox(
        image="img", worktree=tmp_path, volume="v",
        gateway_url="http://172.20.0.2:8080", network="hullwork-attempt-abc",
        services=["postgres-16"],
    )

    argv = box._argv("agent", None, model=True, service_network="hullwork-services-t1")
    joined = [argv[i + 1] for i, flag in enumerate(argv) if flag == "--network"]

    assert joined == ["hullwork-attempt-abc", "hullwork-services-t1"]


def test_a_project_with_no_services_is_unchanged(tmp_path: Path) -> None:
    """`--network none` still, so this field cannot quietly give every project a network."""
    box = Sandbox(image="img", worktree=tmp_path, volume="v")

    argv = box._argv("pytest", None)

    assert [argv[i + 1] for i, flag in enumerate(argv) if flag == "--network"] == ["none"]


# --- the address reaches the suite ---------------------------------------------------------------


def test_the_suite_is_told_where_the_database_is(docker: Path) -> None:
    """`dispatch._run_gate` ran the test command with **no environment at all**, so even with a
    database running the project had no way to be told its address."""
    with Services(["postgres-16"], tag="t1") as services:
        assert services.env["DATABASE_URL"] == (
            "postgresql://hullwork:hullwork@postgres-16:5432/hullwork"
        )
        assert services.env["PGHOST"] == "postgres-16"
        assert services.env["PGPORT"] == "5432"


def test_the_service_port_is_never_published_to_the_host(docker: Path) -> None:
    """Nothing outside the attempt's own network has any business reaching it."""
    with Services(["postgres-16"], tag="t1"):
        pass

    assert not [call for call in _calls(docker) if " -p " in call or "--publish" in call]


def test_the_network_the_services_sit_on_is_internal(docker: Path) -> None:
    """Measured: an `--internal` network resolves container names and no external host, so a
    service network grants no egress. Without the flag it would grant the internet."""
    with Services(["postgres-16"], tag="t1"):
        pass

    created = [call for call in _calls(docker) if call.startswith("network create")]
    # Item 125 added `--label`, so the claim is now made of its parts rather than of one string:
    # the network is internal **and** it says whose it is, which is what stops a second instance's
    # reaper from removing it.
    assert len(created) == 1
    assert "--internal" in created[0]
    assert "--label hullwork.instance=default" in created[0]
    assert created[0].endswith("hullwork-services-t1")


# --- the property that quietly invalidates the product's claim -----------------------------------


def test_the_services_are_recreated_between_the_red_gate_and_the_green_gate(
    docker: Path, tmp_path: Path
) -> None:
    """The one that matters, and the reason this is not a field on `Sandbox`.

    Created once per attempt, a database is mutated by the baseline, the red gate and the green gate
    — three of the six phases. So "this test failed before the change and passes after it" would be
    a comparison of two different databases, and DR-0003's claim is the only thing this product
    asserts. A fresh `postgres:16` answered `pg_isready` two seconds after `docker run`, which is
    what makes paying this per phase affordable.
    """
    (tmp_path / "wt").mkdir()
    box = Sandbox(
        image="img", worktree=tmp_path / "wt", services=["postgres-16"], volume=None,
    )

    box.run("pytest", timeout=10)   # the red gate
    box.run("pytest", timeout=10)   # the green gate

    started = [call for call in _calls(docker) if "postgres:16" in call and "--detach" in call]
    removed = [call for call in _calls(docker) if call.startswith("rm -f")]
    networks = {
        call.split()[-1] for call in _calls(docker) if call.startswith("network create")
    }

    assert len(started) == 2, "each phase must get its own database"
    assert len(networks) == 2, "and its own network, or the two phases could see each other"
    assert len(removed) >= 2, "and both must be gone afterwards"


def test_everything_is_torn_down_even_when_the_phase_raises(docker: Path) -> None:
    """A service left running holds a name and a subnet on somebody's host until they notice."""
    with pytest.raises(RuntimeError, match="the phase blew up"), Services(
        ["postgres-16"], tag="t1"
    ):
        raise RuntimeError("the phase blew up")

    calls = _calls(docker)
    assert [call for call in calls if call.startswith("rm -f")]
    assert [call for call in calls if call.startswith("network rm")]


def test_a_service_that_never_becomes_ready_does_not_cost_the_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It raises a `SandboxError`, which `work.run_one` turns into an abandoned attempt — a database
    that would not start says nothing about whether the bug is reproducible (item 043's rule)."""
    from hullwork.sandbox import services as services_module

    binary = tmp_path / "bin" / "docker"
    binary.parent.mkdir(parents=True, exist_ok=True)
    # Starts fine, never answers the probe.
    binary.write_text(
        "#!/bin/sh\ncase \"$1 $2\" in\n  'run --rm') exit 1 ;;\n  'run --detach') echo c ;;\nesac\n"
        "exit 0\n"
    )
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{binary.parent}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(services_module, "READY_SECONDS", 1)

    with pytest.raises(ServiceError, match="did not become ready"), Services(
        ["postgres-16"], tag="t1"
    ):
        pass


def test_a_name_the_registry_lost_is_refused_before_anything_starts(docker: Path) -> None:
    """Registration refuses these, so reaching here means a validator moved. Say so rather than
    starting half a set of services and failing the suite on the missing one."""
    with pytest.raises(ServiceError, match="supposed to be refused at registration"):
        Services(["kafka-3"], tag="t1")
