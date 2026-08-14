"""The services a project's test suite needs, started beside it and thrown away with it.

Item 052. Measured on `acme` — the project chosen for M7 — `128 failed, 117 passed`, every
failure a `psycopg.OperationalError`. Step 0 requires the whole suite, so every item went
`baseline-red` → `human-only` with its attempt intact: item 043 behaving exactly as designed, and
the project never attempted. The refusal was working and it was the only thing that happened.

Four things measured in production before this was written, because the design rests on all four:

* **An `--internal` network resolves container names and nothing else.** `getent hosts <service>`
  answers; `getent hosts pypi.org` does not. So a service network grants no egress, and isolation
  and the service dependency are not in tension.
* **`docker run` accepts two `--network` flags**, so an agent phase can have the gateway *and* the
  services without any `docker network connect` choreography. `--network none` cannot be joined
  afterwards, so the choice is made at `docker run` time — which is why `Sandbox` decides per call.
* **A fresh `postgres:16` accepted `pg_isready` two seconds after `docker run`.** That is what makes
  the next point affordable rather than theoretical.
* **The services are recreated between the red gate and the green gate.** Created once per attempt,
  they are mutated by the baseline, the red gate and the green gate — three of six phases — so the
  comparison DR-0003 rests on would not be made against the same conditions. A suite that leaves a
  row behind would make the green gate pass for a reason that is not the fix.

**Readiness is probed, never slept on.** A sleep long enough for a slow host is wasted on every
fast one, and one long enough on average fails the attempt on the tail — which reads as "the
project's suite is broken" rather than "the database was not up yet".
"""

import logging
import time
from dataclasses import dataclass, field
from types import TracebackType

from hullwork.sandbox.docker import SandboxError, run_docker
from hullwork.sandbox.inventory import label_args

log = logging.getLogger(__name__)

#: How long a service gets to answer its readiness probe. Generous against a cold image pull on a
#: small host; a service that has not answered by now is broken rather than slow.
READY_SECONDS = 90

#: The capabilities a server image's entrypoint needs to **drop** root, and the reason this constant
#: exists rather than `--cap-drop ALL`.
#:
#: Found by running it, and it is the difference between the sandbox and a service. `--cap-drop ALL`
#: is right for the sandbox, which runs the watched project's code and needs to do nothing
#: privileged. It is *broken* for a database server, whose entrypoint starts as root precisely in
#: order to stop being root: measured in production, `postgres:16` with `--cap-drop ALL` dies with
#: `chmod: changing permissions of '/var/lib/postgresql/data': Operation not permitted` and then
#: `error: failed switching to 'postgres': operation not permitted`.
#:
#: With these five it was ready in two seconds. Dropping everything else is still most of the
#: default set — and the point is worth stating plainly: an earlier hand-run of this experiment
#: passed because it had no `--cap-drop` at all, so the hardening was added afterwards and never
#: re-measured. A container that starts is not a container that works.
_SERVER_CAPABILITIES = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID")

#: Docker's own commands answer quickly or are broken.
DOCKER_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class Service:
    """What one declarable service actually is. **Instance-owned, never the manifest's.**

    Structurally the same decision as `BASE_IMAGES` and `SYSTEM_PACKAGES`: the repository names an
    entry, this table says what the name means. `env` is the variables the *suite* is told, and they
    are named here rather than by the project — a manifest that could name them could overwrite
    `ANTHROPIC_BASE_URL`, or `PATH`.
    """

    image: str
    #: The port the server listens on inside its own container. Not published to the host: the only
    #: thing that has to reach it is on the same internal network.
    port: int
    #: What the server itself needs to start. `POSTGRES_PASSWORD` is mandatory for that image.
    server_env: dict[str, str] = field(default_factory=dict)
    #: What the suite is told, with `{host}` and `{port}` filled in. Several variables per service,
    #: because there is no single convention: a Python project reads `DATABASE_URL`, a Django one
    #: reads the `PG*` set, and guessing between them is how this arrives half-working.
    exports: dict[str, str] = field(default_factory=dict)
    #: The command that proves it is up, run in the service's own image on the same network. A probe
    #: in the *project's* image only works for projects whose language ships a client.
    probe: tuple[str, ...] = ()


#: Every service this build can provide. Adding an entry is three lines and an operator decision;
#: naming one this table does not have is refused at registration (`hullwork projects add`), the
#: same door item 048 put the engine check behind and for the same reason — the cheapest place to
#: find out is before an item ever reaches `ready`.
SERVICES: dict[str, Service] = {
    "postgres-16": Service(
        image="postgres:16",
        port=5432,
        server_env={"POSTGRES_PASSWORD": "hullwork", "POSTGRES_USER": "hullwork",
                    "POSTGRES_DB": "hullwork"},
        exports={
            "DATABASE_URL": "postgresql://hullwork:hullwork@{host}:{port}/hullwork",
            "POSTGRES_HOST": "{host}",
            "POSTGRES_PORT": "{port}",
            "POSTGRES_USER": "hullwork",
            "POSTGRES_PASSWORD": "hullwork",
            "POSTGRES_DB": "hullwork",
            "PGHOST": "{host}",
            "PGPORT": "{port}",
            "PGUSER": "hullwork",
            "PGPASSWORD": "hullwork",
            "PGDATABASE": "hullwork",
        },
        probe=("pg_isready", "-h", "{host}", "-U", "hullwork"),
    ),
    "postgres-15": Service(
        image="postgres:15",
        port=5432,
        server_env={"POSTGRES_PASSWORD": "hullwork", "POSTGRES_USER": "hullwork",
                    "POSTGRES_DB": "hullwork"},
        exports={
            "DATABASE_URL": "postgresql://hullwork:hullwork@{host}:{port}/hullwork",
            "POSTGRES_HOST": "{host}",
            "POSTGRES_PORT": "{port}",
            "POSTGRES_USER": "hullwork",
            "POSTGRES_PASSWORD": "hullwork",
            "POSTGRES_DB": "hullwork",
            "PGHOST": "{host}",
            "PGPORT": "{port}",
            "PGUSER": "hullwork",
            "PGPASSWORD": "hullwork",
            "PGDATABASE": "hullwork",
        },
        probe=("pg_isready", "-h", "{host}", "-U", "hullwork"),
    ),
    "redis-7": Service(
        image="redis:7",
        port=6379,
        exports={"REDIS_URL": "redis://{host}:{port}/0", "REDIS_HOST": "{host}",
                 "REDIS_PORT": "{port}"},
        probe=("redis-cli", "-h", "{host}", "ping"),
    ),
    "mysql-8": Service(
        image="mysql:8",
        port=3306,
        server_env={"MYSQL_ROOT_PASSWORD": "hullwork", "MYSQL_USER": "hullwork",
                    "MYSQL_PASSWORD": "hullwork", "MYSQL_DATABASE": "hullwork"},
        exports={
            "DATABASE_URL": "mysql://hullwork:hullwork@{host}:{port}/hullwork",
            "MYSQL_HOST": "{host}",
            "MYSQL_PORT": "{port}",
            "MYSQL_USER": "hullwork",
            "MYSQL_PASSWORD": "hullwork",
            "MYSQL_DATABASE": "hullwork",
        },
        probe=("mysqladmin", "ping", "-h", "{host}", "-uhullwork", "-phullwork"),
    ),
}


class ServiceError(SandboxError):
    """A service the attempt needs is not running.

    Raised before the phase that needed it. The caller turns this into an **abandoned** attempt: a
    database that would not start says nothing about whether the bug is reproducible, and must not
    cost the item its one try — which is the same rule item 043 wrote for a red baseline.
    """


def unknown(names: list[str]) -> list[str]:
    """Which of these this build cannot provide. For the refusal at registration.

    A function rather than a set difference at the call site, because the answer has to be the same
    in the parser's error message and in `projects add`, and two copies of a membership test are two
    chances to disagree about a name.
    """
    return [name for name in names if name not in SERVICES]


class Services:
    """The services for one phase, on their own network. A context manager; it tears down.

    **Per phase, not per attempt**, and that is the whole reason this is a context manager rather
    than a field on `Sandbox`. A `postgres` mutated by the baseline and then read by the green gate
    makes the red/green comparison a comparison of two different databases — so DR-0003's claim,
    which is the only thing this product asserts, would rest on conditions that changed underneath
    it. Two seconds per phase is what that costs.
    """

    def __init__(
        self,
        names: list[str],
        *,
        tag: str,
        docker: str = "docker",
    ) -> None:
        missing = unknown(names)
        if missing:
            # Should be unreachable: registration refuses these. Here anyway, because "should be
            # unreachable" is how a validator that moved gets discovered at attempt time.
            msg = (
                f"this build cannot provide {missing!r}; it was supposed to be refused at "
                f"registration"
            )
            raise ServiceError(msg)
        self._names = names
        self._docker = docker
        self.network = f"hullwork-services-{tag}"
        self._containers: list[str] = []
        self.env: dict[str, str] = {}

    def __enter__(self) -> "Services":
        if not self._names:
            # No services declared: no network, no containers, nothing to tear down. The phase runs
            # exactly as it did before this module existed.
            return self
        try:
            self._create_network()
            for name in self._names:
                self._start(name)
            for name in self._names:
                self._wait_for(name)
        except BaseException:
            # Half a set of services is worse than none: the suite would fail on the missing one and
            # the failure would be reported as the project's.
            self.close()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Remove every container, its databases and the network. Safe to call twice, never raises.

        **`-v`, and it is the whole of item 244.** `postgres:16` declares
        `VOLUME /var/lib/postgresql/data` in its own Dockerfile, so every `docker run` of it creates
        an anonymous volume — and a `docker rm` without `-v` leaves it behind. One per service, per
        phase, on every attempt and every verification: sixty-nine volumes and 3.2GB on the
        operator's own host, in a day, after the images had already been fixed.

        `-v` removes the container's **anonymous** volumes and leaves named ones alone, which is
        the distinction that matters: `hullwork-worktree-*` and `hullwork-envcache-*` have names
        and owners; this one has neither, and cannot be collected by the reaper for that reason —
        an anonymous volume is a hex string that says nothing about who made it, and removing those
        by pattern would delete everything else on the host (item 125).
        """
        for container in self._containers:
            _quietly(self._docker, ["rm", "-f", "-v", container])
        self._containers = []
        if self._names:
            _quietly(self._docker, ["network", "rm", self.network])
        self.env = {}

    # --- construction --------------------------------------------------------------------------

    def _create_network(self) -> None:
        created = run_docker(
            [self._docker, "network", "create", "--internal", *label_args(), self.network],
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
        if created.returncode != 0:
            msg = "could not create the network the services sit on"
            raise ServiceError(msg, created.stdout + created.stderr)

    def _start(self, name: str) -> None:
        """Start one service, reachable by its own name and by nothing outside the network."""
        service = SERVICES[name]
        host = self._hostname(name)
        argv = [
            self._docker, "run", "--detach",
            "--name", host,
            # The alias is what the suite connects to, and it is the declared name rather than the
            # container's: two attempts on one host must not collide, so the container carries the
            # attempt's tag and the alias does not.
            "--network", self.network,
            "--network-alias", name,
            # Everything dropped except the five an entrypoint needs to stop being root. See
            # `_SERVER_CAPABILITIES`: `--cap-drop ALL` alone kills `postgres:16` at startup.
            "--cap-drop", "ALL",
            *[flag for cap in _SERVER_CAPABILITIES for flag in ("--cap-add", cap)],
            "--security-opt", "no-new-privileges",
            # A test database is small and a runaway one must not take the host with it.
            "--memory", "1g", "--memory-swap", "1g",
            "--pids-limit", "256",
            # No port published to the host. Nothing outside this network has any business reaching
            # a service that exists for the length of one phase.
        ]
        for key, value in service.server_env.items():
            argv += ["--env", f"{key}={value}"]
        argv.append(service.image)

        started = run_docker(argv, timeout=DOCKER_TIMEOUT_SECONDS)
        if started.returncode != 0:
            msg = f"could not start the {name!r} the manifest declares"
            raise ServiceError(msg, started.stdout + started.stderr)
        self._containers.append(host)
        for key, template in service.exports.items():
            self.env[key] = template.format(host=name, port=service.port)

    def _wait_for(self, name: str) -> None:
        """Probe until it answers, and say what it said if it never does.

        Probed rather than slept on: a sleep long enough for a cold host is wasted on every warm
        one, and one long enough on average fails the attempt on the tail — which would be recorded
        as the project's suite failing rather than as the database not being up.
        """
        service = SERVICES[name]
        if not service.probe:  # pragma: no cover - every registry entry has one
            return
        probe = [part.format(host=name) for part in service.probe]
        deadline = time.monotonic() + READY_SECONDS
        last = ""
        while time.monotonic() < deadline:
            answered = run_docker(
                [
                    self._docker, "run", "--rm", "--network", self.network,
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    service.image, *probe,
                ],
                timeout=DOCKER_TIMEOUT_SECONDS,
            )
            if answered.returncode == 0:
                log.info("service ready", extra={"service": name, "network": self.network})
                return
            last = (answered.stdout + answered.stderr).strip()[-300:]
            time.sleep(1)
        msg = f"{name!r} did not become ready within {READY_SECONDS}s"
        raise ServiceError(msg, last)

    def _hostname(self, name: str) -> str:
        return f"{self.network}-{name}"


def _quietly(docker: str, argv: list[str]) -> None:
    """Best-effort teardown. Never raises: a failed cleanup must not mask the real error."""
    try:
        run_docker([docker, *argv], timeout=DOCKER_TIMEOUT_SECONDS)
    except SandboxError as exc:
        log.warning("could not tear down a service", extra={"argv": argv, "error": str(exc)})
