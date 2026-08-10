"""The network one attempt gets, and the one address it can reach.

Item 047. Spec M2 §4.4 settled the shape — an `internal: true` network, the gateway as the only
route out, and a self-test on every attempt "because a firewall nobody probes is a firewall nobody
has". What it also said, and what does not hold everywhere, is *how* the container reaches a gateway
that runs on the host.

**Measured on 2026-07-28, Docker 28.5.1 on Docker Desktop for Mac:**

| From a container on an `--internal` network | Result |
|---|---|
| `http://172.19.0.1:PORT` — the bridge gateway, said to be the host | **curl exit 7**, refused |
| `http://host.docker.internal:PORT` | **curl exit 28**, timeout |
| `https://api.anthropic.com` | exit 6, DNS does not resolve |
| `http://1.1.1.1` | exit 7, no route |

The isolation half is real on both platforms. The reachability half is a Linux property: there the
bridge is an interface *of the host*, so a host process bound to `172.x.0.1` is on the same segment
as the container. Under Docker Desktop the bridge lives inside the LinuxKit VM and the host is
somewhere else entirely, so the same design is airtight on the development machine and simply does
not work — the mirror image of the bind-mount finding in §4.2, and the same lesson.

So the gateway is reached through a **cable**: a container on both the internal network and an
ordinary bridge, forwarding one TCP port to the gateway on the host. One code path, exercised on
both platforms, rather than a Linux path nobody runs on a Mac and a Mac path nobody runs in
production.

What the cable is not:

* **Not a proxy.** It forwards one port to one address and speaks no protocol. Measured with it
  attached: the sandbox still cannot resolve DNS (exit 6) and still has no route to a bare IP
  (exit 7). It carries no credential — that stays in the gateway, on the host, per DR-0004.
* **Not a way in.** The gateway binds loopback only, which is a smaller host surface than binding
  the bridge address. Nothing outside this host can reach either end.

**What this does not fix**, said plainly because §4.4 asserted it as done: on Linux, a container on
an internal network can still reach any *other* host daemon bound to `0.0.0.0`, and the `iptables -I
INPUT -i br-… -j DROP` rule that closes it is not installed here. It cannot be verified on this
workstation, and a firewall rule written blind is the kind of control this project keeps having to
delete. It belongs in the deploy documentation as a host hardening step until somebody can run it on
Linux and read the effect.
"""

import logging
import os
import secrets
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING

from hullwork.sandbox.docker import SandboxError, run_docker
from hullwork.sandbox.inventory import label_args
from hullwork.sandbox.run import CARRIER_IMAGE

if TYPE_CHECKING:  # pragma: no cover - import cycle at runtime, not at type time
    from hullwork.gateway import Recording

log = logging.getLogger(__name__)

#: What the cable runs in. It is already in `image.BASE_IMAGES`, so nothing new is pulled for a
#: Python project. Fixed rather than derived from the manifest: the cable must work the same way for
#: a Node project, and the sandbox image for one has no Python in it.
CABLE_IMAGE = "python:3.12-slim"

#: The image the gateway runs from — Hullwork's own, because the gateway *is* Hullwork code and it
#: needs the package and its HTTP client. The dispatcher already requires a Docker daemon; requiring
#: that the image this installation built is present on it is not a new dependency, and a missing
#: one fails loudly at `docker run` rather than quietly.
GATEWAY_IMAGE = "hullwork:dev"


def gateway_image(configured: str | None) -> str:
    """The image the gateway runs from — **the instance's own, not a constant** (item 201).

    The constant above named the image *this installation built*, which stopped being true the day
    a deployment could pull a published one instead: there is no `hullwork:dev` on a host that never
    built, so the gateway — the component that observes and seals model traffic — could not start.
    That is item 191's failure, and it was already being worked around by a `docker tag` on every
    deploy, with a comment recording the day nobody ran it and the gateway was four days behind the
    dispatcher it serves.

    The default is unchanged on purpose. Every deployment written before this item names no image,
    and moving them to something they do not have would be this item causing the failure it exists
    to prevent.
    """
    return configured or GATEWAY_IMAGE

#: Where the credential and the journal live inside the gateway. One directory, one volume — see
#: `_seed_volume` for why it is a volume and not two bind mounts.
RUN_DIR = "/run/hullwork"

#: How long the gateway gets to bind before the attempt is abandoned. Generous: it is a Python
#: process starting, and the alternative to waiting is a race that reads as a network fault.
GATEWAY_START_SECONDS = 30

#: Where the cable listens, inside the internal network. Not published to the host.
CABLE_PORT = 8080

#: Docker's own commands answer quickly or are broken.
DOCKER_TIMEOUT_SECONDS = 120

#: How long to wait for the cable to be listening before calling it dead.
CABLE_READY_SECONDS = 20

#: The probe that must fail. A hostname, so it exercises DNS as well as routing — DNS exfiltration
#: is the path §4.4 closed by having no resolver at all, and a probe against a bare IP would not
#: notice if a resolver came back.
_BLOCKED_PROBE = "api.anthropic.com"


class EgressError(SandboxError):
    """The attempt's network is not what it must be, so nothing is run in it.

    Raised before the model is called. The caller turns this into an abandoned attempt: a
    misconfigured network says nothing about whether the bug is reproducible, and it must not cost
    the item its one try.
    """


class Cable:
    """One attempt's network, and the only path out of it. A context manager; it cleans up.

    Created and destroyed per attempt rather than shared, so two dispatchers on one host cannot
    end up talking through each other's gateway — which would put one project's prompt in another
    project's recording and make the provenance seal a lie.
    """

    def __init__(
        self,
        upstream: str,
        credential: str,
        *,
        work_dir: Path,
        pinned_model: str | None = None,
        #: The operator's two policies, item 137. Both default to today's behaviour: only the pinned
        #: model is acceptable, and nothing stops an attempt on cost.
        allowed_models: tuple[str, ...] = (),
        max_tokens: int | None = None,
        auth_style: str = "bearer",
        image: str = GATEWAY_IMAGE,
        docker: str = "docker",
        suffix: str | None = None,
    ) -> None:
        self._docker = docker
        self._upstream = upstream
        self._credential = credential
        self._pinned_model = pinned_model
        self._allowed_models = allowed_models
        self._max_tokens = max_tokens
        self._auth_style = auth_style
        self._image = image
        self._work_dir = work_dir
        # Random rather than derived from the item: a retry after a killed dispatcher must not
        # collide with the network the corpse left behind.
        tag = suffix or secrets.token_hex(4)
        self._tag = tag
        self.network = f"hullwork-attempt-{tag}"
        self.container = f"hullwork-cable-{tag}"
        self._address: str | None = None
        self._subnet: str | None = None
        self._journal: Path | None = None
        #: The named volume carrying the credential in and the journal out (item 089).
        self._cable_volume: str | None = None

    # --- lifecycle ---------------------------------------------------------------------------

    def __enter__(self) -> "Cable":
        try:
            self._create_network()
            self._start_gateway()
        except BaseException:
            # Half a network is worse than none: it would be reused, or leak, or be reported as
            # working. Anything that goes wrong here takes the whole thing down with it.
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
        """Remove the container and the network. Safe to call twice, and never raises.

        Teardown that can fail is teardown that leaves a network holding a route on somebody's
        host, so every error here is logged and swallowed.
        """
        # Before the container goes, because it goes with everything it said. A gateway that
        # refused a caller or could not reach upstream explains that in its own output and nowhere
        # else, and the first attempt that got this far had to be reproduced by hand to find out.
        try:
            said = run_docker(
                [self._docker, "logs", "--tail", "40", self.container],
                timeout=DOCKER_TIMEOUT_SECONDS,
            )
        except SandboxError as exc:  # docker missing, or not answering
            # Reading the output is the one part of teardown that is only ever nice to have, and
            # raising here would abandon every removal below it and overwrite the real failure.
            log.warning(
                "could not read what the gateway said",
                extra={"container": self.container, "error": str(exc)},
            )
        else:
            transcript = (said.stdout + said.stderr).strip()
            if transcript:
                log.info("gateway said", extra={"container": self.container, "output": transcript})

        # Last chance at the journal: after the volume goes it is gone, and an attempt that died
        # before anything asked for its seal is exactly the one worth reading afterwards.
        self._pull_journal()
        _quietly(self._docker, ["rm", "-f", self.container])
        _quietly(self._docker, ["network", "rm", self.network])
        if self._cable_volume:
            _quietly(self._docker, ["volume", "rm", "-f", self._cable_volume])
            self._cable_volume = None
        self._address = None

    # --- what the sandbox is told ------------------------------------------------------------

    @property
    def address(self) -> str:
        """The cable's address on the internal network."""
        if self._address is None:
            msg = "the cable is not up"
            raise EgressError(msg)
        return self._address

    @property
    def url(self) -> str:
        """What goes into `ANTHROPIC_BASE_URL` and friends inside the sandbox."""
        return f"http://{self.address}:{CABLE_PORT}"

    def recording(self, endpoint: str, *, pinned_model: str | None = None) -> "Recording":
        """The recording the gateway wrote, replayed. Item 054.

        It used to be an attribute of an object in this process. The gateway is a container now, so
        what comes back is the journal it appended to — which is the point: a container killed
        mid-attempt is exactly the case where the seal explains why, and a file survives that.

        An unreadable line is logged rather than swallowed. A seal is evidence, and evidence that
        quietly describes less than what happened is worse than none.
        """
        from hullwork.gateway.journal import read

        if self._journal is None:
            msg = "the cable is not up"
            raise EgressError(msg)
        # The gateway appends inside the volume, so the host copy is stale until it is fetched
        # (item 089). Every caller of `recording` goes through here, which is why the pull lives
        # here and not at each call site.
        self._pull_journal()
        replayed = read(self._journal, endpoint=endpoint, pinned_model=pinned_model)
        if replayed.unreadable:
            log.error(
                "the gateway journal has unreadable lines, so the seal describes less than what "
                "happened",
                extra={"unreadable": replayed.unreadable, "journal": str(self._journal)},
            )
        return replayed.recording

    # --- the part that is not taken on trust -------------------------------------------------

    def self_test(self) -> None:
        """Prove the network is what it claims, from inside it, before the model is called.

        Two probes, because one proves nothing: the allowed address must answer and a blocked one
        must not. §4.4 stole this from Anthropic's own devcontainer, which fails its run unless
        both hold — the one idea in that design worth keeping after its firewall was rejected.

        Run in the cable's image rather than the project's, deliberately. This is a property of the
        network, the network is identical for both containers, and the project's image may have no
        HTTP client in it at all — a self-test that only works for Python projects is a self-test
        that gets skipped for the others.
        """
        allowed = self._probe(
            f"import urllib.request;"
            f"urllib.request.urlopen('{self.url}/__hullwork__/probe', timeout=8).status"
        )
        if allowed.returncode != 0:
            msg = (
                f"the sandbox cannot reach the gateway at {self.url}, so the agent would have no "
                f"model and no way to say so: {allowed.stdout.strip()[-400:]}"
            )
            raise EgressError(msg)

        blocked = self._probe(
            f"import socket;socket.create_connection(('{_BLOCKED_PROBE}', 443), timeout=8)"
        )
        if blocked.returncode == 0:
            # Refusing to run is the only safe answer. A sandbox with a route out is a sandbox
            # that can post the watched project's source anywhere, and it would look like it
            # worked.
            msg = (
                f"the sandbox reached {_BLOCKED_PROBE} — the network is not isolated, so this "
                f"attempt will not run in it"
            )
            raise EgressError(msg)
        log.info(
            "egress self-test passed",
            extra={"network": self.network, "gateway": self.url},
        )

    def _probe(self, program: str) -> "subprocess.CompletedProcess[str]":
        return run_docker(
            [
                self._docker, "run", "--rm",
                "--network", self.network,
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                CABLE_IMAGE, "python", "-c", program,
            ],
            timeout=DOCKER_TIMEOUT_SECONDS,
        )

    # --- construction ------------------------------------------------------------------------

    def _create_network(self) -> None:
        created = run_docker(
            [self._docker, "network", "create", "--internal", *label_args(), self.network],
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
        if created.returncode != 0:
            msg = "could not create the attempt's network"
            raise EgressError(msg, created.stdout + created.stderr)

        # Read as soon as the network exists, because the gateway is told it at `docker run` time
        # and the sandbox does not exist yet. The sandbox's address cannot be named in advance; the
        # network it will be on can — and that is not a widening, because this network is created
        # for one attempt, destroyed with it, and holds exactly two containers we put there.
        found = run_docker(
            [
                self._docker, "network", "inspect", self.network,
                "--format", "{{(index .IPAM.Config 0).Subnet}}",
            ],
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
        self._subnet = found.stdout.strip() or None
        if not self._subnet:
            msg = "the attempt's network has no subnet, so the gateway cannot be told who to trust"
            raise EgressError(msg, found.stdout + found.stderr)

    def _start_gateway(self) -> None:
        """Start the gateway on the bridge, then attach it to the internal network.

        Two steps because `docker run` takes one `--network`, and the order matters: started on the
        bridge it can reach the model endpoint; attached afterwards it becomes reachable by the
        sandbox. The other way round gives a gateway that can be reached and cannot forward.

        **This used to be a forwarder to a gateway on the host, and that is what item 054 changed.**
        A container on an `--internal` network cannot reach a listener on the host — measured on a
        Linux box with a default-deny firewall, which is most of them — and the answer was never to
        ask every self-hoster to open a port to the Docker bridge. Docker already expresses the
        property; the firewall was being asked to permit a hop the design did not need to make.
        """
        credential_file = self._work_dir / "credential"
        credential_file.write_text(self._credential, encoding="utf-8")
        credential_file.chmod(0o600)
        journal = self._work_dir / "journal.jsonl"
        journal.touch()
        journal.chmod(0o600)
        # These two are written to the host and then **copied into a volume**, not bind mounted from
        # here (item 089): a bind mount is resolved by the daemon, so a containerised dispatcher
        # it would find nothing at these paths. See `_seed_volume` for what that costs.
        self._cable_volume = f"hullwork-wire-{self._tag}"
        self._seed_volume(credential_file, journal)

        started = run_docker(
            [
                self._docker, "run", "--detach",
                "--name", self.container,
                # Whose it is, so a second instance's reaper leaves it standing (item 125).
                *label_args(),
                # **The image's healthcheck is the receiver's, and wrong here** (item 087). It
                # probes `127.0.0.1:8000/ready`; this container serves a forwarder on another port
                # and no such route, so it sat `unhealthy` with a 28-failure streak while answering
                # the model with a clean 200 every few seconds. An `unhealthy` that only means "this
                # is a different program" says nothing the day the gateway really breaks — the same
                # argument as `/health` cannot fail, from the other end.
                "--no-healthcheck",
                "--network", "bridge",
                # As the dispatcher's own uid, so the mode-600 credential file below is readable by
                # exactly one identity and needs no `chown` — which a non-root dispatcher could not
                # do anyway. The image runs non-root by default and this keeps it that way; found
                # by running it, as `PermissionError` on the first container start.
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--memory", "256m", "--memory-swap", "256m",
                "--pids-limit", "128",
                # The credential as a **file**, never an argument and never an environment
                # variable: an argument is in `ps`, and an environment variable is in
                # `docker inspect`.
                # One volume for both. `:ro` is gone from the credential and the mode is what keeps
                # it narrow — 600, owned by the one identity that runs this container — because a
                # read-only mount would also stop the gateway appending to the journal beside it.
                "--volume", f"{self._cable_volume}:/run/hullwork",
                # Past the image's own entrypoint, which runs `alembic upgrade head` before what it
                # was asked for. The gateway has no business touching a database, and the migration
                # chain took long enough that the self-test probed a port nothing had bound yet —
                # which read as "the sandbox cannot reach the gateway". Found by running it.
                "--entrypoint", "hullwork",
                self._image,
                "gateway",
                "--upstream", self._upstream,
                "--credential-file", "/run/hullwork/credential",
                "--journal", "/run/hullwork/journal.jsonl",
                "--port", str(CABLE_PORT),
                "--auth-style", self._auth_style,
                "--allow-network", self._subnet or "",
                *(["--model", self._pinned_model] if self._pinned_model else []),
                *(arg for model in self._allowed_models for arg in ("--allow-model", model)),
                *(["--max-tokens", str(self._max_tokens)] if self._max_tokens else []),
            ],
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
        if started.returncode != 0:
            msg = "could not start the gateway"
            raise EgressError(msg, started.stdout + started.stderr)
        self._journal = journal

        attached = run_docker(
            [self._docker, "network", "connect", self.network, self.container],
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
        if attached.returncode != 0:
            msg = "could not attach the gateway to the attempt's network"
            raise EgressError(msg, attached.stdout + attached.stderr)

        address = run_docker(
            [
                self._docker, "inspect", self.container, "--format",
                f'{{{{(index .NetworkSettings.Networks "{self.network}").IPAddress}}}}',
            ],
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
        self._address = address.stdout.strip() or None
        if not self._address:
            msg = "the gateway has no address on the attempt's network"
            raise EgressError(msg, address.stdout + address.stderr)

        self._wait_until_listening()
        log.info(
            "gateway up",
            extra={"network": self.network, "address": self._address, "subnet": self._subnet},
        )

    # --- the credential in and the journal out (item 089) ---------------------------------------

    def _seed_volume(self, credential_file: Path, journal: Path) -> None:
        """Create the volume and copy both files into it, owned by whoever runs the gateway.

        `docker cp` streams a tar to the daemon; a bind mount asks the daemon to resolve a path.
        That is the whole difference, and it is why the two files these replace worked from a
        dispatcher on the host and could not work from one in a container: the daemon would look for
        `/data/attempts/…/credential` in its own filesystem, find nothing, and mount a fresh empty
        directory over it. The gateway would then read an empty credential — every phase a 401 — and
        append its journal where nothing reads it, publishing a seal that says the model was never
        reached on a run where it answered.

        Owned by this process's uid because that is what `--user` gives the gateway; a volume seeded
        through the socket arrives owned by root, and root's 600 file is unreadable to anyone else.
        """
        created = run_docker(
            [self._docker, "volume", "create", *label_args(), self._cable_volume or ""],
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
        if created.returncode != 0:
            msg = "could not create the cable's volume"
            raise EgressError(msg, created.stdout + created.stderr)
        with self._carrier() as carrier:
            for source in (credential_file, journal):
                copied = run_docker(
                    [self._docker, "cp", str(source), f"{carrier}:{RUN_DIR}/{source.name}"],
                    timeout=DOCKER_TIMEOUT_SECONDS,
                )
                if copied.returncode != 0:
                    msg = "could not seed the cable's volume"
                    raise EgressError(msg, copied.stdout + copied.stderr)
        owned = run_docker(
            [
                self._docker, "run", "--rm", "--user", "0:0",
                "--volume", f"{self._cable_volume}:{RUN_DIR}",
                CARRIER_IMAGE, "chown", "-R", f"{os.getuid()}:{os.getgid()}", RUN_DIR,
            ],
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
        if owned.returncode != 0:
            msg = "could not give the cable's volume to the user the gateway runs as"
            raise EgressError(msg, owned.stdout + owned.stderr)

    def _pull_journal(self) -> None:
        """Volume → the host path `recording` reads. Logged and swallowed, never raised.

        A journal that could not be fetched is an attempt with no seal, which the caller already
        handles as a recording with no completions in it. Raising here would turn a run that
        finished into an abandoned attempt, and the run is the expensive part.

        **The docstring above said this before it was true** (item 095). `_carrier` raises
        `EgressError` when `docker create` fails, and `_docker` raises `SandboxError` when the
        client is missing — so from `close`, where this is called first, a daemon that had gone
        away aborted teardown before `rm -f`, `network rm` and `volume rm -f`, leaking a network, a
        container, and a volume holding a copy of the model credential.

        Reported by the agent in the attempt that fixed the same defect one line up
        (`easybyte/hullwork!10`), as a follow-up it deliberately did not take because its own test
        could not reach this branch. It was right on both counts.
        """
        if self._journal is None or self._cable_volume is None:
            return
        try:
            with self._carrier() as carrier:
                copied = run_docker(
                    [
                        self._docker, "cp",
                        f"{carrier}:{RUN_DIR}/{self._journal.name}", str(self._journal),
                    ],
                    timeout=DOCKER_TIMEOUT_SECONDS,
                )
        except SandboxError as exc:
            # Same shape as the `logs` read in `close`: informational, so a failure here is logged
            # and the removals below it proceed. `EgressError` is a `SandboxError`, so one except
            # covers the carrier and the copy both.
            log.warning(
                "could not fetch the gateway journal, so the seal will describe nothing",
                extra={"volume": self._cable_volume, "error": str(exc)},
            )
            return
        if copied.returncode != 0:
            log.error(
                "could not read the gateway journal back, so the seal will describe nothing",
                extra={"volume": self._cable_volume},
            )

    @contextmanager
    def _carrier(self) -> Iterator[str]:
        """A stopped container mounting the volume, for `docker cp` to target."""
        created = run_docker(
            [
                self._docker, "create", "--volume", f"{self._cable_volume}:{RUN_DIR}",
                CARRIER_IMAGE, "true",
            ],
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
        if created.returncode != 0:
            msg = "could not create the cable volume's carrier"
            raise EgressError(msg, created.stdout + created.stderr)
        carrier = created.stdout.strip()
        try:
            yield carrier
        finally:
            _quietly(self._docker, ["rm", "-f", carrier])

    def _wait_until_listening(self) -> None:
        """Wait for the gateway to say it has bound, or say what it said instead.

        A container that has been started has not necessarily bound, and the self-test that follows
        probes once. Without this the race reads as "the sandbox cannot reach the gateway", which
        sends whoever is debugging it to the network rather than to the clock.
        """
        deadline = time.monotonic() + GATEWAY_START_SECONDS
        while time.monotonic() < deadline:
            logs = run_docker(
                [self._docker, "logs", self.container], timeout=DOCKER_TIMEOUT_SECONDS
            )
            if "gateway listening" in (logs.stdout + logs.stderr):
                return
            state = run_docker(
                [self._docker, "inspect", "-f", "{{.State.Status}}", self.container],
                timeout=DOCKER_TIMEOUT_SECONDS,
            )
            if state.stdout.strip() not in {"running", "created"}:
                msg = "the gateway stopped before it was listening"
                raise EgressError(msg, (logs.stdout + logs.stderr)[-800:])
            time.sleep(0.5)
        msg = f"the gateway did not bind within {GATEWAY_START_SECONDS}s"
        raise EgressError(msg)


def _quietly(docker: str, argv: list[str]) -> None:
    """Best-effort teardown. Never raises: a failed cleanup must not mask the real error."""
    try:
        run_docker([docker, *argv], timeout=DOCKER_TIMEOUT_SECONDS)
    except SandboxError as exc:  # docker missing, or not answering
        log.warning("could not tear down", extra={"argv": argv, "error": str(exc)})


def why_the_gateway_cannot_start(*, docker: str = "docker") -> str | None:
    """The sentence that refuses an agent run before anything is paid for, or `None`. Item 191.

    **Shaped after `image.why_it_cannot_host_a_phase`, and here for the same reason it exists
    there**: two doors needed a refusal and only the expensive one had it. Every agent path starts a
    gateway — `work`, `try` and `deps --fix` — so a missing image is a fact about the instance and
    not about the command that happened to notice.

    Measured on 2026-08-09, running `deps --fix` against a real model for the first time. It died
    with `could not start the gateway / Unable to find image 'hullwork:dev' locally` **after** OSV,
    four image builds and two suite runs. Item 048's finding and item 184's, a third time: the
    refusal existed and happened in the most expensive place available.

    **A daemon that cannot be reached is a different answer**, and answering it here would be
    guessing at somebody else's problem: `doctor` owns that question and says it properly. This one
    answers only *is the image there*, and says nothing at all when the client is absent.
    """
    import shutil
    import subprocess

    if shutil.which(docker) is None:
        # Not this function's question. `doctor` reports a missing or unreachable daemon, with the
        # three things it can mean; a second opinion here would be a worse copy of it.
        return None

    found = subprocess.run(  # noqa: S603
        [docker, "image", "inspect", GATEWAY_IMAGE],
        capture_output=True,
        timeout=DOCKER_TIMEOUT_SECONDS,
        check=False,
    )
    if found.returncode == 0:
        return None
    return (
        f"the gateway image `{GATEWAY_IMAGE}` is not on this Docker daemon, and every agent run "
        f"needs one.\n"
        f"  The gateway is where your model credential lives, so that the sandbox running the "
        f"project's own code never holds it (DR-0004). It runs Hullwork's own image because it is "
        f"Hullwork's own code.\n"
        f"  Build it from a checkout:  docker build --tag {GATEWAY_IMAGE} .\n"
        f"  `docker compose build` does **not** make it: the compose file pins a published image "
        f"and has no build stage."
    )
