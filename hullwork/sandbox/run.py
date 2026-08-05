"""Running one thing inside the sandbox, and getting the work back out.

Item 023, and the reason it is a supervised session rather than a work item: this is where the
authorisation boundary item 017 drew becomes a running process. The container executes the watched
project's own code and test command — arbitrary execution inside is by design — so the container
has to actually be a boundary.

Four things that are decided here and are easy to get wrong later:

* **`subprocess.run(timeout=)` does not kill a container.** It kills the CLI client; the container
  keeps going. Measured. So the container runs detached, is polled, and is killed by us.
* **The only way out is `(path, bytes)`** (item 040). `git apply` on the host is forbidden — it is
  a host git process eating attacker-authored content, which is what §4.1 exists to prevent, and
  git is not a parser whatever the flags say.
* **Egress is the gateway or nothing.** An internal network with no default route, so a harness
  that ignores its configuration reaches nothing and fails loudly.
* **No forge credential, no model credential, no Docker socket.** The first two would be readable
  by the project's own test suite; the third is root on the host.
"""

import hashlib
import json
import logging
import re
import secrets
import shutil
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from hullwork.sandbox.inventory import label_args

log = logging.getLogger(__name__)

#: Where the worktree lives inside. Matches the image's WORKDIR.
WORKDIR = "/work"

#: Where a built image keeps the installed environment. Mirrors `image.ENV_DIR`, which imports
#: from this module — so the constant lives here and that one refers to it.
ENV_DIR = "/opt/hullwork-env"

#: The home the sandbox user was created with (`useradd --create-home --uid 10001 hullwork`). It has
#: to be writable — pip, uv, pytest and every agent harness put caches there — and with a read-only
#: root filesystem the only way to keep it writable is a tmpfs. Spec M2 §4.
SANDBOX_HOME = "/home/hullwork"

#: Who the phases run as, from the image's own `useradd --create-home --uid 10001 hullwork`. Named
#: rather than repeated because `TMPFS_MOUNTS` has to agree with it — a home owned by anyone else is
#: a home the agent cannot write to (item 094).
SANDBOX_UID = 10001
SANDBOX_GID = 10001

#: Writable paths under a read-only root, each its own tmpfs. Nothing here survives the phase, which
#: is the point: a cache outliving one phase would let the fix phase see what reproduce left, and
#: the red-green comparison is only honest if each run starts where the last one did.
#:
#: **`noexec` was here and item 092 took it out.** It broke the baseline of the watched project: 24
#: of Hullwork's own tests write a fake executable into `tmp_path` and run it, which is how any
#: project that tests a CLI is written. A red baseline stops every attempt at step 0 (item 043), so
#: for as long as this held, Hullwork could fix no bug in itself — the loop was closed by a control
#: added to protect it. Measured on the live instance: *24 failed, 875 passed* on an untouched
#: checkout.
#:
#: It was also buying nothing. The worktree is a writable volume by design — the agent edits code
#: there and the gates run it — so anything that can write a file can already execute one. `noexec`
#: on `/tmp` blocked one route to something granted by another.
#:
#: `nosuid` and `nodev` stay: they cost nothing, break nothing, and close things the worktree does
#: not offer. `size=` stays because an unbounded tmpfs is the host's memory.
#: **`exec` is stated, and it has to be.** Docker mounts `--tmpfs` with `noexec` *by default*, so
#: removing the option from this string left the real mount `noexec` anyway — measured inside the
#: sandbox after the first fix: `/proc/mounts` said `rw,nosuid,nodev,noexec`, `os.access(X_OK)` said
#: False, and the baseline stayed red on the same 24 tests. The absence of an option is not its
#: opposite.
#: **The home carries `uid`/`gid`/`mode`, and item 094 is why.** A `--tmpfs` is mounted with the
#: options Docker chooses, not with the container's `--user`: measured inside the sandbox,
#: `/home/hullwork` came up `drwx------ 0 0` while the phase ran as 10001, so the agent could not
#: create a single file in its own `$HOME`. Its config directory lives there, and the failure it
#: produced was `EACCES: permission denied, mkdir '/home/hullwork/.claude/session-env/…'` — on every
#: `Bash` invocation, in both agent phases of the first attempt to reach a pull request. The agent
#: wrote a reproducing test and a fix **by reading source**, said so, and asked for the gates to be
#: run. It was right; that is luck standing in for a loop.
#:
#: `/tmp` needs none of this: Docker gives a tmpfs there the sticky 1777 that path conventionally
#: has, which is why the defect did not show up there and why this took a real attempt to find.
#:
#: `mode=700` because a home is private, and this one holds whatever the agent's tooling caches.
TMPFS_MOUNTS = (
    ("/tmp", "rw,exec,nosuid,nodev,size=1g"),  # noqa: S108 - inside a container, not the host
    (SANDBOX_HOME, f"rw,exec,nosuid,nodev,size=1g,uid={SANDBOX_UID},gid={SANDBOX_GID},mode=700"),
)

#: Ceilings a runaway process hits before the host notices. `nofile` is the one that matters in
#: practice — a test that leaks descriptors takes the daemon's own limits with it otherwise — and
#: `nproc` backs up `--pids-limit` at the kernel's own level rather than only at the cgroup's.
ULIMITS = (("nofile", "4096:8192"), ("nproc", "2048:4096"))

#: How long the preflight gets. Generous for one `sh -c` — it is a container starting, and the
#: alternative to waiting is a timeout that reads as a broken sandbox.
PREFLIGHT_TIMEOUT_SECONDS = 120

#: Where the engine contract's own files live — the brief in, the report out. **A separate mount,
#: outside the worktree, and that is the whole point.**
#:
#: The first version put them in the worktree because that was the only mount, and the reproduce
#: phase promptly refused the attempt: `hullwork-report.json` is a new file outside the declared
#: test path, so our own scaffolding looked exactly like the agent overstepping. Same shape as the
#: `.pytest_cache` bug and worse, because this time we created the file.
CONTRACT_DIR = "/hullwork"

#: The repository's own git directory. Nothing in here ever crosses back: a hook written there
#: executes on the host the next time any git command touches the tree, which is the vector §4.1
#: exists to close.
#:
#: Matched as a path component, not as a string prefix. The first version of this was
#: `startswith(".git")` and it silently swallowed `.gitignore` and `.github/` too — a fix that
#: needed a line in `.gitignore` would have lost it without a word, which is precisely the class
#: of failure this project keeps finding. Found by writing a file called `.git_fake` and noticing
#: it never came back.
GIT_DIR = ".git"

#: Refused **on purpose**, which is a different thing from the accident above. A workflow file is
#: code that runs on the forge's runner with the repository's secrets — outside the sandbox, with
#: privileges the agent does not have and must not be able to grant itself. Changing CI is already
#: an amber decision for a human in the worker contract; here it is simply not on the table.
FORBIDDEN_DIRS = frozenset({GIT_DIR, ".github", ".forgejo", ".gitea"})

#: Things a toolchain writes by itself, which are **not** the agent's work and must never be
#: mistaken for it.
#:
#: Found by running the real thing: `pytest` creates `.pytest_cache/.gitignore` during the baseline
#: run, so the reproduce phase — which accepts only new files under the declared test path — saw a
#: new file outside it and refused the whole attempt. That would have happened on **every real
#: project**, and no amount of unit testing would have shown it, because a fake sandbox does not
#: write caches.
TOOL_ARTEFACTS = frozenset(
    {
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox",
        ".coverage", "htmlcov", ".hypothesis", "node_modules", ".venv", "venv",
        "dist", "build", ".next", ".turbo", ".cache", ".eggs",
    }
)

#: Suffixes with the same problem and no directory to hide in.
TOOL_ARTEFACT_SUFFIXES = (".pyc", ".pyo", ".orig", ".rej", ".coverage")

#: A single file bigger than this is not a source change.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: More changed files than this is not a bug fix, it is something having gone wrong.
MAX_CHANGED_FILES = 200

#: What carries files in and out of the volume and does the chown. Tiny, and never the project's own
#: image: this runs as root and must be something the instance chose.
CARRIER_IMAGE = "alpine:3"


class SandboxError(RuntimeError):
    """The sandbox could not do what was asked. Carries output where there is any — and *shows* it.

    **`__str__` was the message alone until 2026-08-04**, which meant every raise site that bothered
    to capture `stdout + stderr` threw it away at the only moment anybody reads an exception.
    Measured on a stranger evaluating the product: `could not create the attempt's network` cost
    ten minutes and a wrong conclusion, because Docker had said `network with name … already
    exists` and nothing printed it. A message that hides its cause reads as *your Docker is broken*.

    The tail rather than the whole, at the 25-line convention `cli.py` already uses for this: the
    cause of a failed `docker` call is at the end, and a build's output is long enough to bury it.
    """

    def __init__(self, message: str, output: str = "") -> None:
        super().__init__(message)
        self.output = output

    def __str__(self) -> str:
        message = super().__str__()
        tail = "\n".join(self.output.strip().splitlines()[-25:])
        return f"{message}\n{tail}" if tail else message


class UnsafePathError(SandboxError):
    """A file the sandbox produced may not be written to the host."""


@dataclass
class RunResult:
    """What one command inside the container did."""

    command: str
    exit_code: int
    output: str
    duration_ms: int
    timed_out: bool = False
    out_of_memory: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@dataclass
class Sandbox:
    """A container built for one attempt, and destroyed with it."""

    image: str
    #: The host copy. Still the working set every guard in `dispatch` reads and writes — the volume
    #: below is what the container sees, and the two are synchronised around each phase.
    worktree: Path
    #: Host directory mounted at `CONTRACT_DIR`. The brief goes in, the report comes out, and
    #: neither is ever mistaken for the agent's work on the repository.
    contract_dir: Path | None = None
    #: The gateway's address, injected as every harness's base URL. Nothing else is reachable.
    gateway_url: str | None = None
    network: str | None = None
    #: The services the manifest declared, as a list of names. Started per phase rather than per
    #: attempt (item 052): a database mutated by the baseline and then read by the green gate makes
    #: the red/green comparison a comparison of two different databases.
    services: list[str] = field(default_factory=list)
    #: The volume holding the harness bundle, mounted read-only into the agent's phases only
    #: (item 065). `None` when the engine bakes itself into the image instead.
    #:
    #: Only the agent's phases, for the same reason they are the only ones that get the gateway
    #: (item 058): the watched project's test command has no business seeing Hullwork's own
    #: software, and a phase that found it somewhere unexpected would report it as the agent's work.
    harness_bundle: str | None = None
    memory: str = "4g"
    pids_limit: int = 512
    cpus: str = "2"
    docker: str = "docker"
    #: The named volume carrying the contract directory (item 082). Set by `ensure_contract`.
    #:
    #: **The last bind mount of a host path, and the one that kept the dispatcher on the host.** A
    #: bind mount is resolved by the *daemon*, so a path that exists only inside the dispatcher's
    #: own
    #: filesystem yields an empty directory and exit 0 — the failure the deployment notes record as
    #: the reason a containerised dispatcher could not work. Item 055 had already moved the worktree
    #: to a volume seeded over the socket; this is the same recipe for the other direction of
    #: traffic.
    #:
    #: `contract_dir` stays as the host-side mirror, synchronised around each phase exactly as the
    #: worktree is, so every reader in `dispatch` — which reads the brief and the report as files —
    #: is untouched.
    contract_volume: str | None = field(default=None, repr=False)

    #: The named volume the phases actually run on (item 055). Set by `ensure_volume`.
    #:
    #: **Not a bind mount, and spec M2 §4.2 called that disqualifying before it was measured.** The
    #: worktree belongs to whoever runs the dispatcher; the container runs as uid 10001 because it
    #: must not run as root. On Linux those uids are real and the container cannot write to its own
    #: working directory — measured, `could not create cache path /work/.pytest_cache`. On macOS
    #: Docker remaps every uid and the identical recipe appears to work, which is how this survived
    #: a demonstration and a deploy.
    volume: str | None = field(default=None, repr=False)
    _container: str | None = field(default=None, repr=False)
    _uid: int = field(default=SANDBOX_UID, repr=False)
    _gid: int = field(default=SANDBOX_GID, repr=False)

    def _argv(
        self,
        command: str,
        env: dict[str, str] | None,
        *,
        model: bool = False,
        service_network: str | None = None,
    ) -> list[str]:
        """The whole `docker run` argument list. **This is the security surface**, so it is one
        function a test can read without a Docker daemon anywhere near it.

        `model` is the whole of item 058. `network` and `gateway_url` are attempt-wide *values* and
        used to be read on every call — so the four gate phases, which run the watched project's own
        untrusted test command, each got the internal network and three environment variables
        pointing at a gateway that injects the operator's credential. The comment below claimed
        otherwise and nothing enforced it. Now the safe shape is the default and reaching a model
        has to be asked for by name, so a caller who forgets gets a phase with no route out.
        """
        argv = [
            self.docker, "run", "--detach",
            "--workdir", WORKDIR,
            "--volume",
            f"{self.volume}:{WORKDIR}" if self.volume else f"{self.worktree}:{WORKDIR}",
            # **The installed environment, writable** (item 112). The root filesystem is read-only
            # by design, and three toolchains write into their own cache while the tests run:
            # Maven resolves into `m2`, Mix compiles into its build path, Bundler writes a lock.
            # Measured on `google/gson`: `FileSystemException: /opt/hullwork-env/m2/… Read-only
            # file system`, with every dependency it needed already sitting in that directory.
            #
            # A **named** volume, keyed by the image, because Docker initialises a fresh one from
            # the image's own content at that path — so the phase gets everything the build put
            # there and may write beside it. Named rather than anonymous so it is a cache with an
            # owner rather than debris: same argument as `hullwork-harness-*`, and the reaper
            # leaves both alone for the same reason.
            "--volume", f"{self._env_cache()}:{ENV_DIR}",
            "--memory", self.memory,
            # Without this the memory limit means nothing: the container simply swaps.
            "--memory-swap", self.memory,
            "--pids-limit", str(self.pids_limit),
            "--cpus", self.cpus,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            # **The image is read-only, and everything writable is named below.** Spec M2 §4 asked
            # for this and it was absent. What it buys is narrow and real: a test command cannot
            # leave anything behind in the image's own filesystem, so what the next phase runs is
            # what the build produced rather than what the last phase did to it — which is the same
            # property `_restore_infrastructure` protects one layer up, enforced by the kernel
            # instead of by a diff.
            "--read-only",
            # Reaps the zombies a test runner leaves behind.
            "--init",
        ]
        for path, options in TMPFS_MOUNTS:
            argv += ["--tmpfs", f"{path}:{options}"]
        for name, limit in ULIMITS:
            argv += ["--ulimit", f"{name}={limit}"]
        if self.contract_volume:
            # A named volume, so the daemon needs no path from this process's filesystem (item 082).
            argv += ["--volume", f"{self.contract_volume}:{CONTRACT_DIR}"]
        elif self.contract_dir is not None:
            # The bind-mount path, kept for a dispatcher running on the host and for the rehearsal,
            # where there is no reason to spend a volume. It cannot work from inside a container.
            argv += ["--volume", f"{self.contract_dir}:{CONTRACT_DIR}"]
        if model and self.harness_bundle:
            # Read-only: the bundle is shared by every attempt on this instance, so a phase that
            # could write to it could change what the next attempt runs.
            from hullwork.sandbox.harness import BUNDLE_DIR

            argv += ["--volume", f"{self.harness_bundle}:{BUNDLE_DIR}:ro"]
        # A phase that needs the model gets the internal network with the gateway on it, and
        # **nothing else ever does** — enforced here rather than asserted in a comment (item 058).
        #
        # Two `--network` flags are legal and measured (item 052), which is what lets an agent phase
        # have the gateway *and* the project's services. `--network none` cannot be joined
        # afterwards, so every network this container will ever be on is named right here.
        networks = [name for name in (self.network if model else None, service_network) if name]
        if networks:
            for name in networks:
                argv += ["--network", name]
        else:
            # No network at all is the safe default, and it is what a gate phase with no declared
            # services gets.
            argv += ["--network", "none"]
        for name, value in (env or {}).items():
            argv += ["--env", f"{name}={value}"]
        if model and self.gateway_url:
            for variable in ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE"):
                argv += ["--env", f"{variable}={self.gateway_url}"]
        argv += [self.image, "sh", "-lc", command]
        return argv

    def self_test(self) -> None:
        """Prove the phase environment works, before a phase depends on it. Item 094.

        **What this exists for, in the words of the agent it happened to.** The first attempt to
        reach a pull request ran both of its agent phases with a broken shell:

            EACCES: permission denied, mkdir '/home/hullwork/.claude/session-env/6f14460d-…'

        Every `Bash` invocation failed before running anything, so the agent wrote a reproducing
        test and a fix by reading source, hand-checked them against the project's lint rules, and
        asked for the gates to be run. The gates then passed. **That artefact was correct by
        luck**: the loop's whole claim is that a test failed and now passes, and the phase that
        wrote the test never saw it fail.

        Three properties, each measured by doing it rather than by inspecting an argument list —
        which is the lesson of item 092, where a mount option was asserted in argv and applied
        differently by the daemon:

        * the home is writable, because the agent's configuration lives there;
        * a file written into a writable path can be executed, because a suite that tests a CLI
          writes fixtures and runs them;
        * the root filesystem is not writable, because that is a control this depends on rather than
          a preference.

        Raises `SandboxError`, and the caller turns it into an abandoned attempt: a sandbox that
        cannot host a phase says nothing about whether the bug is reproducible, and it must not
        cost the item its one try. Loud, and before the model is called — the two things the run
        above was not.
        """
        probe = (
            f'mkdir -p "$HOME/.hullwork-probe" && printf \'#!/bin/sh\\necho ran\\n\' '
            f'> {SANDBOX_HOME}/.hullwork-probe/x && chmod 755 {SANDBOX_HOME}/.hullwork-probe/x && '
            f'{SANDBOX_HOME}/.hullwork-probe/x && '
            f'(touch /should-not-be-writable 2>/dev/null && echo ROOT-IS-WRITABLE || true) && '
            f'rm -rf "$HOME/.hullwork-probe"'
        )
        result = self.run(probe, timeout=PREFLIGHT_TIMEOUT_SECONDS)
        if result.exit_code != 0:
            msg = (
                "the sandbox cannot host a phase: the probe failed. An agent phase in this "
                "environment would run with a broken shell and produce an artefact nothing "
                "verified, which is worse than no attempt"
            )
            raise SandboxError(msg, result.output)
        if "ran" not in result.output:
            msg = "the sandbox refused to execute a file it had just written"
            raise SandboxError(msg, result.output)
        if "ROOT-IS-WRITABLE" in result.output:
            msg = "the sandbox's root filesystem is writable, so --read-only is not in effect"
            raise SandboxError(msg, result.output)

    def run(self, command: str, timeout: int, env: dict[str, str] | None = None) -> RunResult:
        """Run one command with **no route out at all**. The dispatcher's own gates use this.

        The safe shape is the one with the short name, so that forgetting produces a phase that
        cannot reach anything rather than one that can reach the operator's credential (item 058).
        """
        return self._run(command, timeout, env, model=False)

    def run_with_model(
        self, command: str, timeout: int, env: dict[str, str] | None = None
    ) -> RunResult:
        """Run one command with the gateway reachable. **Only the agent's own phases.**

        A separate method rather than a keyword argument, because a keyword with a default is a
        guardrail that depends on every caller remembering it (item 017), and a caller who reaches
        for the wrong one here hands the watched project's test suite an endpoint that spends
        somebody else's tokens and writes into the provenance seal.
        """
        return self._run(command, timeout, env, model=True)

    def _run(
        self, command: str, timeout: int, env: dict[str, str] | None, *, model: bool
    ) -> RunResult:
        """Run one command inside, bounded, and guarantee the container is gone afterwards.

        Detached and polled rather than `subprocess.run(timeout=)`, because that kills the client
        and leaves the container running — measured, two seconds later it was still up.

        **The declared services are created and destroyed around this one phase** (item 052). Not
        once per attempt: three of the six phases run the project's test command, so a database they
        shared would make the red gate and the green gate two different databases — and that
        comparison is the one thing this product asserts. A fresh `postgres:16` answered in two
        seconds, so this is affordable rather than theoretical.
        """
        from hullwork.sandbox.services import Services

        with Services(self.services, tag=secrets.token_hex(4), docker=self.docker) as services:
            return self._in_container(
                command, timeout, {**(env or {}), **services.env},
                model=model, service_network=services.network if self.services else None,
            )

    def _in_container(
        self,
        command: str,
        timeout: int,
        env: dict[str, str] | None,
        *,
        model: bool,
        service_network: str | None,
    ) -> RunResult:
        argv = self._argv(command, env, model=model, service_network=service_network)

        if self.volume:
            # Both directions, around every phase, because `dispatch` reads the host copy between
            # phases *and* writes to it — `_restore_candidate` and `_restore_infrastructure` both
            # put files back there. The cost is the price of leaving every guard in `dispatch`
            # untouched, and a `docker cp` is a tar stream.
            self._push()
        if self.contract_volume:
            # The brief goes in the same way (item 082). Pushed on every phase rather than once:
            # `dispatch` writes a fresh brief per agent phase, and a stale one is worse than none.
            self._push_contract()

        started = time.monotonic()
        created = _docker(argv, timeout=120)
        if created.returncode != 0:
            raise SandboxError("could not start the sandbox", created.stdout + created.stderr)
        self._container = created.stdout.strip()

        try:
            timed_out = not self._wait(timeout)
            if timed_out:
                _docker([self.docker, "kill", "-s", "KILL", self._container], timeout=30)
            logs = _docker([self.docker, "logs", self._container], timeout=60)
            state = self._state()
            raw_exit = state.get("ExitCode")
            return RunResult(
                command=command,
                exit_code=raw_exit if isinstance(raw_exit, int) else -1,
                output=interleaved(logs.stdout, logs.stderr),
                duration_ms=int((time.monotonic() - started) * 1000),
                timed_out=timed_out,
                # Three different things produce exit 137 and the evidence trail has to tell them
                # apart: the memory limit, a timeout we caused, and the process dying on its own.
                out_of_memory=bool(state.get("OOMKilled")),
            )
        finally:
            _docker([self.docker, "rm", "-f", self._container], timeout=60)
            self._container = None
            if self.volume:
                self._pull()
            if self.contract_volume:
                # …and the report comes back out. `dispatch` reads it as a file on the host, so this
                # is what makes the agent's own account readable at all from inside a container.
                self._pull_contract()


    # --- the contract the container reads and writes (item 082) --------------------------------

    def ensure_contract(self, name: str, *, uid: int = SANDBOX_UID, gid: int = SANDBOX_GID) -> None:
        """Create the contract volume and seed it from `contract_dir`.

        Same recipe as `ensure_volume`, for the same reason and with one difference worth naming:
        the
        contract is **two-way**. The brief goes in and the agent's report comes back out, so both
        directions are copied around every phase rather than only on the way in.

        Refuses without a `contract_dir`, because there would be nothing to seed from and the silent
        version of that is an agent handed an empty brief — which is the exact failure item 086 was.
        """
        if self.contract_dir is None:
            msg = "a contract volume needs a contract directory to seed it from"
            raise SandboxError(msg)
        created = _docker([self.docker, "volume", "create", *label_args(), name], timeout=60)
        if created.returncode != 0:
            msg = "could not create the attempt's contract volume"
            raise SandboxError(msg, created.stdout + created.stderr)
        self.contract_volume = name
        self._uid, self._gid = uid, gid
        self._push_contract()

    def cleanup_contract(self) -> None:
        """Remove the contract volume. Never raises, for `cleanup`'s reason."""
        if self.contract_volume:
            _docker([self.docker, "volume", "rm", "-f", self.contract_volume], timeout=60)
            self.contract_volume = None

    def _push_contract(self) -> None:
        """Host `contract_dir` → volume, owned by the uid the phases run as."""
        with self._contract_carrier() as carrier:
            copied = _docker(
                [self.docker, "cp", f"{self.contract_dir}/.", f"{carrier}:{CONTRACT_DIR}"],
                timeout=120,
            )
            if copied.returncode != 0:
                msg = "could not seed the attempt's contract volume"
                raise SandboxError(msg, copied.stdout + copied.stderr)
        owned = _docker(
            [
                self.docker, "run", "--rm", "--user", "0:0",
                "--volume", f"{self.contract_volume}:{CONTRACT_DIR}",
                CARRIER_IMAGE, "chown", "-R", f"{self._uid}:{self._gid}", CONTRACT_DIR,
            ],
            timeout=120,
        )
        if owned.returncode != 0:
            msg = "could not give the contract volume to the sandbox user"
            raise SandboxError(msg, owned.stdout + owned.stderr)

    def _pull_contract(self) -> None:
        """Volume → host `contract_dir`, so `dispatch` can read the report as a file.

        Logged and swallowed rather than raised, like `_pull`: a report that could not be read back
        is an attempt with no account of itself, which `dispatch` already handles as a missing
        report — and raising here would turn it into an abandoned attempt instead.
        """
        with self._contract_carrier() as carrier:
            copied = _docker(
                [self.docker, "cp", f"{carrier}:{CONTRACT_DIR}/.", str(self.contract_dir)],
                timeout=120,
            )
            if copied.returncode != 0:
                log.error(
                    "could not read the attempt's contract back",
                    extra={"volume": self.contract_volume},
                )

    @contextmanager
    def _contract_carrier(self) -> "Iterator[str]":
        """A stopped container mounting the contract volume, for `docker cp` to target."""
        created = _docker(
            [
                self.docker, "create", "--volume", f"{self.contract_volume}:{CONTRACT_DIR}",
                CARRIER_IMAGE, "true",
            ],
            timeout=120,
        )
        if created.returncode != 0:
            msg = "could not create the contract volume carrier"
            raise SandboxError(msg, created.stdout + created.stderr)
        carrier = created.stdout.strip()
        try:
            yield carrier
        finally:
            _docker([self.docker, "rm", "-f", carrier], timeout=60)


    # --- the worktree the container owns (item 055) --------------------------------------------

    def ensure_volume(
        self,
        name: str,
        *,
        uid: int = SANDBOX_UID,
        gid: int = SANDBOX_GID,
        seed_from_image: bool = False,
    ) -> None:
        """Create the volume and seed it from the host worktree, owned by the uid that will run.

        Spec M2 §4.2's recipe: `docker cp` into a **stopped** container that mounts the volume, then
        a chown so the files belong to the container's user rather than to the dispatcher. The chown
        runs as root *inside a throwaway container* — which is not the sandbox, touches only this
        volume, and is the one way to do it that does not require the dispatcher to be root.

        **`seed_from_image` copies the image's own `/work` in first** (item 114). Every ecosystem so
        far was served by moving its dependencies *out* of the worktree and telling the toolchain
        where they went — `CARGO_HOME`, `GOMODCACHE`, `BUNDLE_PATH`. PHP has no such variable: a
        project's `vendor/` path is written into its `composer.json`, its `phpunit.xml` and every
        `require` it makes. Measured on `briannesbitt/carbon`: the image built, Composer installed,
        and PHPUnit died on `vendor/autoload.php` because this mount had replaced the directory.

        The order is what makes it safe. The image goes down first and the **checkout goes on top**,
        so the source is always the repository's and only what the build added survives. Off by
        default and passed by exactly one caller, so a project that does not need it runs the path
        it ran yesterday — which matters, because this is the seam every attempt goes through.
        """
        created = _docker([self.docker, "volume", "create", *label_args(), name], timeout=60)
        if created.returncode != 0:
            msg = "could not create the attempt's volume"
            raise SandboxError(msg, created.stdout + created.stderr)
        self.volume = name
        self._uid, self._gid = uid, gid
        if seed_from_image:
            self._seed_from_image(name)
        self._push()

    def _seed_from_image(self, name: str) -> None:
        """The image's `/work` into the volume, before the checkout goes on top. Item 114.

        Swallowed rather than raised: an image with nothing at that path is the ordinary case for
        every project that does not build its dependencies into the tree, and a failure here means
        the phase runs without whatever the build installed — which is the behaviour of yesterday,
        not a new way to break.
        """
        copied = _docker(
            [
                self.docker, "run", "--rm", "--volume", f"{name}:/hullwork-seed",
                # **As root, and this took a measurement to see.** The image runs as `hullwork`
                # (uid 10001) and a fresh volume belongs to root, so the copy was refused — and the
                # first version of this line ended in `2>/dev/null || true`, which turned a
                # permission error into a silent empty volume and a test failure three layers away.
                # `_push` chowns the whole volume afterwards, so root here costs nothing.
                "--user", "0:0",
                "--entrypoint", "sh", self.image, "-c",
                # `|| true` **only** for the genuinely empty case: an image whose `/work` holds
                # nothing is the ordinary one. Errors are no longer hidden — `cp` writes them to
                # stderr and a non-zero exit is logged below.
                "if [ -d /work ] && [ -n \"$(ls -A /work 2>/dev/null)\" ]; "
                "then cp -a /work/. /hullwork-seed/; fi",
            ],
            timeout=300,
        )
        if copied.returncode != 0:
            log.warning(
                "could not seed the worktree volume from the image",
                extra={"volume": name, "image": self.image},
            )

    def _env_cache(self) -> str:
        """The name of this image's writable environment cache.

        Derived from the image tag, which is already content-addressed over the base, the installer
        and the dependency files — so two projects never share one and a rebuilt image gets a fresh
        one. A digest of the tag rather than the tag itself: a tag carries a colon and a volume name
        may not.
        """
        digest = hashlib.sha256(self.image.encode()).hexdigest()[:12]
        return f"hullwork-envcache-{digest}"

    def cleanup(self) -> None:
        """Remove the volume. Never raises: a failed cleanup must not mask the real error."""
        if self.volume:
            _docker([self.docker, "volume", "rm", "-f", self.volume], timeout=60)
            self.volume = None

    def _push(self) -> None:
        """Host worktree → volume, and chown to the uid the phases run as."""
        with self._carrier() as carrier:
            copied = _docker(
                [self.docker, "cp", f"{self.worktree}/.", f"{carrier}:{WORKDIR}"], timeout=300
            )
            if copied.returncode != 0:
                msg = "could not seed the attempt's volume"
                raise SandboxError(msg, copied.stdout + copied.stderr)
        owned = _docker(
            [
                self.docker, "run", "--rm", "--user", "0:0",
                "--volume", f"{self.volume}:{WORKDIR}",
                CARRIER_IMAGE, "chown", "-R", f"{self._uid}:{self._gid}", WORKDIR,
            ],
            timeout=300,
        )
        if owned.returncode != 0:
            msg = "could not give the volume to the sandbox user"
            raise SandboxError(msg, owned.stdout + owned.stderr)

    def _pull(self) -> None:
        """Volume → host worktree, owned by the dispatcher again.

        Owned by us on the way back, or the *next* attempt on this host finds a tree it cannot
        write — the same defect one run later, which is the version nobody sees coming.
        """
        with self._carrier() as carrier:
            copied = _docker(
                [self.docker, "cp", f"{carrier}:{WORKDIR}/.", str(self.worktree)], timeout=300
            )
            if copied.returncode != 0:
                log.error("could not read the attempt's volume back", extra={"volume": self.volume})

    @contextmanager
    def _carrier(self) -> "Iterator[str]":
        """A stopped container that mounts the volume, for `docker cp` to have a target."""
        created = _docker(
            [
                self.docker, "create", "--volume", f"{self.volume}:{WORKDIR}",
                CARRIER_IMAGE, "true",
            ],
            timeout=120,
        )
        if created.returncode != 0:
            msg = "could not create the volume carrier"
            raise SandboxError(msg, created.stdout + created.stderr)
        carrier = created.stdout.strip()
        try:
            yield carrier
        finally:
            _docker([self.docker, "rm", "-f", carrier], timeout=60)

    def _wait(self, timeout: int) -> bool:
        """Poll until the container exits. False if it had to be killed."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._state().get("Running", False):
                return True
            time.sleep(0.5)
        return False

    def _state(self) -> dict[str, object]:
        probe = _docker(
            [self.docker, "inspect", "--format", "{{json .State}}", self._container or ""],
            timeout=30,
        )
        try:
            state = json.loads(probe.stdout or "{}")
        except ValueError:
            return {}
        return state if isinstance(state, dict) else {}


#: Files that decide whether tests run at all, wherever in the tree they sit (item 046).
#:
#: `pyproject.toml` and `package.json` are in here and it is worth saying why, because they look
#: like ordinary project files. Both can switch a suite off — `[tool.pytest.ini_options] addopts`
#: and `scripts.test` — and neither can be *legitimately* changed by a fix anyway: the sandbox has
#: no network, so a dependency a fix adds cannot be installed and the green gate fails regardless.
#: Restoring them therefore costs nothing real and closes a live vector.
TEST_CONFIG_FILES = frozenset(
    {
        "conftest.py",
        "pytest.ini",
        "tox.ini",
        "setup.cfg",
        "pyproject.toml",
        "package.json",
        "jest.config.js",
        "jest.config.ts",
        "jest.config.mjs",
        "jest.config.cjs",
        "vitest.config.js",
        "vitest.config.ts",
        "vitest.config.mjs",
    }
)

#: Directory names that conventionally hold tests. Instance-owned, **not** the manifest's
#: `test_path`: that field is untrusted input, and it already pulls the other way — narrowing it
#: tightens the reproduce-phase guard while loosening this one, which is how a guardrail gets
#: quietly inverted by a single edit to a file in somebody else's repository.
TEST_DIRS = frozenset({"tests", "test", "spec", "specs", "__tests__", "testing"})

#: Test filename shapes for the runtimes `SandboxBase` admits — Python and Node, and nothing else,
#: because a pattern for a runtime this instance cannot build is a pattern nobody has ever run.
_TEST_FILE = re.compile(
    r"^test_[^/]*\.py$|^[^/]*_test\.py$|^[^/]*\.(?:test|spec)\.[cm]?[jt]sx?$"
)


def is_test_infrastructure(relative: str) -> bool:
    """Whether this path decides what the test command does, rather than what the code does."""
    parts = relative.split("/")
    if parts[-1] in TEST_CONFIG_FILES:
        return True
    if any(part in TEST_DIRS for part in parts[:-1]):
        return True
    return bool(_TEST_FILE.match(parts[-1]))


@dataclass(frozen=True)
class Changes:
    """What a phase did to the tree: files written, and files removed.

    Item 045. This used to be a bare `dict[str, bytes]` built by walking the tree, which meant a
    **deletion was invisible**: the gates ran against a tree with the file gone and the pull request
    carried the tree with the file intact. A fix that removes a validation by deleting a file was
    therefore tested as one program and published as another, and the red-green claim — the one
    thing this product asserts — was false about the thing being published.

    A dataclass rather than a wider dict on purpose: the old shape compared equal to a dict, so any
    call site that kept treating the result as one would have gone on silently dropping deletions.
    This one raises instead.
    """

    written: dict[str, bytes]
    deleted: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        """Whether the phase did anything at all. A deletion counts."""
        return bool(self.written or self.deleted)

    @property
    def count(self) -> int:
        return len(self.written) + len(self.deleted)


def collect_changes(
    worktree: Path, before: dict[str, bytes], *, allow_new_only_under: str | None = None
) -> Changes:
    """Read back what changed, refusing anything that must not cross.

    Item 040: what crosses back is a file set, not a patch. Applying a patch is a host `git`
    process consuming attacker-authored content, and no arrangement of flags makes git a parser.
    Validating a path list, on the other hand, genuinely is parser-free — and the dispatcher
    already had to know which paths it would accept.

    `allow_new_only_under` is the reproduce phase: new files under the declared test path and
    nothing else, so a phase cannot reach a red gate by breaking working code instead of
    reproducing the bug. **A deletion is refused outright in that phase** — a test that fails
    because a passing test was removed reproduces nothing.
    """
    changed: dict[str, bytes] = {}
    seen: set[str] = set()
    for path in sorted(worktree.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(worktree).as_posix()
        if _forbidden(relative):
            continue
        seen.add(relative)
        content = path.read_bytes()
        if before.get(relative) == content:
            continue
        _check(relative, content, before, allow_new_only_under)
        changed[relative] = content

    # Derived from the before-image rather than from the tree, which is the only place a vanished
    # file still exists. `snapshot` already excludes forbidden paths and tool artefacts, so nothing
    # here needs filtering: a deletion cannot be reported for a path that was never eligible.
    deleted = tuple(sorted(set(before) - seen))
    if deleted and allow_new_only_under is not None:
        msg = (
            f"the reproduce phase deleted {deleted[0]!r}: it may only add new files, or it can "
            f"reach a failing suite by removing a passing test rather than reproducing the bug"
        )
        raise UnsafePathError(msg)

    result = Changes(written=changed, deleted=deleted)
    if result.count > MAX_CHANGED_FILES:
        msg = f"more than {MAX_CHANGED_FILES} files changed; this is not a bug fix"
        raise UnsafePathError(msg)
    return result


def _forbidden(relative: str) -> bool:
    """Whether this path never crosses back, by component rather than by prefix.

    Covers two different reasons in one check because both answers are the same: the git directory
    and the workflow directories are refused for safety, and the toolchain's own droppings are
    refused because they are not the agent's work at all.
    """
    parts = relative.split("/")
    if parts[0] in FORBIDDEN_DIRS:
        return True
    if any(part in TOOL_ARTEFACTS for part in parts):
        return True
    return relative.endswith(TOOL_ARTEFACT_SUFFIXES)


def _check(
    relative: str, content: bytes, before: dict[str, bytes], allow_new_only_under: str | None
) -> None:
    """Every reason a produced file may not be written to the host, in one place."""
    if relative.startswith("/") or ".." in relative.split("/"):
        msg = f"{relative!r} does not stay inside the worktree"
        raise UnsafePathError(msg)
    if len(content) > MAX_FILE_BYTES:
        msg = f"{relative!r} is {len(content)} bytes, which is not a source change"
        raise UnsafePathError(msg)
    if allow_new_only_under is None:
        return
    if relative in before:
        msg = (
            f"{relative!r} already existed: the reproduce phase may only add new files, or it "
            f"can reach a failing test by breaking working code instead of reproducing the bug"
        )
        raise UnsafePathError(msg)
    if not relative.startswith(allow_new_only_under.rstrip("/") + "/"):
        msg = f"{relative!r} is outside the declared test path {allow_new_only_under!r}"
        raise UnsafePathError(msg)


def snapshot(worktree: Path) -> dict[str, bytes]:
    """Every file in the tree, for comparing against afterwards. Skips `.git` entirely."""
    return {
        path.relative_to(worktree).as_posix(): path.read_bytes()
        for path in sorted(worktree.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and not _forbidden(path.relative_to(worktree).as_posix())
    }


def interleaved(stdout: str, stderr: str, *, keep: int = 8_000) -> str:
    """Both streams, each keeping its own tail. Item 098.

    **`stdout + stderr` loses the only part anybody reads.** Measured on the first pull request
    Hullwork produced for another project, whose test command is
    `cd backend && alembic upgrade head && pytest`: concatenated, the tail of the combined string is
    always the tail of *stderr*, so what the artefact stored for every gate was twenty-six alembic
    migrations and not one line of pytest. `252 passed, 1 failed` — the number the red-gate judge
    counts, the number `failing_lines` quotes, the number a reviewer looks for — was inside the part
    that got dropped. The agent had it and the evidence trail did not.

    Every runner worth supporting puts its summary at the end of *its* stream, so each stream keeps
    its own tail and each is labelled. Labelled rather than merged silently, because "this came from
    stderr" is often the diagnosis: a suite that printed nothing to stdout and a page to stderr
    failed differently from one that printed a summary.

    True interleaving is not available here — `docker logs` returns the two streams already
    separated, and the timestamps it can add are per line and cost a second call. Two labelled tails
    is what the data supports.
    """
    parts: list[str] = []
    for name, text in (("stdout", stdout), ("stderr", stderr)):
        body = text.strip("\n")
        if not body:
            continue
        if len(body) > keep:
            body = f"… [earlier {name} omitted] …\n" + body[-keep:]
        # Unlabelled when there is only one stream: a label on a lone body is noise, and most
        # commands only write to one.
        parts.append(body if not (stdout.strip() and stderr.strip()) else f"--- {name} ---\n{body}")
    return "\n".join(parts)


def _docker(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    if shutil.which(argv[0]) is None:
        msg = f"{argv[0]!r} is not on PATH; the dispatcher needs the Docker daemon (spec M2 §1)"
        raise SandboxError(msg)
    try:
        return subprocess.run(  # noqa: S603 - argv list, no shell, binary resolved above
            argv, capture_output=True, text=True, timeout=timeout,
            check=False, stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        msg = f"docker itself did not answer within {timeout}s"
        raise SandboxError(msg, str(exc.stdout)) from exc
