"""Moving a resolved dependency graph, by running the tool that knows how. Item 175, DR-0016.

**Why this is not a file edit.** A lock file is a *resolved graph*: moving `jinja2` can require
moving `markupsafe`, and moving that can require moving something else. Editing one version string
leaves a file that is internally incoherent — and the bad outcome is not that it fails to install,
it is that it **installs**, after which a green suite means nothing at all. That is a false verdict
of the exact kind DR-0017 says this product exists to prevent, produced by the product itself.

Only the ecosystem's own resolver knows how to move that graph. So nothing here parses a lock file.
It runs `npm`, or `uv`, or `poetry`, in a container, and reads back what they wrote.

**And it does not believe them either.** A manifest can forbid the upgrade — `"lodash": "^4.17.11"`
does not permit 5.x — and every one of these tools reports success after resolving to the highest
version the range allows, having not applied the fix. So the lock is re-read and the version
checked. The tool's exit code is not the verdict, which is the same rule the gates run on.
"""

from __future__ import annotations

import json
import logging
import tomllib
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

log = logging.getLogger(__name__)


class ResolveError(RuntimeError):
    """The socket refused something this needed: a volume, a carrier, a copy.

    Its own class rather than `SandboxError`, because this is not an attempt and nothing here holds
    a sandbox — and it is turned into an ordinary non-zero exit by `in_a_container`, so a failure to
    reach Docker is reported as *this upgrade could not be moved* rather than as a crash in a
    dispatcher that has other work to do.
    """

#: How long a resolver may take. Generous: it is a registry round trip plus a graph solve, and a
#: cold npm cache on a large tree is genuinely slow.
RESOLVE_TIMEOUT_SECONDS = 600


class Outcome(StrEnum):
    """What running the ecosystem's resolver did."""

    #: The lock moved and the version in it is the one that was asked for.
    RESOLVED = "resolved"
    #: The tool succeeded and the package did not move: the manifest's range forbids it.
    CONSTRAINED = "constrained-by-manifest"
    #: The tool failed. Its own output is carried.
    FAILED = "failed"
    #: A file the resolver needs is not in the checkout.
    MISSING = "missing-manifest"


@dataclass(frozen=True)
class Result:
    outcome: Outcome
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome is Outcome.RESOLVED


@dataclass(frozen=True)
class Resolver:
    """One ecosystem's way of moving its own graph, declared as data.

    A table entry rather than a code path, so a new ecosystem is a row: `needs` is what must be in
    the context for the tool to work at all, `image` is where the tool lives, and `command` is a
    template. Nothing here knows what any of these tools do.
    """

    #: Which lock file this resolver owns.
    lock: str
    #: Everything that must be present, lock included. **The manifest is not optional**: every
    #: resolver reads it to know what versions are allowed, and without it they resolve nothing.
    needs: tuple[str, ...]
    image: str
    #: `{package}` and `{version}` are substituted. Run through `sh -lc`.
    command: str


#: The ecosystems whose graphs can be moved, and how.
#:
#: `--package-lock-only` on npm moves the graph without downloading `node_modules`, which is the
#: difference between seconds and minutes. The two Python entries are separate resolvers rather
#: than one because `uv` and `poetry` disagree about everything except the file they read.
RESOLVERS: tuple[Resolver, ...] = (
    Resolver(
        lock="package-lock.json",
        needs=("package.json", "package-lock.json"),
        image="node:22-slim",
        command="npm install {package}@{version} --package-lock-only --no-audit --no-fund",
    ),
    Resolver(
        lock="uv.lock",
        needs=("pyproject.toml", "uv.lock"),
        image="ghcr.io/astral-sh/uv:python3.12-bookworm-slim",
        command="uv lock --upgrade-package {package}=={version}",
    ),
    Resolver(
        lock="poetry.lock",
        needs=("pyproject.toml", "poetry.lock"),
        image="python:3.12-slim",
        command=(
            "pip install --quiet poetry && "
            "poetry add {package}=={version} --lock --no-interaction"
        ),
    ),
)


def resolver_for(source: str) -> Resolver | None:
    """The resolver that owns this lock file, or `None` when nothing does.

    `None` is not a gap to fill silently: item 173's refusal still applies to it, by name, so a
    lock file nobody can move is still declined rather than edited by hand.
    """
    name = source.rsplit("/", 1)[-1]
    return next((r for r in RESOLVERS if r.lock == name), None)


def version_in_lock(text: str, lock: str, package: str) -> str | None:
    """What the lock says this package is pinned at now, or `None` if it does not carry it.

    Read back **after** the resolver has run, because a tool that resolved within a range the
    manifest allows exits 0 having moved nothing — and taking that as success would publish a
    `clean` verdict for an upgrade that never happened.
    """
    name = lock.rsplit("/", 1)[-1]
    if name == "package-lock.json":
        try:
            document = json.loads(text)
        except ValueError:
            return None
        packages = document.get("packages")
        if not isinstance(packages, dict):
            return None
        for path, entry in packages.items():
            if not path or not isinstance(entry, dict):
                continue
            if path.split("node_modules/")[-1] == package:
                found = entry.get("version")
                return found if isinstance(found, str) else None
        return None

    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    entries = document.get("package")
    if not isinstance(entries, list):
        return None
    wanted = _canonical(package)
    for entry in entries:
        if isinstance(entry, dict) and _canonical(str(entry.get("name", ""))) == wanted:
            found = entry.get("version")
            return found if isinstance(found, str) else None
    return None


def _canonical(name: str) -> str:
    """PEP 503 again — `Jinja2` and `jinja-2` are one package, and lock files disagree on which."""
    import re

    return re.sub(r"[-_.]+", "-", name).lower()


def command_for(resolver: Resolver, package: str, version: str) -> str:
    """The template filled in. Separate so it can be asserted without a daemon."""
    return resolver.command.format(package=package, version=version)


def beside(path: str) -> str:
    """The directory a path is in, as the repository writes it, and `""` at the root."""
    return path.rsplit("/", 1)[0] if "/" in path else ""


def missing_from(resolver: Resolver, present: Sequence[str], at: str = "") -> list[str]:
    """Which of the files this resolver needs are not **beside the lock**. Item 239.

    Checked before the container starts: a `uv.lock` with no `pyproject.toml` beside it cannot be
    resolved by anything, and finding that out after pulling an image is a minute wasted on a fact
    that was on disk.

    **`at` is the whole of item 239.** This compared basenames anywhere in the checkout, so a
    `pyproject.toml` in `backend/` satisfied a check about a lock in `frontend/` — and the honest
    refusal it exists to produce was unreachable for any repository with more than one lock file.
    Measured on `simplecheck`, which is a monorepo: it pulled an image to be told the file was not
    where it was looking.
    """
    names = {path.rsplit("/", 1)[-1] for path in present if beside(path) == at}
    return [needed for needed in resolver.needs if needed not in names]


def upgrade(
    *,
    resolver: Resolver,
    worktree: Path,
    package: str,
    version: str,
    present: Sequence[str],
    run: Callable[[Resolver, Path, str], tuple[int, str]],
    at: str = "",
) -> Result:
    """Move the graph, then check that it actually moved. Item 175.

    `run` takes the resolver, the directory to mount and the command, and returns an exit code and
    the tool's output. Injected for the reason every other boundary here is: this stays testable
    without a daemon, and nothing in this module knows Docker exists.

    **`at` is where the lock lives**, relative to the worktree, and it is item 239. This mounted the
    root and ran the tool there, so a monorepo — `backend/uv.lock`, `frontend/package.json` — was
    told *No `pyproject.toml` found in current directory or any parent directory* and recorded
    `cannot-move`, which is a sentence about somebody else's repository that was our own working
    directory. It defaults to the root, so a repository with one lock at the top behaves exactly as
    it did.
    """
    absent = missing_from(resolver, present, at)
    if absent:
        return Result(
            Outcome.MISSING,
            f"{resolver.lock} cannot be resolved without {', '.join(absent)}: the resolver reads "
            f"the manifest to know which versions are allowed, and there is none here.",
        )

    where = worktree / at if at else worktree
    code, output = run(resolver, where, command_for(resolver, package, version))
    if code != 0:
        return Result(Outcome.FAILED, output)

    lock_path = where / resolver.lock
    landed = version_in_lock(lock_path.read_text(encoding="utf-8"), resolver.lock, package)
    if landed != version:
        # **The tool's exit code is not the verdict.** Every one of these resolves happily within
        # whatever range the manifest allows and reports success, so `^4.17.11` answers 0 having
        # never gone near 5.x. Believing it would publish `clean` for an upgrade that never
        # happened — the worst artefact this repository can emit.
        return Result(
            Outcome.CONSTRAINED,
            f"the resolver exited 0 and {package} is still {landed or 'absent'}, not {version}: "
            f"the range in the manifest does not allow it. Widen it there, then run this again.",
        )
    return Result(Outcome.RESOLVED)


@contextmanager
def _carrying(context: Path, docker: str) -> Iterator[str]:
    """A named volume holding a copy of `context`, seeded and read back over the socket. Item 240.

    **A bind mount cannot be used here and this is the third time this repository has learned it.**
    `-v {path}:/w` is resolved by the *daemon*: the dispatcher runs in a container, so the path
    exists in one filesystem and is looked up in another. The daemon finds nothing, mounts an empty
    directory, and the resolver reports the project has no manifest — measured on atlas, where every
    dependency verification this instance ever ran took this path.

    Item 055 moved the attempt's worktree off a bind mount for exactly this, and item 082 the
    contract directory. This is that recipe with a different working directory, and it is imported
    from `sandbox.run` rather than written a second time.
    """
    import secrets

    from hullwork.sandbox.docker import run_docker
    from hullwork.sandbox.inventory import label_args
    from hullwork.sandbox.run import CARRIER_IMAGE

    name = f"hullwork-resolve-{secrets.token_hex(4)}"
    made = run_docker([docker, "volume", "create", *label_args(), name], timeout=60)
    if made.returncode != 0:
        raise ResolveError(made.stdout + made.stderr)

    def carrier() -> str:
        created = run_docker(
            [docker, "create", "--volume", f"{name}:/w", CARRIER_IMAGE, "true"], timeout=120
        )
        if created.returncode != 0:
            raise ResolveError(created.stdout + created.stderr)
        return created.stdout.strip()

    try:
        one = carrier()
        try:
            pushed = run_docker([docker, "cp", f"{context}/.", f"{one}:/w"], timeout=300)
        finally:
            run_docker([docker, "rm", "-f", "-v", one], timeout=60)
        if pushed.returncode != 0:
            raise ResolveError(pushed.stdout + pushed.stderr)
        yield name
        # **Back to the dispatcher's own filesystem**, because the regenerated lock is the entire
        # point: everything downstream — `version_in_lock`, the rebuild, the guard that restores
        # what this touched — reads files, and reads them here.
        two = carrier()
        try:
            run_docker([docker, "cp", f"{two}:/w/.", str(context)], timeout=300)
        finally:
            run_docker([docker, "rm", "-f", "-v", two], timeout=60)
    finally:
        run_docker([docker, "volume", "rm", "-f", name], timeout=60)


def in_a_container(
    resolver: Resolver, context: Path, command: str, *, docker: str = "docker"
) -> tuple[int, str]:
    """Run one resolver's command against a copy of the checkout. The only Docker in this module.

    **On a volume rather than a bind mount** (item 240). The docstring here used to argue the
    opposite — a bind mount gets the regenerated file back, a volume does not — and that was true
    while the dispatcher ran on a host and false the moment it ran in a container, where the daemon
    resolves the path in its own filesystem and mounts nothing. Neither the comment nor anything
    else was re-read when the ground moved.

    **`--user` is not a detail.** Without it `npm` leaves root-owned files in the copy, and the
    `docker cp` back hands the operator's checkout a file they cannot write.

    **And this one has a network, deliberately.** Resolving *is* asking the registry what exists. It
    is the trade `image.build` already makes, and it changes nothing about the phase that later runs
    the suite, which still reaches nothing.
    """
    import os
    import subprocess

    try:
        with _carrying(context, docker) as volume:
            argv = [
                docker, "run", "--rm",
                "--user", f"{os.getuid()}:{os.getgid()}",
                # A resolver that hangs must not hold the run: these are network calls to a
                # registry.
                "--stop-timeout", "10",
                "-v", f"{volume}:/w",
                "-w", "/w",
                # `HOME` so the tools have somewhere to write their caches; `/w` is the only
                # writable path and a cache in the checkout would be left behind for the operator.
                "-e", "HOME=/tmp",
                resolver.image,
                "sh", "-lc", command,
            ]
            log.info("resolving", extra={"image": resolver.image, "command": command})
            try:
                done = subprocess.run(  # noqa: S603
                    argv, capture_output=True, text=True, check=False,
                    timeout=RESOLVE_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                return 1, f"the resolver did not finish within {RESOLVE_TIMEOUT_SECONDS}s"
            return done.returncode, (done.stdout + done.stderr).strip()
    except ResolveError as failed:
        return 1, str(failed)


def touches(resolver: Resolver) -> tuple[str, ...]:
    """Every file this resolver may rewrite, which is **all** of them and not just the lock.

    **Measured, not assumed** (item 175's gate, 2026-08-09): `npm install lodash@4.17.21
    --package-lock-only` rewrote `package.json` as well, moving its range from `^4.17.11` to
    `^4.17.21`. That is correct behaviour for an upgrade and it is not what the caller expected.

    Why it matters more than it looks: item 174 found that a candidate leaving its own pin behind
    made the *next* candidate's baseline describe the previous one, and fixed it by restoring the
    file it had rewritten. With a resolver in the path there is more than one such file, and
    restoring only the lock leaves the manifest moved — the same defect, one file over, and
    invisible in exactly the same way.
    """
    return resolver.needs
