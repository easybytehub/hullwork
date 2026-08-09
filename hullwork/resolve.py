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
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

log = logging.getLogger(__name__)

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


def missing_from(resolver: Resolver, present: Sequence[str]) -> list[str]:
    """Which of the files this resolver needs are not in the checkout.

    Checked before the container starts: a `uv.lock` with no `pyproject.toml` beside it cannot be
    resolved by anything, and finding that out after pulling an image is a minute wasted on a fact
    that was on disk.
    """
    names = {path.rsplit("/", 1)[-1] for path in present}
    return [needed for needed in resolver.needs if needed not in names]


def upgrade(
    *,
    resolver: Resolver,
    worktree: Path,
    package: str,
    version: str,
    present: Sequence[str],
    run: Callable[[Resolver, Path, str], tuple[int, str]],
) -> Result:
    """Move the graph, then check that it actually moved. Item 175.

    `run` takes the resolver, the directory to mount and the command, and returns an exit code and
    the tool's output. Injected for the reason every other boundary here is: this stays testable
    without a daemon, and nothing in this module knows Docker exists.
    """
    absent = missing_from(resolver, present)
    if absent:
        return Result(
            Outcome.MISSING,
            f"{resolver.lock} cannot be resolved without {', '.join(absent)}: the resolver reads "
            f"the manifest to know which versions are allowed, and there is none here.",
        )

    code, output = run(resolver, worktree, command_for(resolver, package, version))
    if code != 0:
        return Result(Outcome.FAILED, output)

    lock_path = worktree / resolver.lock
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


def in_a_container(
    resolver: Resolver, context: Path, command: str, *, docker: str = "docker"
) -> tuple[int, str]:
    """Run one resolver's command in an ephemeral container. The only Docker in this module.

    **A bind mount rather than a volume**, unlike an attempt's worktree (item 055), and the
    difference is worth stating so it does not later look like an oversight. An attempt's phases run
    **the project's own untrusted code**, where a bind mount would let it write to the host as the
    uid that started it. This runs one package manager's own command with no project code executing,
    and the entire purpose is to get a regenerated file back — which a bind mount does and a volume
    does not.

    **`--user` is not a detail.** Without it `npm` leaves root-owned files in the operator's
    checkout, and the next ordinary command they run fails with a permission error nothing connects
    back to us.

    **And this one has a network, deliberately.** Resolving *is* asking the registry what exists. It
    is the trade `image.build` already makes, and it changes nothing about the phase that later runs
    the suite, which still reaches nothing.
    """
    import os
    import subprocess

    argv = [
        docker, "run", "--rm",
        "--user", f"{os.getuid()}:{os.getgid()}",
        # A resolver that hangs must not hold the run: these are network calls to a registry.
        "--stop-timeout", "10",
        "-v", f"{context}:/w",
        "-w", "/w",
        # `HOME` so the tools have somewhere to write their caches; `/w` is the only writable path
        # and a cache in the checkout would be left behind for the operator to find.
        "-e", "HOME=/tmp",
        resolver.image,
        "sh", "-lc", command,
    ]
    log.info("resolving", extra={"image": resolver.image, "command": command})
    try:
        done = subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, check=False, timeout=RESOLVE_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        return 1, f"the resolver did not finish within {RESOLVE_TIMEOUT_SECONDS}s"
    return done.returncode, (done.stdout + done.stderr).strip()


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
