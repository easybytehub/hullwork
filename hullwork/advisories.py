"""What OSV has published against what a project pins. DR-0024, item 230.

The half of the product that needs **no model, no write credential and no Docker** — the half an
evaluator can use on their first day — left no trace in a running instance until this: `hullwork
deps` opened no session, stored nothing, and could not even run inside the container.

**What this module is and is not.** It reads, asks and returns; it writes no rows and knows nothing
about pages or clocks. The caller stores the answer, because *when it was asked* is half of it and
that belongs with the row rather than in here.

**The verification half stays where it is.** Applying an upgrade and running a suite needs the
Docker socket, and DR-0005 gives the receiver none. This can say what is published; only the
dispatcher can say whether the fix survives your tests.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from hullwork import dependencies
from hullwork.osv import Finding, Osv


class Tree(Protocol):
    """A listing. **Read-only properties, not attributes**: a `Protocol` declaring a mutable
    attribute is invariant, so the forge's own `Tree` — whose `paths` is a `tuple` — does not
    satisfy `paths: Sequence[str]` however obviously it does in practice."""

    @property
    def paths(self) -> Sequence[str]: ...

    @property
    def truncated(self) -> bool: ...


class Reads(Protocol):
    def tree(self, repo: str) -> Tree: ...
    def read_file(self, repo: str, path: str) -> str | None: ...


@dataclass(frozen=True)
class Report:
    """What was found, and whether the question was asked at all.

    **`asked=False` with a `note` is the answer, not the absence of one.** An advisory list that
    silently reads empty when OSV was unreachable says *you are fine* on no evidence, which is the
    worst failure this feature can have — and it is the operator's own condition on DR-0024.
    """

    asked: bool
    pinned: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    note: str | None = None


def as_rows(found: Sequence[Finding]) -> list[dict[str, Any]]:
    """The findings as the row stores them. One shape, so the page never sees an `Advisory`."""
    return [
        {
            "package": one.dependency.name,
            "version": one.dependency.version,
            "source": one.dependency.source,
            "advisories": [
                {"id": a.id, "summary": a.summary, "fixed": list(a.fixed)} for a in one.advisories
            ],
        }
        for one in found
        if one.advisories
    ]


def about(repo: str, forge: Reads, ask: Callable[[Sequence[Any]], list[Finding]]) -> Report:
    """Read what this repository pins, and ask what is published against it.

    Every failure is a `Report` rather than an exception, and each says which half failed: a forge
    that will not list a tree and a database that will not answer are different problems with
    different fixes, and *something went wrong* is neither.
    """
    try:
        listing = forge.tree(repo)
    except Exception as exc:
        return Report(asked=False, note=f"could not list {repo}: {exc}")

    pinned = dependencies.read_lockfiles(
        list(listing.paths), lambda path: _read(forge, repo, path)
    )
    if not pinned:
        return Report(
            asked=True,
            note=(
                "nothing here pins a version: no lock file and no `==` in a requirements file, so "
                "there is nothing to ask about. A declaration is a range, and a range is not a "
                "fact about what your build resolved to"
            ),
        )
    try:
        found = ask(pinned)
    except Exception as exc:
        return Report(
            asked=False,
            pinned=len(pinned),
            note=f"read {len(pinned)} pinned version(s) and could not reach OSV: {exc}",
        )
    return Report(asked=True, pinned=len(pinned), findings=as_rows(found))


def _read(forge: Reads, repo: str, path: str) -> str | None:
    """One file, or `None`. A file that will not read costs its own contribution and no more —
    `read_lockfiles` already treats that as *this file said nothing*, which is the honest reading
    of a `package-lock.json` the forge refused while `uv.lock` came back fine."""
    try:
        return forge.read_file(repo, path)
    except Exception:
        return None


def asking(timeout: float = 20.0) -> Callable[[Sequence[Any]], list[Finding]]:
    """A callable that asks the real OSV and closes after itself."""

    def _ask(deps: Sequence[Any]) -> list[Finding]:
        with Osv(timeout=timeout) as osv:
            return osv.affected(deps)

    return _ask
