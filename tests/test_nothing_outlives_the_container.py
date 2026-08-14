"""Every container this product removes takes its anonymous volumes with it. Item 244.

Item 241 stopped the verification queue leaving a gigabyte of image per candidate, and the disk kept
climbing — 45% to 54% in an hour, with **zero** sandbox images on the host:

```
Local Volumes   69   ACTIVE 5   3.217GB   96% reclaimable
```

Ten of those carried a hullwork name. The rest were anonymous, and they were databases.
`postgres:16` declares `VOLUME /var/lib/postgresql/data` in its Dockerfile, so every `docker run`
of it makes one, and `docker rm -f` **without `-v`** leaves it behind. One per service, per phase
— item 052 starts them fresh around each one on purpose — on every attempt and verification.

**The reaper cannot collect these.** `inventory` matches by name and an anonymous volume has none:
a 64-character hex string that says nothing about who made it. Removing those by pattern would
delete everything else on the host, which is what item 125 exists to prevent. They have to go with
whoever created them, at the moment that one knows it is done.

So this is a rule rather than seven fixes, and this file is the rule.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import re
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / "hullwork"

#: `docker rm` of a container, in both the spellings this repository uses: `run_docker([docker,
#: "rm", …])` and `_quietly(self._docker, ["rm", …])`. A volume is removed with
#: `["volume", "rm", …]` and is a different call under a different rule: those are **named**, they
#: have owners, and `-v` never touches them.
#:
#: **The whitespace lives inside the lookahead**, and that is not a detail: written the other way
#: — `\s*,\s*(?!"-v")` — the engine backtracks that `\s*` to zero, the lookahead sees ` "-v"` rather
#: than `"-v"`, and the pattern matches the very lines that are correct. It reported all seven fixed
#: call sites as offenders, which is how it was found.
_REMOVES_A_CONTAINER = re.compile(r'(?<!"volume", )"rm"\s*,\s*"-f"\s*,(?!\s*"-v")')


def test_every_container_removal_takes_its_volumes() -> None:
    """**The whole item, as a rule instead of seven patches.** `-v` removes a container's anonymous
    volumes and leaves named ones alone, which is exactly the distinction that matters here:
    `hullwork-worktree-*` and `hullwork-envcache-*` have names and owners; a database started for
    one phase has neither.
    """
    offenders: list[str] = []
    for path in sorted(SOURCE.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if _REMOVES_A_CONTAINER.search(line):
                offenders.append(f"{path.relative_to(SOURCE.parent)}:{number}: {line.strip()}")

    assert offenders == [], (
        "these remove a container without `-v`, so anything the image declared as a VOLUME "
        "outlives it:\n  " + "\n  ".join(offenders)
    )


def test_the_rule_can_tell_a_container_from_a_volume() -> None:
    """A guard that also matched `["volume", "rm", "-f", name]` would demand `-v` on a call that
    does not take it, and the fix would be to weaken the guard — which is how a rule stops being
    one. Asserted so the pattern itself is under test rather than only its verdict."""
    assert _REMOVES_A_CONTAINER.search('_quietly(self._docker, ["rm", "-f", container])')
    assert _REMOVES_A_CONTAINER.search('run_docker([docker, "rm", "-f", one], timeout=60)')
    assert not _REMOVES_A_CONTAINER.search('_quietly(self._docker, ["rm", "-f", "-v", container])')
    assert not _REMOVES_A_CONTAINER.search(
        'run_docker([docker, "rm", "-f", "-v", one], timeout=60)'
    )
    assert not _REMOVES_A_CONTAINER.search(
        'run_docker([self.docker, "volume", "rm", "-f", name], timeout=60)'
    )


def test_the_services_that_hold_a_database_are_the_ones_this_is_about() -> None:
    """Named rather than inferred: `postgres` is the service whose image declares a `VOLUME`, and
    it is why 69 volumes existed on a host that had been cleaned four hours earlier."""
    from hullwork.sandbox.services import SERVICES

    assert any(name.startswith("postgres") for name in SERVICES), (
        "the service this item was found on is gone; check whether the rule still has a subject"
    )
