"""What an attempt leaves behind when nothing gets to run its `finally`. Item 106, part 4.

**The measurement this exists for.** On 2026-07-29 a `docker compose stop` in the middle of an
attempt left a gateway container, an attempt network and three volumes on the host, one of them
holding a copy of the model credential. Item 097 fixed the halves that had an owner — the lease and
the item recovery — and left the inventory claim untested, which is how it ended up here.

**Why a reaper rather than better teardown.** Teardown already works: every one of these objects is
created inside a context manager that removes it. What no context manager can survive is the
process not existing any more — `SIGKILL`, an OOM kill, a `docker compose stop` whose grace period
expires mid-attempt. There is no `finally` for that, so the debris has to be collected by whatever
runs next, and the dispatcher's start-up is the only moment that both knows the previous holder is
gone and is allowed to act on it.

**The condition that makes it safe is the lease, not a timestamp.** `lease.acquire` succeeds only
when the previous lease expired or was released, so a dispatcher that has just taken it is the only
one running — and everything matching these names belongs to a run that is over. Reaping on a clock
instead would race a live attempt and remove the network out from under it. That argument is
already load-bearing for `release_stale` (item 097); this is the same fact used for the same reason.

**`hullwork-harness-*` is deliberately not in the list, and that distinction cost a measurement.**
Those volumes are **content-addressed caches** keyed by the harness image, binary, installer and
entrypoint — shared across attempts by design, and rebuilt in seconds if removed. They are not
debris, they are the thing debris is often confused with: an object with a Hullwork name that no
running attempt holds. Reaping them would be correct-looking, harmless and wrong, and it would
quietly slow every first attempt after a restart.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

#: How long any one `docker` call here may take. Removal is fast; this only bounds a hung daemon.
TIMEOUT_SECONDS = 60

#: Containers an attempt creates and names. The services containers are named per service inside
#: their own network, so they are reached through the network rather than by prefix.
CONTAINER_PREFIXES = ("hullwork-cable-",)

#: Networks. `hullwork-attempt-*` is the cable's; `hullwork-services-*` carries the declared
#: services, and removing it removes nothing else — its containers must go first, which
#: `_containers_on` does.
NETWORK_PREFIXES = ("hullwork-attempt-", "hullwork-services-")

#: Volumes. `hullwork-wire-*` is the one that matters most: it holds a copy of the model credential,
#: which is the reason this whole module is not merely housekeeping.
#:
#: **Not `hullwork-harness-*`** — see the module docstring. A content-addressed cache is not debris.
VOLUME_PREFIXES = ("hullwork-wire-", "hullwork-worktree-", "hullwork-contract-")

#: Whose debris this is. Item 125.
#:
#: The prefixes above say *what* an object is; this says *who made it*. On a host running two
#: instances — the ordinary answer to a second forge, since the forge is chosen per instance — the
#: names collide completely: the tag after each prefix is four random bytes and carries nothing.
#: The lease cannot separate them either, because each instance has its own database and therefore
#: its own lease, which is precisely the premise this module's docstring rests on.
LABEL = "hullwork.instance"


def instance_id() -> str:
    """This instance's label value, from `HULLWORK_INSTANCE`.

    **Read from the environment rather than through `Settings`**, and that is a correction rather
    than a shortcut. `Settings` refuses to load on any unknown `HULLWORK_*` variable — correctly, a
    typo in a security-relevant setting must fail loudly — so going through it would make labelling
    a container require the *whole* configuration to be valid. Measured: three sandbox tests, whose
    doubles set `HULLWORK_TEST_*` variables, stopped being able to create a network.

    It is the same variable `Settings.instance` exposes, with the same default, and a test asserts
    the two agree — the drift is prevented by a measurement rather than by an import.
    """
    import os

    return (os.environ.get("HULLWORK_INSTANCE") or "").strip() or "default"


def label_args(instance: str | None = None) -> list[str]:
    """`--label hullwork.instance=<id>`, for every `docker create`, `run` and `network create`.

    A label rather than a longer name: names are load-bearing in several places here and changing
    their shape moves the seam every attempt runs through, while a label is additive and every
    `docker … ls` can filter on one.
    """
    return ["--label", f"{LABEL}={instance or instance_id()}"]


@dataclass
class Leftovers:
    """What was found, by kind. Empty is the answer an operator wants and must be able to see."""

    containers: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.containers or self.networks or self.volumes)

    def summary(self) -> str:
        """One line, naming counts and the credential-bearing case explicitly."""
        parts = [
            f"{len(self.containers)} container(s)",
            f"{len(self.networks)} network(s)",
            f"{len(self.volumes)} volume(s)",
        ]
        wire = [name for name in self.volumes if name.startswith("hullwork-wire-")]
        credential = f", {len(wire)} of them holding a model credential" if wire else ""
        return ", ".join(parts) + credential


def _listed(
    docker: str, kind: str, prefixes: tuple[str, ...], *, label: str | None
) -> list[str]:
    """Names of `kind` whose name starts with one of `prefixes`, carrying `label` if one is given.

    The prefix is filtered here rather than with `--filter name=`, which is a **substring** match on
    Docker and would claim anything with the word anywhere in it. A reaper that removes by substring
    is one unlucky project name away from removing something that is not ours.

    The label *is* given to Docker, because `--filter label=` is an exact match on a key and value
    and is the only way to ask "and whose is it".
    """
    argv = [docker, "ps", "--all", "--format", "{{.Names}}"] if kind == "container" else [
        docker, kind, "ls", "--format", "{{.Name}}"
    ]
    if label is not None:
        argv += ["--filter", f"label={LABEL}={label}"]
    found = _run(argv)
    if found is None:
        return []
    return sorted(
        name for name in (line.strip() for line in found.splitlines())
        if any(name.startswith(prefix) for prefix in prefixes)
    )


def find(docker: str = "docker", *, instance: str | None = None) -> Leftovers:
    """This instance's debris on this host. Never raises.

    Reads only. `hullwork doctor` calls this to report, and `reap` calls it to act — one definition
    of "what counts as debris", because two would disagree the day somebody adds a prefix to one.
    """
    label = instance or instance_id()
    return Leftovers(
        containers=_listed(docker, "container", CONTAINER_PREFIXES, label=label),
        networks=_listed(docker, "network", NETWORK_PREFIXES, label=label),
        volumes=_listed(docker, "volume", VOLUME_PREFIXES, label=label),
    )


def unclaimed(docker: str = "docker") -> Leftovers:
    """Hullwork-shaped objects on this host that **no instance claims**, for reporting only.

    Two things land here and neither may be removed by a machine. Objects created before item 125
    existed carry no label, and objects created by a *different* instance carry somebody else's —
    and the whole point of this item is that deleting another instance's live attempt is the
    failure, not the housekeeping. So they are named, and a person decides.
    """
    mine = find(docker)
    everything = Leftovers(
        containers=_listed(docker, "container", CONTAINER_PREFIXES, label=None),
        networks=_listed(docker, "network", NETWORK_PREFIXES, label=None),
        volumes=_listed(docker, "volume", VOLUME_PREFIXES, label=None),
    )
    return Leftovers(
        containers=[n for n in everything.containers if n not in mine.containers],
        networks=[n for n in everything.networks if n not in mine.networks],
        volumes=[n for n in everything.volumes if n not in mine.volumes],
    )


def reap(docker: str = "docker") -> Leftovers:
    """Remove the leftovers and return what went. Never raises.

    Order matters and is the reason this is not three loops in a caller: a network with a container
    attached cannot be removed, and a volume mounted by one cannot either. Containers first, then
    the containers sitting on each network, then the networks, then the volumes.

    Swallowed like every other teardown here: a host where this fails is a host with debris on it,
    which is worse than it was and not a reason to refuse to dispatch.
    """
    leftovers = find(docker)
    others = unclaimed(docker)
    if others:
        # Reported and left alone. On a host with a second instance this is its live attempt, and
        # the previous version of this function removed it (item 125).
        log.info(
            "leaving alone what this instance did not create",
            extra={"found": others.summary(), "instance": instance_id()},
        )
    for name in leftovers.containers:
        _run([docker, "rm", "--force", name])
    for network in leftovers.networks:
        for attached in _containers_on(docker, network):
            _run([docker, "rm", "--force", attached])
        _run([docker, "network", "rm", network])
    for volume in leftovers.volumes:
        _run([docker, "volume", "rm", "--force", volume])
    if leftovers:
        log.info("reaped what a stopped attempt left behind", extra={"found": leftovers.summary()})
    return leftovers


def _containers_on(docker: str, network: str) -> list[str]:
    """Whatever is still attached to a services network, by id.

    Named per service rather than per attempt (`postgres-16` on `hullwork-services-<tag>`), so
    there is no prefix to match on — the network is the only thing that identifies them as ours,
    which is why they are found through it rather than beside it.
    """
    listing = "{{range .Containers}}{{.Name}} {{end}}"
    found = _run([docker, "network", "inspect", network, "--format", listing])
    return [name for name in (found or "").split() if name]


def _run(argv: list[str]) -> str | None:
    """`docker`, or `None` when it could not be asked. Nothing here is worth an exception."""
    try:
        done = subprocess.run(  # noqa: S603 - argv is built from constants and docker's own output
            argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("could not ask docker about leftovers", extra={"error": str(exc)})
        return None
    if done.returncode != 0:
        log.warning(
            "docker refused a leftovers command",
            extra={"argv": " ".join(argv[1:3]), "error": done.stderr.strip()[:200]},
        )
        return None
    return done.stdout
