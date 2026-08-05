"""The recording, written down as it happens, so a killed process does not take it with it.

Item 054. The gateway used to live in the dispatcher's own process and hand its `Recording` over at
the end of an attempt. It moves into a container — because a container on an `--internal` network
cannot reach a listener on the host, and asking every self-hoster to open their firewall to the
Docker bridge is not an answer this product wants to give — and the recording has to come back
across that boundary.

**Append-only, one line per event, flushed.** The alternative was reading it out over the bridge at
teardown, which is simpler and loses exactly the case where the seal matters most: a gateway killed
mid-attempt is the one whose recording explains why. A file survives that; a process does not.

**Observations and refusals only. Violations are not written.** `Recording.observe` derives them —
model drift, silent truncation — so replaying the observations reconstructs them identically, and
storing a derived value is how two copies of one rule start disagreeing. `refused` is not derived
and so is written.

A malformed line is skipped rather than fatal. The seal is evidence and a partial seal is worse than
none *if it pretends to be whole*, so the reader reports what it dropped and the caller decides —
which is why `read` returns the count rather than logging it and moving on.
"""

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path

from hullwork.gateway import Recording
from hullwork.gateway.protocols import Observation

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Replayed:
    """A recording rebuilt from a journal, and what the rebuild could not read."""

    recording: Recording
    #: Lines that could not be parsed. Non-zero means the seal describes less than what happened.
    unreadable: int


class Journal:
    """Writes what the gateway sees, one line at a time, to a path the dispatcher can read."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def observed(self, observation: Observation) -> None:
        self._write({"kind": "observation", "observation": asdict(observation)})

    def refused(self, path: str) -> None:
        self._write({"kind": "refused", "path": path})

    def _write(self, event: dict[str, object]) -> None:
        """Open, append, close. Deliberately not a held handle.

        A handle held across the life of a container is a buffer that a `docker kill` discards, and
        this file exists precisely for the case where the container is killed. The cost is a syscall
        per response, against a request that took a model seconds to answer.
        """
        try:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
                handle.flush()
        except OSError:
            # A gateway that dies because it could not write its own journal turns a recoverable
            # attempt into no attempt. Loud, and it keeps serving.
            log.exception("could not append to the gateway journal")


def read(path: Path, *, endpoint: str, pinned_model: str | None = None) -> Replayed:
    """Rebuild a recording from a journal, replaying each observation through `observe`.

    Through `observe` and not by assignment: that method owns the rules that turn an observation
    into a violation, and a reader that appended violations directly would be a second copy of them.
    """
    recording = Recording(endpoint=endpoint, pinned_model=pinned_model)
    unreadable = 0
    if not path.exists():
        return Replayed(recording, 0)

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            if event["kind"] == "observation":
                recording.observe(Observation(**event["observation"]))
            elif event["kind"] == "refused":
                recording.refused.append(str(event["path"]))
            else:
                unreadable += 1
        except (ValueError, KeyError, TypeError):
            unreadable += 1
    return Replayed(recording, unreadable)
