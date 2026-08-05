"""`Cable.close` is documented as never raising, and one `_docker` call in it is not `_quietly`.

**Reported from production.** A dispatcher was configured with a `docker` that is not there
(`/nonexistent/docker`), and the traceback that came back was:

    net.py:188  in __enter__          self._create_network()
    net.py:331  in _create_network    created = _docker(
    run.py:740  in _docker            raise SandboxError(msg)

`_docker` refuses before it spawns anything when `shutil.which(argv[0])` is `None`, which is the
right answer to a missing daemon and is not the defect. The defect is what happens next.
`Cable.__enter__` catches that on purpose — *"half a network is worse than none"* — and calls
`self.close()` to take the whole thing down. But `close` opens with

    said = _docker([self._docker, "logs", "--tail", "40", self.container], timeout=…)

which is a bare `_docker`, not `_quietly`, and every other teardown call in the method *is*
`_quietly`. So with no `docker` on PATH that first line raises the very same `SandboxError` again,
from inside the handler, and two things follow:

* **Teardown stops at line one.** `_pull_journal`, `rm -f` the container, `network rm`, and
  `volume rm -f` are all after it and none of them run. Nothing had been created *in this
  traceback* — the very first call failed — but the same line is reached from `__exit__` and from
  the failure path further along `_start_gateway`, where a network, a container and a volume do
  exist and are then left on the host. That is precisely the leak `__enter__`'s comment says must
  not happen, and `close`'s own docstring promises it cannot: *"teardown that can fail is teardown
  that leaves a network holding a route on somebody's host, so every error here is logged and
  swallowed."*
* **The diagnosis is overwritten.** What reaches the caller is raised by `close`, and the failure
  that actually happened is demoted to its `__context__`. Here both messages read the same, so it
  looks harmless; when `_create_network` fails for its own reasons — `"could not create the
  attempt's network"`, with the daemon's own output attached — that message is what the operator
  needs and it is the one that gets replaced by a teardown error.

Two tests, one for each half. Neither needs a Docker daemon or a shim: a path that is not on PATH
is the whole fixture, and it is exactly what the report carried.
"""

from pathlib import Path

import pytest

from hullwork.sandbox.net import Cable
from hullwork.sandbox.run import SandboxError

#: The value from the report. Absolute, so `shutil.which` checks it directly rather than searching
#: PATH — and answers `None`, which is what makes `_docker` refuse.
MISSING_DOCKER = "/nonexistent/docker"


def _cable(work_dir: Path) -> Cable:
    """A cable pointed at a `docker` that is not there. Nothing is started by construction."""
    return Cable(
        "https://api.example",
        "a-key",
        work_dir=work_dir,
        docker=MISSING_DOCKER,
        suffix="regression",
    )


def _frames(exc: BaseException) -> list[str]:
    """The function names on an exception's traceback, outermost first."""
    names: list[str] = []
    tb = exc.__traceback__
    while tb is not None:
        names.append(tb.tb_frame.f_code.co_name)
        tb = tb.tb_next
    return names


def test_teardown_does_not_raise_when_docker_is_not_on_path(tmp_path: Path) -> None:
    """`close` says it never raises. With no `docker` its first line does, and it stops there.

    Called directly rather than through `__enter__`, because this is the property the docstring
    claims and it has to hold however teardown is reached — from `__exit__` after a good run, from
    the failure path in `__enter__`, and twice in a row.
    """
    _cable(tmp_path).close()


def test_the_failure_that_escapes_is_the_one_that_happened(tmp_path: Path) -> None:
    """The report's traceback, asserted as the traceback the caller should have been handed.

    `_create_network` calling `_docker` is where it went wrong; `close` is where the exception the
    caller sees is raised today, with the real one hidden in `__context__`. An operator
    reading the tracker is sent to teardown for a fault in construction.
    """
    with pytest.raises(SandboxError) as err, _cable(tmp_path):
        pass  # pragma: no cover - the cable never comes up

    frames = _frames(err.value)
    assert "_create_network" in frames, (
        f"the escaping error was not raised by the call that failed; frames were {frames}"
    )
    assert "close" not in frames, (
        f"teardown raised over the real failure and stopped partway through; frames were {frames}"
    )
    assert err.value.__context__ is None, (
        f"the failure the operator needs was demoted to __context__: {err.value.__context__!r}"
    )
