"""What every Docker command in the sandbox goes through, and the error it raises. Item 162.

**Here because a private name was being imported by two siblings.** `SandboxError` and the command
runner lived in `run.py`; `services.py` and `harness.py` imported them from there at module level,
and `run.py` imported *back* from both of those — inside functions, which is what kept the package
importable. Four `py/cyclic-import` alerts pointed at the arrangement, and the arrangement pointed
at something worse: the runner was called `_docker`, and a leading underscore is a claim about who
may use something. Two siblings using it made that claim false, for the one function through which
`docker` invocation in the sandbox passes — the one a reader most needs to find deliberately rather
than by following an import they were not meant to see.

So it is `run_docker()`, it is public, and it lives in the module both sides import. Nothing here
imports from anything else in `sandbox/`, which is what makes the cycle impossible, not absent.
"""

from __future__ import annotations

import shutil
import subprocess


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


def run_docker(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    """Run one `docker` command, or say why it could not be run.

    Two failures become sentences here rather than at forty call sites: the binary is not on PATH,
    and Docker itself did not answer. Everything else is a non-zero exit code the caller reads,
    because *what* failed is the caller's business and *whether Docker works at all* is not.
    """
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
