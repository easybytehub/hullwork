"""The sandbox's mount options, measured against a real Docker daemon rather than in its argv.

**Why this file exists.** Item 092 removed `noexec` from `TMPFS_MOUNTS`, a test asserted the
option was gone from the argument list, three gates went green, and the baseline of the watched
project stayed red on exactly the same 24 tests. Docker mounts `--tmpfs` with `noexec` **by
default**, so the argument said one thing and the kernel did another:

```
$ docker run --rm --tmpfs /tmp:rw,nosuid,nodev,size=1g … cat /proc/mounts
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=1048576k …
$ … os.access('/tmp/probe/docker', os.X_OK)
False
```

An argv assertion cannot see that, and the difference is the whole of whether Hullwork can attempt a
fix on any project whose tests write an executable — which is how a project that tests a CLI is
written, including this one.

Skipped without a daemon, so the ordinary suite stays runnable anywhere. That is a real gap, and
the reason the argv assertions exist too: neither kind of test is sufficient alone.
"""

import json
import shutil
import subprocess

import pytest

from hullwork.sandbox.run import SANDBOX_GID, SANDBOX_HOME, SANDBOX_UID, TMPFS_MOUNTS

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None
    or subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],  # noqa: S607
        capture_output=True,
        timeout=30,
        check=False,
    ).returncode
    != 0,
    reason="needs a reachable Docker daemon; the argv assertions cover what a double can prove",
)

#: Small, present on any daemon that has run a Hullwork attempt, and unrelated to the sandbox image
#: so this measures the *mount options* rather than anything a particular image does.
PROBE_IMAGE = "alpine:3"


def _run_probe(script: str) -> str:
    """Run `script` in a container with the sandbox's real hardening, and return its stdout."""
    argv = ["docker", "run", "--rm", "--read-only"]
    for path, options in TMPFS_MOUNTS:
        argv += ["--tmpfs", f"{path}:{options}"]
    argv += [PROBE_IMAGE, "sh", "-c", script]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False)  # noqa: S603
    assert done.returncode == 0, f"the probe itself failed: {done.stdout}{done.stderr}"
    return done.stdout


def test_a_file_written_into_a_writable_path_can_be_executed() -> None:
    """**The property the baseline of any CLI-testing project stands on.**

    Written, `chmod +x`, run — and `test -x` as well, because that is what `shutil.which` consults
    and it was the check that failed while the file was mode 755.
    """
    for path in (path for path, _ in TMPFS_MOUNTS):
        printed = _run_probe(
            f"printf '#!/bin/sh\\necho ran\\n' > {path}/probe && chmod 755 {path}/probe && "
            f"(test -x {path}/probe && echo 'x-bit honoured' || echo 'X_OK REFUSED') && "
            f"{path}/probe"
        )
        assert "x-bit honoured" in printed, f"{path} is not executable: {printed}"
        assert "ran" in printed, f"{path} refused to execute what was just written: {printed}"


def test_the_mount_options_the_kernel_reports_are_the_ones_intended() -> None:
    """Read from `/proc/mounts`, which is the only place the truth about a mount is.

    `nosuid` and `nodev` are asserted here as well as in the argv: they are what the hardening is
    actually worth once `noexec` turned out to cost the loop more than it bought.
    """
    printed = _run_probe("cat /proc/mounts")

    mounts = {
        parts[1]: parts[3].split(",")
        for line in printed.splitlines()
        if len(parts := line.split()) >= 4
    }
    for path, _ in TMPFS_MOUNTS:
        options = mounts.get(path)
        assert options is not None, f"{path} is not a mount at all: {printed}"
        assert "noexec" not in options, (
            f"{path} is mounted noexec, whatever the argument said — this is the failure item 092 "
            f"fixed twice, and the second time only because it was read here"
        )
        assert "nosuid" in options, f"{path} lost nosuid: {options}"
        assert "nodev" in options, f"{path} lost nodev: {options}"


def test_the_root_filesystem_still_refuses_a_write() -> None:
    """`--read-only` is the half of the hardening that survived, so it is asserted by effect too."""
    printed = _run_probe("touch /should-fail 2>&1 || echo 'root is read-only'")

    assert "root is read-only" in printed, printed


def test_the_writable_paths_are_bounded() -> None:
    """An unbounded tmpfs is the host's memory, and a size is a kernel fact, not a string."""
    printed = _run_probe("cat /proc/mounts")

    for line in printed.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] in {path for path, _ in TMPFS_MOUNTS}:
            assert any(option.startswith("size=") for option in parts[3].split(",")), (
                f"{parts[1]} has no size limit: {line}"
            )


def test_what_this_file_covers_is_named_where_somebody_will_look() -> None:
    """A skipped file is invisible; a named gap is not.

    This asserts nothing about Docker. It asserts that the hardening's own record says these
    properties are only proved with a daemon, so nobody reads the argv assertions as sufficient —
    which is exactly the mistake item 092 made twice.
    """
    from pathlib import Path

    argv_tests = Path(__file__).with_name("test_sandbox_run.py").read_text(encoding="utf-8")

    assert "test_sandbox_docker.py" in argv_tests, (
        "the argv-level test must point at the mount-level one, or the next person will trust it"
    )
    assert json.dumps(list(TMPFS_MOUNTS)).count("exec") >= 2, (
        "both writable paths must state exec: Docker's default for --tmpfs is noexec"
    )


def test_the_home_is_writable_by_the_user_the_phase_runs_as() -> None:
    """**Item 094, measured the only way it can be.**

    `/home/hullwork` came up `drwx------ 0 0` while the phase ran as 10001, so the agent could not
    create its own config directory and every `Bash` call it made failed with `EACCES`. A `--tmpfs`
    takes the ownership Docker gives it, not the container's user — and no argv assertion can see
    that, which is why this is here and not only in `test_sandbox_run.py`.

    Run as the sandbox's own uid rather than as root, because root can write to anything and would
    pass this while the agent still could not.
    """
    argv = ["docker", "run", "--rm", "--read-only", "--user", f"{SANDBOX_UID}:{SANDBOX_GID}"]
    for path, options in TMPFS_MOUNTS:
        argv += ["--tmpfs", f"{path}:{options}"]
    argv += [
        PROBE_IMAGE,
        "sh",
        "-c",
        f"mkdir -p {SANDBOX_HOME}/.config-probe/deep && echo 'home is writable' && "
        f"ls -ldn {SANDBOX_HOME}",
    ]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False)  # noqa: S603

    assert done.returncode == 0, f"the agent's home is not writable: {done.stdout}{done.stderr}"
    assert "home is writable" in done.stdout
    # Parsed rather than matched as a substring: `ls` pads its columns, so a spacing assertion fails
    # on a correct mount and says nothing useful when it does.
    listing = next(line for line in done.stdout.splitlines() if line.startswith("d"))
    fields = listing.split()
    assert (fields[2], fields[3]) == (str(SANDBOX_UID), str(SANDBOX_GID)), (
        f"the home is not owned by the phase's user: {listing}"
    )
    assert fields[0].startswith("drwx------"), f"a home is private: {listing}"
