"""The harness, as something mounted rather than something baked in. Item 065, DR-0007 part 1.

The harness used to be installed **into** a derived image: a multi-stage `COPY --from=harness` of
`node`, its modules and the `claude` binary, layered onto whatever base the manifest declared. That
is
what coupled Hullwork to the project's base image, because those binaries are glibc-linked — so an
Alpine-based project got an image whose harness could not start, with an error naming the wrong
thing
(`sh: …/claude: not found` is about a missing *library*, not a missing file).

**A binary does not need to be static to run on a foreign libc. It needs its own libc to travel with
it.** Measured in production, 2026-07-29, with a bundle mounted into a stock Alpine image:

```
libc of the image:      /lib/ld-musl-x86_64.so.1
claude, run directly:   sh: /hw/bin/claude: not found
claude, via its loader: 2.1.220 (Claude Code)
```

So the bundle carries the executable, its dynamic loader and its libraries, and the wrapper invokes
it
through the loader explicitly. That is what every portable Linux bundle does, and it makes libc a
non-question rather than a documented limitation.

**Built once per instance**, into a named volume identified by what went into it. 266 MB copied at
first use, never again; the alternative — building it per attempt — trades an image rebuild for a
copy
of the same size.

**And the build verifies itself.** A library missed at bundle time fails at *attempt* time with a
message about the wrong thing, which is the failure mode this whole file exists to remove. So the
last
step of building a bundle is running the harness through its own loader, and a bundle whose harness
cannot start is not published.
"""

import hashlib
import logging
import shlex

from hullwork.sandbox.run import SandboxError, _docker

log = logging.getLogger(__name__)

#: Where the bundle is mounted inside the sandbox. Outside the worktree and outside the contract
#: directory: it is neither the project's code nor the agent's own paperwork, and a phase that finds
#: our software under `/work` would report it as the agent's work (the mistake `CONTRACT_DIR` exists
#: for).
BUNDLE_DIR = "/hullwork-harness"

#: The one executable a project's image must provide. Every phase already runs `sh -lc`, so this
#: adds
#: no requirement that was not there.
WRAPPER = f"{BUNDLE_DIR}/bin/hullwork-agent"

#: Docker's own commands answer quickly or are broken.
DOCKER_TIMEOUT_SECONDS = 600


class BundleError(SandboxError):
    """The harness bundle could not be built or is not usable.

    A `SandboxError`, so `run_one` turns it into an **abandoned** attempt: a harness that will not
    start says nothing about whether the bug is reproducible, and it must not cost the item its one
    try — the rule item 043 wrote for a red baseline and item 059 for a spent turn ceiling.
    """


def _extract_script(source_bin: str, install: str) -> str:
    """The shell run inside the harness's own image to assemble the bundle.

    Its own image, and never the project's: the point is to lift the harness out of the environment
    that publishes it, along with everything it links against. `ldd` is read rather than a library
    list being maintained — a maintained list is a list that goes stale the next time the harness
    adds a dependency, and the failure would appear at attempt time.
    """
    return (
        "set -eu\n"
        # Installed into its own publisher's image first, because that image ships the runtime and
        # not the harness. Ours is the command; theirs is the image.
        + (f"{install}\n" if install else "")
        + "mkdir -p /out/bin /out/lib\n"
        f"real=$(readlink -f {shlex.quote(source_bin)})\n"
        'cp "$real" /out/bin/harness\n'
        # **The loader is asked for by name from `ldd`, not written down** — the same reasoning the
        # docstring above gives for the libraries, applied to the one path that was still a literal.
        #
        # It was `ld-linux-x86-64.so.2`, so the bundle could not be built on **any arm64 host**: the
        # loader there is `ld-linux-aarch64.so.1` and `cp` said so. Measured on 2026-08-04 on an
        # Apple Silicon Mac, which is to say on most developer laptops now, running the command the
        # README offers as the cheap first look. It had only ever been built in production, which is
        # x86-64 — the docstrings even say "measured in production", and that was the whole of the
        # coverage.
        #
        # `ldd`'s interpreter line is an absolute path to a file whose name starts `ld-`, indented,
        # with no `=>`. That shape is the same on both architectures, which is why it is read rather
        # than matched against a list of names somebody has to extend.
        'loader=$(ldd /out/bin/harness | grep -oE "^[[:space:]]*/[^ ]*/ld-[^ ]+" '
        '| head -1 | tr -d "[:space:]")\n'
        '[ -n "$loader" ] || { echo "no interpreter in ldd output for /out/bin/harness" >&2; '
        "exit 1; }\n"
        'cp "$loader" /out/lib/\n'
        # Its basename travels with the bundle, because the prologue and the self-test both have to
        # invoke it and neither can know the architecture of the host that assembled this.
        'basename "$loader" > /out/lib/.loader\n'
        # Every shared object the executable names, by path, straight from the loader's own answer.
        'for l in $(ldd /out/bin/harness | grep -o "/lib[^ ]*\\.so[^ ]*"); do\n'
        '  [ -f "$l" ] && cp "$l" /out/lib/ || true\n'
        "done\n"
        "ls /out/lib\n"
    )


#: The prologue prepended to the entrypoint inside a bundle. Defines the same `harness` shell
#: function a baked recipe defines, except it goes through the loader and libraries that travelled
#: with the executable rather than the ones the project's image happens to have.
#:
#: A function, not a variable: the invocation is a loader plus two paths plus an executable, and
#: `exec "$VAR"` would look for a file whose name contains spaces while `exec $VAR` would be
#: word-splitting somebody's path.
#: The loader's name is **read from the bundle** rather than written here, so one bundle format
#: works on x86-64 and arm64 without this string knowing which. See `_bundle_script`.
MOUNTED_PROLOGUE = (
    "harness() {\n"
    f'  exec {BUNDLE_DIR}/lib/"$(cat {BUNDLE_DIR}/lib/.loader)"'
    f" --library-path {BUNDLE_DIR}/lib"
    f' {BUNDLE_DIR}/bin/harness "$@"\n'
    "}\n"
)


def wrapper_script(entrypoint: str) -> str:
    """The bundle's own copy of the phase entrypoint, wired to the mounted harness.

    `entrypoint` is passed in rather than imported, because `engine` imports this module for the
    mount paths and a module cycle is not worth the convenience.

    The shebang has to stay the first line, so the prologue is spliced after it rather than
    prepended
    — a `#!` on line two is a comment, and the script would run under whatever shell called it.
    """
    first, _, rest = entrypoint.partition("\n")
    return f"{first}\n{MOUNTED_PROLOGUE}{rest}"


def bundle_name(
    source_image: str, source_bin: str, install: str = "", entrypoint: str = ""
) -> str:
    """The volume that holds this bundle, named by everything that went into it.

    Content-addressed rather than versioned, for the reason `image_tag` is: a bundle from another
    image or another path is a different bundle, and reusing a volume under a name that claims
    otherwise is how a stale harness runs for a week without anybody noticing.

    **The entrypoint is in the digest, and it was not at first** — which reproduced that exact
    defect within the hour. Item 064 changed `AGENT_ENTRYPOINT`, the entrypoint lives *inside* the
    bundle, and the volume was reused because its name accounted only for where the executable came
    from. The deploy reported success and the agent would have gone on running the previous brief.
    Anything the bundle *contains* belongs in the name that claims to describe it.
    """
    digest = hashlib.sha256(
        f"{source_image}\0{source_bin}\0{install}\0{entrypoint}".encode()
    ).hexdigest()[:12]
    return f"hullwork-harness-{digest}"


def ensure_bundle(
    source_image: str,
    source_bin: str,
    *,
    entrypoint: str,
    install: str = "",
    docker: str = "docker",
) -> str:
    """Build the bundle if this instance does not have it yet, and return the volume's name.

    Idempotent by the volume existing: the check is `docker volume inspect`, which is cheap, and the
    build is 266 MB of copying that must happen once and not once per attempt.
    """
    name = bundle_name(source_image, source_bin, install, entrypoint)
    if _docker([docker, "volume", "inspect", name], timeout=60).returncode == 0:
        log.info("harness bundle present", extra={"bundle": name})
        return name

    log.info("building the harness bundle", extra={"bundle": name, "from": source_image})
    created = _docker([docker, "volume", "create", name], timeout=60)
    if created.returncode != 0:
        msg = "could not create the volume for the harness bundle"
        raise BundleError(msg, created.stdout + created.stderr)

    built = _docker(
        [
            docker, "run", "--rm",
            "--volume", f"{name}:/out",
            "--entrypoint", "sh",
            source_image, "-c", _extract_script(source_bin, install),
        ],
        timeout=DOCKER_TIMEOUT_SECONDS,
    )
    if built.returncode != 0:
        _docker([docker, "volume", "rm", "-f", name], timeout=60)
        # The tail in the message, not only in `output`: `str(exc)` is what reaches the operator
        # through `_dispatcher_failed`, and a sentence that says only "could not" is the shape items
        # 056 and 063 were both diagnosed the long way round because of.
        said = (built.stdout + built.stderr).strip()[-400:]
        msg = f"could not lift the harness out of {source_image!r}: {said}"
        raise BundleError(msg, built.stdout + built.stderr)

    _write_wrapper(name, entrypoint, docker=docker)
    _prove_it_starts(name, docker=docker)
    log.info("harness bundle built", extra={"bundle": name, "libs": built.stdout.split()})
    return name


def _write_wrapper(name: str, entrypoint: str, *, docker: str) -> None:
    """Put the phase entrypoint in the bundle, wired to the mounted harness."""
    script = wrapper_script(entrypoint)
    written = _docker(
        [
            docker, "run", "--rm", "--volume", f"{name}:/out",
            "--entrypoint", "sh", "alpine:3", "-c",
            f"cat > /out/bin/hullwork-agent <<'HULLWORK_EOF'\n{script}HULLWORK_EOF\n"
            "chmod 0755 /out/bin/hullwork-agent",
        ],
        timeout=DOCKER_TIMEOUT_SECONDS,
    )
    if written.returncode != 0:
        msg = "could not write the harness wrapper into the bundle"
        raise BundleError(msg, written.stdout + written.stderr)


def _prove_it_starts(name: str, *, docker: str) -> None:
    """Run the harness through its own loader, in an image that shares nothing with the source.

    **The last step of building a bundle, and the reason the bundle is trustworthy.** A library
    missed
    at bundle time fails at attempt time with a message about a missing *file*, which sends whoever
    is
    reading it to the wrong place — this project has now spent two diagnoses on exactly that shape
    of
    error. Alpine on purpose: it is musl, so a bundle that starts here is one whose libc travelled.
    """
    probe = _docker(
        [
            docker, "run", "--rm", "--volume", f"{name}:{BUNDLE_DIR}:ro",
            "--entrypoint", "sh", "alpine:3", "-c",
            # Same discovered loader as the prologue, for the same reason: this probe is what proves
            # the bundle starts, and a probe hardcoding an architecture proves it on one only.
            f'{BUNDLE_DIR}/lib/"$(cat {BUNDLE_DIR}/lib/.loader)" '
            f"--library-path {BUNDLE_DIR}/lib "
            f"{BUNDLE_DIR}/bin/harness --version",
        ],
        timeout=DOCKER_TIMEOUT_SECONDS,
    )
    if probe.returncode != 0:
        msg = (
            "the harness bundle was assembled and will not start, so it is not published — a "
            "library is missing from it, and that failure would otherwise appear at attempt time "
            "as a missing file rather than a missing library"
        )
        raise BundleError(msg, (probe.stdout + probe.stderr)[-500:])
    log.info("harness bundle starts on a foreign libc", extra={"said": probe.stdout.strip()[:80]})
