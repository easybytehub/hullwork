"""Building the container the tests will run in.

Item 037, and it is a floor rather than a feature. Before this, `autofix.sandbox` said `docker` —
a technology, not an image — so nothing put the watched project's dependencies anywhere. `pytest`
could not start, which means step 0, the baseline that must pass *before the model is ever called*,
could not pass for any project at all.

**Hullwork generates the Dockerfile; the repository does not supply one.** That is item 017's rule
applied to a new surface. A manifest naming an arbitrary image would let whoever can merge to a
connected repository choose what this host pulls and executes, which is supplying with extra steps.
A manifest naming a *base* is choosing among things the instance already trusts, and the install
command belongs to us.

Two consequences worth stating because they are easy to get backwards:

* **The build has network; the attempt does not.** Dependencies are installed while the image is
  made, on the host's network, and the container that later runs the agent reaches nothing but the
  gateway. Item 023 forbids installing at attempt time for good reason: adding package registries
  to the egress allowlist reopens a supply-chain path with code execution at the end of it.
* **The project itself is not installed, only its dependencies.** The source is mounted per attempt
  and changes between them; baking it in would mean rebuilding the image for every fix.
"""

import hashlib
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from hullwork.manifest import RuntimeConfig
from hullwork.sandbox.run import ENV_DIR, SANDBOX_GID, SANDBOX_UID, WORKDIR

if TYPE_CHECKING:  # the engine is data the caller supplies; importing it here would be circular
    from hullwork.engine import Engine

log = logging.getLogger(__name__)

#: A base the manifest may name, and the image it actually means. Pinned to `-slim` rather than
#: `-alpine`: musl breaks wheels, and a sandbox that cannot install the project's dependencies is
#: a sandbox that cannot run its tests.
BASE_IMAGES: dict[str, str] = {
    "python-3.12": "python:3.12-slim",
    "python-3.13": "python:3.13-slim",
    "node-22": "node:22-slim",
    "node-24": "node:24-slim",
}

#: Where an installed environment goes, and the most load-bearing line in this module.
#:
#: `run.py` mounts the worktree over `/work` at attempt time, so **anything the image installs
#: under `/work` is gone by the time the gates run** (item 051). `uv` puts `.venv` in the project
#: directory, `npm` and `pnpm` put `node_modules` there, and `poetry` makes a virtualenv of its
#: own — all inside the mount. The image would build, and the suite would run with nothing
#: installed. Found by pointing this at the first repository that is not Hullwork.
#:
#: Defined in `sandbox.run` and imported here: the phase mounts a writable volume over it (item
#: 112), so the two modules have to mean the same path and only one of them may say what it is.

#: What each declarable system package actually installs. Item 053.
#:
#: **The rule for adding an entry: a real project's test command needed it.** Not "somebody might" —
#: this repository has shipped `openhands`, which parses and resolves to nothing, and a `lint` gate
#: that was on by default with nothing behind it. Both were speculative and both were defects.
#:
#: All four bases are Debian-slim, so one recipe covers them. Installed as root at build time; the
#: container still runs as `hullwork` when a phase does.
SYSTEM_PACKAGES: dict[str, str] = {
    # Measured: three of this repository's own tests shell out to `git`, and `python:3.12-slim`
    # does not have it. They failed inside its own sandbox image and no manifest could ask.
    "git": "git",
    # **Item 063's two Tesseract entries are gone** (item 068). They were the right answer to the
    # wrong question: DR-0007 says a project names its own apt packages, so `acme` keeps
    # working by naming `tesseract-ocr` and `tesseract-ocr-spa` — which is what they were called
    # here anyway — and this instance stops needing to know what OCR is. The table is an alias
    # list now, for the cases where apt's name and the obvious name differ.
}

#: What each installer runs. **These commands are ours, not the repository's.** Every one installs
#: dependencies without installing the project: the source arrives at attempt time and changes
#: between attempts, so baking it in would rebuild the image for every fix.
#:
#: `{first}` is the *basename* of the first dependency file, because the command runs in that
#: file's own directory (see `dockerfile`).
#:
#: **Development dependencies are installed, and that is not an oversight.** This image exists to
#: run the project's own test command; `pytest`, `ruff` and `mypy` are dev dependencies in every
#: layout there is. `uv sync` installs only the main group unless told otherwise, and `npm ci
#: --omit=dev` says the quiet part out loud — both produced an image where `python -m pytest`
#: answered "No module named pytest". Measured, after the PATH was already right (item 051).
#:
#: Both `--all-extras` and `--all-groups`, because Python has two conventions and a generic builder
#: cannot pick between them: `[project.optional-dependencies]` are extras, `[dependency-groups]` are
#: groups.
#:
#: **`uv` exports and then pips, rather than `uv sync`**, and the reason is not style. Extras belong
#: to the *project*, so `--no-install-project` can never install them — and the project cannot be
#: installed here, because only the dependency files are copied in and the source arrives at attempt
#: time. `uv export` resolves the lock without needing the source, and `pip` puts the result in the
#: system site-packages, which was never inside the mount. Measured on a real project: `uv sync
#: --all-extras --no-install-project` installed 150 packages and not `pytest`.
#: **Six of these were Python and Node, and the documentation said "any stack"** (item 112). A Go,
#: Rust, Ruby, PHP, Java or Elixir project taking the sugar path got a toolchain and no
#: dependencies, and its suite failed on the first import. One recipe per language toolchain,
#: bounded by how many languages have an official image — the same argument item 109 made for the
#: three package managers, and the same bound: it grows by language, never by package.
#:
#: Every one installs **outside `/work`**, because the worktree mount replaces that directory at
#: attempt time. That is item 051's defect, and each ecosystem hides it somewhere different:
#: `vendor/bundle`, `target/`, `deps/`, `node_modules`.
INSTALL_COMMANDS: dict[str, str] = {
    "pip": "pip install --no-cache-dir -r {first}",
    "uv": (
        "pip install --no-cache-dir uv && uv export --frozen --all-extras --all-groups "
        "--no-emit-project --no-hashes -o /tmp/hullwork-req.txt "
        "&& pip install --no-cache-dir -r /tmp/hullwork-req.txt"
    ),
    "poetry": "pip install --no-cache-dir poetry && poetry install --no-root --no-interaction",
    "npm": f"npm ci --prefix {ENV_DIR} || npm install --prefix {ENV_DIR}",
    "pnpm": f"corepack enable && pnpm install --frozen-lockfile --dir {ENV_DIR}",
    # **`fetch`, not `build`.** The crates have to be on disk before the network goes away;
    # compiling them here would bake artefacts keyed to a source tree that does not exist yet.
    # `CARGO_HOME` is `ENV_DIR/cargo`, which the mount does not touch, and `cargo test` finds them
    # there at attempt time because the same variable is exported for the login shell.
    # **The `src/lib.rs` is not a mistake.** Cargo refuses to read a manifest with no target —
    # *"either src/lib.rs, src/main.rs, a [lib] section, or [[bin]] section must be present"* — and
    # the build context holds only the dependency files, never the source. A placeholder lets it
    # resolve and fetch; the worktree mount replaces the whole directory at attempt time, so
    # nothing of it survives into the phase. Measured on `dtolnay/anyhow`, exit 101.
    #
    # **`rustup show` first, and it is the pin doing the work.** A repository that carries a
    # `rust-toolchain.toml` makes every `cargo` call ask rustup for that channel — which downloads
    # it, into a `/usr/local/rustup` that is read-only at attempt time and unreachable with no
    # network. Installing it here, where both are still true, means the phase finds it already
    # there. Measured on `dtolnay/anyhow`: *"could not create temp file … Read-only file system"*.
    #
    # **`CARGO_NET_OFFLINE=false` on this line, and only on this line.** The variable is set for
    # the *phase*, where there is no network and the cache is all there is — and it is baked as an
    # `ENV`, so it applied to this `RUN` too and turned the fetch itself offline. The build is the
    # one moment that has a network; overriding it here is narrower than a second table.
    "cargo": ("mkdir -p src && touch src/lib.rs && rustup show >/dev/null "
              "&& CARGO_NET_OFFLINE=false sh -c '(cargo fetch --locked || cargo fetch)' "
              "&& rm -f src/lib.rs"),
    # `--path` keeps the gems out of `/work/vendor`, where the mount would erase them. `--jobs 4`
    # because a serial bundle install on a cold cache is minutes.
    "bundle": f"bundle config set --local path {ENV_DIR}/gems && bundle install --jobs 4",
    # The module cache, which `go test` reads through `GOMODCACHE`. `go mod download` needs only
    # `go.mod` and `go.sum`, which is exactly what a dependency declaration carries.
    "go mod": "go mod download",
    # Hex's cache and the compiled deps, both outside the mount. `--only` is deliberately absent:
    # the test environment is the one this image exists to run.
    "mix": "mix local.hex --force && mix local.rebar --force && mix deps.get && mix deps.compile",
    # **The recipe brings its own tool**, the way `uv` and `poetry` do — the official `php` image
    # ships PHP and no Composer, so this was `composer: not found`, exit 127 (item 113). Same shape
    # as `eclipse-temurin` shipping a JDK and no Maven: a language image is not a build image.
    #
    # `--no-scripts` for the same reason `npm ci --ignore-scripts` is common in CI: a package's
    # install hook is arbitrary code, and this one runs as root at build time.
    "composer": "composer install --no-interaction --no-scripts --no-progress",
    # The one that most needs saying: `go-offline` is what makes `mvn test` work with no network,
    # and without it Maven tries to reach Central from inside a sandbox that has no route out.
    "maven": ("mvn -B -q dependency:go-offline -Dmaven.repo.local=" + ENV_DIR + "/m2 "
              "|| mvn -B dependency:go-offline -Dmaven.repo.local=" + ENV_DIR + "/m2"),
    "none": "",
}

#: Told to each installer, so what it installs lands in `ENV_DIR` and survives the mount.
#:
#: Node is the weakest of these and it is worth saying so: `NODE_PATH` resolves bare specifiers and
#: not relative ones, so a toolchain that reaches for `./node_modules` by hand is still unserved.
#: It is better than an empty directory and it is not a promise.
INSTALL_ENV: dict[str, dict[str, str]] = {
    # Nothing: `uv` exports and pips into the system site-packages, so there is no managed
    # environment to point at. A `UV_PROJECT_ENVIRONMENT` here would be dead configuration that
    # reads as if something depended on it.
    "uv": {},
    # Into the system site-packages rather than a managed virtualenv: outside `/work` either way,
    # and one fewer path to keep on `PATH`.
    "poetry": {"POETRY_VIRTUALENVS_CREATE": "false"},
    "npm": {"NODE_PATH": f"{ENV_DIR}/node_modules", "PATH": f"{ENV_DIR}/node_modules/.bin:$PATH"},
    "pnpm": {"NODE_PATH": f"{ENV_DIR}/node_modules", "PATH": f"{ENV_DIR}/node_modules/.bin:$PATH"},
    # `pip -r` installs into the system site-packages, which was never inside the mount. It is the
    # only configuration that worked before this item, and it needed no help.
    "pip": {},
    # **Each of these is read by the *test* command, not only by the installer** (item 112), so it
    # has to survive into the phase — which means `/etc/profile.d`, not just `ENV`. Item 111
    # measured why: a login shell resets `PATH`, and `ENV` alone is wiped.
    # `CARGO_NET_OFFLINE` is the one that makes the fetch worth anything: without it `cargo test`
    # re-reads the registry index at attempt time — where there is no network — even though every
    # crate it needs is already in `CARGO_HOME`. Measured on `dtolnay/anyhow`: *"Could not resolve
    # host: index.crates.io"* with a full cache sitting beside it.
    "cargo": {"CARGO_HOME": f"{ENV_DIR}/cargo", "PATH": f"{ENV_DIR}/cargo/bin:$PATH",
              "CARGO_NET_OFFLINE": "true"},
    "bundle": {"BUNDLE_PATH": f"{ENV_DIR}/gems", "BUNDLE_APP_CONFIG": f"{ENV_DIR}/bundle"},
    "go mod": {"GOMODCACHE": f"{ENV_DIR}/gomod", "GOFLAGS": "-mod=mod", "GOPATH": f"{ENV_DIR}/go"},
    "mix": {"MIX_HOME": f"{ENV_DIR}/mix", "HEX_HOME": f"{ENV_DIR}/hex",
            "MIX_DEPS_PATH": f"{ENV_DIR}/deps", "MIX_BUILD_PATH": f"{ENV_DIR}/build"},
    # **No `COMPOSER_VENDOR_DIR`** (item 114). Every other ecosystem here is pointed out of the
    # worktree because the mount would erase it; PHP cannot be, because `vendor/` is written into
    # `composer.json`, `phpunit.xml` and every `require` a project makes. So the vendor tree stays
    # where PHP expects it and survives instead: `install_needs_source` puts it in the image and the
    # attempt's volume is seeded from there before the checkout goes on top.
    "composer": {"COMPOSER_HOME": f"{ENV_DIR}/composer"},
    # **`MAVEN_CONFIG` too, and it is the one that is not obvious.** The official `maven` image
    # points it at `/root/.m2`, and a phase runs as uid 10001 — so `mvn` tries to create `/root`,
    # is refused, and the failure surfaces three layers away as `PluginResolutionException`. The
    # give-away was on stderr, under the Maven error: `mkdir: cannot create directory '/root'`.
    "maven": {"MAVEN_OPTS": f"-Dmaven.repo.local={ENV_DIR}/m2",
              "MAVEN_ARGS": f"-Dmaven.repo.local={ENV_DIR}/m2",
              "MAVEN_CONFIG": f"{ENV_DIR}/m2"},
    "none": {},
}

#: Recipes that install **into `ENV_DIR`** rather than into the worktree, so their dependency
#: files have to be copied there too — the installer reads them from its own prefix.
_INSTALLS_IN_ENV_DIR = frozenset({"npm", "pnpm"})

#: The tool a free-form install command drives, and the recipe whose environment it therefore
#: needs. Item 112.
#:
#: **A project's own command is still a `mvn` command.** `install` is free-form since item 068, and
#: `INSTALL_ENV` was keyed only by recipe name — so a manifest saying `mvn dependency:go-offline
#: -Pprofile` got **no** `MAVEN_OPTS`, resolved into a home directory that is a tmpfs at attempt
#: time, and threw the whole install away. Measured on `google/gson`, whose test command needs a
#: profile that the plain recipe cannot know about, so the only way to serve it is a command the
#: project writes — which is exactly the path that had no environment.
_INSTALL_FAMILIES: dict[str, str] = {
    "mvn": "maven", "bundle": "bundle", "cargo": "cargo", "go": "go mod",
    "mix": "mix", "composer": "composer", "npm": "npm", "pnpm": "pnpm",
}


def _family_env(command: str) -> dict[str, str]:
    """The environment for the tool a free-form install command drives, or nothing."""
    first = command.strip().split(" ", 1)[0]
    return dict(INSTALL_ENV.get(_INSTALL_FAMILIES.get(first, ""), {}))

IMAGE_PREFIX = "hullwork-sandbox"

#: Long enough that a collision is not a threat model, short enough to read in `docker images`.
TAG_LENGTH = 12

#: A build that has not finished by now is not going to. Separate from the attempt's own timeout
#: on purpose: a slow `npm ci` must not eat the time the agent was given to think.
BUILD_TIMEOUT_SECONDS = 900

#: How large a sandbox image may get before this instance says so. Item 068, DR-0007 part 3.
#:
#: **Checked after the build, and that is not a compromise — it is the only place the number
#: exists.** `docker build` takes no size limit; the layers are written as they are produced. So the
#: disk is already spent by the time this fires, and what it buys is that the *next* attempt does
#: not
#: spend it again, and that the operator is told which project did it.
#:
#: The item's own framing, and it is the right one: *"an install that fills the operator's disk is
#: their project's doing; hanging their host without saying anything would be Hullwork failing to do
#: what it promises."* The timeout above is the promise. This is the sentence.
#:
#: 8 GiB because a Python image with a scientific stack reaches 4, and a Node image with two
#: toolchains reaches 5. A number a legitimate project trips is one that gets removed, not raised.
BUILD_SIZE_LIMIT_BYTES = 8 * 1024**3


class ImageBuildError(RuntimeError):
    """The sandbox image could not be built. Carries the output, because that is the diagnosis.

    **And it threw that output away until 2026-08-05.** `SandboxError` — the class next door, with
    an identical `__init__` and the same sentence in its docstring — was given a `__str__` that
    shows the tail on 2026-08-04, after a stranger lost ten minutes to a message that hid Docker's
    own explanation. This one was not, so the docstring promised a diagnosis `str()` discarded.

    Found by rendering these errors as sentences at the CLI boundary, which made the omission
    visible: `could not build the sandbox image: base 'no-such-image', install 'none', packages
    none` never said that the image does not exist, though Docker had.

    The tail rather than the whole, at the same 25-line convention: the cause of a failed `docker`
    call is at the end, and a build's output is long enough to bury it.
    """

    def __init__(self, message: str, output: str = "") -> None:
        super().__init__(message)
        self.output = output

    def __str__(self) -> str:
        message = super().__str__()
        tail = "\n".join(self.output.strip().splitlines()[-25:])
        return f"{message}\n{tail}" if tail else message


@dataclass(frozen=True)
class SandboxImage:
    """A built image, and enough about it to explain itself in an evidence trail."""

    tag: str
    base: str
    installer: str
    #: What went into the tag. A reviewer asking "why did this rebuild?" gets an answer.
    dependency_files: tuple[str, ...]
    reused: bool = False


def dependency_digest(files: dict[str, bytes]) -> str:
    """A digest of the pinned dependencies, order-independent.

    This is the whole caching story: the tag *is* the content, so the image is reused while the
    lockfile is unchanged and rebuilt the moment it is not. Nothing has to remember to invalidate
    anything, which is the only kind of invalidation that stays correct.
    """
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(files[path]).digest())
    return digest.hexdigest()


def image_tag(
    runtime: RuntimeConfig,
    files: dict[str, bytes],
    engine: "Engine | None" = None,
    source_ref: str | None = None,
) -> str:
    """The tag this runtime, these dependency files and this engine recipe produce.

    Deterministic across hosts, and the engine is in it: a changed recipe must not silently reuse an
    image built from the previous one. `None` means an image with no harness in it, which is what
    the gates alone need and what the tests of this module describe.
    """
    digest = hashlib.sha256()
    digest.update(runtime.base.encode())
    digest.update(b"\0")
    digest.update(runtime.install.encode())
    digest.update(b"\0")
    # In the tag, or two projects differing only in packages share an image and the second silently
    # gets the first's (item 053). That is the shape of silent failure this project keeps finding.
    digest.update(",".join(sorted(set(runtime.packages))).encode())
    digest.update(b"\0")
    digest.update(dependency_digest(files).encode())
    if engine is not None:
        digest.update(b"\0")
        digest.update(engine.fingerprint().encode())
    # **And the instructions themselves** (item 111). Everything above describes what the *caller*
    # asked for; none of it changes when **Hullwork's own recipe** does. Measured: the fix that puts
    # the base image's `PATH` where a login shell reads it changed the generated Dockerfile and not
    # one byte of this key, so the next build reused the broken image and reported success — the
    # deploy looked applied and `go` was still not found.
    #
    # Exactly the defect item 065 fixed for the harness bundle, in its own words: *anything the
    # bundle contains belongs in the name that claims to describe it*. This is the same sentence
    # about the image, and it is now true of both.
    #
    # **The generated text, not a version somebody remembers to bump.** A constant here would work
    # until the first author who forgot, and the failure it produces is silent reuse of a stale
    # image — which is the failure being fixed. `dockerfile` takes the same two arguments and is a
    # pure function of them, so hashing what it emits costs a string and cannot go stale.
    digest.update(b"\0")
    digest.update(dockerfile(runtime, engine).encode())
    if runtime.install_needs_source:
        # **The commit, because the source is in the image** (item 113). Everything above describes
        # the declaration; when the tree itself is baked in, the tree is part of what the tag
        # claims to describe — and a commit names a tree exactly, for free. Without this the second
        # attempt on a project would reuse an image built from the first one's code.
        digest.update(b"\0")
        digest.update((source_ref or "unknown-source").encode())
    return f"{IMAGE_PREFIX}:{digest.hexdigest()[:TAG_LENGTH]}"


def dockerfile(runtime: RuntimeConfig, engine: "Engine | None" = None) -> str:
    """Generate the Dockerfile. Never read one from the repository.

    A repository's own Dockerfile is written to ship that project, not to sandbox it: it may run as
    root, may install a shell's worth of tooling, and is a file the agent could later edit. What
    goes in here is decided by the instance and by nothing else.

    **The engine's recipe goes on top of the project's base** (operator decision, 2026-07-28,
    amending DR-0004). There is one container per attempt, so the harness and the project's
    dependencies have to be in the same image: with a separate engine image the reproduce phase
    looked for `claude` inside `python:3.12-slim` and exited 127, measured on the first real run of
    `hullwork work`. Putting it the other way round — the project on top of the harness — would make
    `base: python-3.12` a promise the harness's own base decides.

    The harness layer is placed **before** the dependency layer so that a lockfile change does not
    reinstall it.
    """
    # **Sugar, not a gate** (item 068, DR-0007 part 3). A short name resolves to the image this
    # instance recommends; anything else is already an image reference, validated as one by the
    # manifest. The closed set used to be the security property and the grammar is now — a `base`
    # cannot contain a newline, so it cannot escape the `FROM` line it is written into.
    base = BASE_IMAGES.get(runtime.base, runtime.base)
    lines: list[str] = []
    # A **mounted** engine contributes nothing to the image (item 065). It arrives as a read-only
    # volume in the agent's phases instead, so the project's image carries none of Hullwork's own
    # software — which is what makes the base image's libc irrelevant, and what stops a new harness
    # version from invalidating every registered project's cached image.
    baked = engine is not None and not engine.mounted
    if baked and engine is not None:
        lines += list(engine.stages)
    lines.append(f"FROM {base}")
    if baked and engine is not None:
        lines += list(engine.steps)
    lines += [
        # A non-root user, created here so the runtime does not have to invent a uid. The agent
        # writes to the mounted worktree and to tmpfs, and to nothing else.
        "RUN useradd --create-home --uid 10001 hullwork || adduser -D -u 10001 hullwork",
        # **The base image's own `PATH`, kept where a login shell will find it** (item 111).
        #
        # Every phase runs `sh -lc`, and Debian's `/etc/profile` sets `PATH` unconditionally — so
        # an image's `ENV PATH` is wiped before the command runs. Item 051 found this for the
        # variables *Hullwork* adds and re-exported those; it never occurred to anyone that the
        # **base image's** own toolchain arrives the same way. Measured 2026-08-01 on `golang`:
        #
        #     sh -c  → /go/bin:/usr/local/go/bin:…   command -v go → /usr/local/go/bin/go
        #     sh -lc → /usr/local/sbin:/usr/local/bin:…   go: not found
        #
        # So `gorilla/mux` built a perfect image and step 0 died with `exit 127`. Python and Node
        # survived only because their binaries land in `/usr/local/bin`, which Debian's default
        # list happens to contain — which is to say the sandbox worked for exactly the two stacks
        # the closed sets used to allow, and "any stack" was broken here rather than in the reader.
        #
        # `$PATH` inside a `RUN` is the image's own, because `RUN` is not a login shell. So this
        # captures whatever the base declares without anybody having to know what it is: Go, Rust,
        # Elixir, Java, and whatever ships next year.
        #
        # Named to sort **before** `hullwork-env.sh`, which prepends to `$PATH` and would otherwise
        # be overwritten by this one.
        "RUN mkdir -p /etc/profile.d "
        "&& printf 'export PATH=%s\\n' \"$PATH\" > /etc/profile.d/hullwork-base-path.sh",
        f"WORKDIR {WORKDIR}",
    ]
    if runtime.install == "composer":
        # **The recipe brings its own tool, and for Composer the tool is a binary in another
        # image** (item 113). The official `php` image ships PHP and no Composer, so this was
        # `composer: not found` — the same shape as `eclipse-temurin` shipping a JDK and no Maven.
        # `COPY --from` an image reference is Docker's own answer and it needs no network fetch, no
        # installer script and no quoting inside a `RUN`, which the first attempt at this did need
        # and got wrong.
        lines.append("COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer")
    if runtime.packages:
        # Before the dependency install, because a dependency that compiles needs its tools present.
        # One layer, lists cleaned: an image that carries apt's index is an image that is bigger for
        # nothing.
        # `SYSTEM_PACKAGES` is an alias table now, not an allow-list: a name it knows resolves to
        # whatever the distribution actually calls it, and a name it does not is that name already.
        # The grammar (`PACKAGE_NAME`) is what stops `-o` reaching an installer as a flag.
        named = " ".join(
            SYSTEM_PACKAGES.get(p, p) for p in sorted(set(runtime.packages))
        )
        lines.append(f"RUN {install_packages(named)}")
    if runtime.install != "none" and runtime.dependencies:
        # **Where the installer will look for them, which is not always the worktree** (item 111).
        # The `npm` and `pnpm` recipes install with `--prefix ENV_DIR`, and npm reads the
        # `package.json` **in the prefix** — so copying it to `/work` and installing into
        # `/opt/hullwork-env` asks npm to install a project it cannot see. Measured on
        # `expressjs/express`: `npm ci --prefix /opt/hullwork-env` exits 254 on an empty directory.
        #
        # This recipe had never run against a real Node project. Every project this instance has
        # ever built is Python, so the table entry has been wrong since item 051 wrote it and
        # nothing could notice — which is what the eight-repository measurement is for.
        into = ENV_DIR if runtime.install in _INSTALLS_IN_ENV_DIR else WORKDIR
        if runtime.install_needs_source:
            # **The whole tree, because the installer reads it** (item 113). Three real projects
            # cannot be built any other way, and each fails differently: a gemspec reads the
            # library it describes, `-e .` installs the project, and `mvn test` in a directory of
            # bare poms finds no tests — so Surefire never resolves the provider the attempt needs.
            # The cost is a rebuild per attempt, which is why the manifest has to ask for it.
            lines.append(f"COPY . {WORKDIR}")
        else:
            for path in runtime.dependencies:
                lines.append(f"COPY {path} {into}/{PurePosixPath(path).name}"
                             if into != WORKDIR else f"COPY {path} {path}")
        # `.get`, because `install` is any command since item 068 and this table only knows the six
        # recipes. A project with its own command sets whatever environment that command needs;
        # this instance has nothing to add for a recipe it has never seen. Missed on the first pass
        # and found by a test: the fourth table indexed with `[]` where three had been opened.
        env = dict(INSTALL_ENV.get(runtime.install) or _family_env(runtime.install))
        where = PurePosixPath(runtime.dependencies[0]).parent
        if runtime.base.startswith("python"):
            # The project's **own** package, found at attempt time. No source is baked into the
            # image — it changes every attempt, and baking it in would rebuild for every fix — so
            # the package has to be importable from the mount instead. Both the src-layout and
            # the flat one, because a builder cannot know which, and a path that does not exist
            # costs nothing here. Without it, `pytest` collected and then failed on a
            # `ModuleNotFoundError` for the project itself.
            root = f"{WORKDIR}/{where}" if str(where) != "." else WORKDIR
            env["PYTHONPATH"] = f"{root}/src:{root}"
        for name, value in env.items():
            lines.append(f"ENV {name}={value}")
        if env:
            # **And again where a login shell will read it.** `run.py` runs every phase with
            # `sh -lc`, and Debian's `/etc/profile` sets `PATH` unconditionally — so an `ENV PATH`
            # baked into the image is wiped before the command runs. Measured: `sh -c` keeps
            # `/opt/hullwork-env/bin`, `sh -lc` does not. The image would build, the environment
            # would be there, and every gate would run without it on `PATH` (item 051).
            exports = " ".join(f"export {name}={value};" for name, value in env.items())
            lines.append(
                f"RUN mkdir -p /etc/profile.d && printf '%s\\n' '{exports}' "
                f"> /etc/profile.d/hullwork-env.sh"
            )
        # **In the directory the dependency files are in**, not at the repository root. A project
        # under `backend/` is most projects of any size, and running the installer from `/work` made
        # every one of them unbuildable: `uv sync` looked for a `pyproject.toml` that was one
        # directory down. Measured against a real tree, exit code 2 (item 051).
        where = PurePosixPath(runtime.dependencies[0]).parent
        install_dir = f"{WORKDIR}/{where}" if str(where) != "." else WORKDIR
        if install_dir != WORKDIR:
            lines.append(f"WORKDIR {install_dir}")
        # A recipe by name, or the project's own command. `{first}` is only substituted for a recipe
        # — a project that wrote its own command wrote the filename it wants, and `str.format` on an
        # arbitrary string would turn any brace in it into an error or a substitution nobody asked
        # for.
        recipe = INSTALL_COMMANDS.get(runtime.install)
        command = (
            recipe.format(first=PurePosixPath(runtime.dependencies[0]).name)
            if recipe is not None
            else runtime.install
        )
        lines.append(f"RUN {command}")
        # **The installer runs as root and the phase does not** (item 112). Anything under
        # `ENV_DIR` that the *test command* has to write into is therefore unwritable: measured on
        # `elixir-ecto/ecto`, where `mix test` compiles into `MIX_BUILD_PATH` and died in
        # `File.mkdir_p!`. Read-only would be fine for a cache; a build directory is not a cache.
        # The uid is the one the phase runs as, the same number `ensure_volume` chowns the worktree
        # to — and it is spelled here rather than assumed, because nothing else would notice if the
        # two drifted apart.
        lines.append(f"RUN chown -R {SANDBOX_UID}:{SANDBOX_GID} {ENV_DIR} 2>/dev/null || true")
        if install_dir != WORKDIR:
            lines.append(f"WORKDIR {WORKDIR}")
    lines += [
        "USER hullwork",
        # No CMD: the dispatcher supplies the command for each phase, and an image with a default
        # entry point is an image that does something when somebody runs it by accident.
        "",
    ]
    return "\n".join(lines)


def build(
    runtime: RuntimeConfig,
    files: dict[str, bytes],
    engine: "Engine | None" = None,
    *,
    source: Path | None = None,
    source_ref: str | None = None,
    docker: str = "docker",
    timeout: int = BUILD_TIMEOUT_SECONDS,
) -> SandboxImage:
    """Build the image, or return the one that already matches. Raises `ImageBuildError`.

    The build context is a temporary directory holding the generated Dockerfile, the declared
    dependency files and whatever the engine recipe needs — **not** the repository. That keeps the
    context tiny, keeps the layer cache useful, and means the repository's own `.dockerignore` and
    Dockerfile have no say in it.
    """
    # **A declared dependency file that is not there, said by name** (item 111). The Dockerfile
    # emits `COPY <path>` for each one, so a manifest naming a file the repository does not have
    # fails at build with buildkit's own words — *"failed to compute cache key: … not found"*,
    # under a ref hash, with the manifest never mentioned. Measured on `sinatra/sinatra`, whose
    # `Gemfile.lock` is deliberately not committed and which the reader proposed anyway.
    missing = [path for path in runtime.dependencies if path not in files]
    if runtime.install != "none" and missing and not runtime.install_needs_source:
        msg = (
            f"the manifest declares dependency file(s) this repository does not have: "
            f"{', '.join(missing)}. They are the build's cache key and are copied into the image, "
            f"so the build cannot start. Remove them from runtime.dependencies, or commit them."
        )
        raise ImageBuildError(msg)
    tag = image_tag(runtime, files, engine, source_ref)
    if _exists(tag, docker=docker):
        log.info("reusing sandbox image", extra={"tag": tag})
        return SandboxImage(
            tag=tag,
            base=runtime.base,
            installer=runtime.install,
            dependency_files=tuple(runtime.dependencies),
            reused=True,
        )

    with tempfile.TemporaryDirectory(prefix="hullwork-build-") as context:
        root = Path(context)
        if runtime.install_needs_source and source is not None:
            # Copied rather than used in place: the context also holds the Dockerfile and whatever
            # the engine recipe needs, and writing those into somebody's checkout is not on.
            # `.git` is excluded for the reason item 023 gives — a token in a clone URL lives in
            # `.git/config` — and because history is not a dependency.
            shutil.copytree(
                source, root, dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(".git", "node_modules", ".venv", "target", "_build"),
            )
        (root / "Dockerfile").write_text(dockerfile(runtime, engine), encoding="utf-8")
        for path, content in files.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        for path, text in (engine.files if engine else {}).items():
            # Never under a subdirectory: a recipe file is copied by name from the context root, and
            # a path with a separator in it would be the recipe reaching outside what it declared.
            if "/" in path or path in {"", ".", ".."}:
                msg = f"the engine recipe declares an unusable context file name: {path!r}"
                raise ImageBuildError(msg)
            (root / path).write_text(text, encoding="utf-8")

        completed = _run(
            [docker, "build", "--tag", tag, "--file", str(root / "Dockerfile"), str(root)],
            timeout=timeout,
        )

    if completed.returncode != 0:
        # **stderr, not just stdout.** `docker build` writes everything — including the failing
        # step and its output — to stderr, so this class's promise to carry the diagnosis was empty
        # in the one case it exists for. Found by hitting a real build failure and getting a
        # message with nothing after the colon.
        #
        # **And it names all three declarations** (item 068). Now that a base is any image
        # reference,
        # an install is any command and a package is any apt name, a failed build is the common
        # failure mode rather than an exotic one — and "could not build the image for base X" sends
        # an
        # operator to look at the one declaration least likely to be wrong. The three of them, in
        # the
        # sentence, cost nothing.
        raise ImageBuildError(
            f"could not build the sandbox image: base {runtime.base!r}, install "
            f"{runtime.install!r}, packages {sorted(set(runtime.packages)) or 'none'}",
            (completed.stdout or "") + (completed.stderr or ""),
        )
    _refuse_an_image_that_fills_the_disk(docker, tag, runtime)
    log.info("built sandbox image", extra={"tag": tag, "base": runtime.base})
    return SandboxImage(
        tag=tag,
        base=runtime.base,
        installer=runtime.install,
        dependency_files=tuple(runtime.dependencies),
    )


#: The three package managers that cover essentially every Linux base image in use, and the order
#: they
#: are probed in. Item 109, DR-0007's amendment.
#:
#: **Three is not the closed set DR-0007 killed.** The arithmetic that decision called inviable was
#: *"every package of every project of every self-hoster"*; this is three installers. Hullwork still
#: knows nothing about **which** packages a project needs and learns only **how** to install one, on
#: a
#: set that is bounded, stable and language-neutral. A project on Nix or on anything else keeps the
#: two
#: better paths: bring an image, or put its own line in `install`, which is free-form since item
#: 068.
#:
#: Measured before this existed: `FROM alpine:3.20` with one declared package failed the build with
#: `exit code: 127` — `apt-get: not found`. The installer was the one Debian-shaped thing left, and
#: it
#: was the field item 068 opened with the most confidence.
PACKAGE_MANAGERS: tuple[tuple[str, str], ...] = (
    # Lists cleaned in the same layer: an image carrying apt's index is bigger for nothing.
    ("apt-get", "apt-get update && apt-get install -y --no-install-recommends {packages} "
                "&& rm -rf /var/lib/apt/lists/*"),
    # `--no-cache` does both halves at once on Alpine: no index written, nothing to clean.
    ("apk", "apk add --no-cache {packages}"),
    # Fedora, RHEL and their derivatives. `-y` for the same reason as apt's.
    ("dnf", "dnf install -y {packages} && dnf clean all"),
)


def install_packages(named: str) -> str:
    """One shell line that installs `named` on whichever of the three managers the image has.

    **A probe rather than three code paths**, because the generator cannot know what the base image
    is: since item 068 `base` is any image reference, and asking Docker what is inside it before
    writing the Dockerfile would mean pulling it to answer what the build is about to answer anyway.

    The failure names the three it looked for. That matters more here than in most places: a build
    failure is the common failure mode now that a user can name anything (DR-0007 lists it among the
    costs), and *"apt-get: not found"* on an Alpine base is a message about the wrong subject.
    """
    branches = [
        f"if command -v {binary} >/dev/null 2>&1; then {recipe.format(packages=named)}; "
        for binary, recipe in PACKAGE_MANAGERS[:1]
    ]
    branches += [
        f"elif command -v {binary} >/dev/null 2>&1; then {recipe.format(packages=named)}; "
        for binary, recipe in PACKAGE_MANAGERS[1:]
    ]
    looked_for = ", ".join(binary for binary, _ in PACKAGE_MANAGERS)
    branches.append(
        f'else echo "hullwork: this image has none of {looked_for}, so the packages it was asked '
        f'to install ({named}) cannot be installed. Name an image that has one, or put your own '
        f'install line in runtime.install." >&2; exit 1; fi'
    )
    return "".join(branches)


@dataclass(frozen=True)
class BaseFacts:
    """What can be read off a base image before anything is built. Item 108.

    Three answers, and the third keeps this honest: `checked` is `False` when **Docker could not be
    asked**, the ordinary case on the receiver — it holds no socket by design (DR-0009). A
    precondition that cannot tell "wrong" from "not asked" would either refuse every registration
    made from the receiver or claim to have checked what it did not, and item 105 was closed for the
    second of those two hours earlier.
    """

    checked: bool
    #: `None` when the image was readable but declared none.
    architecture: str | None = None
    #: **Only meaningful once `architecture` agrees with the host's.** Measured in production:
    #: `arm64v8/alpine:3.20` on an amd64 host has a perfectly good `/bin/sh` and the probe still
    #: fails, with `exec format error` — so a caller reading this field first refuses an image for
    #: the wrong reason. `cli` checks the architecture before it reads this, and says why there.
    has_shell: bool | None = None
    #: Why it could not be checked, for the sentence the caller prints.
    why_not: str = ""


def inspect_base(
    base: str, *, docker: str = "docker", pull: bool = False, timeout: int = 300
) -> BaseFacts:
    """Read a base image's architecture, and whether it has a shell. Item 108.

    **Both were measured as inscrutable failures before this existed.** A `distroless` image fails
    at the first `RUN` with `exit code: 1` and a message blaming `useradd`, when what is missing is
    `/bin/sh`; an image for another architecture fails at run time with the same misleading *"not
    found"* DR-0007 explains at length for musl. Neither says what is wrong.

    **`pull` is off by default, and that was measured too.** The first version pulled a missing
    image, on the argument that the build was going to pull it anyway. What it actually did was turn
    `projects add` into a command that downloads a few hundred megabytes with no output — the
    existing test that registers a project stopped finishing, which is the same experience an
    operator would have had. A registration command reads; it does not fetch. So a missing image is
    the third answer, `checked=False`, and it names the pull the operator can do first.
    """
    if shutil.which(docker) is None:
        return BaseFacts(
            checked=False,
            why_not="no Docker client on PATH, which is normal on the receiver: it holds no socket",
        )
    # **The daemon is asked before the image, and that ordering is a deployment finding.** The
    # receiver's image *does* carry the docker binary and *does not* carry the socket, so every
    # command fails — and reading the image's failure alone, this reported "the image is not on
    # this host yet" about a host it could not talk to. A client on PATH is not a reachable daemon,
    # and saying the wrong reason is the defect this whole check exists to stop.
    reachable = _run([docker, "version", "--format", "{{.Server.Arch}}"], timeout=60)
    if reachable.returncode != 0:
        detail = ((reachable.stderr or "") + (reachable.stdout or "")).strip().splitlines()
        return BaseFacts(
            checked=False,
            why_not="the Docker daemon cannot be reached from here, which is normal on the "
            f"receiver: it holds no socket by design "
            f"({detail[0] if detail else 'no reason given'})",
        )
    resolved = BASE_IMAGES.get(base, base)
    present = _run([docker, "image", "inspect", resolved, "--format", "{{.Architecture}}"],
                   timeout=60)
    if present.returncode != 0:
        if not pull:
            return BaseFacts(
                checked=False,
                why_not=f"{resolved} is not on this host yet, and registering a project is not a "
                f"reason to download it (`docker pull {resolved}` first for the answer now)",
            )
        pulled = _run([docker, "pull", "--quiet", resolved], timeout=timeout)
        if pulled.returncode != 0:
            detail = ((pulled.stderr or "") + (pulled.stdout or "")).strip().splitlines()
            return BaseFacts(
                checked=False,
                why_not=f"{resolved} could not be pulled: "
                f"{detail[-1] if detail else 'no reason given'}",
            )
        present = _run([docker, "image", "inspect", resolved, "--format", "{{.Architecture}}"],
                       timeout=60)
        if present.returncode != 0:  # pragma: no cover - pulled and still unreadable
            return BaseFacts(
                checked=False, why_not=f"{resolved} was pulled and cannot be inspected"
            )

    architecture = (present.stdout or "").strip() or None
    # `sh -c` and not `--version`: what every phase needs is a shell, and the only way to know an
    # image has one is to ask it for one.
    shell = _run([docker, "run", "--rm", "--entrypoint", "sh", resolved, "-c", "exit 0"],
                 timeout=120)
    return BaseFacts(checked=True, architecture=architecture, has_shell=shell.returncode == 0)


def host_architecture(docker: str = "docker") -> str | None:
    """What the daemon runs on, or `None` when it cannot be asked."""
    if shutil.which(docker) is None:
        return None
    answered = _run([docker, "version", "--format", "{{.Server.Arch}}"], timeout=60)
    return (answered.stdout or "").strip() or None if answered.returncode == 0 else None


def why_it_cannot_host_a_phase(
    base: str, *, docker: str = "docker", pull: bool = False
) -> tuple[str | None, str]:
    """`(refusal, note)` — the sentence that refuses this base image, or `None` and a note.

    **The sentences moved here because two doors needed them and only one had them.** `projects add`
    and `projects refresh` refused a shell-less or wrong-architecture base; `hullwork try` did
    not, and `try` is the door the README sends a stranger to first. Measured 2026-08-05 against
    the published wheel: a manifest declaring `distroless` spent minutes building and then failed
    with a **Python traceback** ending in *"could not build the sandbox image: base 'distroless',
    install 'none', packages none"* — verbatim the inscrutable failure `BaseFacts` above says this
    check exists to prevent.

    That is the fourth time this shape has appeared: the refusal existed, correct and well worded,
    on a path that could not reach it. Item 048 found it for the engine name, on this same
    command, and the comment it left in `trial.run` describes today exactly.

    **The architecture is read before the shell, and the order is a measured defect rather than
    taste.** `arm64v8/alpine:3.20` on an amd64 host *has* a shell and the probe for one fails
    anyway with `exec format error` — so reading the fields in the other order refuses an image for
    a reason that is not true (item 105).

    **"Not checked" is a third answer.** Docker is unreachable from the receiver by design, so a
    check that could not tell *wrong* from *not asked* would refuse every registration made from the
    right place. The note is for the caller to print; it is not a refusal.

    **`pull` is the caller's decision, and the two callers differ on purpose.** `inspect_base`
    explains why registration must not fetch: it made `projects add` a silent download of a few
    hundred megabytes. But an image that is not on the host yet is `checked=False`, so on a fresh
    machine this check refuses nothing at all — measured 2026-08-05, twice, against a real
    `gcr.io/distroless/python3-debian12`, which reached the build and produced the traceback anyway.
    `try` is *about to build*, which pulls regardless, so there it costs nothing and buys the
    sentence. Registration still only reads.
    """
    facts = inspect_base(base, docker=docker, pull=pull)
    if not facts.checked:
        return None, (
            f"Not checked here: whether {base} has a shell and matches this host's architecture — "
            f"{facts.why_not}. The build where the dispatcher runs is what establishes both; a "
            f"failure there will name whichever one it was."
        )
    host = host_architecture(docker)
    if facts.architecture and host and facts.architecture != host:
        return (
            f"runtime.base: {base} is built for {facts.architecture} and this host runs "
            f"{host}. The harness bundle is built per architecture, so a mismatch fails inside "
            f"the sandbox with a misleading \"not found\" about the executable. Name an image "
            f"for {host}, or run this instance on {facts.architecture}."
        ), ""
    if facts.has_shell is False:
        return (
            f"runtime.base: {base} has no shell, so it cannot host a phase. Every phase runs "
            f"`sh -lc`, and the agent works by executing commands — so this is a permanent limit "
            f"rather than a gap: a `distroless` or `scratch` image cannot be used. Name one with a "
            f"shell, which any image your CI runs tests in already has."
        ), ""
    return None, ""


def _refuse_an_image_that_fills_the_disk(
    docker: str, tag: str, runtime: RuntimeConfig, *, limit: int = BUILD_SIZE_LIMIT_BYTES
) -> None:
    """Remove an image over the size bound, naming what produced it. Item 068.

    Removed rather than merely reported: leaving it means the operator pays for it once and then
    forgets, and the next rebuild pays again. An unreadable size is not a failure — `docker image
    inspect` not answering is the daemon's problem and has its own diagnosis.
    """
    reported = _run([docker, "image", "inspect", tag, "--format", "{{.Size}}"], timeout=30)
    if reported.returncode != 0:
        return
    try:
        size = int((reported.stdout or "").strip())
    except ValueError:
        return
    if size <= limit:
        return
    _run([docker, "image", "rm", "--force", tag], timeout=60)
    gib = size / 1024**3
    msg = (
        f"the sandbox image came out at {gib:.1f} GiB, over this instance's "
        f"{limit / 1024**3:.0f} GiB "
        f"bound, and has been removed. What produced it: base {runtime.base!r}, install "
        f"{runtime.install!r}, packages {sorted(set(runtime.packages)) or 'none'}. Narrow one of "
        f"them, or raise HULLWORK_BUILD_SIZE_LIMIT_GIB if this project really is that big."
    )
    raise ImageBuildError(msg)


def compare_with_production(
    image_packages: dict[str, str], event_packages: dict[str, str]
) -> dict[str, tuple[str, str]]:
    """Where the sandbox and the failing process disagree, by package.

    Free once item 036 lands: a fetched event carries 33 to 71 pinned versions from the process
    that actually broke. A reproduction attempted against different versions than production is not
    wrong, but it is a fact the reviewer needs — and it is the first thing to suspect when a bug
    refuses to reproduce.
    """
    return {
        name: (image_packages[name], version)
        for name, version in event_packages.items()
        if name in image_packages and image_packages[name] != version
    }


def _exists(tag: str, *, docker: str = "docker") -> bool:
    return _run([docker, "image", "inspect", tag], timeout=30).returncode == 0


def _run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    if shutil.which(command[0]) is None:
        raise ImageBuildError(
            f"{command[0]!r} is not on PATH. The dispatcher needs the Docker daemon; the service "
            f"does not (spec M2 §1)."
        )
    try:
        return subprocess.run(  # noqa: S603 - argv list, no shell, binary resolved above
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        message = f"the build did not finish within {timeout}s"
        raise ImageBuildError(message, str(exc.stdout)) from exc
