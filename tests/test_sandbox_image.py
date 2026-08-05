"""Building the sandbox, which is the floor the whole dispatcher stands on.

Before item 037 there was no image anywhere: `autofix.sandbox` said `docker`, which is a
technology. `pytest` had nothing to run inside, so step 0 — the baseline that must pass before the
model is ever called — could not pass for any project.
"""

import pytest

from hullwork.manifest import Installer, ManifestError, RuntimeConfig, SandboxBase
from hullwork.sandbox.image import (
    BASE_IMAGES,
    IMAGE_PREFIX,
    TAG_LENGTH,
    ImageBuildError,
    build,
    compare_with_production,
    dockerfile,
    image_tag,
    why_it_cannot_host_a_phase,
)

DEPS = {"pyproject.toml": b"[project]\nname='x'\n", "uv.lock": b"version = 1\n"}


def _runtime(**kw: object) -> RuntimeConfig:
    defaults: dict[str, object] = {
        "base": "python-3.12", "install": "uv", "dependencies": ["pyproject.toml", "uv.lock"]
    }
    defaults.update(kw)
    return RuntimeConfig(**defaults)  # type: ignore[arg-type]


def test_every_base_the_manifest_accepts_can_actually_be_built() -> None:
    """A base a manifest may name and this module cannot map is a `KeyError` at attempt time."""
    for base in ("python-3.12", "python-3.13", "node-22", "node-24"):
        assert base in BASE_IMAGES
        assert dockerfile(_runtime(base=base, install="none", dependencies=[])).startswith("FROM ")


def test_the_tag_is_the_content() -> None:
    """Reuse and invalidation both fall out of this, so nothing has to remember to invalidate."""
    runtime = _runtime()

    assert image_tag(runtime, DEPS) == image_tag(runtime, dict(reversed(list(DEPS.items()))))
    assert image_tag(runtime, DEPS).startswith(f"{IMAGE_PREFIX}:")
    assert len(image_tag(runtime, DEPS).split(":")[1]) == TAG_LENGTH


def test_a_changed_lockfile_is_a_different_image() -> None:
    changed = {**DEPS, "uv.lock": b"version = 2\n"}

    assert image_tag(_runtime(), DEPS) != image_tag(_runtime(), changed)


def test_a_changed_base_or_installer_is_a_different_image() -> None:
    assert image_tag(_runtime(), DEPS) != image_tag(_runtime(base="python-3.13"), DEPS)
    assert image_tag(_runtime(), DEPS) != image_tag(
        _runtime(install="poetry", dependencies=["pyproject.toml", "uv.lock"]), DEPS
    )


def test_the_project_itself_is_never_installed() -> None:
    """Only its dependencies. The source is mounted per attempt and changes between them.

    This asserted the literal `--no-install-project`, which item 051 replaced with
    `--no-emit-project` on a `uv export` — extras belong to the project, so the old flag could never
    install them and a real project came out without `pytest`. The property is the same and it is
    what is asserted now: the project is excluded, and no source is copied in.
    """
    text = dockerfile(_runtime())

    assert "-project" in text
    assert "COPY . " not in text


def test_the_container_does_not_run_as_root() -> None:
    text = dockerfile(_runtime())

    assert text.rstrip().endswith("USER hullwork")


def test_there_is_no_default_command() -> None:
    """The dispatcher supplies one per phase; an image with an entry point does something when
    somebody runs it by accident."""
    text = dockerfile(_runtime())

    assert "CMD" not in text
    assert "ENTRYPOINT" not in text


def test_nothing_from_the_repository_decides_what_is_installed() -> None:
    """Item 017 on a new surface: the manifest names a base, and the command is ours.

    A repository that could name an image would be choosing what this host pulls and runs, which is
    supplying with extra steps.
    """
    text = dockerfile(_runtime(base="python-3.12", install="pip", dependencies=["req.txt"]))

    assert "pip install --no-cache-dir -r req.txt" in text
    assert BASE_IMAGES["python-3.12"] in text


def test_only_the_declared_files_are_copied() -> None:
    text = dockerfile(_runtime())

    assert text.count("COPY ") == 2
    assert "COPY pyproject.toml pyproject.toml" in text


def test_no_install_means_no_install_step() -> None:
    text = dockerfile(_runtime(install="none", dependencies=[]))

    assert "COPY" not in text
    assert "RUN pip" not in text


def test_a_mismatch_with_production_is_reported_per_package() -> None:
    """Free once item 036 lands, and the first thing to suspect when a bug will not reproduce."""
    mismatch = compare_with_production(
        {"fastapi": "0.140.1", "sqlalchemy": "2.0.51", "extra": "1.0"},
        {"fastapi": "0.139.0", "sqlalchemy": "2.0.51", "unknown": "9.9"},
    )

    assert mismatch == {"fastapi": ("0.140.1", "0.139.0")}


@pytest.mark.parametrize("installer", ["pip", "uv", "poetry", "npm", "pnpm", "none"])
def test_every_installer_the_manifest_accepts_has_a_command(installer: str) -> None:
    from hullwork.sandbox.image import INSTALL_COMMANDS

    assert installer in INSTALL_COMMANDS


# --- the engine recipe goes on top of the project's base (item 047, operator 2026-07-28) ---------


def test_the_project_s_image_contains_none_of_hullwork_s_software() -> None:
    """**Replaces an assertion about where the harness is installed** (item 065, DR-0007).

    That assertion existed for a measured reason: on the first real run of `hullwork work`, a
    separate engine image meant the reproduce phase looked for `claude` inside `python:3.12-slim`
    and exited 127, so the harness and the project's pinned dependencies had to share one image.
    **That property still holds** — one container per attempt, harness in it — but it is now met by
    mounting rather than by installing, so the ordering it asserted no longer exists to assert.

    What replaces it is stronger, and is what DR-0007 is for: the image Hullwork builds for somebody
    else's project contains **nothing of ours**. That is what makes the project's base image, and
    its libc, irrelevant.
    """
    from hullwork.engine import REGISTRY

    text = dockerfile(
        _runtime(base="python-3.12", install="pip", dependencies=["req.txt"]),
        REGISTRY["claude-code"],
    )

    assert "FROM python:3.12-slim" in text
    assert "COPY req.txt" in text
    # Nothing of the harness: no auxiliary stage, no binary, no entrypoint of ours.
    assert "AS harness" not in text
    assert "claude" not in text
    assert "hullwork-agent" not in text
    assert "node" not in text
    # And still non-root at the end of it.
    assert text.rstrip().endswith("USER hullwork")


def test_an_image_with_no_engine_is_unchanged() -> None:
    """The gates alone need no harness, and the default must stay byte-for-byte what it was."""
    runtime = _runtime(base="python-3.12", install="pip", dependencies=["req.txt"])

    assert dockerfile(runtime) == dockerfile(runtime, None)
    assert "node" not in dockerfile(runtime)


def test_the_engine_is_part_of_the_tag() -> None:
    """A changed recipe must not silently reuse an image built from the previous one."""
    from hullwork.engine import REGISTRY

    runtime = _runtime()

    assert image_tag(runtime, DEPS) != image_tag(runtime, DEPS, REGISTRY["claude-code"])


def test_a_failed_build_carries_what_docker_printed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The class promises the output "because that is the diagnosis" and it was dropping it.

    `docker build` writes the failing step and its output to **stderr**, and only stdout was
    kept — so the one case this exists for produced a message with nothing after it. Found by
    hitting a real build failure: "could not build the sandbox image for base 'python-3.12'" and
    then silence.
    """
    import subprocess

    from hullwork.sandbox import image as image_module

    def _failed(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command, returncode=1, stdout="", stderr="dangling symlink at step 5"
        )

    monkeypatch.setattr(image_module, "_run", _failed)
    monkeypatch.setattr(image_module, "_exists", lambda tag, docker="docker": False)

    with pytest.raises(ImageBuildError) as err:
        build(_runtime(), DEPS)

    assert "dangling symlink at step 5" in err.value.output


# --- an image a real project can use (item 051) --------------------------------------------------


def test_the_install_runs_where_the_dependencies_are() -> None:
    """A project under `backend/` is most projects of any size, and every one was unbuildable.

    Measured against a real tree before this: `uv sync` ran in `/work`, the project was in
    `/work/backend`, exit code 2.
    """
    text = dockerfile(
        RuntimeConfig(base="python-3.12", install="uv", dependencies=["backend/uv.lock"])
    )

    lines = text.splitlines()
    install = next(i for i, line in enumerate(lines) if line.startswith("RUN pip install"))
    before = [line for line in lines[:install] if line.startswith("WORKDIR ")]

    assert before[-1] == "WORKDIR /work/backend"
    assert lines[-2] == "WORKDIR /work" or "WORKDIR /work" in lines[install:]


@pytest.mark.parametrize("install", ["uv", "poetry", "npm", "pnpm"])
def test_nothing_is_installed_under_the_mount(install: Installer) -> None:
    """`run.py` mounts the worktree over `/work`, so anything installed there is gone at attempt
    time. The image would build and the suite would run with nothing installed."""
    base: SandboxBase = "node-22" if install in {"npm", "pnpm"} else "python-3.12"
    dependency = "package-lock.json" if install in {"npm", "pnpm"} else "uv.lock"

    text = dockerfile(RuntimeConfig(base=base, install=install, dependencies=[dependency]))

    # `PYTHONPATH` deliberately points *into* the mount — that is where the project's own source
    # arrives — so the check is about install targets, not about every mention of `/work`.
    assert "/work/.venv" not in text
    assert "/work/node_modules" not in text
    assert ".venv" not in text or "/opt/" in text


def test_the_environment_is_published_where_a_login_shell_reads_it() -> None:
    """`run.py` runs every phase with `sh -lc`, and Debian's `/etc/profile` resets `PATH`.

    Measured: `sh -c` kept `/opt/hullwork-env/bin`, `sh -lc` did not. An `ENV PATH` alone is wiped
    before the gate command runs.
    """
    text = dockerfile(
        RuntimeConfig(base="node-22", install="npm", dependencies=["package-lock.json"])
    )

    assert "/etc/profile.d/hullwork-env.sh" in text


def test_a_python_project_can_import_itself() -> None:
    """Without this, `pytest` collected and then failed on the project's own package.

    No source is baked into the image — it changes every attempt — so the package has to be found on
    the mount. Both layouts, because a builder cannot know which.
    """
    text = dockerfile(
        RuntimeConfig(base="python-3.12", install="uv", dependencies=["backend/uv.lock"])
    )

    assert "ENV PYTHONPATH=/work/backend/src:/work/backend" in text


# --- tools the language runtime does not have (item 053) -----------------------------------------


def test_a_declared_package_is_installed_before_the_dependencies() -> None:
    """A dependency that compiles needs its tools present first."""
    text = dockerfile(
        RuntimeConfig(
            base="python-3.12", install="uv", dependencies=["uv.lock"], packages=["git"]
        )
    )

    lines = text.splitlines()
    apt = next(i for i, line in enumerate(lines) if "apt-get install" in line)
    install = next(i for i, line in enumerate(lines) if line.startswith("RUN pip install"))

    assert apt < install
    assert "--no-install-recommends git" in lines[apt]
    assert "rm -rf /var/lib/apt/lists/*" in lines[apt]


def test_no_packages_means_no_apt_layer() -> None:
    """Empty by default, so an existing manifest means exactly what it meant."""
    assert "apt-get" not in dockerfile(_runtime())


def test_the_tag_changes_with_the_packages() -> None:
    """Without this two projects differing only in packages share an image, and the second silently
    gets the first's — the shape of silent failure this project keeps finding."""
    files = {"uv.lock": b"x"}
    plain = RuntimeConfig(base="python-3.12", install="uv", dependencies=["uv.lock"])
    with_git = RuntimeConfig(
        base="python-3.12", install="uv", dependencies=["uv.lock"], packages=["git"]
    )

    assert image_tag(plain, files) != image_tag(with_git, files)


def test_a_package_this_build_has_never_heard_of_is_accepted() -> None:
    """**This test asserted the opposite until 2026-07-31, and the operator reversed the decision.**

    It read: *"`SystemPackage` is closed, so the refusal is at parse time"*, and it refused
    `imagemagick` — a perfectly ordinary Debian package. DR-0007 part 3 says a project
    connects whatever stack it has, the operator's words were *"los installs igual"*, and item 068's
    second criterion is that *"a name that is not in them is passed through rather than refused"*.
    So the old assertion is false about the product, not about the code that satisfied it.

    Replaced with a **stronger** pair of claims than the one it made: the capability *and* the guard
    that makes the capability safe. A test that only proved the refusal was gone would be a worse
    test
    than the one it replaced.

    """
    from hullwork.manifest import parse_manifest

    def manifest(packages: str) -> str:
        return f"""
project: p
git: {{provider: forgejo, repo: o/r}}
tests: "pytest"
runtime: {{base: python-3.12, install: uv, dependencies: [uv.lock], packages: {packages}}}
autofix: {{agent: claude-code}}
"""

    # The capability: a name this instance has never heard of reaches apt as itself.
    parsed = parse_manifest(manifest("[imagemagick, libpq-dev, g++]"))
    assert parsed.runtime is not None
    assert parsed.runtime.packages == ["imagemagick", "libpq-dev", "g++"]

    # And the guard, which is what makes opening it defensible. These are installed **as root at
    # build time**, so a leading `-` would be read by `apt-get install` as a flag rather than as a
    # package: argument injection, not a typo.
    for dangerous in ("[-o]", "[--reinstall]", '["git; rm -rf /"]', "[GIT]", '["two words"]'):
        with pytest.raises(ManifestError) as caught:
            parse_manifest(manifest(dangerous))
        assert "packages" in str(caught.value), dangerous


# --- the three closed sets, opened. Item 068, DR-0007 part 3 --------------------------------------


def test_a_base_this_instance_has_never_heard_of_becomes_the_from_line() -> None:
    """DR-0007 part 3: any stack connects.

    `ghcr.io/acme/ci-base:2026.7` is a real answer to "what is your project made of", and no closed
    set was going to contain it.
    """
    runtime = RuntimeConfig(base="ghcr.io/acme/ci-base:2026.7")

    assert "FROM ghcr.io/acme/ci-base:2026.7" in dockerfile(runtime)


def test_a_short_name_still_resolves_to_the_image_this_instance_recommends() -> None:
    """The sugar survives. `BASE_IMAGES` stopped being a gate and did not stop being useful."""
    assert "FROM python:3.12-slim" in dockerfile(RuntimeConfig(base="python-3.12"))


def test_a_base_cannot_escape_the_from_line() -> None:
    """**The guard that makes opening this safe, and the reason it is the newline.**

    `dockerfile` joins its instructions with `\\n`. A `base` containing one would not name a strange
    image — it would append instructions of the author's choosing, and `COPY --from` is enough to
    take anything off the host that the daemon can read.
    """
    for dangerous in ("python:3.12\nFROM scratch", "python 3.12", "-x", "$(whoami)", "a" * 250):
        with pytest.raises(ValueError) as caught:
            RuntimeConfig(base=dangerous)
        assert "runtime.base" in str(caught.value), dangerous


def test_a_project_can_write_its_own_install_command() -> None:
    """The loosest of the three grammars, because it is a command — and the project already supplies
    one this system runs (`tests`)."""
    runtime = RuntimeConfig(
        base="ghcr.io/acme/ci-base:2026.7",
        install="make bootstrap",
        dependencies=["Makefile"],
    )

    assert "RUN make bootstrap" in dockerfile(runtime)


def test_a_recipe_name_is_still_substituted_and_a_command_is_not() -> None:
    """`{first}` is a recipe's placeholder. A project that wrote its own command wrote the filename
    it wanted, and `str.format` on an arbitrary string would turn any brace into an error."""
    recipe = dockerfile(
        RuntimeConfig(base="python-3.12", install="pip", dependencies=["requirements.txt"])
    )
    assert "RUN pip install --no-cache-dir -r requirements.txt" in recipe

    own = dockerfile(
        RuntimeConfig(
            base="python-3.12", install="pip install -r {here}", dependencies=["requirements.txt"]
        )
    )
    assert "RUN pip install -r {here}" in own, "a brace in a command is not a placeholder"


def test_an_install_command_cannot_add_a_dockerfile_instruction() -> None:
    """One newline turns a dependency install into a Dockerfile of somebody else's choosing."""
    with pytest.raises(ValueError) as caught:
        RuntimeConfig(base="python-3.12", install="pip install x\nFROM scratch")

    assert "runtime.install" in str(caught.value)


def test_an_installer_that_does_not_fit_a_known_base_is_still_refused() -> None:
    """The coherence check survives **where the instance knows the family**. `npm` on a Python base
    is a manifest that cannot work, and saying so at parse time is free."""
    with pytest.raises(ValueError):
        RuntimeConfig(base="python-3.12", install="npm", dependencies=["package.json"])


def test_an_unknown_base_takes_whatever_installer_it_names() -> None:
    """And where the instance does **not** know the family, it does not invent one.

    Reading a family from the first path segment of an image reference is how this check refused
    every legitimate reference the moment the field opened — three of three, measured. The build is
    where a wrong installer is found out, which is why a failed build names the command.
    """
    runtime = RuntimeConfig(
        base="ghcr.io/acme/polyglot:1", install="npm", dependencies=["package.json"]
    )

    assert "RUN npm ci" in dockerfile(runtime)


# --- three package managers, not fifty ecosystems. Item 109, DR-0007's amendment ------------------


def test_a_declared_package_installs_on_any_of_the_three_families() -> None:
    """**Measured against real images on 2026-07-31**, before and after.

    Before: `FROM alpine:3.20` with one declared package failed the build with `exit code: 127` —
    `apt-get: not found`. Item 068 opened `packages` to any Debian package name and did not notice
    that
    the installer was hard-coded, so a project on a non-Debian base could not declare a package at
    all.

    After, built on the deployment host and `git --version` run inside each: Debian 2.47.3 (via
    `python:3.12-slim`), Alpine 2.45.4, Fedora 2.49.0. The same declaration, three distribution
    families.

    One generated `RUN` rather than three code paths, because the generator cannot know what the
    base
    is: `base` is any image reference since item 068, and pulling it to find out would answer before
    the
    build a question the build answers anyway.
    """
    for base in ("python-3.12", "alpine:3.20", "fedora:40"):
        recipe = dockerfile(RuntimeConfig(base=base, packages=["git"]))
        assert "command -v apt-get" in recipe
        assert "command -v apk" in recipe
        assert "command -v dnf" in recipe
        # Each manager's own cleanup, in its own branch. An image carrying apt's index is bigger for
        # nothing, and `--no-cache` does both halves at once on Alpine.
        assert "rm -rf /var/lib/apt/lists/*" in recipe
        assert "apk add --no-cache git" in recipe
        assert "dnf clean all" in recipe


def test_a_base_with_no_known_manager_fails_naming_the_three_it_looked_for() -> None:
    """A build failure is the common failure mode now that a user can name anything — DR-0007 lists
    it among the costs — so the message has to be about the right subject.

    `apt-get: not found` on an Alpine base is a message about Hullwork's assumption, not about the
    project's image.
    """
    recipe = dockerfile(RuntimeConfig(base="ghcr.io/acme/scratch-ish:1", packages=["git"]))

    assert "none of apt-get, apk, dnf" in recipe
    assert "put your own install line in runtime.install" in recipe
    assert "exit 1" in recipe


def test_no_packages_means_no_installer_line_at_all() -> None:
    """The negative. A project that declares nothing gets nothing — the probe is not free, it is a
    layer, and a layer that installs nothing is a layer that busts a cache for nothing."""
    recipe = dockerfile(RuntimeConfig(base="alpine:3.20"))

    assert "command -v" not in recipe
    assert "apk" not in recipe


def test_a_build_failure_shows_what_docker_said() -> None:
    """`ImageBuildError`'s docstring promised a diagnosis and `str()` threw it away.

    `SandboxError` — the class next door, identical `__init__`, same promise — was given this on
    2026-08-04 after a stranger lost ten minutes to a message that hid Docker's own explanation.
    This one was not, and the omission only became visible on 2026-08-05 when these errors started
    being rendered as sentences at the CLI boundary instead of as tracebacks: `could not build
    the sandbox image: base 'no-such-image'` never said the image does not exist, though Docker
    had.

    The tail, not the whole: the cause of a failed `docker` call is at the end.
    """
    docker_said = "\n".join(f"step {n}" for n in range(40)) + "\npull access denied"

    rendered = str(ImageBuildError("could not build the sandbox image", docker_said))

    assert rendered.startswith("could not build the sandbox image")
    assert "pull access denied" in rendered, "the diagnosis was in the output and must survive"
    assert "step 0" not in rendered, "the tail, at the 25-line convention, not forty lines of noise"
    assert str(ImageBuildError("alone")) == "alone", "and no trailing newline with no output"


def test_the_verdict_on_a_base_image_is_one_of_three_answers() -> None:
    """Refusal, or nothing, or *not checked* — and the third is what keeps this honest.

    Docker is unreachable from the receiver by design (DR-0009), so a check that could not tell
    *wrong* from *not asked* would refuse every registration made from the right place. Asserted
    with no daemon at all, which is that case exactly.
    """
    refusal, note = why_it_cannot_host_a_phase("python:3.12-slim", docker="docker-that-is-not-here")

    assert refusal is None, "an unanswerable question is not a refusal"
    assert "Not checked here" in note
    assert "no Docker client on PATH" in note, "and it says which of the reasons it was"
