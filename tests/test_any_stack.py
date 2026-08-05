"""What eight real repositories said. Item 111, DR-0007's claim under measurement.

Item 107 measured the reader against three CI formats and this repository's own workflow — files
we wrote, or wrote a fixture for. On 2026-08-01 the same production path was pointed at eight
public GitHub repositories in languages nobody here writes, and **not one of the eight produced a
manifest that could be committed.** Four did not parse.

Every test below is one of the defects that measurement found, with the repository that found it.
The fixtures are excerpts of those real workflows, not inventions: a test written from a guess
about how people write CI is the thing being corrected.

**Two of the eight now pass step 0** — the project's own suite, green, inside a sandbox built from
the proposed manifest, in production: `gorilla/mux` (Go, 89.6% coverage) and
`expressjs/express` (Node, its whole suite with an `nyc` coverage report). Those runs need a Docker
daemon and a network and are not in this file; what is here is every reader-side property they
depend on, so a regression is caught without one.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from hullwork import propose
from hullwork.manifest import parse_manifest
from hullwork.sandbox import image as image_module
from hullwork.sandbox import run as run_module
from hullwork.sandbox.image import ImageBuildError, build, dockerfile, image_tag

#: `gorilla/mux`, trimmed. The shape that produced no base at all: a runner label and a setup
#: action, which is how every language but Python and Node declares its toolchain.
GO = """
name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.23' }
      - run: go test -race -cover ./...
"""

#: `dtolnay/anyhow`, trimmed. The action that puts its version in the **tag**, and pins nothing.
RUST = """
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test
"""

#: `google/gson`, trimmed. A test command carrying a CI expression, and `mvn clean test` — the
#: verb three words from the tool.
JAVA = """
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-java@v4
        with: { java-version: '17', distribution: temurin }
      - run: mvn clean test --projects gson ${{ matrix.extra-mvn-args || '' }}
"""

#: `sinatra/sinatra`, trimmed: a `run: |` block that is two commands, the second of which is the
#: test command, and a lock file the project does not commit.
RUBY = """
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ruby/setup-ruby@v1
        with: { ruby-version: '3.3' }
      - run: |
          bundle install --jobs=3 --retry=3
          bundle exec rake
"""


def _manifest(text: str, repo: str = "acme/thing") -> str:
    return propose.render(propose.read(repo, ".github/workflows/ci.yml", text))


def test_a_toolchain_action_names_the_image_that_carries_it() -> None:
    """**Six of eight had no base**, which is the field that decides whether a project can be
    built at all. `SETUP_ACTIONS` knew `setup-python` and `setup-node`, so the sandbox worked for
    exactly the two stacks the closed sets used to allow.

    A full image reference, not a short name: item 068 made that legal, and it needs no new entry
    in this instance's `BASE_IMAGES`.
    """
    manifest = parse_manifest(_manifest(GO))

    assert manifest.runtime is not None
    assert manifest.runtime.base == "golang:1.23"
    assert manifest.tests == "go test -race -cover ./..."


def test_a_version_the_action_does_not_pin_becomes_the_image_default() -> None:
    """`dtolnay/rust-toolchain@stable` pins nothing, and `rust:stable` is not a tag anybody
    publishes. The image's own default is the honest answer, and the note says why."""
    proposed = _manifest(RUST)
    manifest = parse_manifest(proposed)

    assert manifest.runtime is not None
    assert manifest.runtime.base == "rust"
    assert "pins no version" in proposed

    # **And the case the word list misses**, which is the one that survives the shape rule: a
    # wildcard starts with a digit. `golang:1.x` is not a tag anybody publishes.
    wildcarded = parse_manifest(_manifest("""
jobs:
  test:
    steps:
      - uses: actions/setup-go@v5
        with: { go-version: '1.x' }
      - run: go test ./...
"""))
    assert wildcarded.runtime is not None
    assert wildcarded.runtime.base == "golang"


def test_a_proposal_with_no_base_still_parses() -> None:
    """**Four of eight did not parse**, and this is why: `runtime.base` is required, so a block
    carrying `install:` and no `base:` is refused by the parser the proposal tells a human to feed
    it. The one promise this module makes is that its output can be committed.
    """
    nothing_to_go_on = """
jobs:
  test:
    steps:
      - run: pip install -r requirements.txt
"""
    proposed = _manifest(nothing_to_go_on)

    assert isinstance(yaml.safe_load(proposed), dict)
    parse_manifest(proposed)  # raises if the promise is broken
    assert "# runtime:" in proposed, "the whole block is commented when there is no base"


def test_an_installer_with_no_dependency_file_is_commented_out() -> None:
    """The same promise, from the other side. An installer other than `none` needs at least one
    `dependencies` entry — it is the build's cache key — and `elixir-ecto/ecto` proposed
    `mix deps.get` with nothing to install from."""
    proposed = propose.render(
        propose.only_files_that_exist(
            propose.read("acme/thing", ".github/workflows/ci.yml", """
jobs:
  test:
    steps:
      - uses: erlef/setup-beam@v1
      - run: mix deps.get
      - run: mix test
"""),
            [".github/workflows/ci.yml"],  # a tree with no mix.exs in it
        )
    )

    parse_manifest(proposed)
    assert "#   install:" in proposed
    assert "cache key" in proposed


def test_a_ci_expression_never_reaches_a_field() -> None:
    """`google/gson` runs `mvn clean test … ${{ matrix.extra-mvn-args || '' }}`. GitHub Actions
    expands that and a shell does not, so proposing it puts a command that cannot run into the
    field the whole red-green claim rests on. Named in a comment instead."""
    proposed = _manifest(JAVA)
    manifest = parse_manifest(proposed)

    assert manifest.tests is None
    assert "a CI expression is in this command" in proposed
    assert "mvn clean test" in proposed, "what the project runs is still the best clue there is"


def test_the_verb_may_be_three_words_from_the_tool() -> None:
    """A contiguous match failed on four of eight. `mvn test` is in the list and gson runs
    `mvn clean test`; `npm test` is in the list and express runs `npm run test-ci`."""
    # Through the classifier, not only the helper: a matcher nothing calls is not a fix.
    placed = propose.read("acme/thing", ".github/workflows/ci.yml", """
jobs:
  build:
    steps:
      - run: mvn clean test --projects gson
""")
    assert placed.tests == "mvn clean test --projects gson"

    assert propose._runs("mvn clean test --projects gson", propose.TEST_RUNNERS)
    assert propose._runs("npm run test-ci", propose.TEST_RUNNERS)
    assert propose._runs("bundle exec rake", propose.TEST_RUNNERS)
    # And it stays anchored: a test command inside somebody else's container is not this
    # project's test command.
    assert not propose._runs("docker run --rm ci npm test", propose.TEST_RUNNERS)
    # A word prefix, not a substring anywhere: `latest` is not `test`.
    assert not propose._runs("npm run build-latest", propose.TEST_RUNNERS)


def test_a_run_block_is_several_commands() -> None:
    """`sinatra/sinatra` runs two lines in one block, and the second is the test command. Read as
    one string it became `install: 'bundle install …\\nbundle exec rake'` — a field with a newline
    in it and the test command buried inside the install."""
    manifest = parse_manifest(_manifest(RUBY))

    assert manifest.tests == "bundle exec rake"
    assert manifest.runtime is not None
    # The recipe rather than the observed command (item 112) — and the point of this test is the
    # **split**: the second line was the test command, and read as one string it ended up inside
    # the install field with a newline in it.
    assert manifest.runtime.install == "bundle"
    assert "\n" not in manifest.runtime.install
    assert "bundle install --jobs=3" in _manifest(RUBY), "what the CI runs is still shown"


def test_a_dependency_file_the_repository_does_not_have_is_dropped() -> None:
    """`sinatra/sinatra` does not commit its `Gemfile.lock`, and the inference names it anyway.
    Every declared file is copied into the build context, so a wrong guess here is not a rebuild —
    it is a build that cannot start. The tree is already open when this is decided."""
    proposal = propose.read("sinatra/sinatra", ".github/workflows/ci.yml", RUBY)
    assert "Gemfile.lock" in proposal.dependencies, "the inference still makes the guess"

    checked = propose.only_files_that_exist(proposal, ["Gemfile", "sinatra.gemspec"])

    assert "Gemfile.lock" not in checked.dependencies, "the file the repository does not have"
    assert "Gemfile" in checked.dependencies
    # And the companion the installer reads is added, which is the other half (item 112): a
    # `Gemfile` that says `gemspec` cannot be installed from a context without the gemspec.
    assert "sinatra.gemspec" in checked.dependencies


def test_an_installer_that_writes_into_the_project_is_swapped_for_the_recipe() -> None:
    """**`expressjs/express` built a perfect image and could not find `nyc`.** Its CI runs
    `npm install --ignore-scripts --include=dev`, the reader proposed it verbatim, and it installed
    into `/work/node_modules` — which the worktree mount replaces at attempt time.

    The recipe installs into a directory the mount does not touch. The observed command goes in a
    note rather than being silently rewritten.
    """
    proposed = _manifest("""
jobs:
  test:
    steps:
      - uses: actions/setup-node@v4
        with: { node-version: '22' }
      - run: npm install --ignore-scripts --include=dev
      - run: npm test
""")
    manifest = parse_manifest(proposed)

    assert manifest.runtime is not None
    assert manifest.runtime.install == "npm"
    assert "--ignore-scripts" in proposed, "what the CI actually runs is still shown"


def test_a_workflow_that_lints_is_not_preferred_over_one_that_tests() -> None:
    """`psf/requests` was read from `lint.yml`, a real CI file that runs no tests, because the
    files were sorted alphabetically."""
    # `psf/requests`'s own directory, which has no `ci.yml` at all — so alphabetical order put
    # `lint.yml` first and the reader read a workflow that runs no tests. A fixture where `ci.yml`
    # happens to sort first would pass with or without the fix, which is how this test was wrong
    # the first time.
    paths = [
        ".github/workflows/codeql.yml",
        ".github/workflows/lint.yml",
        ".github/workflows/run-tests.yml",
    ]

    assert propose.find(paths)[0] == ".github/workflows/run-tests.yml"
    assert propose.find(paths)[-1] in {
        ".github/workflows/lint.yml", ".github/workflows/codeql.yml",
    }


# --- the sandbox side: three defects that only a non-Python project could expose ---------------


def test_the_base_images_own_path_survives_a_login_shell() -> None:
    """**The defect that made "any stack" false at the sandbox rather than at the reader.**

    Every phase runs `sh -lc`, and Debian's `/etc/profile` sets `PATH` unconditionally — so an
    image's `ENV PATH` is wiped before the command runs. Measured on `golang`:

        sh -c  → …:/usr/local/go/bin:…    command -v go → /usr/local/go/bin/go
        sh -lc → /usr/local/sbin:/usr/local/bin:…    go: not found

    Item 051 found this for the variables Hullwork adds. Nobody noticed that the base image's own
    toolchain arrives the same way, because Python and Node put their binaries in `/usr/local/bin`
    — which Debian's default list happens to contain.
    """
    text = dockerfile(parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: 'golang:1.23'}
""").runtime)  # type: ignore[arg-type]

    line = next(line for line in text.splitlines() if "hullwork-base-path" in line)
    assert '"$PATH"' in line, "the image's own PATH, read at build time, not one we invented"
    assert "/etc/profile.d/" in line, "where a login shell will read it"
    # Sorted before the file that prepends to `$PATH`, or that one is overwritten.
    assert "hullwork-base-path.sh" < "hullwork-env.sh"


def test_a_changed_recipe_cannot_reuse_the_image_it_did_not_build() -> None:
    """**The fix above was deployed and changed nothing**, because the tag is content-addressed on
    what the *caller* asked for and the recipe is not part of it. The next build reused the broken
    image and reported success.

    Item 065 fixed exactly this for the harness bundle: *anything the bundle contains belongs in
    the name that claims to describe it.*
    """
    runtime = parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: python-3.12}
""").runtime
    assert runtime is not None
    before = image_tag(runtime, {})

    # The same runtime, a changed recipe: the tag has to move, or the next build reuses an image
    # built by instructions nobody runs any more.
    from unittest import mock

    with mock.patch.object(image_module, "dockerfile", lambda *a, **k: "FROM scratch\n"):
        after = image_tag(runtime, {})

    assert before != after, "a changed Dockerfile that keeps its tag is a stale image, silently"
    assert image_tag(runtime, {}) == before, "and it is still deterministic"


def test_a_declared_dependency_file_that_is_missing_is_named() -> None:
    """`sinatra/sinatra` again, from the build's side. The Dockerfile emits `COPY <path>` per
    declared file, so a manifest naming one the repository lacks failed with buildkit's own words:
    *"failed to compute cache key: … not found"*, under a ref hash, with the manifest unmentioned.
    """
    runtime = parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: ruby, install: bundle install, dependencies: [Gemfile, Gemfile.lock]}
""").runtime
    assert runtime is not None

    with pytest.raises(ImageBuildError) as refused:
        build(runtime, {"Gemfile": b"source 'https://rubygems.org'\n"})

    assert "Gemfile.lock" in str(refused.value)
    assert "does not have" in str(refused.value)


def test_a_recipe_that_installs_into_its_own_prefix_gets_the_files_there() -> None:
    """**The `npm` recipe had never run against a real Node project.** It installs with
    `--prefix /opt/hullwork-env`, and npm reads the `package.json` *in the prefix* — while the
    Dockerfile copied it to `/work`. Measured on `expressjs/express`: exit 254 on an empty
    directory. Every project this instance has ever built is Python, so nothing could notice.
    """
    text = dockerfile(parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: node-22, install: npm, dependencies: [package.json]}
""").runtime)  # type: ignore[arg-type]

    assert "COPY package.json /opt/hullwork-env/package.json" in text
    # And a Python recipe still copies into the worktree, where its installer looks.
    python = dockerfile(parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: python-3.12, install: uv, dependencies: [pyproject.toml, uv.lock]}
""").runtime)  # type: ignore[arg-type]
    assert "COPY pyproject.toml pyproject.toml" in python


# --- item 112: the sugar path, widened from two languages to eight ----------------------------


def test_every_measured_ecosystem_has_a_recipe() -> None:
    """**`INSTALL_COMMANDS` had six entries and four of them were Python.** So a Go, Rust, Ruby,
    PHP, Java or Elixir project taking the sugar path got a toolchain and no dependencies, and its
    suite failed on the first import — which is not a project-specific manifest problem, it is a
    table.

    Asserted as a set rather than one by one: the point is coverage of what was measured, and a
    recipe missing from it is a language whose projects silently cannot use the sugar path.
    """
    from hullwork.sandbox.image import INSTALL_COMMANDS, INSTALL_ENV

    measured = {"cargo", "bundle", "go mod", "mix", "composer", "maven"}
    assert measured <= set(INSTALL_COMMANDS), "an ecosystem measured in item 111 has no recipe"
    # Every one needs its environment in the *phase*, not only in the build — item 111's `PATH`
    # lesson, and `mix test` and `mvn test` both read these while the tests run.
    assert measured <= set(INSTALL_ENV)


def test_no_recipe_installs_into_the_worktree() -> None:
    """**The mount replaces `/work` at attempt time**, so anything installed there is gone by the
    time the gates run. Item 051 built `ENV_DIR` for exactly this, and each ecosystem hides it
    somewhere different: `vendor/bundle`, `deps/`, `_build/`, `node_modules`.

    Checked on the environment rather than on the command, because that is where the redirection
    is expressed and a command can spell it a dozen ways.
    """
    from hullwork.sandbox.image import INSTALL_ENV
    from hullwork.sandbox.run import ENV_DIR

    for recipe in ("cargo", "bundle", "go mod", "mix", "composer", "maven"):
        pointed = [value for value in INSTALL_ENV[recipe].values() if ENV_DIR in value]
        assert pointed, f"{recipe} installs somewhere the worktree mount will erase"


def test_the_installed_environment_is_writable_by_the_phase() -> None:
    """**Two of them write into their own cache while the tests run** and the root filesystem is
    read-only by design. Measured on `google/gson`: `FileSystemException: /opt/hullwork-env/m2/…
    Read-only file system`, with every dependency it needed already in that directory. Measured on
    `elixir-ecto/ecto`: `File.mkdir_p!` on the build path.

    Two halves, both asserted: the build hands the directory to the phase's uid, and the phase
    mounts a writable volume over it — a named one, keyed by the image, so it is a cache with an
    owner rather than debris the reaper has to guess about.
    """
    from hullwork.sandbox.run import ENV_DIR, SANDBOX_UID, Sandbox

    text = dockerfile(parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: elixir, install: mix, dependencies: [mix.exs]}
""").runtime)  # type: ignore[arg-type]
    assert f"chown -R {SANDBOX_UID}" in text

    box = Sandbox(image="hullwork-sandbox:abc123", worktree=Path("/tmp/wt"))  # noqa: S108
    argv = box._argv("pytest", None)
    mounted = [argv[n + 1] for n, flag in enumerate(argv) if flag == "--volume"]
    assert any(entry.endswith(f":{ENV_DIR}") for entry in mounted)
    assert any(entry.startswith("hullwork-envcache-") for entry in mounted), (
        "named, so it is a cache with an owner rather than an anonymous volume nobody collects"
    )


def test_a_toolchain_that_fetches_at_test_time_is_given_an_install_step() -> None:
    """**`dtolnay/anyhow` and `google/gson` proposed `install: none`** and built perfect images that
    failed at step 0 reaching for the network. A CI file that installs nothing is not describing a
    project without dependencies — it is describing a runner where `cargo test` and `mvn test`
    fetch as they go. A phase cannot (item 023).

    Three observed facts, no guess: the toolchain, the dependency file in the tree, and the sandbox
    having no network.
    """
    proposal = propose.read("acme/thing", ".github/workflows/ci.yml", GO)
    assert proposal.install is None, "the CI really does not install anything"

    filled = propose.the_recipe_its_toolchain_needs(proposal, ["go.mod", "go.sum", "main.go"])

    assert filled.install == "go mod"
    assert filled.dependencies == ("go.mod", "go.sum")
    # And it says why, because a reader who does not know a phase has no network would read this
    # as Hullwork inventing a step their CI does not have.
    assert any("no network" in note for note in filled.notes)


def test_a_toolchain_with_no_dependency_file_in_the_tree_is_left_alone() -> None:
    """The guard that keeps it from being a guess. No `go.mod`, no recipe."""
    proposal = propose.the_recipe_its_toolchain_needs(
        propose.read("acme/thing", ".github/workflows/ci.yml", GO), ["README.md"]
    )

    assert proposal.install is None


def test_a_requirements_file_that_installs_the_project_asks_for_the_source() -> None:
    """`psf/requests`'s `requirements-dev.txt` begins with `-e .`, and the install failed with
    *"file:///work does not appear to be a Python project"*.

    **Restated by item 113, which removed the reason it was a refusal.** For as long as the build
    context held only dependency files, the honest answer was to decline: `-e .` asks for the
    project and the project was not there. The manifest can now say the installer needs the source,
    so the answer is a bill rather than a no — and the note names the bill.
    """
    proposal = propose.the_recipe_its_toolchain_needs(
        propose.read("acme/thing", ".github/workflows/ci.yml", """
jobs:
  test:
    steps:
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: make ci
"""),
        ["requirements-dev.txt", "pyproject.toml"],
        lambda path: "-e .\npytest\n" if path == "requirements-dev.txt" else None,
    )

    assert proposal.install == "pip"
    assert proposal.needs_source is True
    assert any("rebuild per attempt" in note for note in proposal.notes)


def test_a_projects_own_install_command_still_gets_its_familys_environment() -> None:
    """**`install` is free-form since item 068, and `INSTALL_ENV` was keyed only by recipe name.**

    So a manifest saying `mvn dependency:go-offline -Pprofile` — which is the only way to serve a
    project whose test command needs a profile — got no `MAVEN_OPTS` at all, resolved into a home
    directory that is a tmpfs at attempt time, and threw the whole install away.
    """
    text = dockerfile(parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime:
  base: 'maven:3-eclipse-temurin-17'
  install: mvn clean test -Pfast -DskipTests
  dependencies: [pom.xml]
""").runtime)  # type: ignore[arg-type]

    assert "MAVEN_OPTS" in text, "a project's own mvn command needs the same repository path"
    assert "maven.repo.local" in text
    # And `MAVEN_CONFIG`, which the official image points at `/root` — unwritable to a phase.
    assert "MAVEN_CONFIG" in text


def test_a_maven_install_carries_the_test_commands_own_goals() -> None:
    """**Maven resolves plugins per goal**, so a warm-up that never runs `clean` never downloads
    the plugin that does. Measured on `google/gson` across three attempts, each failing on
    something the previous had not fetched — the last on `maven-clean-plugin`, because the test
    command is `mvn clean test` and the warm-up was `test-compile`.

    So the install step becomes that build with its tests skipped, which is the only warm-up
    guaranteed to resolve what the real command needs.
    """
    proposal = propose.read("acme/thing", ".github/workflows/ci.yml", JAVA_WITHOUT_EXPRESSIONS)
    filled = propose.the_recipe_its_toolchain_needs(proposal, ["pom.xml", "gson/pom.xml"])

    # `|| true` rather than `-DskipTests` since item 113: skipping the tests is what kept Surefire
    # from ever resolving its provider, and the build is warming a cache rather than judging.
    assert filled.install == "mvn clean test --projects gson || true"
    # A test command that is not Maven's leaves the recipe alone.
    other = propose.the_recipe_its_toolchain_needs(
        propose.read("acme/thing", ".github/workflows/ci.yml", GO), ["go.mod"]
    )
    assert other.install == "go mod"


#: `google/gson`'s workflow with the matrix expression removed, so the test command reaches a field.
JAVA_WITHOUT_EXPRESSIONS = """
jobs:
  build:
    steps:
      - uses: actions/setup-java@v4
        with: { java-version: '17', distribution: temurin }
      - run: mvn clean test --projects gson
"""


# --- item 113: the installer that needs the source ---------------------------------------------


def test_an_installer_that_reads_the_source_gets_it() -> None:
    """**The root cause under three of item 111's four remaining failures**, and it took until
    item 113 to name it: the build context holds the declared dependency files and nothing else.

    * a `Gemfile` that says `gemspec` reads the library the gemspec describes (`sinatra/sinatra`);
    * `mvn test` in a directory of bare poms finds no tests, so Surefire never resolves the
      provider the attempt will need (`google/gson`, five measured attempts);
    * a `requirements-dev.txt` beginning with `-e .` installs the project (`psf/requests`).

    All three are ordinary ways to write a project. The manifest can now say so, and it costs a
    rebuild per attempt — which is why it is opt-in and why the proposal spells out the bill.
    """
    text = dockerfile(parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime:
  base: ruby
  install: bundle
  dependencies: [Gemfile]
  install_needs_source: true
""").runtime)  # type: ignore[arg-type]

    assert "COPY . /work" in text
    assert "COPY Gemfile Gemfile" not in text, "the whole tree, not the file twice"

    # And the default is unchanged: a project that does not ask keeps the cheap context.
    ordinary = dockerfile(parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: python-3.12, install: uv, dependencies: [pyproject.toml, uv.lock]}
""").runtime)  # type: ignore[arg-type]
    assert "COPY . /work" not in ordinary
    assert "COPY pyproject.toml pyproject.toml" in ordinary


def test_an_image_built_from_the_source_is_keyed_by_the_commit() -> None:
    """Otherwise the second attempt on a project reuses an image built from the first one's code —
    the same class of staleness item 065 found in the harness bundle and item 111 found in the
    recipe. A commit names a tree exactly, and it is already in hand."""
    runtime = parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: ruby, install: bundle, dependencies: [Gemfile], install_needs_source: true}
""").runtime
    assert runtime is not None

    assert image_tag(runtime, {}, None, "abc123") != image_tag(runtime, {}, None, "def456")
    # And a project that does not bake the source is unaffected by the ref.
    plain = parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: python-3.12}
""").runtime
    assert plain is not None
    assert image_tag(plain, {}, None, "abc123") == image_tag(plain, {}, None, "def456")


def test_the_maven_warm_up_runs_the_tests_and_ignores_their_result() -> None:
    """**Surefire downloads its provider while executing**, so a warm-up that skips the tests
    leaves the attempt reaching for `surefire-junit4` on a network that is not there. Measured five
    times on `google/gson`, and green on the sixth.

    `|| true` is the other half: the build is warming a cache, not judging a project. A suite that
    is already red must reach the sandbox and become `baseline-red`, which costs the item nothing —
    not a build failure that reads as Hullwork being broken.
    """
    filled = propose.the_recipe_its_toolchain_needs(
        propose.read("acme/thing", ".github/workflows/ci.yml", JAVA_WITHOUT_EXPRESSIONS),
        ["pom.xml", "gson/pom.xml"],
    )

    assert filled.install == "mvn clean test --projects gson || true"
    assert filled.needs_source is True
    assert "-DskipTests" not in filled.install, "skipping the tests is what broke this for a day"


# --- item 114: what the build put in the tree survives the mount -------------------------------


def test_the_worktree_volume_can_be_seeded_from_the_image() -> None:
    """**The last structural gap, and it is not about PHP** (item 114).

    Every ecosystem before this was served by moving its dependencies *out* of the worktree and
    telling the toolchain where they went — `CARGO_HOME`, `GOMODCACHE`, `BUNDLE_PATH`. PHP has no
    such variable: `vendor/` is written into `composer.json`, `phpunit.xml` and every `require` a
    project makes. Measured on `briannesbitt/carbon`: the image built, Composer installed, and
    PHPUnit died on `vendor/autoload.php` because the mount had replaced the directory.

    Two properties, and the second is what makes the first safe to ship: the image is copied in
    **as root**, because a fresh volume belongs to root and the image runs as uid 10001 — the first
    version swallowed that permission error and produced an empty volume — and the **checkout goes
    on top**, so the source is always the repository's.
    """
    from hullwork.sandbox.run import Sandbox

    calls: list[list[str]] = []

    class Recorder(Sandbox):
        def _push(self) -> None:
            calls.append(["__push__"])

    box = Recorder(image="hullwork-sandbox:abc", worktree=Path("/tmp/wt"))  # noqa: S108
    def recorded(argv: list[str], timeout: int = 0) -> subprocess.CompletedProcess[str]:
        del timeout
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatched = run_module._docker
    run_module._docker = recorded
    try:
        box.ensure_volume("hullwork-worktree-x", seed_from_image=True)
    finally:
        run_module._docker = monkeypatched

    seeding = next(argv for argv in calls if "--entrypoint" in argv)
    assert "--user" in seeding and seeding[seeding.index("--user") + 1] == "0:0"
    assert "hullwork-sandbox:abc" in seeding, "the project's own image, not a carrier"
    # The checkout is copied after the image, or the image's source would win over the repository's.
    assert calls.index(seeding) < calls.index(["__push__"])


def test_seeding_from_the_image_is_off_unless_asked_for() -> None:
    """The seam every attempt runs through, so the default has to be yesterday's behaviour. Six
    repositories pass step 0 through this path and none of them needs the seeding."""
    from hullwork.sandbox.run import Sandbox

    calls: list[list[str]] = []

    class Recorder(Sandbox):
        def _push(self) -> None:
            calls.append(["__push__"])

    box = Recorder(image="hullwork-sandbox:abc", worktree=Path("/tmp/wt"))  # noqa: S108
    def recorded(argv: list[str], timeout: int = 0) -> subprocess.CompletedProcess[str]:
        del timeout
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatched = run_module._docker
    run_module._docker = recorded
    try:
        box.ensure_volume("hullwork-worktree-x")
    finally:
        run_module._docker = monkeypatched

    assert not [argv for argv in calls if "--entrypoint" in argv]


def test_php_keeps_its_vendor_directory_where_php_looks_for_it() -> None:
    """The other half of the same fix: with the tree surviving, Composer stops being redirected.

    `COMPOSER_VENDOR_DIR` pointed out of the worktree for the reason every other ecosystem is
    pointed out of it — and for PHP that broke the project's own paths instead of saving them.
    """
    from hullwork.sandbox.image import INSTALL_ENV

    assert "COMPOSER_VENDOR_DIR" not in INSTALL_ENV["composer"]
    assert "COMPOSER_HOME" in INSTALL_ENV["composer"], "the cache still goes out of the way"
