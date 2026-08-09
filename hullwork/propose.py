"""Read the answer the repository already wrote. Item 107, DR-0007's amendment.

**The goal this serves**, set by the operator: Hullwork works with any kind of software
project, and connecting one is easy and self-service.
Item 068 served the first half — any stack **can** connect. This serves the second:
connecting one should not require a person to translate their project by hand.

**Why the CI configuration and not the Dockerfile.** DR-0007 measured a Dockerfile and
concluded that a project's own files cannot answer Hullwork's question. Correct about
the file, wrong about the repository: a Dockerfile is a *deployment* artefact and is
supposed not to carry test tooling — `RUN pip install .` installs the project and not
its dev dependencies, so a sandbox built from it has no pytest at all.

A CI configuration is a *test* artefact. Measured on this repository's own
`.forgejo/workflows/ci.yml`:

    runs-on: ubuntu-latest
    setup-python@v5 with: { python-version: "3.12" }
    run: pip install -e ".[dev]"
    run: ruff check .   |   run: mypy .   |   run: pytest

Every field the manifest asks for, including the install command **with `[dev]`** —
precisely what the Dockerfile lacked. And it generalises structurally rather than
luckily: a CI configuration exists in order to say how a project is set up and tested,
and it is green on the default branch by construction. Evidence, not inference.

**Why this is one reader and not fifty.** Formats that describe an environment are
about three, and they are language-neutral; ecosystems are about fifty and they keep
arriving. This module reads *the project's own answer* about its tooling rather than
knowing that tooling — which is what makes it a translation instead of a treadmill.

**The rule that keeps it honest, and it is DR-0006's.** What was **observed** is
written; what was merely **inferred** is commented out with what was seen. A reader
that half-understands a workflow and emits a confident manifest is worse than no
reader, because a person skims a proposal that looks finished. So no branch here
guesses a default: a fact not found becomes a comment.

Nothing is written to the watched repository and nothing is registered. The operator
reads the proposal, edits it and commits it — a manifest belongs in the project, and a
proposer that committed would be a far larger promise than this one.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, NamedTuple

import yaml

#: Where a CI configuration lives, in the order they are preferred.
#:
#: Directories rather than filenames for the two Actions dialects, because the filename
#: is the author's choice — `Forge.tree` (item 068) turns a directory into its files.
#: `.gitlab-ci.yml` is a fixed path, so it is looked for directly.
CI_LOCATIONS: tuple[str, ...] = (
    ".forgejo/workflows/",
    ".gitea/workflows/",
    ".github/workflows/",
    ".gitlab-ci.yml",
)

#: CI locations that name the forge holding the repository, and the ones that do not.
#:
#: **`.github/workflows/` is deliberately absent, and that absence is the whole subject of
#: item 171.** Forgejo Actions and Gitea Actions both read that directory — this repository's
#: own deployment runs those workflows on a Forgejo instance — so treating it as evidence of
#: GitHub would be wrong for exactly the self-hosted projects this product is for.
CI_NAMES_THE_FORGE: tuple[tuple[str, str], ...] = (
    (".forgejo/workflows/", "forgejo"),
    (".gitea/workflows/", "gitea"),
    (".gitlab-ci.yml", "gitlab"),
)

#: Hosts that name themselves. Everything else is self-hosted and unresolvable from here:
#: `git.example.com` may be Forgejo, Gitea, a private GitHub or a self-hosted GitLab, and no
#: request may be made to find out — `propose` reaches nothing and needs no credential.
HOSTS_THAT_NAME_THE_FORGE: dict[str, str] = {
    "github.com": "github",
    "gitlab.com": "gitlab",
}

#: What `git.provider` says when nothing decided.
#:
#: A value rather than a placeholder, unlike `_coordinate_of`'s `owner/name`. The field is
#: required, so an unparseable proposal would cost every reader a fix to serve the undecidable
#: minority — and unlike a repository coordinate, a wrong forge name is something an operator
#: recognises on sight. What it must not do is look like a reading, so `render` says it is a
#: default and names what would have settled it.
PROVIDER_WHEN_UNDECIDED = "forgejo"


class ForgeGuess(NamedTuple):
    """Which forge holds a repository, and what said so.

    `evidence` is `None` when nothing did. That is not a detail for the caller to ignore: the
    difference between an observation and a default is what `render`'s contract is about.
    """

    provider: str
    evidence: str | None


def host_of_remote(url: str | None) -> str | None:
    """The host out of a git remote URL, in either spelling, or `None`.

    `_coordinate_of` has parsed this URL since item 107 and kept only the last two segments —
    discarding the one part of it that says which forge this is (item 171).
    """
    if not url:
        return None
    trimmed = url.strip().removesuffix(".git")
    for scheme in ("https://", "http://", "ssh://", "git://"):
        trimmed = trimmed.removeprefix(scheme)
    # `git@host:owner/name` and `git@host/owner/name` after the scheme is gone.
    _, _, after_user = trimmed.rpartition("@")
    host = re.split(r"[:/]", after_user, maxsplit=1)[0]
    # A host has a dot and no whitespace. Anything else was not a URL, and guessing from it
    # would be the constant-in-a-costume this function exists to remove.
    if not host or " " in host or "." not in host:
        return None
    return host.lower()


def forge_for(source: str | None, remote_host: str | None) -> ForgeGuess:
    """Which forge holds this repository. Pure, and reaches nothing.

    **The host outranks the CI location**, because where a repository lives beats which runner
    reads its workflows: a GitHub repository whose workflows sit in `.forgejo/workflows/` is a
    mirror, and the coordinate a manifest needs is the one that answers requests.
    """
    named = HOSTS_THAT_NAME_THE_FORGE.get(remote_host or "")
    if named:
        return ForgeGuess(named, f"the origin remote is on {remote_host}")
    for prefix, provider in CI_NAMES_THE_FORGE:
        if source and source.startswith(prefix):
            return ForgeGuess(provider, f"the CI configuration is at {prefix}")
    return ForgeGuess(PROVIDER_WHEN_UNDECIDED, None)

#: Package-manager invocations that mean "this step installs the dependencies".
#:
#: About a dozen, stable for years, and **being wrong here is free**: an unrecognised
#: step is emitted as a comment for a human to read, never dropped. That is the whole
#: difference between this and the closed `Literal`s DR-0007 removed — a list that
#: degrades into a comment is a convenience, a list that refuses to work is a gate.
INSTALLERS: tuple[str, ...] = (
    "pip install", "uv sync", "uv pip", "poetry install", "pipenv install",
    "pdm install", "npm ci", "npm install", "yarn install", "pnpm install",
    "bun install", "go mod download", "cargo fetch", "bundle install",
    "composer install", "mvn dependency", "mvn -b", "gradle dependencies",
    "dotnet restore", "mix deps.get", "swift package resolve", "cabal build",
)

#: Test runners. Same rule: unrecognised is a comment, never a guess.
TEST_RUNNERS: tuple[str, ...] = (
    "pytest", "tox", "nose", "unittest", "npm test", "yarn test", "pnpm test",
    "bun test", "jest", "vitest", "mocha", "go test", "cargo test", "mvn test",
    "gradle test", "dotnet test", "rspec", "rake test", "minitest", "phpunit",
    "pest", "mix test", "swift test",
    # Added 2026-08-01 (item 111), each from a repository that runs it: `make ci` in
    # `psf/requests`, `bundle exec rake` in `sinatra/sinatra`, `npm run test-ci` in
    # `expressjs/express` — which the two-word rule above already covers as `npm test`.
    "make test", "make check", "make ci", "bundle exec rake", "rake spec",
)

#: Linters and type checkers, kept apart from tests because the manifest has two fields
#: and a reviewer reads them differently: a failing lint gate publishes (item 067), a
#: failing test gate does not.
LINTERS: tuple[str, ...] = (
    "ruff", "mypy", "pyright", "flake8", "pylint", "black --check", "isort --check",
    "eslint", "prettier --check", "tsc --noemit", "biome", "golangci-lint", "go vet",
    "gofmt -l", "clippy", "cargo fmt", "rubocop", "standardrb", "phpstan", "psalm",
    "php-cs-fixer", "credo", "dialyzer",
)

#: A system-package install seen inside a CI step.
_SYSTEM_INSTALL = re.compile(
    r"(?:apt-get|apt)\s+install|apk\s+add|dnf\s+install|yum\s+install", re.I
)
#: Words to drop when reading package names out of such a line: anything option-shaped,
#: plus the words that are the command rather than a package.
_NOT_A_PACKAGE = re.compile(
    r"^(-|sudo$|apt$|apt-get$|apk$|dnf$|yum$|install$|add$|&&$|\|\|$)"
)
#: What a package name may look like, matching `manifest.PACKAGE_NAME`'s shape.
_PACKAGE_SHAPE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")

#: Language setup actions, mapped to the official image that carries that toolchain.
#:
#: **Measured 2026-08-01 against eight public repositories, which is why this is not two
#: entries any more** (item 111). It was `setup-python` and `setup-node` only, and the
#: result was that Go, Rust, Ruby, PHP, Java and Elixir projects all got a proposal with
#: the base left blank — the one field that decides whether the project can be built at
#: all. A proposal that leaves that to a human saves nobody the work it exists to save.
#:
#: **This is not the catalogue DR-0007 refused, and the difference is the whole hinge.**
#: That decision refused learning every ecosystem's *packages and installers* — the
#: arithmetic of "every package of every project of every self-hoster". This maps *"the
#: CI file says it sets up Go 1.23"* to *"the `golang:1.23` image has Go 1.23 in it"*:
#: one convention, Docker Hub's official language images, and it produces a **proposal a
#: human reads** rather than a build rule. It grows by language, not by package.
#:
#: A full image reference rather than a short name, because item 068 made that legal and
#: it needs no new entry in `BASE_IMAGES` — the instance keeps recommending its own short
#: names, and a repository gets told what its own CI already runs.
SETUP_ACTIONS: dict[str, str] = {
    "actions/setup-python": "python",
    "actions/setup-node": "node",
    "actions/setup-go": "golang",
    "actions/setup-java": "eclipse-temurin",
    "ruby/setup-ruby": "ruby",
    "shivammathur/setup-php": "php",
    "dtolnay/rust-toolchain": "rust",
    "actions-rs/toolchain": "rust",
    "erlef/setup-beam": "elixir",
    "actions/setup-dotnet": "mcr.microsoft.com/dotnet/sdk",
}

#: Which input each action pins its version with. `*-version` covers most of them, and
#: these are the ones that do it differently — `dtolnay/rust-toolchain` puts the version
#: in the **tag** (`@1.79`) and `erlef/setup-beam` names two toolchains at once.
_VERSION_INPUTS = ("go-version", "java-version", "ruby-version", "php-version",
                   "elixir-version", "dotnet-version", "toolchain", "node-version",
                   "python-version")

#: Version strings that name a moving target rather than a version. Proposing `golang:stable`
#: or `python:3.12.x` proposes an image tag nobody publishes; the image's own default tag is the
#: honest answer and the note says the version was not pinned.
#:
#: **The word list is the easy half and it was doing nothing** (item 111's reintroduction found
#: this): `stable`, `latest` and `lts/*` are already refused by the shape rule below, which wants a
#: leading digit. What earns this its place is the **wildcard**, which does start with one —
#: `go-version: '1.x'` and `python-version: '3.12.x'` are ordinary in real workflows, and both
#: would have become a tag that does not exist.
_UNPINNED = frozenset({"stable", "latest", "nightly", "beta", "current", "lts/*", "lts"})
_WILDCARD = re.compile(r"(^|[.\-])(x|\*)$|[*^~<>=]")

#: Keys at a GitLab file's top level that are configuration rather than a job.
_NOT_A_JOB = frozenset({"jobs", "image", "stages", "variables", "default", "include"})

#: How many unplaced steps to show. Enough that the test command is almost certainly
#: among them, few enough that the comment stays readable.
UNCLASSIFIED_SHOWN = 12

#: How much of one step to show.
#:
#: **The proposal is a manifest, so every line of it has to be a manifest line.** A CI
#: step can be a twelve-line shell script, and printing one whole put its second line
#: onwards into the file without a `#` — which made the rendered proposal fail to parse
#: as YAML. Caught by reading the output against this repository's own CI file, where the
#: DCO check is exactly such a script.
STEP_SHOWN_CHARS = 96


def _one_line(text: str) -> str:
    """A step as something that can live inside a `#` comment.

    First line only, bounded, and with the newlines gone rather than escaped: a reader
    needs to recognise the step, not to reconstruct it.
    """
    first = text.strip().splitlines()[0] if text.strip() else ""
    if len(first) > STEP_SHOWN_CHARS:
        first = first[: STEP_SHOWN_CHARS - 1].rstrip() + "…"
    return first + (" […]" if len(text.strip().splitlines()) > 1 else "")


@dataclass
class Proposal:
    """A manifest a human is about to read, and what it was built from.

    `unclassified` is not a leftover — it is the honest half of the output. A step this
    module could not place is shown so the operator can place it, and that is the only
    behaviour that makes a reader built on word lists safe to have.
    """

    repo: str
    #: The CI file it read, or `None` when there was none.
    source: str | None = None
    #: The host of the `origin` remote, when this was read from a checkout that has one.
    #: Item 171 — the strongest signal for `git.provider`, and it was being thrown away.
    remote_host: str | None = None
    base: str | None = None
    install: str | None = None
    tests: str | None = None
    lint: str | None = None
    packages: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    #: Facts seen but not usable as a field, each already worded for a human.
    notes: list[str] = field(default_factory=list)
    #: `run:` steps that matched nothing.
    unclassified: list[str] = field(default_factory=list)
    #: Whether the installer needs the repository's source, not only its dependency files.
    #: Item 113 — three of item 111's eight repositories cannot be built without it.
    needs_source: bool = False

    @property
    def found_anything(self) -> bool:
        """Whether this is worth printing as a proposal rather than as a refusal."""
        return any((self.base, self.install, self.tests, self.lint, self.packages))


def find(paths: object) -> list[str]:
    """CI configuration files in a repository tree, most-preferred first. Item 107.

    Takes the paths from `Forge.tree` and checks their shape, because a tree arrives in
    a forge response and a wrong assumption here is a wrong assumption about somebody
    else's repository.
    """
    if not isinstance(paths, (list, tuple)):
        return []
    known = [path for path in paths if isinstance(path, str)]
    found: list[str] = []
    for location in CI_LOCATIONS:
        if location.endswith("/"):
            found += sorted(
                (
                    path
                    for path in known
                    if path.startswith(location) and path.endswith((".yml", ".yaml"))
                ),
                key=_looks_like_tests,
            )
        elif location in known:
            found.append(location)
    return found


#: What a workflow that runs the suite is called, and what one that does not is called.
#: Measured on eight public repositories (item 111): sorting alphabetically read
#: `psf/requests` from `lint.yml`, a real CI file that runs no tests at all.
_TEST_WORKFLOW = ("ci", "test", "tests", "build", "check")
_NOT_TEST_WORKFLOW = ("lint", "release", "publish", "docs", "codeql", "stale", "label",
                      "deploy", "benchmark", "coverage", "scorecard", "dependabot")


def _looks_like_tests(path: str) -> tuple[int, str]:
    """Sort key: the workflow most likely to run the suite first, then by name.

    A guess, and it is allowed to be one because the proposal names the file it read in
    its own header — a reader who disagrees can point the command at another one. What it
    must not do is silently prefer a workflow that lints and never tests.
    """
    stem = path.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
    if stem in _TEST_WORKFLOW:
        return (0, stem)
    if any(word in stem for word in _NOT_TEST_WORKFLOW):
        return (2, stem)
    return (1, stem)


def read(repo: str, path: str, text: str) -> Proposal:
    """One CI configuration, read into a proposal. Never raises on what it cannot read.

    A file that is not YAML, or is YAML of an unexpected shape, produces a proposal
    carrying a note that says so and no fields at all. That is DR-0006's rule applied to
    the parser itself: giving up out loud beats half-understanding a large grammar, which
    is the cost DR-0007 named for reading these files in the first place.
    """
    proposal = Proposal(repo=repo, source=path)
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        proposal.notes.append(f"{path} is not valid YAML, so nothing was read: {exc}")
        return proposal
    if not isinstance(document, dict):
        proposal.notes.append(f"{path} is not a mapping, so nothing was read from it")
        return proposal

    steps = _steps(document)
    if not steps:
        proposal.notes.append(f"{path} has no steps this reader recognises")
    for step in steps:
        _classify(step, proposal)
    _guess_dependency_files(proposal)
    return proposal


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Every step of every job, in both dialects, flattened.

    Actions puts `jobs.<name>.steps[]` with `run:` or `uses:`; GitLab puts
    `<job>.script[]` as bare strings. Both are read as "a list of things this project
    runs", because that is all this module needs — and a deeper model of either format
    would be the large grammar DR-0007 warns about.
    """
    out: list[dict[str, Any]] = []
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            if job.get("container") is not None:
                out.append({"__container__": job["container"]})
            if job.get("runs-on") is not None:
                out.append({"__runs_on__": job["runs-on"]})
            for step in job.get("steps") or []:
                if isinstance(step, dict):
                    out.append(step)
    if document.get("image") is not None:
        out.append({"__container__": document["image"]})
    for key, value in document.items():
        if key in _NOT_A_JOB or not isinstance(value, dict):
            continue
        if value.get("image") is not None:
            out.append({"__container__": value["image"]})
        scripts = _as_lines(value.get("before_script")) + _as_lines(value.get("script"))
        out += [{"run": line} for line in scripts]
    return out


def _as_lines(value: object) -> list[str]:
    """A YAML scalar-or-sequence of strings, as one string per command.

    **A `run: |` block is several commands and used to be read as one** (item 111). A
    manifest field is a single command, so `sinatra/sinatra`'s two-line block arrived as
    `install: 'bundle install …\\nbundle exec rake'` — a value carrying a newline, with the
    project's actual test command buried inside the install field. Split, each line is
    classified on its own and `bundle exec rake` lands in `tests` where it belongs.

    Continuations are rejoined: a command broken across lines with a trailing `\\` is one
    command that happens to be typed on three lines, and splitting it would produce three
    fragments that each run nothing.
    """
    raw: list[str] = []
    if isinstance(value, str):
        raw = [value]
    elif isinstance(value, list):
        raw = [item for item in value if isinstance(item, str)]
    commands: list[str] = []
    for block in raw:
        pending = ""
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.endswith("\\"):
                pending += stripped[:-1].strip() + " "
                continue
            commands.append((pending + stripped).strip())
            pending = ""
        if pending:
            commands.append(pending.strip())
    return commands


def _classify(step: dict[str, Any], proposal: Proposal) -> None:
    """Place one step, or record that it could not be placed."""
    if "__container__" in step:
        _read_container(step["__container__"], proposal)
        return
    if "__runs_on__" in step:
        # A runner label is not an image, and pretending otherwise would propose
        # something unbuildable.
        proposal.notes.append(
            f"the workflow runs on `{step['__runs_on__']}`, a runner label rather than "
            f"an image — name an image your tests run in, or a short name"
        )
        return
    uses = step.get("uses")
    if isinstance(uses, str):
        _read_setup_action(uses, step.get("with"), proposal)
        return
    for line in _as_lines(step.get("run")):
        _classify_command(line.strip(), proposal)


def _runs(command: str, phrases: tuple[str, ...]) -> bool:
    """Whether `command` runs one of `phrases`, allowing anything between the words.

    **A contiguous substring match was measured failing on four of eight real repositories**
    (item 111). `mvn test` is in the list and `google/gson` runs `mvn clean test --projects
    gson`; `npm test` is in the list and `expressjs/express` runs `npm run test-ci`. People
    put subcommands and flags between the tool and the verb, and a catalogue of exact
    phrases predicts what they write — DR-0008's finding, in a new place.

    So a two-word phrase matches when the command **starts with the tool** and a later word
    **begins with the verb**: `mvn … test`, `npm … test-ci`, `bundle exec rake`. Anchored at
    the start so `docker run … npm test` is not read as this project's test command, and the
    verb matches a word prefix so `test-ci` counts while `latest` does not.
    """
    words = command.split()
    if not words:
        return False
    for phrase in phrases:
        parts = phrase.split()
        if len(parts) == 1:
            if any(word.startswith(parts[0]) for word in words):
                return True
            continue
        if words[0] != parts[0]:
            continue
        rest = words[1:]
        for verb in parts[1:]:
            index = next((n for n, word in enumerate(rest) if word.startswith(verb)), None)
            if index is None:
                break
            rest = rest[index + 1:]
        else:
            return True
    return False


def _classify_command(command: str, proposal: Proposal) -> None:
    """One `run:` line. First match wins, and no match becomes a comment.

    Tests and lint are matched **before** install, because a runner and an installer can
    share a prefix — `cargo test` would otherwise be read as `cargo`-something to
    install, and the field that matters most would be the one lost.
    """
    if not command:
        return
    if "${{" in command:
        # **A CI expression is not a command** (item 111). `google/gson` runs
        # `mvn test … ${{ matrix.extra-mvn-args || '' }}`, which GitHub Actions expands and
        # a shell does not — so proposing it as `tests:` proposes a command that cannot
        # run, in the field the whole red-green claim rests on. Named, not dropped: what
        # the project runs is still the best clue a reader has.
        proposal.notes.append(
            f"a CI expression is in this command, so it is not proposed as a field: "
            f"`{_one_line(command)}`"
        )
        return
    lowered = command.lower()
    if _SYSTEM_INSTALL.search(lowered):
        found = tuple(_packages_in(command))
        proposal.packages = tuple(dict.fromkeys(proposal.packages + found))
        return
    is_test = _runs(lowered, TEST_RUNNERS)
    is_lint = _runs(lowered, LINTERS)
    is_install = _runs(lowered, INSTALLERS)

    if is_test and proposal.tests is None:
        proposal.tests = command
        return
    if is_lint and proposal.lint is None:
        proposal.lint = command
        return
    if is_install and proposal.install is None:
        for phrase, recipe in INSTALLS_INTO_THE_PROJECT:
            if _runs(lowered, (phrase,)):
                proposal.install = recipe
                proposal.needs_source = recipe in INSTALLERS_THAT_READ_THE_SOURCE
                proposal.notes.append(
                    f"the CI runs `{_one_line(command)}`, and the proposal says `{recipe}` "
                    f"instead: this instance's recipe installs into a directory the worktree "
                    f"mount does not replace, and that command's `node_modules` would be gone "
                    f"by the time the tests run"
                )
                return
        proposal.install = command
        return
    if is_test or is_lint or is_install:
        # **A second one is not unplaceable, it is a second one.** The manifest has one
        # `tests` and one `lint`, and this repository's own CI runs `ruff` *and* `mypy` —
        # dropping the second into "could not place" reads as though the reader failed,
        # when what it found is a field that wants both commands joined.
        kind = "test runner" if is_test else ("linter" if is_lint else "installer")
        proposal.notes.append(
            f"a second {kind} runs in the CI: `{_one_line(command)}` — the manifest has "
            f"one field, so join them with `&&` if you want both"
        )
        return
    proposal.unclassified.append(command)


#: Where an install line stops being an install line. Item 113.
#:
#: **Measured on `briannesbitt/carbon`**, whose CI runs
#: `sudo apt-get update || apt --fix-broken install || echo 'Apt failure ignored'` — an ordinary
#: defensive one-liner. Everything after `install` was read as package names, so the manifest
#: declared `echo` and `failure`, and the build died with apt's exit 100 on packages that do not
#: exist. A shell operator ends the argument list; anything after it is a different command.
_END_OF_THE_INSTALL = re.compile(r"\|\||&&|;|\||>|<|#")


def _packages_in(command: str) -> list[str]:
    """Package names out of a system-install line, flags and command words dropped."""
    tail = re.split(_SYSTEM_INSTALL, command, maxsplit=1)[-1]
    tail = _END_OF_THE_INSTALL.split(tail, maxsplit=1)[0]
    names = []
    for word in tail.replace("\\", " ").split():
        if _NOT_A_PACKAGE.match(word) or not _PACKAGE_SHAPE.match(word):
            continue
        names.append(word)
    return names


def _read_container(container: object, proposal: Proposal) -> None:
    """An explicit image is the best answer this reader can find. DR-0007's path (B).

    It needs no mapping and no knowledge on Hullwork's side: the project already runs
    its tests in it, which is the most agnostic environment there is.
    """
    image = container.get("image") if isinstance(container, dict) else container
    if isinstance(image, str) and image.strip() and proposal.base is None:
        proposal.base = image.strip()


def _read_setup_action(uses: str, inputs: object, proposal: Proposal) -> None:
    """`actions/setup-go@v5` and friends, mapped to the image that carries that toolchain.

    **The short name is preferred where this instance has one**, because that is the image
    the operator has chosen to recommend and it is what `BASE_IMAGES` exists for. Where it
    has none — every language but Python and Node — the official image is proposed by full
    reference, which item 068 made legal.

    A version the action does not pin becomes the image's own default tag with a note. The
    alternative was measured on eight real repositories: `dtolnay/rust-toolchain@stable` is
    how a Rust project pins nothing, and `rust:stable` is not a tag that exists.
    """
    action = uses.split("@", 1)[0].strip().lower()
    family = SETUP_ACTIONS.get(action)
    if family is None:
        return
    version = _setup_version(action, uses, inputs)
    if proposal.base is not None:
        return

    from hullwork.sandbox.image import BASE_IMAGES

    if version is None:
        proposal.base = family
        proposal.notes.append(
            f"`{uses}` pins no version, so the base is `{family}` — the image's own default "
            f"tag. Pin it if your project needs a particular one"
        )
        return
    short = f"{'python' if family == 'python' else family}-{version}"
    if short in BASE_IMAGES:
        # The instance's own recommendation, where it has one for exactly this version.
        proposal.base = short
        return
    proposal.base = f"{family}:{version}"


def _setup_version(action: str, uses: str, inputs: object) -> str | None:
    """The toolchain version a setup action pins, or `None` when it pins nothing.

    Three shapes, all measured on real workflows: an input named `*-version`, a version in
    the action's own tag (`dtolnay/rust-toolchain@1.79`), and a matrix reference, which
    pins nothing this reader can resolve — the matrix is the CI's, not the manifest's.
    """
    named = None
    if isinstance(inputs, dict):
        for key, value in inputs.items():
            if isinstance(key, str) and (key in _VERSION_INPUTS or key.endswith("-version")):
                named = str(value).strip().strip('"').splitlines()[0].strip()
                break
    if named is None and action.endswith("rust-toolchain"):
        # The one action that carries its version where the ref goes.
        tag = uses.split("@", 1)[1].strip().lower() if "@" in uses else ""
        named = tag or None
    if not named or named.lower() in _UNPINNED or "${{" in named:
        return None
    if _WILDCARD.search(named):
        return None
    # `3.12.x`, `>=1.21`, `1.79.0` — anything that is not a plain tag is left to the image's
    # default rather than turned into a tag nobody publishes.
    return named if re.fullmatch(r"[0-9][0-9a-zA-Z.\-_]*", named) else None


#: Installers that put their output **inside the project directory**, and the recipe that
#: redirects it out of the way. Item 111.
#:
#: **Measured on `expressjs/express`.** Its CI runs `npm install --ignore-scripts
#: --include=dev`; the reader proposed that command verbatim, it ran at build time, and it
#: installed into `/work/node_modules` — which the worktree mount replaces at attempt time.
#: The image was perfect and `npm run test-ci` answered `sh: 1: nyc: not found`.
#:
#: Item 051 found this and built `ENV_DIR` for it, and `INSTALL_COMMANDS` uses it. What that
#: fix could not cover is a project's **own** command, which item 068 made legal a month
#: later — so the recipe is proposed instead, and the command that was seen goes in a note
#: for the reader to compare. Nothing is rewritten: a proposal that quietly edited somebody's
#: install flags would be worse than one that names both.
#:
#: Only the ecosystems that install into the project directory are here. `pip install -e .`
#: lands in site-packages, `cargo` in `$CARGO_HOME`, `go` in `$GOPATH` — all outside the
#: mount, all fine as written.
INSTALLS_INTO_THE_PROJECT: tuple[tuple[str, str], ...] = (
    ("pnpm install", "pnpm"),
    ("npm ci", "npm"),
    ("npm install", "npm"),
    # **Item 112 widened this from "installs into the project directory" to "has a recipe".** The
    # reason is the same in every case and it is not only the mount: these commands are written to
    # run in CI, where the network is open at test time. Inside a sandbox it is not — so `cargo
    # test` cannot fetch, `mvn test` cannot reach Central, and the recipe is what puts the
    # dependencies on disk while the build still has a network.
    ("cargo fetch", "cargo"),
    ("cargo build", "cargo"),
    ("bundle install", "bundle"),
    ("go mod download", "go mod"),
    ("mix deps.get", "mix"),
    ("composer install", "composer"),
    ("mvn dependency", "maven"),
    ("mvn -b", "maven"),
)


#: Which dependency files an installer implies. **Inferred, and reported as such**: the
#: manifest wants `dependencies` as its cache key, so a wrong guess costs a rebuild
#: rather than a wrong result — the one place in this module where a guess is affordable.
DEPENDENCY_FILES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("uv", ("pyproject.toml", "uv.lock")),
    ("poetry", ("pyproject.toml", "poetry.lock")),
    ("pip", ("pyproject.toml",)),
    ("pnpm", ("package.json", "pnpm-lock.yaml")),
    ("yarn", ("package.json", "yarn.lock")),
    ("npm", ("package.json", "package-lock.json")),
    ("go mod", ("go.mod", "go.sum")),
    # `rust-toolchain.toml` is a dependency file in every sense that matters here: it decides
    # which compiler the tests need, and a phase with no network cannot fetch one (item 112).
    ("cargo", ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain")),
    ("bundle", ("Gemfile", "Gemfile.lock")),
    ("composer", ("composer.json", "composer.lock")),
    # Added 2026-08-01 (item 111): `elixir-ecto/ecto` proposed `install: mix deps.get` with
    # no dependency file, and the manifest refuses an installer that has nothing to install
    # from — so the proposal did not parse.
    ("mix", ("mix.exs", "mix.lock")),
    ("maven", ("pom.xml",)),
    ("mvn", ("pom.xml",)),
    ("gradle", ("build.gradle", "build.gradle.kts")),
    ("dotnet restore", ("*.csproj",)),
)


def _guess_dependency_files(proposal: Proposal) -> None:
    """Dependency files implied by the install command, if one was found."""
    if not proposal.install:
        return
    lowered = proposal.install.lower()
    for marker, files in DEPENDENCY_FILES:
        if marker in lowered:
            proposal.dependencies = files
            return


def _SHORT_NAMES() -> frozenset[str]:  # noqa: N802 - a table, spelled like one
    """The short base names this instance recommends, for the comment beside the field."""
    from hullwork.sandbox.image import BASE_IMAGES

    return frozenset(BASE_IMAGES)


#: The recipe a toolchain needs, and the file that proves the project uses it. Item 112.
#:
#: **This is not a guess, and that is why it is allowed to fill a field.** Three facts, all
#: observed: the CI file says it sets up this toolchain, the repository contains that toolchain's
#: dependency declaration, and a phase runs with **no network** (item 023). A CI file that never
#: installs anything is not describing a project with no dependencies — it is describing a runner
#: where `cargo test` and `mvn test` fetch as they go. Inside the sandbox they cannot.
#:
#: Measured on `dtolnay/anyhow` and `google/gson`: both propose `install: none`, both build a
#: perfect image, and both fail at step 0 reaching for the network. Python is deliberately absent —
#: its projects install explicitly in CI, and `pip` vs `uv` vs `poetry` is a real choice this
#: cannot read off a lock file.
TOOLCHAIN_RECIPES: tuple[tuple[str, str, str], ...] = (
    ("golang", "go.mod", "go mod"),
    ("rust", "Cargo.toml", "cargo"),
    ("eclipse-temurin", "pom.xml", "maven"),
    ("ruby", "Gemfile", "bundle"),
    ("elixir", "mix.exs", "mix"),
    ("php", "composer.json", "composer"),
    ("node", "package.json", "npm"),
    # **Python is here for one shape only**, and the file is what makes it unambiguous. `pip` vs
    # `uv` vs `poetry` cannot be read off a `pyproject.toml` — but a `requirements-dev.txt` is a
    # project saying, in a file, exactly which packages its tests need. `psf/requests` runs
    # `make ci` and installs nothing in the workflow this reader can see; that file is the answer
    # it left in the repository.
    ("python", "requirements-dev.txt", "pip"),
)


#: What an installer reads **besides** the file that names it, found in the tree. Item 112.
#:
#: **The build context is the declared dependency files and nothing else**, which is what keeps it
#: tiny and the layer cache useful — and it is why two of item 111's repositories could not build.
#: `google/gson` is a multi-module Maven project whose root `pom.xml` refers to children that were
#: not in the context (`ProjectBuildingException`), and `sinatra/sinatra`'s `Gemfile` says
#: `gemspec`, which reads a file the context did not have (exit 15).
#:
#: Neither is a guess: the tree is open, the files either exist or they do not, and a declared file
#: that is missing is refused by name at build time (item 111).
COMPANION_FILES: dict[str, tuple[str, ...]] = {
    "maven": ("pom.xml",),
    "gradle": ("build.gradle", "build.gradle.kts", "settings.gradle"),
    "bundle": (".gemspec",),
}

#: Installers that read the repository's **source** and not only its dependency files. Item 113.
#:
#: Each measured, each failing differently before this existed:
#:
#: * **`bundle`** — a `Gemfile` that says `gemspec` reads the library the gemspec describes, so
#:   `bundle install` in a context of `Gemfile` + `.gemspec` exits 14 (`sinatra/sinatra`).
#: * **`maven`** — `mvn test` in a directory of bare `pom.xml` files finds no tests, so Surefire
#:   never resolves the provider the attempt will need and step 0 dies with `surefire-junit4`
#:   absent, no matter how the warm-up is spelled (`google/gson`, five attempts).
#: * **`pip`** — a `requirements-dev.txt` beginning with `-e .` installs the project itself
#:   (`psf/requests`).
#:
#: It costs a rebuild per attempt, which is why it is set only for the installers that need it and
#: why the manifest field it sets is off by default.
INSTALLERS_THAT_READ_THE_SOURCE = frozenset({"bundle", "maven", "pip"})

#: Packages a **recipe** needs, as opposed to packages the project needs. Item 113.
#:
#: Composer extracts what it downloads, and the official `php` image has neither `unzip` nor `git`
#: — measured, after the binary itself was already in place. The recipe is Hullwork's, so its
#: prerequisites are Hullwork's to declare; they go into the proposal where a reader can see them
#: rather than into a hidden step, because `packages` is a field that says what an image contains.
RECIPE_PACKAGES: dict[str, tuple[str, ...]] = {"composer": ("unzip", "git")}

#: How many companion files to carry. A monorepo with three hundred modules is a build context
#: nobody wants, and a project that large is one whose operator writes the manifest by hand.
COMPANIONS_MAX = 40


def _with_companions(proposal: Proposal, present: set[str], recipe: str | None = None) -> None:
    """Add the files the installer reads beside the one that named it.

    **The recipe is passed in rather than read off `proposal.install`**, and that is a defect this
    function shipped with for an hour: item 112 made the Maven install a *free-form command* so it
    could carry the test command's profile flags, and this lookup — keyed by the recipe name —
    stopped matching. The multi-module poms vanished from the context and `google/gson` went back
    to failing exactly as it had before, one layer earlier.
    """
    suffixes = COMPANION_FILES.get(recipe or proposal.install or "")
    if not suffixes:
        return
    found = sorted(
        path for path in present
        if any(path.endswith(suffix) for suffix in suffixes)
        and path not in proposal.dependencies
    )
    if len(found) > COMPANIONS_MAX:
        proposal.notes.append(
            f"this project has {len(found)} files the installer reads and only the first "
            f"{COMPANIONS_MAX} are declared — a tree this size wants a manifest written by hand"
        )
    proposal.dependencies = tuple(proposal.dependencies) + tuple(found[:COMPANIONS_MAX])


#: A requirements line that installs **the project itself**. Item 112.
#:
#: `psf/requests`'s `requirements-dev.txt` starts with `-e .`, and the build context holds only the
#: dependency files — never the source, deliberately, because the source changes every attempt
#: (this module's own docstring says so). So the install fails with *"file:///work does not appear
#: to be a Python project"*, and a proposal that cannot build is worse than one that stays quiet.
_INSTALLS_THE_PROJECT = re.compile(r"^\s*(-e\s+\.|\.|-e\s+file:)", re.MULTILINE)


def _resolving_what_the_tests_will_run(recipe: str, tests: str | None) -> str:
    """The install command, carrying the selectors the test command uses. Item 112.

    **Maven's offline resolution cannot guess a profile.** `google/gson` runs
    `mvn clean test --projects gson --activate-profiles gson-subset`, and a `dependency:go-offline`
    run without those flags fetches a different set — so the image built, resolved, and then step 0
    died with `DependencyResolutionException` inside a sandbox with no network.

    The test command is right there in the same manifest. Carrying its selectors across is the
    difference between resolving *a* build and resolving *the* build, and it is why `install` being
    free-form (item 068) is load-bearing rather than decoration.
    """
    if recipe != "maven" or not tests or not tests.strip().startswith("mvn"):
        return recipe
    # **The install step is the test command with the tests skipped**, and getting here took three
    # measurements on `google/gson`, each failing on something the previous one had not fetched:
    #
    #   dependency:go-offline                      → DependencyResolutionException
    #   dependency:go-offline --projects … -P …    → DependencyResolutionException
    #   test-compile --projects … -P …             → PluginResolutionException: maven-clean-plugin
    #
    # The last one is the lesson: the test command is `mvn **clean** test …`, and a warm-up that
    # never runs `clean` never downloads the plugin that does. Maven resolves plugins per goal, so
    # the only warm-up guaranteed to fetch what a build needs is **that build**.
    #
    # **And it has to actually run the tests**, which `-DskipTests` was quietly preventing: Surefire
    # picks and downloads its *provider* while executing, so a skipped run leaves `surefire-junit4`
    # out of the repository and the attempt dies reaching for it. That is why this needs the source
    # in the image at all.
    #
    # `|| true` because **the build is warming a cache, not judging a project**. A suite that is
    # already red must produce `baseline-red` in the sandbox, where it is an honest verdict that
    # costs the item nothing — not a build failure that reads as Hullwork being broken.
    return f"{tests.strip()} || true"


def the_recipe_its_toolchain_needs(
    proposal: Proposal,
    paths: object,
    read: Callable[[str], str | None] | None = None,
) -> Proposal:
    """Fill `install` when the CI never does it and the sandbox will need it anyway. Item 112.

    Only when three things hold: no install command was observed, the base is a toolchain this
    knows a recipe for, and the repository actually carries that toolchain's dependency file. The
    note says why the proposal is adding a step the CI does not have — a reader who does not know
    that a phase has no network would otherwise read this as Hullwork inventing work.
    """
    if proposal.install or not proposal.base or not isinstance(paths, (list, tuple)):
        return proposal
    present = {path for path in paths if isinstance(path, str)}
    base = proposal.base.split(":", 1)[0]
    for family, marker, recipe in TOOLCHAIN_RECIPES:
        # `python-3.12` and `node-22` are this instance's **short names** and name the same family
        # as `python` or `node:22`. Matched as a prefix rather than by splitting on `-`, because
        # `eclipse-temurin` has one in the middle of its own name.
        if (base != family and not base.startswith(f"{family}-")) or marker not in present:
            continue
        # **The build tool is part of the environment, and `setup-java` does not name it**
        # (item 112). `actions/setup-java` means a JDK, and `eclipse-temurin` is exactly that: a
        # JDK with no Maven in it, so the build died with `mvn: not found`, exit 127. The
        # `pom.xml` that just proved this project uses Maven also names the image that has it.
        if recipe == "maven" and proposal.base:
            version = proposal.base.split(":", 1)[1] if ":" in proposal.base else "17"
            proposal.base = f"maven:3-eclipse-temurin-{version}"
            proposal.notes.append(
                f"the CI sets up a JDK and the project builds with Maven, so the base is "
                f"`{proposal.base}` — a plain `eclipse-temurin` has no `mvn` in it"
            )
        proposal.install = _resolving_what_the_tests_will_run(recipe, proposal.tests)
        proposal.needs_source = recipe in INSTALLERS_THAT_READ_THE_SOURCE
        needed = RECIPE_PACKAGES.get(recipe, ())
        if needed:
            proposal.packages = tuple(dict.fromkeys(proposal.packages + needed))
            proposal.notes.append(
                f"`{recipe}` needs {', '.join(needed)} to unpack what it downloads, and the "
                f"official image has neither — so they are declared here rather than left to fail"
            )
        _guess_dependency_files(proposal)
        if recipe == "pip":
            # `pip` means `pip install -r`, so the first dependency has to be the requirements file
            # itself — the manifest refuses the pair otherwise, and it is right to (item 051).
            proposal.dependencies = (marker,)
            text = read(marker) if read is not None else None
            if text is not None and _INSTALLS_THE_PROJECT.search(text):
                # **Not a refusal any more** (item 113). It was one for as long as the build
                # context held only dependency files: `-e .` asks for the project, and the project
                # was not there. Now the manifest can say so, and the note explains the bill rather
                # than declining the work.
                #
                # `needs_source` is **already** true here — `pip` is in
                # `INSTALLERS_THAT_READ_THE_SOURCE` — and setting it again was dead code found by
                # reintroducing it: the test passed with the line gone. Third time today that a
                # reintroduction has found dead code rather than a missing test.
                proposal.notes.append(
                    f"`{marker}` installs the project itself (`-e .`), so the image needs the "
                    f"whole checkout — hence `install_needs_source`, and a rebuild per attempt"
                )
        proposal.dependencies = tuple(
            name for name in proposal.dependencies if name in present
        )
        _with_companions(proposal, present, recipe)
        proposal.notes.append(
            f"the CI installs nothing explicitly, because on a runner `{recipe}` fetches as the "
            f"tests run — a phase here has no network (item 023), so the dependencies are fetched "
            f"while the image is built instead"
        )
        return proposal
    return proposal


def only_files_that_exist(proposal: Proposal, paths: object) -> Proposal:
    """The proposal with dependency files the repository does not have removed. Item 111.

    **Inference is cheap to check when the tree is already open.** `DEPENDENCY_FILES` pairs an
    installer with the files it usually reads, and "usually" is doing real work there: a Ruby
    project that does not commit its lock file is ordinary, and Hullwork copies every declared file
    into the build context — so a wrong guess here is not a rebuild, it is a build that cannot
    start. Measured on `sinatra/sinatra`.

    Dropped silently rather than noted: the guess was this module's, not the project's, and a
    comment explaining that Hullwork nearly named a file that does not exist tells a reader
    something about Hullwork rather than about their repository.
    """
    if not isinstance(paths, (list, tuple)):
        return proposal
    present = {path for path in paths if isinstance(path, str)}
    proposal.dependencies = tuple(
        name for name in proposal.dependencies if name in present
    )
    _with_companions(proposal, present)
    return proposal


def _the_git_lines(proposal: Proposal) -> list[str]:
    """`git:`, and whether its provider was read or defaulted to. Item 171.

    Uncommented means observed, everywhere else in this output. A constant printed under that
    rule is the failure this file exists to avoid, so an undecided provider is preceded by a
    comment saying so rather than being quietly indistinguishable from a reading.
    """
    guess = forge_for(proposal.source, proposal.remote_host)
    line = f"git: {{provider: {guess.provider}, repo: {proposal.repo}}}"
    if guess.evidence:
        return [line]
    return [
        "# `provider` below is a default, not a reading: neither the origin remote's host",
        "# nor the CI path named a forge. `.github/workflows/` cannot name one — Forgejo",
        "# and Gitea Actions read that directory too. Correct it if this is not a Forgejo.",
        line,
    ]


def render(proposal: Proposal) -> str:
    """The proposal as manifest text: observed values live, everything else commented.

    DR-0006's rule, and the reason this is safe to print at all — a person reads it,
    edits it and commits it. Nothing here is adopted by having been generated.
    """
    name = proposal.repo.split("/")[-1]
    lines = [
        f"# Proposed by `hullwork propose {proposal.repo}`, read from"
        f" {proposal.source or 'nothing'}.",
        "#",
        "# Read it before you commit it. What this instance observed is uncommented;",
        "# what it could only infer is commented out with what was seen. A proposal",
        "# that looks finished is a proposal nobody checks.",
        "",
        f"project: {name}",
        *_the_git_lines(proposal),
        "",
    ]

    if proposal.tests:
        lines.append(f"tests: {proposal.tests!r}")
    else:
        lines.append("# tests: <the command that runs your suite>   # not in the CI file")
    if proposal.lint:
        lines.append(f"lint: {proposal.lint!r}")
    else:
        lines.append("# lint: <your linter, for the lint gate>      # not in the CI file")

    # **Every runtime field is commented out when there is no base, and that is a defect
    # this file shipped with** (item 111). `runtime.base` is required, so a block carrying
    # `install:` and no `base:` is a manifest the parser refuses — and this function's one
    # promise is that what it prints can be committed. Four of eight real repositories
    # produced exactly that, while the test asserting "the proposal parses" passed, because
    # this repository's own CI always yields a base.
    # **An installer with nothing to install from is refused too** (item 111). The manifest
    # requires at least one `dependencies` entry for any installer but `none` — it is the
    # cache key — so `elixir-ecto/ecto`'s `install: mix deps.get` with no inferred file made
    # a proposal that does not parse. Named in a comment rather than dropped: the command is
    # right and what is missing is the file it reads.
    installable = bool(proposal.install) and bool(proposal.dependencies)
    lines += ["", "runtime:" if proposal.base else "# runtime:"]
    mark = "  " if proposal.base else "#   "
    if proposal.base:
        why = "an image your CI runs the tests in" if (
            "/" in proposal.base or ":" in proposal.base
        ) else "the official image for the toolchain your CI sets up"
        if proposal.base in _SHORT_NAMES():
            why = "a short name this instance has an image for"
        lines.append(f"  base: {proposal.base}   # {why}")
    else:
        lines += [
            "#   base: <an image your tests run in, or python-3.12 | node-22 | …>",
            "#   Nothing in the CI file named one, and this is the field that decides",
            "#   whether your project can be built at all — so the block below stays",
            "#   commented until it has one: a `runtime:` without a `base:` is refused.",
        ]
    if proposal.install and installable:
        lines.append(f"{mark}install: {proposal.install!r}")
    elif proposal.install:
        lines += [
            f"#   install: {proposal.install!r}",
            "#     Commented out: an installer needs at least one `dependencies` file to",
            "#     install from — it is the cache key — and this reader could not name one",
            "#     for that command. Add the file your project reads and uncomment both.",
        ]
    elif proposal.base:
        # **What no installer costs, said where the field is not** (item 185). Every other field
        # this reader cannot fill carries a comment explaining what is missing; `install` carried
        # none, because its absence produces a manifest that **parses and builds perfectly**. What
        # it cannot do is measure a dependency upgrade: with no installer the image is the base
        # exactly as it comes, so rewriting a pin changes nothing the suite runs against.
        #
        # Measured on 2026-08-09 (item 182) before this comment existed: a checkout pinning
        # `jinja2==2.4.1`, a base image carrying 3.0.0, and a verdict reading *your suite passed
        # before this change and passes after it* — about a version that was never installed.
        #
        # The command is deliberately not named: it is not in the published image, and naming
        # something a reader cannot run invites them to type it and be told it does not exist.
        lines += [
            f"{mark}# No `install:` — nothing in the CI file named one, and this reader does not",
            f"{mark}# guess between pip, uv and poetry from a lock file. Your tests will run: the",
            f"{mark}# image is `{proposal.base}` exactly as it comes.",
            f"{mark}#",
            f"{mark}# What it costs: dependency upgrades cannot be **measured** against this",
            f"{mark}# manifest. Nothing is installed from a lock file, so changing a pinned",
            f"{mark}# version changes nothing your suite would run against, and a green suite",
            f"{mark}# would say nothing about the upgrade.",
            f"{mark}#",
            f"{mark}# To answer that, keep this base and add two lines — the command your CI",
            f"{mark}# already uses, and the file it reads:",
            f"{mark}#     install: <your command>",
            f"{mark}#     dependencies: [<the file your versions are pinned in>]",
            f"{mark}# That is one layer on top of the image you named, not a rebuild from",
            f"{mark}# scratch, and it is why no list here has to grow for your ecosystem.",
        ]
    if proposal.packages:
        lines.append(f"{mark}packages: [{', '.join(proposal.packages)}]")
    if proposal.dependencies:
        lines.append(
            f"{mark}dependencies: [{', '.join(proposal.dependencies)}]"
            f"   # inferred — check it, it is the cache key"
        )
    if proposal.needs_source and proposal.base:
        lines += [
            f"{mark}install_needs_source: true",
            f"{mark}  # Your installer reads the project's own files, not just the ones above —",
            f"{mark}  # a gemspec, an `-e .`, or a test tree Maven has to see. So the whole",
            f"{mark}  # checkout goes into the image, and it is rebuilt when your code changes",
            f"{mark}  # rather than when your lock file does. Minutes per attempt, not seconds.",
        ]

    # Deduplicated: every job in a workflow names the same runner, and saying it once per
    # job is noise that makes the rest of the comment look like noise too.
    notes = list(dict.fromkeys(proposal.notes))
    if notes:
        lines += ["", "# Seen, and not usable as a field:"]
        lines += [f"#   - {_one_line(note)}" for note in notes]
    steps = list(dict.fromkeys(proposal.unclassified))
    if steps:
        lines += ["", "# Steps this reader could not place. One may be your test command:"]
        lines += [f"#   - {_one_line(step)}" for step in steps[:UNCLASSIFIED_SHOWN]]
        if len(steps) > UNCLASSIFIED_SHOWN:
            lines.append(f"#   … and {len(steps) - UNCLASSIFIED_SHOWN} more")

    lines += [
        "",
        "# Nothing about lanes on purpose: since M8 this instance derives which code is",
        "# dangerous from the path an error came from, so an empty `autofix` is fully",
        "# configured. `hullwork projects lanes` prints that policy against your tree.",
        "# Add `autofix: {agent: claude-code}` when you want fixes attempted.",
        "",
    ]
    return "\n".join(lines)
