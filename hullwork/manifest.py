"""Parse and validate `hullwork.yml`, the manifest a project puts in its repository.

This file is the product's public interface (constitution §4), so the parser is deliberately strict:

* **Unknown keys are an error.** A typo in `autofix.lanes.red` must not leave a project believing it
  has a guardrail it does not have.
* **`human-merge` cannot be removed from `gates`.** A configuration file is not allowed to
  switch off the human.
* **`safe_load` only.** The manifest arrives from a repository, which is untrusted input.

All problems are reported at once, each naming the key that caused it. Fixing a config file one
error per run is a miserable way to spend an afternoon.
"""

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

MANIFEST_FILENAME = "hullwork.yml"

#: What this build understands. A manifest may say `version: 1`; one that says something higher
#: was written for a newer Hullwork and is refused with a message saying so, rather than
#: producing a wall of `Extra inputs are not permitted` about fields that will exist one day.
#:
#: Absent means 1, and will keep meaning 1 for ever. That is the promise: once this file is
#: public, `absent` is a value people have already written, and reinterpreting it later would
#: break files nobody can be asked to change.
SCHEMA_VERSION = 1

#: Mandatory gate. Present in every manifest, removable by nobody.
HUMAN_MERGE = "human-merge"


class ManifestError(Exception):
    """The manifest is not usable. Carries every problem found, not just the first."""

    def __init__(self, source: str, problems: list[str]) -> None:
        self.source = source
        self.problems = problems
        listed = "\n".join(f"  {problem}" for problem in problems)
        super().__init__(f"{source} is not a valid Hullwork manifest:\n{listed}")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ErrorsConfig(_Strict):
    """Where production errors come from. The DSN lives in the project's environment, never here."""

    provider: Literal["glitchtip", "sentry"] = "glitchtip"


class GitConfig(_Strict):
    """Which forge holds the repository, and which repository."""

    provider: Literal["forgejo", "gitea", "github", "gitlab"]
    repo: str

    @field_validator("repo")
    @classmethod
    def _looks_like_a_repository_at_all(cls, value: str) -> str:
        """What is wrong with a repository name whatever forge holds it.

        **Split from the per-provider rule below, and a test is why.** Moving the whole check into a
        model validator broke `test_every_problem_is_reported_at_once`: pydantic skips an `after`
        validator once any field has failed, so a manifest with a bad provider *and* a bad repo
        reported only the provider — and that test exists because fixing a config file one error per
        run is the failure this parser was written to avoid. Field-level problems are collected in
        parallel, so everything that needs no other field belongs here.
        """
        segments = value.split("/")
        if len(segments) < 2 or any(not segment for segment in segments):
            msg = "expected 'owner/name'"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _the_repo_has_the_shape_this_provider_uses(self) -> "GitConfig":
        """Two segments, except on GitLab, where subgroups are ordinary. Item 132.

        **Checked against the provider rather than loosened for everybody.** Three segments on
        GitHub is a typo, and accepting it everywhere to make room for GitLab would trade a refusal
        an operator can read for a 404 four layers down.
        """
        if self.provider == "gitlab":
            return self
        if len(self.repo.split("/")) != 2:
            msg = "expected 'owner/name'"
            raise ValueError(msg)
        return self


#: Subjects no manifest may ever hand to an agent, whatever it writes in `green` or `amber`.
#: The manifest comes from a repository, so whoever can merge to its default branch would
#: otherwise be choosing the agent's authorisation scope — a lower bar than the operator who
#: connected the project ever agreed to. Kept deliberately short: these are the areas where a
#: wrong "fix" is not a bug but a breach.
ALWAYS_RED = frozenset({"secret", "secrets", "token", "credential", "auth", "payment", "payments"})

#: Lane patterns are interpolated into an issue body that Hullwork's own account authors. Newlines
#: and pipes would break out of the table row and let a manifest inject arbitrary markdown — and a
#: forged fingerprint marker — into a document a human is meant to trust.
_LANE_PATTERN = re.compile(r"^[A-Za-z0-9._/*-]{1,64}$")


def _valid_patterns(value: list[str], field: str) -> list[str]:
    for pattern in value:
        if not _LANE_PATTERN.match(pattern):
            msg = (
                f"{field}: {pattern!r} is not a usable pattern — letters, digits and "
                f". _ / * - only, up to 64 characters"
            )
            raise ValueError(msg)
    return value


class Lanes(_Strict):
    """What the agent may attempt, by risk. Anything unlisted is treated as red."""

    green: list[str] = Field(default_factory=list)
    amber: list[str] = Field(default_factory=list)
    red: list[str] = Field(default_factory=list)
    #: Paths the instance's derived policy calls sensitive that **this** project treats as ordinary
    #: code (M8, `hullwork/territory.py`). The escape hatch for a project whose layout the policy
    #: reads wrong — a `migrations/` directory holding documentation, a vendored `package.json` that
    #: is nobody's dependency.
    #:
    #: An override of the *instance's opinion*, never of `ALWAYS_RED`: those are checked before the
    #: derived policy is consulted, so this cannot reach them structurally, and the validator below
    #: refuses them anyway so a manifest that tries says why it will not load.
    #:
    #: Matched like every other lane pattern — substring, plus glob when it contains `*`.
    ordinary: list[str] = Field(default_factory=list)

    @field_validator("green", "amber", "ordinary")
    @classmethod
    def _reserved_subjects_cannot_be_promoted(
        cls, value: list[str], info: ValidationInfo
    ) -> list[str]:
        """The second invariant the spec always claimed and never enforced.

        Refused at parse time rather than corrected at triage time, because a manifest that
        silently means something other than what it says is worse than one that will not load.
        """
        _valid_patterns(value, f"autofix.lanes.{info.field_name}")
        reserved = sorted({p for p in value if p.strip().lower() in ALWAYS_RED})
        if reserved:
            msg = (
                f"autofix.lanes.{info.field_name}: {reserved} cannot be promoted out of the red "
                f"lane — these subjects are always a human's decision"
            )
            raise ValueError(msg)
        return value

    @field_validator("red")
    @classmethod
    def _red_patterns_are_still_patterns(cls, value: list[str]) -> list[str]:
        return _valid_patterns(value, "autofix.lanes.red")


#: What an engine name may look like. **A shape, not a list** — DR-0004, and M6 is where it lands.
#:
#: An agent is NAMED, never supplied. The manifest is untrusted input, so a field carrying a
#: command string would let whoever can push to a connected repository choose what this host
#: executes. Adding an engine is an instance-side decision, not a repository-side one.
#:
#: It was a closed `Literal["none", "claude-code", "openhands"]`, and both halves of that were wrong
#: for one reason. **`openhands` parsed and resolved to nothing**: a public surface advertising a
#: capability no build has ever had, which is what M6 exists to stop. And an operator who registers
#: their own engine — the thing `engine.REGISTRY` is *for*, and which its own comment invites —
#: could not name it, because the parser had never heard of it.
#:
#: So parse time checks the shape and nothing else, and `_the_engine_must_be_known` resolves the
#: name against the registry at registration. DR-0004 in its own words: *"Parse time can only check
#: the shape; the registry is the authority."* Nothing is executed as given either way — the name
#: selects a recipe this instance already holds.
#:
#: The pattern is deliberately tighter than a slug needs to be: an engine name reaches an image
#: reference and a container's argv, so no whitespace, no punctuation, nothing shell-shaped.
AGENT_NAME = re.compile(r"^[a-z][a-z0-9-]{0,30}[a-z0-9]$")

#: Kept as a name rather than inlined, because `none` is a sentinel and not an engine: it means no
#: agent at all and never reaches the registry.
NO_AGENT = "none"

#: Every gate this build knows. A closed set because `list[str]` meant `[tests, lnt, human-merge]`
#: validated cleanly and silently dropped the lint gate — a guardrail lost to a typo, which is
#: exactly the failure this module's opening paragraph says it exists to prevent.
Gate = Literal["tests", "lint", "human-merge"]  # must stay in step with HUMAN_MERGE

#: What a manifest gets when it says nothing.
#:
#: `lint` is deliberately absent, and its removal is the point of this change rather than a side
#: effect. A gate needs a command to run; `lint` had none anywhere in this schema, so it was
#: accepted, defaulted on, and ran nothing — for every manifest ever written. Same class of defect
#: as the misspelling above, and it survived because nothing tied a gate to the thing that
#: satisfies it. A default may now only name a gate the defaults can also satisfy, and no command
#: has a sensible default.
#:
#: This changes what an **absent** `gates` key means, which item 020 established is a promise once
#: this file is public. It is not public. That window is the only reason this is affordable.
DEFAULT_GATES: tuple[Gate, ...] = ("tests", "human-merge")

#: Where a reproducing test may be created (spec M2 §3). A directory, not a glob: it is a boundary,
#: and `*` in a boundary is how boundaries stop being ones.
_TEST_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")


class AutofixConfig(_Strict):
    """How, and whether, an agent may attempt a fix.

    `agent: none` is the default (DR-0002): the pipeline is fully useful with no external model
    call, and attempting fixes is what you opt into.
    """

    agent: str = NO_AGENT

    @field_validator("agent")
    @classmethod
    def _an_engine_is_named_not_described(cls, value: str) -> str:
        """The shape only. Whether this instance knows the name is `_the_engine_must_be_known`.

        A refusal here would have to guess what the operator has registered, and guessing in this
        direction is what let `openhands` sit in the public surface: a value the parser blessed and
        no build could serve.
        """
        if value != NO_AGENT and not AGENT_NAME.match(value):
            msg = (
                f"autofix.agent: {value!r} is not a usable engine name — lowercase letters, digits "
                f"and hyphens, 2 to 32 characters, or 'none'. The name selects a recipe this "
                f"instance already holds; a repository can never supply one."
            )
            raise ValueError(msg)
        return value
    sandbox: Literal["docker"] = "docker"
    lanes: Lanes = Field(default_factory=Lanes)
    gates: list[Gate] = Field(default_factory=lambda: list(DEFAULT_GATES))

    #: What happens to an error that matched no rule at all. Item 072, DR-0008 part 3.
    #:
    #: `human` is the default and every existing manifest keeps it, byte for byte. `attempt` is a
    #: project saying *"try anything my rules do not protect"* — the lanes stop being an allow-list
    #: and become the exceptions to a default of trying.
    #:
    #: **Per project, opted into, and that direction is the mitigation.** The operator's decision on
    #: 2026-07-29 reversed the proposal: inverting the instance default with a per-project opt-out
    #: would mean a project inherits the risky answer *by being forgotten*, and forgetting is the
    #: adversary DR-0008 names here. A project also cannot inherit somebody else's appetite — one
    #: instance watches many repositories and only some have a client depending on them.
    #:
    #: Reserved subjects and territory still override it — it buys leniency only where nothing else
    #: objected. It is the same class of decision as writing a green lane, taken by the same people
    #: with the same net underneath: one attempt, a red baseline required, a failing test before the
    #: fix, and a human merge.
    unmatched: Literal["human", "attempt"] = "human"

    @field_validator("gates")
    @classmethod
    def _human_merge_is_not_removable(cls, value: list[Gate]) -> list[Gate]:
        if HUMAN_MERGE not in value:
            msg = (
                f"'{HUMAN_MERGE}' is mandatory and cannot be removed — a manifest may not "
                f"switch off the human gate"
            )
            raise ValueError(msg)
        if len(set(value)) != len(value):
            msg = "autofix.gates: a gate is listed more than once"
            raise ValueError(msg)
        return value


#: Bases this build knows how to make a sandbox out of. A closed set, and the same argument as
#: `AgentSpec`: the manifest arrives from a repository, so a free-form image name would let whoever
#: can merge there choose what this host pulls and runs. Naming a base is a choice among things the
#: instance already trusts; supplying an image reference is not.
#: What a base image may look like. **A shape, not a list** — DR-0007 part 3, item 068.
#:
#: It was `Literal["python-3.12", "python-3.13", "node-22", "node-24"]`, and the closed set was the
#: security property: a free-form string here goes into a Dockerfile's `FROM` line, chosen by
#: whoever
#: can merge to a watched repository's default branch. That is a real exposure and the answer is not
#: a
#: catalogue — it is that **the grammar cannot escape the line it is written into**.
#:
#: The load-bearing character is the newline. `image.dockerfile` joins its instructions with `\n`,
#: so
#: a `base` containing one would not merely name a strange image, it would append arbitrary
#: instructions — `COPY --from`, another `FROM`, an `ENV` that changes what every later step sees.
#: Whitespace and shell metacharacters go for the same reason.
#:
#: What remains is the grammar of an image reference: a registry with an optional port, a path, a
#: tag
#: or a digest. `ghcr.io/acme/ci-base:2026.7` is a legitimate answer to "what is your project made
#: of", and no closed set was going to contain it. `BASE_IMAGES` keeps the four names as sugar.
IMAGE_REFERENCE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{1,199}$")

#: Kept as a name because it reads as documentation at a call site — `base: SandboxBase` says more
#: than `base: str`. Validated by `IMAGE_REFERENCE`, not by membership, since item 068.
SandboxBase = str

#: A Debian package name, per Debian policy §5.6.1: lowercase, digits, plus, minus, dot, and it must
#: start alphanumeric. **The leading character matters** — a name beginning with `-` would be read
#: by
#: `apt-get install` as a flag, and that is an argument-injection surface rather than a typo.
PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,79}$")

#: An install command's only structural rule: **it fits on one line.**
#:
#: Item 068's own words about this field — *"an image reference, a package name and a command have
#: three different grammars and the command's is the loosest — it is a command"*. There is nothing
#: to
#: validate about its content, because content is the point, and a project already supplies a
#: command
#: this system runs: `tests`. What is different here is **where** it runs — as root, at image build
#: time, with the network open, before `--read-only` applies to anything — which is why the build
#: gets
#: a timeout and a size bound (item 068) rather than why the string gets a grammar.
#:
#: So the guard is the newline, and it is not a formality: the command is interpolated into `RUN
#: {command}` and the result is joined with `\n`. One newline turns a dependency install into a
#: Dockerfile of somebody else's choosing.
_NO_NEWLINES = re.compile(r"^[^\r\n]{1,2000}$")

#: How dependencies get installed inside the sandbox. **Six recipes, and now also anything else.**
#:
#: The old comment read *"also closed, also because a free-form string here would be a command from
#: an
#: untrusted file — the field item 017 deleted, wearing a hat"*, and it was half right. Item 017
#: deleted a field that let a repository choose **what this host executes**; this one chooses what a
#: build container runs while making an image for that repository's own tests. The project already
#: supplies `tests`, a command that runs in the same sandbox — so the class of exposure is not new,
#: and DR-0007 part 3 is the operator deciding that any stack has to be able to connect.
#:
#: The six names below stay as sugar in `image.INSTALL_COMMANDS`. Anything else is the command.
Installer = str

#: Tools a project's *test command* needs that its language runtime does not provide. Closed for the
#: same reason as the two above: a free-form string here is a package name from an untrusted file
#: going to `apt-get install` as root at build time.
#:
#: **Every entry is here because a real project's test command needed it** — the rule item 053 set,
#: and the only one that keeps this set honest. Speculative entries here have all been defects:
#: `openhands` parsed and resolved to nothing, and the `lint` gate shipped on by default with no
#: command behind it.
#:
#: * `git` — this repository's own suite, three tests that shell out to it (item 053).
#: * `tesseract-ocr`, `tesseract-ocr-spa` — `acme`'s ingestion accuracy gate, two tests that
#:   OCR a scanned PDF and a photo through `pytesseract` with `lang="spa+eng"` (item 063). Two names
#:   rather than one so a project that needs OCR is not handed a language pack it never asked for.
#: Kept as a name for the two places that still read it as documentation. The type is now `str`,
#: validated by `PACKAGE_NAME` — see `RuntimeConfig.packages`.
SystemPackage = str

#: Services a project's test suite needs running beside it. Closed for the third time and the same
#: reason: a free-form string here is an image reference from an untrusted file, chosen by whoever
#: can merge to a default branch, going to `docker run` on the operator's host.
#:
#: **The set is what a measured project needed, and nothing else.** `acme` — the project
#: chosen for M7 — fails 128 of 245 tests inside the sandbox with `psycopg.OperationalError`, so
#: `postgres-16` is the entry that exists for a reason. `redis-7` and `mysql-8` are here because the
#: registry that resolves them is the same three lines each and the closed set is the security
#: property, not the shortness — but no project has yet needed either, and that is recorded rather
#: than hidden.
#:
#: The long tail — Kafka, Elasticsearch, a proprietary sidecar — will never be covered by a closed
#: set. The plan M10 keeps an escape hatch for it (an operator-provided network, labelled *you own
#: the isolation and the state on this network*), and that is not this item.
ServiceSpec = Literal["postgres-16", "postgres-15", "redis-7", "mysql-8"]

#: Which installers make sense with which base. A `npm` install on a Python base builds an image
#: that cannot run the tests, and finding that out at attempt time costs an attempt.
_BASE_INSTALLERS: dict[str, frozenset[str]] = {
    "python": frozenset({"pip", "uv", "poetry", "none"}),
    "node": frozenset({"npm", "pnpm", "none"}),
}


class RuntimeConfig(_Strict):
    """What the sandbox has to contain for this project's tests to run at all.

    Without this the milestone has no floor: `autofix.sandbox` said `docker`, which is a
    technology and not an image, so there was nowhere for `pytest` to come from and step 0 — the
    baseline that must pass before the model is ever called — could not pass for any project.

    Hullwork builds the image from these declarations rather than pulling one the repository names.
    The difference is the whole of item 017: a base is chosen from a set the instance trusts, and
    the dependency files are read from the repository we are already going to check out.
    """

    base: str
    install: str = "none"
    #: Tools the test command needs beyond the language runtime (item 053). Empty by default, so an
    #: existing manifest means exactly what it meant.
    packages: list[SystemPackage] = Field(default_factory=list)
    #: Services that must be running for the test command to pass (item 052). Empty by default, for
    #: the same reason: a manifest written before this field means exactly what it meant.
    #:
    #: **A project names a service; it never supplies an image, a port or an environment.** The
    #: registry beside `BASE_IMAGES` decides what each name means and which variables the suite is
    #: told, so a repository cannot point the operator's Docker daemon at an image of its choosing
    #: (item 017), and cannot overwrite a variable the sandbox already uses.
    services: list[ServiceSpec] = Field(default_factory=list)
    #: Files that pin the dependencies, relative to the repository root, in the order they should
    #: be copied. They are also the cache key: change one and the image is rebuilt, change none and
    #: it is reused.
    dependencies: list[str] = Field(default_factory=list)

    #: Whether the install step needs the repository's **source**, not only its dependency files.
    #: Item 113. Off by default, and the default is the right one for most projects.
    #:
    #: **What it costs, plainly, because it is the reason this is not simply always on:** the image
    #: is keyed by what goes into it, so an image built from the source is rebuilt whenever the
    #: source changes — which is every attempt. That is minutes per attempt instead of seconds, and
    #: for a project that does not need it, it buys nothing at all.
    #:
    #: **What it buys**, measured on three real repositories whose installers cannot work without
    #: it: a `Gemfile` that says `gemspec` reads the library it describes; a `requirements-dev.txt`
    #: beginning with `-e .` installs the project; and `mvn test` finds no tests in a context of
    #: bare `pom.xml` files, so Surefire never resolves the provider it will need at attempt time.
    #: All three are ordinary ways to write a project, and none of them could be served at all.
    install_needs_source: bool = False

    @field_validator("base")
    @classmethod
    def _a_base_is_an_image_reference(cls, value: str) -> str:
        """A short name from `BASE_IMAGES`, or an image reference. Item 068, DR-0007 part 3.

        The grammar is the security property, and the newline is the character that matters: `base`
        goes into a Dockerfile's `FROM` line and the instructions are joined with `\n`, so one
        newline appends instructions of the author's choosing rather than naming a strange image.
        """
        name = value.strip()
        if not IMAGE_REFERENCE.match(name):
            msg = (
                f"runtime.base: {value!r} is neither one of this instance's short names nor a "
                f"usable image reference — letters, digits and . _ - / : @ only, no whitespace, "
                f"up to 200 "
                f"characters. `hullwork projects add` lists the short names."
            )
            raise ValueError(msg)
        return name

    @field_validator("install")
    @classmethod
    def _an_install_fits_on_one_line(cls, value: str) -> str:
        """One of the six recipes, or a command. Item 068.

        The only structural rule is that it fits on one line, and that is not tidiness: the command
        is interpolated into `RUN {command}` and the result is joined with `\n`. A newline here
        turns
        a dependency install into a Dockerfile of somebody else's choosing.
        """
        command = value.strip()
        if not _NO_NEWLINES.match(command):
            msg = (
                "runtime.install: an install command must fit on one line and be under 2000 "
                "characters. It is interpolated into a Dockerfile instruction, so a newline would "
                "add instructions rather than arguments."
            )
            raise ValueError(msg)
        return command

    @field_validator("packages")
    @classmethod
    def _packages_are_package_names(cls, value: list[str]) -> list[str]:
        """Debian package names, per policy §5.6.1. Item 068.

        **The leading character is the one that matters.** `apt-get install` reads a name beginning
        with `-` as a flag, which is argument injection rather than a typo, and these are installed
        as
        root at build time.
        """
        for package in value:
            if not PACKAGE_NAME.match(package.strip()):
                msg = (
                    f"runtime.packages: {package!r} is not a Debian package name — lowercase "
                    f"letters, digits, +, - and ., starting with a letter or digit, up to 80 "
                    f"characters"
                )
                raise ValueError(msg)
        return [package.strip() for package in value]

    @field_validator("dependencies")
    @classmethod
    def _stay_inside_the_repository(cls, value: list[str]) -> list[str]:
        for path in value:
            cleaned = path.strip()
            if not cleaned or cleaned.startswith("/") or not _TEST_PATH.match(cleaned):
                msg = (
                    f"runtime.dependencies: {path!r} must be a path inside the repository — "
                    f"letters, digits and . _ - / only, not absolute"
                )
                raise ValueError(msg)
            if ".." in cleaned.split("/"):
                msg = f"runtime.dependencies: {path!r} must not climb out of the repository"
                raise ValueError(msg)
        return [p.strip() for p in value]

    @model_validator(mode="after")
    def _the_installer_has_to_fit_the_base(self) -> "RuntimeConfig":
        # **Only for the short names**, since item 068 opened this field. `python-3.12` tells the
        # instance the family and therefore which installers make sense; an arbitrary image
        # reference tells it nothing, and inventing a family from the first path segment is how this
        # check refused every legitimate reference the moment the field opened — three of three.
        #
        # With an unknown base, the project's choice of installer stands and the build is where it
        # is found out. That is the trade DR-0007 part 3 accepts, and it is why a failed build has
        # to
        # name the command it ran (item 068's last criterion) rather than only its exit code.
        family = self.base.split("-", 1)[0]
        allowed = _BASE_INSTALLERS.get(family, frozenset())
        # **And only for the recipes.** A recipe has to fit the family — `npm` on a Python base is a
        # manifest that cannot work, and saying so at parse time is free. An arbitrary command is
        # the
        # project's business on any base: `base: python-3.12` with `install: make bootstrap` is a
        # perfectly ordinary project, and refusing it would keep the closed set alive under a
        # different name. Caught by a test that expected exactly that combination to work.
        recipes = frozenset().union(*_BASE_INSTALLERS.values())
        if allowed and self.install in recipes and self.install not in allowed:
            msg = (
                f"runtime.install: {self.install!r} does not go with base {self.base!r} — "
                f"choose one of {sorted(allowed)}, or name an image and any command you like"
            )
            raise ValueError(msg)
        if self.install != "none" and not self.dependencies:
            msg = (
                f"runtime.dependencies: {self.install!r} needs at least one dependency file to "
                f"install from"
            )
            raise ValueError(msg)
        if self.install == "pip" and self.dependencies:
            # `pip` means `pip install -r`, and `-r` reads a requirements file. Handed a
            # `pyproject.toml` it answers "Invalid requirement: '[build-system]'" — measured, and
            # this repository's own manifest declared exactly that combination for weeks, unnoticed
            # because nothing ever built the image (item 051). Accepting a declaration that cannot
            # work is the defect; refusing it here is where it costs nothing to fix.
            first = self.dependencies[0].rsplit("/", 1)[-1]
            if not first.endswith(".txt"):
                msg = (
                    f"runtime.install: 'pip' installs from a requirements file and {first!r} is "
                    f"not one — `pip install -r` cannot read a pyproject or a lock. Use 'uv' or "
                    f"'poetry' for those, or point this at a requirements .txt"
                )
                raise ValueError(msg)
        return self


class NotifyConfig(_Strict):
    """Where the digest goes. Never one message per event.

    `telegram` and `email` parse but are not deliverable yet. The manifest is a contract that
    outlives any one build, so refusing to *parse* them would break these files the day the
    transports land; the notifier refuses to *deliver* them instead, loudly.
    """

    channel: Literal["none", "console", "telegram", "email"] = "none"


class Manifest(_Strict):
    """A project's declaration of how Hullwork should treat it."""

    version: int = SCHEMA_VERSION
    project: str
    git: GitConfig
    errors: ErrorsConfig = Field(default_factory=ErrorsConfig)
    ci: Literal["forgejo-actions", "github-actions", "none"] = "none"
    deploy: Literal["compose", "ftp", "argocd", "none"] = "none"
    autofix: AutofixConfig = Field(default_factory=AutofixConfig)
    tests: str | None = None

    #: What the sandbox is built from. Absent means no agent can run here, and the validator below
    #: says so rather than letting an attempt discover it.
    runtime: RuntimeConfig | None = None

    #: The command behind the `lint` gate. Separate from `tests` so that a project which bundles
    #: everything into one command can say so by naming only the `tests` gate, instead of having
    #: the same suite run twice and be reported as two independent verifications.
    lint: str | None = None

    #: The only directory an agent may create a reproducing test in (spec M2 §3). A phase allowed
    #: to write anywhere can reach a red gate by breaking something instead of by reproducing
    #: anything — a root `conftest.py` is the cheapest version of that.
    test_path: str = "tests"

    health_url: str | None = None
    notify: NotifyConfig = Field(default_factory=NotifyConfig)

    @field_validator("test_path")
    @classmethod
    def _stays_inside_the_repository(cls, value: str) -> str:
        cleaned = value.strip().rstrip("/")
        if not cleaned:
            msg = "test_path: cannot be empty"
            raise ValueError(msg)
        if cleaned.startswith("/") or not _TEST_PATH.match(cleaned):
            msg = (
                f"test_path: {value!r} must be a path inside the repository — letters, digits "
                f"and . _ - / only, not absolute, up to 128 characters"
            )
            raise ValueError(msg)
        if ".." in cleaned.split("/"):
            msg = f"test_path: {value!r} must not climb out of the repository"
            raise ValueError(msg)
        return cleaned

    @field_validator("version")
    @classmethod
    def _from_the_future_is_refused_clearly(cls, value: int) -> int:
        if value > SCHEMA_VERSION:
            msg = (
                f"this manifest is version {value} and this Hullwork understands "
                f"{SCHEMA_VERSION} — upgrade Hullwork, or pin the manifest to a version it knows"
            )
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _an_agent_needs_a_way_to_verify_itself(self) -> "Manifest":
        """Every gate an agent will be held to must have something behind it.

        Checked only when an agent is named, because gates govern **attempts** and with
        `agent: none` nothing is ever attempted. Demanding a test command from a project that only
        wants triage would be asking for a promise it has no reason to keep — and triage with no
        external model call is the default, not a degraded mode (DR-0002).

        `tests` is stronger than the others: DR-0003 makes a reproducing test the whole basis of a
        fix, so it can no more be dropped from `gates` than `human-merge` can. An agent with
        nothing to run cannot produce that evidence, and letting it try produces exactly the
        unverifiable diff the rule exists to prevent.
        """
        if self.autofix.agent == "none":
            return self

        problems: list[str] = []
        if self.runtime is None:
            problems.append(
                "runtime: an agent needs a sandbox to run in, and this manifest does not say what "
                "it is made of — declare `runtime.base`, or leave autofix.agent as 'none'"
            )
        if not (self.tests or "").strip():
            problems.append(
                "tests: a test command is required when autofix.agent is set — the agent must "
                "prove its fix with a test that failed before it (DR-0003)"
            )
        if "tests" not in self.autofix.gates:
            problems.append(
                "autofix.gates: 'tests' cannot be removed when an agent is named — a fix lands "
                "only as a test that failed before it (DR-0003)"
            )
        if "lint" in self.autofix.gates and not (self.lint or "").strip():
            problems.append(
                "lint: the 'lint' gate is named in autofix.gates but no lint command is declared "
                "— declare one, or remove the gate"
            )

        if problems:
            raise ValueError("; ".join(problems))
        return self


def _problems(exc: ValidationError) -> list[str]:
    """Render every pydantic error as `key.path: what is wrong (got: what you wrote)`.

    The offending value is quoted back on purpose. "Input should be 'tests', 'lint' or
    'human-merge'" tells an operator the rule and leaves them hunting for which entry broke it —
    and the entry is usually a typo they will read straight past in their own file.
    """
    rendered = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "(root)"
        got = error.get("input")
        # Only for short scalars: echoing a whole nested mapping back would bury the message.
        suffix = f" (got: {got!r})" if isinstance(got, str | int | float | bool) else ""
        rendered.append(f"{location}: {error['msg']}{suffix}")
    return rendered


def parse_manifest(text: str, source: str = "<string>") -> Manifest:
    """Parse manifest text. Use this for content fetched from a forge; `load_manifest` for files."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        # Includes the constructor error raised when a payload tries to instantiate Python objects.
        raise ManifestError(source, [f"not valid YAML: {exc}"]) from exc

    if raw is None:
        raise ManifestError(source, ["file is empty"])
    if not isinstance(raw, dict):
        found = type(raw).__name__
        raise ManifestError(source, [f"expected a mapping at the top level, found {found}"])

    try:
        return Manifest.model_validate(raw)
    except ValidationError as exc:
        raise ManifestError(source, _problems(exc)) from exc


def load_manifest(path: Path) -> Manifest:
    """Read and parse a manifest from disk."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(str(path), [f"cannot be read: {exc.strerror}"]) from exc
    return parse_manifest(text, source=str(path))
