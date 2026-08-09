"""Reading the answer the repository already wrote. Item 107, DR-0007's amendment.

**The measurement this rests on.** DR-0007 concluded that a project's own files cannot
answer Hullwork's question, on the strength of `acme`'s Dockerfile: `RUN pip
install .` installs the project and not its dev dependencies, so a sandbox built from it
has no pytest. True, and about the wrong file — a Dockerfile is a *deployment* artefact.

A CI configuration is a *test* artefact, and it is green on the default branch by
construction. This repository's own is checked in below as a fixture, because a reader
tested only against workflows written for the test is a reader tested against itself.

**One reader, three formats.** Formats that describe an environment are about three and
they are language-neutral; ecosystems are about fifty and keep arriving. That asymmetry
is the whole reason this is a translation rather than a treadmill, and it is what these
tests are asserting — not that the word lists are complete.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from hullwork import propose
from hullwork.manifest import ManifestError, parse_manifest

ROOT = Path(__file__).resolve().parent.parent

#: A GitHub Actions workflow that names its container. DR-0007's path (B), found
#: automatically: the project already runs its tests in that image, so there is nothing
#: for Hullwork to build and nothing for it to know.
WITH_A_CONTAINER = """
name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/acme/ci-base:2026.7
    steps:
      - uses: actions/checkout@v4
      - run: go mod download
      - run: go test ./...
      - run: golangci-lint run
"""

#: GitLab, whose shape is different enough to be worth a fixture: jobs at the top level,
#: `script` as a list of bare strings, and an `image` that is not under `container`.
GITLAB = """
image: ruby:3.3
stages: [test]
variables:
  BUNDLE_PATH: vendor
rspec:
  stage: test
  before_script:
    - apt-get update && apt-get install -y --no-install-recommends libpq-dev imagemagick
    - bundle install
  script:
    - bundle exec rspec
    - bundle exec rubocop
"""

#: A workflow that sets up a language version this instance has no short name for.
#: Inventing `python-3.11` would propose a manifest that cannot build.
UNKNOWN_VERSION = """
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pytest
"""


def test_it_reads_this_repositorys_own_ci_and_gets_every_field() -> None:
    """**The measurement the whole item rests on**, against the real file.

    Not a fixture written for the test: `.forgejo/workflows/ci.yml` as this repository
    actually runs it. Four fields, and the install command carries `[dev]` — precisely
    what DR-0007 found missing in the Dockerfile.
    """
    path = ".forgejo/workflows/ci.yml"
    text = (ROOT / path).read_text(encoding="utf-8")

    proposal = propose.read("easybyte/hullwork", path, text)

    assert proposal.base == "python-3.12"
    # **The install line moved to uv when CI started installing from the lock** (item 149), and the
    # derivation is why those two `run:` steps became one: this reader takes the first
    # install-shaped step, and `pip install uv` alone is a true line and a wrong answer. Caught by
    # this test failing, which is the only reason the workflow reads the way it does.
    assert proposal.install == "pip install uv && uv sync --frozen --extra dev"
    # Whatever the workflow actually runs, read back faithfully — `-ra` since CI started printing
    # skip reasons, and `uv run` since it started using the locked environment.
    assert proposal.tests == "uv run pytest -ra"
    assert proposal.lint == "uv run ruff check ."
    assert proposal.found_anything is True


def test_the_proposal_is_a_manifest_that_parses() -> None:
    """**The property that was nearly shipped broken.**

    A proposal is a manifest, so every line of it has to be a manifest line. The first
    version printed an unplaced CI step whole — and this repository's DCO check is a
    twelve-line shell script, so its second line onwards landed in the file without a
    `#`, and the rendered proposal did not parse as YAML at all.

    Asserted twice, because "it is YAML" and "it is a manifest Hullwork accepts" are
    different claims and only the second one is useful.
    """
    path = ".forgejo/workflows/ci.yml"
    rendered = propose.render(
        propose.read("easybyte/hullwork", path, (ROOT / path).read_text(encoding="utf-8"))
    )

    assert isinstance(yaml.safe_load(rendered), dict)
    manifest = parse_manifest(rendered)
    assert manifest.tests == "uv run pytest -ra"
    assert manifest.runtime is not None
    assert manifest.runtime.base == "python-3.12"


def test_an_explicit_container_becomes_the_base_and_needs_no_mapping() -> None:
    """DR-0007's most agnostic path, found without anybody choosing it.

    An image the project's CI already runs its tests in needs no short name, no version
    mapping and nothing on Hullwork's side. It is also a Go project, which is one of the
    languages the closed sets could not express at all before item 068.
    """
    proposal = propose.read("acme/thing", ".github/workflows/ci.yml", WITH_A_CONTAINER)

    assert proposal.base == "ghcr.io/acme/ci-base:2026.7"
    # **`go mod`, not the command the CI runs** (item 112): the recipe puts the module cache
    # outside the worktree, which the mount replaces at attempt time, and sets `GOMODCACHE` where
    # a login shell reads it. The observed command is kept in a note — see the test for that in
    # `test_any_stack.py`.
    assert proposal.install == "go mod"
    assert proposal.tests == "go test ./..."
    assert proposal.lint == "golangci-lint run"


def test_gitlab_is_the_same_reader() -> None:
    """The third format, and the point of the asymmetry: one reader, not one per stack.

    A Ruby project here, with its system packages inside a `before_script` — which is
    where they live in real CI files, not in a field.
    """
    proposal = propose.read("acme/shop", ".gitlab-ci.yml", GITLAB)

    assert proposal.base == "ruby:3.3"
    assert proposal.install == "bundle"  # the recipe, for the reason above (item 112)
    assert proposal.tests == "bundle exec rspec"
    assert proposal.lint == "bundle exec rubocop"
    assert proposal.packages == ("libpq-dev", "imagemagick")
    assert proposal.dependencies == ("Gemfile", "Gemfile.lock")


def test_a_version_with_no_short_name_is_not_invented_as_one() -> None:
    """**The rule that makes a word-list reader safe**, and DR-0006's in its own words:
    write what was observed, comment out what was inferred.

    `python-3.11` is not a name `BASE_IMAGES` has, so proposing it would produce a
    manifest that cannot build — confident and wrong, which is worse than vague.

    **Rewritten 2026-08-01 by item 111, and it asserts something stronger.** The original
    ended at `proposal.base is None`: leave the field for a human. Measured on eight real
    repositories, that policy left *six of eight* with no base at all — the one field that
    decides whether a project can be built — because only Python and Node had a short name.
    A full image reference is legal since item 068 and `python:3.11` is an image that
    exists, so the proposal now names it. What must never happen is still asserted, and it
    is the actual defect this test was guarding: an invented **short name** that this
    instance cannot resolve.
    """
    proposal = propose.read("acme/old", ".github/workflows/ci.yml", UNKNOWN_VERSION)

    assert proposal.base == "python:3.11", "a real image, read off the workflow"
    assert "python-3.11" not in propose.render(proposal), "never a short name nothing resolves"
    # And it builds: the base a proposal names has to be one the parser accepts.
    assert parse_manifest(propose.render(proposal)).runtime is not None


def test_a_second_linter_is_reported_as_a_second_one() -> None:
    """Not as a failure to classify. The manifest has one `lint` field and this
    repository's CI runs `ruff` **and** `mypy`; dropping the second into "could not
    place" reads as though the reader broke, when what it found is a field wanting both.
    """
    path = ".forgejo/workflows/ci.yml"
    proposal = propose.read(
        "easybyte/hullwork", path, (ROOT / path).read_text(encoding="utf-8")
    )

    assert any("a second linter" in note and "mypy" in note for note in proposal.notes)
    assert not any("mypy" in step for step in proposal.unclassified)


def test_a_runner_label_is_never_proposed_as_an_image() -> None:
    """`ubuntu-latest` is not an image reference, and proposing it would be unbuildable.

    Said once rather than once per job: every job in a workflow names the same runner,
    and repeating it makes the rest of the comment look like noise too.
    """
    path = ".forgejo/workflows/ci.yml"
    rendered = propose.render(
        propose.read("easybyte/hullwork", path, (ROOT / path).read_text(encoding="utf-8"))
    )

    assert rendered.count("runner label") == 1
    assert "base: ubuntu-latest" not in rendered


# --- giving up out loud ---------------------------------------------------------------


def test_a_file_that_is_not_yaml_gives_up_and_says_so() -> None:
    """DR-0007 named the cost of reading these files: a parser for a large grammar *"must
    be allowed to give up and say so rather than half-understand one"*. This is that."""
    proposal = propose.read("acme/thing", ".github/workflows/ci.yml", "{{{ not yaml")

    assert proposal.found_anything is False
    assert any("not valid YAML" in note for note in proposal.notes)


def test_a_yaml_file_with_nothing_recognisable_proposes_nothing() -> None:
    proposal = propose.read("acme/thing", ".gitlab-ci.yml", "stages: [build]\n")
    rendered = propose.render(proposal)

    assert proposal.found_anything is False
    # **Restated 2026-08-01 by item 111**: the whole `runtime:` block is commented out now,
    # not just the `base:` line, so the spelling changed from `# base:` to `#   base:`. The
    # property is the same and the assertion is stronger — a proposal with nothing in it has
    # to *parse*, which is what four real repositories proved it did not.
    assert "#   base: <an image your tests run in" in rendered
    assert rendered.count("base: <") == 1, "one field left for a human, not two"
    parse_manifest(rendered)


def test_finding_the_file_prefers_the_forges_own_dialect() -> None:
    """A repository can carry both — mirrored to GitHub, or migrating — and the one this
    forge runs is the one whose result is true here."""
    paths = [
        "README.md",
        ".github/workflows/release.yml",
        ".github/workflows/ci.yml",
        ".forgejo/workflows/ci.yml",
        ".gitlab-ci.yml",
    ]

    assert propose.find(paths)[0] == ".forgejo/workflows/ci.yml"
    assert ".gitlab-ci.yml" in propose.find(paths)
    assert propose.find("not a list") == []
    assert propose.find(["README.md"]) == []


def test_a_step_that_is_a_shell_script_is_shown_as_one_line() -> None:
    """The defect that made the output unparseable, from the other side."""
    workflow = """
jobs:
  test:
    steps:
      - run: |
          set -e
          echo one
          echo two
"""
    rendered = propose.render(propose.read("acme/thing", ".github/workflows/ci.yml", workflow))

    # The property, stated as what went wrong: no line of the script escapes into the file
    # on its own. `echo two` was such a line, and it made the proposal unparseable.
    assert "\necho two" not in rendered
    # **Item 111 removed the truncation this used to assert, by removing its cause.** A
    # `run: |` block is several commands and is now split into them — `sinatra/sinatra`'s
    # test command was the second line of one — so each is short and shown whole. The
    # truncation still exists for a single command longer than the limit; what no longer
    # happens is a three-line script arriving as one string.
    assert "#   - echo two" in rendered, "each command on its own commented line"
    # And the whole thing is still a manifest, which is the claim that matters.
    assert isinstance(yaml.safe_load(rendered), dict)


def test_nothing_it_proposes_is_ever_a_lane() -> None:
    """Since M8 the instance derives which code is dangerous from the path an error came
    from, so an empty `autofix` is fully configured — and a proposal that guessed lanes
    would be re-introducing the word lists DR-0008 measured as a poor predictor."""
    path = ".forgejo/workflows/ci.yml"
    rendered = propose.render(
        propose.read("easybyte/hullwork", path, (ROOT / path).read_text(encoding="utf-8"))
    )

    parsed = yaml.safe_load(rendered)
    assert "autofix" not in parsed
    assert "projects lanes" in rendered, "it should say where the policy can be read"


def test_a_proposal_never_names_an_agent() -> None:
    """An agent is an operator's decision on their own instance (item 017), and a
    proposal that pre-filled it would be a repository choosing to be acted on."""
    for text in (WITH_A_CONTAINER, GITLAB, UNKNOWN_VERSION):
        rendered = propose.render(propose.read("a/b", ".github/workflows/ci.yml", text))
        parsed = yaml.safe_load(rendered)
        assert "autofix" not in parsed
        # And what it does parse as is a manifest, on all three.
        try:
            parse_manifest(rendered)
        except ManifestError as exc:  # pragma: no cover - a failure here is the point
            pytest.fail(f"the proposal for {text[:24]!r} is not a manifest: {exc}")


# --- Which forge holds this. Item 171. -------------------------------------------------
#
# The defect: `render` emitted `provider: forgejo` as a constant, uncommented, so it read
# as observed while no code path could produce any other value. Found by running the
# command against a checkout hosted on GitHub and reading the two lines it printed.


def test_the_remote_host_decides_when_it_is_one_that_can_be_recognised() -> None:
    """`github.com` and `gitlab.com` are the only hosts that name themselves.

    Everything else is self-hosted and unresolvable without asking it, which `propose`
    may never do — it reaches nothing and needs no credential.
    """
    assert propose.forge_for(".github/workflows/ci.yml", "github.com").provider == "github"
    assert propose.forge_for(".gitlab-ci.yml", "gitlab.com").provider == "gitlab"


def test_the_github_workflows_directory_is_not_evidence_of_github() -> None:
    """**The finding that stops this being a one-line change.**

    Forgejo Actions and Gitea Actions both read `.github/workflows/`, and this repository's
    own deployment is the proof — those workflows run on a Forgejo instance. Reading that
    directory as GitHub would be wrong for exactly the self-hosted projects this is for.

    This test exists to fail if somebody later "improves" the mapping.
    """
    guess = propose.forge_for(".github/workflows/ci.yml", "git.example.com")
    assert guess.evidence is None, "that directory settles nothing on an unknown host"
    assert guess.provider == propose.PROVIDER_WHEN_UNDECIDED


def test_the_ci_location_decides_when_the_host_cannot() -> None:
    """A self-hosted host says nothing; the three unambiguous directories say plenty."""
    for source, expected in (
        (".forgejo/workflows/ci.yml", "forgejo"),
        (".gitea/workflows/ci.yml", "gitea"),
        (".gitlab-ci.yml", "gitlab"),
    ):
        guess = propose.forge_for(source, "git.example.com")
        assert guess.provider == expected, source
        assert guess.evidence is not None


def test_the_host_outranks_the_ci_location() -> None:
    """Where the repository lives beats which runner reads its workflows.

    A GitHub repository whose workflows sit in `.forgejo/workflows/` is a mirror, and the
    coordinate a manifest needs is the one that answers requests.
    """
    assert propose.forge_for(".forgejo/workflows/ci.yml", "github.com").provider == "github"


def test_a_remote_url_gives_up_its_host_in_both_spellings() -> None:
    """`https://` and the `git@host:owner/name` form, plus what is not a URL at all."""
    assert propose.host_of_remote("https://github.com/owner/repo.git") == "github.com"
    assert propose.host_of_remote("git@github.com:owner/repo.git") == "github.com"
    assert propose.host_of_remote("ssh://git@forge.example.com/o/r") == "forge.example.com"
    assert propose.host_of_remote(None) is None
    assert propose.host_of_remote("not a url") is None


def test_an_undecided_provider_says_so_instead_of_looking_read() -> None:
    """The whole point of the item: a default must not wear the costume of a reading.

    `render`'s contract is that uncommented means observed. When nothing decided, the line
    still has to carry a value — `git.provider` is required and an unparseable proposal is
    worse — so it carries the default *and says which two things would have settled it*.
    """
    rendered = propose.render(propose.read("a/b", ".github/workflows/ci.yml", WITH_A_CONTAINER))
    lines = rendered.splitlines()
    git_at = next(i for i, line in enumerate(lines) if line.startswith("git:"))

    assert "provider: forgejo" in lines[git_at]
    said_it = "\n".join(lines[max(0, git_at - 3) : git_at])
    assert "default, not a reading" in said_it, "an undecided value has to admit that it is one"
    assert ".github/workflows/" in said_it, "and say why that directory settled nothing"
    parse_manifest(rendered)  # and it still parses, which is why the value stays


def test_a_decided_provider_does_not_apologise_for_itself() -> None:
    """The mirror of the test above: an observation must not read as a guess."""
    proposal = propose.read("a/b", ".github/workflows/ci.yml", WITH_A_CONTAINER)
    proposal.remote_host = "github.com"
    rendered = propose.render(proposal)

    assert "provider: github" in rendered
    git_line = next(line for line in rendered.splitlines() if line.startswith("git:"))
    assert "default" not in git_line
    parse_manifest(rendered)


def test_the_header_and_the_provider_can_never_contradict_each_other() -> None:
    """The defect as a reader saw it: a header naming one forge's file, then another's name.

    Asserted for the three locations that decide, on a host that decides nothing — which is
    where the contradiction was reachable.
    """
    for source, text, expected in (
        (".forgejo/workflows/ci.yml", WITH_A_CONTAINER, "forgejo"),
        (".gitea/workflows/ci.yml", WITH_A_CONTAINER, "gitea"),
        (".gitlab-ci.yml", GITLAB, "gitlab"),
    ):
        proposal = propose.read("a/b", source, text)
        proposal.remote_host = "git.example.com"
        rendered = propose.render(proposal)
        header = rendered.splitlines()[0]
        assert source in header
        assert f"provider: {expected}" in rendered, f"{header} then a different forge"


def test_the_command_itself_carries_the_host_to_the_proposal(tmp_path: Path) -> None:
    """**The test the other eight did not make redundant**, and the reason it exists.

    Every assertion above exercises pure functions. Deleting the one line in `cli.py` that
    reads the remote and hands its host to the proposal left all of them green — so the whole
    repair would have been reachable for deletion without a single test noticing, which is the
    shape of defect item 116 found (a test that passes with its own subject removed).

    This drives the command against a real checkout with a real `origin`, which is how the
    defect was found in the first place.
    """
    from hullwork.cli import propose_from_local_ci

    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(WITH_A_CONTAINER, encoding="utf-8")

    for argv in (
        ["init", "-q"],
        ["add", "-A"],
        ["remote", "add", "origin", "https://github.com/owner/thing.git"],
    ):
        done = subprocess.run(  # noqa: S603
            ["git", "-C", str(tmp_path), *argv],  # noqa: S607
            capture_output=True, text=True, check=False,
        )
        assert done.returncode == 0, done.stderr

    rendered = propose_from_local_ci(tmp_path)
    assert rendered is not None
    assert "git: {provider: github, repo: owner/thing}" in rendered
    parse_manifest(rendered)


def test_a_proposal_with_no_installer_says_what_that_costs() -> None:
    """Item 185. Every field this reader cannot fill carries a comment saying what is missing;
    `install` carried none, and its absence is the one that is invisible.

    **Because the manifest it produces parses and builds perfectly.** What it cannot do is measure a
    dependency upgrade: with no installer the image is the base exactly as it comes, so rewriting a
    pinned version changes nothing the suite runs against. Measured on 2026-08-09 (item 182) before
    this comment existed — a checkout pinning `jinja2==2.4.1`, a base image carrying 3.0.0, and a
    verdict reading *your suite passed before this change and passes after it*, about a version that
    was never installed.
    """
    proposal = propose.Proposal(repo="o/r", source="ci.yml", base="python-3.12", tests="pytest")

    text = propose.render(proposal)

    assert "cannot be **measured**" in text
    assert "changes nothing your suite would run against" in text
    # **And what to do about it, which item 188 added.** Saying only the cost sent a reader with an
    # image of their own away from a feature that serves them: `base` takes any image and `install`
    # takes their own command, so the answer is one layer on top of what they already named — not a
    # rebuild from scratch, and not a stack anybody has to add.
    assert "keep this base and add two lines" in text
    assert "one layer on top of the image you named" in text
    # The command is not named: it is not in the published image, and naming something a reader
    # cannot run invites them to type it and be told it does not exist.
    assert "hullwork deps" not in text


def test_a_proposal_that_names_an_installer_says_nothing_of_the_kind() -> None:
    """The note is about an absence. A manifest that can measure must not carry a caveat it earned
    nothing of — a warning printed for everybody is a warning nobody reads."""
    proposal = propose.Proposal(
        repo="o/r", source="ci.yml", base="python-3.12", tests="pytest",
        install="pip", dependencies=("requirements.txt",),
    )

    text = propose.render(proposal)

    assert "cannot be **measured**" not in text
    assert "install: 'pip'" in text


def test_a_proposal_with_no_base_does_not_lecture_about_installers() -> None:
    """Without a base the whole `runtime` block is commented out and refused anyway (item 111).
    Adding a second paragraph about a third field there is noise on top of a refusal."""
    proposal = propose.Proposal(repo="o/r", source="ci.yml", tests="pytest")

    text = propose.render(proposal)

    assert "cannot be **measured**" not in text
