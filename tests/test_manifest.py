"""The manifest is the public interface, so its parser is tested like one.

Each rejection here is a way a project could otherwise believe it has a guardrail that it does
not actually have.
"""

from pathlib import Path

import pytest

from hullwork.manifest import (
    HUMAN_MERGE,
    Manifest,
    ManifestError,
    load_manifest,
    parse_manifest,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_the_full_example_from_the_spec_parses() -> None:
    manifest = load_manifest(FIXTURES / "manifest-full.yml")

    assert manifest.project == "demo"
    assert manifest.git.provider == "forgejo"
    assert manifest.git.repo == "acme/demo"
    assert manifest.autofix.agent == "claude-code"
    assert manifest.autofix.lanes.red == ["secrets", "auth", "payments"]
    assert manifest.notify.channel == "telegram"


def test_a_minimal_manifest_defaults_to_no_agent() -> None:
    # DR-0002: the product is fully useful with no external model call, so `none` is the default.
    manifest = load_manifest(FIXTURES / "manifest-minimal.yml")

    assert manifest.autofix.agent == "none"
    assert HUMAN_MERGE in manifest.autofix.gates
    assert manifest.notify.channel == "none"


def test_human_merge_cannot_be_removed() -> None:
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix:
      gates: [tests, lint]
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "human-merge" in str(caught.value)
    assert "cannot be removed" in str(caught.value)


def test_an_unknown_key_is_rejected_rather_than_ignored() -> None:
    # The dangerous version of this typo is in a lane name; the mechanism is the same.
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix:
      lanes: {green: [], amber: [], redd: [secrets]}
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "redd" in str(caught.value)


def test_every_problem_is_reported_at_once() -> None:
    text = """
    project: p
    git: {provider: bitbucket, repo: not-a-repo}
    ci: jenkins
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    problems = caught.value.problems
    assert len(problems) >= 3
    joined = " ".join(problems)
    assert "git.provider" in joined
    assert "git.repo" in joined
    assert "ci" in joined


def test_an_agent_without_a_test_command_is_rejected() -> None:
    # DR-0003: no way to run tests means no way to prove the fix, so the agent may not be enabled.
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix: {agent: claude-code}
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "test command is required" in str(caught.value)


def test_a_repository_cannot_supply_the_command_this_host_will_run() -> None:
    """A manifest may NAME an agent; it may never supply an executable.

    This used to be accepted as `agent: {custom: "..."}`. The manifest arrives from a repository —
    the module says so in its first paragraph — so that field let whoever can push to a connected
    project's default branch choose what this host executes, the moment M2 turned the field into
    an exec. Adding an engine is an instance-side decision (item 017).
    """
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix:
      agent: {custom: "./scripts/my-agent.sh"}
    tests: "pytest"
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "autofix.agent" in str(caught.value)


def test_a_yaml_tag_that_would_build_a_python_object_is_refused() -> None:
    # The manifest comes from a repository. safe_load is the only loader allowed here.
    text = "project: !!python/object/apply:os.system ['echo pwned']\n"

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "not valid YAML" in str(caught.value)


def test_an_empty_file_says_so() -> None:
    with pytest.raises(ManifestError) as caught:
        parse_manifest("")

    assert "empty" in str(caught.value)


def test_a_top_level_list_is_refused_clearly() -> None:
    with pytest.raises(ManifestError) as caught:
        parse_manifest("- one\n- two\n")

    assert "mapping" in str(caught.value)


def test_a_repo_without_an_owner_is_refused() -> None:
    text = """
    project: p
    git: {provider: forgejo, repo: justaname}
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "owner/name" in str(caught.value)


def test_a_missing_file_reports_the_path() -> None:
    with pytest.raises(ManifestError) as caught:
        load_manifest(FIXTURES / "does-not-exist.yml")

    assert "does-not-exist.yml" in str(caught.value)


# --- item 021: a gate must have something to run ------------------------------------------------


def test_the_lint_gate_is_not_on_by_default() -> None:
    """It used to be, and it ran nothing.

    `gates` accepted `lint`, `DEFAULT_GATES` included it, and no lint command existed anywhere in
    the schema — so every manifest ever written claimed a gate that could not run. A default may
    only name a gate the defaults can also satisfy.
    """
    manifest = load_manifest(FIXTURES / "manifest-minimal.yml")

    assert "lint" not in manifest.autofix.gates
    assert HUMAN_MERGE in manifest.autofix.gates
    assert "tests" in manifest.autofix.gates


def test_naming_the_lint_gate_without_a_lint_command_is_refused() -> None:
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix:
      agent: claude-code
      gates: [tests, lint, human-merge]
    tests: "pytest"
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "no lint command is declared" in str(caught.value)


def test_a_snapshot_written_by_an_older_build_still_validates() -> None:
    """The registered projects on the live instance look exactly like this.

    `_manifest_for` re-validates the cached snapshot against whatever code is running, and a
    snapshot that stops validating degrades every incoming error to red (item 020). Both live
    manifests carry `gates: [tests, lint, human-merge]` with no `lint` command, because none could
    exist before this change — so an unconditional lint rule would have turned a schema improvement
    into a silent outage on two deployed projects. Tying gate checks to a named agent is what keeps
    that from happening, and this is the test that says so.
    """
    snapshot = {
        "project": "hullwork",
        "git": {"provider": "forgejo", "repo": "easybyte/hullwork"},
        "autofix": {"agent": "none", "gates": ["tests", "lint", "human-merge"]},
        "tests": "ruff check . && mypy . && pytest",
    }

    manifest = Manifest.model_validate(snapshot)

    assert manifest.autofix.gates == ["tests", "lint", "human-merge"]
    assert manifest.test_path == "tests"


def test_the_lint_gate_with_its_command_validates() -> None:
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix:
      agent: claude-code
      gates: [tests, lint, human-merge]
    tests: "pytest"
    lint: "ruff check ."
    runtime: {base: python-3.12, install: pip, dependencies: [requirements.txt]}
    """

    manifest = parse_manifest(text)

    assert manifest.lint == "ruff check ."
    assert "lint" in manifest.autofix.gates


def test_gates_are_inert_without_an_agent() -> None:
    """They govern attempts, and with `agent: none` nothing is ever attempted.

    Demanding a test command from a project that only wants triage would be asking for a promise it
    has no reason to keep — and triage with no external model call is the default, not a degraded
    mode (DR-0002).
    """
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix:
      gates: [tests, lint, human-merge]
    """

    manifest = parse_manifest(text)

    assert manifest.autofix.agent == "none"
    assert manifest.tests is None
    assert manifest.lint is None


def test_the_tests_gate_cannot_be_dropped_when_an_agent_is_named() -> None:
    # DR-0003: a fix lands only as a test that failed before it, so `tests` is as mandatory as
    # `human-merge` the moment an agent exists to be held to it.
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix:
      agent: claude-code
      gates: [human-merge]
    tests: "pytest"
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "'tests' cannot be removed" in str(caught.value)


def test_a_blank_command_does_not_satisfy_a_gate() -> None:
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    autofix:
      agent: claude-code
      gates: [tests, lint, human-merge]
    tests: "   "
    lint: ""
    """

    with pytest.raises(ManifestError) as caught:
        parse_manifest(text)

    assert "test command is required" in str(caught.value)
    assert "no lint command is declared" in str(caught.value)


# --- item 021: test_path is a boundary ----------------------------------------------------------


def test_test_path_defaults_to_tests() -> None:
    manifest = load_manifest(FIXTURES / "manifest-minimal.yml")

    assert manifest.test_path == "tests"


def test_a_trailing_slash_in_test_path_is_normalised() -> None:
    text = """
    project: p
    git: {provider: forgejo, repo: o/r}
    test_path: "src/tests/"
    """

    assert parse_manifest(text).test_path == "src/tests"


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("/etc", id="absolute"),
        pytest.param("../../etc", id="climbs-out"),
        pytest.param("tests/../../etc", id="climbs-out-mid-path"),
        pytest.param("tests/*", id="a-glob-is-not-a-boundary"),
        pytest.param("tests;rm -rf /", id="shell-metacharacters"),
        pytest.param("tests\nmore", id="newline"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="whitespace-only"),
    ],
)
def test_test_path_must_stay_inside_the_repository(path: str) -> None:
    """The reproduction phase may only create files here.

    A phase allowed to write anywhere reaches a red gate by breaking something rather than by
    reproducing anything, and a root `conftest.py` is the cheapest version of that. The test ids
    name what each rejected value would have cost.
    """
    text = f"""
    project: p
    git: {{provider: forgejo, repo: o/r}}
    test_path: {path!r}
    """

    with pytest.raises(ManifestError, match="test_path"):
        parse_manifest(text)
