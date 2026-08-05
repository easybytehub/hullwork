"""The CI workflow is a supply chain, and this asserts the two properties that make it one.

**Both were learned by the mirror refusing to run it.** On 2026-08-04 the public forge failed the
whole job at `Set up job`, before one step of ours ran: *"all actions must be pinned to a
full-length commit SHA"*. The policy was right, and this file had `@v4` and `@v5` in it.

A tag is a moving pointer somebody else controls, so `@v4` means "whatever that account publishes
next" — and this workflow installs dependencies and runs the tests of a tool holding a token that
can push. Pinning is the difference between trusting a commit and trusting an account.

Asserted here rather than left to the forge: the forge only tells you on the day you push, and only
the forge that has the policy tells you at all.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from hullwork import scaffold

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".forgejo/workflows/ci.yml"

#: A 40-character hexadecimal commit. Nothing shorter is one: an abbreviated SHA is a prefix, and a
#: prefix can collide, which is why the policy says full-length.
PINNED = re.compile(r"^[a-z0-9\-./]+@[0-9a-f]{40}$")


def _uses() -> list[str]:
    """Every `uses:` in the workflow, read as data rather than grepped.

    Through the parser because a `uses:` inside a comment is not one, and a grep cannot tell.
    """
    loaded = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return [
        step["uses"]
        for job in loaded["jobs"].values()
        for step in job["steps"]
        if isinstance(step, dict) and "uses" in step
    ]


def test_every_action_is_pinned_to_a_full_commit() -> None:
    """The property the mirror's organisation enforces, enforced here first.

    Failing on a push to a forge is the expensive place to learn this: the run is refused before any
    output exists, so the failure reads as a broken runner rather than as a policy.
    """
    used = _uses()
    assert used, "no actions found — this test has lost its subject"

    unpinned = [ref for ref in used if not PINNED.match(ref)]
    assert not unpinned, (
        f"pin these to a full 40-character commit SHA, with the version in a trailing comment: "
        f"{unpinned}"
    )


def test_every_pin_says_which_version_it_is() -> None:
    """A SHA nobody can read is a SHA nobody dares refresh.

    Forty hex characters answer *what* is pinned and nothing about *when* — so the version travels
    beside it as a comment, and moving one without the other is the mistake this catches. Checked on
    the text rather than the parse, because a comment is what the parser discards.
    """
    text = WORKFLOW.read_text(encoding="utf-8")

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("- uses:"):
            continue
        assert "#" in stripped, f"pinned without a version comment: {stripped}"
        comment = stripped.split("#", 1)[1].strip()
        assert re.match(r"^v\d", comment), (
            f"the comment beside a pin should be the version it is, not {comment!r}"
        )


def test_the_gates_the_constitution_names_are_the_gates_it_runs() -> None:
    """The workflow is what makes "no commit lands red" true, so it has to run all three.

    Item 147's second round found the README claiming things the code did not do; a workflow that
    quietly dropped `mypy` would be the same defect where nobody would look for it.
    """
    loaded = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    commands = " ".join(
        str(step.get("run", ""))
        for step in loaded["jobs"]["gates"]["steps"]
        if isinstance(step, dict)
    )

    assert "ruff check ." in commands
    assert "mypy ." in commands
    assert "pytest" in commands
    # `-rs` so a skip prints its reason: "9 skipped" without one reads as noise rather than as the
    # isolation boundary going unproven (item 149's neighbourhood).
    assert "-ra" in commands or "-rs" in commands, "a skip has to print why"


def test_the_uid_the_scaffold_assumes_is_the_uid_the_image_runs_as() -> None:
    """Two files have to agree on one number, and nothing makes them.

    `hullwork init` gives `deploy.env` group `CONTAINER_USER_ID` so the container can read the file
    the compose mounts for `doctor`. If the `Dockerfile` ever changes its uid, that grant lands on a
    group nobody is in, the mount goes back to being unreadable, and the only symptom is a check
    reporting `unknown` on a stranger's deployment — a failure with no error and no log line.

    Asserted against the `Dockerfile` rather than against a second literal, so the test fails when
    the *image* changes rather than when somebody remembers to update a fixture.
    """
    dockerfile = (Path(__file__).parent.parent / "Dockerfile").read_text(encoding="utf-8")
    declared = re.search(r"useradd\s+.*?--uid\s+(\d+)\s+hullwork", dockerfile)

    assert declared, "the Dockerfile no longer creates the hullwork user with an explicit uid"
    assert int(declared.group(1)) == scaffold.CONTAINER_USER_ID, (
        f"the image runs as {declared.group(1)} and the scaffold grants the group "
        f"{scaffold.CONTAINER_USER_ID}: deploy.env would be mounted unreadable"
    )


def test_the_pinning_rule_covers_every_workflow_not_just_this_one() -> None:
    """The two tests above read one file, so the rule applied to one file by accident.

    A release workflow needs it most — it holds a token that can publish packages and create
    releases, the worst place for an unpinned third party — and it arrived after those tests were
    written. Adding a workflow must not silently opt out of the project's own policy, so this globs
    instead of naming.
    """
    files = sorted(
        path
        for directory in (".forgejo/workflows", ".github/workflows")
        for path in (ROOT / directory).glob("*.yml")
    )

    assert len(files) >= 2, "this test has lost its subject, or a workflow moved"

    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.startswith("- uses:"):
                continue
            reference = stripped.split("uses:", 1)[1].split("#")[0].strip()
            assert PINNED.match(reference), f"{path.name}: pin {reference} to a full commit SHA"
            assert "#" in stripped, f"{path.name}: pinned without a version comment: {stripped}"


def test_the_release_workflow_refuses_to_publish_a_version_that_disagrees() -> None:
    """A release whose image says one version and whose wheel says another is unusable for anybody
    pinning either, and the bug report arrives months later from somebody who cannot reproduce it.

    Asserted on the workflow's text because there is no way to run it here: what matters is that the
    check exists *before* the push steps, so a mismatch costs nothing rather than being discovered
    after an image is public and immutable.
    """
    release = ROOT / ".github/workflows/release.yml"
    text = release.read_text(encoding="utf-8")

    assert "__version__" in text, "nothing compares the tag against the package"
    assert text.index("__version__") < text.index("docker buildx build"), (
        "the version check has to run before anything is pushed; afterwards it is an autopsy"
    )
    assert "if: github.repository ==" in text, (
        "without a repository guard this also runs on the primary forge, failing on every release"
    )


def test_a_prerelease_does_not_move_the_latest_tag() -> None:
    """`0.1.0a1` is what this project is, and `latest` is what somebody types without reading.

    A moving tag pointing at the first alpha ever published, a year after it was superseded, is the
    kind of thing nobody notices until a stranger reports behaviour from a build we forgot existed.
    Asserted on the workflow because there is no way to run it here.
    """
    text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "stable=false" in text and "stable=true" in text, "nothing distinguishes a prerelease"
    assert '[ "$STABLE" = "true" ] && tags+=(--tag "$image:latest")' in text, (
        "latest must be conditional on the version being a plain N.N.N"
    )
    assert '[ "$STABLE" = "true" ] || flags+=(--prerelease)' in text, (
        "an alpha released without --prerelease shows up as the recommended download"
    )


def test_the_release_bakes_the_extras_into_the_image() -> None:
    """The defect of `0.1.0a1`, and the reason it is a test rather than a fixed line.

    `ARG EXTRAS=` is empty and this line was simply missing, so the published image had neither
    `sentry-sdk` nor `psycopg`. Both are documented capabilities — reporting Hullwork's own crashes
    to your tracker, and running on Postgres — and both were impossible in the artefact. Nobody
    noticed because a development checkout installs `[dev]`, which carries them.

    Asserted on the workflow because that is where the omission lived, and by extra name because a
    later edit dropping one of them would otherwise be silent again.
    """
    text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "--build-arg EXTRAS=" in text, "with no extras the image is missing both"
    for extra in ("postgres", "telemetry"):
        assert extra in text.split("--build-arg EXTRAS=")[1].split("\n")[0], extra
