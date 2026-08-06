"""The repository's own rules, asserted where they can go stale. Item 159.

**Anchored to something outside this project on purpose.** The rules are not house taste: they are
[OpenSSF Scorecard](https://github.com/ossf/scorecard/blob/main/docs/checks.md)'s checks, the
enumeration the industry already uses for *what a well-run repository does* — and, better for this
project than any argument, it can be **run** and it produces a number.

What this file asserts is the half a score cannot see: that the mechanisms are configured in the
files they live in. The ruleset on `main` is asserted by the ruleset and no test can reach it;
everything below is what a commit could undo silently.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted(
    path
    for directory in (".forgejo/workflows", ".github/workflows")
    for path in (ROOT / directory).glob("*.yml")
)


def _loaded(path: Path) -> dict[Any, Any]:
    """A workflow as data. `Any` keys because of the `on:` quirk `_triggers` explains."""
    loaded: dict[Any, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return loaded


def _triggers(loaded: dict[Any, Any]) -> Any:  # noqa: ANN401 - a YAML value is arbitrary
    """A workflow's `on:` block, whatever PyYAML decided that key was.

    **`on` is a YAML 1.1 boolean**, so `safe_load` returns it under `True` rather than `"on"` —
    found by this test raising `KeyError: 'on'` against a perfectly good workflow. The older
    workflow tests never hit it because they only ever read `jobs`.
    """
    return loaded.get("on", loaded.get(True))


# --------------------------------------------------------------------------------------------
# Token-Permissions: least privilege, declared rather than inherited
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_workflow_declares_its_permissions(path: Path) -> None:
    """Scorecard's Token-Permissions, and the reason it is a check.

    A workflow with no `permissions:` block inherits whatever the repository grants, which on older
    repositories is write access to everything. The CI workflow runs code from a pull request, and
    that is the one place the code is not ours yet.
    """
    loaded = _loaded(path)

    assert "permissions" in loaded, f"{path.name} inherits its token's permissions"
    top = loaded["permissions"]
    assert isinstance(top, dict) and top, f"{path.name} declares an empty permissions block"


def test_the_ci_workflow_can_only_read() -> None:
    """The strongest version of the rule, for the workflow that runs untrusted code.

    `ci.yml` installs, lints, types and tests. Nothing it does needs to write anything, anywhere.
    """
    for name in (".forgejo/workflows/ci.yml", ".github/workflows/ci.yml"):
        path = ROOT / name
        if not path.is_file():
            continue
        assert _loaded(path)["permissions"] == {"contents": "read"}, f"{name} wants more than read"


def test_only_the_workflows_that_publish_may_write() -> None:
    """A `write` scope is a claim about what a workflow is for, so the list is enumerated.

    The point is not that these are safe. It is that a fourth workflow appearing with
    `packages: write` fails a test rather than passing review.
    """
    allowed = {"release.yml", "edge.yml", "codeql.yml"}

    for path in WORKFLOWS:
        scopes = _loaded(path)["permissions"]
        assert isinstance(scopes, dict)
        writes = {scope for scope, level in scopes.items() if level == "write"}
        if writes:
            assert path.name in allowed, f"{path.name} wants {sorted(writes)} and publishes nothing"


# --------------------------------------------------------------------------------------------
# Signed-Releases: provenance for everything published
# --------------------------------------------------------------------------------------------


def test_both_published_artefacts_get_provenance() -> None:
    """Scorecard's Signed-Releases. **Without a key of ours**, which is the part worth keeping.

    GitHub mints a short-lived OIDC token for the run and signs with it, so there is nothing to
    store, rotate or leak. What the attestation says is which commit, which workflow and which
    runner produced the artefact — the only question somebody pulling our image can check.
    """
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    # On `uses:` lines rather than anywhere in the file: the header explains why the action is here,
    # and counting prose as configuration is how a test starts measuring its own comments.
    used = [line for line in release.splitlines() if "uses:" in line and "attest" in line]
    assert len(used) == 2, f"the wheel and the image, or one of them is unsigned: {used}"
    assert "subject-path: dist/*.whl" in release
    assert "push-to-registry: true" in release, (
        "an attestation only in this repository is one a stranger with the image cannot find"
    )
    for scope in ("id-token: write", "attestations: write"):
        assert scope in release, f"attestation needs {scope}"

    # Before the release exists: an attestation that arrives afterwards is one somebody could have
    # downloaded without.
    assert release.index("Attest the image") < release.index("Create the release")


def test_the_image_digest_comes_from_the_build_not_the_tag() -> None:
    """A tag can move between the push and a read of it, and then the attestation describes
    something other than what shipped. `--metadata-file` is the build's own answer.
    """
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "--metadata-file metadata.json" in release
    assert "containerimage.digest" in release


# --------------------------------------------------------------------------------------------
# Pinned-Dependencies
# --------------------------------------------------------------------------------------------


def test_the_base_image_is_pinned_by_digest() -> None:
    """A tag is a pointer somebody else moves, so two builds of one commit can differ — which makes
    a reproducible build a coincidence. Both stages, because one of them becomes the runtime.
    """
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    images = re.findall(r"^FROM (\S+)", dockerfile, re.MULTILINE)

    assert images, "no FROM lines — this test has lost its subject"
    for image in images:
        assert "@sha256:" in image, f"{image} is pinned by tag rather than by digest"


def test_dependabot_proposes_and_does_not_merge() -> None:
    """The other half of pinning: a project that pins everything and bumps nothing has traded one
    risk for another. Proposals though — a bot that could merge its own bump would undo the rule
    the ruleset just added.
    """
    text = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
    config = yaml.safe_load(text)
    ecosystems = {entry["package-ecosystem"] for entry in config["updates"]}

    assert {"github-actions", "docker", "pip"} <= ecosystems, f"only watching {sorted(ecosystems)}"
    assert "auto-merge" not in text


# --------------------------------------------------------------------------------------------
# The release policy: prose, and therefore the most likely thing here to go stale
# --------------------------------------------------------------------------------------------


def test_the_release_policy_says_the_things_that_matter() -> None:
    """Written down because *"a version is for a state worth pinning"* cannot be read off the code,
    and because four releases in nineteen hours is what happens without it.
    """
    policy = (ROOT / "docs/releasing.md").read_text(encoding="utf-8")

    for owed in ("edge", "sha-<commit>", "gh attestation verify", "Scorecard"):
        assert owed in policy, f"the policy does not mention {owed}"
    assert "approvals are not required" in policy.lower(), (
        "the one rule we deliberately do not enforce has to be the one stated most plainly"
    )


def test_the_edge_channel_exists_so_measuring_costs_no_version() -> None:
    """The mechanism the policy leans on. Without it, *"do not cut a version to measure"* is advice
    somebody breaks the next time a gate demands the published image.
    """
    path = ROOT / ".github/workflows/edge.yml"
    edge = _loaded(path)
    text = path.read_text(encoding="utf-8")

    assert _triggers(edge) == {"push": {"branches": ["main"]}}, "edge follows main and nothing else"
    assert "sha-$short" in text, "an immutable tag, or a recorded measurement means nothing later"
    assert "$image:latest" not in text, "edge must never move latest"
    concurrency = edge["concurrency"]
    assert isinstance(concurrency, dict)
    assert concurrency["cancel-in-progress"] is True, (
        "two publications a minute apart would race for one tag, and the loser would define it"
    )


def test_publishing_no_longer_prints_a_force_push() -> None:
    """**The habit that made a mistake permanent.** The script used to end in
    `git push --force origin main`; client and partner names reached the public repository and its
    history that way, and the fix was deleting the repository.
    """
    path = ROOT / "scripts/publish.sh"
    if not path.is_file():
        # `scripts/` is withheld: it is the derivation machinery, not the product, so in the derived
        # tree there is nothing here to assert. Found by the gates that run on that tree, which is
        # exactly what they are for.
        pytest.skip("the publish script is not in this tree (withheld from publication)")

    script = path.read_text(encoding="utf-8")
    # Comments excluded: the file explains at length *why* the force push is gone, and a test that
    # counts the explanation as the thing it forbids forbids explaining anything.
    runnable = "\n".join(
        line for line in script.splitlines() if not line.lstrip().startswith("#")
    )

    assert "push --force" not in runnable
    assert "gh pr create" in script, "publishing goes through a pull request now"
    assert "ruff check" in script and "pytest" in script, (
        "the gates run in the derived tree before the pull request, because a derivation can fail "
        "checks its source passed"
    )
