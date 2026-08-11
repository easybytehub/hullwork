"""What a deployment runs before anybody has cloned anything. Item 201.

Two compose files shipped, and the one for real deployments was the one that needed a clone: this
repository's own pulls `ghcr.io/easybytehub/hullwork` and is labelled the *evaluation* stack, while
the file `hullwork init` writes builds from `${BUILD_SOURCE}` and does not contain the string
`ghcr.io` anywhere. So the documented path was clone, build 500 MB, and never find out a published
image exists.

The gateway is why this is more than a compose edit: its image was the constant `hullwork:dev`, and
its own docstring names the assumption — *the image this installation built* — that pulling breaks.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from pathlib import Path

import pytest
from the_registry import published_tags

from hullwork import __version__, scaffold
from hullwork.sandbox import net

ROOT = Path(__file__).resolve().parent.parent
SURFACE = json.loads((ROOT / "docs/published-surface.json").read_text(encoding="utf-8"))


def _compose() -> str:
    return scaffold.compose(docker_gid=None)


# --- the default ---------------------------------------------------------------------------------


def test_the_scaffolded_compose_pulls_a_published_image() -> None:
    """The whole item. A deployment should not have to compile the product to run it."""
    text = _compose()

    assert "ghcr.io/easybytehub/hullwork:" in text


def test_it_pins_a_version_and_not_a_moving_tag() -> None:
    """Whatever it pins, it is a version. `edge` moves, and a deployment that follows a moving tag
    cannot say what it is running when somebody asks."""
    text = _compose()

    assert "ghcr.io/easybytehub/hullwork:edge" not in text
    assert f"ghcr.io/easybytehub/hullwork:{__version__}" in text, (
        "the image doing the scaffolding pins itself (item 201)"
    )


def pin_disagreement(
    version: str, *, surface: str, pinned: str, published: Iterable[str] | None
) -> str | None:
    """The failure, or `None` when there is nothing to report. Item 216.

    A pure function taking the registry's answer rather than asking for it, for the reason item 192
    gives: the interesting states are the ones that cannot be reached on demand, and a rule only
    exercised against the live registry is a rule tested in whichever state today happens to be in.
    """
    if published is None:
        raise LookupError("the registry could not be asked, which is not `nothing published`")
    if version not in published:
        # The window between the bump and the release. The tree is genuinely ahead of every
        # release; pinning `__version__` is the honest answer and the surface is allowed to lag.
        if pinned != version:
            return f"no image is published for {version} and the compose pins {pinned}"
        return None
    if surface != version:
        return (
            f"an image is published for {version} and the surface records {surface}: "
            "`docs/releasing.md` has the two post-release steps, in order"
        )
    if pinned != surface:
        return f"the surface records {surface} and the compose pins {pinned}"
    return None


def test_the_registry_being_unreachable_is_not_a_pass() -> None:
    """**Written because a mutation escaped.** Treating `None` as *nothing published* still passed,
    because during the window the two answers agree — they only diverge after the release, which is
    the one moment nobody would be running this by hand.

    `published_tags` returns `None` for *could not ask* on purpose. Blurring it into *nothing
    published* makes an unreachable registry look like permission, which is the failure mode this
    whole file exists to make impossible."""
    with pytest.raises(LookupError):
        pin_disagreement("0.1.0a9", surface="0.1.0a8", pinned="0.1.0a9", published=None)


def test_the_window_between_the_bump_and_the_release_is_allowed() -> None:
    """The deadlock item 216 found: the pin is `__version__` by construction and the surface cannot
    be re-recorded until the image is public, which cannot happen until this passes."""
    assert pin_disagreement(
        "0.1.0a9", surface="0.1.0a8", pinned="0.1.0a9", published=("0.1.0a8",)
    ) is None


def test_the_window_does_not_excuse_a_pin_that_names_something_else() -> None:
    """**The branch nothing covered.** Deleting the check inside the window escaped a mutation
    round: every test here either expected `None` from the window or exercised a published version,
    so a window that accepted any pin at all looked exactly like a window that accepted the right
    one. Pinning a release that does not exist is how a compose file sends somebody to a 404."""
    said = pin_disagreement(
        "0.1.0a9", surface="0.1.0a8", pinned="0.1.0a7", published=("0.1.0a8",)
    )

    assert said is not None
    assert "0.1.0a7" in said


def test_a_published_version_requires_the_surface_and_the_pin_to_name_it() -> None:
    """And the window closes by itself the moment the image exists — no flag to clear.

    **Asserted on which failure it is**, not merely that there is one: the first version checked for
    a message containing `0.1.0a8`, and deleting this branch fell through to the next one, whose
    message also contains it. Two different faults reading the same to a test is a test that cannot
    tell you which of them you have."""
    said = pin_disagreement(
        "0.1.0a9", surface="0.1.0a8", pinned="0.1.0a9", published=("0.1.0a8", "0.1.0a9")
    )

    assert said is not None
    assert "post-release" in said, f"the wrong branch answered: {said}"


def test_the_finished_state_is_quiet() -> None:
    assert pin_disagreement(
        "0.1.0a9", surface="0.1.0a9", pinned="0.1.0a9", published=("0.1.0a8", "0.1.0a9")
    ) is None


@pytest.mark.skipif(
    not os.environ.get("ASK_THE_REGISTRY"),
    reason="asks ghcr.io; set ASK_THE_REGISTRY=1 to run it (CI does)",
)
def test_it_pins_the_release_this_repository_documents() -> None:
    """**Asserted against the recorded surface**, not against a literal typed twice. A compose file
    telling somebody to run a version the documentation does not describe is the two-halves problem
    item 192 closed, arriving in a third file.

    **Except during the window between the bump and the release** (item 216). The pin is
    `__version__` by construction and the surface cannot be re-recorded until the image is public,
    so the first version of this deadlocked the release that found it: `publish.sh --pr` gates the
    derived tree before opening anything, and the gate could only pass after the thing it gates.

    The exemption is the fact item 192 already asks for, not a flag: **is an image published for
    the version this tree claims to be?** If it is, the surface must record it and the pin must be
    it. If not, the tree is genuinely ahead of every release, and saying so is the honest answer.

    Offline is not a pass. `published_tags` returns `None` for *could not ask*, which is a different
    answer from *nothing published* — blurring them would make an unreachable registry look like
    permission.
    """
    found = re.search(r"ghcr\.io/easybytehub/hullwork:([^\s}]+)", _compose())

    assert found is not None, "the scaffolded compose names no published image at all"
    said = pin_disagreement(
        __version__, surface=SURFACE["version"], pinned=found.group(1), published=published_tags()
    )

    assert said is None, said


def test_building_is_still_possible_and_now_explicit() -> None:
    """Item 197's rule: a shorter file is not the goal. Somebody changing the code still needs this,
    and it is what `BUILD_SOURCE` was always actually for."""
    text = _compose()

    assert "BUILD_SOURCE" in text
    assert "build:" in text


def test_a_checkout_is_no_longer_something_only_a_person_can_supply() -> None:
    """`BUILD_SOURCE` was one of four variables the report said a person had to fill in, for a
    deployment with no business needing a checkout at all."""
    needed = [
        name
        for capability in scaffold.CAPABILITIES
        for name, _ in capability.needs
    ]

    assert "BUILD_SOURCE" not in needed


# --- the gateway, which pulling would otherwise break --------------------------------------------


def test_the_gateway_runs_the_instance_image_rather_than_a_constant() -> None:
    """**Item 191's failure, waiting to happen again.** With a pulled deployment there is no
    `hullwork:dev` on the host, so a constant sends the gateway to an image nobody has — and the
    gateway is the component that observes and seals model traffic.
    """
    assert net.gateway_image("ghcr.io/easybytehub/hullwork:0.1.0a8") == (
        "ghcr.io/easybytehub/hullwork:0.1.0a8"
    )


def test_a_deployment_that_builds_gets_the_image_it_built() -> None:
    """The other side, and the reason this is a function rather than a rename: this repository's own
    instance builds on purpose, and its gateway has to be what it built."""
    assert net.gateway_image("hullwork:dogfood") == "hullwork:dogfood"


def test_with_nothing_configured_it_is_what_it_always_was() -> None:
    """Every deployment that exists today was written before this item. Changing the default under
    them would turn a working instance into one whose gateway cannot start, which is the failure
    this item is preventing rather than causing."""
    assert net.gateway_image(None) == "hullwork:dev"


def test_the_scaffold_tells_the_dispatcher_which_image_to_use() -> None:
    """One value, set by the scaffold and never by a person — so `deploy-atlas.sh`'s retag can go
    and a pulled deployment's gateway is the version it says it is."""
    assert "HULLWORK_GATEWAY_IMAGE" in _compose()


def test_the_deploy_script_no_longer_retags() -> None:
    """A shell command keeping two names equal is the same defect as items 193, 194 and 200. It ran
    on every deploy, and the day nobody ran it the gateway was four days behind the dispatcher."""
    script = ROOT / "scripts/deploy-atlas.sh"
    if not script.exists():  # pragma: no cover - withheld from publication
        return

    assert "docker tag hullwork:" not in script.read_text(encoding="utf-8")
