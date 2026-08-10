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
from pathlib import Path

from hullwork import scaffold
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


def test_it_pins_the_release_this_repository_documents() -> None:
    """**Asserted against the recorded surface**, not against a literal typed twice. A compose file
    telling somebody to run a version the documentation does not describe is the two-halves problem
    item 192 closed, arriving in a third file.
    """
    text = _compose()

    assert f"ghcr.io/easybytehub/hullwork:{SURFACE['version']}" in text


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
