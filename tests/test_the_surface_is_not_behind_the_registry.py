"""Whether the documented release is the published one. Item 192.

`test_the_documentation_describes_the_published_artefact` compares the recorded surface to the
pins and catches both of the ordinary mistakes. It compares the two halves **to each other**, and
nothing compares either to the tag that was actually pushed — so the two of them agreeing on the
*previous* release is green, and that state is reachable by following `docs/releasing.md` in the
order it is written, with no step skipped.

Found cutting `0.1.0a8`: the recorder, given no argument, reads the tag pinned in
`docker-compose.yml` — which at that point in the order is still the previous release. The step is a
no-op, and if the pins are then forgotten too, everything agrees on `0.1.0a7` and the suite is green
while the registry serves `0.1.0a8`.

**The tree cannot tell the two states apart**, which is the whole reason this file needs a fact from
outside it. `version=0.1.0a8, surface=0.1.0a7` is a correct publication whose post-release steps are
not done *yet*, and it is also post-release steps done *wrong*. Same bytes. The one thing that
separates them is whether an image exists for the version this tree claims to be.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from the_registry import behind_the_registry, published_tags

ROOT = Path(__file__).resolve().parent.parent
SURFACE = json.loads((ROOT / "docs/published-surface.json").read_text(encoding="utf-8"))


def _version() -> str:
    """What this tree claims to be, read from the package rather than from a document."""
    from hullwork import __version__

    return __version__


# --- the rule, decided without a network ---------------------------------------------------------


def test_a_published_image_for_this_version_requires_the_surface_to_record_it() -> None:
    """The failure this file exists for, and the state that is green in every other test.

    Reported with the published tag in it, because *the surface and the pins disagree* sends a
    reader to reconcile two things that are already equal.
    """
    said = behind_the_registry("0.1.0a8", surface="0.1.0a7", published=("0.1.0a7", "0.1.0a8"))

    assert said is not None
    assert "0.1.0a8" in said and "0.1.0a7" in said


def test_no_published_image_for_this_version_means_the_surface_may_lag() -> None:
    """**The bump-to-release window, exempted by a fact rather than by a flag.**

    The version is raised before the release exists — the publication pull request carries the bump,
    and the image is built from the tag that merge produces. For all of that time the surface
    honestly records the previous release, because that is the artefact that exists.
    """
    assert behind_the_registry("0.1.0a8", surface="0.1.0a7", published=("0.1.0a7",)) is None


def test_a_surface_recorded_from_this_version_is_the_finished_state() -> None:
    said = behind_the_registry("0.1.0a8", surface="0.1.0a8", published=("0.1.0a7", "0.1.0a8"))

    assert said is None


def test_it_replays_the_sequence_that_produced_the_defect() -> None:
    """`0.1.0a8`'s own release, state by state, which is what item 192's gate asks for.

    The third row is the one that is green today and must not be: the image is on the registry and
    every document in the tree describes the release before it.
    """
    steps = [
        ("before the bump", "0.1.0a7", "0.1.0a7", ("0.1.0a7",), False),
        ("version bumped, nothing published", "0.1.0a8", "0.1.0a7", ("0.1.0a7",), False),
        ("image public, post-release not done", "0.1.0a8", "0.1.0a7", ("0.1.0a7", "0.1.0a8"), True),
        ("surface re-recorded", "0.1.0a8", "0.1.0a8", ("0.1.0a7", "0.1.0a8"), False),
    ]
    for name, version, surface, published, should_fail in steps:
        said = behind_the_registry(version, surface=surface, published=published)
        assert (said is not None) is should_fail, name


def test_a_registry_that_cannot_be_reached_is_not_a_pass() -> None:
    """**`None` means checked and fine**, so an unreachable registry must not borrow that word.

    A check that reports success when it could not run is the failure this repository has now found
    three times: the permanently-on signal (item 073), the two halves agreeing wrongly (this item),
    and a mutation harness that called six caught defects uncaught (item 193).
    """
    with pytest.raises(LookupError):
        behind_the_registry("0.1.0a8", surface="0.1.0a7", published=None)


# --- the same rule, against the real registry ----------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("ASK_THE_REGISTRY"),
    reason="asks ghcr.io; set ASK_THE_REGISTRY=1 to run it (CI does)",
)
def test_this_tree_is_not_describing_a_release_the_registry_has_moved_past() -> None:
    """The one that runs for real, and the only one here that can fail because of a person.

    Anonymous: the token endpoint issues a pull scope for a public package with no account. If this
    is red, either the surface was recorded from the wrong tag or the post-release commit has not
    landed yet — `docs/releasing.md` has both, in order.
    """
    said = behind_the_registry(
        _version(), surface=SURFACE["version"], published=published_tags()
    )

    assert said is None, said
