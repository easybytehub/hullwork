"""What a manifest is told when it carries a field this build does not know. Item 195.

`SCHEMA_VERSION`'s own docstring promises this:

> A manifest may say `version: 1`; one that says something higher was written for a newer Hullwork
> and is refused with a message saying so, **rather than producing a wall of `Extra inputs are not
> permitted` about fields that will exist one day.**

The wall is what a project actually gets, because `version:` is optional and nobody writes it. That
was found asking whether `0.1.0a8` adding `autofix.open_upgrades` justified bumping the schema — it
does not, and the message is the thing that needed fixing instead.

The bound matters as much as the fix: **most unknown fields are typos**, and a typo sent looking for
a Hullwork release is a worse answer than the wall. So the field and its value stay in the message,
and the version is added beside them rather than in place of them.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import pytest

from hullwork.manifest import SCHEMA_VERSION, ManifestError, parse_manifest

BASE = """
project: p
git: {provider: github, repo: o/r}
tests: "pytest"
test_path: tests
"""


def _refused(text: str) -> str:
    with pytest.raises(ManifestError) as raised:
        parse_manifest(text)
    return str(raised.value)


def test_an_unknown_field_says_which_schema_this_build_understands() -> None:
    """The sentence a reader needs and did not have: *this build is 1*, so the field may simply be
    newer than the binary rather than wrong."""
    said = _refused(BASE + "autofix: {invented_field: 3}\n")

    assert f"schema {SCHEMA_VERSION}" in said or f"version {SCHEMA_VERSION}" in said
    assert "newer" in said.lower()


def test_it_still_names_the_field_and_the_value() -> None:
    """**The bound.** Most of these are typos, and a message that replaced the field name with a
    paragraph about releases would send somebody to upgrade over a missing letter."""
    said = _refused(BASE + "autofix: {invented_field: 3}\n")

    assert "invented_field" in said
    assert "3" in said


def test_a_manifest_from_the_future_keeps_its_own_message() -> None:
    """Two different failures that must not be merged. This one is unambiguous — the file *says* it
    is newer — and its remedy is exact: upgrade, or pin the manifest down."""
    said = _refused(BASE + f"version: {SCHEMA_VERSION + 1}\n")

    assert "upgrade Hullwork" in said
    assert "invented" not in said


def test_the_schema_version_is_unchanged() -> None:
    """Signed by the operator on 2026-08-09: adding an optional field with a safe default is not a
    schema change. A number that increments on every added key stops telling anybody whether their
    existing file still means what it meant.
    """
    assert SCHEMA_VERSION == 1


def test_an_ordinary_mistake_is_not_told_to_go_and_upgrade() -> None:
    """**Found by mutation, and it was the one no test covered.** Gluing the hint onto every failure
    passed everything else here.

    A malformed `repo` has nothing to do with the schema version, and a suggestion to upgrade
    Hullwork attached to it is worse than silence: it is the product guessing at a cause it has no
    reason to believe, in the message somebody reads while already stuck. The hint belongs to
    unknown fields and to nothing else.
    """
    said = _refused(BASE.replace("repo: o/r", "repo: not-a-repo"))

    assert "newer Hullwork" not in said
    assert "upgrade" not in said.lower()


def test_a_valid_manifest_is_not_lectured() -> None:
    """The message is attached to the failure, never to the parse — a hint printed on success is a
    hint printed for ever."""
    assert parse_manifest(BASE).project == "p"
