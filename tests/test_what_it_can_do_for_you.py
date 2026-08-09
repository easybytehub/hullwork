"""What this can do for your project, and what it cannot. Item 186.

The operator's framing: **Hullwork is modular — a developer turns features on and off, and each
feature has its limitations.** The first half already existed in `hullwork.yml`; the second half
existed nowhere, so every limitation was found by walking into it.

**The tests that matter here are about the two halves not blending.** A feature's *needs* are
checkable and either met or not; its *limits* are true whatever the answer, and both have to be
printed either way — because a limit you meet after adopting something is a limit you found the
expensive way.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hullwork import features
from hullwork.manifest import Manifest, parse_manifest

MANIFEST = """
project: p
git: {provider: github, repo: o/r}
tests: "pytest"
test_path: tests
runtime: {base: python-3.12, install: pip, dependencies: [requirements.txt]}
"""

#: The shape `propose` writes when a project's CI hides its install step, and the shape a project
#: that brings its own image has. Item 182 measured a **false verdict** produced under it.
OWN_IMAGE = """
project: p
git: {provider: github, repo: o/r}
tests: "pytest"
test_path: tests
runtime: {base: python-3.12, install: none, dependencies: []}
"""


def _checkout(
    manifest_text: str | None = MANIFEST,
    *,
    paths: tuple[str, ...] = ("requirements.txt", "src/app.py"),
    configured: tuple[str, ...] = (),
) -> features.Checkout:
    manifest: Manifest | None = parse_manifest(manifest_text) if manifest_text else None
    return features.Checkout(
        paths=paths, manifest=manifest, configured=frozenset(configured)
    )


def _named(answers: list[features.Answer], name: str) -> features.Answer:
    return next(a for a in answers if a.feature.name == name)


# --- the half that had no home anywhere --------------------------------------------------------


def test_every_feature_declares_what_it_cannot_do() -> None:
    """**Never empty**, and this is the structural half of the operator's framing.

    A feature with no limits reads as one that has none. Until this module that was true of all of
    them, and it was false of every single one — the limits existed and lived in docstrings, in
    decision records, and in what a person found out by running it.
    """
    for feature in features.FEATURES:
        assert feature.limits, f"{feature.name} declares no limits, which is never true"
        assert feature.needs, f"{feature.name} declares no needs"
        for need in feature.needs:
            assert need.fix, f"{feature.name}: a need with no way to satisfy it is a dead end"


def test_the_limits_are_printed_whether_or_not_the_feature_is_available() -> None:
    """The whole point. A feature you *can* have is the one where nobody thinks to look."""
    available = features.examine(_checkout())
    unavailable = features.examine(_checkout(OWN_IMAGE))

    said = " ".join(features.lines(available))
    also = " ".join(features.lines(unavailable))

    for text in (said, also):
        assert "What is measured is **your suite**" in text
        assert "the image has to be refreshed" in text


# --- what it says about the case that produced a false verdict ---------------------------------


def test_a_project_that_brings_its_own_image_is_told_verification_cannot_serve_it() -> None:
    """Item 182's finding, answered before anybody pays for it.

    With `install: none` the image is `runtime.base` exactly as it comes and nothing is installed
    from a lock file, so rewriting a pinned version changes nothing the suite would run against.
    Measured against a base carrying `jinja2 3.0.0` and a checkout pinning `2.4.1`: a verdict
    reading *your suite passed before this change and passes after it*, about a version that was
    never installed.

    `install: none` is the **default**, and DR-0007 makes *the project brings its own image* the
    primary path — so this is most projects, and the answer has to arrive before the containers do.
    """
    answer = _named(features.examine(_checkout(OWN_IMAGE)), "dependency verification")

    assert not answer.available
    missing = " ".join(need.what for need in answer.missing)
    assert "installer that reads the file your versions are pinned in" in missing
    fix = " ".join(need.fix for need in answer.missing)
    assert "runtime.install" in fix and "runtime.dependencies" in fix


def test_a_project_whose_image_hullwork_builds_is_told_it_can() -> None:
    """The other side of the same answer: a report that says no to everything is not a report."""
    answer = _named(features.examine(_checkout()), "dependency verification")

    assert answer.available
    assert answer.missing == ()


def test_a_checkout_with_no_manifest_is_told_which_command_writes_one() -> None:
    """The commonest first contact there is, and the one where a refusal has to end in a verb."""
    answer = _named(features.examine(_checkout(None)), "dependency verification")

    assert not answer.available
    assert any("propose" in need.fix for need in answer.missing)
    # And the report still works: a lock file is a fact about the checkout, not about the manifest.
    assert _named(features.examine(_checkout(None)), "dependency report").available


def test_every_unmet_need_is_listed_and_not_just_the_first() -> None:
    """A reader who fixes one thing and runs this again to find a second is doing the work this
    command exists to save them."""
    answer = _named(features.examine(_checkout(None, paths=())), "dependency verification")

    assert len(answer.missing) >= 2


# --- the rules it runs under -------------------------------------------------------------------


def test_a_credential_is_read_for_whether_it_is_set_and_never_for_its_value() -> None:
    """This is the command somebody runs before trusting the product with anything.

    It says *needs a model credential, and none is configured* while holding none — which is what
    lets it be run by somebody who has configured nothing at all, and what stops it becoming a
    place a secret can be printed.
    """
    with_key = features.examine(_checkout(configured=(features.MODEL_KEY,)))
    without = features.examine(_checkout())

    assert _named(with_key, "fixing an upgrade that breaks your suite").missing != ()
    listed = " ".join(
        need.what for need in _named(without, "fixing an upgrade that breaks your suite").missing
    )
    assert "model credential" in listed
    # The whole surface, checked for a value that was never handed to it.
    assert "sk-" not in " ".join(features.lines(with_key))


def test_nothing_it_reads_requires_a_daemon_a_socket_or_a_forge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asserted by making every route out explode.

    The precedent is `projects lanes --checkout .`, which prints this instance's policy against a
    tree with no credential of any kind — *"a policy nobody has read is a policy nobody has agreed
    to"*. A capability report that quietly opened a socket would be a different command wearing
    this one's promise.
    """
    import socket
    import subprocess

    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("features opened something it may not")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    said = features.lines(features.examine(_checkout()))

    assert said


def test_the_features_a_checkout_cannot_answer_are_named_rather_than_guessed() -> None:
    """Whether a forge answers, whether a tracker is reachable, whether a dispatcher holds the
    lease — a checkout cannot know any of it, and a report that pretended to would be worse than
    one that says whose question it is."""
    assert features.INSTANCE_SHAPED
    reported = {feature.name for feature in features.FEATURES}
    for named in features.INSTANCE_SHAPED:
        assert named not in reported, f"{named} is claimed here and cannot be answered here"


def test_it_writes_nothing_at_all(tmp_path: Path) -> None:
    """It is a reading of what you already have. A report that edited a manifest to make itself
    truer would be the worst possible version of this command."""
    before = sorted(p.name for p in tmp_path.iterdir())

    features.lines(features.examine(_checkout()))

    assert sorted(p.name for p in tmp_path.iterdir()) == before


# --- the third answer (item 187, DR-0019) ------------------------------------------------------


def test_a_feature_a_project_has_not_permitted_reads_as_a_decision() -> None:
    """**Not `no`.** That would report a choice somebody made as a part that is missing, which is
    the one way this report could insult its reader.

    Everything the feature needs is here — the lock file, the manifest, the installer, the
    credential, the remote. What is absent is the project's yes.
    """
    everything = _checkout(configured=(features.CODE_TOKEN, "origin"))

    answer = _named(features.examine(everything), "opening the upgrades that pass")

    assert answer.available, "the capability is all there"
    assert not answer.permitted
    said = " ".join(features.lines([answer]))
    assert "[not permitted here]" in said
    assert "this project has not permitted it" in said
    assert "open_upgrades: true" in said


def test_the_permission_granted_reads_as_yes() -> None:
    """The other side: a project that said yes gets the plain answer and no lecture."""
    permitted = features.Checkout(
        paths=("requirements.txt",),
        manifest=parse_manifest(MANIFEST.rstrip() + "\nautofix: {open_upgrades: true}\n"),
        configured=frozenset((features.CODE_TOKEN, "origin")),
    )

    answer = _named(features.examine(permitted), "opening the upgrades that pass")

    assert answer.available and answer.permitted
    said = " ".join(features.lines([answer]))
    assert "[yes]" in said
    assert "not permitted" not in said


def test_a_missing_capability_still_reads_as_no_even_when_unpermitted() -> None:
    """Two different absences, and the more fundamental one wins the headline.

    A project with no credential *and* no permission is told `no` — because *not permitted here*
    would suggest that granting it would be enough, and it would not.
    """
    neither = _checkout()

    answer = _named(features.examine(neither), "opening the upgrades that pass")

    assert not answer.available
    assert "[no]" in " ".join(features.lines([answer]))


def test_only_what_writes_to_a_repository_asks_for_permission() -> None:
    """DR-0019's bound, asserted structurally so the switchboard cannot grow quietly.

    *Could a project have the capability, understand the feature, and rationally not want it?* If
    wanting is implied by having, there is no switch — and every feature that writes nothing to
    somebody's repository is in that class. A second `permits` entry appearing here is Renovate's
    complaint nº2 arriving as a feature, which DR-0018 refuses by name.
    """
    asking = [f.name for f in features.FEATURES if f.permits]

    assert asking == ["opening the upgrades that pass"], (
        "a new permission was added; DR-0019's rule has to be applied to it in writing first"
    )


# --- the two paths compose (item 188, DR-0007) -------------------------------------------------

#: A project's own image, plus the one line that refreshes its dependencies on top of it. Legal
#: since DR-0007 was built and written down nowhere until item 188.
OWN_IMAGE_REFRESHED = """
project: p
git: {provider: github, repo: o/r}
tests: "pytest"
test_path: tests
runtime:
  base: ghcr.io/acme/ci-base:2026.7
  install: "pip install -r requirements.txt"
  dependencies: [requirements.txt]
"""


def test_an_image_hullwork_did_not_build_is_served_when_it_is_refreshed() -> None:
    """**The operator's directive answered without adding a stack** (item 188).

    Item 182 measured that verification served only projects whose image Hullwork builds — DR-0007's
    path (A), which that decision demoted to *sugar*. Going to design a table of environment
    strategies found none was needed: `base` takes any image and `install` takes the project's own
    command, so *your image plus one line* was always legal.

    Measured against a real daemon on 2026-08-09, asking both containers rather than reading the
    report: `before -> jinja2 3.0.0` (what the project's own image carries) and
    `after -> jinja2 3.1.6` (the upgrade, actually installed).
    """
    answer = _named(features.examine(_checkout(OWN_IMAGE_REFRESHED)), "dependency verification")

    assert answer.available, "a base Hullwork did not build is still measurable when refreshed"


def test_the_limit_no_longer_says_a_project_with_its_own_image_is_not_served() -> None:
    """It said exactly that, and item 188 measured it false.

    A limit that overstates is worse than none: this one would have sent every project on DR-0007's
    **primary** path away from a feature that serves them, and it would have read as honesty.
    """
    said = " ".join(features.lines(features.examine(_checkout(OWN_IMAGE_REFRESHED))))

    assert "not served" not in said
    assert "does not mean Hullwork must build your image" in said


def test_the_remedy_tells_them_to_keep_their_own_base() -> None:
    """The difference between one line and a rebuild from scratch, said where they will read it."""
    answer = _named(features.examine(_checkout(OWN_IMAGE)), "dependency verification")

    fix = " ".join(need.fix for need in answer.missing)
    assert "Keep your own image" in fix
