"""The reaper removes its own debris and nobody else's. Item 125.

**Found while planning the deployment the product recommends.** A project's forge is chosen per
instance (item 124), so a second forge means a second instance — and two instances on one host share
one Docker daemon. `inventory` finds debris by name prefix, and the tag after each prefix is four
random bytes: nothing in a name says who made it. The module's safety argument is the lease, and the
lease lives in a database, so each instance has its own.

The consequence, before this item: the second instance's dispatcher, on any restart after its first,
removed the **live** attempt of the first — its gateway container, its network, and the
`hullwork-wire-*` volume holding the copy of the model credential.
"""

from __future__ import annotations

import pytest

from hullwork.config import Settings
from hullwork.sandbox import inventory


class FakeDocker:
    """A host with objects belonging to two instances, and one from before labels existed.

    Answers `ls`/`ps` the way Docker does — names on stdout, filtered by `--filter label=` when one
    is given — and records every removal, which is the whole subject here.
    """

    def __init__(self) -> None:
        #: name → the instance label it carries, or `None` for an object created before item 125.
        self.objects: dict[str, dict[str, str | None]] = {
            "container": {
                "hullwork-cable-aaaa": "dogfood",
                "hullwork-cable-bbbb": "dashboard",
                "hullwork-cable-cccc": None,
            },
            "network": {
                "hullwork-attempt-aaaa": "dogfood",
                "hullwork-services-bbbb": "dashboard",
            },
            "volume": {
                "hullwork-wire-aaaa": "dogfood",
                "hullwork-worktree-bbbb": "dashboard",
                "hullwork-harness-deadbeef": "dogfood",  # a cache, never debris
            },
        }
        self.removed: list[str] = []

    def __call__(self, argv: list[str]) -> str | None:
        verb = argv[1:3]
        if verb[0] == "rm" or (len(verb) > 1 and verb[1] == "rm"):
            self.removed.append(argv[-1])
            return ""
        if verb == ["network", "inspect"]:
            return ""  # nothing attached: the services containers are their own test
        kind = {"ps": "container", "network": "network", "volume": "volume"}.get(verb[0])
        if kind is None or (kind != "container" and verb[1] != "ls"):
            return ""
        wanted = None
        if "--filter" in argv:
            wanted = argv[argv.index("--filter") + 1].split("=", 2)[-1]
        return "\n".join(
            name for name, label in self.objects[kind].items()
            if wanted is None or label == wanted
        )


@pytest.fixture
def docker(monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    fake = FakeDocker()
    monkeypatch.setattr(inventory, "_run", lambda argv: fake(argv))
    monkeypatch.setenv("HULLWORK_INSTANCE", "dogfood")
    return fake


def test_it_finds_only_its_own(docker: FakeDocker) -> None:
    """The measurement, as an assertion: `bbbb` belongs to the other instance and `cccc` to nobody
    this build can identify."""
    mine = inventory.find()

    assert mine.containers == ["hullwork-cable-aaaa"]
    assert mine.networks == ["hullwork-attempt-aaaa"]
    assert mine.volumes == ["hullwork-wire-aaaa"]


def test_the_other_instances_live_attempt_survives_a_reap(docker: FakeDocker) -> None:
    """**The defect, stated as the damage it did.** A restart of the second instance removed the
    first one's running gateway, its network, and the volume holding its model credential."""
    inventory.reap()

    assert "hullwork-cable-bbbb" not in docker.removed
    assert "hullwork-services-bbbb" not in docker.removed
    assert "hullwork-worktree-bbbb" not in docker.removed
    assert "hullwork-cable-aaaa" in docker.removed, "and its own is still collected"


def test_an_unlabelled_object_is_reported_and_left_alone(docker: FakeDocker) -> None:
    """Two things land here and a machine may remove neither: an object from before this item, and
    one belonging to an instance that is not this one. Naming them is the whole answer."""
    others = inventory.unclaimed()

    assert "hullwork-cable-cccc" in others.containers, "no label: predates this, or is not ours"
    assert "hullwork-cable-bbbb" in others.containers
    assert "hullwork-cable-aaaa" not in others.containers

    inventory.reap()
    assert "hullwork-cable-cccc" not in docker.removed


def test_the_cache_is_still_not_debris(docker: FakeDocker) -> None:
    """`hullwork-harness-*` is content-addressed and shared across attempts. Labelling it does not
    make it collectable, and this guards the distinction item 106 paid a measurement for."""
    inventory.reap()

    assert "hullwork-harness-deadbeef" not in docker.removed


def test_one_instance_on_a_host_behaves_as_it_always_did(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default is boring on purpose: a deployment that never heard of this setting labels
    everything `default` and reaps everything it labels."""
    fake = FakeDocker()
    fake.objects = {
        "container": {"hullwork-cable-aaaa": "default"},
        "network": {"hullwork-attempt-aaaa": "default"},
        "volume": {"hullwork-wire-aaaa": "default"},
    }
    monkeypatch.setattr(inventory, "_run", lambda argv: fake(argv))
    monkeypatch.delenv("HULLWORK_INSTANCE", raising=False)

    assert inventory.instance_id() == "default"
    inventory.reap()

    assert fake.removed == ["hullwork-cable-aaaa", "hullwork-attempt-aaaa", "hullwork-wire-aaaa"]


def test_the_label_and_the_setting_cannot_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    """`instance_id` reads the environment directly and `Settings.instance` reads it through
    pydantic, so the two are separate readers of one variable. That is deliberate — going through
    `Settings` would make labelling a container require the whole configuration to be valid, which
    broke three sandbox tests whose doubles set `HULLWORK_TEST_*` — and this is what keeps them
    honest about it.
    """
    monkeypatch.setenv("HULLWORK_INSTANCE", "dashboard")

    assert inventory.instance_id() == Settings().instance == "dashboard"

    monkeypatch.setenv("HULLWORK_INSTANCE", "   ")
    assert inventory.instance_id() == "default", "blank means unset, as everywhere else"


def test_every_object_an_attempt_creates_carries_the_label() -> None:
    """A label added at five call sites and forgotten at the sixth is a reaper that leaves debris
    for ever. Read from the source, because the alternative is trusting six edits."""
    from pathlib import Path

    root = Path(inventory.__file__).parent
    creations = []
    for module in ("net.py", "run.py", "services.py"):
        for line in (root / module).read_text().splitlines():
            stripped = line.strip()
            if '"volume", "create"' in stripped or '"network", "create"' in stripped:
                creations.append((module, stripped))
            if '"run", "--detach",' in stripped:
                creations.append((module, stripped))

    assert len(creations) >= 5, "the creation sites moved; this test has to move with them"
    for module, line in creations:
        if '"run", "--detach",' in line:
            continue  # the label is on the following lines, asserted by the sandbox tests
        assert "label_args()" in line, f"{module}: {line}"
