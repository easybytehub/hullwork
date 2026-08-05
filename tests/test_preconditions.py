"""Two preconditions and the diff of adoption. Item 108, DR-0007's amendment.

Both preconditions were measured as **inscrutable failures** before this existed, which
is the cost DR-0007 promised not to pay:

* `FROM gcr.io/distroless/static-debian12` fails at the first `RUN` with `exit code: 1`
  and a message about `useradd`. What is missing is `/bin/sh`, and it will never not be
  required: every phase runs `sh -lc`, and the harness works by executing commands
  (item 059).
* an image for another architecture fails at run time with the same misleading *"not
  found"* DR-0007 spends a boxed aside explaining for musl — and nothing checked it.

And the third answer is what keeps them usable: **"not checked here"**. `projects add` is
normally typed on the receiver, which holds no Docker socket by design (DR-0009), so a
check unable to tell an unreachable daemon from a bad image would refuse every
registration made from the right place. That is item 105's lesson, closed the same day.

The diff is the other half, and it rests on a property DR-0007 never claimed: the
manifest is **adopted, not followed** — so the risk is not a stranger editing
`hullwork.yml`, it is the operator adopting a change without seeing it.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from hullwork.cli import CommandError, _the_image_must_be_able_to_host_a_phase, runtime_diff
from hullwork.manifest import parse_manifest
from hullwork.sandbox import image as image_module
from hullwork.sandbox.image import BaseFacts

WITH_A_BASE = """
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: ghcr.io/acme/thing:1}
"""

NO_RUNTIME = """
project: p
git: {provider: forgejo, repo: o/r}
"""


def _facts(monkeypatch: pytest.MonkeyPatch, facts: BaseFacts, host: str | None) -> None:
    monkeypatch.setattr(image_module, "inspect_base", lambda base, **kw: facts)
    monkeypatch.setattr(image_module, "host_architecture", lambda *a, **kw: host)


def test_an_image_with_no_shell_is_refused_saying_that(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**Measured against `gcr.io/distroless/static-debian12`**: exit 1 at the first
    `RUN`, blaming `useradd`.

    The refusal has to say what is actually wrong, and that it is permanent — a reader who
    thinks a shell is a missing feature will wait for it.
    """
    _facts(monkeypatch, BaseFacts(checked=True, architecture="amd64", has_shell=False), "amd64")

    with pytest.raises(CommandError) as refused:
        _the_image_must_be_able_to_host_a_phase(parse_manifest(WITH_A_BASE), out=None)

    message = str(refused.value)
    assert "has no shell" in message
    assert "sh -lc" in message, "it must say why a shell is required"
    assert "permanent" in message, "and that waiting for it is not a plan"
    assert "useradd" not in message, "the old message blamed the wrong thing"


def test_an_image_for_another_architecture_is_refused_naming_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The axis DR-0007 named and nothing checked.

    The harness bundle is built per architecture, so a mismatch fails *inside* the sandbox
    with a message about the executable rather than about the image.
    """
    _facts(monkeypatch, BaseFacts(checked=True, architecture="arm64", has_shell=True), "amd64")

    with pytest.raises(CommandError) as refused:
        _the_image_must_be_able_to_host_a_phase(parse_manifest(WITH_A_BASE), out=None)

    message = str(refused.value)
    assert "arm64" in message
    assert "amd64" in message


def test_a_foreign_architecture_is_not_reported_as_a_missing_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**Found by asking a real daemon, after the first version shipped.**

    `arm64v8/alpine:3.20` on an amd64 host has a shell. The probe that looks for one runs
    `docker run --entrypoint sh` and fails anyway — `exec format error` — so the first
    version refused it saying *"has no shell"*, which is false about that image and sends
    the operator to fix the wrong thing.

    The architecture is a **fact** read off the image; the shell is an **inference** from a
    command that ran. Item 105 in one line: do not assert a cause you did not establish.
    """
    _facts(monkeypatch, BaseFacts(checked=True, architecture="arm64", has_shell=False), "amd64")

    with pytest.raises(CommandError) as refused:
        _the_image_must_be_able_to_host_a_phase(parse_manifest(WITH_A_BASE), out=None)

    message = str(refused.value)
    assert "arm64" in message and "amd64" in message
    assert "has no shell" not in message


def test_a_good_image_registers_with_no_ceremony(monkeypatch: pytest.MonkeyPatch) -> None:
    """The negative that matters: a precondition inconveniencing the working case is a bad
    precondition."""
    _facts(monkeypatch, BaseFacts(checked=True, architecture="amd64", has_shell=True), "amd64")

    _the_image_must_be_able_to_host_a_phase(parse_manifest(WITH_A_BASE), out=None)


def test_an_unreachable_daemon_is_not_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """**The third answer, and the reason there are three.**

    `projects add` is normally typed on the receiver, which has no Docker socket by design.
    Refusing there would refuse every registration made from the right place; claiming to
    have checked would be item 105's defect in a new spot.
    """
    _facts(monkeypatch, BaseFacts(checked=False, why_not="no Docker client on PATH"), None)
    printed: list[str] = []

    class Sink:
        def write(self, text: str) -> int:
            printed.append(text)
            return len(text)

        def flush(self) -> None:
            return None

    _the_image_must_be_able_to_host_a_phase(
        parse_manifest(WITH_A_BASE), out=Sink()  # type: ignore[arg-type]
    )

    said = "".join(printed)
    assert "Not checked here" in said
    assert "no Docker client on PATH" in said
    assert "where the dispatcher runs" in said, "it must say where the answer lives"


def test_an_architecture_the_host_will_not_say_is_not_a_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown is not mismatched. A daemon that will not answer about itself says nothing
    about the image, and guessing here would refuse a correct registration."""
    _facts(monkeypatch, BaseFacts(checked=True, architecture="arm64", has_shell=True), None)

    _the_image_must_be_able_to_host_a_phase(parse_manifest(WITH_A_BASE), out=None)


def test_a_manifest_with_no_runtime_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """`runtime` is optional: a project with `agent: none` needs no sandbox at all, and
    checking an image it never named would be checking nothing."""
    called: list[str] = []

    def record(base: str, **kwargs: object) -> BaseFacts:
        called.append(base)
        return BaseFacts(checked=False)

    monkeypatch.setattr(image_module, "inspect_base", record)

    _the_image_must_be_able_to_host_a_phase(parse_manifest(NO_RUNTIME), out=None)

    assert called == []


def test_an_unreachable_daemon_is_not_reported_as_a_missing_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**Found by deploying, not by testing.**

    The receiver's image carries the docker *binary* and, by design, not the *socket*. So
    `shutil.which` finds a client, every command fails, and reading only the image
    lookup's failure this said *"python:3.12-slim is not on this host yet"* — about a host
    it could not talk to at all. A client on PATH is not a reachable daemon, and naming
    the wrong reason is the defect this whole check exists to prevent.
    """
    monkeypatch.setattr(shutil, "which", lambda name, mode=1, path=None: "/usr/bin/docker")

    def unreachable(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command, 1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."
        )

    monkeypatch.setattr(image_module, "_run", unreachable)

    facts = image_module.inspect_base("python-3.12")

    assert facts.checked is False
    assert "daemon cannot be reached" in facts.why_not
    assert "not on this host yet" not in facts.why_not, "that was the wrong reason"
    assert "no socket by design" in facts.why_not, "and it should say why that is normal"


# --- the diff at the moment of adoption -----------------------------------------------


def test_a_changed_install_command_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    """**What `refresh` said nothing about.** It printed lane counts, while `install` can be
    any command at all since item 068."""
    del monkeypatch
    before = {"runtime": {"base": "python-3.12", "install": "uv", "packages": ["git"]}}
    after = parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: python-3.12, install: make bootstrap, dependencies: [Makefile]}
""")

    changes = runtime_diff(before, after)

    assert any("install" in line and "make bootstrap" in line for line in changes)
    assert any("packages" in line for line in changes), "a package that went away is a change"
    assert not any("base" in line for line in changes), "the base did not change"


def test_nothing_changed_is_a_thing_the_diff_says() -> None:
    """An empty list, and the caller prints a sentence for it — silence about a check reads
    as the check not having happened."""
    same = {"runtime": {"base": "python-3.12", "install": "none", "packages": []}}
    after = parse_manifest("""
project: p
git: {provider: forgejo, repo: o/r}
runtime: {base: python-3.12}
""")

    assert runtime_diff(same, after) == []


def test_a_runtime_appearing_or_disappearing_is_named() -> None:
    """The two edges. A project that gains a runtime gains a build; one that loses it stops
    being buildable, and both are worth a line."""
    appeared = runtime_diff({}, parse_manifest(WITH_A_BASE))
    assert any("absent →" in line for line in appeared)

    disappeared = runtime_diff({"runtime": {"base": "python-3.12"}}, parse_manifest(NO_RUNTIME))
    assert any("→ absent" in line for line in disappeared)


def test_a_manifest_that_was_never_stored_does_not_crash_the_diff() -> None:
    """`project.manifest` is JSON from a column and can be anything, including `None` on a
    row an older build wrote."""
    assert runtime_diff(None, parse_manifest(NO_RUNTIME)) == []
    assert runtime_diff("not a mapping", parse_manifest(NO_RUNTIME)) == []
