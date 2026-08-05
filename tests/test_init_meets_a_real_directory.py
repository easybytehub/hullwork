"""What `hullwork init` does when the directory is not the one the author arranged. Item 126.

Item 115 measured `init` in a clean checkout on a machine with Docker, and it passed. This file is
the second installation — the first one nobody set up in advance — and it is where the three things
below were found, in this order, before a single line of configuration was filled in:

1. the first command in `deployment-notes.md` is a command of a package that is not installed yet;
2. run the way a stranger *can* run it, from the image, it died with a `PermissionError` traceback,
   because the image runs as uid 10001 and a deployment directory belongs to root;
3. run inside a clone, it kept the repository's own **evaluation stack** and said only that it had
   kept something — which leaves an operator holding exactly the compose file the notes spend
   a boxed warning on.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from hullwork import scaffold
from hullwork.cli import main


def test_a_directory_it_cannot_write_to_is_a_message_and_not_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """**`main` promises an exit code and never a traceback**, and that promise ended exactly where
    somebody new was standing: `docker run … init --into /out` on a root-owned mount."""
    unwritable = tmp_path / "theirs"
    unwritable.mkdir()
    unwritable.chmod(0o500)
    try:
        code = main(["init", "--into", str(unwritable)], out=io.StringIO())
    finally:
        unwritable.chmod(0o700)

    assert code == 1
    said = capsys.readouterr().err
    assert "Traceback" not in said
    assert str(unwritable) in said
    assert "chown" in said, "the remedy, not just the diagnosis"
    assert "uid" in said


def test_keeping_the_evaluation_stack_says_what_that_means(tmp_path: Path) -> None:
    """The trap item 115 exists to close, arrived at through the front door: `init` inside a clone
    finds this repository's own compose, keeps it — correctly — and the operator's deployment then
    has no dispatcher and no error reporting."""
    (tmp_path / scaffold.COMPOSE_FILE).write_text(
        "# Local evaluation stack. Bound to loopback on purpose…\nservices:\n  api:\n"
    )

    done = scaffold.write(tmp_path, docker_gid="999")

    assert scaffold.COMPOSE_FILE in done.kept
    note = " ".join(done.notes)
    assert "evaluation" in note
    assert "no dispatcher" in note
    assert "into a directory of your own" in note


def test_a_compose_file_that_is_not_ours_is_kept_without_editorialising(tmp_path: Path) -> None:
    """The point is to warn about a **known** file, not to have opinions about a stranger's. Item
    115's rule is unchanged: named, kept, and nothing else said."""
    (tmp_path / scaffold.COMPOSE_FILE).write_text("# mine, and it took me a week\nservices: {}\n")

    done = scaffold.write(tmp_path, docker_gid="999")

    assert scaffold.COMPOSE_FILE in done.kept
    assert not [note for note in done.notes if "evaluation" in note]
    assert (tmp_path / scaffold.COMPOSE_FILE).read_text().startswith("# mine")


def test_the_note_reaches_the_operator_and_not_only_the_dataclass(tmp_path: Path) -> None:
    """A note nobody prints is a note nobody reads."""
    (tmp_path / scaffold.COMPOSE_FILE).write_text("# Local evaluation stack.\nservices: {}\n")

    out = io.StringIO()
    assert main(["init", "--into", str(tmp_path)], out=out) == 0

    assert "evaluation" in out.getvalue()


# --- item 127: what the scaffold writes, its own compose has to be able to serve ---------------


def test_the_build_context_is_said_rather_than_assumed() -> None:
    """**Two right items that contradicted each other.** Item 115's gate ran `init` in a checkout,
    where `build: .` finds a Dockerfile; item 126 then told operators — correctly — to run it into a
    directory of their own, where `docker compose up --build` dies with `open Dockerfile: no such
    file or directory`. Measured on the second installation, which is the first nobody arranged.

    **And the fix was half a fix, which this test proved by asserting it** (corrected 2026-08-04).
    Making the context a variable was right; writing it as `.` put the same failure back, because
    the deploy directory is deliberately not the checkout. So the docstring above described a
    `Dockerfile: no such file or directory` while the assertion below guaranteed one — a stranger
    hit it, from a value they never chose. The interpolation stays; the value ships empty, failing
    at the same step with `BUILD_SOURCE` named in the error.
    """
    import yaml

    built = yaml.safe_load(scaffold.compose(docker_gid="989"))["services"]["api"]["build"]

    assert built["context"] == "${BUILD_SOURCE:-.}"
    assert "\nBUILD_SOURCE=\n" in scaffold.environment(docker_gid="989")


def test_the_dsn_and_the_extra_that_makes_it_usable_are_written_together() -> None:
    """`deploy.env` named `HULLWORK_ERROR_DSN` and the compose beside it built with no extras, so
    setting the variable the scaffold wrote made the receiver refuse to start. The refusal is right;
    handing somebody an unusable variable is not."""
    import yaml

    built = yaml.safe_load(scaffold.compose(docker_gid="989"))["services"]["api"]["build"]
    assert built["args"]["EXTRAS"] == "${BUILD_EXTRAS:-}"

    written = scaffold.environment(docker_gid="989")
    dsn_at = written.index("HULLWORK_ERROR_DSN=")
    extras_at = written.index("BUILD_EXTRAS=")
    assert 0 < extras_at - dsn_at < 40, "the trap is only visible when the two are read together"
    assert "stops the receiver from starting" in written[:dsn_at][-400:]


def test_neither_is_filled_in_for_you() -> None:
    """`BUILD_EXTRAS` empty means no SDK nobody asked for. `BUILD_SOURCE` empty is newer and
    is a correction: **this test asserted `.`, and that assertion was the defect.**

    The reasoning behind `.` was that it leaves a deployment-from-a-checkout working — but the
    comment three lines above it in the generated file says the deploy directory must *not* be the
    checkout, so the default served the one layout the scaffold advises against. A stranger followed
    `init`'s own printed steps verbatim on 2026-08-04 and got `failed to read dockerfile: open
    Dockerfile: no such file or directory`, from a value they never chose and could not see.

    Empty fails at the same step with the variable named in the error. Same reasoning as
    `REPLACE-ME` for `group_add`, one file over: a placeholder that fails loudly beats a default
    that fails obscurely.
    """
    written = scaffold.environment(docker_gid="989")

    assert "\nBUILD_EXTRAS=\n" in written, "empty: no SDK you did not ask for"
    assert "\nBUILD_SOURCE=\n" in written, "empty: the build context has no sensible default"
    assert "\nBUILD_SOURCE=.\n" not in written, "the default that broke its own instructions"


# --- item 130: two instances on one host both want the same four things ------------------------


def test_the_image_is_tagged_with_the_instance() -> None:
    """**Measured on the host that runs two.** `image: hullwork:dev` is a constant, so the second
    instance to build takes the name and the first keeps running an image nothing points at:

        dashboard-api-1 | hullwork:dev
        hullwork-api-1  | 549264ac374f   ← the tag moved out from under it

    A deployment directory, a database, a set of sandbox objects and an image name are the four
    things two instances on one host both want. Item 125 did the third; this is the fourth.
    """
    import yaml

    services = yaml.safe_load(scaffold.compose(docker_gid="989"))["services"]

    assert services["api"]["image"] == "hullwork:${HULLWORK_INSTANCE:-dev}"
    assert services["dispatcher"]["image"] == services["api"]["image"], (
        "two halves of one instance on two builds is a worse failure than the one being fixed"
    )


def test_one_instance_keeps_the_name_it_has_today() -> None:
    """The default is the old constant, so nobody who never heard of this has to do anything —
    the same rule item 125 and item 127 both followed.

    Asserted per service and by equality, not by presence: the compose names the image twice, and a
    check that only asks whether the string appears *somewhere* is satisfied by the other one. Found
    by reintroducing exactly that.
    """
    import yaml

    services = yaml.safe_load(scaffold.compose(docker_gid="989"))["services"]

    for name in ("api", "dispatcher"):
        assert services[name]["image"] == "hullwork:${HULLWORK_INSTANCE:-dev}", name
        assert ":-dev}" in services[name]["image"], f"{name}: unset must resolve as it always did"
