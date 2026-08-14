"""Moving a resolved graph by running the ecosystem's own tool. Item 175, DR-0016.

**No test here starts a container**: `run` is injected, so what these assert is the decision logic
— which command, which files, and above all whether the tool is believed. The Docker path is
measured once by hand and written into the item.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from pathlib import Path

from hullwork import resolve

NPM_LOCK = """
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/lodash": {"version": "%s"}
  }
}
"""

UV_LOCK = """
[[package]]
name = "jinja2"
version = "%s"
"""


def test_each_lock_file_has_exactly_one_owner() -> None:
    assert resolve.resolver_for("package-lock.json").lock == "package-lock.json"  # type: ignore[union-attr]
    assert resolve.resolver_for("deep/uv.lock").lock == "uv.lock"  # type: ignore[union-attr]
    assert resolve.resolver_for("poetry.lock").lock == "poetry.lock"  # type: ignore[union-attr]


def test_a_lock_nobody_can_move_has_no_resolver() -> None:
    """`None` is not a gap to fill silently — item 173's refusal still applies, by name."""
    assert resolve.resolver_for("Cargo.lock") is None
    assert resolve.resolver_for("requirements.txt") is None


def test_the_command_names_the_package_and_the_version() -> None:
    npm = resolve.resolver_for("package-lock.json")
    assert npm is not None
    built = resolve.command_for(npm, "lodash", "4.17.21")

    assert "lodash@4.17.21" in built
    # Moves the graph without downloading node_modules: seconds rather than minutes.
    assert "--package-lock-only" in built


def test_the_manifest_is_required_and_named_when_absent() -> None:
    """A `uv.lock` with no `pyproject.toml` cannot be resolved by anything.

    Checked before the container starts, because finding it out after pulling an image is a minute
    spent on a fact that was on disk the whole time.
    """
    uv = resolve.resolver_for("uv.lock")
    assert uv is not None
    assert resolve.missing_from(uv, ["uv.lock"]) == ["pyproject.toml"]
    assert resolve.missing_from(uv, ["pyproject.toml", "uv.lock"]) == []
    # And from a subdirectory, because a monorepo pins per package.
    assert resolve.missing_from(uv, ["svc/pyproject.toml", "svc/uv.lock"], "svc") == []


def test_a_manifest_in_another_directory_does_not_count(monkeypatch: object) -> None:
    """**Item 239, and the reason item 238's fix surfaced a second bug rather than a verdict.**

    This compared basenames anywhere in the checkout, so `backend/pyproject.toml` satisfied a check
    about `frontend/`'s lock — and the honest refusal it exists to produce was unreachable for any
    repository with more than one lock file. Measured on `simplecheck`, which is a monorepo: it
    pulled a 200MB image to be told the file was not where it was looking.
    """
    del monkeypatch
    uv = resolve.resolver_for("uv.lock")
    assert uv is not None

    tree = ["backend/pyproject.toml", "backend/uv.lock", "frontend/uv.lock"]

    assert resolve.missing_from(uv, tree, "backend") == []
    assert resolve.missing_from(uv, tree, "frontend") == ["pyproject.toml"]


def test_the_resolver_runs_where_the_lock_is() -> None:
    """**The defect itself**: `uv lock` in the worktree root, on a repository whose `pyproject.toml`
    is in `backend/`, answers *No `pyproject.toml` found in current directory or any parent
    directory* — a sentence about our own working directory, recorded as a fact about somebody
    else's repository (`cannot-move`).
    """
    import tempfile
    from pathlib import Path

    uv = resolve.resolver_for("uv.lock")
    assert uv is not None
    root = Path(tempfile.mkdtemp())
    (root / "backend").mkdir()
    (root / "backend" / "pyproject.toml").write_text("[project]\nname='x'\n")
    (root / "backend" / "uv.lock").write_text(UV_LOCK % "3.1.6")
    mounted: list[Path] = []

    def run(_r: object, context: Path, _c: str) -> tuple[int, str]:
        mounted.append(context)
        return 0, ""

    outcome = resolve.upgrade(
        resolver=uv, worktree=root, package="jinja2", version="3.1.6",
        present=["backend/pyproject.toml", "backend/uv.lock"], run=run, at="backend",
    )

    assert mounted == [root / "backend"], "the tool ran somewhere other than beside the lock"
    assert outcome.ok, outcome.detail


def test_a_lock_at_the_root_is_unchanged() -> None:
    """Every project that worked yesterday takes the path it took yesterday: `at` defaults to the
    root, and this is what says so rather than the default's existence."""
    import tempfile
    from pathlib import Path

    uv = resolve.resolver_for("uv.lock")
    assert uv is not None
    root = Path(tempfile.mkdtemp())
    (root / "pyproject.toml").write_text("[project]\nname='x'\n")
    (root / "uv.lock").write_text(UV_LOCK % "3.1.6")
    mounted: list[Path] = []

    def run(_r: object, context: Path, _c: str) -> tuple[int, str]:
        mounted.append(context)
        return 0, ""

    outcome = resolve.upgrade(
        resolver=uv, worktree=root, package="jinja2", version="3.1.6",
        present=["pyproject.toml", "uv.lock"], run=run,
    )

    assert mounted == [root]
    assert outcome.ok, outcome.detail


def test_the_version_is_read_back_out_of_each_lock_shape() -> None:
    assert resolve.version_in_lock(NPM_LOCK % "4.17.21", "package-lock.json", "lodash") == "4.17.21"
    assert resolve.version_in_lock(UV_LOCK % "3.1.6", "uv.lock", "jinja2") == "3.1.6"
    # Spelling is not identity: lock files disagree about which one they write.
    assert resolve.version_in_lock(UV_LOCK % "3.1.6", "uv.lock", "Jinja2") == "3.1.6"
    assert resolve.version_in_lock(UV_LOCK % "3.1.6", "uv.lock", "absent") is None


def test_a_resolver_that_moved_nothing_is_not_a_success(tmp_path: Path) -> None:
    """**The defect this whole module is careful about.**

    Every one of these tools resolves within whatever range the manifest allows and exits 0. A
    `"^4.17.11"` answers success having never gone near 5.x. Believing the exit code publishes a
    `clean` verdict for an upgrade that never happened — the worst artefact this can emit.
    """
    (tmp_path / "package-lock.json").write_text(NPM_LOCK % "4.17.20", encoding="utf-8")
    npm = resolve.resolver_for("package-lock.json")
    assert npm is not None

    result = resolve.upgrade(
        resolver=npm, worktree=tmp_path, package="lodash", version="5.0.0",
        present=["package.json", "package-lock.json"],
        run=lambda *_: (0, "up to date"),
    )

    assert result.outcome is resolve.Outcome.CONSTRAINED
    assert result.ok is False
    assert "still 4.17.20, not 5.0.0" in result.detail
    assert "range in the manifest" in result.detail


def test_a_resolver_that_moved_the_graph_is_a_success(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text(NPM_LOCK % "4.17.11", encoding="utf-8")
    npm = resolve.resolver_for("package-lock.json")
    assert npm is not None

    def run(_resolver: resolve.Resolver, _dir: Path, _command: str) -> tuple[int, str]:
        # What the real tool does: rewrites the file in place, through the bind mount.
        lock.write_text(NPM_LOCK % "4.17.21", encoding="utf-8")
        return 0, ""

    result = resolve.upgrade(
        resolver=npm, worktree=tmp_path, package="lodash", version="4.17.21",
        present=["package.json", "package-lock.json"], run=run,
    )

    assert result.outcome is resolve.Outcome.RESOLVED
    assert result.ok is True


def test_a_failing_tool_carries_its_own_words(tmp_path: Path) -> None:
    """`npm ERR! code ETARGET` is what the operator needs; "resolution failed" is not."""
    (tmp_path / "package-lock.json").write_text(NPM_LOCK % "4.17.11", encoding="utf-8")
    npm = resolve.resolver_for("package-lock.json")
    assert npm is not None

    result = resolve.upgrade(
        resolver=npm, worktree=tmp_path, package="lodash", version="99.0.0",
        present=["package.json", "package-lock.json"],
        run=lambda *_: (1, "npm ERR! code ETARGET\nnpm ERR! notarget No matching version"),
    )

    assert result.outcome is resolve.Outcome.FAILED
    assert "ETARGET" in result.detail


def test_nothing_runs_when_a_needed_file_is_absent(tmp_path: Path) -> None:
    ran: list[str] = []
    npm = resolve.resolver_for("package-lock.json")
    assert npm is not None

    def run(_resolver: resolve.Resolver, _dir: Path, _command: str) -> tuple[int, str]:
        ran.append("ran")
        return 0, ""

    result = resolve.upgrade(
        resolver=npm, worktree=tmp_path, package="lodash", version="4.17.21",
        present=["package-lock.json"], run=run,
    )

    assert result.outcome is resolve.Outcome.MISSING
    assert "package.json" in result.detail
    assert ran == [], "no container may start for a file that is missing on disk"


def test_a_resolver_may_rewrite_every_file_it_needs_not_only_the_lock() -> None:
    """**Measured, and it surprised the design.**

    `npm install lodash@4.17.21 --package-lock-only` rewrites `package.json` too, moving its range
    from `^4.17.11` to `^4.17.21`. Correct for an upgrade, and not what the caller assumed.

    The consequence is item 174's defect one file over: restoring only the lock between candidates
    leaves the manifest moved, so the next candidate resolves against a range the previous one
    widened — and nothing in the output would say so.
    """
    for resolver in resolve.RESOLVERS:
        assert resolve.touches(resolver) == resolver.needs
        assert resolver.lock in resolve.touches(resolver)
        # The manifest is in there too, which is the whole point of this test.
        assert len(resolve.touches(resolver)) >= 2


# --- the checkout the daemon can actually see (item 240) ---------------------------------------


def test_the_resolver_never_bind_mounts_the_checkout(monkeypatch: object) -> None:
    """**The third time this repository has learned it**, and the first time it is asserted.

    `-v {path}:/w` is resolved by the *daemon*. The dispatcher runs in a container, so that path
    exists in one filesystem and is looked up in another: the daemon finds nothing, mounts an empty
    directory, and `uv` reports the project has no manifest. Measured from inside the deployed
    dispatcher — a file written there, and `.`/`..` seen by the daemon.

    Item 055 moved the attempt's worktree off a bind mount for exactly this and item 082 the
    contract directory; this path kept one, with a docstring arguing a bind mount was *better*
    here — true on a host, false in a container, and never re-read when the ground moved.
    """
    import subprocess
    from pathlib import Path

    ran: list[list[str]] = []

    class Done:
        returncode = 0
        stdout = "carrier\n"
        stderr = ""

    def watch(argv: list[str], **kwargs: object) -> Done:
        ran.append(argv)
        return Done()

    monkeypatch.setattr(subprocess, "run", watch)  # type: ignore[attr-defined]
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "hullwork.sandbox.docker.run_docker", lambda argv, **k: watch(argv)
    )
    uv = resolve.resolver_for("uv.lock")
    assert uv is not None

    resolve.in_a_container(uv, Path("/inside/the/dispatcher"), "uv lock")

    resolving = [argv for argv in ran if "sh" in argv and "-lc" in argv]
    assert resolving, "the resolver never ran"
    mounts = [argv[i + 1] for argv in resolving for i, a in enumerate(argv) if a == "-v"]
    assert mounts, "the resolver runs with nothing mounted at all"
    for mount in mounts:
        assert not mount.startswith("/"), f"a host path is bind-mounted: {mount}"
        assert mount.startswith("hullwork-resolve-"), mount


def test_the_regenerated_lock_is_copied_back(monkeypatch: object) -> None:
    """The whole point of running it: `version_in_lock`, the rebuild and the guard that restores
    what this touched all read files, and they read them in the dispatcher's own filesystem."""
    import subprocess
    from pathlib import Path

    ran: list[list[str]] = []

    class Done:
        returncode = 0
        stdout = "carrier\n"
        stderr = ""

    def watch(argv: list[str], **kwargs: object) -> Done:
        ran.append(argv)
        return Done()

    monkeypatch.setattr(subprocess, "run", watch)  # type: ignore[attr-defined]
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "hullwork.sandbox.docker.run_docker", lambda argv, **k: watch(argv)
    )
    uv = resolve.resolver_for("uv.lock")
    assert uv is not None

    resolve.in_a_container(uv, Path("/w/backend"), "uv lock")

    copies = [argv for argv in ran if len(argv) > 1 and argv[1] == "cp"]
    assert any(one[-1] == "/w/backend" for one in copies), "nothing is copied back out"
    assert any(one[2] == "/w/backend/." for one in copies), "nothing is copied in"
    assert any(one[1] == "volume" and one[2] == "rm" for one in ran), "the volume is left behind"
