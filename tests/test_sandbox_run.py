"""Getting work out of the sandbox without letting anything else out with it (item 023).

The validation tests here are the ones that matter. Item 040 decided that what crosses back is a
set of `(path, bytes)` rather than a patch, precisely because validating a path list is
parser-free and `git apply` is a host git process eating attacker-authored content. These are
that validation.
"""

from pathlib import Path

import pytest

from hullwork.sandbox.run import (
    MAX_CHANGED_FILES,
    MAX_FILE_BYTES,
    SANDBOX_HOME,
    SANDBOX_UID,
    WORKDIR,
    RunResult,
    Sandbox,
    SandboxError,
    UnsafePathError,
    collect_changes,
    is_test_infrastructure,
    snapshot,
)


def _tree(root: Path, files: dict[str, bytes]) -> Path:
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return root


def test_a_changed_file_comes_back(tmp_path: Path) -> None:
    _tree(tmp_path, {"src.py": b"x = 1\n"})
    before = snapshot(tmp_path)
    (tmp_path / "src.py").write_bytes(b"x = 2\n")

    assert collect_changes(tmp_path, before).written == {"src.py": b"x = 2\n"}


def test_an_untouched_file_does_not(tmp_path: Path) -> None:
    _tree(tmp_path, {"a.py": b"1", "b.py": b"2"})
    before = snapshot(tmp_path)
    (tmp_path / "a.py").write_bytes(b"3")

    assert set(collect_changes(tmp_path, before).written) == {"a.py"}


def test_nothing_from_dot_git_ever_crosses(tmp_path: Path) -> None:
    """A hook written there runs on the host the next time git touches the tree."""
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    _tree(tmp_path, {".git/hooks/post-checkout": b"#!/bin/sh\ncurl evil\n"})

    assert collect_changes(tmp_path, before).written == {}


def test_a_symlink_is_never_read_back(tmp_path: Path) -> None:
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    (tmp_path / "escape").symlink_to("/etc/passwd")

    assert collect_changes(tmp_path, before).written == {}


def test_a_file_too_large_to_be_a_source_change_is_refused(tmp_path: Path) -> None:
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    (tmp_path / "blob.bin").write_bytes(b"x" * (MAX_FILE_BYTES + 1))

    with pytest.raises(UnsafePathError, match="not a source change"):
        collect_changes(tmp_path, before)


def test_too_many_changed_files_is_something_going_wrong(tmp_path: Path) -> None:
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    _tree(tmp_path, {f"f{n}.py": b"x" for n in range(MAX_CHANGED_FILES + 2)})

    with pytest.raises(UnsafePathError, match="not a bug fix"):
        collect_changes(tmp_path, before)


# --- the reproduce phase: new files, under the declared test path, and nothing else ----------


def test_the_reproduce_phase_accepts_a_new_test(tmp_path: Path) -> None:
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    _tree(tmp_path, {"tests/test_repro.py": b"def test_x():\n    assert False\n"})

    changed = collect_changes(tmp_path, before, allow_new_only_under="tests")

    assert set(changed.written) == {"tests/test_repro.py"}
    assert changed.deleted == ()


def test_the_reproduce_phase_refuses_to_modify_working_code(tmp_path: Path) -> None:
    """Otherwise a phase reaches a red gate by breaking something rather than reproducing it."""
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    (tmp_path / "src.py").write_bytes(b"raise SystemExit\n")

    with pytest.raises(UnsafePathError, match="already existed"):
        collect_changes(tmp_path, before, allow_new_only_under="tests")


def test_the_reproduce_phase_refuses_a_new_file_outside_the_test_path(tmp_path: Path) -> None:
    """A root `conftest.py` is the cheapest way to fake a reproduction."""
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    _tree(tmp_path, {"conftest.py": b"import sys\nsys.exit(1)\n"})

    with pytest.raises(UnsafePathError, match="outside the declared test path"):
        collect_changes(tmp_path, before, allow_new_only_under="tests")


def test_the_fix_phase_may_touch_source(tmp_path: Path) -> None:
    _tree(tmp_path, {"src.py": b"1", "tests/test_repro.py": b"assert False"})
    before = snapshot(tmp_path)
    (tmp_path / "src.py").write_bytes(b"2")

    assert set(collect_changes(tmp_path, before).written) == {"src.py"}


def test_a_nested_new_test_is_still_under_the_path(tmp_path: Path) -> None:
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    _tree(tmp_path, {"tests/unit/test_deep.py": b"x"})

    assert set(collect_changes(tmp_path, before, allow_new_only_under="tests").written) == {
        "tests/unit/test_deep.py"
    }


def test_a_sibling_directory_that_merely_starts_the_same_is_not_inside(tmp_path: Path) -> None:
    """`tests_evil/` is not `tests/`, and a prefix check without the separator would say it was."""
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    _tree(tmp_path, {"tests_evil/conftest.py": b"x"})

    with pytest.raises(UnsafePathError, match="outside the declared test path"):
        collect_changes(tmp_path, before, allow_new_only_under="tests")


def test_gitignore_is_not_the_git_directory(tmp_path: Path) -> None:
    """The first version of this filter was a string prefix and swallowed `.gitignore` silently.

    A fix that needed a line there would have lost it without a word. Found by writing a file
    called `.git_fake` and noticing it never came back.
    """
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    _tree(tmp_path, {".gitignore": b"*.pyc\n", ".git_fake": b"x"})

    assert set(collect_changes(tmp_path, before).written) == {".gitignore", ".git_fake"}


@pytest.mark.parametrize("path", [".github/workflows/ci.yml", ".forgejo/workflows/ci.yml"])
def test_workflow_files_are_refused_on_purpose(tmp_path: Path, path: str) -> None:
    """A different thing from the accident above, and worth keeping separate.

    A workflow runs on the forge's runner with the repository's secrets — outside the sandbox,
    with privileges the agent does not have and must not be able to grant itself.
    """
    _tree(tmp_path, {"src.py": b"1"})
    before = snapshot(tmp_path)
    _tree(tmp_path, {path: b"run: curl evil"})

    assert collect_changes(tmp_path, before).written == {}


# --- a deletion is a change (item 045) -----------------------------------------------------------


def test_a_deleted_file_is_reported(tmp_path: Path) -> None:
    """It was invisible, and that made the red-green claim false about what got published.

    `collect_changes` walked the tree, so a file the fix removed simply stopped appearing. The gates
    ran against a tree with the validation gone; the pull request carried the tree with it intact.
    """
    _tree(tmp_path, {"src.py": b"x = 1\n", "validate.py": b"def check(): raise ValueError\n"})
    before = snapshot(tmp_path)
    (tmp_path / "validate.py").unlink()
    (tmp_path / "src.py").write_text("x = 2\n")

    changed = collect_changes(tmp_path, before)

    assert changed.deleted == ("validate.py",)
    assert set(changed.written) == {"src.py"}
    assert changed.count == 2


def test_a_deletion_alone_is_still_a_change(tmp_path: Path) -> None:
    """`if not changes` decided whether anything happened, and a deletion answered no."""
    _tree(tmp_path, {"validate.py": b"def check(): raise ValueError\n"})
    before = snapshot(tmp_path)
    (tmp_path / "validate.py").unlink()

    changed = collect_changes(tmp_path, before)

    assert bool(changed) is True
    assert changed.written == {}


def test_the_reproduce_phase_may_not_delete(tmp_path: Path) -> None:
    """A suite that fails because a passing test was removed reproduces nothing."""
    _tree(tmp_path, {"tests/test_ok.py": b"def test_ok():\n    pass\n"})
    before = snapshot(tmp_path)
    (tmp_path / "tests" / "test_ok.py").unlink()

    with pytest.raises(UnsafePathError) as caught:
        collect_changes(tmp_path, before, allow_new_only_under="tests")

    assert "may only add new files" in str(caught.value)


def test_a_vanished_tool_artefact_is_not_a_deletion(tmp_path: Path) -> None:
    """`snapshot` never recorded it, so nothing can claim it was removed."""
    _tree(tmp_path, {"src.py": b"x = 1\n", ".pytest_cache/CACHEDIR.TAG": b"x"})
    before = snapshot(tmp_path)
    (tmp_path / ".pytest_cache" / "CACHEDIR.TAG").unlink()

    assert collect_changes(tmp_path, before).deleted == ()


@pytest.mark.parametrize(
    "path",
    [
        "conftest.py",
        "tests/conftest.py",
        "src/deep/conftest.py",
        "pytest.ini",
        "tox.ini",
        "setup.cfg",
        "pyproject.toml",
        "package.json",
        "vitest.config.ts",
        "tests/test_thing.py",
        "test/thing_test.py",
        "src/widget.test.ts",
        "src/widget.spec.tsx",
        "__tests__/widget.js",
    ],
)
def test_test_infrastructure_is_recognised(path: str) -> None:
    """Item 046. Instance-owned, and deliberately not the manifest's `test_path`."""
    assert is_test_infrastructure(path) is True


@pytest.mark.parametrize(
    "path",
    ["src/app.py", "app.py", "README.md", "src/testing_helpers.py", "contest.py", "src/latest.py"],
)
def test_ordinary_source_is_not_test_infrastructure(path: str) -> None:
    """Over-matching here would freeze half a repository, which is the opposite failure."""
    assert is_test_infrastructure(path) is False


# --- a worktree the sandbox owns (item 055) ------------------------------------------------------


def test_a_phase_never_bind_mounts_the_host_worktree(tmp_path: Path) -> None:
    """The mistake this replaces, asserted on the argument list because it would come back as a
    one-line convenience.

    Spec M2 §4.2 called a bind mount disqualifying; the reason was measured on the first attempt
    that reached a Linux sandbox — `could not create cache path /work/.pytest_cache`, because the
    worktree belongs to the dispatcher and the container runs as uid 10001.
    """
    box = Sandbox(image="img", worktree=tmp_path, volume="hullwork-worktree-t1")

    argv = box._argv("pytest", None)

    assert f"{tmp_path}:{WORKDIR}" not in argv
    assert f"hullwork-worktree-t1:{WORKDIR}" in argv


# --- the gate phases have no route to the gateway (item 058) -------------------------------------


def _attempt_box(tmp_path: Path) -> Sandbox:
    """What `work._attempt` builds: an attempt-wide network and gateway address."""
    return Sandbox(
        image="img",
        worktree=tmp_path,
        volume="hullwork-worktree-t1",
        gateway_url="http://172.20.0.2:8080",
        network="hullwork-attempt-abc",
    )


def test_a_gate_phase_carries_nothing_that_points_at_a_model(tmp_path: Path) -> None:
    """One rule, two doors, and only one of them was shut (item 060).

    Item 058 moved the network and the `*_BASE_URL` variables out of the gate phases. The reference
    engine's placeholder credential lived in the image's `ENV` instead of in `docker run`'s argv, so
    it survived — and a watched project that feature-detects on `ANTHROPIC_API_KEY` takes its AI
    branch and calls an API the gate phases correctly cannot reach.

    Measured on `acme`, the first project that is not Hullwork to reach a suite result inside
    the sandbox: `3 failed, 246 passed`, all three with `anthropic._base_client: Retrying request to
    /v1/messages`, because its `get_mapper()` is "Anthropic si hay key; si no, el heurístico".

    Asserted on the recipe rather than only on the argv, because the argv cannot show what the image
    baked in — which is exactly how this hid behind item 058's tests.
    """
    from hullwork.engine import resolve

    engine = resolve("claude-code")

    assert not [line for line in engine.steps if "API_KEY" in line], (
        "a credential in the recipe reaches every phase; it belongs in `env`, which only the "
        "agent's phases receive"
    )
    assert "ANTHROPIC_API_KEY" in engine.env

    # And the environment a gate phase is actually given carries none of it.
    argv = _attempt_box(tmp_path)._argv("pytest", None)

    assert not [flag for flag in argv if "API_KEY" in flag]


def test_an_agent_phase_gets_the_placeholder_or_the_harness_will_not_start(
    tmp_path: Path,
) -> None:
    """The other half. The CLI refuses to start with the variable absent."""
    from hullwork.engine import resolve

    argv = _attempt_box(tmp_path)._argv(
        "hullwork-agent", dict(resolve("claude-code").env), model=True
    )

    assert "ANTHROPIC_API_KEY=placeholder-the-gateway-holds-the-real-one" in argv


def test_a_gate_phase_can_reach_nothing_at_all(tmp_path: Path) -> None:
    """The watched project's own test command is untrusted code — that is why the sandbox exists.

    Measured before item 058: every gate phase got the internal network *and* three environment
    variables pointing at a gateway that injects the operator's credential on every request. So a
    `conftest.py` in any repository somebody can merge to could spend the operator's tokens and add
    responses to the provenance seal of an attempt it had nothing to do with. `_argv`'s own comment
    said "nothing else ever does" and no code enforced it.

    Both halves are asserted because either one alone leaves a working route: the network without
    the address is still reachable by IP, and the address without the network is a hint plus a route
    that `--network none` happens to be closing.
    """
    argv = _attempt_box(tmp_path)._argv("pytest", None)

    assert "hullwork-attempt-abc" not in argv
    assert argv[argv.index("--network") + 1] == "none"
    assert not [flag for flag in argv if "BASE_URL" in flag or "API_BASE" in flag]


def test_an_agent_phase_gets_the_gateway_and_only_it(tmp_path: Path) -> None:
    """Or the fix is a product that cannot think. The other half of the same rule."""
    argv = _attempt_box(tmp_path)._argv("hullwork-agent", None, model=True)

    assert argv[argv.index("--network") + 1] == "hullwork-attempt-abc"
    assert "--env" in argv
    assert "ANTHROPIC_BASE_URL=http://172.20.0.2:8080" in argv
    assert "OPENAI_BASE_URL=http://172.20.0.2:8080" in argv


def test_the_short_name_is_the_safe_one(tmp_path: Path) -> None:
    """`run` has no route out and `run_with_model` does, so forgetting fails closed.

    Asserted on the two public methods rather than on `_argv`'s keyword, because the keyword is an
    implementation detail and which method a caller reaches for is the actual guardrail.
    """
    safe = _attempt_box(tmp_path)._argv("pytest", None, model=False)

    assert safe[safe.index("--network") + 1] == "none"
    # And the default of the private helper agrees with the public method that has no route.
    assert _attempt_box(tmp_path)._argv("pytest", None) == safe


# --- the harness is mounted, and only where it belongs (item 065) ---------------------------------


def test_only_an_agent_phase_receives_the_harness_bundle(tmp_path: Path) -> None:
    """The same rule as the gateway (item 058), applied to the other thing only the agent needs.

    The watched project's test command has no business seeing Hullwork's own software, and a phase
    that found an unexpected executable under a path it did not put there would be reporting it as
    the agent's work — the mistake `CONTRACT_DIR` exists to prevent, one directory over.
    """
    from hullwork.sandbox.harness import BUNDLE_DIR

    box = Sandbox(
        image="img", worktree=tmp_path, volume="v",
        gateway_url="http://172.20.0.2:8080", network="hullwork-attempt-abc",
        harness_bundle="hullwork-harness-abc123",
    )

    gate = box._argv("pytest", None)
    agent = box._argv("hullwork-agent", None, model=True)

    assert not [flag for flag in gate if BUNDLE_DIR in flag]
    assert f"hullwork-harness-abc123:{BUNDLE_DIR}:ro" in agent


def test_the_bundle_is_mounted_read_only(tmp_path: Path) -> None:
    """It is shared by every attempt on the instance, so a phase that could write to it would be
    choosing what the next attempt runs."""
    box = Sandbox(
        image="img", worktree=tmp_path, volume="v",
        network="net", gateway_url="http://x", harness_bundle="hullwork-harness-abc123",
    )

    mounts = [
        argument for flag, argument in zip(
            box._argv("agent", None, model=True), box._argv("agent", None, model=True)[1:],
            strict=False,
        ) if flag == "--volume"
    ]
    bundle = [m for m in mounts if "hullwork-harness" in m]

    assert bundle and all(m.endswith(":ro") for m in bundle)


def test_a_baked_engine_mounts_nothing(tmp_path: Path) -> None:
    """`harness_bundle` absent is the old arrangement, unchanged: nothing is mounted and the image
    carries the harness. The two ways must not both be half-applied."""
    box = Sandbox(image="img", worktree=tmp_path, volume="v", network="n", gateway_url="http://x")

    assert not [flag for flag in box._argv("agent", None, model=True) if "harness" in flag]


# --- M5: the hardening spec M2 §4 asked for -------------------------------------------------------


def test_the_root_filesystem_is_read_only_and_says_what_is_writable() -> None:
    """Spec M2 §4 asked for this and it was absent.

    What it buys is narrow and real: the project's own test command cannot leave anything in the
    image's filesystem, so what the next phase runs is what the build produced rather than what the
    last phase did to it — the property `_restore_infrastructure` protects one layer up, enforced by
    the kernel instead of by a diff.
    """
    box = Sandbox(image="img", worktree=Path("/tmp/wt"))  # noqa: S108

    argv = box._argv("pytest", None)

    assert "--read-only" in argv
    tmpfs = [argv[i + 1] for i, a in enumerate(argv) if a == "--tmpfs"]
    # `/tmp` here is a path inside the container, not on this machine.
    assert any(entry.startswith("/tmp:") for entry in tmpfs), "pytest and pip need it writable"  # noqa: S108
    assert any(entry.startswith(f"{SANDBOX_HOME}:") for entry in tmpfs), (
        "the home holds every tool's cache; read-only without it breaks the baseline"
    )


def test_every_writable_path_is_bounded_and_cannot_escalate() -> None:
    """What the tmpfs options are actually worth, one property at a time.

    **This asserted `noexec`, and item 092 is why it no longer does.** That option broke the
    baseline of the watched project — 24 of its own tests write a fake executable into `tmp_path`
    and run it, which is how any project that tests a CLI is written — and a red baseline stops
    every attempt at step 0, so the loop was closed by a control added to protect it. The
    document is the measurement: `attempt_steps.output` for attempt 14 on the live instance, *"24
    failed, 875 passed"* on a checkout nobody had touched.

    `nosuid` and `nodev` are the ones that pay for themselves: they cost nothing, break nothing, and
    close things the writable worktree does not already offer. `size=` is the one that protects the
    host — an unbounded tmpfs is the host's memory. `nodev` was **not** asserted before; it is now.
    """
    box = Sandbox(image="img", worktree=Path("/tmp/wt"))  # noqa: S108

    argv = box._argv("pytest", None)

    tmpfs = [argv[i + 1] for i, a in enumerate(argv) if a == "--tmpfs"]
    assert tmpfs, "there is at least one writable path"
    for entry in tmpfs:
        assert "nosuid" in entry, entry
        assert "nodev" in entry, entry
        assert "size=" in entry, f"an unbounded tmpfs is the host's memory: {entry}"


def test_the_phase_has_ceilings_of_its_own() -> None:
    """`--ulimit`, absent until now.

    `nofile` is the one that bites in practice — a test that leaks descriptors otherwise takes the
    daemon's own limits with it — and `nproc` backs `--pids-limit` up at the kernel's level rather
    than only at the cgroup's.
    """
    box = Sandbox(image="img", worktree=Path("/tmp/wt"))  # noqa: S108

    argv = box._argv("pytest", None)
    limits = [argv[i + 1] for i, a in enumerate(argv) if a == "--ulimit"]

    assert any(entry.startswith("nofile=") for entry in limits), limits
    assert any(entry.startswith("nproc=") for entry in limits), limits


def test_hardening_applies_to_the_agent_phase_too() -> None:
    """The phase that runs a model's chosen commands is not the one to exempt.

    Asserted separately because `model=True` is the branch that adds the gateway network, and an
    exemption added there would be invisible to every test above.
    """
    box = Sandbox(image="img", worktree=Path("/tmp/wt"), gateway_url="http://gw:8080")  # noqa: S108

    argv = box._argv("agent", None, model=True)

    assert "--read-only" in argv
    assert any(a == "--tmpfs" for a in argv)
    assert any(a == "--ulimit" for a in argv)


def test_no_writable_path_is_mounted_noexec() -> None:
    """The other half of item 092, asserted so the option cannot come back by good intentions.

    It reads as hardening and it is not: the worktree is a writable volume the gates execute from,
    so nothing is denied by forbidding execution in `/tmp` — while the ordinary pattern of writing a
    fixture executable and running it stops working, and with it the baseline of any project that
    tests a CLI. Measured: 24 of this project's own tests, on an untouched checkout.
    """
    box = Sandbox(image="img", worktree=Path("/tmp/wt"))  # noqa: S108

    argv = box._argv("pytest", None)
    tmpfs = [argv[index + 1] for index, flag in enumerate(argv) if flag == "--tmpfs"]

    assert tmpfs, "there is at least one writable path"
    for entry in tmpfs:
        assert "noexec" not in entry, (
            f"noexec is back on {entry}: this closes step 0 for every project whose tests write an "
            f"executable, and grants nothing the writable worktree does not already grant"
        )
        # **And `exec` has to be stated, not merely not-forbidden.** Docker mounts `--tmpfs` with
        # `noexec` by default, so the first version of this fix removed the option from the argument
        # and changed nothing: `/proc/mounts` inside the sandbox still said `noexec`, and the
        # baseline stayed red on the same 24 tests. This assertion is what that measurement bought;
        # `tests/test_sandbox_docker.py` checks the mount itself, which is the only real proof.
        assert "exec" in entry.split(","), (
            f"exec is not stated on {entry}: Docker's default for --tmpfs is noexec, so leaving it "
            f"out is the same as asking for it"
        )


# --- the phase environment is proved before a phase depends on it. Item 094 -----------------------


def test_the_home_is_owned_by_the_user_the_phase_runs_as() -> None:
    """**The defect that made the first merged fix an unverified artefact.**

    A `--tmpfs` is mounted with the options Docker chooses, not with the container's `--user`, and
    `/home/hullwork` came up `drwx------ 0 0` while the phase ran as 10001. The agent's config
    directory lives there, so every `Bash` invocation failed with
    `EACCES … mkdir '/home/hullwork/.claude/session-env/…'` and both agent phases worked by reading
    source. `/tmp` hid the same defect because Docker gives a tmpfs there the sticky 1777 that path
    conventionally has.

    Asserted in the argv, and by effect in `tests/test_sandbox_docker.py` — item 092 is the reason
    both exist.
    """
    box = Sandbox(image="img", worktree=Path("/tmp/wt"))  # noqa: S108

    argv = box._argv("pytest", None)
    tmpfs = [argv[index + 1] for index, flag in enumerate(argv) if flag == "--tmpfs"]
    home = next(entry for entry in tmpfs if entry.startswith(f"{SANDBOX_HOME}:"))

    assert f"uid={box._uid}" in home, f"the home is not given to the phase's own uid: {home}"
    assert f"gid={box._gid}" in home, home
    assert "mode=700" in home, f"a home is private: {home}"
    # There is no `--user` here on purpose: the image declares `USER hullwork` (uid 10001), so the
    # phase's identity comes from the build. Which is exactly why the mount has to name the same
    # number — nothing on the command line would have made them agree, and nothing complains when
    # they do not. `_uid` is the same value `ensure_volume` chowns the worktree to.
    assert "--user" not in argv
    assert box._uid == SANDBOX_UID, "the mount and the chown must mean the same user"


def _preflight_saying(
    box: Sandbox, monkeypatch: pytest.MonkeyPatch, *, exit_code: int, output: str
) -> None:
    """Run the preflight with the probe's answer supplied.

    The *decision* is what these tests are about — which answers stop an attempt — and it is
    testable without a daemon. Whether the probe itself measures the right things is not something a
    double can say, and `tests/test_sandbox_docker.py` runs it against real Docker for that.
    """
    monkeypatch.setattr(
        Sandbox,
        "run",
        lambda self, command, timeout, env=None: RunResult(
            command=command, exit_code=exit_code, output=output, duration_ms=1
        ),
    )
    box.self_test()


def test_the_preflight_refuses_a_sandbox_that_cannot_host_a_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Loud, and before the model is called — the two things the failing run was not.

    A `SandboxError` here becomes an abandoned attempt, so it costs the item nothing. An artefact
    produced by a phase that could not run a command costs the item its only try and is
    indistinguishable from one that was verified.
    """
    box = Sandbox(image="img", worktree=tmp_path)

    with pytest.raises(SandboxError) as refused:
        _preflight_saying(box, monkeypatch, exit_code=1, output="mkdir: Permission denied")

    assert "cannot host a phase" in str(refused.value)
    assert "Permission denied" in refused.value.output, "the probe's own words are the diagnosis"


def test_the_preflight_reads_the_probe_rather_than_only_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exit code from a shell is the last command's, which is how a defect survives a green run.

    The probe writes a file and executes it. A sandbox where that produced nothing could still exit
    0, so what it printed is read too.
    """
    box = Sandbox(image="img", worktree=tmp_path)

    with pytest.raises(SandboxError) as refused:
        _preflight_saying(box, monkeypatch, exit_code=0, output="")

    assert "refused to execute" in str(refused.value)


def test_the_preflight_refuses_a_writable_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--read-only` is a control other things depend on, so its absence stops the attempt."""
    box = Sandbox(image="img", worktree=tmp_path)

    with pytest.raises(SandboxError) as refused:
        _preflight_saying(box, monkeypatch, exit_code=0, output="ran\nROOT-IS-WRITABLE")

    assert "root filesystem is writable" in str(refused.value)


def test_a_sandbox_that_works_passes_quietly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The positive half, or the three above only prove it can refuse."""
    box = Sandbox(image="img", worktree=tmp_path)

    _preflight_saying(box, monkeypatch, exit_code=0, output="ran")


# --- both streams keep their own tail. Item 098 ---------------------------------------------------


def test_the_test_runners_summary_survives_a_noisy_stderr() -> None:
    """**Measured on `acme!9`, the first artefact Hullwork produced for another project.**

    Its test command is `cd backend && alembic upgrade head && pytest`. `alembic` logs to stderr,
    `pytest` summarises to stdout, and `stdout + stderr` puts the tail of *stderr* at the end — so
    every gate in that artefact stored twenty-six migration lines and not one line of pytest.
    `252 passed, 1 failed` was in the part that got dropped: the number the red-gate judge counts,
    the number `failing_lines` quotes, and the number a reviewer looks for.
    """
    from hullwork.sandbox.run import interleaved

    pytest_out = "\n".join(f"tests/test_{n}.py .." for n in range(400)) + "\n252 passed, 1 failed\n"
    alembic_err = "\n".join(
        f"INFO  [alembic.runtime.migration] Running upgrade {n:04d} -> {n + 1:04d}, …"
        for n in range(400)
    )

    stored = interleaved(pytest_out, alembic_err, keep=2_000)

    assert "252 passed, 1 failed" in stored, (
        "the runner's summary was dropped, which is the whole finding of item 098"
    )
    # And the other stream's tail is there too — the migrations are noise, not nothing: a suite that
    # printed only to stderr failed differently from one that printed a summary.
    assert "Running upgrade 0399" in stored
    assert "--- stdout ---" in stored and "--- stderr ---" in stored, "each stream is named"


def test_a_command_that_writes_to_one_stream_gets_no_labels() -> None:
    """A label over a lone body is noise, and most commands only write to one stream."""
    from hullwork.sandbox.run import interleaved

    stored = interleaved("904 passed in 61.26s\n", "")

    assert stored == "904 passed in 61.26s"
    assert "---" not in stored


def test_each_stream_is_bounded_on_its_own() -> None:
    """One stream flooding must not evict the other, which is what one shared budget did."""
    from hullwork.sandbox.run import interleaved

    stored = interleaved("x" * 50_000 + "\nSUMMARY", "y" * 50_000 + "\nWARNING", keep=1_000)

    assert "SUMMARY" in stored
    assert "WARNING" in stored
    assert stored.count("[earlier") == 2, "both tails were cut, and both said so"
    assert len(stored) < 3_000
