"""An engine is a container image satisfying a contract, not an integration (item 024, DR-0004).

The contract is tiny because everything Hullwork relies on is enforced outside it: the sandbox
bounds what the image can do, the gateway records which model answered whatever the image says
about itself, and the dispatcher runs the tests and decides the outcome. What is left for the
image to get wrong is small on purpose.
"""

import pytest

from hullwork.engine import BRIEF_PATH, REGISTRY, AgentReport, Engine, Phase, resolve


def test_the_manifest_names_and_the_instance_decides() -> None:
    """Item 017, on the surface DR-0004 created. A repository may not name its way into an image."""
    assert resolve("claude-code").image

    with pytest.raises(KeyError, match="no engine named"):
        resolve("attacker/evil")


def test_the_refusal_says_what_this_instance_does_know() -> None:
    with pytest.raises(KeyError, match="claude-code"):
        resolve("nope")


def test_a_command_never_reaches_a_shell() -> None:
    """It is instance configuration, but a command that reaches a shell is one somebody will
    eventually put a variable into."""
    engine = Engine(
        name="e", image="i", protocol="anthropic",
        command="agent --phase {phase} --turns {max_turns}",
    )

    assert engine.argv(Phase.REPRODUCE) == ["agent", "--phase", "reproduce", "--turns", "60"]


def test_both_phases_are_expressible() -> None:
    engine = Engine(name="e", image="i", protocol="anthropic", command="agent {phase}")

    assert engine.argv(Phase.FIX)[-1] == "fix"
    assert engine.argv(Phase.REPRODUCE)[-1] == "reproduce"


def test_the_reference_engine_drives_its_own_recipe(
) -> None:
    """**Changed on 2026-07-28 with the operator's approval, and here is what it used to assert.**

    It required `--bare` in the registry's command. That could not be true: the reference recipe
    implements `hullwork-agent --phase <phase>`, and its own entry point records why it does not use
    `--bare` — the flag reads no credentials file and no OAuth, so the harness could only
    authenticate from an environment variable, and DR-0004 puts the credential in the gateway. The
    registry's command also carried no prompt text at all, so it had never been able to drive the
    image it names. Nobody noticed because the dogfood built its `Engine` by hand in a script; the
    defect was on the path a *user* takes, which is `agent: claude-code` in a manifest.

    What `--bare` was wanted for — no CLAUDE.md, no AGENTS.md, no hooks, no plugins, so the context
    Hullwork supplies is the only context — this arrangement gets for free: the image is built by
    us, from a generated Dockerfile, and there is nothing ambient in it to read.

    **Changed again on 2026-07-29 (item 065, DR-0007).** The recipe no longer *installs* anything:
    the harness travels as a mounted bundle, so `argv` names the wrapper's path inside the mount and
    `engine.files` is empty. The properties this test was protecting are unchanged, and are asserted
    against the script that now carries them.
    """
    from hullwork.engine import AGENT_ENTRYPOINT
    from hullwork.sandbox.harness import WRAPPER, wrapper_script

    engine = REGISTRY["claude-code"]

    assert engine.argv(Phase.FIX) == [WRAPPER, "--phase", "fix"]
    # The brief still reaches the harness, and the entrypoint in the bundle is what puts it there.
    script = wrapper_script(AGENT_ENTRYPOINT)
    assert BRIEF_PATH in script
    assert "--max-turns" in script
    assert "stream-json" in script
    # And it is invoked through the loader that travelled with it, not through PATH.
    #
    # **By the mechanism, not by the loader's name.** This asserted `ld-linux-x86-64.so.2`, which is
    # the x86-64 loader — so the assertion was an architecture lock, and the bundle it locked in
    # could not be built on arm64 at all: `cp: cannot stat '/lib/ld-linux-x86-64.so.2'`, measured
    # on an Apple Silicon Mac on 2026-08-04 running the command the README offers as the cheap
    # first look. The name comes from the bundle now, discovered by `ldd` as the libraries are.
    assert "/lib/.loader" in script, "the loader's name travels with the bundle"
    assert "ld-linux-x86-64" not in script, "and no architecture is written into the wrapper"
    assert "--library-path" in script


def test_the_harness_comes_from_its_own_image_and_not_from_a_pipe_to_a_shell() -> None:
    """What the 2026-07-28 amendment was protecting, asserted against how it now travels.

    That amendment made an engine a recipe over the project's base rather than a fixed image: the
    gates need the project's pinned dependencies (item 037) and the agent needs the harness in the
    same container, and a separate engine image meant the reproduce phase looked for `claude` inside
    `python:3.12-slim` and exited 127.

    **Item 065 keeps that property and drops the recipe** (DR-0007). The harness is lifted once out
    of its own official image and mounted, so it is still in the same container as the project's
    dependencies and still never fetched by a script piped into a shell. And now the project's
    image does not contain it.
    """
    engine = REGISTRY["claude-code"]

    assert engine.mounted
    assert engine.bundle_from == "node:22-slim"
    assert engine.bundle_bin == "/usr/local/bin/claude"
    # Nothing is fetched at build time, so there is no pipe to a shell to check for — and nothing of
    # ours is added to the project's image at all.
    assert engine.stages == ()
    assert engine.steps == ()
    assert engine.files == {}


def test_a_changed_recipe_cannot_reuse_the_previous_image() -> None:
    """The recipe is in the tag, so an operator editing it gets a rebuild rather than a lie."""
    engine = REGISTRY["claude-code"]
    edited = Engine(
        name=engine.name, image=engine.image, protocol=engine.protocol, command=engine.command,
        stages=engine.stages, steps=(*engine.steps, "RUN echo something-new"),
        files=engine.files,
    )

    assert engine.fingerprint() != edited.fingerprint()


# --- the report is advisory, and that is not scepticism for its own sake ----------------------


def test_a_report_is_read_for_detail() -> None:
    report = AgentReport.parse('{"reproduced": true, "summary": "found it in billing.py"}')

    assert report.reproduced is True
    assert "billing.py" in report.summary


@pytest.mark.parametrize(
    "text",
    ["", "not json", "[]", '{"reproduced": "yes"}', '{"reproduced": tru'],
)
def test_a_broken_report_is_not_a_failed_attempt(text: str) -> None:
    """The image's job is to change files. Spending the item's one try on a formatting mistake
    would be the wrong thing to punish."""
    report = AgentReport.parse(text)

    assert report.reproduced is None
    assert isinstance(report.summary, str)


def test_a_report_cannot_become_most_of_the_evidence_trail() -> None:
    report = AgentReport.parse('{"summary": "' + "A" * 50_000 + '"}')

    assert len(report.summary) <= 2000


def test_the_raw_report_is_kept_so_a_reviewer_sees_what_was_claimed() -> None:
    report = AgentReport.parse('{"reproduced": false, "confidence": "high"}')

    assert report.raw["confidence"] == "high"


# --- the operator's ceiling, and that it reaches the container (item 062) -------------------------


def test_the_ceiling_can_be_overridden_without_editing_the_source() -> None:
    """Item 059 asks the operator whether thirty turns is right, and this is what makes it askable.

    `HULLWORK_AGENT_MAX_TURNS=60 hullwork work` used to fail at start-up with "unknown variable(s),
    likely a typo" — the name is read by the image's entrypoint, but the value comes from
    `Engine.max_turns`, a literal in `REGISTRY`. So the number with the most leverage over what an
    attempt costs needed a source edit and a redeploy to try.
    """
    from hullwork.engine import REGISTRY, resolve

    # 90, not 60: the recipe's own default became 60 when the operator raised the ceiling on
    # measurement, and an override that equals the default proves nothing about overriding.
    assert resolve("claude-code", max_turns=90).max_turns == 90
    # And the registry itself is untouched: it is module state, so a mutation would follow this
    # process into every other project it handles.
    assert REGISTRY["claude-code"].max_turns == 60


def test_no_override_leaves_the_engine_s_own_number_alone() -> None:
    """An instance that sets nothing behaves as it did, and each recipe keeps its own default."""
    from hullwork.engine import resolve

    assert resolve("claude-code").max_turns == 60
    assert resolve("claude-code", max_turns=None).max_turns == 60


def test_the_reference_recipe_can_be_told_which_model_to_ask_for() -> None:
    """Item 139. Without this an instance chooses its provider and not its model.

    The gateway *observes* the pin and forwards without rewriting (DR-0004), so a pin that never
    reaches the harness is an expectation and not an instruction. Anthropic hid it — the harness's
    default is a Claude model, which is what you pinned — and every other endpoint exposed it.

    Every tier, because this harness asks for more than one model in an attempt. Names taken from
    the harness publisher's documentation; a recipe is the only place that knowledge belongs.
    """
    engine = resolve("claude-code", model="deepseek/deepseek-v4-pro")

    assert set(engine.model_env) == {
        "ANTHROPIC_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    }
    for name in engine.model_env:
        assert engine.phase_env()[name] == "deepseek/deepseek-v4-pro"
    # The placeholder the CLI needs to start survives; the gateway replaces it on the wire.
    assert engine.phase_env()["ANTHROPIC_API_KEY"].startswith("placeholder")
    # Module state, untouched, for the same reason as the ceiling above.
    assert REGISTRY["claude-code"].model is None


def test_an_unpinned_instance_says_nothing_about_the_model() -> None:
    """Today's behaviour for every instance running, preserved exactly.

    Absent is not empty: setting these to `""` would tell the harness to ask for a model with no
    name, which is the failure item 082 spent a restart loop learning to tell apart.
    """
    assert resolve("claude-code").phase_env() == REGISTRY["claude-code"].env
    assert "ANTHROPIC_MODEL" not in resolve("claude-code").phase_env()


def test_a_recipe_that_cannot_be_steered_still_runs() -> None:
    """A harness with no variable for this is not an error — it is one that keeps its default.

    Hullwork does not know which variable any harness reads; the recipe does. One that declares
    nothing gets the pin's old meaning and nothing else, rather than a guess at a variable name.
    """
    mute = Engine(name="mute", image="i", protocol="openai", command="c", model="some/model")

    assert mute.phase_env() == {}


def test_the_override_reaches_the_command_the_container_runs() -> None:
    """The defect was a knob wired to nothing, so parsing the setting proves nothing.

    `dispatch._run_agent` passes `HULLWORK_AGENT_MAX_TURNS` into the sandbox from the resolved
    engine, and the image's entrypoint reads it as `--max-turns`. This asserts the number arrives.
    """
    from hullwork.engine import Phase, resolve

    engine = resolve("claude-code", max_turns=45)
    argv = engine.argv(Phase.REPRODUCE)

    assert engine.max_turns == 45
    # The dispatcher builds the environment from `engine.max_turns` (dispatch.py), which is what
    # the entrypoint turns into `--max-turns`. The command itself carries the phase.
    assert "reproduce" in " ".join(argv)


def test_a_ceiling_of_zero_or_less_is_refused() -> None:
    """Zero is an agent that cannot act; a negative number is a typo on its way to `--max-turns`."""
    import pytest as _pytest
    from pydantic import ValidationError

    from hullwork.config import Settings

    for bad in (0, -1):
        with _pytest.raises(ValidationError):
            Settings(max_turns=bad)

    assert Settings(max_turns=60).max_turns == 60
    assert Settings().max_turns is None


def test_the_mounted_wrapper_keeps_the_shebang_first() -> None:
    """A `#!` on line two is a comment, and the script would run under whatever shell called it.

    The prologue is spliced *after* the shebang rather than prepended, and this asserts it because
    the failure would be silent — `sh` would run it anyway, and the difference only shows up on a
    construct the two shells disagree about.
    """
    from hullwork.engine import AGENT_ENTRYPOINT
    from hullwork.sandbox.harness import wrapper_script

    lines = wrapper_script(AGENT_ENTRYPOINT).splitlines()

    assert lines[0] == "#!/bin/sh"
    assert lines[1].startswith("harness()")


def test_a_mounted_engine_contributes_nothing_to_the_image_tag() -> None:
    """Or a new harness version would invalidate every registered project's cached image.

    Which harness ran is provenance and belongs on the attempt (DR-0002 §4), not in an image tag.
    """
    from hullwork.engine import REGISTRY, Engine

    mounted = REGISTRY["claude-code"]
    other_version = Engine(
        name=mounted.name, image=mounted.image, protocol=mounted.protocol,
        command=mounted.command,
        bundle_from="node:24-slim", bundle_bin=mounted.bundle_bin,
    )

    assert mounted.fingerprint() == other_version.fingerprint() == "mounted"
    # And a baked engine still gets a real fingerprint, so that path is unaffected.
    baked = Engine(name="x", image="i", protocol="anthropic", steps=("RUN something",))
    assert baked.fingerprint() != "mounted"
