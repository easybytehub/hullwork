"""What an agent is, from Hullwork's side of the wall.

Item 024, reshaped by DR-0004. An engine is **not** an integration: it is a container image that
satisfies a contract, because everything Hullwork actually relies on is enforced outside it.

* The sandbox bounds what it can do (item 023).
* The gateway records what model answered, whatever the image chooses to say about itself
  (item 033).
* The dispatcher runs the tests and decides the outcome, so the agent's own account of how it went
  is read for detail and trusted for nothing (item 025).

That is why the contract is tiny. Anyone can wrap Aider, Codex CLI, OpenHands or a shell script in
twenty lines and satisfy it, and Hullwork stays out of the business of maintaining N integrations.

**Item 017 is what makes this safe and it is untouched.** The manifest *names* an engine from what
the instance knows; it never supplies one. Registering an engine is an operator action. So
agnosticism belongs to the person running Hullwork, and never to the repository being watched.
"""

import hashlib
import json
import logging
import shlex
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Literal

from hullwork.sandbox.harness import WRAPPER

log = logging.getLogger(__name__)

#: Where the contract puts things inside the container. Fixed, because an image cannot negotiate.
WORKTREE = "/work"
BRIEF_PATH = "/hullwork/brief.md"
REPORT_PATH = "/hullwork/report.json"


class Phase(StrEnum):
    """Which half of the red-green sequence the image is being asked for."""

    REPRODUCE = "reproduce"
    FIX = "fix"


@dataclass(frozen=True)
class Engine:
    """One named engine: a recipe for installing a harness, and how to ask it for a phase.

    `command` is a template owned by **the instance**, not by any repository. It is the one place
    a string becomes an argument list, and it is filled from values this side controls.

    **A recipe rather than a bare image, decided by the operator on 2026-07-28**, and it amends
    DR-0004's third part. The reason is a measurement: the gates need the *project's* image — its
    pinned dependencies, which is the whole of item 037 — and the agent needs the harness. There is
    one container per attempt, so a fixed engine image meant the reproduce phase looked for `claude`
    inside `python:3.12-slim` and exited 127. Two containers over one worktree was the alternative
    and it costs more than it looks: the harness could then not run the project's suite during its
    own phase, which is exactly what the reference prompt tells it to do before finishing.

    So the harness is installed **on top of the base the manifest declares**. `BASE_IMAGES` keeps
    meaning what it says, the agent sees the same environment the gate will run in, and what an
    operator registers is a recipe instead of an image name.
    """

    name: str
    #: The reference image, published for anyone who wants to run the harness by hand. The
    #: dispatcher does not run it — it builds from `stages` and `steps` onto the project's base —
    #: and it is recorded in the evidence trail as the provenance of the recipe.
    image: str
    #: Which protocol family this harness speaks, and therefore **which endpoints can serve it**.
    #: Item 134.
    #:
    #: The gateway forwards rather than translates — it terminates the connection, injects the
    #: credential, observes and passes the same request on — so the harness, not the operator, fixes
    #: the shape of every model call. DR-0004's promise is *any provider with an API key*, and the
    #: qualifier it never wrote down is *that serves this family*: with `anthropic` here, Kimi,
    #: DeepSeek, OpenRouter, Bedrock and Vertex all work through their compatible routes, and
    #: OpenAI's own endpoint does not.
    #:
    #: A field rather than a comment because three things need the answer and none of them can
    #: derive it: `doctor` reports it before anybody hits the wall, the mismatch diagnosis names it,
    #: and the operator registering a second harness has to be asked for it.
    #:
    #: **No default, deliberately.** Defaulting to `anthropic` would let a harness that speaks
    #: something else be registered in silence and fail as a 404 four layers down — which is the
    #: exact failure this field exists to make readable. Whoever adds a recipe knows what it speaks;
    #: this is the one question they cannot be allowed to skip.
    protocol: Literal["anthropic", "openai"]
    #: Given to the container as its command. `{phase}` is the only substitution.
    command: str = "hullwork-agent --phase {phase}"
    #: Dockerfile lines placed **before** the project's `FROM`, for auxiliary build stages. This is
    #: how a harness arrives without `curl | bash`: copy it out of its own official image.
    stages: tuple[str, ...] = ()
    #: Dockerfile lines placed **after** the project's `FROM` and **before** its dependencies, so
    #: the harness layer is cached across every lockfile change.
    steps: tuple[str, ...] = ()
    #: Files the recipe needs in the build context, by name. Contents rather than paths: the wheel
    #: has to carry them, and `images/` is not packaged.
    files: dict[str, str] = field(default_factory=dict)
    #: Environment the image needs beyond the base URLs the sandbox always injects.
    env: dict[str, str] = field(default_factory=dict)
    #: The variables **this harness** reads to decide which model to ask for. Item 139.
    #:
    #: **Without this, an instance can choose its provider but not its model.**
    #: `HULLWORK_MODEL_ENDPOINT` picks who answers and `HULLWORK_MODEL_KEY` pays for it, but
    #: `HULLWORK_MODEL_NAME` was only ever read by the gateway, which *compares* it to what came
    #: back (DR-0002) and forwards without rewriting. So the harness asked for whatever it defaults
    #: to. Pointed at Anthropic that is invisible — the default is the model you pinned. Pointed at
    #: any other provider it is the whole problem: measured on 2026-08-04 against OpenRouter, the
    #: request would have named a Claude model, been served one, and been recorded as a violation
    #: of a pin that never reached anyone, while billing at that model's rates.
    #:
    #: A tuple rather than one name because a harness may ask for several tiers in one attempt —
    #: `claude-code` has a cheap model for subtasks — and every one of them has to resolve to
    #: something the endpoint serves. Naming them all here is also what makes `model_allowed`
    #: (item 137) the answer to a provider that aliases, rather than a workaround for us.
    #:
    #: **Declared by the recipe, never by Hullwork.** DR-0004 keeps provider knowledge out of this
    #: repository; which variable a harness reads is a fact about that harness, and whoever writes
    #: the recipe is the only party who knows it. Empty means a harness that cannot be told, and
    #: then the pin stays what it always was: an expectation the seal checks.
    model_env: tuple[str, ...] = ()
    #: The model this instance pinned, filled in by `resolve` from `HULLWORK_MODEL_NAME`. Item 139.
    #: Run-time configuration like `max_turns`, so `fingerprint` ignores it and switching model does
    #: not invalidate a cached image.
    model: str | None = None
    #: How many turns the harness may take. The only real bound on what a run can spend, since a
    #: harness that loops is not something the sandbox can distinguish from one that is working.
    #:
    #: **60, raised from 30 on measurement rather than on feel.** At 30 the ceiling was reached
    #: three times out of three, each reported as `stop_reason: tool_use` — a run cut off mid-work,
    #: which item 059 then correctly refuses to call `not-reproducible`. At 60 the same work
    #: finished in 38 with `end_turn`. A ceiling the real workload hits every time is not a safety
    #: bound, it is a wall: it spends the whole cost of an attempt and buys no verdict.
    max_turns: int = 60
    #: Where to lift the harness out of, and what to lift, for a **mounted** bundle (item 065).
    #:
    #: When set, the harness does not enter the project's image at all: it is extracted once from
    #: this image, along with its dynamic loader and libraries, and mounted read-only into the
    #: agent's phases. That is what makes the project's base image irrelevant — a glibc binary runs
    #: on musl through its own loader, measured on Alpine — and what stops Hullwork's software from
    #: being part of anybody's image.
    bundle_from: str | None = None
    bundle_bin: str | None = None
    #: How the harness gets into `bundle_from` before it is lifted out. Run once, at bundle build
    #: time, inside the harness's own official image — which is what keeps this off `curl | bash`
    #: territory: the command is ours, the image is the publisher's, and neither is the project's.
    bundle_install: str = ""
    #: The command line the wrapper `exec`s, with `{harness}` standing for the mounted executable.
    #: Separate from `command`, which is what the *container* is given: `command` invokes the
    #: wrapper, the wrapper invokes this through the loader.
    bundle_invocation: str = ""

    @property
    def mounted(self) -> bool:
        """Whether this engine travels as a bundle rather than as image layers."""
        return bool(self.bundle_from and self.bundle_bin)

    def fingerprint(self) -> str:
        """What this recipe contributes to the image tag.

        **A mounted engine contributes nothing** (item 065), and that is the point rather than an
        optimisation: it puts no layer in the image, so a new harness version must not invalidate
        every registered project's cached image. Which harness actually ran is provenance, and
        provenance belongs on the attempt.
        """
        if self.mounted:
            return "mounted"
        digest = hashlib.sha256()
        for part in (self.name, self.command, *self.stages, *self.steps):
            digest.update(part.encode())
            digest.update(b"\0")
        for path in sorted(self.files):
            digest.update(path.encode())
            digest.update(self.files[path].encode())
        return digest.hexdigest()

    def phase_env(self) -> dict[str, str]:
        """Everything the container is given beyond the base URLs the sandbox injects. Item 139.

        One function rather than two spreads at the call site, because the model variables and the
        harness's own are the same kind of thing — configuration this side owns — and a caller that
        merges one and forgets the other is exactly the defect this item is about.

        With nothing pinned, this is `env` and the harness keeps its own default. That is today's
        behaviour on every instance running, and it is correct for the one provider whose default
        *is* the pinned model.
        """
        if not (self.model and self.model_env):
            return dict(self.env)
        return {**self.env, **dict.fromkeys(self.model_env, self.model)}

    def argv(self, phase: Phase) -> list[str]:
        """The command for one phase, as an argument list.

        `shlex.split` rather than a shell: this string is instance configuration, but only known
        values are interpolated and there is no reason for a shell to be involved. A command that
        reaches a shell is a command somebody will eventually put a variable into.
        """
        rendered = self.command.format(
            phase=phase.value, max_turns=self.max_turns, brief=BRIEF_PATH, worktree=WORKTREE
        )
        return shlex.split(rendered)


@dataclass(frozen=True)
class AgentReport:
    """What the image says about its own run. **Advisory.**

    Read for detail and trusted for nothing, which is not scepticism for its own sake: measured on
    2026-07-27, Claude Code returned `subtype: success` together with `is_error: true` and an exit
    code that agreed with neither, and produced a response whose model was the literal
    `<synthetic>` — an answer generated locally with no model call at all. The dispatcher's own
    test runs decide the outcome; this is colour for the evidence trail.
    """

    reproduced: bool | None = None
    summary: str = ""
    notes: str = ""
    #: Whatever the image chose to send. Kept whole so a reviewer can see what it claimed.
    raw: dict[str, object] = field(default_factory=dict)

    @classmethod
    def parse(cls, text: str) -> "AgentReport":
        """Read a report, tolerating every way an image can get it wrong.

        A missing, empty, truncated or nonsense report is **not** a failure of the run. The image's
        job is to change files; the report is a courtesy, and treating a malformed courtesy as a
        failed attempt would spend the item's one try on a formatting mistake.
        """
        try:
            payload = json.loads(text)
        except (ValueError, TypeError):
            return cls(notes="the image wrote no readable report")
        if not isinstance(payload, dict):
            return cls(notes="the image's report was not an object")
        reproduced = payload.get("reproduced")
        return cls(
            reproduced=reproduced if isinstance(reproduced, bool) else None,
            summary=str(payload.get("summary", ""))[:2000],
            notes=str(payload.get("notes", ""))[:2000],
            raw=payload,
        )


#: The phase entry point the reference recipe installs. It is data here rather than a file because
#: the wheel has to carry it and `images/` is not packaged.
#:
#: The prompts are specific on purpose. Measured: the first version said "write a test under the
#: project's test directory" and a real run spent seven turns exploring and produced nothing the
#: dispatcher would accept — an agent asked vaguely does vague work, and here that costs the item
#: its one attempt.
#:
#: `claude -p`, not `claude --bare -p`. `--bare` reads no credentials file and no OAuth, so it can
#: only authenticate from an environment variable — and DR-0004 puts the credential in the gateway,
#: not in here. What `--bare` was wanted for is ambient configuration, and this arrangement gets
#: that for nothing anyway: the container is built by us, so there is no CLAUDE.md, no AGENTS.md, no
#: hooks and no plugins in it to read.
#:
#: **There used to be a second copy of this**, in `images/claude-code/`, kept as the standalone form
#: of the same recipe while the two fronts were separate. Deleted 2026-08-05 after measuring the
#: drift: 39 lines against this one's 61, missing the `harness` indirection for the mounted bundle
#: (item 065), the per-item test filename (item 094) and the lint work (item 064). So anybody who
#: built from that directory got a harness that wrote a fixed `test_regression.py` — the defect item
#: 094 exists to prevent, where two attempts overwrite each other's evidence. A duplicate nothing
#: builds and no test covers does not stay in sync; it waits in a public repository to mislead.
#: This is the only copy now, and the wheel carries it as data.
#: The prologue a **baked** recipe prepends: the harness is on `PATH`, so the function is a
#: passthrough.
#: A function rather than a variable because the mounted form is a loader plus two paths plus the
#: executable, and `exec "$VAR"` would run a file with spaces in its name while `exec $VAR` would be
#: word-splitting somebody's path.
BAKED_PROLOGUE = "harness() { exec claude \"$@\"; }\n"

AGENT_ENTRYPOINT = r"""#!/bin/sh
# The contract: brief in at /hullwork/brief.md, changed files out in /work, report optional.
#
# `harness` is a shell function the prologue defines — `claude` on PATH when the recipe is baked
# into
# the image, or the mounted bundle invoked through its own dynamic loader (item 065). The phase
# logic
# below does not know or care which.
set -eu
PHASE="${HULLWORK_AGENT_PHASE:?}"
TEST_PATH="${HULLWORK_AGENT_TEST_PATH:-tests}"
# Named per item by the dispatcher (item 094). The default is only reached by an image older than
# the dispatcher driving it, and a fixed name is what this replaces — two attempts writing the same
# path, the second overwriting evidence for a fix already merged.
TEST_FILE="${HULLWORK_AGENT_TEST_FILE:-test_regression.py}"

# Item 064: the test the agent writes has to pass the project's own lint gate, and nothing told it
# so. Measured twice on this repository: both attempts that reached the lint gate failed there, on
# the same diagnostic, in the file the agent had just written — `Statement is unreachable`, which is
# easy to produce when constructing a test that must fail. The gate is right and is not relaxed;
# what changes is that the agent is told what it will be judged by.
#
# Absent when the manifest declares no lint gate, in which case the sentence is not added at all
# rather than mentioning a command nobody will run.
LINT_ASK=""
if [ -n "${HULLWORK_AGENT_LINT:-}" ]; then
  LINT_ASK="

Your file must also pass this project's own lint command, which is a gate later in this run:
  ${HULLWORK_AGENT_LINT}
Run it on what you wrote before you finish, and fix what it says."
fi

case "$PHASE" in
  reproduce)
    ASK="Read the brief you were given: it describes a real production error, with the failing line
and the values involved.

Your ONLY deliverable is one new test file at exactly '${TEST_PATH}/${TEST_FILE}'. Write it
with the Write tool. It must FAIL against the code as it stands right now, because it reproduces the
reported bug — run the project's tests to confirm it fails before you finish.

Do not modify any existing file. Do not fix anything. If you genuinely cannot construct a failing
test from the evidence, write no file and say so: that is a correct and useful answer.${LINT_ASK}"
    ;;
  fix)
    ASK="The test at '${TEST_PATH}/${TEST_FILE}' reproduces a real bug and currently fails.

Make it pass with the smallest change to the source code. Do NOT modify the test — it is the
evidence, and a test the fix was allowed to edit proves nothing. Run the whole suite before you
finish: every other test must still pass."
    ;;
  *) echo "unknown phase $PHASE" >&2; exit 2 ;;
esac

harness -p "$ASK" \
  --append-system-prompt-file /hullwork/brief.md \
  --output-format stream-json --verbose \
  --max-turns "${HULLWORK_AGENT_MAX_TURNS:-60}" \
  ${HULLWORK_MODEL:+--model "$HULLWORK_MODEL"} \
  --dangerously-skip-permissions
"""

#: Engines this instance knows. An operator adds to it; a repository never does.
#:
#: `claude-code` is the reference recipe and the first implementation of the contract, not a
#: privileged path. Anyone can wrap Aider, Codex CLI or a shell script in the same shape.
REGISTRY: dict[str, Engine] = {
    "claude-code": Engine(
        name="claude-code",
        # It calls `/v1/messages`. Measured every day: it is the only path this instance's gateway
        # has ever been asked to forward.
        protocol="anthropic",
        # Published for anyone who wants to run the harness by hand, and recorded in the evidence
        # trail as the provenance of the recipe. The dispatcher does not run it.
        image="ghcr.io/easybyte/hullwork-agent-claude:dev",
        # What the *container* is given. It invokes the wrapper that travelled in the bundle.
        command=f"{WRAPPER} --phase {{phase}}",
        # **Mounted, not baked** (item 065, DR-0007 part 1). The harness is lifted once out of the
        # image below — the executable, its dynamic loader and its libraries — and mounted read-only
        # into the agent's phases. Measured in production: a glibc binary invoked through its own
        # loader
        # starts in stock Alpine, so the project's base image and its libc stop mattering, and
        # nothing
        # of Hullwork's is baked into anybody's image.
        bundle_from="node:22-slim",
        bundle_bin="/usr/local/bin/claude",
        bundle_install="npm install -g @anthropic-ai/claude-code@latest && npm cache clean --force",
        # The CLI refuses to start without something here, and the gateway replaces whatever is sent
        # — so the value is irrelevant and a placeholder beats a real key. In `env` and never as a
        # Dockerfile `ENV`, because that reached the gate phases too (item 060).
        env={"ANTHROPIC_API_KEY": "placeholder-the-gateway-holds-the-real-one"},
        # What this CLI reads to choose a model, and all four because it asks for tiers rather than
        # one name: a cheap model for subtasks, a strong one for the work. Against Anthropic the
        # unset defaults are Claude models and nobody notices; against any other endpoint each tier
        # has to resolve to something that endpoint serves, or the attempt spends its turns on 404s.
        # Taken from the harness publisher's own documentation of these variables, not guessed.
        model_env=(
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        ),
        max_turns=60,
    ),
}


def resolve(name: str, *, max_turns: int | None = None, model: str | None = None) -> Engine:
    """The engine this instance knows by that name, or a refusal that says what it does know.

    The manifest names; the instance decides what the name means. A name this build has never
    heard of is an error here rather than at parse time, because the parser cannot know what the
    operator has registered — and guessing would let a repository name its way into something.

    `max_turns` is the operator's override (item 062), and a *parameter* rather than a lookup in
    here: `REGISTRY` is module state, so mutating an engine in place would change it for every
    project this process touches afterwards, and reading `Settings` from here would make `resolve`
    untestable without an environment. `None` leaves the engine's own number alone, so each recipe
    keeps a default that suits it.

    `model` is `HULLWORK_MODEL_NAME`, and it arrives the same way and for the same reasons
    (item 139). It reaches the harness only if the recipe declared which variables to put it in;
    a recipe that did not is a harness this instance can point at a provider but not steer, and
    the pin goes on meaning what it meant before — an expectation the seal checks.
    """
    engine = REGISTRY.get(name)
    if engine is None:
        known = ", ".join(sorted(REGISTRY)) or "none"
        msg = f"no engine named {name!r} is registered on this instance (known: {known})"
        raise KeyError(msg)
    if max_turns is not None and max_turns != engine.max_turns:
        # A copy, never a mutation of the registry entry. `fingerprint()` deliberately ignores this:
        # the ceiling is passed to the container at run time and is not baked into the image, so
        # changing it must not invalidate an image that is otherwise identical.
        engine = replace(engine, max_turns=max_turns)
    if model is not None and model != engine.model:
        # Same copy-never-mutate rule, and `fingerprint()` ignores this for the same reason: the
        # model is handed to the container at run time, so changing it must not rebuild an image.
        engine = replace(engine, model=model)
    return engine
