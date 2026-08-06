"""The files a real deployment needs, written for you. Item 115.

**The asymmetry this exists to remove.** Connecting a *project* is one command since item 107:
`hullwork propose` reads a repository's own CI configuration and writes its manifest. Standing up
the *instance* that would run it is `deployment-notes.md`, which is 820 lines and grew every time
something surprised us. That document is the honest record of what a deployment costs and it is not
an installer — the roadmap has said so since it was written, in the first obstacle of the first
section, because an instance nobody can install cannot be trusted, used or judged by anybody.

**A scaffold, not a wizard.** Nothing here is interactive, nothing is probed over the network, and
nothing is guessed that would be wrong more often than right. It writes two files and then says,
in order, what only a person can do.

**And it never writes a credential.** Every one of them is minted by a human in a web interface,
once; a token typed into a terminal is a token in a shell history. What the environment file
carries is *names*, *comments* and *empty values* — including a sentence per credential saying
where it comes from and what scope it needs.

The three rules the generated compose file encodes, each of which cost a measured failure to learn
and none of which a stranger should have to rediscover:

* **The two programs are separate and their credentials are disjoint** (DR-0009, spec M2 §1). The
  receiver answers webhooks and holds no code credential — it refuses to start holding one. The
  dispatcher holds it, mounts the Docker socket, and **listens on nothing**: that is the property
  that makes it safe for it to be able to push, not the socket.
* **The dispatcher does not migrate.** The image's entrypoint runs `alembic upgrade head`; the
  receiver owns the schema (item 076) and two processes migrating one database race each other.
* **`stop_grace_period` is twenty minutes** (item 097). The signal handler honours a stop *between
  turns* and never mid-attempt, so the default ten seconds kills it before it can release its lease
  — measured, and it left an orphaned gateway, a network and three volumes behind.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

#: What the scaffold writes. Two files, and neither of them is a secret.
COMPOSE_FILE = "docker-compose.yml"
ENVIRONMENT_FILE = "deploy.env"

#: The uid the image runs as, and therefore the group that has to be able to read `deploy.env` for
#: the deployment check to run at all. It is `useradd --uid 10001 hullwork` in the `Dockerfile`, and
#: the two are asserted equal by a test rather than trusted to stay in step — a drift here is silent
#: and only shows up as a check reporting `unknown` on somebody else's machine.
CONTAINER_USER_ID = 10001

#: Where the daemon's socket lives, and where its group number is read from rather than guessed.
DOCKER_SOCKET = "/var/run/docker.sock"


#: How to read the socket's group by hand. **GNU `stat`, unconditionally**, and that is the answer
#: rather than an oversight: a group number for `group_add` is only meaningful on the Linux host
#: that will run the dispatcher, so it is always read there and never on the machine `init` happened
#: to run on. A stranger on macOS in 2026-08-04 got an error from this, because `-c` is GNU and `-f`
#: is BSD — but the fix is not a second flavour of the command. It is saying that macOS cannot run
#: this half at all, which `write` now does.
STAT_GROUP = f"stat -c %g {DOCKER_SOCKET}"


def docker_socket_group(socket: str = DOCKER_SOCKET) -> str | None:
    """The gid that owns the Docker socket, or `None` when it cannot be read.

    **Read, not defaulted.** The socket is `root:docker 0660`, so mounting it is not enough: a
    container whose user is not in that group finds a client that works and a daemon that does not
    answer, and `hullwork doctor` exists partly to tell those two apart (item 074). The number
    differs between distributions — 999 on Debian, 130 elsewhere, whatever `groupadd` picked on a
    host somebody built by hand — so a scaffold that writes a constant writes a wrong one.

    `None` where the socket is absent, which is the ordinary case when the scaffold is run on a
    laptop for a deployment that will happen elsewhere. The generated file says so rather than
    filling in a number from this machine that means nothing on that one.
    """
    try:
        return str(os.stat(socket).st_gid)
    except OSError:
        return None


class Reach(StrEnum):
    """Which half of Hullwork a setting is passed to. Item 145.

    **The two halves get different sets, and the difference is the product.** The receiver must
    never receive `HULLWORK_FORGE_CODE_TOKEN` — it refuses to start holding one that can push
    (item 032) — so a generator that handed every setting to both services would undo DR-0009's
    split while looking tidier than the hand-written file it replaced.
    """

    BOTH = "both"
    RECEIVER = "receiver"
    DISPATCHER = "dispatcher"
    #: Read at deployment time and never passed into a container: the two paths of item 144 name
    #: files on the host, and a container told about the host's filesystem learns nothing.
    NEITHER = "neither"


#: Every field of `Settings`, and which half needs it.
#:
#: **This mapping is the item.** The scaffold used to be a string literal enumerating variables by
#: hand, and a literal has no relationship to the model it mirrors: measured on 2026-08-04, it named
#: 16 of 35, so nineteen settings — every one added by items 133, 137 and 144 — could not reach a
#: container in a deployment written by our own command. That was not a mistake on two hosts. It
#: shipped as the default.
#:
#: `test_every_setting_is_classified` fails when a field is missing here, which is what makes the
#: omission impossible rather than merely visible. Adding a setting means deciding where it goes.
REACH: dict[str, Reach] = {
    # Both halves log, and both are the same instance on the same database.
    "log_level": Reach.BOTH,
    "log_format": Reach.BOTH,
    "instance": Reach.BOTH,
    "database_url": Reach.BOTH,
    "error_dsn": Reach.BOTH,
    # Both, because both programs crash. The receiver is where a stranger's first failure happens
    # and the dispatcher is where the long-running one does; hearing from only one would make every
    # measurement of *where Hullwork breaks* an artefact of which half we listened to.
    "upstream_dsn": Reach.BOTH,
    "telemetry": Reach.BOTH,
    "environment": Reach.BOTH,
    "release": Reach.BOTH,
    # The receiver builds the webhook URLs it hands out, and answers on them.
    "base_url": Reach.RECEIVER,
    "sweep_interval_seconds": Reach.RECEIVER,
    "forge_recheck_seconds": Reach.RECEIVER,
    # The forge both halves read from, and the tracker only the receiver enriches from.
    "forge_url": Reach.BOTH,
    "forge_token": Reach.BOTH,
    "forge_kind": Reach.BOTH,
    # All three to both, and not by symmetry: `work.eligible` is handed `tracker_configured`, so a
    # dispatcher that cannot see these decides that no item is owed enrichment and attempts items
    # the receiver was still going to give frames to (item 100). The hand-written compose already
    # passed them to both; this records why.
    "tracker_url": Reach.BOTH,
    "tracker_token": Reach.BOTH,
    "tracker_org": Reach.BOTH,
    # **The one line that only exists on one side.** DR-0009, and the receiver refuses to start if
    # it finds it.
    "forge_code_token": Reach.DISPATCHER,
    # The model route: only the half that runs attempts talks to a provider.
    "model_endpoint": Reach.DISPATCHER,
    "model_auth_style": Reach.DISPATCHER,
    "model_key": Reach.DISPATCHER,
    "model_credentials_file": Reach.DISPATCHER,
    "max_turns": Reach.DISPATCHER,
    # The sandbox's own bounds, enforced where the sandbox is built.
    "allowed_base_images": Reach.DISPATCHER,
    "allowed_packages": Reach.DISPATCHER,
    "build_size_limit_gib": Reach.DISPATCHER,
    # Policy: enforced by the dispatcher, **rendered by the receiver**. The page shows what this
    # instance allows (items 136, 137, 143), so both halves need to know — one to obey, one to say.
    "model_name": Reach.BOTH,
    "model_allowed": Reach.BOTH,
    "max_attempt_tokens": Reach.BOTH,
    "model_price_input": Reach.BOTH,
    "model_price_output": Reach.BOTH,
    "model_price_cache_write": Reach.BOTH,
    "model_price_cache_read": Reach.BOTH,
    "model_price_currency": Reach.BOTH,
    # Paths on the host, for item 144's check. Named in the environment file and mounted, never
    # passed as configuration to a container that cannot see the host's filesystem.
    # **`BOTH`, and they used to be `NEITHER`** — see `DEPLOYMENT_MOUNT`. `doctor` runs inside a
    # container, in either half, and its own advice tells you to run it in the dispatcher too, so
    # both need to know where the deployment's files are mounted.
    "deployment_env_file": Reach.BOTH,
    "deployment_compose_file": Reach.BOTH,
}

#: Values the compose fixes rather than passing through, because the container's answer differs from
#: the host's. The path inside is the volume; the one in the environment file is the same file seen
#: from the other side of the mount.
#: Where the deployment's own two files are readable **from inside a container**, which is where
#: `doctor` runs. Item 144 built a check comparing the variables a compose file assigns against
#: those an environment file sets, and its item records that it had never executed once. This is why
#: it still had not: both paths were classified `Reach.NEITHER`, on the reasoning that a container
#: told about the host's filesystem learns nothing — true, and the conclusion drawn was wrong. The
#: files were never mounted, so the check had nothing to read, and `environment_gaps` reported an
#: absent file, which item 144 had just taught it to say out loud.
#:
#: So both halves ship together: mounted read-only by `compose`, and named here. Found on 2026-08-04
#: by a stranger who noticed that the check whose docstring says it *"would have caught every defect
#: of 2026-08-04"* was switched off by default in a deployment this project's own command writes.
DEPLOYMENT_MOUNT = "/deployment"

_FIXED: dict[str, str] = {
    "database_url": "sqlite:////data/hullwork.db",
    "deployment_env_file": f"{DEPLOYMENT_MOUNT}/{ENVIRONMENT_FILE}",
    "deployment_compose_file": f"{DEPLOYMENT_MOUNT}/{COMPOSE_FILE}",
}

#: A sentence for the settings that had one nowhere. Measured on 2026-08-04: the generated
#: environment file promises that `deployment-notes.md` explains each, and six names had **zero**
#: mentions across `docs/` and the README — two of them the ones `doctor`'s own last check tells you
#: to set. `config.py` was the stated fallback and `log_level` had no comment there either, so all
#: three promises failed for one variable.
#:
#: Here rather than in the notes because this file is generated: a sentence beside the name
#: explains cannot drift from the model the way an 800-line guide does. One line each — this is
#: where a setting is *discovered*, not where it is documented in full.
_ONE_LINE: dict[str, str] = {
    "environment": "which deployment this is, on every error report: production, staging, …",
    "log_level": "DEBUG | INFO | WARNING | ERROR | CRITICAL. DEBUG prints every phase's command.",
    "forge_recheck_seconds": (
        "how stale a forge verdict may get before `status` re-asks. 0 asks every time."
    ),
    "tracker_org": "your tracker's organisation slug — the one before the project in its URLs.",
    "deployment_env_file": (
        "this file, as the container sees it — `doctor` compares it against the compose file and "
        "cannot without both. Set for you in the compose; override only if you move them."
    ),
    "deployment_compose_file": "the compose file, likewise. Same check, its other half.",
}

#: Settings whose default in the compose is not empty, because empty would mean *not configured* and
#: these have a working value that an operator should have to opt out of rather than into.
_DEFAULTS: dict[str, str] = {
    "base_url": "http://127.0.0.1:8000",
    "log_format": "json",
    "instance": "default",
    "model_endpoint": "https://api.anthropic.com",
    "model_auth_style": "bearer",
    "model_price_currency": "USD",
}


def belongs_to_one_half(variable: str) -> Reach | None:
    """Which half a `HULLWORK_*` variable is *only* for, or `None` if both halves read it.

    Exported for `doctor`, which needs the same answer this module already holds and had a single
    hardcoded exception instead. Item 144, 2026-08-05: with the deployment check finally armed, the
    receiver reported four of the dispatcher's variables as `BROKEN` — assigned in `deploy.env` and
    absent from this process, which is exactly how it is meant to be — and `hullwork doctor` exited
    1 on a correct instance. A signal that is permanently on is not a signal (item 073).

    The reach map is the right authority because it is the same one that writes the compose file: if
    these two disagree, one of them is wrong, and a test asserts they cannot.
    """
    for name, reach in REACH.items():
        if f"HULLWORK_{name.upper()}" == variable:
            return None if reach is Reach.BOTH else reach
    return None


def environment_block(reach: Reach, *, indent: str = "      ") -> str:
    """The `environment:` lines one service gets, generated from `Settings`. Item 145.

    Alphabetical, so a regenerated file diffs cleanly against the one it replaces and a reviewer
    sees only what changed. No commentary: every one of these already carries its reasoning in
    `config.py`, and a generated file that repeats prose goes stale in two places instead of one.
    """
    wanted = sorted(
        name
        for name, where in REACH.items()
        if where is Reach.BOTH or where is reach
    )
    lines = []
    for name in wanted:
        variable = f"HULLWORK_{name.upper()}"
        if name in _FIXED:
            lines.append(f'{indent}{variable}: "{_FIXED[name]}"')
        else:
            lines.append(f'{indent}{variable}: "${{{variable}:-{_DEFAULTS.get(name, "")}}}"')
    return "\n".join(lines)


def compose(*, docker_gid: str | None) -> str:
    """The deployment's compose file: two programs, disjoint credentials, one database."""
    gid = docker_gid or "REPLACE-ME"
    unknown = "" if docker_gid else (
        "\n      # This host had no Docker socket to read the group from, so the number\n"
        "      # above is a placeholder. On the machine that will run this:\n"
        f"      #     {STAT_GROUP}\n"
        "      # Getting it wrong looks like a daemon that does not answer."
    )
    receiver_env = environment_block(Reach.RECEIVER)
    dispatcher_env = environment_block(Reach.DISPATCHER)
    return f"""# Hullwork, as a real deployment. Written by `hullwork init`.
#
# Two programs, and the split is the product rather than a precaution (DR-0009, spec M2 §1):
#
#   * **api** answers your error tracker's webhooks. It holds a credential that can file issues and
#     provably not one that can push — it refuses to start if it finds one.
#   * **dispatcher** attempts fixes. It holds the code credential and the Docker socket, and it
#     **listens on nothing**. That is what makes it safe for it to be able to push.
#
# Start it with both files loaded, in this order:
#
#     set -a; . ./{ENVIRONMENT_FILE}; set +a; docker compose up -d --build
#
# `docker compose up` on its own gives you ingest, deduplication, triage and issues. It does not
# attempt fixes and no setting here turns that on: that is `autofix.agent` in each project's own
# `hullwork.yml`, plus the credentials below.

services:
  api:
    build:
      # **Where the source is, and it is not here** (item 127). This directory is your deployment,
      # and `hullwork init` asks that it not be the checkout — a clone already carries a
      # `docker-compose.yml` of its own, which `init` would keep. So the context is a variable, and
      # `.` only works if you ignored that advice.
      context: ${{BUILD_SOURCE:-.}}
      args:
        # Empty by default: a self-hosted tool should not install an error-reporting SDK you did
        # not ask for. Set `BUILD_EXTRAS=[telemetry]` when you set HULLWORK_ERROR_DSN, or the
        # receiver refuses to start — it will not pretend to be watched when it is not.
        EXTRAS: "${{BUILD_EXTRAS:-}}"
    # **Tagged with the instance** (item 130). A constant here means the second instance on a host
    # takes the name and the first keeps running an image nothing points at — measured on the host
    # that runs two. The default keeps a single-instance deployment on `hullwork:dev`.
    image: hullwork:${{HULLWORK_INSTANCE:-dev}}
    restart: unless-stopped
    # Bound to an address of your choosing, and the default is loopback because the webhook
    # endpoint is real: the token is a path segment, and anything that can reach this URL can post
    # to it. Put a reverse proxy with TLS in front before it answers the internet.
    #
    # **Your tracker has to be able to reach whatever you choose**, and hosted GlitchTip refuses to
    # call private addresses at all — see `deployment-notes.md` §1, which is about that and nothing
    # else.
    ports:
      - "${{BIND_ADDRESS:-127.0.0.1}}:8000:8000"
    # `/ready`, never `/health`: the second one cannot fail by design, so it reports a healthy
    # container with a dead subsystem behind it (item 087).
    healthcheck:
      test: ["CMD", "python", "-c",
             "import urllib.request as r; r.urlopen('http://127.0.0.1:8000/ready').read()"]
      interval: 30s
      timeout: 5s
      start_period: 10s
    # `--no-access-log` is not a preference: the webhook token is a path segment, so an access log
    # writes every project's credential to disk on every delivery.
    command: ["uvicorn", "hullwork.main:app", "--host", "0.0.0.0", "--port", "8000",
              "--no-access-log"]
    # **Generated from `Settings`, not typed** (item 145). Every field this half needs, in a fixed
    # order. `HULLWORK_FORGE_CODE_TOKEN` is absent because `scaffold.REACH` says it belongs to the
    # dispatcher: the receiver refuses to start holding a credential that can push, and this
    # classification is what stops that boundary being lost by somebody tidying this file.
    # Each variable's reasoning lives in `hullwork/config.py`; repeating it here would go stale
    # in two places instead of one.
    environment:
{receiver_env}
    volumes:
      # The database survives `docker compose down`. Losing it loses every fingerprint — every
      # error you already know about looks new again the next morning — and every
      # `forge_sync_pending` intent, which is the only record that an issue is still owed.
      - hullwork-data:/data
      # **This deployment's own two files, read-only, so `doctor` can read them** (item 144).
      # The check that compares what the compose assigns against what the environment file sets
      # could not run without this — it lived on the host and `doctor` lives in here. `:ro` because
      # nothing in either container may write its own deployment, and because `deploy.env` is mode
      # 600 on the host: this mounts a credential file into the process that already holds those
      # values, and into no other.
      - ./{COMPOSE_FILE}:{DEPLOYMENT_MOUNT}/{COMPOSE_FILE}:ro
      - ./{ENVIRONMENT_FILE}:{DEPLOYMENT_MOUNT}/{ENVIRONMENT_FILE}:ro

  dispatcher:
    # **Behind a profile, so `docker compose up -d` starts what `init` says it starts** (item 135).
    #
    # Measured on a first installation that followed the document exactly: with no model key — the
    # state `init` describes as complete for ingest — this container refuses to start, says *"this
    # will not fix itself"*, and `restart: unless-stopped` restarts it four times a minute for ever.
    # The program and this file disagreed about whether that failure is recoverable, and the file
    # won. A profile settles it by not starting the half whose credentials nobody has yet:
    #
    #     docker compose up -d                      # ingest, dedup, triage, issues
    #     docker compose --profile autofix up -d    # and the agent, once its two credentials exist
    profiles: [autofix]
    # The same tag as the receiver above, always: two halves of one instance on two builds is a
    # worse failure than the one item 130 is about.
    image: hullwork:${{HULLWORK_INSTANCE:-dev}}
    depends_on: [api]
    restart: unless-stopped
    # **No `ports:`, no healthcheck, nothing listening.** The dangerous property is listening *and*
    # holding a push credential, not holding the socket.
    healthcheck:
      disable: true
    # The image's entrypoint migrates the database and this process must not: the receiver owns the
    # schema (item 076), and two processes migrating one database race each other. Overriding the
    # entrypoint makes `command` its arguments — `["hullwork", "work", "--loop"]` in one list
    # produces `hullwork hullwork work --loop`, which is a real start-up failure somebody has had.
    entrypoint: ["hullwork"]
    command: ["work", "--loop"]
    # **Twenty minutes, and ten seconds is not enough** (item 097). The signal handler honours a
    # stop between turns and never mid-attempt — cutting one leaves a claimed item and a
    # half-written record — so with the default the process never reaches its `finally` and never
    # releases its lease. Measured: the next dispatcher was locked out for an hour while the
    # previous one's gateway, network and three volumes sat orphaned on the host.
    stop_grace_period: 20m
    group_add:
      # The Docker socket's group, read off this host rather than guessed. The socket is
      # `root:docker 0660`: mounting it is not enough, and without this the client is present, the
      # daemon does not answer, and no attempt can build its sandbox.{unknown}
      - "{gid}"
    # Generated from `Settings` (item 145). **The one line that only exists on this side** is
    # `HULLWORK_FORGE_CODE_TOKEN`, and that is the credential split.
    environment:
{dispatcher_env}
    volumes:
      # The same database as the receiver, which migrates it.
      - hullwork-data:/data
      # The daemon's socket. This is the only reason this service exists separately — it builds
      # sandboxes — and it is mounted here and in no other service.
      - {DOCKER_SOCKET}:{DOCKER_SOCKET}
      # Same two as the receiver, for the same reason: `doctor`'s own advice is to run it in this
      # half as well, and it cannot check a deployment it cannot read.
      - ./{COMPOSE_FILE}:{DEPLOYMENT_MOUNT}/{COMPOSE_FILE}:ro
      - ./{ENVIRONMENT_FILE}:{DEPLOYMENT_MOUNT}/{ENVIRONMENT_FILE}:ro

volumes:
  hullwork-data:
"""


#: Settings the environment file does not list, and why each one.
#:
#: Everything else is named, because **the environment file is where an operator discovers a
#: setting exists at all**. Item 145 taught the compose to *deliver* 33 and left this file naming
#: 15 — including `MAX_ATTEMPT_TOKENS`, the ceiling that protects a prepaid balance, which is the
#: setting a first-time evaluator most needs and could not have known about. Found by walking the
#: golden path as a stranger would, on 2026-08-04.
_NOT_IN_ENVIRONMENT: dict[str, str] = {
    #: Fixed by the compose: the container's path into the volume, which is not the host's path to
    #: the same file. An operator who set this here would be overriding it with the wrong side.
    "database_url": "fixed by the compose file",
}


def _discoverable(already_written: str) -> str:
    """Every remaining setting, named and commented out, so it can be found. Item 145, second half.

    **Names and grouping, not prose.** Each of these already carries its reasoning in `config.py`,
    and a generated file that repeats it goes stale in two places instead of one — the failure this
    whole item is about. What this adds is the one thing a comment in our source cannot: the
    knowledge that the variable exists at all.

    Grouped by which half receives it, because that is the question somebody has when a setting
    appears not to work, and `hullwork config` prints the same grouping for a running instance.

    **Filtered against the text above rather than against a list.** The prose section of this file
    names a dozen settings with real values and a paragraph each; listing any of them again here,
    commented out, invites somebody to uncomment the dead copy. Reading what has already been
    written means a setting promoted into the prose stops being duplicated on its own.
    """
    groups = (
        (Reach.BOTH, "both halves"),
        (Reach.RECEIVER, "the receiver only"),
        (Reach.DISPATCHER, "the dispatcher only — needs `--profile autofix`"),
        (Reach.NEITHER, "read on the host, never passed to a container"),
    )
    out: list[str] = [
        "",
        "# ---------------------------------------------------------------------------------------",
        "# Everything else this instance understands, commented out at its default.",
        "#",
        "# Uncomment what you need. `hullwork config` prints what a running instance holds,",
        "# `hullwork doctor` says whether it arrived, and `deployment-notes.md` explains each.",
        "# ---------------------------------------------------------------------------------------",
    ]
    already = {
        name
        for name in REACH
        if f"HULLWORK_{name.upper()}=" in already_written
    } | set(_NOT_IN_ENVIRONMENT)
    for reach, caption in groups:
        names = sorted(
            name
            for name, where in REACH.items()
            if where is reach and name not in already
        )
        if not names:
            continue
        out.append("")
        out.append(f"# {caption}")
        for name in names:
            if name in _ONE_LINE:
                out.append(f"#   {_ONE_LINE[name]}")
            out.append(f"# HULLWORK_{name.upper()}={_DEFAULTS.get(name, '')}")
    return "\n".join(out) + "\n"


def environment(*, docker_gid: str | None) -> str:
    """The environment file: every name, no value that matters, and where each one comes from."""
    del docker_gid  # read into the compose file directly; kept in the signature for symmetry
    prose = f"""# Hullwork's deployment environment. Written by `hullwork init`. Mode 600.
#
# **Nothing here was filled in for you, and the two credentials never will be.** Each is minted by
# a person in a web interface, once; a token typed into a terminal is a token in a shell history.
#
# Loaded into the shell before compose, so the file is read by you and not by the application:
#
#     set -a; . ./{ENVIRONMENT_FILE}; set +a; docker compose up -d --build
#
# It is deliberately not `.env`: `Settings` reads that one with `extra="forbid"` and refuses to
# start on any key in it that is not a setting — which is correct, and which makes `.env` the wrong
# place for the variables compose interpolates.

# --- required to file issues -------------------------------------------------------------------

# Where this instance is reachable *from your error tracker*. It goes into the webhook URLs the CLI
# prints, so `127.0.0.1` is only right while you are evaluating.
HULLWORK_BASE_URL=

# Which address the container publishes on. Loopback until there is a reverse proxy with TLS in
# front of it: the webhook endpoint is real and its token is a path segment.
BIND_ADDRESS=127.0.0.1

# Your forge, and a token that can **read content and write issues and provably not push**.
# Forgejo/Gitea: `read:repository` + `write:issue`. GitHub: `contents: read` + `issues: write`.
# `hullwork status` asks the forge whether this one can push and says so.
HULLWORK_FORGE_URL=
HULLWORK_FORGE_TOKEN=

# --- required only to attempt fixes --------------------------------------------------------------

# The credential that opens pull requests. **Only the dispatcher receives it** — the receiver
# refuses to start holding it, which is the boundary the two-program split exists for.
# Forgejo/Gitea: `write:repository`. GitHub: `contents: write` + `pull_requests: write`.
HULLWORK_FORGE_CODE_TOKEN=

# The model. An API key from any provider that issues one; the endpoint is OpenAI- or
# Anthropic-shaped and every call passes through Hullwork's own recording gateway, so the key never
# reaches a sandbox. Leave empty and nothing is attempted, which is the default and a supported way
# to run this.
HULLWORK_MODEL_KEY=
HULLWORK_MODEL_ENDPOINT=https://api.anthropic.com
HULLWORK_MODEL_NAME=

# --- optional, and each buys something specific ---------------------------------------------------

# Read the *full* error from your tracker rather than only what its webhook sends: frames, source
# context, dependency versions. Without it an agent works from a title (item 036). All three or
# none — the org is the slug in your tracker's own URLs, the one before the project name.
HULLWORK_TRACKER_URL=
HULLWORK_TRACKER_TOKEN=
HULLWORK_TRACKER_ORG=

# Hullwork's own errors, sent to your tracker. The instance watching itself.
#
# **Setting this alone stops the receiver from starting**, and that refusal is deliberate: the SDK
# is an optional extra, and an instance that believes it is being watched and is not is worse than
# one that knows it is not. Set both of these together, and rebuild.
HULLWORK_ERROR_DSN=
BUILD_EXTRAS=

# **The other direction, and it is not yours.** The image *we publish* carries a destination for
# Hullwork's own crashes — the defects it hits on installations we will never see — baked in at
# release time. This is the switch that declines: `off` and nothing is sent, in any build.
#
# What it would send is not an error report as you know one. It is constructed from a fixed list of
# fields — the exception class, our own stack frames, our version, your Python version, a random
# identifier for this installation, and how many projects and items it holds — and it cannot carry a
# message, a local variable, a URL, a repository name or your hostname. `hullwork/upstream.py` is
# short and is the whole of it.
#
# An image you build yourself sends nothing regardless: the repository contains no destination, and
# a test fails if one ever appears in it.
HULLWORK_TELEMETRY=on

# The commit this deployment is running. **Set it from your deploy** — `git rev-parse HEAD` — or
# the post-merge watch cannot tell whether a recurrence came from code that contains the fix, and
# every verdict it produces is `undecidable`.
HULLWORK_RELEASE=

HULLWORK_LOG_FORMAT=json
HULLWORK_MAX_TURNS=

# Where the image is built from. **This directory is not the checkout** — `hullwork init` asks that
# it not be, because a clone carries a `docker-compose.yml` of its own that it would keep. Point
# this at the source you cloned; the build cannot work until you do.
#
# **Empty rather than `.`, deliberately.** This shipped as `.` and the sentence above already said
# `.` is wrong for the layout this scaffold recommends — so `init` wrote a value it knew was wrong,
# and a stranger following its own printed steps verbatim on 2026-08-04 got
# `failed to read dockerfile: open Dockerfile: no such file or directory`, from a value they never
# chose. Empty fails at the same step with `BUILD_SOURCE` named in the error, which is the whole
# difference. Same reasoning as `REPLACE-ME` for `group_add`: a placeholder that fails loudly
# beats a default that fails obscurely.
BUILD_SOURCE=

# Who this instance is, when a host runs more than one. Every container, network and volume an
# attempt creates is labelled with it, and this instance's reaper removes only what carries its
# own. **Set it to something distinct on the second instance you put on a host** — with both at
# the default, one restarting deletes the other's running attempt.
HULLWORK_INSTANCE=default
"""
    # The prose above names a dozen settings with a paragraph each; everything else is listed below
    # so it can be found at all, filtered against what is already here (item 145, second half).
    return prose + _discoverable(prose)


#: How this repository's own evaluation compose announces itself, on its first line. Item 126.
#:
#: Recognising *that* file rather than judging any file: `init` run inside a clone finds a
#: `docker-compose.yml` already there and keeps it — correctly — and the operator ends up with a
#: deployment directory whose compose has no dispatcher, no error DSN and a loopback binding. That
#: is the failure the boxed warning in the notes is about, reached through the front door.
EVALUATION_MARKER = "Local evaluation stack"


@dataclass
class Written:
    """What the scaffold did, and what it refused to do."""

    created: list[str] = field(default_factory=list)
    #: Files that were already there. **Never overwritten** — see `write`.
    kept: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _is_the_evaluation_stack(path: Path) -> bool:
    """Whether this file is the one this repository ships, rather than one somebody wrote."""
    try:
        return EVALUATION_MARKER in path.read_text(encoding="utf-8", errors="replace")[:400]
    except OSError:
        return False


def write(into: Path, *, docker_gid: str | None) -> Written:
    """Write the two files into `into`, refusing to overwrite anything. Item 115.

    **Refusing is the interesting half.** Measured on this project's own deployment, hours before
    this was written: a compose file copied over another one silently dropped `HULLWORK_ERROR_DSN`,
    the instance came up healthy, and its own error reporting was off — nothing failed, a capability
    just went quiet. A scaffold is exactly the tool that would do that to somebody's configuration,
    so it does not: an existing file is named, kept, and reported.
    """
    done = Written()
    into.mkdir(parents=True, exist_ok=True)
    for name, text, mode in (
        (COMPOSE_FILE, compose(docker_gid=docker_gid), None),
        # **640 and the container's group, not 600.** The compose above mounts this file so `doctor`
        # can compare what it assigns against what arrived (item 144) — and 600 makes that mount
        # unreadable to uid CONTAINER_USER_ID, so the check that exists to catch a variable never
        # reaching the container could not run on any deployment this command writes. Measured on
        # this project's own instance, 2026-08-05, where it reported the file as assigning nothing.
        #
        # The group is the same trade the model credential already makes here: readable by the one
        # identity that has to read it, and by nobody else. Still not world-readable, which is the
        # line that matters for a file holding tokens.
        (
            ENVIRONMENT_FILE,
            environment(docker_gid=docker_gid),
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP,
        ),
    ):
        target = into / name
        if target.exists():
            done.kept.append(name)
            if name == COMPOSE_FILE and _is_the_evaluation_stack(target):
                # Item 126: kept is right, and silence about *which* file was kept is not.
                done.notes.append(
                    f"The {COMPOSE_FILE} already here is this repository's own **evaluation "
                    f"stack**, not a deployment: no dispatcher, no error reporting, and bound to "
                    f"loopback. Nothing was overwritten — but if this directory is your "
                    f"deployment, that file is the one `docs/deployment-notes.md` warns about. Run "
                    f"`hullwork init` into a directory of your own, or move this one aside."
                )
            continue
        target.write_text(text, encoding="utf-8")
        if mode is not None:
            # 640 before anybody fills it in, not after: the window where a credential sits in a
            # world-readable file is the one nobody remembers to close.
            target.chmod(mode)
            # And the group that mode is *for*. Changing a file's group needs privilege unless you
            # are already in the target group, so this can fail perfectly legitimately — running
            # `init` as yourself is the common case. Say the command rather than failing, since the
            # consequence is one check going quiet, not a broken deployment.
            try:
                os.chown(target, -1, CONTAINER_USER_ID)
            except (OSError, AttributeError):
                # **Only where the answer is true** (item 135). Docker Desktop maps ownership across
                # its VM, so a mounted file is read fine whatever its group on the host — the Linux
                # note would send a Mac reader to fix something that is not broken, which is the
                # same defect item 135 corrected in the socket note below.
                if sys.platform == "darwin":
                    done.notes.append(
                        f"`{name}` is mode 640 and its group was left alone: on macOS, Docker "
                        f"Desktop maps ownership across its VM, so the read-only mount this "
                        f"compose file makes of it is readable as-is. On the Linux host you "
                        f"deploy to it is not, and the file needs group {CONTAINER_USER_ID} "
                        f"(`sudo chown :{CONTAINER_USER_ID} {name}`) or `doctor` cannot compare "
                        f"what this file assigns against what actually arrived."
                    )
                else:
                    done.notes.append(
                        f"`{name}` is mode 640, and its group could not be set to "
                        f"{CONTAINER_USER_ID} — the uid the container runs as. Until it is, this "
                        f"compose file mounts a file the process cannot read, and `doctor`'s "
                        f"deployment check stays `unknown` instead of comparing what this file "
                        f"assigns against what actually arrived. One command, on the deployment "
                        f"host: `sudo chown :{CONTAINER_USER_ID} {name}`."
                    )
        done.created.append(name)
    if docker_gid is None:
        # **Say why, because the likeliest reason is how this was run** (item 135). The notes
        # tells you to run `init` inside a container, and a container without the socket mounted
        # cannot see the host's — so the documented route produced this note every time, under a
        # first paragraph promising the group would be read off the host. A `stat` to run by hand
        # left the operator to work out where the number goes.
        # **The explanation has to fit the host it is printed on** (item 135, corrected 2026-08-04).
        # This offered exactly one reason — you are in a container — to a stranger running `init` on
        # macOS, where Docker Desktop has no `/var/run/docker.sock` unless the operator opts in, and
        # where the `stat` suggested was the GNU one. Two wrong answers with nothing marking either
        # as a guess.
        if sys.platform == "darwin":
            done.notes.append(
                f"No Docker socket at {DOCKER_SOCKET}: on macOS, Docker Desktop does not create it "
                f"unless *Settings > Advanced > Allow the default Docker socket to be used* is on. "
                f"The dispatcher's group is a placeholder, and `group_add` means nothing to Docker "
                f"Desktop anyway, so this compose file's autofix half cannot run on this machine. "
                f"It is written for the Linux host you will deploy on, where "
                f"`{STAT_GROUP}` gives the number that belongs in `group_add`. The "
                f"receiver half runs here fine."
            )
        else:
            done.notes.append(
                f"No Docker socket at {DOCKER_SOCKET} here, so the dispatcher's group is a "
                f"placeholder — and if you are running this in a container, that is why. Re-run "
                f"with `--volume {DOCKER_SOCKET}:{DOCKER_SOCKET}:ro` and it reads the real one. If "
                f"not: `{STAT_GROUP}` on the host, into `group_add` in the compose file."
            )
    return done
