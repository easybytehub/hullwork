"""`hullwork try`: the six phases against a checkout on this host, with no forge and no database.

Item 140, and it is DR-0006's entry point finally built. The plan M11 listed this command among the
things that already existed; it did not, and the cost was that **there was no way to see Hullwork
work before committing to it** — two services, a Docker socket, two forge tokens with different
scopes, a registered project and a real error in a repository you own, all before the product had
done anything.

**Almost none of this file is new work, which is the point.** `work --no-publish` already runs six
phases, already refuses to need a credential that can push, already seals the attempt and already
writes what it produced through `write_locally`. Three things stood between it and a stranger, and
this module removes exactly those three:

* it read its work from a database — so a trial builds one in memory, for the length of one run;
* it still asked a forge for the base commit — so a trial hands `_attempt` a checkout instead;
* the bug had to arrive through ingest — so a trial derives one fact from a pasted stack trace.

Everything downstream is untouched. Same `dispatch`, same gates, same seal, same artefact function
the pull request body uses, so the two surfaces cannot come to disagree about what an attempt was.

**What a trial does not remove, and saying so is part of the honesty:** Docker and a model
credential. The claim this product makes is a test that failed against unmodified code and passes
with the change, run in a sandbox, by a model whose identity was read off the wire. Faking either
turns this into a demo of itself. *No credentials* here means **no forge credentials** — nothing
that can push, nothing that can read private code, no account anywhere.
"""

import logging
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from hullwork.config import Settings
from hullwork.manifest import Manifest, parse_manifest
from hullwork.models import Base, Item, ItemState, Lane, Project
from hullwork.normalise import ErrorFact, derive_fingerprint
from hullwork.scrub import instance_secrets

log = logging.getLogger(__name__)

#: The first line of a traceback that names the error, e.g. `ValueError: no such column`. Anchored
#: at a line start so a message quoting an exception mid-sentence does not win over the real one.
_EXCEPTION = re.compile(r"^([A-Za-z_][\w.]*(?:Error|Exception|Warning))\b\s*:?\s*(.*)$", re.M)

#: `File "path/to/thing.py", line 42, in fn` — CPython's frame line. The **last** match is the
#: deepest frame, which is where the error actually happened and what territory should judge.
_FRAME = re.compile(r'^\s*File "([^"]+)", line \d+', re.M)


def fact_from_trace(trace: str, *, project_ref: str, now: datetime | None = None) -> ErrorFact:
    """One `ErrorFact` from text a person pasted. The thin adapter, and thin is the requirement.

    It derives three things and invents nothing:

    * the **title**, from the line naming the exception, because that is the line a person would
      read out loud if you asked them what broke;
    * the **culprit**, from the deepest frame, because that is what `triage.choose_lane` matches
      against and getting it wrong would show the evaluator the wrong lane — the one decision a
      trial must reproduce faithfully, since it is the one a real instance would make;
    * the **fingerprint**, over the derived title and culprit rather than over the raw text, so the
      same crash pasted twice with different line numbers is the same fact.

    `fingerprint_derived` is `True` and it is not a formality: no tracker grouped this, we did, and
    the difference is exactly what that flag exists to record.
    """
    stamp = now or datetime.now(UTC)
    stripped = trace.strip()
    if not stripped:
        msg = "the trace is empty, so there is no error to reproduce"
        raise ValueError(msg)

    match = _EXCEPTION.search(stripped)
    if match:
        kind, detail = match.group(1), match.group(2).strip()
        title = f"{kind}: {detail}" if detail else kind
    else:
        # **Not a refusal.** A panic, a Node stack, a plain log line: this command exists to accept
        # what the evaluator already has in front of them, and a first line is a usable title.
        title = stripped.splitlines()[0].strip()
    title = title[:200]

    frames = _FRAME.findall(stripped)
    culprit = frames[-1] if frames else None

    return ErrorFact(
        provider="trace",
        project_ref=project_ref,
        title=title,
        culprit=culprit,
        # The shared helper, not a hash of our own: identity is derived the same way here as for
        # every other fact, over the title and the culprit rather than over the raw text — so the
        # same crash pasted twice with different line numbers is the same fact.
        fingerprint=derive_fingerprint("trace", title, culprit),
        fingerprint_derived=True,
        timestamps_are_receipt_time=True,
        first_seen=stamp,
        last_seen=stamp,
        # What was handed in, kept whole. On a delivery this is the payload; here it is the text,
        # and it is the only copy of what the evaluator actually saw.
        raw={"trace": stripped},
    )


def head_sha(checkout: Path) -> str:
    """The commit the gates will run against, read from the checkout the evaluator handed us.

    **A trial does not clone, so nothing else knows this.** It matters for the same reason it
    matters in an attempt: everything the artefact claims is a claim about one commit, and one that
    said `unknown` would be an artefact nobody could check.

    A directory that is not a repository is not an error. Somebody trying this against an unpacked
    tarball is exactly the person this command is for, and `working tree` is the honest answer.
    """
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell, path from the operator
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "working tree"
    return done.stdout.strip() if done.returncode == 0 and done.stdout.strip() else "working tree"


def ephemeral_session() -> Session:
    """A database that exists for one run and is never written to disk.

    The schema is real and the machinery above it is untouched — `attempts`, the steps and the seal
    all record exactly what they record in production, which is what makes a trial's artefact worth
    reading. What a trial removes is the *deployment*, not the bookkeeping.
    """
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def stage(
    session: Session, manifest: Manifest, trace: str, *, repo: str
) -> "tuple[Project, Item]":
    """Put one project and one item into the ephemeral database, through the real triage path.

    `dedup.resolve` rather than a hand-built `Item`: it is what assigns the lane, and the lane is
    the one thing a trial has to get right for the same reasons a real instance does. An evaluator
    whose error lands in the red lane should see that, and see why — it is the product working, not
    a limitation of the trial.

    The manifest is stored on the project because that is where `_attempt` reads it from
    (`ingest._manifest_for`), and a trial must not be the one caller that gets it from somewhere
    else — two paths to the manifest is two ways for them to disagree.

    **A red-lane error is not run, and that is the trial being truthful rather than a limitation.**
    The state machine has no edge from a red item to `ready` — *"red lane items are never handed to
    an agent"* — and a trial that forced one would show the evaluator something their own instance
    would refuse to do, on their own manifest's rules. So it stops and says which rule.

    That was found here by item 042's guard, which forbids assigning `item.state` outside `states`.
    Its docstring names this exact situation: the assignment it was written to forbid "was about to
    become load-bearing for DR-0006's dry run — a mode that runs on other people's machines before
    it runs on ours". This is that mode, and the guard was right.
    """
    from hullwork import dedup

    project = Project(
        slug="trial", forge=manifest.git.provider, repo=repo,
        webhook_secret_hash="",  # nothing listens: a trial has no webhook to authenticate
        manifest=manifest.model_dump(mode="json"),
    )
    session.add(project)
    session.flush()

    fact = fact_from_trace(trace, project_ref=repo)
    resolution = dedup.resolve(session, project.id, fact, manifest)
    return project, resolution.item


class NotForAnAgentError(Exception):
    """This error is red-lane on this manifest, so no instance would attempt it. Item 140.

    Its own exception rather than a `WiringError` because nothing is misconfigured: triage ran, made
    a decision, and the decision was *a human looks at this*. Telling an evaluator their setup is
    broken when the product just worked would be the wrong lesson from the right behaviour.
    """


def run(
    settings: "Settings", checkout: Path, trace: str, *, into: Path, approve: bool = False
) -> "object":
    """One trial, end to end. Composes what exists; decides nothing new.

    The forges are `None` and that is the whole claim of this command: `_attempt` is handed a
    checkout, so it never asks one for a base commit, and it publishes through `write_locally`, so
    it never asks one to open anything. Nothing in this call path can reach a forge, which is
    stronger than not configuring one.
    """
    from hullwork import work
    from hullwork.states import transition

    manifest_path = checkout / "hullwork.yml"
    if not manifest_path.is_file():
        # **`--checkout`, because the old form needed a forge token** — inside the one flow whose
        # selling point is having no forge account. Two strangers followed this advice on 2026-08-04
        # and got `HULLWORK_FORGE_URL and HULLWORK_FORGE_TOKEN must be set`. It also interpolated a
        # bare directory name where the command wanted `owner/name`.
        msg = (
            f"{checkout} has no hullwork.yml, so nothing here knows how to run its tests.\n"
            f"  `hullwork propose --checkout {checkout}` prints one from the project's own CI "
            f"config, with no credential — read it, save it as hullwork.yml, and run this again"
        )
        raise work.WiringError(msg)
    # **The path as the source**, not the default `<string>`: the message names what to open, and a
    # stranger who mistyped their manifest on 2026-08-04 was told a file was invalid without being
    # told which one.
    manifest = parse_manifest(manifest_path.read_text(encoding="utf-8"), source=str(manifest_path))

    # **The engine has to exist here too** (item 048's refusal, on the path it did not cover).
    # `projects add` and `projects refresh` resolve the name against this instance's registry, which
    # is where DR-0004 says it belongs — "at project registration, where the manifest is already
    # read". `try` has no registration, so an unknown name walked straight past: verified on
    # 2026-08-04 with `agent: gpt-9-turbo`, which reached the model-credential check and would have
    # gone on to build an image and start an attempt before failing. Item 048's whole finding was
    # that the refusal existed and happened in the most expensive place available.
    if manifest.autofix.agent != "none":
        from hullwork.engine import resolve as resolve_engine

        try:
            resolve_engine(manifest.autofix.agent)
        except KeyError as exc:
            raise work.WiringError(
                f"autofix.agent: {exc}. Registering an engine is an operator action on this "
                f"instance, never something a repository can do (item 017) — so a name this build "
                f"does not hold cannot be attempted here either. Set `agent: claude-code`, which "
                f"ships with Hullwork."
            ) from exc

    session = ephemeral_session()
    project, item = stage(session, manifest, trace, repo=checkout.name)
    if item.state is ItemState.WAITING_APPROVAL and approve:
        # **Running `try --approve` on your own checkout *is* the per-item approval.** Amber means
        # a human decides this one, by hand, before an agent touches it — and the person typing this
        # against a tree they control is that human. Through `transition`, which is the only door
        # (item 042), and it is the same `waiting_approval -> ready` edge `hullwork approve` uses.
        transition(item, ItemState.READY)
    if item.state is not ItemState.READY:
        lanes = manifest.autofix.lanes
        lanes_are_empty = not (lanes.green or lanes.amber or lanes.red)
        # **Four causes, four sentences**, and until 2026-08-04 they shared one that was wrong for
        # three of them. Two strangers evaluating the product an hour apart both quit here, and the
        # second one traced why: the first fix separated red from amber and still misreported the
        # commonest case of all, `autofix.agent: none` — which is the *default*, so the README's own
        # example manifest reaches this refusal, and the advice it got (`--approve`) cannot work
        # because the item is not waiting for approval. It never became attemptable at all.
        #
        # The order matters. `agent: none` is asked first because it is not a lane decision: no lane
        # would have helped, and telling somebody to widen a lane when the agent is switched off
        # sends them to edit the wrong half of their manifest.
        if manifest.autofix.agent == "none":
            why = (
                "this manifest sets `autofix.agent: none`, which is the default, so no agent is "
                "ever asked and the lane never mattered"
            )
            through = (
                f"Set `autofix.agent: claude-code` in {manifest_path} — that is the switch, and it "
                f"is off until you turn it on (README, 'The agent half, stated exactly')."
            )
        elif item.lane is Lane.RED and lanes_are_empty:
            # Red *by default* rather than by decision, which is a configuration answer wearing a
            # policy answer's clothes — and the single thing that made `try` look like a no-op.
            #
            # Asked of the **manifest**, not of `lane_reason`: triage fills that in either way ("no
            # lane rule matched; defaulting to red so a human decides"), so a message keying off its
            # absence would never fire. Found by running it.
            why = (
                "nothing in this manifest classified it, and an unclassified error defaults to red "
                "so that a human decides — `autofix.unmatched: human`, the default"
            )
            through = (
                f"Give {manifest_path} a green lane for what you are happy to have attempted, for "
                f"example `autofix: {{lanes: {{green: [keyerror]}}}}`, or set "
                f"`autofix.unmatched: attempt` to opt the whole project in. Neither is a flag on "
                f"this command: what an agent may touch is the project's decision, in its manifest."
            )
        elif item.lane is Lane.RED:
            why = (
                "a red-lane item is never handed to an agent, by any instance, and there is no "
                "flag that changes that"
            )
            through = (
                f"To see the fix half, paste an error from code your manifest calls green, or move "
                f"this path out of the red lane in `autofix.lanes` in {manifest_path}."
            )
        elif item.state is ItemState.WAITING_APPROVAL:
            why = (
                "an amber-lane item waits for a human to approve it one item at a time, which on a "
                "real instance is `hullwork approve <project> <item>`"
            )
            through = (
                "You are that human here: re-run this with `--approve` to attempt it anyway, or "
                "paste an error from code your manifest calls green."
            )
        else:
            # **Bound to the state rather than guessing from the lane.** The branch above offers
            # `--approve`, which only fires on `waiting_approval`; a message that offered it for any
            # other state would be advice that cannot work, which is exactly the defect this whole
            # block was rewritten to remove. If a state arrives here that nothing above explains,
            # say which one it is and stop.
            why = f"it is '{item.state.value}', which is not a state an agent is handed work from"
            through = (
                "This is unexpected rather than a policy decision — `hullwork try` reaches it "
                "through the same triage a real instance uses, so please report it with the trace "
                "and the manifest that produced it."
            )
        # **The lane is not always the story, so it does not always lead.** With `agent: none` the
        # lane is irrelevant by construction, and opening with "triage put this in the red lane"
        # before explaining that the lane never mattered is how the old single message read: it sent
        # people to edit their lane rules over a switch that was off.
        if manifest.autofix.agent == "none" or lanes_are_empty:
            # `lane_reason` and `why` say the same thing when nothing was classified, and the prefix
            # made the sentence state the default twice.
            msg = f"{why}. That is the product working, not a limit of `try`.\n  {through}"
        else:
            msg = (
                f"triage put this in the {item.lane.value} lane — "
                f"{item.lane_reason or 'no rule matched'} — and {why}. That is the product "
                f"working, not a limit of `try`.\n  {through}"
            )
        raise NotForAnAgentError(msg)
    resolved = work.Checkout(path=checkout, sha=head_sha(checkout))
    # **`debug`, not `info`.** This is the one command a newcomer runs interactively, and a JSON log
    # line above its first human sentence is the tool talking to a log aggregator that is not there.
    # Still reachable with `HULLWORK_LOG_LEVEL=DEBUG`, which is who wanted it.
    log.debug(
        "trial starting", extra={"checkout": str(checkout), "sha": resolved.sha, "into": str(into)}
    )
    return work._attempt(
        session,
        settings,
        work.Eligible(item=item, project=project),
        code_forge=None,
        forge=None,
        credential=work._model_credential(settings),
        secrets=instance_secrets(settings),
        rehearse_into=into,
        local_checkout=resolved,
    )
