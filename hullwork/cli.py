"""The `hullwork` command.

Registration is a command rather than an HTTP endpoint (operator decision, 2026-07-27). The core is
single-tenant, so the operator already has the server: an administration endpoint would be a
permanent attack surface and one more credential to rotate, for something done a handful of times in
an instance's life. It also keeps the generated webhook token off the network — it is printed here,
in the operator's own terminal, instead of travelling in a response body.

`argparse` on purpose. A CLI framework is a dependency this does not need.
"""

import argparse
import json
import logging
import signal
import subprocess
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TextIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from hullwork import (
    __version__,
    credentials,
    doctor,
    lease,
    outcomes,
    page,
    propose,
    readiness,
    recurrence,
    spend,
    territory,
    triage,
    work,
)
from hullwork.config import ConfigError, Settings, get_settings
from hullwork.credentials import PushCapability
from hullwork.db import get_engine, make_session_factory
from hullwork.forge import Forge, ForgeError
from hullwork.forge.factory import (
    configured_kind,
    make_code_forge,
    make_forge,
    make_permission_reader,
    serves,
)
from hullwork.ingest import forge_answers, sweep_inventory
from hullwork.logging import configure_logging
from hullwork.manifest import MANIFEST_FILENAME, Manifest, ManifestError, parse_manifest
from hullwork.models import (
    Attempt,
    AttemptOutcome,
    Delivery,
    Event,
    FetchedEvent,
    Item,
    ItemState,
    Project,
)
from hullwork.sandbox.image import ImageBuildError
from hullwork.sandbox.run import SandboxError
from hullwork.security import generate_token, hash_token
from hullwork.states import IllegalTransitionError, transition
from hullwork.telemetry import configure_error_reporting
from hullwork.tracker.factory import make_inventory

log = logging.getLogger(__name__)

#: **GitHub is here since item 068.** It was left out of this tuple while `forge/github.py` was 936
#: exercised lines with no project that could ever reach them: `--forge github` was refused by
#: argparse, `_forge_for` built a `ForgejoForge` whatever it was given, and item 034's ticked
#: criterion — *"a manifest declaring `provider: github` registers and works end to end"* — was
#: false against the shipped command. README principle 3 promises GitHub from day one.
#:
#: `gitea` and `forgejo` are the same adapter under two names, which is why both are here and there
#: is no third class: Forgejo is a Gitea fork and its API is compatible at every endpoint this uses.
#:
#: `gitlab` joined in item 132 and is the one name here whose **URL cannot identify it** — a
#: self-hosted GitLab and a self-hosted Forgejo look identical — so the instance is told which
#: it serves by `HULLWORK_FORGE_KIND`, and this list is what a project may then claim to be.
SUPPORTED_FORGES = ("forgejo", "gitea", "github", "gitlab")


class CommandError(Exception):
    """Something the operator can fix. Printed as a message, never as a traceback."""


@dataclass(frozen=True)
class Registration:
    """What `projects add` produced. The token is here exactly once and never stored."""

    project: Project
    manifest: Manifest
    token: str

    def webhook_url(self, base_url: str) -> str:
        provider = self.manifest.errors.provider
        return f"{base_url.rstrip('/')}/webhooks/{provider}/{self.project.slug}/{self.token}"


def _forge_for(settings: Settings, kind: str) -> Forge:
    """The forge this registration will talk to, chosen the same way the pipeline chooses it.

    **Through `factory.make_forge`, not by constructing one here** (item 068). This function used to
    return a `ForgejoForge` unconditionally, so a `--forge github` registration — once the tuple
    above allowed it — would have been *validated against a Forgejo API at a GitHub URL*, which
    fails in a way that reads like a credential problem. The factory selects on the configured URL
    and is the same code path every later request takes, so registration cannot succeed against a
    forge the pipeline would then fail to reach.

    The kind is still checked, because argparse's `choices` covers `projects add` and not a
    manifest: `_the_manifest_must_agree` compares this against `git.provider`, and a name nothing
    can serve has to be refused with a sentence rather than an adapter mismatch four layers down.
    """
    if kind not in SUPPORTED_FORGES:
        available = ", ".join(SUPPORTED_FORGES)
        raise CommandError(
            f"forge '{kind}' is not supported in this version (available: {available})"
        )
    if not settings.forge_url or not settings.forge_token:
        raise CommandError(
            "HULLWORK_FORGE_URL and HULLWORK_FORGE_TOKEN must be set to reach the forge"
        )
    # **Before any request, and naming both** (item 124). Measured on the first third-party project
    # anybody pointed this at: `--forge github` on a Forgejo-configured instance was accepted here,
    # thrown away, and the request went to Forgejo — which answered `HTTP 404` about a repository it
    # has never heard of. Both commands then reported that the *repository* was empty or missing,
    # sending the operator to write a manifest by hand for a wall that is in their configuration.
    if not serves(settings, kind):
        raise CommandError(
            f"this instance is configured for a {configured_kind(settings)} forge "
            f"({settings.forge_url}), so it cannot register or read a '{kind}' project.\n"
            f"  Nothing was asked of {kind} — the request would have gone to the URL above, and "
            f"its answer would have looked like your repository being empty.\n"
            f"  Two ways forward: point this instance at that forge (HULLWORK_FORGE_URL and a "
            f"token for it), or run a second instance for it — `hullwork init` writes one, and "
            f"give it its own HULLWORK_INSTANCE so the two do not collect each other's sandboxes."
        )
    forge = make_forge(settings)
    if forge is None:  # pragma: no cover - the settings check above is the same condition
        raise CommandError(
            "HULLWORK_FORGE_URL and HULLWORK_FORGE_TOKEN must be set to reach the forge"
        )
    return forge


def _manifest_from_file(path: str) -> str:
    """A manifest the operator hands over. DR-0012.

    Read here rather than in the caller so both doors — `projects add --manifest` and
    `projects refresh --manifest` — refuse the same way, in the same words, for a path that is not
    there or cannot be read. The content is not inspected: `parse_manifest` owns that, and a second
    opinion about what a manifest is would be a second thing to keep in step.
    """
    try:
        return Path(path).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        raise CommandError(
            f"cannot read the manifest at {path}: {exc.strerror or exc}.\n"
            f"  This is a path on the machine running this command, not in the repository."
        ) from exc


def _repository_is_reachable(forge: Forge, repo: str) -> bool:
    """Whether this credential can see the repository at all, as opposed to its manifest.

    Split from the manifest read because DR-0012 separates the two questions for the first time: a
    missing `hullwork.yml` is ordinary and now has an answer, while a repository this instance
    cannot see is a wall, and the two used to arrive as the same `ForgeError`.

    `tree` and not `default_branch`, which would be one request instead of three: the ingest
    `Forge` protocol does not carry `default_branch` — only the code one does — and widening it
    would oblige every adapter and every double to grow a method for a question asked once per
    project, by a human, at registration. The cost is a tree listing on a command that already
    reads a manifest.
    """
    try:
        forge.tree(repo)
    except ForgeError:
        return False
    return True


def add_project(
    session: Session,
    settings: Settings,
    *,
    slug: str,
    forge_kind: str,
    repo: str,
    manifest_file: str | None = None,
    out: TextIO | None = None,
) -> Registration:
    """Register a project, after proving we can read and understand its manifest.

    Nothing is written until the manifest validates. A project registered in a broken state is worse
    than a refused registration: it looks connected and silently is not.

    `manifest_file` is DR-0012: the same file, handed over instead of committed, for a repository
    the operator cannot write to. **The forge is still asked whether the repository exists** —
    registering one this instance cannot reach is the failure item 068 guards, and it has nothing
    to do with where the manifest came from — and every validation below runs unchanged. A manifest
    that arrives by hand is not a manifest that is trusted more.
    """
    if session.query(Project).filter(Project.slug == slug).one_or_none():
        raise CommandError(f"a project called '{slug}' is already registered")

    origin = "operator" if manifest_file else "repository"
    forge = _forge_for(settings, forge_kind)
    try:
        if manifest_file:
            text = _manifest_from_file(manifest_file)
            # Asked, and its answer thrown away except for the refusal: this is the check that the
            # repository exists and that this credential can see it.
            try:
                forge.read_manifest(repo)
            except ForgeError as exc:
                if not _repository_is_reachable(forge, repo):
                    raise CommandError(
                        f"this instance cannot see {repo} on {settings.forge_url}: {exc}\n"
                        f"  A manifest of your own does not help with that — the credential has to "
                        f"be able to read the repository the fixes would be about."
                    ) from exc
        else:
            try:
                text = forge.read_manifest(repo)
            except ForgeError as exc:
                # **A refusal that could have printed the answer is a bad refusal** (item 107). A
                # repository with no manifest is the ordinary first contact, and the project's own
                # CI configuration already says how it is set up and tested.
                proposed = propose_from_ci(forge, repo)
                if proposed is None:
                    raise CommandError(
                        f"could not read {MANIFEST_FILENAME} from {repo}: {exc}\n"
                        f"  And nothing in that repository proposes one: no CI configuration was "
                        f"found at {', '.join(propose.CI_LOCATIONS)}. Write {MANIFEST_FILENAME} by "
                        f"hand — docs/hullwork-yml.md is the reference — and register again, or "
                        f"hand it over without committing it: `projects add --manifest FILE` "
                        f"(DR-0012)."
                    ) from exc
                raise CommandError(
                    f"{repo} has no {MANIFEST_FILENAME}, so there is nothing to register yet.\n\n"
                    f"Its CI configuration answers most of what one needs. Commit this to "
                    f"{MANIFEST_FILENAME}, having read it — or keep it out of the repository and "
                    f"register with `--manifest FILE` (DR-0012):\n\n{proposed}"
                ) from exc
    finally:
        forge.close()

    try:
        manifest = parse_manifest(text, source=f"{forge_kind}:{repo}")
    except ManifestError as exc:
        raise CommandError(str(exc)) from exc

    _the_manifest_must_agree(manifest, slug=slug, forge_kind=forge_kind, repo=repo)
    _the_engine_must_be_known(manifest)
    _the_services_must_be_known(manifest)
    _the_runtime_must_be_allowed(manifest, settings)
    _the_image_must_be_able_to_host_a_phase(manifest, out=out)

    token = generate_token()
    project = Project(
        slug=slug,
        forge=forge_kind,
        repo=repo,
        webhook_secret_hash=hash_token(token),
        manifest=manifest.model_dump(mode="json"),
        manifest_fetched_at=datetime.now(UTC),
        manifest_origin=origin,
    )
    session.add(project)
    session.commit()

    return Registration(project=project, manifest=manifest, token=token)


def _the_manifest_must_agree(
    manifest: Manifest, *, slug: str, forge_kind: str, repo: str
) -> None:
    """Refuse a registration whose arguments and manifest describe different things.

    The constitution says the manifest is the law. It was not: `add_project` took the slug, forge
    and repository from the command line and never compared them to the file it had just parsed, so
    a manifest could say `easybyte/hullwork` while the row said something else and nothing
    complained. Both halves have been in hand all along; this is the comparison.

    It is also where the spec's promise about GitHub finally holds — `git.provider: github` was
    accepted and then quietly ignored, which is precisely what the spec says must never happen.
    """
    mismatches = [
        f"  project: manifest says {manifest.project!r}, you asked for {slug!r}"
        if manifest.project != slug
        else "",
        f"  git.repo: manifest says {manifest.git.repo!r}, you asked for {repo!r}"
        if manifest.git.repo != repo
        else "",
        f"  git.provider: manifest says {manifest.git.provider!r}, you asked for {forge_kind!r}"
        if manifest.git.provider != forge_kind
        else "",
    ]
    listed = [line for line in mismatches if line]
    if listed:
        raise CommandError(
            "the manifest and this command disagree, and the manifest is the law:\n"
            + "\n".join(listed)
            + "\nFix hullwork.yml, or register the project it actually describes."
        )



def _the_image_must_be_able_to_host_a_phase(
    manifest: Manifest, *, out: TextIO | None
) -> None:
    """Refuse a base image that cannot host a phase, and say which of the two it is. Item 108.

    **Two preconditions, both measured as inscrutable failures.** An image with no shell dies at
    the first `RUN` with a message about `useradd`, when every phase runs `sh -lc` and the harness
    works by executing commands (item 059) — that one will never be fixable, because it is what
    the harness *is*. An image for another architecture dies at run time with the same misleading
    *"not found"* DR-0007 spends a boxed aside explaining for musl.

    **And "not checked" is a third answer, not a refusal.** `projects add` is normally typed on the
    receiver, which holds no Docker socket by design (DR-0009), so a check that could not tell an
    unreachable daemon from a bad image would refuse every registration made from the right place.
    Item 105's whole lesson: do not attribute a failure to a cause you did not establish.
    """
    runtime = manifest.runtime
    if runtime is None:
        return
    from hullwork.sandbox.image import host_architecture, inspect_base

    facts = inspect_base(runtime.base)
    if not facts.checked:
        if out is not None:
            print(
                f"Not checked here: whether {runtime.base} has a shell and matches this host's "
                f"architecture — {facts.why_not}. The build where the dispatcher runs is what "
                f"establishes both; a failure there will name whichever one it was.",
                file=out,
            )
        return
    # **The architecture first, and the order is a measured defect rather than taste.** Asked on
    # in production: `arm64v8/alpine:3.20` on an amd64 host *has* a shell — and the probe for one
    # fails anyway, with `exec format error`. Read in the other order, the refusal said "has no
    # shell" about an image whose shell is fine, which is item 105's defect exactly: a cause
    # asserted rather than established. The architecture is a fact off the image; the shell is an
    # inference from a command that ran, and an inference is only sound once the fact agrees.
    host = host_architecture()
    if facts.architecture and host and facts.architecture != host:
        msg = (
            f"runtime.base: {runtime.base} is built for {facts.architecture} and this host runs "
            f"{host}. The harness bundle is built per architecture, so a mismatch fails inside the "
            f"sandbox with a misleading \"not found\" about the executable. Name an image for "
            f"{host}, or run this instance on {facts.architecture}."
        )
        raise CommandError(msg)
    if facts.has_shell is False:
        msg = (
            f"runtime.base: {runtime.base} has no shell, so it cannot host a phase. Every phase "
            f"runs `sh -lc`, and the agent works by executing commands — so this is a permanent "
            f"limit rather than a gap: a `distroless` or `scratch` image cannot be used. Name one "
            f"with a shell, which any image your CI runs tests in already has."
        )
        raise CommandError(msg)


def _propose_entry(args: argparse.Namespace, settings: Settings, out: TextIO) -> int:
    """Standalone with a checkout, database-backed with a repo — same shape as `lanes`.

    One command for one question, for the reason given there: a separate subcommand for the
    credential-free form would make the honest order look like a lesser variant of the real thing.
    """
    if not (args.checkout or args.repo):
        raise CommandError(
            "name a repository as owner/name, or pass --checkout PATH to read a local directory "
            "with no credential"
        )
    if args.checkout:
        return _cmd_propose(args, None, settings, out)  # type: ignore[arg-type]
    factory = make_session_factory(get_engine(settings.database_url))
    with factory() as session:
        return _cmd_propose(args, session, settings, out)


def _coordinate_of(checkout: Path) -> str:
    """`owner/name` for a local checkout, from its `origin` remote, or a visible placeholder.

    A manifest's `git.repo` is validated as `owner/name` (`manifest.py`), so the directory's own
    name would produce a proposal that cannot parse — the one thing a proposal must never do, since
    its whole purpose is to be committed. The remote is where that coordinate exists locally.

    When there is no usable remote the placeholder is `owner/name` verbatim: it fails validation
    loudly and reads as something to replace, which is the same choice as `REPLACE-ME` for
    `group_add`. A plausible-looking wrong value would be committed.
    """
    url = subprocess.run(  # noqa: S603
        ["git", "-C", str(checkout), "remote", "get-url", "origin"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if url.returncode == 0:
        trimmed = url.stdout.strip().removesuffix(".git")
        # `git@host:owner/name` and `https://host/owner/name` both end in the two segments wanted,
        # and anything else falls through to the placeholder rather than being guessed at.
        parts = trimmed.replace(":", "/").rstrip("/").split("/")
        if len(parts) >= 2 and all(parts[-2:]):
            return "/".join(parts[-2:])
    return "owner/name"


def propose_from_local_ci(checkout: Path) -> str | None:
    """The same proposal, read from a directory instead of a forge. **No credential at all.**

    **Why this exists** (2026-08-04). `propose` is the on-ramp the README sells hardest — you do not
    have to write the manifest — and its own help says *"Writes nothing and registers nothing"*, yet
    it took only `owner/name`, so it refused without `HULLWORK_FORGE_URL` and a forge token.
    A read-only, side-effect-free command needed a forge token while `try`, which runs containers,
    happily took a local path.

    Worse, and this is what made it a dead end rather than an inconvenience: `trial.run` recommends
    exactly this command to somebody whose checkout has no `hullwork.yml` — inside the flow whose
    entire selling point is having no forge account. Two strangers evaluating the product hit it.

    The seam was already there: `propose.find` takes a list of paths and
    `the_recipe_its_toolchain_needs` takes a reader, so neither knows where each came from. Tracked
    files only, to match what a forge serves — a walk would read `.venv/` and propose from a cache.
    """
    listed = subprocess.run(  # noqa: S603
        ["git", "-C", str(checkout), "ls-files"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode != 0:
        raise CommandError(
            f"could not list the files in {checkout}: it is not a git checkout, and this reads "
            f"tracked files so the proposal matches what a forge would serve.\n"
            f"  {listed.stderr.strip()}"
        )
    paths = [line for line in listed.stdout.splitlines() if line]

    def read(path: str) -> str | None:
        try:
            return (checkout / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    for candidate in propose.find(paths):
        text = read(candidate)
        if text is None:
            continue
        proposal = propose.read(_coordinate_of(checkout), candidate, text)
        if proposal.found_anything:
            checked = propose.only_files_that_exist(proposal, paths)
            return propose.render(
                propose.the_recipe_its_toolchain_needs(checked, paths, read)
            )
    return None


def propose_from_ci(forge: Forge, repo: str) -> str | None:
    """A manifest proposed from the repository's own CI configuration, or `None`. Item 107.

    Two reads and no writes: the tree to find the file (item 068's `Forge.tree`), then the file.
    Both are reads, so the ingest credential is enough — which is what makes this usable from
    `projects add`, where the code credential must not be.
    """
    try:
        listing = forge.tree(repo)
        candidates = propose.find(list(listing.paths))
        for path in candidates:
            text = forge.read_file(repo, path)
            if text is None:
                continue
            proposal = propose.read(repo, path, text)
            if proposal.found_anything:
                # **Checked against the tree that is already in hand** (item 111). The dependency
                # files are inferred from the installer — a lock file is the usual companion of an
                # install command — and `sinatra/sinatra` does not commit its `Gemfile.lock`. A
                # manifest naming a file the repository lacks fails at build time, which is a long
                # way from here, so the answer is filtered where the tree is already open.
                checked = propose.only_files_that_exist(proposal, listing.paths)
                return propose.render(
                    propose.the_recipe_its_toolchain_needs(
                        checked, listing.paths, lambda path: forge.read_file(repo, path)
                    )
                )
    except ForgeError as exc:
        # Not being able to look is not the same as there being nothing to find, and this runs on a
        # path that is already reporting a failure — so it says nothing rather than guessing.
        log.warning("could not look for a CI configuration", extra={"repo": repo, "why": str(exc)})
        return None
    return None


def _the_runtime_must_be_allowed(manifest: Manifest, settings: Settings) -> None:
    """Enforce this instance's narrowing, if it has any. Item 068, DR-0007's *"default open"*.

    **Empty means no narrowing**, which is the default and what every existing deployment does: a
    project names its base image and its apt packages, and the grammar in `manifest.py` is what
    stops either escaping the Dockerfile line it goes into. These lists exist for the operator
    running Hullwork against repositories they do not control, or inside a network with one
    reachable registry — and for nobody else, which is why they ship off.

    At registration rather than at build time, for item 048's reason: a refusal that arrives after
    the item is claimed and the attempt row is open happened in the most expensive place available.
    Both callers get it, because `refresh` is how a manifest changes after registration.
    """
    runtime = manifest.runtime
    if runtime is None:
        return
    allowed_images = [name.strip() for name in settings.allowed_base_images if name.strip()]
    if allowed_images and runtime.base not in allowed_images:
        msg = (
            f"runtime.base: {runtime.base!r} is not one this instance permits. "
            f"HULLWORK_ALLOWED_BASE_IMAGES restricts it to: {', '.join(sorted(allowed_images))}."
        )
        raise CommandError(msg)
    allowed_packages = [name.strip() for name in settings.allowed_packages if name.strip()]
    if allowed_packages:
        refused = sorted(set(runtime.packages) - set(allowed_packages))
        if refused:
            msg = (
                f"runtime.packages: {refused} not permitted by this instance. "
                f"HULLWORK_ALLOWED_PACKAGES restricts them to: "
                f"{', '.join(sorted(allowed_packages))}."
            )
            raise CommandError(msg)


def _the_engine_must_be_known(manifest: Manifest) -> None:
    """Refuse a manifest naming an engine this instance has never heard of. Item 048.

    DR-0004's stated consequence: `AgentSpec` stops being a closed `Literal`, "resolved against the
    instance's engine registry **at project registration** — where the manifest is already read and
    compared against its arguments". It was resolved at dispatch time instead, so an unknown name
    registered cleanly, waited in the queue, and failed after the item had been claimed, an attempt
    row started and a container image built. The refusal existed; it happened in the most expensive
    place available.

    `none` is the default and means no engine at all, so it never reaches the registry.
    """
    if manifest.autofix.agent == "none":
        return
    from hullwork.engine import resolve

    try:
        resolve(manifest.autofix.agent)
    except KeyError as exc:
        raise CommandError(
            f"autofix.agent: {exc}.\n"
            f"  Registering an engine is an operator action on this instance, never something a "
            f"repository can do (item 017). Either register it here, or set `agent: none`."
        ) from exc


def _the_services_must_be_known(manifest: Manifest) -> None:
    """Refuse a manifest naming a service this build cannot provide. Item 052, half one.

    The same door as `_the_engine_must_be_known` and for the same reason. The plan M10 makes this
    half worth shipping alone: without it, an item on such a project reaches `ready`, is claimed,
    starts an attempt row, builds an image, and only then finds out — where item 043 correctly sends
    it to `human-only` with a message about the project's own suite. Refused here, nothing reaches
    `ready` at all and the operator learns it at the moment they can act on it.
    """
    if manifest.runtime is None:
        return
    from hullwork.sandbox.services import SERVICES, unknown

    missing = unknown(list(manifest.runtime.services))
    if missing:
        raise CommandError(
            f"runtime.services: this build cannot provide {', '.join(missing)}.\n"
            f"  It knows: {', '.join(sorted(SERVICES))}.\n"
            f"  A project names a service and the instance decides what the name means, never the "
            f"other way round (item 017). Adding one is an operator action here."
        )


def runtime_diff(before: object, after: Manifest) -> list[str]:
    """What changed in `base`, `install` and `packages` between two manifests. Item 108.

    **This is the mitigation the opened fields actually need**, and it rests on a property DR-0007
    never claimed: the manifest is **adopted, not followed**. Nothing re-reads it from the forge in
    order to act — `ingest.confirm_forge` reads it as a health check and throws the answer away,
    and everything that decides uses the stored copy. So a repository cannot change its own build
    environment without the operator running `refresh`, and the real risk is not a stranger editing
    `hullwork.yml`: it is the operator adopting a change **without seeing it**.

    Which is exactly what `refresh` allowed: it printed lane counts, and said nothing about the
    three fields that, since item 068, can be any image, any command and any package.

    An empty list means nothing changed, and the caller says so rather than staying quiet: silence
    reads as "not checked".
    """
    was = before if isinstance(before, dict) else {}
    old_runtime = was.get("runtime") if isinstance(was.get("runtime"), dict) else {}
    new_runtime = after.runtime
    changes: list[str] = []

    def compare(field: str, old_value: object, new_value: object) -> None:
        if old_value == new_value:
            return
        changes.append(f"{field}: {old_value!r} → {new_value!r}")

    if new_runtime is None:
        if old_runtime:
            changes.append("runtime: declared → absent")
        return changes
    if not old_runtime:
        changes.append(f"runtime: absent → base {new_runtime.base!r}")
        return changes

    compare("base", (old_runtime or {}).get("base"), new_runtime.base)
    compare("install", (old_runtime or {}).get("install"), new_runtime.install)
    compare("packages", (old_runtime or {}).get("packages") or [], list(new_runtime.packages))
    return changes


def refresh_manifest(
    session: Session,
    settings: Settings,
    slug: str,
    *,
    manifest_file: str | None = None,
    out: TextIO | None = None,
) -> Manifest:
    """Re-read a project's manifest from its default branch and replace the cached copy.

    Until this existed, **editing `hullwork.yml` after registration did nothing at all**: the
    manifest was snapshotted by `projects add` and never read again. The README tells users to edit
    it, the constitution calls it the law, and a filed issue tells them to reclassify a lane there
    — all three were false the moment a project was registered.

    Refusing to store an invalid manifest is the point: a project keeps the rules it had rather
    than losing them to a typo.
    """
    project = _require(session, slug)

    # **DR-0012: a project whose manifest this instance holds has nothing to re-read.** Refusing
    # here rather than fetching is the whole point — going to the forge would either find no file
    # and fail, or find one nobody registered and adopt it behind the operator's back. Silently
    # doing nothing was the third option and it is what item 105 was closed for.
    if project.manifest_origin == "operator" and not manifest_file:
        raise CommandError(
            f"'{slug}' was registered with a manifest you handed over, so there is nothing in "
            f"{project.repo} to re-read (DR-0012).\n"
            f"  To change it: hullwork projects refresh {slug} --manifest FILE\n"
            f"  To move it into the repository instead, commit {MANIFEST_FILENAME} there and "
            f"register again — that is the default for a reason: it versions with the test command "
            f"it describes."
        )

    # One path from here on: the same parser, the same checks, the same diff printed before the
    # stored copy is replaced. Only where the text came from differs, and the row remembers which.
    if manifest_file:
        text = _manifest_from_file(manifest_file)
    else:
        forge = _forge_for(settings, project.forge)
        try:
            text = forge.read_manifest(project.repo)
        except ForgeError as exc:
            raise CommandError(f"could not read the manifest from {project.repo}: {exc}") from exc
        finally:
            forge.close()

    try:
        manifest = parse_manifest(text, source=f"{project.forge}:{project.repo}")
    except ManifestError as exc:
        raise CommandError(f"{exc}\n\nThe cached manifest is unchanged.") from exc

    _the_engine_must_be_known(manifest)
    _the_services_must_be_known(manifest)
    _the_runtime_must_be_allowed(manifest, settings)
    _the_image_must_be_able_to_host_a_phase(manifest, out=out)
    _the_manifest_must_agree(
        manifest, slug=project.slug, forge_kind=project.forge, repo=project.repo
    )
    # **Read before the stored copy is replaced**, because after that there is nothing to compare —
    # and printed rather than stored, because it is a thing to see now and not state to keep.
    changes = runtime_diff(project.manifest, manifest)
    project.manifest_origin = "operator" if manifest_file else "repository"
    if out is not None:
        if changes:
            print("  The build environment changed:", file=out)
            for line in changes:
                print(f"    {line}", file=out)
        else:
            # Said out loud. Silence about a check reads as the check not having happened, which is
            # the defect item 105 was closed for in a different place the same day.
            print("  Nothing changed in the build environment.", file=out)
    project.manifest = manifest.model_dump(mode="json")
    project.manifest_fetched_at = datetime.now(UTC)
    session.commit()
    return manifest


def prune(session: Session, older_than_days: int) -> int:
    """Forget the raw bodies of deliveries older than N days. Returns how many were cleared.

    The payload is kept so a delivery accepted before a restart can still be processed after one —
    a purpose measured in minutes, not months. Nothing expires it, and `events.raw` stores the
    **whole** delivery once per fact inside it, so a payload carrying twenty errors is stored
    twenty-one times. Measured: 2,000 attachments in one 160 KB request became a 322 MB database.

    Rows, fingerprints, counters and issue references are untouched. Only the verbatim bodies go,
    which is the part that is large and the part whose usefulness has an expiry date.

    **`fetched_events` is cleared too, and it is now the biggest table.** Item 036 made Hullwork a
    reader of the tracker, so every item carries frames with source context and 33 to 71 dependency
    versions — the same shape of growth `events.raw` had, arriving by a new door. Missing it would
    have reproduced the 322 MB measurement exactly.

    **`attempts` and `attempt_steps` are never touched.** That is a deliberate exception rather than
    an oversight: the attempt record is the only evidence that an item has already cost its one try,
    and the steps are the claim an open pull request makes about itself. Pruning them would leave a
    pull request asserting "this test failed and now passes" with nothing behind it, and an item
    looking untried when it is spent.
    """
    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    cleared = (
        session.query(Delivery)
        .filter(Delivery.received_at < cutoff, Delivery.payload_json != "")
        .update({Delivery.payload_json: ""}, synchronize_session=False)
    )
    session.query(Event).filter(Event.received_at < cutoff).update(
        {Event.raw: {}}, synchronize_session=False
    )
    session.query(FetchedEvent).filter(FetchedEvent.fetched_at < cutoff).update(
        # The identity and the shape stay — exception type, message, release, the counters a brief
        # is built from. What goes is the bulk: frames with their source context, the dependency
        # list, and `extra`.
        {FetchedEvent.frames: [], FetchedEvent.packages: {}, FetchedEvent.extra: {}},
        synchronize_session=False,
    )
    session.commit()
    return int(cleared)


def rotate_secret(session: Session, slug: str) -> str:
    """Issue a new token. Items and events are untouched — rotation is not re-registration."""
    project = _require(session, slug)
    token = generate_token()
    project.webhook_secret_hash = hash_token(token)
    session.commit()
    return token


def disable_project(session: Session, slug: str) -> Project:
    """Deactivate. Never delete: destroying history to unregister a project is a footgun."""
    project = _require(session, slug)
    project.active = False
    session.commit()
    return project


def _require(session: Session, slug: str) -> Project:
    project = session.query(Project).filter(Project.slug == slug).one_or_none()
    if project is None:
        raise CommandError(f"no project called '{slug}'")
    return project


# --- presentation ----------------------------------------------------------------------------


def _print_credential(url: str, slug: str, out: TextIO) -> None:
    print("\n  This URL is the credential. It is shown once and cannot be recovered:\n", file=out)
    print(f"    {url}\n", file=out)
    print("  Paste it into your error tracker as the webhook target.", file=out)
    print(f"  If it leaks or is lost: hullwork projects rotate-secret {slug}\n", file=out)


def _cmd_add(args: argparse.Namespace, session: Session, settings: Settings, out: TextIO) -> int:
    registration = add_project(
        session,
        settings,
        slug=args.slug,
        forge_kind=args.forge,
        repo=args.repo,
        manifest_file=args.manifest,
        out=out,
    )
    print(
        f"Registered '{registration.project.slug}' "
        f"({registration.project.repo} on {registration.project.forge}).",
        file=out,
    )
    lanes = registration.manifest.autofix.lanes
    print(
        f"  Manifest read and valid. Lanes: {len(lanes.green)} green, "
        f"{len(lanes.amber)} amber, {len(lanes.red)} red. "
        f"Agent: {registration.manifest.autofix.agent}.",
        file=out,
    )
    _print_credential(registration.webhook_url(settings.base_url), registration.project.slug, out)
    _report_credentials(session, settings, out, only=registration.project.slug)
    _print_what_is_live(registration, out)
    return 0


def _print_what_is_live(registration: "Registration", out: TextIO) -> None:
    """What this command just turned on, and what it deliberately did not. Item 118.

    **The gap was at first contact.** `set-tracker` already says the first sweep is deliberate, and
    `sweep` refuses the first pass with an explanation — but both sentences are read by somebody who
    already knew to run those commands. The operator who has just registered a repository has a
    credential and two unanswered questions, and on this project's own instance the answer to the
    second one took an hour to find with everything else working.

    The gate itself is right and is not what this changes: sweeping a tracker's backlog unasked is
    three hundred forge issues on somebody's first afternoon.
    """
    slug = registration.project.slug
    agent = registration.manifest.autofix.agent
    attempts = (
        "Nothing will be attempted: `autofix.agent` is `none` in this repository's manifest, which "
        "is the default and a supported way to run this."
        if agent == "none"
        else f"Fixes will be attempted by `{agent}`, as this repository's manifest asks."
    )
    print(
        f"What is live from this moment:\n"
        f"  Errors your tracker posts to that URL are deduplicated, triaged and filed as issues.\n"
        f"  {attempts}\n"
        f"\n"
        f"What is not, and it is on purpose:\n"
        f"  The backlog already in your tracker is untouched. Sweeping it unasked would be three\n"
        f"  hundred issues on your first afternoon, so it takes two deliberate commands:\n"
        f"\n"
        f"    hullwork projects set-tracker {slug} <its name in your tracker>\n"
        f"    hullwork sweep {slug} --confirm      # or --from-now, to start from today\n",
        file=out,
    )


def _cmd_list(args: argparse.Namespace, session: Session, settings: Settings, out: TextIO) -> int:
    projects = session.query(Project).order_by(Project.slug).all()
    if not projects:
        print("No projects registered. Add one with: hullwork projects add --help", file=out)
        return 0
    for project in projects:
        state = "active" if project.active else "disabled"
        # DR-0012's cost, made visible where projects are listed rather than only in a decision
        # record: a repository that declares nothing is a repository whose contributors cannot see
        # what an agent may attempt there.
        held = "  manifest held here" if project.manifest_origin == "operator" else ""
        print(
            f"{project.slug:20} {project.forge:10} {project.repo:35} {state}{held}", file=out
        )
    return 0


def _cmd_disable(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    project = disable_project(session, args.slug)
    print(f"Disabled '{project.slug}'. Its events and items are kept.", file=out)
    return 0


def _cmd_rotate(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    token = rotate_secret(session, args.slug)
    project = _require(session, args.slug)
    manifest = project.manifest or {}
    provider = str((manifest.get("errors") or {}).get("provider", "glitchtip"))
    url = f"{settings.base_url.rstrip('/')}/webhooks/{provider}/{project.slug}/{token}"
    print(f"Rotated the token for '{project.slug}'. The previous one stops working now.", file=out)
    _print_credential(url, project.slug, out)
    return 0


def approve(session: Session, slug: str, item_id: int) -> Item:
    """Let an agent attempt one amber item. One item, named explicitly, by a human.

    A command rather than an endpoint, for the reason registration is one: the operator already has
    the host, and an approval endpoint would be a permanent attack surface for something done by one
    person a handful of times. There is deliberately no `--all`.
    """
    project = _require(session, slug)
    item = (
        session.query(Item)
        .filter(Item.id == item_id, Item.project_id == project.id)
        .one_or_none()
    )
    if item is None:
        raise CommandError(f"'{slug}' has no item {item_id}")

    if item.state is not ItemState.WAITING_APPROVAL:
        # Naming the state it found is the difference between a refusal and a puzzle. An item that
        # is already `ready`, or that a human closed, is the common case here.
        raise CommandError(
            f"item {item_id} is '{item.state.value}', not '{ItemState.WAITING_APPROVAL.value}' — "
            f"only an item waiting for approval can be approved"
        )

    try:
        transition(item, ItemState.READY)
    except IllegalTransitionError as exc:
        # Red reaches here only if a manifest was edited underneath a queued item. The state machine
        # refuses it whatever this command thinks, which is the point of enforcing it there.
        raise CommandError(str(exc)) from exc

    session.commit()
    return item


def requeue(session: Session, slug: str, item_id: int) -> Item:
    """Put a `human-only` item back in the queue when what stopped it was the environment. Item 093.

    **The gap this closes.** `baseline-red` ends an item `human-only` and records `consumed =
    False`, with a reason that tells the operator to fix the suite and try again — and nothing
    offered a way to try again. Item 092 was exactly that case: the suite was red because of
    Hullwork's own sandbox mount options, the mount was fixed, and item #14 sat `human-only`
    holding an attempt it could not spend. The only route was an `UPDATE` against a SQLite file
    inside a Docker volume.

    **Eligibility is the outcome, not the state.** `human-only` is reached from several places and
    they are different claims: a red baseline says *nothing was learned about the bug*, while
    `not-reproducible` and `failed` say the agent looked and this is what it found. Requeueing those
    spends a second attempt on the same evidence, so they are refused — and the refusal names the
    outcome it read, so an operator can disagree with the classification rather than with an exit
    code.

    **Where it goes is `triage.route`'s decision, not this function's.** An amber item goes back to
    `waiting-approval` and needs `approve` again, because the human decision it represents was never
    about the sandbox. Duplicating that mapping here is how a second copy of a policy starts.
    """
    project = _require(session, slug)
    item = (
        session.query(Item)
        .filter(Item.id == item_id, Item.project_id == project.id)
        .one_or_none()
    )
    if item is None:
        raise CommandError(f"'{slug}' has no item {item_id}")

    if item.state is not ItemState.HUMAN_ONLY:
        raise CommandError(
            f"item {item_id} is '{item.state.value}', not '{ItemState.HUMAN_ONLY.value}' — "
            f"requeue is for an item a stopped attempt left with a human"
        )

    last = (
        session.query(Attempt)
        .filter(Attempt.item_id == item.id)
        .order_by(Attempt.id.desc())
        .first()
    )
    if last is None or last.outcome is not AttemptOutcome.BASELINE_RED:
        # `outcome` is nullable: an attempt in flight has none yet, and mypy is right to ask.
        found = (
            last.outcome.value
            if last is not None and last.outcome is not None
            else "no finished attempt at all"
        )
        raise CommandError(
            f"item {item_id}'s last attempt was '{found}', and requeue only takes "
            f"'{AttemptOutcome.BASELINE_RED.value}' — that is the one outcome where nothing was "
            f"learned about the bug, because the project's suite was already failing and the agent "
            f"was never asked. Any other outcome means a second attempt would run on the same "
            f"evidence"
        )
    if last.consumed:
        raise CommandError(
            f"item {item_id}'s attempt was consumed, so it has none left to spend"
        )

    try:
        transition(item, ItemState.REOPENED)
        transition(item, ItemState.TRIAGED)
    except IllegalTransitionError as exc:  # pragma: no cover - both edges are declared legal
        raise CommandError(str(exc)) from exc

    if not item.project.manifest:
        # A project registered before its manifest was stored, or one whose refresh failed. Naming
        # it is the difference between a refusal and a `ManifestError` from four frames down about a
        # file that is empty — which is true and describes nothing the operator can act on.
        raise CommandError(
            f"'{slug}' has no stored manifest, so where this item should go cannot be decided. "
            f"Run `hullwork projects refresh {slug}` and try again"
        )
    manifest = parse_manifest(json.dumps(item.project.manifest))
    triage.route(item, manifest)
    session.commit()
    return item


def release_lease(session: Session) -> str:
    """Give up a lease whose holder is gone, so the next dispatcher does not wait an hour. Item 097.

    **Refuses a lease that is still being renewed**, which is the whole reason this is a command and
    not an `UPDATE`: two dispatchers claiming at once is what the lease exists to prevent, and a
    recovery path that can cause the thing it recovers from is worse than the wait.

    "Alive" here is `ALIVE_SECONDS`, not `LEASE_SECONDS` — a holder that renewed in the last five
    minutes is working right now, whatever its lease is good for. That is the same distinction
    `lease.state` draws for `status`, and using the shorter window means this refuses in exactly the
    case where refusing matters.
    """
    state, when = lease.state(session)
    if state == "alive":
        raise CommandError(
            f"the lease was renewed at {when}, so a dispatcher is working right now — releasing it "
            f"would let a second one claim alongside the first, which is what the lease prevents. "
            f"Stop that dispatcher first."
        )
    if state == "released":
        return "the lease is already free; nothing to do"
    held_by = lease.holder_of(session)
    if held_by is None:
        return "no lease has ever been taken; nothing to do"
    lease.release(session, held_by)
    return (
        f"released the lease held by {held_by} (last renewed {when}). The next dispatcher takes it "
        f"on its next start, and any item that holder had claimed is freed with it."
    )


def _cmd_lease(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    print(release_lease(session), file=out)
    return 0


def _cmd_requeue(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    item = requeue(session, args.slug, args.item)
    print(
        f"Item {item.id} ({item.lane.value}) is now '{item.state.value}'. "
        f"Its attempt was never spent, so it still has one.",
        file=out,
    )
    return 0


def _cmd_approve(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    item = approve(session, args.slug, args.item)
    print(
        f"Item {item.id} ({item.lane.value}) is now '{item.state.value}'. "
        f"The next `hullwork work` run may attempt it once.",
        file=out,
    )
    return 0


def _scope_probe(settings: Settings) -> Callable[[str], bool | None] | None:
    """The audit's way of asking what the **token** may do, or `None` when it cannot ask. Item 073.

    Built here because this is where the credential lives; `credentials` takes it as an argument so
    that module never reads a secret from settings, and so a test can supply both answers.
    """
    if not settings.forge_url or not settings.forge_token:
        return None
    token = settings.forge_token.get_secret_value()
    url = settings.forge_url

    # What the operator declared, because with three forges the URL no longer identifies which one
    # (item 132). The probe still chooses its own request from it.
    declared = settings.forge_kind

    def ask(repo: str) -> bool | None:
        return credentials.token_may_write_code(url, token, repo, declared_kind=declared)

    return ask


def _report_credentials(
    session: Session, settings: Settings, out: TextIO, *, only: str | None = None
) -> list[PushCapability]:
    """Print what the forge says this instance's ingest credential may do to code.

    Called from `status`, and from the two commands that read a manifest — because registering or
    refreshing a project is the moment an operator is choosing a token and can act on the answer.
    """
    findings = credentials.audit(
        session, make_permission_reader(settings), probe=_scope_probe(settings)
    )
    if only is not None:
        findings = [finding for finding in findings if finding.slug == only]

    lines = [line for line in (credentials.describe(finding) for finding in findings) if line]
    # Item 073, and it costs nothing: one token in two variables is a split that is false by
    # arithmetic rather than by inference. Checked here because this is where an operator is already
    # being told about credentials and can act on the answer.
    same = credentials.the_two_tokens_must_differ(
        settings.forge_token.get_secret_value() if settings.forge_token else None,
        settings.forge_code_token.get_secret_value() if settings.forge_code_token else None,
    )
    if same:
        lines.insert(0, same)
    # **The model credential, in the place a person looks when nothing is happening** (item 096).
    # The loop refuses to claim while it is expired and says so once; sixty seconds later that line
    # has scrolled, and `status` is what gets typed next. Naming it here is what makes the refusal
    # findable rather than merely correct.
    #
    # **Through the ownership test, which it was not** (item 105). This read `credential_expired`
    # directly, so the *receiver* — which holds no model credential by design (DR-0009) — announced
    # "no item will be claimed" about a dispatcher that was claiming fine, on every `status`, for
    # as long as the instance ran. Item 091 taught the doctor to say "not from here" and this line
    # never learned it. Now the same `not_from_here` decides, so what survives is what is true from
    # here: a token whose *expiry* has passed is reported from anywhere, because that number is the
    # same in every process, while a credential this process simply does not hold belongs to the
    # dispatcher and is left to `hullwork doctor` run where the dispatcher runs.
    owned = doctor.not_from_here([doctor.model_credential(settings)], session)[0]
    if owned.is_failure:
        lines.insert(0, f"no item will be claimed while this holds — {owned.detail}")
    if lines:
        print("\n  Credentials:", file=out)
        for line in lines:
            print(f"    ! {line}", file=out)
    return findings


def _dispatcher_reporting_line(loop_state: str, reporting: bool | None) -> str:
    """Whether the dispatcher's own errors reach the tracker, in words. Item 110.

    **`/ready` answers this for the receiver by asking itself, and nothing could answer it for the
    dispatcher.** That process listens on nothing (DR-0009), so the decision it makes at start-up
    was visible in the first line of its container output and nowhere else — item 090 built the
    reporting and left an operator no way to see whether it was on.

    Three states, and the third is the point: `None` means *not recorded*, which is what a lease
    taken by an older build says, and reading it as "off" would report a capability as switched off
    on the strength of nothing.
    """
    which = "the dispatcher" if loop_state == "alive" else "the last dispatcher"
    if reporting is None:
        return (
            "whether it reports its own errors was not recorded — the lease predates the column, "
            "and the next dispatcher to start will say"
            if loop_state != "never"
            else "no dispatcher has ever taken the lease, so nothing is recorded about it"
        )
    if reporting:
        return f"{which} reports its own errors to the tracker"
    return (
        f"{which} does **not** report its own errors: HULLWORK_ERROR_DSN reached the receiver or "
        f"nobody, but not this process — the two services are configured separately"
    )


def _cmd_page_token(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Mint the credential that opens the read-only page. Item 122.

    **Refuses to replace an existing one without `--rotate`.** A second person running this to
    "get the link" would silently lock out everybody who has the first, and the failure would look
    like the page being broken rather than like a token having changed under them.
    """
    existing = page.configured(session)
    if existing and not args.rotate:
        raise CommandError(
            "this instance already has a page token, and it cannot be shown again — it was "
            "printed once and only its hash is stored.\n"
            "  To replace it: hullwork page-token --rotate. Every URL handed out so far stops "
            "working the moment you do."
        )

    token = generate_token()
    page.issue(session, hash_token(token))
    # **The trailing slash is part of the URL, not decoration.** Without it the request is answered
    # by a 308 to the same path with one — correct, and invisible in a browser, but a stranger
    # checking the link with `curl` on 2026-08-04 got `HTTP 308  bytes=0` and reasonably concluded
    # they had mangled a credential that by design cannot be shown again. The redirect stays (it is
    # what keeps the token out of the HTML, see `main.page_instance`); what was wrong was printing
    # the one URL that needs it.
    url = f"{settings.base_url.rstrip('/')}{page.PREFIX}/{token}/"

    print("Rotated." if existing else "The page is on.", file=out)
    print("\n  This URL is the credential. It is shown once and cannot be recovered:\n", file=out)
    print(f"    {url}\n", file=out)
    print(
        "  Anyone who has it can read every item, attempt and captured output on this instance.\n"
        "  It is read-only — nothing behind it changes anything — and it is a **shared** key, not\n"
        "  a login: when somebody should stop having it, rotate.\n"
        "\n"
        "  Put a reverse proxy with TLS in front before handing it to anybody: the token is a\n"
        "  path segment, so plain HTTP puts it on the wire in the clear.",
        file=out,
    )
    return 0


def _cmd_status(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Ask the instance how it is, and mean it — the exit code is the answer.

    `/ready` serves the same numbers to a probe; this exists because a probe cannot carry the
    detail a human needs to act, and because `deliveries.error` and `items.forge_error` have been
    written faithfully since M1 and read by absolutely nothing. `hullwork status || mail me` in a
    cron line is the whole monitoring story for a single-container tool.

    Deliberately does not consult the running server: an operator debugging a service that will not
    answer needs this to work anyway.
    """
    # **The schema, once, before anything counts anything** (2026-08-04). Against a database with no
    # tables this command printed a raw `sqlite3.OperationalError` traceback — the defect that fed
    # the first real trial. It had *three* causes: `readiness.check`, `work.readiness_notes` and
    # `lease.state`, each querying unguarded. An agent fixed the first correctly, with a test that
    # reproduces, and the traceback survived the other two.
    #
    # Guarding each was the wrong shape, and finding that out is the useful part: the fact is
    # singular. `doctor.database_built` already asks it, compares against what the models declare
    # rather than a list, and exists because of the 2026-07-29 failure where a dispatcher read an
    # empty database beside the real one. Asked here, answered once, in a sentence.
    built = doctor.database_built(session, settings)
    if built.state is doctor.State.BROKEN:
        raise CommandError(built.detail)

    # Spec §8 promised these and there was nowhere for the numbers to come from until item 038.
    # The forge is passed so `status` can say which items point at an issue that no longer exists
    # (item 069). Best-effort by construction: `_issue_resolves` answers "yes" on any failure, so
    # a forge that blinks reports nothing rather than every project as stranded.
    _status_forge = make_forge(settings) if settings.forge_url and settings.forge_token else None
    try:
        dispatcher = work.readiness_notes(
            session,
            code_token_configured=settings.forge_code_token is not None,
            forge=_status_forge,
        )
        # **Asked, not assumed** (item 129). `readiness._forge_state` is module state in whichever
        # process last spoke to the forge; this is a different process from the receiver, so
        # without this the report said `forge: unknown` while `/ready`, served by the receiver,
        # said `ok` about the same forge and the same credential. Two answers about one thing —
        # and `unknown` reads as a state of the forge when it is a fact about who is asking.
        #
        # Measured, not recorded: this process reports and exits, and writing an answer into module
        # state that outlives the report is how the two came to disagree in the first place.
        forge_now = forge_answers(session, _status_forge)
    finally:
        if _status_forge is not None:
            # On the `Forge` protocol since item 068. This was an `attr-defined` ignore whose
            # comment argued that declaring it *"would oblige every future adapter to have one"* —
            # true, and the point: an adapter that opens connections has to close them, and leaving
            # it off the protocol removed the check rather than the obligation.
            _status_forge.close()
    # Item 075, gate 4. Three states, because the middle one is the one worth having: an operator
    # looking at waiting items could not tell a dispatcher that was busy from one that died four
    # days ago, and those need opposite reactions.
    report = readiness.check(
        session,
        settings,
        error_reporting=settings.error_dsn is not None,
        forge_state=forge_now,
    )
    loop_state, loop_seen = lease.state(session)
    loop_line = {
        "alive": f"a dispatcher is running (last seen {loop_seen})",
        # Item 078. Distinct from `stale`, because the remedies differ: a holder that died may have
        # left items claimed mid-attempt, and one that was stopped left nothing behind.
        "released": "no dispatcher is running; the last one was stopped and gave up its lease",
        "stale": (
            f"no dispatcher has run since {loop_seen}, and the last one did not give up its lease "
            f"— it was killed, so check for items it claimed mid-attempt"
        ),
        "never": "no dispatcher has ever run on this instance",
    }[loop_state]

    if args.json:
        findings = credentials.audit(
        session, make_permission_reader(settings), probe=_scope_probe(settings)
    )
        compose = DEFAULT_COMPOSE_FILE if DEFAULT_COMPOSE_FILE.exists() else None
        gaps = doctor.environment_gaps(
            settings, env_file=DEFAULT_ENV_FILE, compose_file=compose
        )
        payload = report.as_dict()
        payload["dispatcher_loop"] = {
            "state": loop_state,
            "last_seen": loop_seen,
            # `null` is "not recorded", which is not `false`. Item 110.
            "error_reporting": lease.reporting_of(session),
        }
        json_merged, json_holding, json_recurred = recurrence.counted(session)
        payload["attempts"] = outcomes.funnel(session).as_dict()
        spent = spend.per_instance(
            session.query(Attempt).all(), spend.Prices.from_settings(settings)
        )
        payload["spend"] = {
            "measured_attempts": spent.measured,
            "context_served_tokens": spent.total.context_served if spent.total else None,
            "total": str(spent.total_cost) if spent.total_cost else None,
            "counted_against_an_item": str(spent.fair_try_cost) if spent.fair_try_cost else None,
            "fair_try_attempts": spent.fair_try,
            # Seconds, because a JSON consumer computes its own units and `12m 3s` is for a person.
            "median_seconds": (
                int(spent.median_duration.total_seconds()) if spent.median_duration else None
            ),
            "slowest_seconds": int(spent.slowest.total_seconds()) if spent.slowest else None,
            "no_model_answered": spent.no_model_answered,
        }
        payload["merged_fixes"] = {
            "merged": json_merged,
            "holding": json_holding,
            "recurred": json_recurred,
            # Item 121: without it, `merged` reads as the number that can still hold.
            "cannot_be_decided": recurrence.undecided(session),
            "window_days": recurrence.WATCH_DAYS,
        }
        payload["dispatcher"] = [{"note": n.text, "degraded": n.degraded} for n in dispatcher]
        payload["credentials"] = [
            {"project": f.slug, "ingest_can_write_code": f.can_push, "agent": f.agent}
            for f in findings
        ]
        payload["environment"] = [
            {"variable": g.check, "state": g.state.value, "detail": g.detail} for g in gaps
        ]
        print(json.dumps(payload, indent=2, default=str), file=out)
        degraded = (
            any(f.is_degradation for f in findings)
            or any(n.degraded for n in dispatcher)
            or doctor.failed(gaps)
        )
        return 1 if not report.ready or report.gaps or degraded else 0

    # **Three words, because there are three answers**, and the middle one used to be missing. An
    # instance that was never finished being configured is not broken, and calling it `DEGRADED`
    # collided with `doctor` reporting `SOUND` about the same instance seconds later — a stranger
    # read both on 2026-08-04 and assumed one of the two was buggy. `NOT CONFIGURED` is the honest
    # third answer, and it still exits 1: monitoring must fire on an instance that can never file
    # anything, which is the whole point of `hullwork status || mail me`.
    if not report.ready:
        verdict = "DEGRADED"
    elif report.gaps:
        verdict = "NOT CONFIGURED"
    else:
        verdict = "READY"
    print(f"{verdict}  (hullwork {report.version})", file=out)
    for problem in report.problems:
        print(f"  ! {problem}", file=out)
    for gap in report.gaps:
        # A different mark, because it is a different kind of thing: nothing broke, something was
        # never supplied. `/ready` deliberately still answers 200 on these — see `Readiness.gaps`.
        print(f"  ? {gap}", file=out)

    print(
        f"\n  forge: {report.forge}   error reporting: {'on' if report.error_reporting else 'off'}"
        f"   sweep: every {report.sweep_interval_s}s"
        # Item 122. An operator has to be able to tell "nobody can read this instance over HTTP"
        # from "somebody can and I have forgotten who", and the page is invisible by design: it
        # answers 404 to anybody without the token, including to whoever is looking for it.
        f"   page: {'on' if page.configured(session) else 'off'}",
        file=out,
    )
    print(
        f"  backlog: {report.backlog} item(s) owed an issue"
        + (f", oldest {int(report.backlog_oldest_age_s)}s" if report.backlog_oldest_age_s else ""),
        file=out,
    )
    print(f"  deliveries carrying an error: {report.failed_deliveries}", file=out)

    # M9, and the one line in `status` that is about outcomes rather than plumbing. Three numbers
    # rather than a rate: this repository never publishes a success rate, each instance computes its
    # own on its own code (DR-0005), and "holding" is deliberately not "merged minus recurred" —
    # `recurrence.counted` explains why an unasked item belongs in neither column.
    merged_fixes, holding, recurred = recurrence.counted(session)
    # **The fourth number is not decoration** (item 121). This instance had four merged fixes and
    # three that could ever produce a verdict; printing only the first three invites a reader to
    # expect four the day the window closes.
    cannot = recurrence.undecided(session)
    if merged_fixes:
        print(
            f"  merged fixes: {merged_fixes}   held the {recurrence.WATCH_DAYS}-day window: "
            f"{holding}   came back: {recurred}"
            + (f"   cannot be decided: {cannot}" if cannot else ""),
            file=out,
        )

    # Item 119, and the same question as the line above at a different distance: that one is about
    # fixes that landed, this one about what became of every attempt that was made. Counts, never a
    # percentage — `outcomes` says why, and the two most important numbers in it are the ones a
    # cheerful version would leave out: the runs that never counted, and the rehearsals.
    attempts_said = outcomes.lines(outcomes.funnel(session))
    if attempts_said:
        print("\n  Attempts:", file=out)
        for line in attempts_said:
            print(f"    - {line}", file=out)

    # What they cost, under what became of them, because the two are read together (item 133): a
    # spend without outcomes is a bill and outcomes without a spend cannot be decided about.
    spent = spend.per_instance(
        session.query(Attempt).all(), spend.Prices.from_settings(settings)
    )
    for line in spend.lines(spent):
        print(line, file=out)

    # **What the humans decided**, which is the half the funnel above cannot see (item 138). Printed
    # under it because the order is the story: what Hullwork did, what it cost, what a person made
    # of it.
    reviewed_lines = outcomes.review_lines(outcomes.reviewed(session))
    if reviewed_lines:
        print("\n  Reviewers:", file=out)
        for line in reviewed_lines:
            print(f"    - {line}", file=out)

    # The dispatcher is a second program (spec M2 §1), so its state is invisible to `/ready` — which
    # runs inside the service and has no way to know whether anything ever picks work up.
    #
    # **Printed unconditionally, and it was not.** `loop_line` used to live inside `if dispatcher:`,
    # so whether a dispatcher is alive was reported only when something else was already worth
    # saying. Measured when item 077 cleared the last note in production: `status` went to exit 0
    # and stopped mentioning the dispatcher at all — while it was stopped. That is the failure item
    # 075's fourth gate exists to prevent, arrived at from the other side: an operator could not
    # tell a quiet healthy instance from one with nothing running.
    print("\n  Dispatcher:", file=out)
    for note in dispatcher:
        mark = "!" if note.degraded else "-"
        print(f"    {mark} {note.text}", file=out)
    print(f"    - {loop_line}", file=out)
    print(f"    - {_dispatcher_reporting_line(loop_state, lease.reporting_of(session))}", file=out)

    stranded = (
        session.query(Item)
        # The same exclusion the drain makes (item 084): a closed item is owed nothing, and listing
        # what will never be retried tells an operator to fix something that needs no fixing.
        .filter(Item.forge_sync_pending.is_(True), Item.state != ItemState.DONE)
        .order_by(Item.forge_attempts.desc())
        .limit(5)
        .all()
    )
    if stranded:
        print("\n  Still owed an issue:", file=out)
        for item in stranded:
            why = f" — {item.forge_error}" if item.forge_error else ""
            print(f"    #{item.id} after {item.forge_attempts} attempt(s){why[:120]}", file=out)

    broken = (
        session.query(Delivery)
        .filter(Delivery.error.is_not(None))
        .order_by(Delivery.id.desc())
        .limit(5)
        .all()
    )
    if broken:
        print("\n  Deliveries that failed:", file=out)
        for delivery in broken:
            state = "given up" if delivery.processed_at else "will retry"
            print(f"    #{delivery.id} {state} — {(delivery.error or '')[:100]}", file=out)

    muted = [
        project.slug
        for project in session.query(Project).all()
        if str(((project.manifest or {}).get("notify") or {}).get("channel", "none"))
        in _UNDELIVERABLE_CHANNELS
    ]
    if muted:
        print(
            f"\n  ! these projects ask for a channel this build cannot deliver to: {muted}",
            file=out,
        )

    # Always asked, never only when something else is already wrong: the whole failure mode here is
    # a guarantee nobody checks (item 031).
    findings = _report_credentials(session, settings, out)

    # Item 074. Cheap enough for a command in a cron — two local file reads — and it corrects the
    # readiness notes above rather than adding to them: `tracker configured: false` is true of this
    # process and can be false of the machine, and nothing said so.
    gaps = _report_environment(settings, out)

    # The dispatcher's notes count. A perfectly clear sentence about work nothing will ever pick
    # up, printed above an exit code of zero, is the shape of failure item 019 was written to end —
    # and it is what the first version of this did.
    degraded = (
        not report.ready
        # **`report.gaps` here too, and forgetting it once is why this comment exists.** The verdict
        # word and the `--json` exit code were changed together and this branch was not, so
        # `NOT CONFIGURED` printed above an exit code of zero — the exact shape item 019 was written
        # to end, and the shape of the defect this whole change fixes.
        or bool(report.gaps)
        or any(f.is_degradation for f in findings)
        or any(note.degraded for note in dispatcher)
        or doctor.failed(gaps)
    )
    return 1 if degraded else 0


#: Parse in the manifest, refused at delivery. A project configured for one believes it is being
#: notified and is not, which is worth saying out loud in a status report.
_UNDELIVERABLE_CHANNELS = frozenset({"telegram", "email"})


#: Where the doctor looks for the two files it compares, relative to where it was invoked. Both are
#: in the deployment's own directory — the deployment notes tell the operator to run from there, and
#: `pydantic-settings` already reads `.env` the same relative way.
DEFAULT_ENV_FILE = Path(".env")
DEFAULT_COMPOSE_FILE = Path("docker-compose.yml")


def _cmd_doctor(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Why an instance that is running will not work. Item 074.

    A separate command from `status` because the two make opposite trades. `status` consults no
    daemon, spends no subprocess, and lives in people's crons; the doctor spends a Docker call, a
    forge call per repository and two file reads, because a person types it when something is
    already wrong and the answer is worth more than the cost.

    Exit code is the answer, as everywhere else — and an `unknown` never sets it. That is item 073's
    lesson: a warning wired into an exit code with no action available to clear it is not a signal.
    """
    # **Configuration before the working directory** (item 144). The flags still win, because
    # somebody running this from a host shell knows where the files are. What changed is the
    # fallback: it used to be the working directory, which inside a container holds neither file, so
    # the check silently never ran on any real deployment. Now the instance can say where they are.
    env_file = Path(
        args.env_file or settings.deployment_env_file or DEFAULT_ENV_FILE
    )
    named_compose = args.compose_file or settings.deployment_compose_file
    if named_compose:
        compose_file: Path | None = Path(named_compose)
    else:
        compose_file = DEFAULT_COMPOSE_FILE if DEFAULT_COMPOSE_FILE.exists() else None

    code_forge = make_code_forge(settings)
    # The **ingest** credential for the inventory check: asking whether an issue still exists is a
    # read on issues, which is exactly what that token is for. Handed over as `IssueReader`, so this
    # command cannot file or label anything while it is looking.
    issue_reader = make_forge(settings)
    try:
        findings = doctor.examine(
            session,
            settings,
            code_forge=code_forge,
            issue_reader=issue_reader,
            env_file=env_file,
            compose_file=compose_file,
        )
    finally:
        for client in (code_forge, issue_reader):
            close = getattr(client, "close", None) if client is not None else None
            if close is not None:
                close()

    if args.json:
        print(
            json.dumps(
                [{"check": f.check, "state": f.state.value, "detail": f.detail} for f in findings],
                indent=2,
            ),
            file=out,
        )
        return 1 if doctor.failed(findings) else 0

    broken = [f for f in findings if f.state is doctor.State.BROKEN]
    print(
        f"{'AILING' if broken else 'SOUND'}  ({len(findings)} check(s), {len(broken)} broken)",
        file=out,
    )
    for finding in findings:
        mark = {
            doctor.State.OK: "ok      ",
            doctor.State.BROKEN: "BROKEN  ",
            doctor.State.UNKNOWN: "unknown ",
            doctor.State.EXPECTED: "expected",
        }[finding.state]
        print(f"\n  {mark} {finding.check}", file=out)
        print(f"           {finding.detail}", file=out)
    return 1 if broken else 0


def _cmd_republish(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Finish publishing a verdict the dispatcher reached and could not send. Item 077.

    A command rather than something the dispatcher retries on its own, and the reason is DR-0003's
    arithmetic: the attempt is **already spent**. An automatic retry loop against an issue that does
    not exist would run for the life of the instance, and the operator would never learn that the
    destination is the problem. This is typed once, by somebody who can also read the answer.
    """
    stranded = work.unpublished_verdicts(session)
    if args.attempt is not None:
        stranded = [attempt for attempt in stranded if attempt.id == args.attempt]
        if not stranded:
            raise CommandError(
                f"attempt {args.attempt} is not waiting to publish anything. "
                f"`hullwork status` lists the ones that are."
            )
    if not stranded:
        print("No verdict is waiting to be published.", file=out)
        return 0

    if args.give_up:
        if args.attempt is None:
            # The same refusal `approve` makes, for the same reason: writing off a first-class
            # result is a decision about one thing, and a `--give-up` that took the whole list
            # would be a way to make an inconvenient verdict disappear in one keystroke.
            raise CommandError(
                "--give-up needs --attempt N. Writing off a verdict is a decision about one "
                "attempt, so there is no way to do it in bulk."
            )
        if not args.why:
            raise CommandError(
                "--give-up needs --why '<reason>'. It is recorded on the attempt, and a decision "
                "with no reason attached is indistinguishable from a bug six months from now."
            )
        try:
            work.give_up_publishing(session, stranded[0], why=args.why)
        except work.PublicationError as exc:
            raise CommandError(str(exc)) from exc
        print(
            f"Attempt {stranded[0].id}: publication given up, and why is recorded on the attempt. "
            f"The verdict is untouched and `hullwork status` stops reporting it.",
            file=out,
        )
        return 0

    forge = make_forge(settings)
    # **The code credential too, since item 079.** A `pr-open` verdict is finished by opening a pull
    # request, which is a code write; a comment is the ingest one (spec M2 §1). `None` where it is
    # not configured — which is the receiver, by design — and `republish` says so by name rather
    # than failing on an attribute four layers down.
    code_forge = make_code_forge(settings)
    failures = 0
    try:
        for attempt in stranded:
            item = session.get(Item, attempt.item_id)
            project = session.get(Project, item.project_id) if item else None
            if project is None:  # pragma: no cover - a foreign key makes this unreachable
                raise CommandError(f"attempt {attempt.id} belongs to no registered project")
            try:
                where = work.republish(
                    session,
                    attempt,
                    forge=forge,
                    code_forge=code_forge,
                    repo=project.repo,
                    secrets=_redactions(settings),
                )
            except work.PublicationError as exc:
                # Reported and carried on: one unpublishable verdict must not stop the others, the
                # same rule `drain_pending` follows for one bad payload.
                failures += 1
                print(f"attempt {attempt.id}: {exc}", file=out)
                continue
            print(f"attempt {attempt.id}: published to {project.repo}{where}", file=out)
    finally:
        if forge is not None:
            forge.close()
        if code_forge is not None:
            code_forge.close()
    return 1 if failures else 0


def _cmd_sweep(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Read the tracker's unresolved list and file what is missing. DR-0011, item 080.

    **A command as well as a clock**, because the first pass of a project is not like the others. A
    project with three hundred open issues would become three hundred forge issues in one pass, and
    a tool that does that on its first afternoon gets uninstalled that evening — DR-0006's adoption
    failure arriving from the other direction. So the first pass shows its count and does nothing
    until an operator says go; every pass after it runs on the receiver's own clock.
    """
    inventory = make_inventory(settings)
    if inventory is None:
        raise CommandError(
            "no tracker inventory is configured. It needs HULLWORK_TRACKER_URL, "
            "HULLWORK_TRACKER_TOKEN and HULLWORK_TRACKER_ORG — the organisation cannot be "
            "discovered, because the least-privilege token is refused the route that would list it."
        )

    project = _require(session, args.slug) if args.slug else None
    if project is not None and not project.tracker_project:
        raise CommandError(
            f"'{args.slug}' has no tracker project set, so there is nothing to sweep. "
            f"`hullwork projects set-tracker {args.slug} <name-in-the-tracker>`"
        )

    if args.from_now:
        # The answer for a project with a real backlog: adopt the present and ignore the history.
        # Explicit rather than a default, because the history is where the bugs that have been
        # failing longest live, and those are the ones worth having.
        if project is None:
            raise CommandError("--from-now needs a project slug: it changes that project's mark")
        project.tracker_swept_until = datetime.now(UTC)
        session.commit()
        print(
            f"'{project.slug}' now sweeps from this moment on. Its existing unresolved issues will "
            f"not be filed — run without --from-now to take them in.",
            file=out,
        )
        return 0

    first = project is not None and project.tracker_swept_until is None
    results = sweep_inventory(
        session,
        inventory,
        limit=args.limit,
        slug=args.slug,
        first_pass=True,
        dry_run=not args.confirm and first,
    )
    if not results:
        print(
            "Nothing to sweep: no active project has a tracker project set.",
            file=out,
        )
        return 0

    failed = 0
    for result in results:
        if result.error:
            failed += 1
            print(f"{result.project}: could not read the tracker — {result.error}", file=out)
            continue
        if not args.confirm and first:
            print(
                f"{result.project}: {result.created} issue(s) would be filed and "
                f"{result.deduplicated} are already known. **Nothing was written.**\n"
                f"  This is the first sweep of this project, so it needs --confirm. "
                f"Or --from-now to start from today and leave the backlog alone.",
                file=out,
            )
            continue
        print(
            f"{result.project}: filed {result.created}, already knew {result.deduplicated}"
            + (f", swept up to {result.swept_until}" if result.swept_until else ""),
            file=out,
        )
    return 1 if failed else 0


def _cmd_set_tracker(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Name this project in the tracker. Instance configuration, never the manifest (DR-0011)."""
    project = _require(session, args.slug)
    project.tracker_project = args.tracker_project or None
    session.commit()
    if project.tracker_project is None:
        print(f"'{project.slug}' will no longer be swept.", file=out)
        return 0
    print(
        f"'{project.slug}' reads its inventory from tracker project "
        f"'{project.tracker_project}'. Nothing is swept until `hullwork sweep {project.slug}` "
        f"runs once — the first pass of a project is deliberate.",
        file=out,
    )
    return 0


def _report_environment(settings: Settings, out: TextIO) -> list["doctor.Finding"]:
    """The cheap half of the doctor, printed by `status` too. Item 074's own acceptance criterion.

    Two local file reads and no call to anything, which is why it is allowed in a command that lives
    in a cron. It belongs next to the readiness notes because those are the ones it corrects:
    `tracker configured: false` is true of this process and can be false of the machine, and that
    sentence is what sent somebody looking in the wrong place for a day.
    """
    compose = DEFAULT_COMPOSE_FILE if DEFAULT_COMPOSE_FILE.exists() else None
    gaps = doctor.environment_gaps(settings, env_file=DEFAULT_ENV_FILE, compose_file=compose)
    if not gaps:
        return []
    print("\n  Configuration that did not arrive:", file=out)
    for finding in gaps:
        mark = "!" if finding.state is doctor.State.BROKEN else "-"
        print(f"    {mark} {finding.check}: {finding.detail}", file=out)
    return gaps


def _cmd_refresh(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    # **The header first, then what changed.** Measured on the live instance: the runtime diff came
    # out above the line saying which project had been re-read, so indented detail arrived before
    # anything it could be detail *of*. The work happens either way; the reading order is the whole
    # point of printing it.
    where = "the file you handed over" if args.manifest else "the default branch"
    print(f"Re-read the manifest for '{args.slug}' from {where}.", file=out)
    manifest = refresh_manifest(
        session, settings, args.slug, manifest_file=args.manifest, out=out
    )
    lanes = manifest.autofix.lanes
    print(
        f"  Lanes: {len(lanes.green)} green, {len(lanes.amber)} amber, {len(lanes.red)} red. "
        f"Agent: {manifest.autofix.agent}.",
        file=out,
    )
    # Naming an agent here is the moment the credential split starts protecting something real.
    _report_credentials(session, settings, out, only=args.slug)
    return 0




def _cmd_propose(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Print a manifest read from the repository's own CI configuration. Item 107.

    **The mechanism of "fácil y autónomo"**, and the reason it prints rather than writes: a
    manifest belongs in the project's repository, committed by somebody who read it. A proposer
    that committed would be a much larger promise — and DR-0006's rule, that what was inferred
    stays commented, only means anything if a person is the one who uncomments it.

    Takes a repository rather than a registered project on purpose: this is what somebody runs
    *before* they have a project, which is when they need it.
    """
    del session
    subject = args.checkout or args.repo
    if args.checkout:
        proposed = propose_from_local_ci(Path(args.checkout).resolve())
    else:
        forge = _forge_for(settings, args.forge)
        try:
            proposed = propose_from_ci(forge, args.repo)
        finally:
            forge.close()

    if proposed is None:
        msg = (
            f"nothing in {subject} proposes a manifest: no CI configuration was found at "
            f"{', '.join(propose.CI_LOCATIONS)}, or the one there says nothing this reader "
            f"recognises.\n"
            f"  That is not a refusal to connect the project — it means the manifest has to be "
            f"written by hand. `docs/hullwork-yml.md` is the reference, and the field that decides "
            f"whether anything can be built is `runtime.base`: an image your tests already run in."
        )
        raise CommandError(msg)

    print(proposed, file=out)
    return 0


def _cmd_lanes(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Show the derived policy applied to this repository's own directories. M8, item 104.

    **The point of the command.** The policy that decides whether an agent may touch a file is not
    written in the project's manifest any more — it is the instance's, in `hullwork/territory.py`.
    An operator who cannot see it applied to *their* code is being asked to trust a paragraph, and
    this project's first principle is that trust is the product. So: fetch the tree, run the policy
    over it, print what it claims and why.

    Read-only and stores nothing. A derived policy kept on disk would be a snapshot of "which code
    is dangerous", and the module explains why that fails in the direction that matters.
    """
    project = session.scalars(select(Project).where(Project.slug == args.slug)).one_or_none()
    if project is None:
        msg = f"no project called '{args.slug}' — `hullwork projects list` shows the ones there are"
        raise CommandError(msg)

    forge = _forge_for(settings, project.forge)
    try:
        # The adapter resolves the default branch and its head itself, and reports which commit it
        # read on the `Tree`. One call rather than three, and the listing cannot end up describing a
        # different commit from the policy applied to it.
        listing = forge.tree(project.repo)
    except ForgeError as exc:
        msg = f"could not read the tree of {project.repo}: {exc}"
        raise CommandError(msg) from exc
    finally:
        forge.close()

    override = Manifest.model_validate(project.manifest).autofix.lanes.ordinary
    return _print_lanes(
        list(listing.paths),
        subject=f"{project.repo} at {listing.ref[:12]}",
        truncated=listing.truncated,
        override=override,
        out=out,
    )


def _lanes_entry(args: argparse.Namespace, settings: Settings, out: TextIO) -> int:
    """Standalone when a checkout was named, database-backed when a slug was.

    Both live behind one command because they answer one question. A second subcommand for the
    credential-free form would make the honest order — read the policy, *then* decide — look like a
    lesser variant of the real thing, when it is the one an evaluator should reach first.
    """
    if args.checkout:
        return _lanes_of_a_checkout(args, settings, out)
    if not args.slug:
        raise CommandError(
            "name a project, or pass --checkout PATH to read the policy over a local directory "
            "without any credential"
        )
    factory = make_session_factory(get_engine(settings.database_url))
    with factory() as session:
        return _cmd_lanes(args, session, settings, out)


def _lanes_of_a_checkout(args: argparse.Namespace, settings: Settings, out: TextIO) -> int:
    """The same policy, over a directory, with **no credential of any kind**.

    **Why this exists** (2026-08-04). `projects lanes` is what the README tells you to run before
    trusting an instance with a repository — the strongest thing this product says for itself — and
    it needed a registered project, which needs `projects add`, refused without a forge token. So
    the one check that answers *may an agent touch my code* could only be run **after** handing over
    a credential. For a product whose first principle is that trust is the product, that order is
    backwards, and a stranger evaluating it said so.

    Nothing here reaches the network or the database. The policy is a function of a path
    (`territory.py`), so the tree can come from anywhere — the forge above, or `git ls-files` here.
    """
    del settings
    checkout = Path(args.checkout).resolve()
    if not checkout.is_dir():
        raise CommandError(f"{checkout} is not a directory")

    listed = subprocess.run(  # noqa: S603
        ["git", "-C", str(checkout), "ls-files"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode != 0:
        # Tracked files, to match what a forge would serve. A directory walk would classify
        # `.venv/` and `node_modules/`, and a list padded with what the forge never sees is a
        # different answer wearing the same shape.
        raise CommandError(
            f"could not list the files in {checkout}: it is not a git checkout, and this reads "
            f"tracked files so that the answer matches what a forge would serve.\n"
            f"  {listed.stderr.strip()}"
        )
    paths = [line for line in listed.stdout.splitlines() if line]

    override: list[str] = []
    manifest_file = checkout / MANIFEST_FILENAME
    if manifest_file.is_file():
        try:
            override = list(
                parse_manifest(
                    manifest_file.read_text(encoding="utf-8"), source=str(manifest_file)
                ).autofix.lanes.ordinary
            )
        except ManifestError as exc:
            # Reported, not fatal: the question asked is what the *derived* policy claims, and that
            # answer does not depend on the manifest parsing. Refusing here would withhold the whole
            # report over an override.
            print(f"  ! {exc}\n  The derived policy below does not depend on it.", file=out)
    return _print_lanes(paths, subject=str(checkout), truncated=False, override=override, out=out)


def _print_lanes(
    paths: list[str], *, subject: str, truncated: bool, override: list[str], out: TextIO
) -> int:
    """One renderer for both sources, so the two cannot drift into different answers."""
    claimed = territory.sensitive_tree(paths)
    print(
        f"{subject} — {len(paths)} file(s), "
        f"{len(claimed)} that this instance keeps a human on:",
        file=out,
    )
    if truncated:
        # Said before the list, not after it. An operator who reads a complete-looking list and only
        # then learns it was partial has already formed the wrong belief.
        print(
            "  ! the forge did not serve the whole tree, so this list is incomplete — what is "
            "missing is unclassified here, not classified as ordinary",
            file=out,
        )
    by_rule: dict[str, list[str]] = {}
    for path, rule in claimed:
        by_rule.setdefault(rule.pattern, []).append(path)
    for pattern, paths in by_rule.items():
        why = next(r.why for r in territory.POLICY if r.pattern == pattern)
        print(f"\n  {pattern} — {why}", file=out)
        for path in paths[:12]:
            print(f"    {path}", file=out)
        if len(paths) > 12:
            print(f"    … and {len(paths) - 12} more", file=out)

    if override:
        print(
            f"\n  This project overrides the derived policy for: {', '.join(override)} "
            f"(autofix.lanes.ordinary)",
            file=out,
        )
    if not claimed:
        print(
            "\n  Nothing in this tree matches the derived policy. Errors here are decided by the "
            "reserved subjects, the manifest's own rules, and `autofix.unmatched`.",
            file=out,
        )
    return 0


def _redactions(settings: Settings) -> list[str]:
    """Every credential this process holds, for the renderer to blank on sight.

    Not imported from `main`: that module pulls FastAPI in, and the CLI has no business needing a
    web framework to print a report. Same list, built where it is used — as `work.run` already does.
    """
    return [
        value.get_secret_value()
        for value in (
            settings.forge_token, settings.forge_code_token,
            settings.tracker_token, settings.model_key,
        )
        if value is not None
    ]


def _rehearsal_report(session: Session, outcome: "work.Outcome", *, secrets: list[str]) -> str:
    """Render one rehearsed attempt for a terminal, from what is in the database."""
    from hullwork.evidence import terminal_report
    from hullwork.models import Attempt, Item

    item_id = outcome.item_id
    item = session.get(Item, item_id)
    attempt = session.execute(
        select(Attempt).where(Attempt.item_id == item_id).order_by(Attempt.id.desc()).limit(1)
    ).scalar_one_or_none()
    if item is None or attempt is None:  # pragma: no cover - both were just written
        return f"item {item_id}: {outcome.outcome.value}"
    return terminal_report(
        item,
        attempt,
        detail=outcome.detail,
        written_to=outcome.pull_request,
        secrets=secrets,
    )


def _cmd_config(args: argparse.Namespace, settings: Settings, out: TextIO) -> int:
    """What this instance is set to. Item 146, last of DR-0014's four.

    Standalone like `try`, and for a reason rather than for symmetry: it reads the environment and
    nothing else, so it still answers on a deployment whose database is unreachable — which is one
    of the moments somebody most wants to know what the process actually got.
    """
    from hullwork import settings_report

    for line in settings_report.lines(settings):
        print(line, file=out)
    return 0


def _cmd_try(args: argparse.Namespace, settings: Settings, out: TextIO) -> int:
    """Six phases against a checkout on this host. Item 140, and DR-0006's entry point.

    **No forge, no deployment, no database.** It takes the two things an evaluator already has — a
    checkout and a stack trace — and needs from them only what cannot be faked: the Docker daemon
    and a model credential.
    """
    from hullwork import trial, work

    checkout = Path(args.checkout).resolve()
    if not checkout.is_dir():
        raise CommandError(f"{checkout} is not a directory")

    # `-` is stdin, because a stack trace is already in a terminal and the pipe is the shortest
    # path from *I have this error* to *show me*.
    if args.error == "-":
        trace = sys.stdin.read()
    else:
        source = Path(args.error)
        if not source.is_file():
            raise CommandError(f"{source} is not a file; use `-` to read the trace from stdin")
        trace = source.read_text(encoding="utf-8", errors="replace")

    into = Path(args.into).resolve() if args.into else checkout.parent / "hullwork-trial"
    try:
        outcome = trial.run(settings, checkout, trace, into=into, approve=args.approve)
    except trial.NotForAnAgentError as exc:
        # Not an error: triage ran and decided a human should look. Exit 0, because the command did
        # what it promised — it showed what a real instance would do with this error.
        print(f"\nNot attempted. {exc}", file=out)
        return 0
    except ValueError as exc:  # an empty trace: the one input error worth its own sentence
        raise CommandError(str(exc)) from exc
    except ManifestError as exc:
        # **`ManifestError` is not a `ValueError`**, so the clause above never caught it and an
        # invalid `hullwork.yml` came out of the newcomer's first command as a raw traceback through
        # four frames of PyYAML internals — a mistake in their file, wearing the costume of a crash
        # in ours. Measured on a stranger evaluating the product on 2026-08-04.
        raise CommandError(str(exc)) from exc
    except work.WiringError as exc:
        raise CommandError(str(exc)) from exc

    verdict = getattr(outcome, "outcome", outcome)
    print(f"\n{verdict}. What it produced is under {into}.", file=out)
    print(
        "  Nothing was published and no forge was contacted. The artefact there is the same one a "
        "pull request would carry.\n"
        "  A real instance shows this and the rest — cost, policies, review debt — on a page: "
        "`hullwork page-token` (DR-0014).",
        file=out,
    )
    # A trial cannot consume an item, so its exit code answers a different question from `work`'s:
    # did the sequence run, not was a fix found. Not reproducing is a legitimate answer here.
    return 0


def _cmd_work(args: argparse.Namespace, session: Session, settings: Settings, out: TextIO) -> int:
    """The dispatcher: attempt what is ready, and say what happened. **The second program.**

    Spec M2 §1 ships Hullwork as two programs with different privileges, and until now only one of
    them could be invoked — while `hullwork status`, `hullwork approve` and the notes all
    told the operator to run this one. The same defect as the `lint` gate that ran nothing: a
    guardrail, or here a whole program, that existed only in prose.

    The exit code is the answer, as it is for `status`. Nothing to do is a zero; a reason nothing
    *could* be done is not, because "0 items attempted" above an exit code of zero is precisely the
    shape of failure item 019 was written to end.
    """
    if args.no_publish and args.release_stale:
        raise CommandError("--no-publish and --release-stale do nothing together; pick one")
    if getattr(args, "loop", False):
        if args.release_stale:
            raise CommandError(
                "--loop releases stale items on every start, so --release-stale adds nothing"
            )
        return _work_loop(args, session, settings, out)
    if args.release_stale:
        freed = work.release_stale(session)
        if freed:
            print(
                f"Released {len(freed)} stale item(s): {freed}. Their attempt records are intact, "
                f"and none of them counted.",
                file=out,
            )
        else:
            print("No item has been in-progress long enough to be stale.", file=out)
        return 0

    try:
        rehearse_into = Path("hullwork-rehearsals").resolve() if args.no_publish else None
        if rehearse_into is not None:
            print(
                f"Rehearsing: every gate runs, nothing is published, and no item loses its "
                f"attempt. Output under {rehearse_into}.",
                file=out,
            )
        outcomes = work.run(
            session, settings, limit=args.limit, slug=args.project, rehearse_into=rehearse_into
        )
    except work.WiringError as exc:
        # Configuration and infrastructure, not the agent. Nothing was claimed and nothing was
        # spent, so the message has to be enough to act on.
        raise CommandError(str(exc)) from exc
    except SandboxError as exc:
        raise CommandError(f"the sandbox is not usable: {exc}") from exc
    except ImageBuildError as exc:
        # The build output is the diagnosis — a failing `RUN` line and what it printed — and it is
        # the most likely first-run failure after `docker` itself. Printing the message without it
        # leaves an operator with "could not build the image" and nothing to act on.
        tail = "\n".join(exc.output.strip().splitlines()[-25:])
        raise CommandError(f"{exc}\n\n{tail}") from exc

    if not outcomes:
        print("Nothing is ready to attempt.", file=out)
        notes = work.readiness_notes(
            session, code_token_configured=settings.forge_code_token is not None
        )
        for note in notes:
            print(f"  {'!' if note.degraded else '-'} {note.text}", file=out)
        return 1 if any(note.degraded for note in notes) else 0

    for outcome in outcomes:
        if rehearse_into is not None:
            # The whole artefact, in the skin that fits a prompt (item 050). A rehearsal exists to
            # be read, and `pull_request_body` was measured at 532 lines on a five-step fixture —
            # 148 to 171 on the four bodies really published (item 116) — of markdown that does not
            # collapse at a terminal.
            print(_rehearsal_report(session, outcome, secrets=_redactions(settings)), file=out)
            continue
        where = f" → {outcome.pull_request}" if outcome.pull_request else ""
        print(f"item {outcome.item_id}: {outcome.outcome.value}{where}", file=out)
        print(f"  {outcome.detail}", file=out)
    # An attempt that ended `abandoned` did not count, and the operator needs to know the run did
    # not achieve what it was scheduled to do.
    return 1 if any(o.outcome is AttemptOutcome.ABANDONED for o in outcomes) else 0



#: What the loop waits when it found nothing, and the ceiling it backs off to. Adaptive because a
#: fixed interval is equally wrong with a queue and with nothing — the argument against a cron,
#: applied to the thing that replaces it.
LOOP_FLOOR_SECONDS = 5
LOOP_CEILING_SECONDS = 300


def _work_loop(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Stay alive, attempt what becomes ready, and never listen for anything. Item 075, DR-0009.

    **This process binds no socket, and that is what lets it hold a push credential.**
    `main.lifespan` refuses that credential to the receiver because *"this process listens
    on the network and holds it for as long as it runs; the two are kept apart on purpose"*.
    The dangerous property is the pairing, not the duration — so a resident process making
    only outbound calls keeps the guarantee whole. A health endpoint, a metrics port or a
    control socket here would break it silently, so `tests/test_work_loop.py` asserts the
    absence instead of trusting this paragraph.

    Two things the loop owes an operator who is no longer typing the command:

    * **releasing what its dead predecessor claimed**, on every start, because otherwise an
      item sits in-progress for ever and the failure is silent;
    * **saying it is alive**, which it does by renewing the lease — never by answering a
      request.

    And a third, added by item 090: **reporting its own crashes**. This is the half that drives
    Docker, builds images, starts gateways and runs agents, and until that item it reported
    nothing anywhere — every failure in it this week was found by reading logs on the box, which
    is the thing this product exists to stop people doing. Installed here rather than for every
    CLI command on purpose: an interactive command usually fails because of the environment the
    operator is standing in, and a tracker full of that is a tracker nobody reads.
    """
    # **Before the lease, because a dispatcher that cannot work must not hold the right to.**
    # Item 076: the schema belongs to the receiver, which applies migrations in its entrypoint;
    # this process only uses it. Against a database whose tables are not this build's — the usual
    # cause being `HULLWORK_DATABASE_URL` unset, which makes SQLite create an empty file beside the
    # real one — the loop used to start, take the lease, find nothing ready and report a healthy
    # instance for ever. Measured twice on the live instance, both times found by reading rather
    # than by the loop saying anything.
    # First, so a failure in anything below is itself reported — including the refusal underneath.
    reporting = configure_error_reporting(settings)
    if reporting:
        print("Reporting this dispatcher's own errors to the configured tracker.", file=out)

    schema = doctor.database_built(session, settings)
    if schema.state is doctor.State.BROKEN:
        raise CommandError(
            f"refusing to start: {schema.detail}\n"
            f"A dispatcher that claims items against a schema it does not recognise is worse than "
            f"one that will not start. `hullwork doctor` reports the whole environment."
        )

    # **The same rule, for the resource without which nothing works at all** (item 103). A
    # credential that *expired* comes back by itself, and the loop below is right to keep running
    # and refuse to claim (item 096). One that can never be read comes back only when a person
    # changes something — and until then this process stays "Up" while unable to do the one thing it
    # exists to do. Measured on 2026-07-30: forty minutes, ended by somebody reading the tracker.
    #
    # Exiting is not a smaller failure, it is a *visible* one. `restart: unless-stopped` turns it
    # into a container that reports "Restarting", which is the signal every operator already
    # watches — no cron, no alarm, nothing to install. The alternative was an instance that looked
    # healthy to `docker ps`, to `/ready`, and to `hullwork status` run from the receiver.
    unusable = doctor.credential_never_works(settings)
    if unusable:
        raise CommandError(
            f"refusing to start: {unusable}\n"
            f"This will not fix itself, so this dispatcher is stopping rather than running without "
            f"a model. An expired token is different — that one comes back, and the loop waits for "
            f"it. `hullwork doctor` reports the whole environment."
        )

    holder = lease.new_holder()
    # Read before `acquire`, which overwrites it. A lease that changed hands is the proof that the
    # previous dispatcher is gone (item 097).
    previous = lease.holder_of(session)
    if not lease.acquire(session, holder, error_reporting=reporting):
        _, when = lease.state(session)
        # **The clock time, not a number of seconds** (item 097). "expire after 3600s" needs
        # arithmetic against a timestamp printed two lines up in another format, and this is read by
        # somebody whose service is down. Measured: forty copies of it in the log of a container
        # restarting every few seconds, and not one said when it would clear.
        clears = (
            f" It clears by itself at {when + timedelta(seconds=lease.LEASE_SECONDS):%H:%M} UTC."
            if when
            else ""
        )
        raise CommandError(
            f"another dispatcher holds the lease (last seen {when}); this one is stopping rather "
            f"than claiming items alongside it.{clears}"
        )

    stopping = threading.Event()

    def _stop(signum: int, _frame: object) -> None:
        # Recorded and then honoured between turns, never mid-attempt. A signal that interrupted a
        # running attempt would leave a claimed item and a half-written record — the state
        # `--release-stale` exists to clean up, arrived at by the *normal* way this process ends.
        print(f"signal {signum} received; finishing the current turn", file=out)
        stopping.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    # **The lease just changed hands, which is proof the previous holder is gone** (item 097).
    # `acquire` only succeeds when the old lease expired or was released, so its claims are orphans
    # and there is no reason to make them wait out `STALE_AFTER` — three hours in which the item
    # cannot be attempted by the dispatcher that is now running. Measured on the live instance: a
    # `docker compose stop` mid-attempt left exactly that, and the recovery was a hand-called
    # function with its clock pushed forward.
    took_the_lease = previous not in (None, holder)
    freed = work.release_stale(session, took_the_lease=took_the_lease)
    if freed:
        print(
            f"Released {len(freed)} item(s) claimed by a dispatcher that is gone: {freed}. "
            f"Their attempt records are intact and none of them counted.",
            file=out,
        )
    # **And what that dispatcher left on the host** (item 106, part 4). The same fact licenses both:
    # the lease changing hands is proof the previous holder is gone, so nothing matching these names
    # belongs to a run that is still happening. Measured on the live instance — a `docker compose
    # stop` mid-attempt left a gateway, a network and three volumes, one holding a copy of the model
    # credential, and nothing ever collected them.
    if took_the_lease:
        from hullwork.sandbox import inventory

        left = inventory.reap()
        if left:
            print(
                f"Cleared what the previous dispatcher left on this host: {left.summary()}.",
                file=out,
            )

    print(f"Dispatching continuously as {holder}. Nothing listens on any port.", file=out)
    wait = LOOP_FLOOR_SECONDS
    try:
        credential_complained = False
        while not stopping.is_set():
            if not lease.renew(session, holder):
                raise CommandError(
                    "this dispatcher lost its lease, so another one is running; stopping rather "
                    "than working alongside it"
                )
            # **Before claiming anything, ask whether there is a model to think with** (item 096).
            # Cheap: it reads a file and compares a number to the clock, no request to anybody. The
            # alternative was measured — an instance that had printed "valid until 14:07 UTC" spent
            # an attempt, a clone, an image, a network, a gateway and 21 model calls at 14:31
            # finding out, and did it again a minute later because `abandoned` does not consume the
            # item's attempt.
            #
            # Said **once** per spell rather than once per pass: a refusal logged every sixty
            # seconds is a log nobody reads, and `status` is where a person looks for a stopped
            # instance. Said again when it comes back, because "it started working" is the other
            # half of the same fact.
            expired = doctor.credential_expired(settings)
            if expired:
                if not credential_complained:
                    credential_complained = True
                    # **`warning`, and the level is the whole of item 120.** An `ERROR` becomes an
                    # event, an event becomes a webhook, and a webhook becomes an issue somebody
                    # has to close — seven of them on this repository before anybody noticed, every
                    # one of them the instance doing exactly what item 096 built it to do. This is
                    # an operational condition that clears itself, and `status` and `doctor` are
                    # where a person looks for a stopped instance.
                    log.warning("not claiming anything: %s", expired)
                    print(f"Not claiming anything — {expired}", file=out)
                stopping.wait(LOOP_CEILING_SECONDS)
                continue
            if credential_complained:
                credential_complained = False
                log.info("the model credential works again; claiming resumes")
                print("The model credential works again. Claiming resumes.", file=out)

            try:
                outcomes = work.run(
                    session, settings, limit=args.limit, slug=args.project, rehearse_into=None
                )
            except (work.WiringError, SandboxError, ImageBuildError) as exc:
                # One unusable item, or a forge that is down, must not end the process. Same rule
                # `drain_pending` follows for one bad payload, and for the same reason: the queue
                # behind it is somebody else's work.
                log.warning("a turn of the dispatcher failed", extra={"error": str(exc)})
                outcomes = []
            except Exception:
                log.exception("a turn of the dispatcher raised")
                outcomes = []

            for outcome in outcomes:
                where = f" → {outcome.pull_request}" if outcome.pull_request else ""
                print(f"item {outcome.item_id}: {outcome.outcome.value}{where}", file=out)

            # Work found → look again at once, because a queue drains fastest when nothing sleeps on
            # it. Nothing found → back off, so an idle instance is idle.
            wait = LOOP_FLOOR_SECONDS if outcomes else min(wait * 2, LOOP_CEILING_SECONDS)
            stopping.wait(wait)
    finally:
        lease.release(session, holder)
        print("Dispatcher stopped. Its lease is free for the next one.", file=out)
    return 0


def _cmd_gateway(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Run the recording gateway in the foreground. **Not for a person to type** (item 054).

    The dispatcher starts this inside the attempt's own network, because a container on an
    `--internal` network cannot reach a listener on the host and asking every self-hoster to open
    their firewall to the Docker bridge is not an answer this product wants to give.

    The credential arrives as a **file**, never an argument and never an environment variable: an
    argument is in `ps` and an environment variable is in `docker inspect`. DR-0004 says the key
    lives in the proxy and not in the sandbox, and that is still true — this is a different
    container on a different network, which the watched project's test command cannot reach except
    through the API it exposes.
    """
    from hullwork.gateway.journal import Journal
    from hullwork.gateway.server import Gateway

    credential = Path(args.credential_file).read_text(encoding="utf-8").strip()
    if not credential:
        msg = f"{args.credential_file} is empty, so there is nothing to authenticate with"
        raise CommandError(msg)

    with Gateway(
        args.upstream,
        credential,
        pinned_model=args.model or None,
        allowed_models=tuple(args.allow_model or ()),
        max_tokens=args.max_tokens or None,
        auth_style=args.auth_style,
        journal=Journal(Path(args.journal)),
        host="0.0.0.0",  # noqa: S104 - the peer is on this network and nothing else can reach it
        port=args.port,
    ) as gateway:
        for cidr in args.allow_network or []:
            gateway.allow_network(cidr)
        print(f"gateway listening on {gateway.port}", file=out, flush=True)
        # Until killed. The dispatcher owns the lifetime; there is nothing to wait *for* here.
        threading.Event().wait()
    return 0


def _cmd_prune(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    cleared = prune(session, args.older_than_days)
    print(
        f"Cleared the stored body of {cleared} delivery(s) older than "
        f"{args.older_than_days} days. Every row, fingerprint and issue reference is intact.",
        file=out,
    )
    return 0


def _cmd_init(args: argparse.Namespace, out: TextIO) -> int:
    """Write the files a real deployment needs, and say what only a person can do. Item 115.

    **No session, and that is not an optimisation.** This runs on a machine with no instance yet,
    and opening the database would create an empty `hullwork.db` in whatever directory the operator
    happens to be standing in — the exact trap the notes warn about, sprung by the command
    that exists to spare them the reading.
    """
    from hullwork import scaffold

    into = Path(args.into).resolve()
    gid = scaffold.docker_socket_group()
    try:
        done = scaffold.write(into, docker_gid=gid)
    except OSError as exc:
        # **Item 126, measured on the first installation nobody arranged.** Run the only way a
        # stranger can run it — from the image, before the package exists anywhere — this was a
        # `PermissionError` traceback, because the image runs as uid 10001 and the directory
        # belongs to root. `main` promises never to raise at an operator; that promise ended here.
        import os

        raise CommandError(
            f"cannot write into {into}: {exc.strerror or exc}.\n"
            f"  This process runs as uid {os.getuid()}, and that directory does not allow it to "
            f"write.\n"
            f"  Either point --into at a directory you own, or give this one to that uid: "
            f"`chown {os.getuid()} {into}`. Running the whole thing as root works and leaves "
            f"root-owned files behind, which the next non-root run will trip over in the same way."
        ) from exc

    for name in done.created:
        print(f"  wrote     {into / name}", file=out)
    for name in done.kept:
        # **Kept, never overwritten** — and said out loud. Measured on this project's own
        # deployment: a compose file copied over another silently dropped an error DSN, the
        # instance came up healthy, and its own reporting was off. Nothing failed; a capability
        # went quiet.
        print(f"  kept      {into / name} — it was already there, so nothing was written", file=out)
    for note in done.notes:
        print(f"  note      {note}", file=out)
    if not done.created:
        print("\nNothing to do: both files already exist. Nothing was changed.", file=out)
        return 0

    print(
        f"\nWhat only you can do, in this order:\n"
        f"\n"
        f"  1. Mint a forge token that can read content and write issues, and **not** push, and\n"
        f"     put it in {scaffold.ENVIRONMENT_FILE} as HULLWORK_FORGE_TOKEN. A token cannot mint\n"
        f"     a token, so this is a web interface and a human, once.\n"
        f"  2. Set HULLWORK_BASE_URL to an address your error tracker can actually reach.\n"
        f"     Hosted GlitchTip refuses to call private addresses at all — the deploy notes §1\n"
        f"     is about that and nothing else.\n"
        # **Step 3 was missing and step 4 could not work without it** (2026-08-04). This list claims
        # to be everything only a person can do, and it omitted the one value with no sensible
        # default: the build context. A stranger followed steps 1-3 verbatim and got
        # `failed to read dockerfile` — from a directory this command chose for them. It is now
        # written empty rather than as `.`, so the failure names itself, and it is named here too.
        f"  3. Set BUILD_SOURCE to the checkout you cloned. It is **not** this directory — a\n"
        f"     clone carries a docker-compose.yml of its own — and the build cannot find a\n"
        f"     Dockerfile until you set it.\n"
        f"  4. set -a; . ./{scaffold.ENVIRONMENT_FILE}; set +a; docker compose up -d --build\n"
        f"  5. hullwork doctor — it names what is still missing, one line each.\n"
        f"\n"
        f"That gives you ingest, deduplication, triage and issues — one container, and step 3\n"
        f"starts exactly that. Attempting fixes needs two more credentials (a code token and a\n"
        f"model key), is opted into per project in each repository's own hullwork.yml, and\n"
        f"runs in\n"
        f"a second container this file keeps behind a profile:\n"
        f"\n"
        f"  docker compose --profile autofix up -d\n"
        f"\n"
        f"Nothing here turns it on, and now the compose file agrees (item 135).",
        file=out,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hullwork", description="Hullwork instance administration."
    )
    # **The first thing anybody pastes into a bug report**, and until 2026-08-05 it printed a usage
    # error. The string existed and `status` printed it, so the version was reachable only by
    # running a command that opens the database — which is exactly what somebody filing a report
    # about an instance that will not start does not have. This answers before any config is read.
    parser.add_argument("--version", action="version", version=f"hullwork {__version__}")
    subparsers = parser.add_subparsers(dest="group", required=True)

    status = subparsers.add_parser("status", help="is this instance actually working?")
    status.add_argument("--json", action="store_true", help="machine-readable, same exit code")
    status.set_defaults(func=_cmd_status)

    doctoring = subparsers.add_parser(
        "doctor",
        help="why an instance that is running will not work",
        description=(
            "Proves the preconditions an attempt needs by doing them — git resolved, the Docker "
            "daemon answering, this build's tables present, the code token reaching every active "
            "repository, a model credential present and unexpired — and reports which configured "
            "variable never arrived where it was needed.\n\n"
            "Separate from `status` because it makes the opposite trade: it spends a subprocess, a "
            "forge call per repository and two file reads, on the assumption that a person is "
            "typing it because something is already wrong."
        ),
    )
    doctoring.add_argument("--json", action="store_true", help="machine-readable, same exit code")
    doctoring.add_argument(
        "--env-file",
        default=None,
        help="the environment file to compare against (default: ./.env)",
    )
    doctoring.add_argument(
        "--compose-file",
        default=None,
        help=(
            "the compose file whose one-at-a-time variable list is compared against the "
            "environment file (default: ./docker-compose.yml when it exists)"
        ),
    )
    doctoring.set_defaults(func=_cmd_doctor)

    projects = subparsers.add_parser("projects", help="manage connected projects")
    actions = projects.add_subparsers(dest="action", required=True)

    add = actions.add_parser("add", help="register a project after validating its manifest")
    add.add_argument(
        "--manifest",
        default=None,
        metavar="FILE",
        help=(
            "a hullwork.yml on this machine, for a repository you cannot commit to (DR-0012). "
            "Same file, same parser, same refusals; the instance holds the copy and says so in "
            "`projects list`. Committing it to the repository is the default and versions it with "
            "the test command it describes"
        ),
    )
    add.add_argument("--slug", required=True, help="unique name for this project in this instance")
    add.add_argument("--forge", default="forgejo", choices=SUPPORTED_FORGES)
    add.add_argument("--repo", required=True, help="owner/name on the forge")
    add.set_defaults(func=_cmd_add)

    listing = actions.add_parser("list", help="list registered projects")
    listing.set_defaults(func=_cmd_list)

    disable = actions.add_parser("disable", help="deactivate a project without deleting anything")
    disable.add_argument("slug")
    disable.set_defaults(func=_cmd_disable)

    rotate = actions.add_parser("rotate-secret", help="issue a new webhook token")
    rotate.add_argument("slug")
    rotate.set_defaults(func=_cmd_rotate)

    refresh = actions.add_parser(
        "refresh", help="re-read hullwork.yml from the default branch"
    )
    refresh.add_argument("slug")
    refresh.add_argument(
        "--manifest",
        default=None,
        metavar="FILE",
        help=(
            "replace the copy this instance holds with this file (DR-0012). Required for a project "
            "registered that way: there is nothing in its repository to re-read"
        ),
    )
    refresh.set_defaults(func=_cmd_refresh)

    proposing = subparsers.add_parser(
        "propose",
        help="read a repository's CI configuration and print the manifest it implies",
        description=(
            "Prints a `hullwork.yml` derived from the repository's own CI configuration — the "
            "environment, the runtime, the install command, and the test and lint commands. Those "
            "are the fields a manifest asks for, and a CI file exists in order to say them.\n\n"
            "Writes nothing and registers nothing. What was observed is uncommented; what could "
            "only be inferred is commented out with what was seen, so you can tell the two apart "
            "before you commit it to your repository."
        ),
    )
    proposing.add_argument(
        "repo",
        nargs="?",
        help="owner/name on the forge. Omit it and pass --checkout to read a local directory.",
    )
    proposing.add_argument(
        "--checkout",
        default=None,
        help=(
            "a local checkout to read instead of a repository on a forge. Needs no forge token and "
            "no network — which is what makes this usable before you have handed over anything, "
            "including from `hullwork try`, which recommends this when a manifest is missing."
        ),
    )
    proposing.add_argument("--forge", default="forgejo", choices=SUPPORTED_FORGES)
    proposing.set_defaults(standalone=_propose_entry)

    laning = actions.add_parser(
        "lanes",
        help="show which of this repository's files the instance keeps a human on",
        description=(
            "Applies this instance's derived policy to the project's own tree and prints what it "
            "claims, with the reason for each rule. Reads nothing from the manifest except the "
            "`autofix.lanes.ordinary` override, and stores nothing: the policy is a function of a "
            "path, so it cannot go stale between this command and the next error.\n\n"
            "Run it before trusting an instance with a repository. The policy decides whether an "
            "agent is allowed to touch a file, and a policy nobody has read is a policy nobody has "
            "agreed to."
        ),
    )
    laning.add_argument(
        "slug",
        nargs="?",
        help="a registered project. Omit it and pass --checkout to ask the same of a directory.",
    )
    laning.add_argument(
        "--checkout",
        default=None,
        help=(
            "a local checkout to read instead of a registered project's tree. Needs no forge "
            "token, no database and no network — the point being that you can read the policy "
            "before handing this instance a credential."
        ),
    )
    laning.set_defaults(standalone=_lanes_entry)
    laning.set_defaults(func=_cmd_lanes)

    tracking = actions.add_parser(
        "set-tracker", help="name this project in the error tracker (for the inventory sweep)"
    )
    tracking.add_argument("slug")
    tracking.add_argument(
        "tracker_project", help="the project's name in the tracker; empty string to stop sweeping"
    )
    tracking.set_defaults(func=_cmd_set_tracker)

    approving = subparsers.add_parser(
        "approve", help="let an agent attempt one amber item"
    )
    approving.add_argument("slug")
    approving.add_argument("item", type=int, help="the item id, as shown on its issue")
    approving.set_defaults(func=_cmd_approve)

    requeueing = subparsers.add_parser(
        "requeue",
        help="put back an item whose attempt was stopped by the project's own failing suite",
    )
    requeueing.add_argument("slug")
    requeueing.add_argument("item", type=int, help="the item id, as shown on its issue")
    requeueing.set_defaults(func=_cmd_requeue)

    leasing = subparsers.add_parser(
        "lease", help="release a dispatcher lease whose holder is gone"
    )
    lease_actions = leasing.add_subparsers(dest="lease_action", required=True)
    releasing = lease_actions.add_parser(
        "release", help="free the lease so the next dispatcher does not wait for it to expire"
    )
    releasing.set_defaults(func=_cmd_lease)

    configuring = subparsers.add_parser(
        "config",
        help="what this instance is set to, on one screen",
        description=(
            "Every setting, its value, where it came from, and which half of Hullwork the "
            "deployment passes it to.\n\n"
            "**No credential is printed.** A secret reads `set` or `not set`, which answers the "
            "only question a terminal can answer about one; whether it is the right value is "
            "asked of the far end by `hullwork doctor`.\n\n"
            "`doctor` says what is broken and `status` says what has happened. This says what the "
            "instance is — the question that, on 2026-08-04, took a session to answer by reading "
            "a compose file, an environment file and a container's environment side by side."
        ),
    )
    configuring.set_defaults(func=None, standalone=_cmd_config)

    trying = subparsers.add_parser(
        "try",
        help="run the six phases against a local checkout, with no forge and no deployment",
        description=(
            "The way to see Hullwork work before committing to it (DR-0006, item 140). Hand it a "
            "checkout and the stack trace you already have, and it runs the same six steps a real "
            "attempt runs — baseline, reproduce, red gate, fix, green gate, lint gate — writing "
            "what it produced to a directory instead of opening a pull request.\n\n"
            "It needs **no forge credential of any kind**: nothing that can push, nothing that can "
            "read private code, no account anywhere. It does need the Docker daemon and a model "
            "credential (HULLWORK_MODEL_KEY), and those are not removable: the claim this product "
            "makes is a test that failed against unmodified code and passes with the change, run "
            "in a sandbox, by a model whose identity was read off the wire. Faking either would "
            "make this a demo of itself.\n\n"
            "Nothing is written outside the output directory, and no database is created."
        ),
    )
    trying.add_argument("checkout", help="path to a checkout with a hullwork.yml in it")
    trying.add_argument(
        "--error",
        required=True,
        help="file holding the stack trace, or `-` to read it from stdin",
    )
    trying.add_argument(
        "--into",
        default=None,
        help="where to write what the attempt produced (default: ./hullwork-trial beside it)",
    )
    trying.add_argument(
        "--approve",
        action="store_true",
        help=(
            "attempt an amber-lane error anyway. Amber means a human approves this one item by "
            "hand; running this against a checkout you control is that approval. Red is never "
            "attempted and this does not change it."
        ),
    )
    trying.set_defaults(func=None, standalone=_cmd_try)

    working = subparsers.add_parser(
        "work",
        help="attempt ready items: clone, sandbox, agent, gates, draft pull request",
        description=(
            "The dispatcher. Runs the six steps of the red-green gate for each ready item and "
            "opens a draft pull request when a test that failed against unmodified code passes "
            "with the change applied.\n\n"
            "This is the second of Hullwork's two programs and it needs three things the "
            "always-on service deliberately does not have: HULLWORK_FORGE_CODE_TOKEN, a model "
            "credential (HULLWORK_MODEL_KEY), and the Docker daemon. Run it from the operator's "
            "own scheduler — there is no trigger field in the manifest, because a manifest cannot "
            "make anything happen at 02:00."
        ),
    )
    working.add_argument(
        "--limit", type=int, default=1,
        help="how many items to attempt in this run (default 1; each gets its own sandbox)",
    )
    working.add_argument(
        "--project", default=None, help="only attempt items belonging to this project slug"
    )
    working.add_argument(
        "--loop",
        action="store_true",
        help=(
            "stay resident: attempt what becomes ready, release what a dead dispatcher claimed, "
            "and renew a lease that doubles as the heartbeat. Binds no port (DR-0009)"
        ),
    )
    working.add_argument(
        "--release-stale", action="store_true",
        help="free items whose dispatcher died mid-attempt, without losing the record",
    )
    working.add_argument(
        "--no-publish", action="store_true",
        help=(
            "rehearse: run every gate and publish nothing. Writes what the attempt produced under "
            "./hullwork-rehearsals/, and no item loses its attempt. Needs no credential that can "
            "write anywhere, which is the point"
        ),
    )
    working.set_defaults(func=_cmd_work)

    sweeping = subparsers.add_parser(
        "sweep",
        help="read the tracker's unresolved list and file what is missing",
        description=(
            "The tracker notifies once per issue for the issue's whole life, so only the first "
            "appearance of a new signature ever arrives by webhook — and a bug that was already "
            "failing when Hullwork was installed never does. This reads the list instead "
            "(DR-0011).\n\n"
            "The first pass of a project shows its count and writes nothing until --confirm, "
            "because filing three hundred issues on a first afternoon is how a tool gets "
            "uninstalled. Every pass after it happens on the receiver's own clock."
        ),
    )
    sweeping.add_argument("slug", nargs="?", default=None, help="one project (default: all)")
    sweeping.add_argument(
        "--confirm", action="store_true", help="actually file what the first pass found"
    )
    sweeping.add_argument(
        "--from-now",
        action="store_true",
        help=(
            "start sweeping from this moment and leave the existing backlog unfiled. For a project "
            "with more open issues than you want to look at"
        ),
    )
    sweeping.add_argument("--limit", type=int, default=25, help="issues per project per pass")
    sweeping.set_defaults(func=_cmd_sweep)

    republishing = subparsers.add_parser(
        "republish",
        help="publish a verdict the dispatcher reached and could not send",
        description=(
            "The attempt is already spent and its verdict is a fact in this database. Publishing "
            "was the last step and the only one that can fail after a verdict exists, so this "
            "finishes the job — no sandbox, no gates, no model call.\n\n"
            "Only the comment-shaped outcomes. A `pr-open` verdict needs the files the agent "
            "wrote and nothing stores them (item 079), so it is refused rather than faked."
        ),
    )
    republishing.add_argument(
        "--attempt", type=int, default=None, help="one attempt, as `hullwork status` names it"
    )
    republishing.add_argument(
        "--give-up",
        action="store_true",
        help=(
            "record that this verdict has no destination and stop reporting it. Needs --attempt "
            "and --why. For a failure a retry can never fix, such as an issue that no longer "
            "exists"
        ),
    )
    republishing.add_argument(
        "--why", default=None, help="the reason, recorded on the attempt (required by --give-up)"
    )
    republishing.set_defaults(func=_cmd_republish)

    gateway = subparsers.add_parser(
        "gateway",
        help="run the recording gateway (started by the dispatcher, not by a person)",
    )
    gateway.add_argument("--upstream", required=True)
    gateway.add_argument("--credential-file", required=True)
    gateway.add_argument("--journal", required=True)
    gateway.add_argument("--port", type=int, default=8080)
    gateway.add_argument("--model", default="")
    # Item 137. Both default to today's behaviour exactly: no ceiling, and only the pinned
    # model acceptable.
    gateway.add_argument("--allow-model", action="append", default=[])
    gateway.add_argument("--max-tokens", type=int, default=0)
    gateway.add_argument("--auth-style", default="bearer", choices=["bearer", "x-api-key"])
    gateway.add_argument("--allow-network", action="append", default=[])
    gateway.set_defaults(func=_cmd_gateway)

    starting = subparsers.add_parser(
        "init", help="write the compose file and environment a real deployment needs"
    )
    starting.add_argument(
        "--into", default=".", help="where to write them (default: the current directory)"
    )
    # No session: this runs before there is an instance, and opening the database here would
    # create an empty one in the operator's working directory.
    starting.set_defaults(func=None, scaffolding=_cmd_init)

    page_token = subparsers.add_parser(
        "page-token",
        help="mint the credential that opens the read-only page",
        description=(
            "The page lives on the receiver, because the dispatcher listens on nothing and that is "
            "what lets it hold a credential that can push. So it is on the half of Hullwork your "
            "error tracker has to be able to reach: until this command runs there is no page, and "
            "every path under it answers 404 the way an unknown path does.\n\n"
            "Shown once, stored as a hash. The URL is the credential."
        ),
    )
    page_token.add_argument(
        "--rotate",
        action="store_true",
        help="replace the existing token, invalidating every URL handed out so far",
    )
    page_token.set_defaults(func=_cmd_page_token)

    pruning = subparsers.add_parser(
        "prune", help="forget the raw bodies of old deliveries, keeping every row"
    )
    pruning.add_argument("--older-than-days", type=int, default=90)
    pruning.set_defaults(func=_cmd_prune)

    return parser


def main(argv: Sequence[str] | None = None, out: TextIO = sys.stdout) -> int:
    """Entry point. Returns an exit code and never raises at an operator."""
    args = build_parser().parse_args(argv)
    scaffolding = getattr(args, "scaffolding", None)
    if scaffolding is not None:
        # Before `get_settings`, before the logger, before the database — a command that writes a
        # deployment's first two files cannot require the deployment to exist.
        try:
            answered: int = scaffolding(args, out)
            return answered
        except CommandError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    try:
        settings = get_settings()
        # **The dispatcher had no log at all.** Nothing here ever called `configure_logging`, so
        # every `log.info` in `work`, `dispatch` and `sandbox` — claimed an item, gateway up, what
        # the gateway said before teardown — went nowhere, and Python's fallback handler carried
        # only warnings. The service does this in its lifespan; the second program never did, which
        # is why diagnosing an attempt meant reproducing its containers by hand.
        #
        # The redactor is armed with the credentials this process holds, which is the whole reason
        # it exists (item 015): the dispatcher holds more of them than the service does.
        configure_logging(
            level=settings.log_level, log_format=settings.log_format, secrets=_redactions(settings)
        )
        # **A command that brings its own database must not be handed one** (item 140). `try` runs
        # against a checkout with no deployment behind it, and `HULLWORK_DATABASE_URL` defaults to
        # `sqlite:///./hullwork.db` — so opening a session here would create a file in the
        # evaluator's working directory to satisfy a command whose whole claim is that it leaves
        # nothing behind. It needs the settings above; it does not need this.
        standalone = getattr(args, "standalone", None)
        if standalone is not None:
            tried: int = standalone(args, settings, out)
            return tried
        factory = make_session_factory(get_engine(settings.database_url))
        with factory() as session:
            result: int = args.func(args, session, settings, out)
            return result
    except CommandError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ConfigError as exc:
        # **Nobody had ever seen this message**, and it is a good one — it names the variable and
        # says a typo would otherwise read as *not configured*. `get_settings` raises it on purpose
        # "instead of a stack trace", per its own docstring, and then nothing caught it, so the only
        # way to reach a careful sentence was through twelve frames of pydantic. The same shape as
        # item 144's check that never ran and `ManifestError` reaching `try` uncaught: the work was
        # done and the last connection was missing. Found on 2026-08-04 by running it.
        print(f"error: {exc}", file=sys.stderr)
        return 1
