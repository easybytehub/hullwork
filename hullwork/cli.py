"""The `hullwork` command.

Registration is a command rather than an HTTP endpoint (operator decision, 2026-07-27). The core is
single-tenant, so the operator already has the server: an administration endpoint would be a
permanent attack surface and one more credential to rotate, for something done a handful of times in
an instance's life. It also keeps the generated webhook token off the network — it is printed here,
in the operator's own terminal, instead of travelling in a response body.

`argparse` on purpose. A CLI framework is a dependency this does not need.
"""

import argparse
import getpass
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
from collections.abc import Callable, Sequence
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TextIO

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from hullwork import (
    __version__,
    bump,
    credentials,
    db,
    dependencies,
    doctor,
    features,
    lease,
    operator,
    osv,
    outcomes,
    page,
    propose,
    readiness,
    recurrence,
    refit,
    resolve,
    spend,
    territory,
    triage,
    upgrades,
    work,
)
from hullwork import decisions as decide
from hullwork import dispatch as dispatch_module
from hullwork import features as features_module
from hullwork import upstream as upstream_module
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
from hullwork.sandbox.docker import SandboxError, UnsafePathError
from hullwork.sandbox.harness import BundleError
from hullwork.sandbox.image import ImageBuildError
from hullwork.sandbox.net import EgressError
from hullwork.sandbox.services import ServiceError
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

    **The sentences live in `sandbox.image` since 2026-08-05**, because `hullwork try` needed the
    same refusal and could not import them from here — so it had none, and a `distroless` base got a
    traceback after minutes of building instead of one line before spending anything. This is the
    door that registers a project; `trial.run` is the other one, and both now read one verdict.
    """
    runtime = manifest.runtime
    if runtime is None:
        return
    from hullwork.sandbox.image import why_it_cannot_host_a_phase

    refusal, note = why_it_cannot_host_a_phase(runtime.base)
    if note and out is not None:
        print(note, file=out)
    if refusal:
        raise CommandError(refusal)


def _cmd_deps(args: argparse.Namespace, settings: Settings, out: TextIO) -> int:
    """Which pinned dependencies have something published against them. Item 172, DR-0016.

    **Standalone, and that is the product claim rather than a convenience.** No forge, no model, no
    Docker, no database — a person can run this against their own checkout in the first minute,
    before they have decided anything. It is the only half of DR-0016 that needs nothing.
    """
    checkout = Path(args.checkout).resolve()
    # `--fix` and `--open` are `--verify` plus one more step each: there is nothing to fix that has
    # not first been measured breaking, and nothing to open that has not first been measured
    # passing. Read once, here, so everything below asks the same question.
    opening = bool(getattr(args, "open", False))
    verifying = bool(args.verify or getattr(args, "fix", False) or opening)
    # **Before the lock files are read and before OSV is asked**, for `_manifest_for_verify`'s
    # reason and with more at stake: `--open` is the one flag here that can write to somebody's
    # repository, and finding out after two container builds that there is no credential is a
    # refusal that arrives after the work it invalidates.
    code_forge = _forge_for_opening(settings, checkout) if opening else None
    if getattr(args, "fix", False):
        # **Item 048's finding, on the path that had not learned it** (found by running `--fix` for
        # the first time, 2026-08-09). This was raised inside `refit.run`, so it arrived *after*
        # every container had been built and every suite run — the most expensive place available —
        # and it arrived as a `WiringError` traceback rather than as a refusal, which item 120 is
        # about. The message itself was right; where and how it appeared was not.
        _refuse_without_a_model(settings)
    # **Before the lock files are read and before OSV is asked.** Found by running it: validating
    # the manifest after the report meant paying for a network round trip and a full listing to be
    # told a file was missing — and the refusal arrived interleaved with the output it invalidated.
    manifest = _manifest_for_verify(checkout) if verifying else None
    paths = _tracked_files(checkout)

    def read(path: str) -> str | None:
        try:
            return (checkout / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    pinned = dependencies.read_lockfiles(paths, read)
    if not pinned:
        raise CommandError(
            f"no lock file in {checkout}: looked for "
            f"{', '.join(dependencies.WHAT_IS_LOOKED_FOR)}.\n"
            f"  A declaration is a range and a range does not say what your build resolved to, so "
            f"there is nothing here a vulnerability database can be asked about. Commit a lock "
            f"file, or pin with `==` in requirements.txt."
        )

    sources = sorted({d.source for d in pinned})
    print(f"{len(pinned)} pinned dependencies, from {', '.join(sources)}", file=out)

    # Said before the answer rather than after it: a file whose ranges were skipped reports fewer
    # dependencies than it has, and a reader who learns that afterwards has already believed it.
    #
    # **Every requirements file that was read, not the root one by name** (item 180). Keyed off the
    # same predicate the reader uses, so a layout that becomes readable becomes countable in the
    # same edit — two places deciding what a requirements file is would eventually disagree, and
    # the half that goes quiet is this one.
    for source in sources:
        if dependencies.is_requirements(source):
            text = read(source) or ""
            skipped = dependencies.unpinned(text)
            if skipped:
                print(
                    f"  {skipped} line(s) in {source} are ranges rather than `==` pins and were "
                    f"not checked",
                    file=out,
                )

    # **Quiet here and nowhere else.** httpx2 logs every request at INFO, which is right for the
    # dispatcher — those lines are how an attempt gets diagnosed — and wrong for a report a person
    # reads. This is the command a stranger runs first, and one `HTTP Request: POST …` line in the
    # middle of its output is the kind of friction the cold evaluations kept finding.
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    with osv.Osv() as database:
        findings = database.affected(pinned)

    if not findings:
        print("\nNothing published against any of those versions.", file=out)
        return 0

    print(f"\n{len(findings)} with a published advisory:\n", file=out)
    for finding in findings:
        dep = finding.dependency
        print(f"  {dep.name} {dep.version}  ({dep.ecosystem}, {dep.source})", file=out)
        for advisory in finding.advisories:
            if advisory.has_a_fix:
                where = " or ".join(advisory.fixed)
                ends = f"fixed in {where}"
            else:
                # Not "no fix found": the advisory publishes none, which is a fact about the
                # advisory rather than a gap in this reading.
                ends = "no fixed version is published — there is no upgrade to attempt"
            print(f"      {advisory.id}: {ends}", file=out)
            if advisory.summary:
                print(f"        {advisory.summary}", file=out)
            print(f"        {advisory.url}", file=out)
        print("", file=out)

    if not verifying:
        print(
            "Whether any of these upgrades survives your own test suite is a different question, "
            "and nothing above has run it. `--verify` runs it.",
            file=out,
        )
        return 0

    assert manifest is not None  # noqa: S101 - built above when --verify is set
    reports = _verify_upgrades(checkout, paths, read, manifest, findings, out)
    if opening:
        assert code_forge is not None  # noqa: S101 - built above when --open is set
        _open_the_ones_that_pass(code_forge, checkout, manifest, findings, reports, out)
    if not getattr(args, "fix", False):
        return 0
    return _fix_the_ones_that_break(
        args, settings, checkout, paths, manifest, findings, reports, out
    )


def _manifest_for_verify(checkout: Path) -> Manifest:
    """The manifest `--verify` needs, or a refusal naming exactly what is missing. Item 174.

    **Called before the lock files are read and before OSV is asked**, because everything it checks
    is knowable from disk. Validating afterwards spent a network round trip and a full listing to
    tell somebody a file was missing, and printed the refusal interleaved with the report it had
    just invalidated. Found by running it.
    """
    manifest_path = checkout / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise CommandError(
            f"--verify needs a {MANIFEST_FILENAME} in {checkout}: it says which image your tests "
            f"run in and what the test command is, and neither can be guessed.\n"
            f"  `hullwork propose --checkout {checkout}` writes one from your CI configuration."
        )
    manifest = parse_manifest(manifest_path.read_text(encoding="utf-8"))
    if manifest.runtime is None or not manifest.runtime.base:
        raise CommandError(
            "--verify needs `runtime.base`: an image your tests already run in. Without it there "
            "is nothing to build the upgrade into."
        )
    if not manifest.tests:
        raise CommandError(
            "--verify needs `tests`: the command that runs your suite. That suite is the whole "
            "verdict — without it there is nothing to ask."
        )
    return manifest


def _verify_upgrades(
    checkout: Path,
    paths: Sequence[str],
    read: Callable[[str], str | None],
    manifest: Manifest,
    findings: Sequence[osv.Finding],
    out: TextIO,
) -> list[bump.Report]:
    """Apply each published fix in a sandbox and let the project's own suite decide. Item 174.

    Returns the reports as well as printing them, because item 179 has to act on the same ones the
    reader was shown — recomputing them would be a second verdict about the same upgrade, and the
    two could differ by the time anybody noticed.
    """
    print("\n--- verifying each published fix against your own suite ---\n", file=out)
    reports: list[bump.Report] = []
    for finding in findings:
        dep = finding.dependency
        versions = bump.candidates(finding.advisories)
        refusal = _cannot_be_verified(dep, manifest, versions)
        if refusal is not None:
            print(f"  {dep.name}: {refusal}\n", file=out)
            # **Counted, not merely printed** (item 182). A refusal that only goes to the terminal
            # is absent from the summary below, so a run that could verify none of six reads as
            # `0 blocked` — and the one number in this whole command that a person acts on is a
            # count. "I could not verify this" is a first-class answer and it has to be in the
            # tally, which is the property `docs/what-hullwork-is.md` puts second.
            reports.append(
                bump.Report(
                    package=dep.name,
                    was=dep.version,
                    answers=(
                        bump.Answer(
                            bump.Verdict.CANNOT_MOVE, dep.name, dep.version,
                            versions[0] if versions else "", detail=refusal,
                        ),
                    ),
                )
            )
            continue
        report = _verify_one(checkout, paths, read, manifest, dep, versions, out)
        if report is not None:
            reports.append(report)

    _print_the_queue(reports, out)
    return reports


def _forge_for_opening(settings: Settings, checkout: Path) -> object:
    """The credential `--open` pushes through, or a refusal that says what is missing. Item 178.

    **It is `HULLWORK_FORGE_CODE_TOKEN`, and the operator decided that on 2026-08-09.** The
    alternative was a third token of its own, and it was declined for a reason worth keeping: a
    third token would need exactly the same scope — `write:repository` — so it would be an
    audit boundary rather than a capability boundary, which is not what the split between
    `forge_token` and `forge_code_token` is. That one is real and was measured (item 073); a
    same-scope sibling would be the same power under another name.

    What that decision costs is one sentence, and it has been paid: `config.py` no longer calls this
    *the credential an agent pushes through*, because this path opens pull requests with no agent
    having run. Nobody may infer "a model was called" from the fact that something was pushed.

    Called before the lock files are read and before OSV is asked, so a missing credential costs
    nothing to discover.
    """
    forge = make_code_forge(settings)
    if forge is None:
        raise CommandError(
            "--open needs HULLWORK_FORGE_URL and HULLWORK_FORGE_CODE_TOKEN: it opens pull "
            "requests, which is the one thing in `deps` that writes to your repository.\n"
            "  Everything else here needs no account anywhere — `--verify` runs your suite "
            "against each upgrade and prints the answer, and it is the honest way to see what "
            "this would open before letting it."
        )
    coordinate = _coordinate_from(_origin_url(checkout))
    if coordinate == "owner/name":
        forge.close()
        raise CommandError(
            f"--open needs to know which repository this is, and {checkout} has no usable `origin` "
            f"remote to read it from.\n"
            f"  Add one, or run without --open: the verification does not need a coordinate "
            f"because it opens nothing."
        )
    return forge


def _refuse_without_a_model(settings: Settings) -> None:
    """Refuse `--fix` before anything is built when no model credential is configured. Item 048.

    Knowable from the settings and nothing else, so it costs nothing to answer — which is the only
    reason a refusal belongs this early. `--verify` is untouched: it calls no model and must keep
    needing no credential of any kind, which is the property `deps` is sold on.
    """
    try:
        work._model_credential(settings)
    except work.WiringError as exc:
        raise CommandError(
            f"{exc}\n"
            f"  `--verify` on its own needs no credential at all and still runs your suite "
            f"against every published fix — it is `--fix`, which asks an agent to change your "
            f"code, that needs a model."
        ) from exc

    # **The other thing every agent run needs, and it was found the expensive way** (item 191).
    # `deps --fix` died at the gateway after OSV, four image builds and two suite runs, on the
    # first real model call this command ever made. Asked here, where the credential is asked.
    from hullwork.sandbox.net import why_the_gateway_cannot_start

    missing = why_the_gateway_cannot_start()
    if missing:
        raise CommandError(missing)


def _open_the_ones_that_pass(
    code_forge: object,
    checkout: Path,
    manifest: Manifest,
    findings: Sequence[osv.Finding],
    reports: Sequence[bump.Report],
    out: TextIO,
) -> None:
    """Open one draft pull request per verified-green upgrade. Item 178, DR-0018 step 3.

    The end of DR-0018's sentence, and the first thing in this line of work that needs a credential
    able to write: *we open the thirty-one that pass and tell you what to do with the nine that do
    not*. The nine are already on screen by the time this runs.
    """
    from hullwork import trial

    eligible = upgrades.eligible(reports)
    if eligible and not manifest.autofix.open_upgrades:
        # **Said before the count, and as a decision** (DR-0019, item 187). This is the first thing
        # a project can refuse while Hullwork is perfectly able to do it, so it must not read as a
        # part that is missing — the verification above ran and its answer stands.
        print(
            f"\n{len(eligible)} upgrade(s) passed your suite and **none was opened**: this "
            f"project has not permitted it.\n"
            f"  Set `autofix: {{open_upgrades: true}}` in {MANIFEST_FILENAME} if you want them "
            f"opened. It is false by default because having the credential is not the same as "
            f"having agreed, and the report above is what there is to act on either way.",
            file=out,
        )
        return
    if not eligible:
        print(
            "\nNothing was verified green, so there is nothing to open. That is a result rather "
            "than a failure: the report above is what there is to act on.",
            file=out,
        )
        return

    # **The commit the gates ran against**, read from the checkout that was verified rather than
    # from the forge's idea of its own default branch. The base can move while a verification runs,
    # and a branch rooted at wherever it points now contains a tree nobody tested.
    base = trial.head_sha(checkout)
    if base == "working tree":
        print(
            "\nThis checkout is not a git repository, so there is no commit to root a pull "
            "request at and nothing was opened. What was verified is above.",
            file=out,
        )
        return

    by_package = {f.dependency.name: f.advisories for f in findings}
    coordinate = _coordinate_from(_origin_url(checkout))
    print(f"\n--- opening {len(eligible)} verified-green upgrade(s) on {coordinate} ---\n",
          file=out)
    opened = upgrades.open_them(
        code_forge, repo=coordinate, reports=eligible,
        advisories=by_package, base_sha=base,
        permitted=manifest.autofix.open_upgrades,
    )
    for where in opened:
        print(f"  {where}", file=out)
    if len(opened) < len(eligible):
        # Never silence: a package that produced no pull request is either already open from a
        # previous run or something the forge refused, and both are facts a reader needs.
        print(
            f"\n  {len(eligible) - len(opened)} opened nothing — already open from an earlier "
            f"run, or refused by the forge. The log says which.",
            file=out,
        )
    print(
        f"\nAll drafts, rooted at {base[:12]}, one per package. Nobody merges them but you.",
        file=out,
    )


def _fix_the_ones_that_break(
    args: argparse.Namespace,
    settings: Settings,
    checkout: Path,
    paths: Sequence[str],
    manifest: Manifest,
    findings: Sequence[osv.Finding],
    reports: Sequence[bump.Report],
    out: TextIO,
) -> int:
    """Hand each broken upgrade to an agent and let the gates decide. Item 179, DR-0018 step 4.

    **The middle of the queue, which is the part nobody else ships.** The verified-green ones need
    no agent and are item 178's to deliver; the blocked ones have nothing to try. What is left is
    *six break, tests named*, and until this existed the honest answer to those was a list.

    Worst-first through `bump.ranked`, so a run that is interrupted has spent its money on the ones
    a person would have started with.
    """
    into = Path(args.into).resolve()
    queue: list[tuple[bump.Report, refit.Upgrade]] = []
    for report in bump.ranked(reports):
        if bump.needs_of(report) is not bump.Needs.NEEDS_WORK:
            continue
        finding = next(
            (
                f for f in findings
                if f.dependency.name == report.package and f.dependency.version == report.was
            ),
            None,
        )
        if finding is None:  # pragma: no cover - every report was built from one
            continue
        first = finding.advisories[0] if finding.advisories else None
        upgrade = refit.from_report(
            report,
            source=finding.dependency.source,
            guarded=refit.guarded_for(finding.dependency.source),
            advisory=first.id if first else "",
            url=first.url if first else "",
        )
        if upgrade is not None:
            queue.append((report, upgrade))

    if not queue:
        print(
            "\nNothing broke that an agent could be asked about, so --fix had nothing to do.",
            file=out,
        )
        return 0

    print(f"\n--- asking an agent to make {len(queue)} upgrade(s) fit ---\n", file=out)
    failures = 0
    for _report, upgrade in queue:
        print(f"  {upgrade.package} {upgrade.was} → {upgrade.to}", file=out)
        try:
            outcome = refit.run(
                settings, checkout, manifest, upgrade,
                present=paths, into=into, repo=_coordinate_from(_origin_url(checkout)),
            )
        except refit.NotUpgradableError as refused:
            # The upgrade never went into the tree, so no attempt was begun and nothing was spent.
            # Said as the fact about the project that it is, in the resolver's own words.
            print(f"      could not be applied: {refused}\n", file=out)
            failures += 1
            continue
        except work.WiringError as broken:
            # Belt and braces over the refusal above: an engine this build does not know is a
            # per-project fact, and a queue of six must not end at the first one that has it.
            print(f"      not attempted: {broken}\n", file=out)
            failures += 1
            continue
        print(f"      {outcome.outcome.value}: {outcome.detail.splitlines()[0]}", file=out)
        if outcome.pull_request:
            print(f"      written to {outcome.pull_request}\n", file=out)
        else:
            print("", file=out)
        if outcome.outcome not in (AttemptOutcome.PR_OPEN, AttemptOutcome.PR_OPEN_LINT_FAILED):
            failures += 1

    print(
        f"{len(queue) - failures} of {len(queue)} now pass your suite with the upgrade still "
        f"applied. Nothing was opened anywhere: read what is in {into} and decide.",
        file=out,
    )
    return 0


def _cannot_be_verified(
    dep: dependencies.Dependency, manifest: Manifest, versions: Sequence[str]
) -> str | None:
    """Why this upgrade cannot be measured at all, or `None` when it can. Item 182.

    Every reason here is knowable from the manifest and the finding, so all of them are answered
    **before a container is built** — the same rule `can_rewrite` follows and for the same reason.

    **The one that was missing is the one a real repository found immediately.** `encode/flask` pins
    four of its five advisory-carrying packages in `examples/celery/requirements.txt`, which is not
    a file its image installs from. The image is built from `runtime.dependencies`; rewriting
    anything outside that set changes no byte the build reads, so `dependency_digest` does not move,
    the image is reused, and the suite passes exactly as it passed before.

    **Measured on 2026-08-09 against a real daemon**, on a tree with `requirements.txt` declared and
    `extras/requirements.txt` not:

        [ready to take] jinja2 2.4.1 → 2.10.1
        $ docker run --rm <image> python -c "import jinja2"
        ModuleNotFoundError: No module named 'jinja2'

    *Ready to take*, for a package **not installed in the environment its suite ran in** — and with
    item 178's `--open`, a pull request. That is item 174's defect arriving by a second route, and
    it is the exact artefact DR-0017 says this product exists to prevent.

    An empty `runtime.dependencies` is not this case: `_verify_one` falls back to the file that
    pins, so the build does read it.
    """
    runtime = manifest.runtime
    assert runtime is not None  # noqa: S101 - `_manifest_for_verify` refused a manifest without one

    if runtime.install == "none":
        # **The worse half of the same finding, and it is the default value.** With `install: none`
        # the generated Dockerfile copies no dependency file and runs no installer
        # (`sandbox/image.py`: `if runtime.install != "none" and runtime.dependencies`), so whatever
        # the project's environment holds came from `runtime.base` and cannot be moved by editing a
        # lockfile. DR-0007 makes *the project brings its own image* the primary path, so this is
        # not an edge case — it is most projects.
        #
        # **Measured on 2026-08-09** against a base image carrying `jinja2 3.0.0`, on a checkout
        # pinning `jinja2==2.4.1`:
        #
        #     [ready to take] jinja2 2.4.1 → 2.10.1
        #     $ docker run --rm <both sandbox images> python -c "import jinja2; print(...)"
        #     3.0.0
        #     3.0.0
        #
        # Neither version in the claim was ever installed. The "before" run did not use 2.4.1 and
        # the "after" run did not use 2.10.1; both used a third version, and the verdict said the
        # suite passed before the change and after it — which was true, and about nothing.
        return (
            f"your manifest sets `install: none`, so the image is `{runtime.base}` exactly as it "
            f"comes and nothing is installed from {dep.source}. Changing a version there cannot "
            f"change what your suite runs against, so no verdict here would be about this "
            f"upgrade.\n"
            f"    This is the primary path in DR-0007 and it is not a defect in your project: an "
            f"image that already carries your dependencies is upgraded by rebuilding it, not by "
            f"editing a pin. Declare an installer and the file it reads if you want this measured."
        )

    if runtime.dependencies and dep.source not in runtime.dependencies:
        declared = ", ".join(runtime.dependencies)
        return (
            f"{dep.source} is not one of the files your image is built from ({declared}), so "
            f"changing a version in it changes nothing the suite would run against. Whatever this "
            f"upgrade does, your suite cannot say — and a green run here would mean only that the "
            f"file nobody installs from was edited.\n"
            f"    Declare it in `runtime.dependencies` if your build should read it, or upgrade it "
            f"by hand: this is a fact about what your image installs, not about the upgrade."
        )

    if not versions:
        # Not "no fix found": the advisory publishes none, which is a fact about the advisory rather
        # than a gap in this reading.
        return "no published fixed version, so there is nothing to try"

    try:
        bump.can_rewrite(dep.source)
    except bump.CannotRewriteError as refused:
        return str(refused)
    return None


def _print_the_queue(reports: Sequence[bump.Report], out: TextIO) -> None:
    """The ranked report. DR-0018 step 2, and the whole of what it is for.

    **This is the part Renovate cannot produce.** Its documented weakness is that it hands over
    every update undecided — noise rather than signal — and ranking them requires knowing what each
    one does, which requires running them. Everything above ran them; this is where that is spent.
    """
    if not reports:
        return
    counted = bump.summary(reports)
    print("\n=== what to do with them ===\n", file=out)
    for needs in (
        bump.Needs.FIX_YOUR_SUITE, bump.Needs.NEEDS_WORK,
        bump.Needs.BLOCKED, bump.Needs.JUST_TAKE_IT,
    ):
        # Every bucket, including the empty ones: a reader has to be able to tell "none of these"
        # from "this was not counted", and only one of those is good news.
        print(f"  {counted[needs]:>3}  {needs.value}", file=out)

    print("", file=out)
    for report in bump.ranked(reports):
        needs = bump.needs_of(report)
        settled = report.settled
        where = f" → {settled.to}" if settled is not None else ""
        broke = bump.broke(report)
        cost = f", {broke} test(s) to fix" if broke and settled is None else ""
        print(f"  [{needs.value}] {report.package} {report.was}{where}{cost}", file=out)
    print("", file=out)


def _verify_one(
    checkout: Path,
    paths: Sequence[str],
    read: Callable[[str], str | None],
    manifest: Manifest,
    dep: dependencies.Dependency,
    versions: list[str],
    out: TextIO,
) -> bump.Report | None:
    """One package, every candidate, each in its own sandbox."""
    from hullwork import trial
    from hullwork.sandbox import image as image_module
    from hullwork.sandbox.run import Sandbox

    runtime = manifest.runtime
    assert runtime is not None  # noqa: S101 - refused above, and mypy cannot see that
    tests = manifest.tests or ""
    source = dep.source

    # Which candidate `verify` is on, so a resolver-backed mover knows what to ask for.
    _pending: dict[str, str] = {"version": ""}

    with ExitStack() as stack:
        worktree = dispatch_module.prepare_worktree(checkout)
        stack.callback(shutil.rmtree, worktree, ignore_errors=True)

        def files_now() -> dict[str, bytes]:
            """The declared dependency files as they are in the worktree right now.

            Read per build rather than once: the rewrite happens between the two, and the second
            build has to see it — `image.dependency_digest` then makes the tag differ by itself,
            which is what turns the second build into a real rebuild.
            """
            found: dict[str, bytes] = {}
            for path in runtime.dependencies or [source]:
                whole = worktree / path
                if whole.exists():
                    found[path] = whole.read_bytes()
            return found

        built: dict[str, str] = {}
        # **The commit the source is at, when the source goes into the build at all** (item 182).
        # Read once: it is what `image_tag` hashes to decide whether an image can be reused, and the
        # source does not move between candidates — only the dependency files do, and those are
        # hashed separately by `dependency_digest`.
        source_ref = trial.head_sha(checkout) if runtime.install_needs_source else None

        def build_now() -> str | None:
            try:
                image = image_module.build(
                    runtime, files_now(), None,
                    # **Item 113's fix, which this path never inherited** (found by item 182, on
                    # the first third-party tree it was pointed at). The build context holds the
                    # declared dependency files and never the source, and three ordinary installers
                    # read the source anyway: a `requirements.txt` beginning `-e .`, a `Gemfile`
                    # that says `gemspec`, and `mvn test`. Measured on `encode/httpx`, whose first
                    # requirement is `-e .[brotli,cli,http2,socks,zstd]`:
                    #
                    #   ERROR: file:///work does not appear to be a Python project:
                    #          neither 'setup.py' nor 'pyproject.toml' found.
                    #
                    # Reported as *your own environment does not build*, which was true of what we
                    # built and false of the project. Ruby, Java and PHP are on the roadmap as
                    # stacks whose attempts work; every one of them reaches this the same way.
                    source=worktree if runtime.install_needs_source else None,
                    source_ref=source_ref,
                )
            except image_module.ImageBuildError as failed:
                return str(failed)
            built["tag"] = image.tag
            return None

        # The baseline image, before anything is rewritten. A failure here is the project's
        # environment, not the upgrade's, so it is said as that.
        problem = build_now()
        if problem is not None:
            print(f"  {dep.name}: your own environment does not build — {problem}\n", file=out)
            return None

        made = {"n": 0}

        def make_box(_version: str) -> bump.Box:
            """A box on **whatever image `built` holds right now**.

            Called once per run rather than once per candidate, because the second run has to
            happen on the rebuilt image — reusing the first box measures the upgraded project's
            suite against the environment it replaced, and reports `clean` for a version that was
            never installed. Found by a real Docker run; see item 174.
            """
            made["n"] += 1
            # Built from the worktree **as it is now**, which is what makes each run happen in the
            # environment its own tree describes. Cheap when nothing changed: the digest is the
            # content, so `build` reuses the existing image rather than making another.
            build_now()
            box = Sandbox(image=built["tag"], worktree=worktree)
            stack.callback(box.cleanup)
            box.ensure_volume(
                f"hullwork-deps-{os.getpid()}-{made['n']}",
                # **Item 114's fix, which this path never inherited either** (item 182). Anything
                # the build installed under `/work` is erased by the worktree volume unless the
                # image goes down first — which is what `vendor/` is for PHP, and the reason that
                # item exists. Off unless the project asks, so every other project takes the path
                # it took yesterday.
                seed_from_image=runtime.install_needs_source,
            )
            return box  # type: ignore[return-value]

        # How this file is moved, and everything moving it can touch (items 175 and 176). For a
        # list the line is the pin; for a resolved graph only the ecosystem's own tool may move it,
        # and `touches` is what stops one candidate leaving a widened range behind for the next.
        resolver = resolve.resolver_for(source)
        mover = None
        guarded: tuple[str, ...] = (source,)
        if resolver is not None:
            guarded = resolve.touches(resolver)
            here = [p for p in paths if p.rsplit("/", 1)[-1] in set(resolver.needs)]

            def mover(worktree: Path, _r: resolve.Resolver = resolver) -> str | None:
                outcome = resolve.upgrade(
                    resolver=_r, worktree=worktree, package=dep.name, version=_pending["version"],
                    present=here, run=resolve.in_a_container,
                )
                return None if outcome.ok else f"{outcome.outcome.value}: {outcome.detail}"

        report = bump.verify(
            tests=tests, source=source, package=dep.name,
            was=dep.version, versions=versions,
            make_box=make_box, rebuild=lambda _text: build_now(),
            mover=mover, touches=guarded, pending=_pending,
        )

    for answer in report.answers:
        print(f"  {answer.says}", file=out)
        if answer.detail:
            for line in answer.detail.splitlines()[:8]:
                print(f"      {line}", file=out)
    print("", file=out)
    return report


def _cmd_features(args: argparse.Namespace, settings: Settings, out: TextIO) -> int:
    """What this can do for your project, and what it cannot. Item 186.

    **The same rules as `projects lanes --checkout .`**, which is the precedent this copies: a
    checkout, no credential of any kind, nothing executed, nothing written and no socket opened. It
    answers before you have decided anything, which is the only moment the answer is worth having.

    Settings are read for **which variables are set and never for their values**, so this can say
    *needs a model credential, and none is configured* while holding none — and can be run by
    somebody who has configured nothing at all.
    """
    checkout = Path(args.checkout).resolve()

    manifest = None
    manifest_path = checkout / MANIFEST_FILENAME
    if manifest_path.exists():
        try:
            manifest = parse_manifest(manifest_path.read_text(encoding="utf-8"),
                                      source=str(manifest_path))
        except ManifestError as broken:
            # Said and carried on. A manifest that does not parse is a fact about this checkout and
            # answers half the questions below by itself; refusing here would withhold the other
            # half over a file the reader is about to fix anyway.
            print(f"{manifest_path} does not parse, so everything it would answer reads as no:\n"
                  f"  {broken}\n", file=out)

    known = features.Checkout(
        paths=tuple(_tracked_files(checkout)),
        manifest=manifest,
        configured=frozenset(
            name
            for name, present in (
                (features.MODEL_KEY, settings.model_key is not None),
                (features.CODE_TOKEN, settings.forge_code_token is not None),
                ("origin", _origin_url(checkout) is not None),
            )
            if present
        ),
    )

    print(f"What Hullwork can do for {checkout.name}, and what it cannot.\n", file=out)
    answers = features.examine(known)
    for line in features.lines(answers):
        print(line, file=out)

    print(
        "Every limit above is true whether or not the feature is available — that is what a limit "
        "is. Nothing here ran, opened a socket or needed a credential.",
        file=out,
    )
    if features.INSTANCE_SHAPED:
        print(
            "\nAnswered by `hullwork doctor` on the instance rather than here, because a checkout "
            "cannot know them: " + ", ".join(features.INSTANCE_SHAPED) + ".",
            file=out,
        )
    return 0


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


def _tracked_files(checkout: Path) -> list[str]:
    """The checkout's tracked files, which is what a forge would serve.

    **Tracked rather than walked**, and the reason is the same for both callers: a walk reads
    `.venv/` and `node_modules/`, so a proposal would come from a cache and a dependency report
    would be about somebody else's dependencies.
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
            f"tracked files so what it reports matches what a forge would serve.\n"
            f"  {listed.stderr.strip()}"
        )
    return [line for line in listed.stdout.splitlines() if line]


def _origin_url(checkout: Path) -> str | None:
    """The `origin` remote's URL, or `None` when there is not one to have.

    One call, two readers: the coordinate below and the forge that holds it (item 171). Asking
    git twice for the same string would let the two answers disagree about the same repository.
    """
    url = subprocess.run(  # noqa: S603
        ["git", "-C", str(checkout), "remote", "get-url", "origin"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    return url.stdout.strip() if url.returncode == 0 else None


def _coordinate_from(url: str | None) -> str:
    """`owner/name` out of a remote URL, or a visible placeholder.

    A manifest's `git.repo` is validated as `owner/name` (`manifest.py`), so the directory's own
    name would produce a proposal that cannot parse — the one thing a proposal must never do, since
    its whole purpose is to be committed. The remote is where that coordinate exists locally.

    When there is no usable remote the placeholder is `owner/name` verbatim: it fails validation
    loudly and reads as something to replace, which is the same choice as `REPLACE-ME` for
    `group_add`. A plausible-looking wrong value would be committed.
    """
    if url:
        trimmed = url.removesuffix(".git")
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
    paths = _tracked_files(checkout)

    def read(path: str) -> str | None:
        try:
            return (checkout / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    origin = _origin_url(checkout)
    for candidate in propose.find(paths):
        text = read(candidate)
        if text is None:
            continue
        proposal = propose.read(_coordinate_from(origin), candidate, text)
        # Which forge holds this, when the host says so (item 171). Set here rather than passed
        # into `read`, which parses CI text and has no business knowing about remotes.
        proposal.remote_host = propose.host_of_remote(origin)
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


def set_tracker(session: Session, slug: str, tracker_project: str | None) -> Project:
    """Name this project in the tracker, or unname it. Instance configuration, never the manifest.

    **Extracted by item 207**, the only production code that item moved: this lived inside
    `_cmd_set_tracker` and had no caller but that command, so the page would have had to reimplement
    it — the drift items 193, 194, 200 and 203 each cost a day to. Empty means *stop sweeping it*,
    which is a real answer and not a missing one.
    """
    project = _require(session, slug)
    project.tracker_project = tracker_project or None
    session.commit()
    return project


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


def _print_credential(url: str, slug: str, out: TextIO, into: str | None = None) -> None:
    """Hand the operator their webhook URL — to the screen, or to a file only they can read.

    **The screen is the right default and the wrong channel for a script.** The token is stored
    hashed, so this is the only moment it exists in readable form: an operator who cannot see it
    cannot paste it into their tracker. But standard output is not private — it lands in terminal
    scrollback, in `script` output, in a screenshot sent with a question, and in a CI log the day
    somebody automates registration. CodeQL called that `clear-text-logging-sensitive-data` at
    `high` (item 163), and it was right about the pipeline even though wrong about the person.

    So `--credential-file` writes it at mode 600 and prints the path instead, the same shape the
    gateway's model credential already uses. Same rule as `hullwork init` (item 115): it **refuses
    to overwrite**, because a credential silently replaced is one somebody is still using.
    """
    if into is not None:
        target = Path(into)
        if target.exists():
            raise CommandError(
                f"{target} already exists, and this would overwrite a credential.\n"
                f"  Something may still be using it. Move it aside, or name another path."
            )
        # Created with the mode rather than chmod-ed after: between the two calls there is a moment
        # where the token is world-readable, and that moment is the whole point of the flag.
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(f"{url}\n")
        print(f"\n  The credential is in {target}, mode 600, and nowhere else.\n", file=out)
        print("  Paste it into your error tracker as the webhook target, then delete it.", file=out)
        print(f"  If it leaks or is lost: hullwork projects rotate-secret {slug}\n", file=out)
        return

    print("\n  This URL is the credential. It is shown once and cannot be recovered:\n", file=out)
    print(f"    {url}\n", file=out)
    print("  Paste it into your error tracker as the webhook target.", file=out)
    print(f"  If it leaks or is lost: hullwork projects rotate-secret {slug}\n", file=out)
    print(
        "  Registering from a script? `--credential-file PATH` writes it at mode 600 and prints\n"
        "  the path instead, so the token does not end up in a log.\n",
        file=out,
    )


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
    _print_credential(
        registration.webhook_url(settings.base_url),
        registration.project.slug,
        out,
        into=getattr(args, "credential_file", None),
    )
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
    _print_credential(url, project.slug, out, into=getattr(args, "credential_file", None))
    return 0


def approve(session: Session, slug: str, item_id: int) -> Item:
    """Let an agent attempt one amber item. One item, named explicitly, by a human.

    **The decision itself moved to `decisions.py` in item 166**, because the page grew a button and
    a route would otherwise import a command from here — the shape item 162 removed from `sandbox/`.
    What stays is this signature, which takes a slug because a person types a slug, and the mapping
    from the decision's refusal to this module's.

    The comment that used to live here argued that approval should be a command and never an
    endpoint: *"the operator already has the host, and an approval endpoint would be a permanent
    attack surface for something done by one person a handful of times."* Item 166 reversed it, with
    the ground it stood on: the operator no longer *has* the host in any useful sense — reading the
    page happens on a laptop and acting meant SSH, `docker compose exec` and this command, which
    measured out at two items waiting twenty-one hours on an instance somebody was looking at. The
    attack surface is still real, which is why the endpoint needs a second credential that never
    appears in a URL.
    """
    try:
        return decide.approve(session, _require(session, slug), item_id)
    except decide.DecisionError as exc:
        raise CommandError(str(exc)) from exc


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


def _cmd_password(
    args: argparse.Namespace, session: Session, settings: Settings, out: TextIO
) -> int:
    """Set the password that unlocks the two buttons on the page. Item 168.

    **Read from a prompt, not from an argument.** A password on a command line is in shell history,
    in `ps`, and in whatever collects either. `--stdin` exists for a provisioning script, which has
    the same problem and has usually already solved it.

    Third design in three items, and the two before were secure and unusable: a stored key to paste,
    then a one-time link that meant a trip to the host every twelve hours. This is what every
    self-hosted tool does, for a mechanical reason — a browser's password manager fills it in.
    """
    if args.end_sessions:
        ended = operator.end_every_session(session)
        print(f"Ended {ended} session(s). The password is unchanged.", file=out)
        return 0

    if args.stdin:
        chosen = sys.stdin.readline().rstrip("\n")
    else:
        chosen = getpass.getpass("New password: ")
        if chosen != getpass.getpass("Again: "):
            raise CommandError("the two did not match; nothing was changed")

    least = 12
    if len(chosen) < least:
        raise CommandError(
            f"that is {len(chosen)} character(s); this wants at least {least}.\n"
            "  It is the only thing between a stranger who found the page URL and your budget,\n"
            "  and the browser will remember it for you — so length is nearly free here."
        )

    existing = operator.configured(session)
    operator.set_password(session, chosen)
    print("Password changed. Every session that was open has ended." if existing else
          "Password set. The page can now be signed in to.", file=out)
    print(
        f"\n  Open the page and sign in once per browser; the session lasts "
        f"{operator.LIFETIME.days} days and renews while you use it.\n"
        "\n"
        "  What a session may do: approve one item waiting for a decision, or hand one to a\n"
        "  human. Nothing else on the page changes anything, and there is no approve-everything.\n"
        "\n"
        "  The page's own URL is unaffected: it still only reads, so it is still safe to hand to\n"
        "  somebody who should see this instance without being able to spend its budget.\n"
        "\n"
        "  To end every session without changing the password: hullwork password --end-sessions",
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
            # The dispatcher skips an item whose enrichment has not come back, and only when there
            # is a tracker for it to come back from. Counting without this reports work as ready
            # that the dispatcher would deliberately leave alone.
            tracker_configured=bool(settings.tracker_url and settings.tracker_token),
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
        env_file, compose = where_the_deployment_files_are(settings)
        gaps = doctor.environment_gaps(settings, env_file=env_file, compose_file=compose)
        payload = report.as_dict()
        payload["dispatcher_loop"] = {
            "state": loop_state,
            "last_seen": loop_seen,
            # `null` is "not recorded", which is not `false`. Item 110.
            "error_reporting": lease.reporting_of(session),
        }
        json_merged, json_holding, json_recurred = recurrence.counted(session)
        payload["attempts"] = outcomes.funnel(session).as_dict()
        # Item 183: the parts, so an operator computes their own ratio. Never a percentage here
        # either — six samples do not carry that precision, and a number this product publishes
        # about itself is the one place that matters most.
        payload["desk"] = outcomes.desk(session).as_dict()
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

    # **First, because DR-0017 signed for it** (item 183). Everything below this block has
    # *attempts* as its denominator and therefore answers *of the attempts we made, how did they
    # go*. This one has **what arrived** as its denominator, which is the question the accepted
    # decision says the product is measured by — and it is above the others because a reader who
    # stops after one block should have read the one that can embarrass us.
    desk_said = outcomes.desk_lines(outcomes.desk(session))
    if desk_said:
        print("\n  The desk:", file=out)
        for line in desk_said:
            print(f"    - {line}", file=out)

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
    # **The same function the page renders** (item 203), so a reader with a terminal and a reader
    # with a browser cannot come to disagree about the same instance.
    standing = features_module.on_this_instance(session, settings)
    worrying = [one for one in standing if one.state is not features_module.ON]
    print("\n  Features:", file=out)
    if worrying:
        for one in worrying:
            print(f"    ! {one.name}: {one.state} — {one.detail}", file=out)
        print(f"    - {len(standing) - len(worrying)} of {len(standing)} on", file=out)
    else:
        print(f"    - all {len(standing)} on", file=out)

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


def where_the_deployment_files_are(
    settings: Settings,
    *,
    env_file: str | None = None,
    compose_file: str | None = None,
) -> tuple[Path, Path | None]:
    """The env file and the compose file `environment_gaps` should read, for every command.

    **One question, one answer** (item 194, and item 193 the same day for the same reason). Item 144
    added these settings so a containerised instance could point the check at the host's files —
    inside a container the working directory holds neither, so it silently never ran on any real
    deployment. That fix reached `doctor` and neither of the two call sites `status` uses, so on the
    live instance the configured path was set, the file was mounted at it, and `status` printed *not
    checked: no environment file at `.env`* — the default it never replaced.

    Precedence is a person, then the machine, then the default: `--env-file` is the only place
    somebody names the file by hand, and somebody standing in front of the machine outranks how it
    was configured.

    The compose falls back to the default **only when it exists**, because `None` there means *no
    compose to compare against*, which is a different fact from *a compose that passes nothing on*.
    """
    resolved_env = Path(env_file or settings.deployment_env_file or DEFAULT_ENV_FILE)

    named = compose_file or settings.deployment_compose_file
    if named:
        return resolved_env, Path(named)
    return resolved_env, DEFAULT_COMPOSE_FILE if DEFAULT_COMPOSE_FILE.exists() else None


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
    # **Configuration before the working directory** (item 144), and now in one place for all three
    # commands (item 194) — this was the only one that had it, which is why `status` was reporting
    # `not checked` on an instance that had configured everything the message asked for.
    env_file, compose_file = where_the_deployment_files_are(
        settings, env_file=args.env_file, compose_file=args.compose_file
    )

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
    project = set_tracker(session, args.slug, args.tracker_project)
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
    env_file, compose = where_the_deployment_files_are(settings)
    gaps = doctor.environment_gaps(settings, env_file=env_file, compose_file=compose)
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

    if getattr(args, "telemetry", False):
        return _cmd_config_telemetry(settings, out)

    for line in settings_report.lines(settings):
        print(line, file=out)
    return 0


def _cmd_config_telemetry(settings: Settings, out: TextIO) -> int:
    """The exact bytes this instance would send upstream. Item 153.

    **The project's own standard, applied to itself.** Everything else here refuses to guess on an
    operator's behalf — *asked, not assumed*, `None ≠ 0 ≠ absent`, a claim is checkable or it is not
    made. A prose description of a payload is exactly the kind of claim this product exists to
    distrust, so the payload is printed instead.

    Built from this instance's real state, not from an example: the identifier is the one in this
    database, the counts are its rows, and the frames come from a live traceback of a crash raised
    here — so the shape shown is the shape the machinery reads. When the database cannot be reached,
    it says so and prints the rest, which is what a report from that instance would look like too.
    """
    from hullwork import upstream

    destination_dsn = upstream.destination(settings)
    if destination_dsn is None:
        why = (
            "declined with HULLWORK_TELEMETRY"
            if settings.upstream_dsn is not None
            else "this build has no destination in it"
        )
        print(f"Nothing is reported upstream: {why}.", file=out)
        print(
            "\nA destination exists only in the image published by the project's own release\n"
            "workflow. A build made from a checkout has nowhere to send anything, and no test\n"
            "in this repository would pass if one appeared in the source.",
            file=out,
        )
        return 0

    factory: Callable[[], Session] | None = None
    with suppress(Exception):  # a report from an instance in this state is worth showing too
        factory = make_session_factory(get_engine(settings.database_url))

    destination = upstream.Destination(
        destination_dsn, operation="cli:config", session_factory=factory
    )
    # **`mint=False`: asking what would be sent must not enrol anybody.** This command exists so a
    # person can decide, and writing the row that identifies them as the price of checking would be
    # the opposite of the point.
    instance = destination.instance(mint=False)

    print(upstream.notice(destination.host).strip(), file=out)
    print(
        f"\nThe payload for a crash right now, exactly as it would be sent to "
        f"{destination.host}:\n",
        file=out,
    )

    # A real exception, raised here, so the frames are read from a live traceback rather than typed.
    try:
        msg = "the crash this payload is for"
        raise RuntimeError(msg)
    except RuntimeError as raised:
        event = upstream.event_for_a_crash_here(raised)

    payload = upstream.upstream_payload(event, instance)
    if payload is None:
        # Not reachable from the raise above — the frame is inside `hullwork.cli` — but the
        # constructor is allowed to refuse (item 151: an event with no frame of ours is not ours to
        # send), and a command about honesty must not print `null` as if it were a payload.
        print(
            "Nothing would be sent for that crash: it has no frame inside Hullwork's own code, "
            "so it is not Hullwork's defect to collect.",
            file=out,
        )
        return 0

    print(json.dumps(payload, indent=2, sort_keys=True), file=out)

    if instance.installation is None:
        print(
            "\n`installation` is null: this instance has no identifier, because asking what\n"
            "would be sent does not create one. It is sixteen random bytes in one row, written\n"
            "the first time something is actually reported — nothing derived from this machine —\n"
            "and all it does is tell forty crashes from one install from one crash from forty.",
            file=out,
        )
    print(
        f"\nThat is the whole of it: {len(json.dumps(payload))} bytes, "
        f"{len(payload)} fields, no message.\n"
        "HULLWORK_TELEMETRY=off stops it.",
        file=out,
    )
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
        "pull request would carry, and `evidence.html` beside it is the page a reviewer is shown "
        "on a real instance — open it, or send it to somebody.\n"
        "  What that page cannot have here: the numbers an instance keeps across runs — cost over "
        "time, review debt, whether a fix held. Those need one (DR-0014).",
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
    # `dispatcher` is the label an upstream report is counted under, and the session this command
    # already holds is where the installation's identifier is read from (item 152).
    reporting = configure_error_reporting(
        settings, operation="dispatcher", session_factory=lambda: session
    )
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


def _init_description() -> str:
    """What `init` is, said where a person meets it. Item 200.

    It reaches the network now, which it never used to, and that belongs here rather than in a
    release note nobody reads.
    """
    return (
        "Write the compose file and environment a real deployment needs, then say what is still "
        "missing — for the capabilities you asked for, not for everybody.\n\n"
        "Safe to run again: it never overwrites a file that is already there, and the second run "
        "is the report on its own, which is what you want after pasting a credential.\n\n"
        "**It reaches the network** when a forge is configured: one connection to it, and one "
        "authenticated request to ask what your token may do. With nothing configured it contacts "
        "nobody. It writes nothing outside the directory you give it and creates no database."
    )


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
    # **Asked only where there is somebody to ask** (item 197). This command is documented as
    # running from inside the image, before the package exists anywhere, and an installer script has
    # no terminal to answer with — so with no TTY it does what it has always done. Pressing
    # enter at every question produces the same files, which is what keeps the documented path and
    # the lazy path the same path.
    answers = scaffold.Answers()
    if sys.stdin.isatty() and not args.no_questions:
        print("Five questions, and enter is an answer to all of them.\n", file=out)
        answers = scaffold.ask(lambda q, hint: input(f"  {q}\n    [{hint}] "))
        print("", file=out)
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
        # **No longer a no-op** (item 200). This said *nothing to do* at the exact moment somebody
        # has pasted a token and wants to know whether it works — the least useful output in the
        # product, printed on the run where the reader has the most to ask.
        print("\nBoth files were already there, so nothing was written.", file=out)

    # Only what was answered, and only into a file this run created — `write` refuses to overwrite
    # (item 115), and filling in a file somebody already had would be that refusal with extra steps.
    environment = into / scaffold.ENVIRONMENT_FILE
    if answers.assigned() and scaffold.ENVIRONMENT_FILE in done.created:
        environment.write_text(
            scaffold.filled(environment.read_text(encoding="utf-8"), answers), encoding="utf-8"
        )
        print(
            f"\n  filled in  {len(answers.assigned())} value(s) you gave, in "
            f"{scaffold.ENVIRONMENT_FILE}",
            file=out,
        )

    # **One report, assembled in one place** (item 200). This called `what_is_still_needed` and
    # printed it, while `preflight` answered the same question its own way four hours later — two
    # enumerations of what is missing, kept equal by nobody. `preflight.examine` now asks the
    # capability question too, so a variable's consequence is written in the capability table and
    # read from there by whoever prints it.
    from hullwork import preflight

    # **Its own settings, because this runs before `main` builds any** (item 115's `scaffolding`
    # hook). A configuration this process cannot even parse is the most useful thing a report can
    # say, so it is shown rather than raised: `init` is where somebody is still fixing it.
    try:
        settings = get_settings()
    except ConfigError as exc:
        print(f"\n  broken   configuration\n             {exc}", file=out)
        return 1

    found = preflight.examine(
        settings, answers=answers, environment_file=into / scaffold.ENVIRONMENT_FILE
    )
    print("\nWhere this deployment stands:\n", file=out)
    for one in found:
        if one.state is doctor.State.OK:
            continue
        print(f"  {one.state.value:9}{one.check}", file=out)
        print(f"             {one.detail}", file=out)

    print(
        f"\nThen:\n"
        f"\n"
        f"  set -a; . ./{scaffold.ENVIRONMENT_FILE}; set +a; docker compose up -d --build\n"
        f"  hullwork doctor — it names what is still missing, one line each.\n",
        file=out,
    )
    if not answers.autofix:
        print(
            "Attempting fixes is off, which is a whole product and the default. It is opted into "
            "per project in each repository's own hullwork.yml, needs two more credentials, and "
            "runs in a second container this compose file keeps behind a profile:\n"
            "\n"
            "  docker compose --profile autofix up -d\n",
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
    add.add_argument(
        "--credential-file",
        metavar="PATH",
        help=(
            "write the webhook URL there at mode 600 and print the path instead of the URL, so a "
            "script's log does not end up holding a credential. Refuses to overwrite"
        ),
    )
    add.set_defaults(func=_cmd_add)

    listing = actions.add_parser("list", help="list registered projects")
    listing.set_defaults(func=_cmd_list)

    disable = actions.add_parser("disable", help="deactivate a project without deleting anything")
    disable.add_argument("slug")
    disable.set_defaults(func=_cmd_disable)

    rotate = actions.add_parser("rotate-secret", help="issue a new webhook token")
    rotate.add_argument("slug")
    rotate.add_argument(
        "--credential-file",
        metavar="PATH",
        help=(
            "write the webhook URL there at mode 600 and print the path instead of the URL, so a "
            "script's log does not end up holding a credential. Refuses to overwrite"
        ),
    )
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

    depending = subparsers.add_parser(
        "deps",
        help="which pinned dependencies have a published vulnerability",
        description=(
            "Reads the lock files a checkout carries, asks OSV what is published against those "
            "exact versions, and prints what came back with the version that ends each one.\n\n"
            "Needs no credential of any kind: no forge, no model, no Docker, no database. The one "
            "host it contacts is OSV's public API, which takes no key and no account. Lock files "
            "rather than declarations, because a declaration is a range and a range does not say "
            "what your build resolved to.\n\n"
            "It proposes nothing and changes nothing. Whether an upgrade survives your own test "
            "suite is a separate question, and answering it is what the sandbox is for.\n\n"
            "Your checkout is never written to, by any of these flags: `--verify` and `--fix` work "
            "in a copy, and what `--fix` produces is written where you point `--into` — for you to "
            "read. Nothing is opened on any forge."
        ),
    )
    depending.add_argument(
        "--checkout", default=".", help="the checkout to read (default: the current directory)"
    )
    depending.add_argument(
        "--verify",
        action="store_true",
        help=(
            "take each published fix, apply it, and run your own test suite against it in a "
            "sandbox — reporting whether the upgrade holds, breaks your suite (naming the tests) "
            "or will not install. Needs a hullwork.yml and the Docker daemon; the report without "
            "this flag needs neither. No model credential either way: there is no agent in this "
            "path."
        ),
    )
    depending.add_argument(
        "--fix",
        action="store_true",
        help=(
            "for the upgrades that break your suite, ask an agent to change your code so they fit "
            "— then run your suite again with the upgrade still applied, and check the version is "
            "still pinned afterwards. Implies --verify. This is the only part of `deps` that calls "
            "a model, so it needs a model credential; it still needs no forge and opens nothing, "
            "and what it produced is written to --into for you to read."
        ),
    )
    depending.add_argument(
        "--open",
        action="store_true",
        help=(
            "open a draft pull request for every upgrade that passed your suite — one per package, "
            "never a batch, rooted at the commit the runs were made against. Implies --verify. "
            "This is the only flag here that writes to your repository, and it needs "
            "HULLWORK_FORGE_URL and HULLWORK_FORGE_CODE_TOKEN. Nothing that broke, nothing that "
            "was blocked, and nothing whose baseline was red is ever opened."
        ),
    )
    depending.add_argument(
        "--into",
        default="hullwork-refits",
        help="where to write what the fix attempts produced (default: ./hullwork-refits)",
    )
    depending.set_defaults(standalone=_cmd_deps)

    featuring = subparsers.add_parser(
        "features",
        help="what Hullwork can do for this project, and what it cannot",
        description=(
            "Reads your checkout and your hullwork.yml and says, feature by feature, whether this "
            "instance can do it for you — and when it cannot, which requirement is missing and "
            "what to do about it.\n\n"
            "Needs no credential of any kind. It runs nothing, opens no socket, starts no "
            "container and writes nothing: it is a reading of what you already have, meant to be "
            "run before you have decided anything.\n\n"
            "Every feature also carries what it cannot do **even when it is available**, because a "
            "limit you meet after adopting something is a limit you found the expensive way. "
            "Variables are read for whether they are set, never for their values."
        ),
    )
    featuring.add_argument(
        "--checkout", default=".", help="the checkout to read (default: the current directory)"
    )
    featuring.set_defaults(standalone=_cmd_features)

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
    configuring.add_argument(
        "--telemetry",
        action="store_true",
        help=(
            "print the exact payload this build would report upstream, built from this instance's "
            "own state"
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
        "init",
        help="write what a deployment needs, and say what is still missing",
        description=_init_description(),
    )
    starting.add_argument(
        "--into", default=".", help="where to write them (default: the current directory)"
    )
    starting.add_argument(
        "--no-questions",
        action="store_true",
        help=(
            "write the files without asking anything, which is what happens anyway when there is "
            "no terminal. Answering every question with enter produces the same files"
        ),
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

    password = subparsers.add_parser(
        "password",
        help="set the password that unlocks the buttons on the page",
        description=(
            "The page reads with a token in its URL, which is why it may not act: a URL is a thing "
            "that gets saved, screenshotted and forwarded. This sets a second credential that "
            "never appears in a URL — typed into the page's login once per browser, which is "
            "where a browser's password manager takes over.\n\n"
            "Until this runs there is no login and no buttons, and every route that would change "
            "something answers 404 the way an unknown path does.\n\n"
            "Read from a prompt: a password on a command line is in shell history and in `ps`."
        ),
    )
    password.add_argument(
        "--stdin",
        action="store_true",
        help="read it from standard input instead of prompting, for a provisioning script",
    )
    password.add_argument(
        "--end-sessions",
        action="store_true",
        help="end every open session without changing the password",
    )
    password.set_defaults(func=_cmd_password)

    pruning = subparsers.add_parser(
        "prune", help="forget the raw bodies of old deliveries, keeping every row"
    )
    pruning.add_argument("--older-than-days", type=int, default=90)
    pruning.set_defaults(func=_cmd_prune)

    return parser


#: The sandbox's declared failures, rendered as sentences at the boundary rather than as tracebacks.
#: Bound to the package by a test, so a new one is covered on the day it is written.
SANDBOX_FAILURES = (BundleError, EgressError, ImageBuildError, SandboxError, ServiceError,
                    UnsafePathError)


def _label(args: argparse.Namespace) -> str:
    """What an upstream report from this command is counted under. Item 157."""
    return f"cli:{getattr(args, 'group', None) or upstream_module.UNKNOWN}"


def _arm_reporting_quietly(args: argparse.Namespace) -> None:
    """Reporting for a command that runs before a deployment exists, and never at its expense.

    **Everything is swallowed here on purpose.** `init` writes a deployment's first two files, so it
    must work when the environment is empty or wrong — its own comment below says so. Refusing it
    because *error reporting* could not be set up would invert the priority completely.

    Which means `hullwork init` reports its crashes only when the environment is already valid. That
    is a real gap and it is the honest one: the alternative is a command that cannot run.
    """
    try:
        configure_error_reporting(get_settings(), operation=_label(args), brief=True)
    except Exception:
        log.debug("could not arm error reporting for a scaffolding command", exc_info=True)


def main(argv: Sequence[str] | None = None, out: TextIO = sys.stdout) -> int:
    """Entry point. Returns an exit code and never raises at an operator."""
    args = build_parser().parse_args(argv)
    scaffolding = getattr(args, "scaffolding", None)
    if scaffolding is not None:
        # Before `get_settings`, before the logger, before the database — a command that writes a
        # deployment's first two files cannot require the deployment to exist.
        _arm_reporting_quietly(args)
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
        # **Every command, not only `work`** (item 157). Measured: with a DSN configured, a crash in
        # `hullwork projects list` sent nothing at all — `configure_error_reporting` was called from
        # one subcommand out of sixteen, so an operator reading `error reporting: on` in `status`
        # had been told something true about the service and false about the tool.
        #
        # `init`, `projects add` and `try` are the first three commands a stranger runs, before
        # there is a service to report anything, and they were the silent ones.
        #
        # Not for `work`: it arms its own further down, with a session, so its reports carry this
        # installation's identifier. Arming here as well would print the notice twice.
        #
        # **A caught failure is still not an event.** `CommandError`, the sandbox's declared
        # failures, `ConfigError` and a database that will not answer are all handled below and
        # never reach an excepthook — which is what keeps item 120's boundary intact: a refusal is
        # not a defect.
        if getattr(args, "group", None) != "work":
            configure_error_reporting(settings, operation=_label(args), brief=True)
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
    except SANDBOX_FAILURES as exc:
        # **`main`'s own docstring says it "never raises at an operator", and it did.** Measured
        # 2026-08-05 against the published wheel: a base image Docker cannot resolve reaches
        # `image.build`, which raises `ImageBuildError`, which nothing caught — so a stranger's
        # first five minutes ended in eleven frames of Python and the sentence *"could not build
        # the sandbox image: base 'distroless', install 'none', packages none"*.
        #
        # These six are the sandbox's **declared** failures: what it says can go wrong. Rendering
        # them as sentences is not the same as swallowing exceptions — an unexpected error is a bug
        # and still gets its traceback, which is what a bug deserves. A test asserts that every
        # `*Error` in `hullwork/sandbox/` is in this tuple, so the seventh one cannot arrive
        # unhandled the way the first one did.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except SQLAlchemyError as exc:
        # **A database that will not answer is an operator's problem, not a stack trace** (item
        # 156). Measured inside the published image with the SQLite file overwritten by bytes that
        # are not a database: `hullwork projects list` printed eleven frames whose last line was a
        # link to SQLAlchemy's error index, and the good diagnosis — *"file is not a database"* —
        # was three lines from the top where nobody reads.
        #
        # Only what SQLAlchemy declares, for the reason the tuple above exists: an unexpected error
        # is a bug and still gets its traceback. The database URL comes from the settings rather
        # than from the exception, so the sentence names a path the reader can edit — and for
        # Postgres, a host and a database instead of a file that does not exist.
        print(
            f"error: {db.why_the_database_would_not_open(get_settings().database_url, exc)}",
            file=sys.stderr,
        )
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
