"""Whether the credentials this instance holds are the ones it claims to hold.

`config.py` promises in writing that the always-on ingest credential "should never be able to push".
Item 017 split the protocols to protect that sentence and item 022 gave them separate classes so a
mix-up fails loudly. On the first instance anybody actually asked, the ingest token created a branch
and committed to the default branch. The sentence was true of the code and false of the token.

So this module exists to stop it being unverifiable. It is deliberately **not** part of `readiness`:
that module states, and depends on, calling no forge — a probe that makes network calls fails for
reasons unrelated to the thing it is probing. This runs when a human asks, which is also when a
human can act.

What it can and cannot see, said once: Forgejo computes `permissions.push` from the **account's**
access to the repository. A token's scope is a second layer underneath that, and no endpoint
*declares* a token's own scope to the token. So a `False` here is meaningful and a `True` is only
half an answer.

**Item 073 corrected what this module says about that half.** It reported a push-capable account as
*"the ingest credential CAN write code — the credential split is a fiction"*, and on 2026-07-29 that
was measured false on the live instance: the account is an owner, and the token, scoped to reads and
issues, is refused with `token does not have at least one of required scope(s): [write:repository]`.
The split was real; this module could not see it, and its remedy sentence prescribed provisioning
a second identity for a guarantee one token scope already gave — the friction DR-0006 removes.

No endpoint declares a scope, but **every write endpoint reveals one by refusing**. That probe is
not implemented here, and the reason is worth recording rather than rediscovering: the ingest client
refuses any write outside issues and labels *before building the request*
(`refuse_unless_ingest_may_write`), which is what makes spec M2 §1 a property of this program
rather than of somebody's token hygiene. A probe would need either an exception to that guard or a
second HTTP client — both of which put code capable of pushing with the ingest token back into the
repository.

**Closed 2026-07-31.** The probe is `token_may_write_code`, and it needs neither: it takes no path
and no body, so there is exactly one request it can make and that request cannot succeed. Its
`old_ref_name` names a ref no repository has, and Forgejo checks the token's scope before it
validates the body — a scoped token gets 403, an unscoped one gets 404, and nothing is created on
either path. The guard on the ingest client is untouched, because this shares no code with it.

Measured on the live instance the day it shipped: both projects answered 403, so the warning printed
on every `status` for two days was about a credential split that was real.

**And it only asked Forgejo, which nobody noticed for three days (item 131).** The second instance
watches a GitHub repository, where `can_write_code` answers `None` by design — GitHub's
`permissions` block reports the account's role and says nothing about a token's grants — and the
probe, built for Forgejo's API, was being sent at a path `github.com` does not serve, so it answered
`None` too. Two honest unknowns, stacking into `could not confirm that the ingest credential is
unable to push`: the audit reporting, correctly, that on that instance DR-0009's split was
**unverified rather than safe**. There are now two request shapes, one per forge, chosen by
`token_may_write_code` and never by a caller.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote

from sqlalchemy.orm import Session

from hullwork.forge import ForgeError, PermissionReader, kind_of
from hullwork.models import Project

log = logging.getLogger(__name__)

#: What an ingest token needs, and the one scope it must not have. `write:repository` is the only
#: scope granting code write on Forgejo and cannot be narrowed, so the split has to be made by
#: leaving it out rather than by trimming it.
INGEST_SCOPES = "read:repository + write:issue (never write:repository)"


@dataclass(frozen=True)
class PushCapability:
    """What the forge says the ingest credential may do to one project's code."""

    slug: str
    repo: str
    #: What the **account** may do, from `GET /repos/{owner}/{repo}`'s `permissions`. `None` when
    #: the forge did not say. Never read as "no", and never as the token's answer — that mistake is
    #: item 073's whole subject.
    can_push: bool | None
    #: The engine this project's manifest names. `none` means no agent will ever act here.
    agent: str
    #: What the **token** may do, from the probe. `None` when it could not be asked or the forge
    #: answered something else. Item 073.
    #:
    #: Separate from `can_push` rather than replacing it, because the two are different facts and an
    #: operator fixes them differently: a narrow token on an account with push access is *correct*,
    #: and telling them to provision a bot account for it would be wrong. Last, and defaulted, so a
    #: caller that cannot run the probe builds a finding that reports the account's answer and
    #: claims nothing about the token.
    token_can_push: bool | None = None

    @property
    def has_an_agent(self) -> bool:
        return self.agent != "none"

    @property
    def is_degradation(self) -> bool:
        """Whether this should make `hullwork status` exit non-zero.

        **Since the probe exists: only when the token itself can write code and an agent is
        configured.** That is the fiction the split exists to prevent, and it is now measured rather
        than inferred from the account's permissions. A token the probe cleared is silent, which is
        what makes this a signal again.

        The history below is kept because it is the reason the flag reads the way it does.

        It used to be `can_push is True and has_an_agent`, and the reasoning was sound given what
        this module believed: with an agent configured, the credential split is what keeps the
        receiver's token away from the repository, and a fiction there is a real degradation.

        What changed is that `can_push` was never evidence of a fiction. It is the **account's**
        access, and a token scoped to reads and issues is refused regardless — measured on the live
        instance, where this flag fired for both projects while `POST /branches` came back `403
        token does not have … scope(s): [write:repository]`. So the exit code was
        raised by the correct configuration, permanently, with no action available that would clear
        it. `hullwork status`'s exit code is wired into people's crons as "is the pipeline working"
        (`docs/deployment-notes.md`), and a signal that is always on is not a signal.

        **The warning was still printed, every run.** What was gone is the claim that this instance
        is degraded on evidence that cannot support it. That sentence ended *"a `True` from the
        probe is the thing that belongs here, and it will be a fact rather than an inference"* —
        and this is that line.
        """
        return self.token_can_push is True and self.has_an_agent


#: The branch a scope probe would create if a scope probe could create anything. It cannot: the
#: request names an `old_ref_name` no repository has, and Forgejo checks the token's scope
#: **before** it validates the body, so a scoped token gets 404 and an unscoped one gets 403. The
#: successful form of this request does not exist.
_PROBE_BRANCH = "hullwork-scope-probe"
_PROBE_FROM = "hullwork-no-such-ref-073"

#: GitHub's half of the same idea, and it needs its own shape because GitHub has no endpoint that
#: branches from a ref by name — it takes a commit to point at. So the impossibility moves into the
#: object: forty zeros is not a commit in any repository that has ever existed, which makes this a
#: request whose successful form cannot be constructed either. Item 131.
_PROBE_SHA = "0" * 40

#: Where GitHub is, spelled out here rather than imported from the client this module must not
#: touch. One constant is a smaller duplication than one import of a class that can push.
_GITHUB_API = "https://api.github.com"

#: The answers that mean something. Named here rather than imported from `forge`, because this
#: module deliberately shares no code with the client whose guard it must not weaken.
_SCOPE_REFUSED = 403
_REF_MISSING = 404
#: GitHub, past the permission check and into validation: the object does not exist. On Forgejo the
#: same "I got as far as the body" answer is a 404, which is why the two shapes cannot share a
#: table of status codes — on GitHub a 404 means something else entirely (see below).
_OBJECT_MISSING = 422
#: GitLab's version of the same answer: past the role check, refusing the ref by name (item 132).
#: Three forges, three status codes for "your credential was fine and your request was not", which
#: is why each shape carries its own table instead of one shared mapping.
_INVALID_REFERENCE = 400


def token_may_write_code(
    forge_url: str,
    token: str,
    repo: str,
    *,
    declared_kind: str | None = None,
    timeout: float = 15.0,
) -> bool | None:
    """Whether **the token** — not the account — may write code to `repo`. `None` when undecidable.

    Item 073's probe, and the reason it took two days to write is that the obvious implementation
    weakens the thing it is auditing. `refuse_unless_ingest_may_write` guards every request the
    ingest client makes, before the request is built, and that guard is *why* spec M2 §1 is a
    property of this program rather than of somebody's token hygiene. Routing a probe through an
    exception to it, or handing the ingest credential to a general-purpose client, would trade a
    real guarantee for a warning.

    **So this function takes no path and no body.** There are exactly two requests it can make —
    one per forge, chosen here and not by a caller — their shapes are fixed in the constants above,
    and the caller supplies only where to ask and with what. It is not code capable of pushing; it
    is code capable of asking a question whose successful form does not exist.

    Measured against the live forge on 2026-07-31, on the deployment whose `status` had been warning
    about a credential split for two days:

    | | |
    |---|---|
    | `easybyte/hullwork` | `403 … does not have at least one of required scope(s):`
      `[write:repository]` |
    | `acme/checkout-api` | the same |
    | branches before and after | `main`, `work-command` — identical |

    The token was already narrow. The warning was reading the account's permissions and calling them
    the token's, which is this item's whole subject.

    **A forge that answers neither is `None`, never `False`.** Guessing "probably fine" is how the
    original defect was introduced, and an unreadable answer is not a pass.

    **`declared_kind` is configuration, not a shape** (item 132). A third forge arrived whose URL
    cannot identify it, so the caller passes what the operator declared — the same kind of value as
    `forge_url`, which has always come from outside — and this function still chooses the request
    from it. What a caller cannot name is a path, a method or a body, which is the property
    `test_the_probe_takes_no_path_and_no_body` holds.
    """
    kind = kind_of(forge_url, declared_kind)
    if kind == "github":
        return _github_may_write_code(token, repo, timeout=timeout)
    if kind == "gitlab":
        return _gitlab_may_write_code(forge_url, token, repo, timeout=timeout)
    return _forgejo_may_write_code(forge_url, token, repo, timeout=timeout)


def _forgejo_may_write_code(
    forge_url: str, token: str, repo: str, *, timeout: float
) -> bool | None:
    """Forgejo rejects an unscoped token before it looks at `old_ref_name`, and rejects the
    `old_ref_name` before it creates a branch. Two checks in that order are what make the question
    askable at all."""
    import httpx2

    try:
        with httpx2.Client(
            base_url=forge_url.rstrip("/") + "/api/v1",
            headers={"Authorization": f"token {token}"},
            timeout=timeout,
        ) as client:
            response = client.post(
                f"/repos/{repo}/branches",
                json={"new_branch_name": _PROBE_BRANCH, "old_ref_name": _PROBE_FROM},
            )
    except Exception:  # any transport failure means "cannot tell", not "safe"
        return None

    if response.status_code == _SCOPE_REFUSED:
        # The scope stopped it. Whether the *account* could is beside the point: the token is what
        # travels with every request this instance makes.
        return False
    if response.status_code == _REF_MISSING:
        # Past the scope check and into the body, where the ref does not exist. The token can write.
        return True
    return None


def _github_may_write_code(token: str, repo: str, *, timeout: float) -> bool | None:
    """The same question, in the only shape GitHub answers. Item 131.

    **Why this had to exist rather than reusing the one above.** `GitHubForge.can_write_code`
    returns `None` on purpose: GitHub's `permissions` block reports the *account's* role, not the
    token's grants, and reports `admin: true, push: true` for both of ours. The Forgejo probe was
    then sent at `github.com/api/v1/…`, a path GitHub does not serve, so it answered `None` too.
    Two honest unknowns stacked into a warning nobody could clear — and the warning said, correctly,
    that on the GitHub instance the credential split of DR-0009 was **unverified rather than safe**.

    Measured on 2026-08-03 against `FlagshipDev/personal-dashboard`, with the instance's two real
    tokens, from inside the two containers that hold them:

    | | |
    |---|---|
    | ingest token (receiver) | `403 Resource not accessible by personal access token` |
    | code token (dispatcher) | `422 Object does not exist` |
    | `heads` before and after | `glitchtip-error-reporting`, `main` — identical |

    So the signal is clean in both directions and it was worth measuring: the refusal and the
    permitted-but-invalid answer are different status codes, which is the whole basis for reading
    one as `False` and the other as `True`.

    **A `404` is `None` here, and this is the part that must never become `False`.** GitHub answers
    `404` rather than `403` when a token cannot see a repository at all, precisely so that probing
    cannot enumerate private repositories — so a `404` is *"no permission, or no such repository"*,
    two facts with opposite meanings for this audit. Reading it as a refusal would report a
    credential as verified-safe on the strength of a repository name typo.
    """
    import httpx2

    try:
        with httpx2.Client(
            base_url=_GITHUB_API,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=timeout,
        ) as client:
            response = client.post(
                f"/repos/{repo}/git/refs",
                json={"ref": f"refs/heads/{_PROBE_BRANCH}", "sha": _PROBE_SHA},
            )
    except Exception:  # any transport failure means "cannot tell", not "safe"
        return None

    if response.status_code == _SCOPE_REFUSED:
        return False
    if response.status_code == _OBJECT_MISSING:
        # Past the permission check and into validation, where the object does not exist. Nothing
        # was created — it could not be — and the token has been shown to be able to write code.
        return True
    return None


def _gitlab_may_write_code(
    forge_url: str, token: str, repo: str, *, timeout: float
) -> bool | None:
    """The same question, in GitLab's shape. Item 132.

    The branch route takes the source ref as a parameter, like Forgejo's, so the impossibility stays
    in the ref rather than moving into an object: `_PROBE_FROM` names a ref no repository has.

    **The status mapping is a prediction until item 132's gate runs**, and it is written down so the
    gate can contradict it: a refusal is expected as `403`, and a permitted request dying on the
    invalid ref as `400 Invalid reference name`.

    **Which way this fails if the order is the other one.** If GitLab validated the ref *before* the
    role, a Reporter would also get `400` and this would answer `True` — a warning about a
    credential split that is actually intact. Noise, and an operator can act on it. The opposite
    reading is the one that must never happen, and cannot: a `403` does not arrive from a token that
    can push, so a `False` cannot be manufactured by getting the order wrong. Anything else is
    `None`, including the `404` GitLab answers when a token cannot see the project at all — the same
    trap as GitHub's, and the same answer.
    """
    import httpx2

    try:
        with httpx2.Client(
            base_url=forge_url.rstrip("/") + "/api/v4",
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        ) as client:
            response = client.post(
                f"/projects/{quote(repo, safe='')}/repository/branches",
                params={"branch": _PROBE_BRANCH, "ref": _PROBE_FROM},
            )
    except Exception:  # any transport failure means "cannot tell", not "safe"
        return None

    if response.status_code == _SCOPE_REFUSED:
        return False
    if response.status_code == _INVALID_REFERENCE:
        # Past the role check and into validation, where the ref does not exist. Nothing was
        # created — it could not be — and the token has been shown able to write code.
        return True
    return None


def the_two_tokens_must_differ(ingest: str | None, code: str | None) -> str | None:
    """The one failure this module can prove without asking anybody. Item 073.

    If the same token is in both variables, the credential split is not a fiction to be inferred
    from an API's answer — it is **arithmetic**, and it is false. Two protocols, two classes and a
    request-time guard all exist to keep the ingest client away from code, and every one of them is
    bypassed by pasting one value into two places.

    Worth writing down that it was missing: `audit` went to the network on every project to infer a
    permission it cannot see, while the case it *can* see for free went unchecked. The cheap certain
    answer is always worth more than the expensive uncertain one.

    Compared by value and never logged. Returning a message rather than the tokens is not manners:
    this string reaches a terminal and a log, and the two things compared are credentials.
    """
    if ingest is None or code is None:
        return None
    if ingest != code:
        return None
    return (
        "HULLWORK_FORGE_TOKEN and HULLWORK_FORGE_CODE_TOKEN hold the same value, so there is no "
        "credential split at all — the always-on receiver holds the credential that can push. Two "
        "protocols, two classes and a request-time guard exist to prevent this, and none can. "
        "Issue a second token: the ingest one needs " + INGEST_SCOPES + "."
    )


def audit(
    session: Session,
    forge: PermissionReader | None,
    *,
    probe: Callable[[str], bool | None] | None = None,
) -> list[PushCapability]:
    """Ask the forge, per active project. Two calls each; only ever run on request.

    `probe` answers what the **token** may do (item 073) and is injected rather than built here, for
    two reasons. It needs the raw credential, which this module has no business reading from
    settings. And a test has to be able to assert the audit is silent when the probe says the token
    is narrow *and* loud when it says otherwise — both directions, or the change only proves the
    warning can be turned off.

    `None` leaves `token_can_push` unset, which reports the account's answer and claims nothing
    about the token: the behaviour before the probe existed.
    """
    if forge is None:
        return []

    findings: list[PushCapability] = []
    for project in session.query(Project).filter(Project.active.is_(True)).all():
        manifest = project.manifest or {}
        autofix = manifest.get("autofix") if isinstance(manifest.get("autofix"), dict) else {}
        agent = str((autofix or {}).get("agent", "none"))
        try:
            can_push = forge.can_write_code(project.repo)
        except ForgeError as exc:
            # An unreachable forge is not an answer about a credential, and it is already reported
            # by every other path. Unknown, and it says so.
            log.warning(
                "could not ask the forge what this credential may do",
                extra={"project": project.slug, "error": str(exc)},
            )
            can_push = None
        # Only where it could matter. The probe is a request per project, and a project whose
        # account cannot push has nothing for it to disprove — the split is not in question there.
        token_can_push = (
            probe(project.repo) if probe is not None and can_push is not False else None
        )
        findings.append(
            PushCapability(
                slug=project.slug,
                repo=project.repo,
                can_push=can_push,
                agent=agent,
                token_can_push=token_can_push,
            )
        )
    return findings


def describe(finding: PushCapability) -> str | None:
    """One line for a human, or `None` when there is nothing worth saying.

    Says what to do, not only what is wrong. "Your token is too powerful" sends an operator to a
    search engine; naming the two scopes sends them to the right page of their own forge.
    """
    # **The token's answer first, because it is the one that decides.** Item 073: the account's
    # permissions describe what a person could do, and every request this instance makes carries the
    # token. A narrow token on an account with push access is a correct installation, and the old
    # message called it a fiction on every run — a warning that cannot be cleared by doing the right
    # thing teaches people to ignore warnings.
    if finding.token_can_push is False:
        return None
    if finding.token_can_push is True and finding.has_an_agent:
        return (
            f"{finding.slug}: the ingest **token** can write code to {finding.repo} — measured, "
            f"not inferred: a request only a code scope allows was accepted. An agent is "
            f"configured here, so the credential split for this project is a fiction. Give the "
            f"token {INGEST_SCOPES}."
        )
    if finding.can_push is None:
        return (
            f"{finding.slug}: could not confirm that the ingest credential is unable to push — "
            f"treat it as unknown, not as safe"
        )
    if not finding.can_push:
        return None
    severity = (
        "if the token's scope does not stop it, the credential split for this project is a fiction"
        if finding.has_an_agent
        else "check when convenient: nothing here writes code yet"
    )
    return (
        f"{finding.slug}: the **account** behind the ingest credential can write code to "
        f"{finding.repo}, and whether the token's own scope stops it is not readable from here — "
        f"{severity}. Cheapest fix first: give the token {INGEST_SCOPES}. Failing that, the "
        f"account behind it should not have push access. To confirm which you have, ask the forge "
        f"to do something only a code scope allows and read the refusal."
    )
