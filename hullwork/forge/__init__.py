"""The forge boundary: read a manifest, create and label issues.

Constitution §3 says core logic never imports a provider directly, and this is the first place that
rule earns its keep. Everything above this module sees the `Forge` protocol and nothing else.

Only Forgejo/Gitea ships in M1 (operator decision, 2026-07-27). GitHub fits the same protocol
without touching core, but shipping an adapter verified against nothing but our own recorded
fixtures would be claiming support we have never once exercised.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable
from urllib.parse import urlsplit

#: Marker embedded in the issue body so an item can be found again without relying on the title,
#: which humans edit. Verified searchable against a live Forgejo on 2026-07-27.
MARKER_PREFIX = "hullwork:fingerprint="


#: A missing issue is the one permanent failure a caller may treat as ordinary news.
HTTP_NOT_FOUND = 404

#: What makes a pull request a draft on Forgejo and Gitea: a title prefix, and nothing else.
#:
#: Verified against Forgejo 15.0.5 on 2026-07-27, and three of the findings matter. `draft` is
#: absent from the create and edit payloads, so it cannot be set directly. `Draft:` does **not**
#: work — only `WIP:` and `[WIP]`, which are the instance defaults. And the configured prefixes are
#: exposed by **no** API endpoint, so this constant is a guess about somebody else's configuration.
#:
#: Which is why every caller asserts `draft is True` on the response instead of trusting it: on an
#: instance configured differently, the failure mode of trusting it is a merge-ready pull request
#: that everything downstream calls a draft.
WIP_PREFIX = "WIP: "


class ForgeError(Exception):
    """Something went wrong talking to the forge.

    Carries the HTTP status when there was one. Without it a caller has to tell "the issue was
    deleted" from "your token was revoked" by reading an error string, and getting that wrong
    turns a dead credential into silence.
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class RetryableForgeError(ForgeError):
    """Worth trying again: a 5xx, a timeout, a rate limit.

    Kept distinct because of DR-0003: an item gets **one** attempt. A network blip must not consume
    it — "the forge was down" and "the agent could not fix this" are not the same outcome, and only
    the second one should ever be terminal.
    """


class PermanentForgeError(ForgeError):
    """Trying again will not help: bad credentials, missing repo, malformed request."""


class BranchExistsError(PermanentForgeError):
    """The branch is already there.

    Its own type because it is the one failure of `create_branch` a caller should handle rather
    than report: it means a previous attempt was killed between creating the branch and finishing,
    and the caller has to decide whether to reuse it or stand aside. A `bool` return would say the
    same thing and be ignorable.
    """


@dataclass(frozen=True)
class ForgeIssue:
    """The bits of an issue this system cares about."""

    number: int
    title: str
    state: str
    html_url: str
    body: str = ""

    @property
    def ref(self) -> str:
        """Stable reference stored on the item."""
        return f"#{self.number}"


@dataclass(frozen=True)
class FileChange:
    """One file's fate in a commit.

    `sha` is the **pre-image blob id**, required for an update or a delete: without it the forge
    refuses with "a SHA or commit ID must be provided", and with the wrong one it refuses with a 409
    that quotes the right one back. That is a feature — it makes a commit onto a tree that has moved
    underneath us impossible rather than merely unlikely.
    """

    path: str
    operation: Literal["create", "update", "delete"]
    content: bytes | None = None
    sha: str | None = None


@dataclass(frozen=True)
class ForgePullRequest:
    """The bits of a pull request this system cares about."""

    number: int
    title: str
    html_url: str
    draft: bool

    @property
    def ref(self) -> str:
        """Stable reference stored on the item."""
        return f"#{self.number}"


def labels_of(payload: object) -> tuple[str, ...]:
    """Label names off a pull request payload, whatever shape the forge sent. Item 138.

    All three answer a list of objects with a `name`, and GitLab also answers a list of plain
    strings. Shared rather than written three times because it is a fact about JSON, not about a
    provider — and because three copies of a parser agree right until one of them is widened.
    """
    if not isinstance(payload, dict):
        return ()
    raw = payload.get("labels")
    if not isinstance(raw, list):
        return ()
    names: list[str] = []
    for entry in raw:
        if isinstance(entry, str):
            names.append(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
            names.append(entry["name"])
    return tuple(names)


def marker_for(fingerprint: str) -> str:
    """The hidden line that ties an issue back to its item.

    An HTML comment so it renders as nothing, and searchable so a database restored from an older
    backup than the forge can still find what it already filed.
    """
    return f"<!-- {MARKER_PREFIX}{fingerprint} -->"


#: Every forge this version can serve. `forgejo` and `gitea` are one adapter under two names.
FORGE_KINDS = ("forgejo", "gitea", "github", "gitlab")

#: The kinds that share the Forgejo adapter: Forgejo is a Gitea fork and its API is compatible at
#: every endpoint this uses.
_GITEA_FAMILY = frozenset({"forgejo", "gitea"})


def kind_of(url: str, declared: str | None = None) -> str:
    """Which API this instance talks to: one of `FORGE_KINDS`, collapsed to one adapter each.

    **This exists because the URL stopped being able to answer.** `is_github` works for one reason
    that is not a property of adapters — GitHub has a fixed host — and a self-hosted GitLab at
    `git.example.com` is indistinguishable by URL from a Forgejo at the same address. Item 124
    established that an instance serves exactly one forge and has to say which; with a third forge
    registrable, that sentence needs a mechanism, and the URL cannot be it.

    So the operator declares it, and the declaration is the authority — the rule `is_github` already
    states for provider disagreements: *the operator's value is the one to believe*. What is **not**
    here is autodetection. A probe that guesses wrong sends one forge's request shape at another,
    which is the regression item 131 had to check for, and it would arrive silently rather than as a
    refusal somebody can read. `declaration_disagrees` says the loud thing instead.

    Two deliberate asymmetries:

    * **GitHub still comes from the URL**, and a declaration cannot move it. `api.github.com` speaks
      one API whatever a configuration file says.
    * **No declaration means the Gitea family**, which is what "self-hosted" has meant since M1.
      Every instance running today declares nothing and none has to learn a new variable.
    """
    if is_github(url):
        return "github"
    if declared is None:
        return "forgejo"
    named = declared.strip().lower()
    if named in _GITEA_FAMILY:
        return "forgejo"
    if named == "gitlab":
        return "gitlab"
    # An unknown name is not a licence to pick: `_forge_for` refuses names outside `FORGE_KINDS`
    # with a sentence, and a fallback here would let one through by being helpful.
    return "forgejo"


def declaration_disagrees(url: str, declared: str | None) -> str | None:
    """The one conflict `kind_of` resolves silently, said out loud. `None` when there is none.

    A declaration of anything but GitHub against `api.github.com` is not a preference to honour: it
    is two facts that cannot both be true, and the shape of every request depends on which. Kept
    out of `kind_of` so that decision stays a pure function and the complaint reaches a person
    through `doctor`, where a person can act on it.
    """
    if declared is None:
        return None
    named = declared.strip().lower()
    if named not in FORGE_KINDS:
        return (
            f"HULLWORK_FORGE_KIND is '{declared}', which this version cannot serve "
            f"(available: {', '.join(FORGE_KINDS)})"
        )
    if is_github(url) and named != "github":
        return (
            f"HULLWORK_FORGE_KIND says '{named}' and HULLWORK_FORGE_URL points at GitHub. The URL "
            f"decides — GitHub's host speaks one API — so this instance is serving GitHub and the "
            f"declaration is being ignored. Set them to agree, or point the URL somewhere else"
        )
    return None


def is_github(url: str) -> bool:
    """Whether a configured forge URL is GitHub.

    By the configured URL rather than by the manifest's `git.provider`, because the URL is what the
    operator set and the manifest is what a repository claims. Registration already refuses a
    manifest whose provider disagrees with the instance (item 017 §4), so the two cannot drift —
    and if they ever do, the operator's value is the one to believe.

    **Here, in the interface module, because two callers need it and neither may import the
    other.** `forge.factory` builds a client from it; `credentials` picks which shape of scope
    probe to send (item 131) and must not import a forge client — its whole point is to ask a
    question without going near the guarded ingest path. A second copy of a two-line rule is the
    failure this project has now found four times.
    """
    # **The host, parsed — not a substring of the URL.** CodeQL found the previous version, and it
    # was right: `"github.com" in url` answers yes for `https://github.com.evil.example/`, for
    # `https://notgithub.com/`, and for any URL carrying the string in a query. What that decides is
    # which client shape gets built and **which scope probe gets sent** (item 131), so a spoofable
    # answer is a request shaped for one forge arriving at another.
    parsed = urlsplit(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower()
    return host == "github.com" or host.endswith(".github.com")


#: A release string that can be compared against a commit: forty hex characters, or the
#: abbreviated form a deploy script usually records — seven is git's own minimum and what `git
#: rev-parse --short` gives. Anything else is a package version, and `release_contains` answers
#: `None` rather than asking a forge to compare `0.4.2` with a commit.
#:
#: **Shared by both adapters on purpose.** What a release looks like is a fact about deploy
#: conventions, not about a provider, and two copies of this regex would agree right up until one
#: of them was widened.
SHA = re.compile(r"[0-9a-f]{7,40}")


def parsed_time(raw: str) -> datetime | None:
    """A forge timestamp, or `None` if it is not one.

    Never raises: a `merged_at` this cannot read must not turn a merged pull request into an error.
    The merge is the fact; the timestamp is the decoration.
    """
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None

@dataclass(frozen=True)
class MergeState:
    """Whether a pull request was merged, and what the merge produced. M9.

    Read rather than remembered: Hullwork opens a draft and never merges, so at publish time
    there is nothing to record. The commit is the whole point — without it, an error coming back
    cannot be told apart from an error arriving from a release that predates the fix, which says
    nothing about the fix
    (the same confusion item 039 fixed from the other direction).

    `merged_at` can be `None` on a merged pull request: not every forge reports it, and a missing
    timestamp must not be read as "not merged".
    """

    merged: bool
    commit: str | None = None
    merged_at: datetime | None = None
    #: `open`, `closed` or `merged` — the reviewer's decision, or the absence of one. Item 138.
    #:
    #: **`merged: bool` could not express this**, and that is what made review debt uncountable: a
    #: pull request nobody has looked at and one a reviewer closed without merging both answered
    #: `False`, so an item stayed `pr-open` for ever in both cases. Waiting and refused are opposite
    #: facts, and the milestone that claims not to create review debt has to be able to count it.
    #:
    #: `unknown` when a forge answers something none of the three names, which is neither a decision
    #: nor an absence of one and must not be read as either.
    state: Literal["open", "closed", "merged", "unknown"] = "unknown"
    #: Labels on the pull request, verbatim. The reason for a rejection lives here because that is
    #: where a reviewer can put it without leaving the page they are already on.
    labels: tuple[str, ...] = ()


#: How many pages of a tree listing to follow. Forgejo paginates this route and reports `truncated`
#: per page — measured on 2026-07-30: 295 entries, 200 returned, `truncated: true` — so without a
#: bound one command against a monorepo becomes hundreds of requests. Ten pages covers every
#: repository this instance watches by an order of magnitude, and the caller is told when it does
#: not reach the end.
TREE_PAGES = 10
#: Entries per page. Forgejo's maximum for this route; GitHub ignores it and answers in one shot.
TREE_PAGE_SIZE = 200


@dataclass(frozen=True)
class Tree:
    """A repository's file paths, and whether this is all of them. M8, item 104.

    **`truncated` is not a detail.** This exists so `hullwork lanes` can show an operator which of
    their directories the derived policy calls sensitive, and a partial list presented as complete
    is worse than no list: it reads as *"the policy claims nothing else"* about files it never saw.
    Whoever prints this has to say so.

    Directories are excluded: a policy about code reads file paths, and the route returns both.
    """

    paths: tuple[str, ...]
    truncated: bool = False
    #: The commit these paths are from, resolved by the adapter.
    #:
    #: Reported rather than taken as an argument, and that is the design decision: a caller that
    #: passed a branch name would be describing "whatever the branch is right now", and a listing
    #: plus a policy applied to it has to describe one commit or the two halves can disagree. The
    #: caller prints it, so an operator can tell which tree they read.
    ref: str = ""


@runtime_checkable
class Forge(Protocol):
    """What the always-on pipeline needs from a forge. Deliberately small — and deliberately
    incapable of touching code.

    **This protocol is a credential boundary, not just an interface.** The token behind it is held
    by the webhook path and the periodic sweep: it is in memory whenever the service is running,
    and it is reachable by anything that can reach the receiver. It needs issue write and content
    read, and it must never gain the ability to push.

    M2 wants branches, commits and pull requests. Those belong to `ForgeCode` below, built from a
    different credential and held only by the dispatcher, so that adding them cannot silently make
    the always-on token push-capable. Splitting it after the dispatcher, the sandbox and the tests
    all depend on one object is a re-plumb; splitting it now is a type alias.

    There is no generic `read_file(repo, path, ref)` here either: the manifest is read from the
    **default branch only**, and exposing an arbitrary ref would let a caller read it from a pull
    request head — which is how someone with permission to open a PR rewrites their own risk lanes.
    """

    def read_manifest(self, repo: str) -> str:
        """Manifest text from the repository's default branch. Never from any other ref."""
        ...

    def ensure_labels(self, repo: str, names: dict[str, str]) -> dict[str, int]:
        """Create any missing labels and return name → id.

        Ids, not names: the API attaches labels by id, and passing a name attaches nothing at all
        without complaining. Verified against a live instance.
        """
        ...

    def create_issue(
        self, repo: str, title: str, body: str, label_ids: list[int] | None = None
    ) -> ForgeIssue: ...

    def get_issue(self, repo: str, number: int) -> ForgeIssue | None:
        """Read one issue, or None if it no longer exists.

        Filing an issue and never looking at it again means our idea of what is outstanding drifts
        away from the one the team is actually working from, silently and permanently.
        """
        ...

    def find_issue_by_marker(self, repo: str, fingerprint: str) -> ForgeIssue | None:
        """Locate a previously filed issue by its hidden marker, or None."""
        ...

    def merge_state(self, repo: str, number: int) -> MergeState:
        """Whether a pull request was merged, and what commit the merge produced. M9.

        **On this protocol rather than on `ForgeCode`, deliberately.** Reading a pull request's
        state is a read, and the process that needs it is the receiver — which by DR-0009 must never
        hold a credential that can write code. Putting it on the pushing half would mean the
        recurrence watch had to run in the dispatcher, and the reason it does not is that a watch
        belongs on a clock, not on a queue.
        """
        ...

    def read_file(self, repo: str, path: str) -> str | None:
        """One file's text from the default branch, or `None` if it is not there. Item 107.

        The generalisation of `read_manifest`, and it carries the same rule: **no `ref` parameter.**
        Reading from a pull request head would let anyone able to open one decide what this instance
        believes about their project.

        `None` rather than raising for a missing file, because the only caller looks for files a
        repository *may* have — a CI configuration under three possible names — and absence is the
        common answer rather than a failure.

        This adds no capability the credential did not have: an ingest token holds
        `read:repository` and could always read any file. What it adds is the protocol saying so —
        item 068's argument about `close()`: omitting what callers use is not a smaller protocol,
        it is an unchecked one.
        """
        ...

    def tree(self, repo: str) -> Tree:
        """Every file path in `repo` at the head of its default branch. M8.

        On the **read** protocol: listing paths is a read, and the only caller is a CLI command that
        answers a question for a person. It is deliberately not consulted to decide a lane — a lane
        derived from a stored tree is a snapshot, and `hullwork/territory.py` explains why that
        fails in the fail-open direction.
        """
        ...

    def release_contains(self, repo: str, release: str, commit: str) -> bool | None:
        """Whether the code identified by `release` includes `commit`. `None` when unanswerable. M9.

        Three answers, not two, and the third is the honest one. A tracker's `release` is *"whatever
        the SDK called the deployed version — a commit sha if you were disciplined, a package
        version
        if you were not"*. Given a sha, the forge can compare ancestry. Given `0.4.2`, nothing here
        can, and guessing turns "the fix did not hold" into a claim nobody can check.

        Returning `None` is what lets the caller say *"a recurrence arrived and whether it carries
        the fix cannot be decided from a version string"* — better than either of the two lies
        available.
        """
        ...

    def close(self) -> None:
        """Release the HTTP connection this holds.

        **Declared here because callers already require it.** Both implementations have had it all
        along and `cli.py` calls it in a `finally`; the protocol simply did not say so, which only
        went unnoticed while every caller happened to hold a concrete class. Item 068 made the CLI
        take a `Forge` from the factory and mypy said the quiet part out loud.

        A forge object owns a connection pool. One left open in a long-lived process is a socket
        nobody will close until the process ends, and in a CLI it is a warning on exit that teaches
        an operator to ignore warnings.
        """
        ...

    def head_commit(self, repo: str, branch: str) -> str:
        """The sha a branch points at. **A read**, and that is the whole reason it is here.

        It lived only on `ForgeCode` because only the publisher had needed it. Then item 049's
        rehearsal — which must work without a credential that can write anything — asked the read
        forge for it and got `AttributeError`. Found by running it. `GET /repos/…/branches/…` needs
        nothing an ingest token does not already have.
        """
        ...

    def comment(self, repo: str, number: int, body: str) -> None: ...

    def set_issue_state(self, repo: str, number: int, state: str) -> ForgeIssue: ...


#: What an **ingest** client may write to, matched on the path's structure. Item 061.
#:
#: An allowlist rather than a denylist, and matched on segments rather than as a substring, because
#: both choices fail in the safe direction: a path nobody thought of is refused, and
#: `/repos/o/r/contents/issues` does not sneak through by containing the word.
#:
#: Measured from what the ingest role actually does: create an issue, comment on one, close one, and
#: create a label. Everything else it needs is a GET.
#:
#: **Two route shapes, one rule.** `/repos/{owner}/{name}/…` is Forgejo's and GitHub's; GitLab
#: addresses a project as a single segment — `/projects/{id}/…`, where the id is numeric or the
#: project's path with its separators percent-encoded (item 132).
#:
#: That single segment is what keeps the same `[^/]+` safe for a path with subgroups: `%2F` is not
#: `/`, so `group%2Fsub%2Fproject` is one segment and `/projects/{id}/repository/branches` cannot
#: reach `issues|labels` by having more of them. And an adapter that forgets to encode sends
#: `/projects/group/project/issues`, which matches nothing here and is **refused** — the failure
#: lands on us at the first write rather than on a route nobody predicted.
_INGEST_WRITABLE = re.compile(r"^/(repos/[^/]+/[^/]+|projects/[^/]+)/(issues|labels)(/|$)")

#: Methods that change something. A GET is never restricted: reading a manifest, a branch head or an
#: issue is the ingest role's whole job.
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class CredentialMisuseError(Exception):
    """This code tried to do something it promised not to. Item 061.

    **Not a `ForgeError`**, and that is deliberate: a `ForgeError` means the forge could not serve a
    legitimate request, and callers retry it, degrade around it and report it as the forge being
    unavailable. This is none of those. It means Hullwork attempted a write the credential split
    forbids, so the only correct response is to stop and be noticed.
    """


def refuse_unless_ingest_may_write(method: str, path: str) -> None:
    """Guard every request an ingest client makes. Raises rather than returning a verdict.

    Spec M2 §1 promises that the always-on service's credential cannot write code. Until this
    existed, that promise rested on two things being true: the operator scoping their token
    correctly, and nobody adding a write method to the wrong one of two similarly-named classes.
    Hullwork's own readiness check reports the first as a warning on the instance running today —
    *"the ingest credential CAN write code… the credential split for this project is a fiction"* —
    which makes the promise a property of somebody else's token hygiene rather than of this program.

    The check lives in the one function every request passes through, for the reason item 017 gives
    about guardrails: one that depends on every caller remembering it is not a guardrail.
    """
    if method.upper() not in _WRITE_METHODS:
        return
    if _INGEST_WRITABLE.match(path.split("?", 1)[0]):
        return
    msg = (
        f"the ingest client tried {method} {path}, which is not an issue or a label. Its "
        f"credential must never write code (spec M2 §1), and this refusal does not depend on how "
        f"the token is scoped — only the dispatcher's `ForgeCode` client publishes"
    )
    raise CredentialMisuseError(msg)


@runtime_checkable
class PermissionReader(Protocol):
    """Asks the forge what the credential holding it is allowed to do to code.

    A protocol of its own rather than a method on `Forge`, and the reason is `Forge`'s own first
    line: it is deliberately small and holds what the **pipeline** needs. Nothing in the pipeline
    needs this — only the credential audit does, and only when a human asks. Widening `Forge` for a
    diagnostic would also have required every test double in the suite to grow a method it has no
    use for, which is the shape of a protocol drifting away from its purpose.

    It exists because `config.py` promises in writing that the ingest credential cannot push, and on
    the first instance anybody actually asked, it could: it created a branch and committed to the
    default branch. The sentence was true of the code and false of the token (item 031).
    """

    def can_write_code(self, repo: str) -> bool | None:
        """`True`, `False`, or `None` when the forge does not say.

        `None` is a first-class answer and must never be read as "no". A token's scope is a second
        layer underneath the account's permissions and no endpoint discloses it to the token itself,
        so this answers one of the two questions and admits to the other.
        """
        ...


@runtime_checkable
class ForgeCode(Protocol):
    """Everything that can change a repository. Behind `HULLWORK_FORGE_CODE_TOKEN`, and held only
    by the dispatcher — never by the request path or the sweep.

    Declared empty by item 017 so the split would exist before there was anything to split. Filled
    in by item 022, and **implemented by a different class** than `Forge` rather than by the same
    one. That is a deliberate second line: if the always-on object does not so much as *have* a
    `create_branch`, then a bug that passes the ingest forge where a code forge belongs fails
    immediately and loudly. Share one class and the same bug pushes with the always-on token and
    reports success — silently, and only on instances whose token happens to carry the scope.

    There is no `merge`, and there never will be. `human-merge` is a gate (constitution §1); a
    method for it would be one refactor away from being called.
    """

    def default_branch(self, repo: str) -> str:
        """The branch a pull request should target."""
        ...

    def head_commit(self, repo: str, branch: str) -> str:
        """The commit a branch points at.

        Read once before the tree is checked out, and it becomes the identity of the thing the gates
        were run against. Everything the evidence trail claims is claimed about this sha.
        """
        ...

    def create_branch(self, repo: str, name: str, from_ref: str) -> None:
        """Branch from `from_ref`, which may be a **commit sha** and normally is.

        Rooting the branch at the exact sha that was tested, rather than at whatever the default
        branch points to now, is what makes the evidence honest without needing a lock: the base can
        move freely during an attempt and the pull request still contains precisely the tree the
        gates passed. Raises `BranchExistsError` if the name is taken.
        """
        ...

    def file_sha(self, repo: str, path: str, ref: str) -> str | None:
        """The pre-image blob id of one file, or `None` if it is not there.

        Needed because `FileChange` requires it for an update or a delete, and the fix phase always
        updates files that already exist — so without this every real pull request stops at its
        second commit. Found exactly that way, on the first end-to-end run.

        `ref` is explicit and is the sha the gates ran against, never a branch name. Reading the
        pre-image from wherever the branch happens to point now is how a commit lands on a tree
        nobody tested.
        """
        ...

    def close(self) -> None:
        """Release whatever the adapter opened.

        **Declared here for item 068's reason, one protocol later.** Both implementations have had a
        `close` since they were written, and this protocol did not say so — which meant `mypy`
        refused the one caller that tried to use it (`hullwork republish`, item 079) and the honest
        options were to declare it or to leave a client unclosed. Item 068 answered the same
        question for the read protocol in the same words: an adapter that opens connections has to
        close them, and leaving it off the protocol removes the check rather than the obligation.
        """
        ...

    def commit_files(
        self,
        repo: str,
        branch: str,
        message: str,
        changes: Sequence[FileChange],
        *,
        author: str,
        email: str,
    ) -> str:
        """Land every change as **one** commit and return its sha.

        One commit, not one per file: the reproducing test is one commit and the fix is the next,
        and a reviewer's ability to check out the first and watch it fail is the point of DR-0003.

        Refuses an empty change set. The forge accepts one — it returns 201 and moves the branch
        head with an empty commit — so "the agent changed nothing" would otherwise become a branch
        and a pull request with no diff in it.

        No sign-off trailer, ever, though the API adds one. CONTRIBUTING.md says the DCO
        sign-off is a human act performed at the merge gate; that a machine *can* emit the
        trailer is exactly why it must not.
        """
        ...

    def open_draft_pull_request(
        self,
        repo: str,
        head: str,
        base: str,
        title: str,
        body: str,
        label_ids: list[int] | None = None,
    ) -> ForgePullRequest:
        """Open a pull request that a human has to un-draft before it can be merged.

        Draft is not a parameter. M2 opens nothing else, and an argument that is always `True` is an
        argument that can one day be `False` by accident.

        Labels go in at creation on purpose: on Forgejo, labelling here needs `write:repository`
        while labelling an issue afterwards needs `write:issue` — so doing it in this call keeps
        issue-write off the code credential entirely.
        """
        ...

