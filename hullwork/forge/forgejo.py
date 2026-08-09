"""Forgejo and Gitea, which share an API.

Every shape below was confirmed against a live Forgejo (`easybyte/hullwork-sandbox`) on 2026-07-27,
not taken from documentation. Three of those confirmations changed the code:

* file contents come back **base64-encoded** inside JSON, never as plain text;
* labels attach **by id**, and passing a name attaches nothing without erroring;
* the default branch is read from the repository rather than assumed to be `main`.
"""

import base64
import binascii
import logging
from collections.abc import Sequence
from typing import Any

import httpx2

from hullwork.forge import (
    HTTP_NOT_FOUND,
    MARKER_PREFIX,
    SHA,
    TREE_PAGE_SIZE,
    TREE_PAGES,
    WIP_PREFIX,
    BranchExistsError,
    FileChange,
    ForgeIssue,
    ForgePullRequest,
    MergeState,
    PermanentForgeError,
    RetryableForgeError,
    Tree,
    labels_of,
    parsed_time,
    refuse_unless_ingest_may_write,
)
from hullwork.manifest import MANIFEST_FILENAME

log = logging.getLogger(__name__)


#: Anything at or above this is worth another go; below it, retrying just wastes the attempt.
_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})

#: HTTP 500 responses whose message says the request will never work.
#:
#: The contents API answers **500** to three deterministic mistakes — deleting a path that is not
#: there, an unrecognised operation verb, and a path containing `..` — all verified against a live
#: instance. Classified by status alone, a path typo would exhaust its retries and then be reported
#: as "the forge was down", which is the exact misclassification DR-0003's attempt accounting exists
#: to prevent: "the network was bad" and "this request is wrong" must not look the same.
#:
#: Only 500 is second-guessed. A 502, 503 or 504 comes from infrastructure in front of the
#: application and its body says nothing about our request.
_PERMANENT_AT_500 = (
    "does not exist",
    "invalid file operation",
    "exit status 128",
)

_INTERNAL_SERVER_ERROR = 500

#: A branch that is already there, as reported by `POST /branches`. The contents endpoint answers
#: 422 for the same condition; we only use the first, so this is the one that needs translating.
HTTP_CONFLICT = 409


class _ForgejoAPI:
    """HTTP plumbing for one Forgejo instance and one token.

    **No longer ignorant of what the token is allowed to do** (item 061). It used to be, and the two
    subclasses below were the whole boundary — which made spec M2 §1's promise rest on nobody adding
    a write method to the wrong one of two similarly-named classes. `ingest_only` moves the promise
    into the one function every request passes through, so it holds however the operator's token
    happens to be scoped.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 15.0,
        transport: httpx2.BaseTransport | None = None,
        ingest_only: bool = False,
    ) -> None:
        self._base = base_url.rstrip("/")
        #: Whether this client may only write to issues and labels (item 061). Set by the subclass
        #: rather than by the caller: which role a client is, is not configuration.
        self._ingest_only = ingest_only
        self._client = httpx2.Client(
            base_url=f"{self._base}/api/v1",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/json",
                "User-Agent": "hullwork",
            },
            timeout=timeout,
            follow_redirects=False,
            # Injected only by tests, so the suite never opens a socket.
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:  # noqa: ANN401
        if self._ingest_only:
            # Before the request is built, so a refusal means nothing was asked. "It returned an
            # error" and "it never asked" differ, and only the second is the promise.
            refuse_unless_ingest_may_write(method, path)
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx2.TimeoutException as exc:
            raise RetryableForgeError(f"{method} {path}: timed out") from exc
        except httpx2.TransportError as exc:
            raise RetryableForgeError(f"{method} {path}: {exc}") from exc

        if response.status_code in _RETRYABLE_STATUS:
            if _says_it_will_never_work(response):
                # Still without the body: the message is matched, never echoed.
                raise PermanentForgeError(
                    f"{method} {path}: HTTP {response.status_code}, and the forge says the "
                    f"request itself is wrong",
                    response.status_code,
                )
            raise RetryableForgeError(
                f"{method} {path}: HTTP {response.status_code}", response.status_code
            )
        if response.status_code >= 400:
            # The body can carry the token back in an error echo, so it is never included here.
            raise PermanentForgeError(
                f"{method} {path}: HTTP {response.status_code}", response.status_code
            )

        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise PermanentForgeError(f"{method} {path}: response was not JSON") from exc


def _decoded(repo: str, path: str, data: object) -> str:
    """The text of a `contents` response, or a refusal that says what arrived instead.

    Shared by `read_manifest` and `read_file` (item 107) rather than written twice: base64 is
    confirmed against a live instance, and anything else means the API changed — where guessing is
    worse than stopping.
    """
    if not isinstance(data, dict):
        raise PermanentForgeError(f"{repo}: unexpected response reading {path}")
    encoding = data.get("encoding")
    content = data.get("content")
    if encoding != "base64" or not isinstance(content, str):
        raise PermanentForgeError(
            f"{repo}: expected base64 content for {path}, got {encoding!r}"
        )
    try:
        return base64.b64decode(content).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise PermanentForgeError(f"{repo}: {path} is not valid UTF-8") from exc


def _says_it_will_never_work(response: httpx2.Response) -> bool:
    """Whether a 500 is really a permanent refusal wearing the wrong status code."""
    if response.status_code != _INTERNAL_SERVER_ERROR:
        return False
    try:
        message = str((response.json() or {}).get("message", ""))
    except ValueError:
        return False
    lowered = message.lower()
    return any(phrase in lowered for phrase in _PERMANENT_AT_500)


class ForgejoForge(_ForgejoAPI):
    """The ingest client. **Writes to issues and labels only, enforced in `_request`** (061)."""

    def __init__(self, base_url: str, token: str, **kwargs: Any) -> None:  # noqa: ANN401
        # `ingest_only` is not a keyword the caller may pass: being the ingest role is what this
        # class *is*, and a caller able to switch it off would be the hole this closes.
        kwargs.pop("ingest_only", None)
        super().__init__(base_url, token, ingest_only=True, **kwargs)

    """A Forgejo/Gitea instance seen through the always-on credential.

    Issue write and content read. **No verb here may change code** — that is `ForgejoCodeForge`,
    which is a separate class on a separate token so that handing one where the other belongs fails
    at once instead of pushing quietly.
    """

    # --- reads -----------------------------------------------------------------------------

    def head_commit(self, repo: str, branch: str) -> str:
        data = self._request("GET", f"/repos/{repo}/branches/{branch}")
        commit = data.get("commit") if isinstance(data, dict) else None
        sha = commit.get("id") if isinstance(commit, dict) else None
        if not sha:
            raise PermanentForgeError(f"{repo}: branch {branch} has no head commit")
        return str(sha)

    def default_branch(self, repo: str) -> str:
        """Ask the repository, never assume `main`.

        Plenty of repositories still use `master`, and a wrong guess here reads the manifest from a
        branch that does not exist — a 404 that looks like "no manifest" rather than "wrong branch".
        """
        data = self._request("GET", f"/repos/{repo}")
        branch = data.get("default_branch") if isinstance(data, dict) else None
        if not branch:
            raise PermanentForgeError(f"{repo}: repository has no default branch")
        return str(branch)

    def can_write_code(self, repo: str) -> bool | None:
        """Read `permissions.push` from the repository, or `None` if the forge omits it.

        Verified against Forgejo 15.0.5: `GET /repos/{repo}` carries
        `permissions: {admin, push, pull}` for the authenticated credential. A missing field is
        reported as unknown rather than as absence of permission — an optimistic reading here would
        turn "the API changed" into "your credential is safe", which is the worst available error.
        """
        data = self._request("GET", f"/repos/{repo}")
        permissions = data.get("permissions") if isinstance(data, dict) else None
        if not isinstance(permissions, dict) or "push" not in permissions:
            return None
        return bool(permissions["push"])

    def read_file(self, repo: str, path: str) -> str | None:
        """`GET /repos/{repo}/contents/{path}` on the default branch. Item 107.

        `None` for a missing file: the caller is looking for a CI configuration under three possible
        names and absence is the ordinary answer.
        """
        ref = self.default_branch(repo)
        try:
            data = self._request("GET", f"/repos/{repo}/contents/{path}", params={"ref": ref})
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return None
            raise
        return _decoded(repo, path, data)

    def read_manifest(self, repo: str) -> str:
        """Manifest text from the default branch, and from nowhere else.

        No `ref` parameter by design: reading it from a pull request head would let anyone able to
        open a PR rewrite their own risk lanes.
        """
        ref = self.default_branch(repo)
        data = self._request(
            "GET", f"/repos/{repo}/contents/{MANIFEST_FILENAME}", params={"ref": ref}
        )
        if not isinstance(data, dict):
            raise PermanentForgeError(f"{repo}: unexpected response reading {MANIFEST_FILENAME}")

        return _decoded(repo, MANIFEST_FILENAME, data)

    def get_issue(self, repo: str, number: int) -> ForgeIssue | None:
        """Read one issue, or None if it is genuinely gone.

        **Only a 404 means gone.** This used to swallow every `PermanentForgeError` and return
        `None`, which the caller reads as "the issue was deleted" — so a revoked, expired or
        wrongly-scoped token silently disabled reconciliation for the life of the instance, with no
        log line anywhere. The retryable failures were reported and the permanent one was not,
        which is exactly the wrong way round (item 016).
        """
        try:
            data = self._request("GET", f"/repos/{repo}/issues/{number}")
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return None
            raise
        return _to_issue(data) if isinstance(data, dict) else None

    def merge_state(self, repo: str, number: int) -> MergeState:
        """Ask the forge whether a pull request was merged, and what commit it produced. M9.

        Forgejo answers `merged`, `merge_commit_sha` and `merged_at` on the pull request itself, so
        this is one request. A 404 is `merged=False` rather than an error: a pull request somebody
        deleted is not merged, and the watch has to keep working after a tidy-up.
        """
        try:
            data = self._request("GET", f"/repos/{repo}/pulls/{number}")
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                # Deleted. Not merged, and not a decision either — nobody closed it, it is gone.
                return MergeState(merged=False)
            raise
        if not isinstance(data, dict):
            return MergeState(merged=False)
        # Item 138: `state` is `open` or `closed` here, and `merged` is the separate flag that says
        # which kind of closed. Read together, they are the reviewer's decision.
        closed = str(data.get("state", "")) == "closed"
        labels = labels_of(data)
        if not data.get("merged"):
            return MergeState(
                merged=False, state="closed" if closed else "open", labels=labels
            )
        raw = data.get("merged_at")
        return MergeState(
            merged=True,
            commit=str(data["merge_commit_sha"]) if data.get("merge_commit_sha") else None,
            merged_at=parsed_time(raw) if isinstance(raw, str) else None,
            state="merged",
            labels=labels,
        )

    def tree(self, repo: str) -> Tree:
        """`GET /repos/{repo}/git/trees/{sha}?recursive=1`. M8, item 104.

        **This route paginates and says so per page**, measured against the live forge on
        2026-07-30: 295 entries in this repository, 200 returned with `per_page=200`, and
        `truncated: true` meaning *"this page is not the whole tree"* rather than *"the forge gave
        up"*. `total_count` is served alongside, which is what makes following pages deterministic
        without the `Link` header — broken on this API, as `list_unresolved` documents.

        A branch name works in place of a sha here (measured), and the sha is used anyway: a listing
        and the policy applied to it have to describe one commit, or the two halves can disagree
        about a file added between two requests. Which commit it was comes back on the `Tree`.
        """
        ref = self.head_commit(repo, self.default_branch(repo))
        paths: list[str] = []
        truncated = False
        for page in range(1, TREE_PAGES + 1):
            data = self._request(
                "GET",
                f"/repos/{repo}/git/trees/{ref}",
                params={"recursive": "1", "per_page": TREE_PAGE_SIZE, "page": page},
            )
            if not isinstance(data, dict):
                break
            entries = data.get("tree")
            if not isinstance(entries, list):
                break
            paths.extend(
                entry["path"]
                for entry in entries
                # `blob` only: a policy about code reads files, and this route returns directories
                # too. Keeping them would put `migrations` in the listing as well as every file in
                # it, which reads as a duplicate rather than as a directory.
                if isinstance(entry, dict)
                and entry.get("type") == "blob"
                and isinstance(entry.get("path"), str)
            )
            total = data.get("total_count")
            if not entries or not isinstance(total, int) or len(paths) >= total:
                break
            if page == TREE_PAGES:
                # The bound was reached with entries still unread. Said out loud rather than
                # returning a short list that looks complete.
                truncated = True
        return Tree(tuple(paths), truncated=truncated, ref=ref)

    def release_contains(self, repo: str, release: str, commit: str) -> bool | None:
        """Whether `release` names code that includes `commit`. `None` when it cannot be decided.

        `release` comes from the tracker and is whatever the reporting SDK called the deployed
        version. Only a sha-looking value can be compared, so anything else answers `None`
        **before** a request is made — asking the forge to compare `0.4.2` against a commit
        produces a 404 that looks like a missing repository.

        The comparison is Forgejo's own `compare/base...head`, and **the direction is the whole
        answer**: the route returns the commits `head` has that `base` does not. So the release
        contains the merge when `compare/{release}...{commit}` counts zero — there is nothing in the
        merge the release is missing.

        Measured against the live forge on 2026-07-30, with a release six commits past the merge:

        | asked | `total_commits` |
        |---|---|
        | `compare/{merge}...{release}` | 6 |
        | `compare/{release}...{merge}` | 0 |
        | `compare/{merge}...{merge}` | 0 |

        The first version of this method asked the first row and read a non-zero count as "the
        release predates the merge", which is exactly backwards and reported every genuine
        recurrence as old code still deployed. Nothing caught it: the unit tests served whatever
        number the handler was told to, and the doubles agreed because the same person wrote both.
        The GitHub adapter has the same intent and is correct, because `status: ahead` names the
        direction and a count does not.

        A release that is not sha-shaped answers `None` before any request: comparing `0.4.2` to a
        commit is a 404 that reads like a missing repository.
        """
        if not SHA.fullmatch(release):
            return None
        try:
            data = self._request("GET", f"/repos/{repo}/compare/{release}...{commit}")
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                # Either ref is unknown to the forge — a release tagged from a fork, a commit on a
                # branch that was deleted. Unanswerable, not false.
                return None
            raise
        if not isinstance(data, dict):
            return None
        missing = data.get("total_commits")
        return missing == 0 if isinstance(missing, int) else None

    def find_issue_by_marker(self, repo: str, fingerprint: str) -> ForgeIssue | None:
        """Find an issue by the hidden marker in its body.

        A recovery path, not the usual one: the item already stores its issue reference. This is for
        a database restored from an older backup than the forge.
        """
        marker = f"{MARKER_PREFIX}{fingerprint}"
        data = self._request("GET", f"/repos/{repo}/issues", params={"state": "all", "q": marker})
        if not isinstance(data, list):
            return None
        for raw in data:
            # The search is a text match, so confirm the marker really is in the body rather than
            # trusting the engine to have meant what we meant.
            if isinstance(raw, dict) and marker in (raw.get("body") or ""):
                return _to_issue(raw)
        return None

    # --- writes ----------------------------------------------------------------------------

    def ensure_labels(self, repo: str, names: dict[str, str]) -> dict[str, int]:
        """Create missing labels, return every requested name mapped to its id."""
        existing = self._request("GET", f"/repos/{repo}/labels", params={"limit": 100})
        by_name: dict[str, int] = {}
        if isinstance(existing, list):
            for raw in existing:
                if isinstance(raw, dict) and "name" in raw and "id" in raw:
                    by_name[str(raw["name"])] = int(raw["id"])

        for name, colour in names.items():
            if name in by_name:
                continue
            created = self._request(
                "POST", f"/repos/{repo}/labels", json={"name": name, "color": colour}
            )
            if isinstance(created, dict) and "id" in created:
                by_name[name] = int(created["id"])

        missing = set(names) - set(by_name)
        if missing:
            raise PermanentForgeError(f"{repo}: could not resolve labels {sorted(missing)}")
        return {name: by_name[name] for name in names}

    def create_issue(
        self, repo: str, title: str, body: str, label_ids: list[int] | None = None
    ) -> ForgeIssue:
        payload: dict[str, Any] = {"title": title, "body": body}
        if label_ids:
            # Ids, never names. Passing names here attaches nothing and reports success.
            payload["labels"] = label_ids
        data = self._request("POST", f"/repos/{repo}/issues", json=payload)
        if not isinstance(data, dict):
            raise PermanentForgeError(f"{repo}: unexpected response creating an issue")
        return _to_issue(data)

    def comment(self, repo: str, number: int, body: str) -> None:
        self._request("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body})

    def set_issue_state(self, repo: str, number: int, state: str) -> ForgeIssue:
        if state not in {"open", "closed"}:
            raise PermanentForgeError(f"invalid issue state {state!r}")
        data = self._request("PATCH", f"/repos/{repo}/issues/{number}", json={"state": state})
        if not isinstance(data, dict):
            raise PermanentForgeError(f"{repo}: unexpected response updating issue {number}")
        return _to_issue(data)


class ForgejoCodeForge(_ForgejoAPI):
    """The verbs that change a repository, on `HULLWORK_FORGE_CODE_TOKEN`.

    Everything here was exercised against a live Forgejo 15.0.5 before it was written. Four of those
    findings are load-bearing and are commented where they apply: `draft` cannot be set, an empty
    change set produces an empty commit, "branch already exists" arrives as two different statuses
    depending on which endpoint you used, and three permanent errors arrive as HTTP 500.
    """

    def default_branch(self, repo: str) -> str:
        data = self._request("GET", f"/repos/{repo}")
        branch = data.get("default_branch") if isinstance(data, dict) else None
        if not branch:
            raise PermanentForgeError(f"{repo}: repository has no default branch")
        return str(branch)

    def head_commit(self, repo: str, branch: str) -> str:
        data = self._request("GET", f"/repos/{repo}/branches/{branch}")
        commit = data.get("commit") if isinstance(data, dict) else None
        sha = commit.get("id") if isinstance(commit, dict) else None
        if not sha:
            raise PermanentForgeError(f"{repo}: branch {branch} has no head commit")
        return str(sha)

    def create_branch(self, repo: str, name: str, from_ref: str) -> None:
        """Branch from a ref, which for us is always the sha the gates were run against.

        `old_ref_name` takes a commit sha as happily as a branch name — verified — and that is what
        makes the pull request contain the tree that was tested even if the base moved meanwhile.
        """
        try:
            self._request(
                "POST",
                f"/repos/{repo}/branches",
                json={"new_branch_name": name, "old_ref_name": from_ref},
            )
        except PermanentForgeError as exc:
            # 409 here, but 422 for the same condition when a branch is created as a side effect of
            # the contents call. We only ever use this endpoint, so 409 is the one to translate.
            if exc.status == HTTP_CONFLICT:
                raise BranchExistsError(
                    f"{repo}: branch {name} already exists", exc.status
                ) from exc
            raise

    def file_sha(self, repo: str, path: str, ref: str) -> str | None:
        """The blob id of `path` at `ref`, or `None` when the file is not there.

        A missing file is ordinary news — the fix phase may add one — so it is `None` rather than an
        error, the same shape `get_issue` already uses for a deleted issue.
        """
        try:
            data = self._request("GET", f"/repos/{repo}/contents/{path}", params={"ref": ref})
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return None
            raise
        sha = data.get("sha") if isinstance(data, dict) else None
        return str(sha) if sha else None

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
        """One commit for the whole change set. Returns its sha."""
        if not changes:
            # The forge would answer 201 and move the branch head with an empty commit, turning
            # "the agent changed nothing" into a branch and a diff-less pull request.
            raise PermanentForgeError(f"{repo}: refusing to commit an empty change set")

        identity = {"name": author, "email": email}
        payload: dict[str, Any] = {
            "branch": branch,
            "message": message,
            "author": identity,
            "committer": identity,
            # `signoff` is available and deliberately not set: the DCO sign-off is a human act
            # performed at the merge gate (CONTRIBUTING.md).
            "files": [_to_operation(change) for change in changes],
        }
        data = self._request("POST", f"/repos/{repo}/contents", json=payload)
        commit = data.get("commit") if isinstance(data, dict) else None
        sha = commit.get("sha") if isinstance(commit, dict) else None
        if not sha:
            raise PermanentForgeError(f"{repo}: unexpected response committing to {branch}")
        return str(sha)

    def open_draft_pull_request(
        self,
        repo: str,
        head: str,
        base: str,
        title: str,
        body: str,
        label_ids: list[int] | None = None,
    ) -> ForgePullRequest:
        """Open it as a draft, then check that the forge agrees it is one."""
        payload: dict[str, Any] = {
            "head": head,
            "base": base,
            # The only way to make a draft: `draft` is absent from the create payload entirely.
            "title": f"{WIP_PREFIX}{title}",
            "body": body,
        }
        if label_ids:
            payload["labels"] = label_ids

        data = self._request("POST", f"/repos/{repo}/pulls", json=payload)
        if not isinstance(data, dict):
            raise PermanentForgeError(f"{repo}: unexpected response opening a pull request")
        pull = _to_pull_request(data)

        if not pull.draft:
            # This instance's work-in-progress prefixes differ from the defaults, and no endpoint
            # exposes them, so there was no way to know in advance. Failing here is the point: the
            # alternative is a merge-ready pull request that the rest of the system calls a draft.
            raise PermanentForgeError(
                f"{repo}: pull request {pull.ref} did not come back as a draft — this instance's "
                f"work-in-progress title prefixes are not the defaults"
            )
        return pull


def _to_operation(change: FileChange) -> dict[str, Any]:
    """One `ChangeFileOperation`. Content is base64, and a delete carries none."""
    operation: dict[str, Any] = {"operation": change.operation, "path": change.path}
    if change.operation != "delete":
        if change.content is None:
            raise PermanentForgeError(f"{change.path}: {change.operation} needs content")
        operation["content"] = base64.b64encode(change.content).decode("ascii")
    if change.sha:
        operation["sha"] = change.sha
    elif change.operation != "create":
        # The forge refuses with "a SHA or commit ID must be provided", but only after the round
        # trip. Saying so here names the missing argument instead of the HTTP status.
        raise PermanentForgeError(f"{change.path}: {change.operation} needs the pre-image blob sha")
    return operation


def _to_pull_request(raw: dict[str, Any]) -> ForgePullRequest:
    return ForgePullRequest(
        number=int(raw["number"]),
        title=str(raw.get("title", "")),
        html_url=str(raw.get("html_url", "")),
        # Read-only and derived from the title by the forge. Never sent, always checked.
        draft=bool(raw.get("draft", False)),
    )


def _to_issue(raw: dict[str, Any]) -> ForgeIssue:
    return ForgeIssue(
        number=int(raw["number"]),
        title=str(raw.get("title", "")),
        state=str(raw.get("state", "")),
        html_url=str(raw.get("html_url", "")),
        body=str(raw.get("body") or ""),
    )
