"""GitHub, both halves.

Items 034 and 035. Every shape below was confirmed against `FlagshipDev/hullwork-sandbox` with two
fine-grained tokens on 2026-07-27, and **two of the four things this adapter was expected to need
turned out to be wrong** — which is the argument for the standard M1 set rather than against it:

* labelling a pull request was expected to need issue write. It does not: `POST /issues/{n}/labels`
  succeeds with `pull_requests: write` alone, verified applied. So nothing widens and nothing is
  skipped;
* drafts were expected to be roughly Forgejo's. They are better — a real `draft` field, and
  `405 Pull Request is still a draft` on merge, rather than a title prefix anyone with PR write can
  edit away.

The two that held:

* **there is no batch contents endpoint.** A multi-file commit is blobs → tree → commit → update
  ref, so atomicity stops being the server's problem and becomes ours;
* **`GET /git/ref/heads/{branch}` on a repository with no commits answers 409 `Git Repository is
  empty`**, so there is no base to build on until something is committed.

And the thing that made the credential split worth having: GitHub separates `contents` from `issues`
from `pull_requests` per repository, so the boundary item 017 drew in code is enforceable **in the
credential** here — proved by effect, where the ingest token gets 403 writing a file and the code
token gets 403 filing an issue. Forgejo's finest grain is `write:repository`, which also carries
deploy keys and collaborators.
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
    BranchExistsError,
    FileChange,
    ForgeIssue,
    ForgePullRequest,
    MergeState,
    PermanentForgeError,
    RetryableForgeError,
    Tree,
    labels_of,
    marker_for,
    parsed_time,
    refuse_unless_ingest_may_write,
)
from hullwork.manifest import MANIFEST_FILENAME

log = logging.getLogger(__name__)

API = "https://api.github.com"

#: Worth another go. **403 is in here on purpose and Forgejo's adapter does not do this**: GitHub
#: answers a rate limit with 403 plus a zero remaining-quota header, and classifying that as
#: permanent would report "your credentials are bad" and burn the item's one attempt on a wait.
#: The header is what tells the two apart, so the check is not on the status alone.
_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})

_FORBIDDEN = 403
_CONFLICT = 409
_UNPROCESSABLE = 422
_CLIENT_ERROR = 400

#: The blob mode for an ordinary file. GitHub's tree API wants it spelled out.
_FILE_MODE = "100644"


class _GitHubAPI:
    """One authenticated client. Shared shape with the Forgejo adapter, different vocabulary.

    `ingest_only` is item 061: the ingest role's promise not to write code is enforced here rather
    than by the two subclasses being separate, so it holds however the token happens to be scoped.
    """

    def __init__(
        self,
        token: str,
        timeout: float = 20.0,
        base_url: str = API,
        *,
        ingest_only: bool = False,
    ) -> None:
        self._ingest_only = ingest_only
        self._client = httpx2.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=timeout,
            follow_redirects=False,
        )

    def request(self, method: str, path: str, **kwargs: Any) -> Any:  # noqa: ANN401 - provider JSON
        if self._ingest_only:
            # Before the request is built, so a refusal means nothing was asked (item 061).
            refuse_unless_ingest_may_write(method, path)
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx2.TimeoutException as exc:
            raise RetryableForgeError(f"github timed out: {exc}") from exc
        except httpx2.HTTPError as exc:
            raise RetryableForgeError(f"github unreachable: {exc}") from exc

        if response.status_code == HTTP_NOT_FOUND:
            raise PermanentForgeError(f"{method} {path}: not found", HTTP_NOT_FOUND)
        if response.status_code in _RETRYABLE_STATUS or self._is_rate_limit(response):
            raise RetryableForgeError(
                f"{method} {path}: HTTP {response.status_code}", response.status_code
            )
        if response.status_code >= _CLIENT_ERROR:
            detail = _message(response)
            raise PermanentForgeError(
                f"{method} {path}: HTTP {response.status_code} {detail}", response.status_code
            )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise PermanentForgeError(f"{method} {path}: not JSON") from exc

    @staticmethod
    def _is_rate_limit(response: httpx2.Response) -> bool:
        """A 403 with the quota exhausted is a wait, not a refusal.

        This is the trap the Forgejo work predicted and this adapter has to handle: on GitHub a rate
        limit arrives as 403, which every sane classifier calls permanent — and DR-0003's
        accounting exists precisely so "the network was busy" cannot look like "the agent failed".
        """
        if response.status_code != _FORBIDDEN:
            return False
        return bool(response.headers.get("x-ratelimit-remaining") == "0")

    def close(self) -> None:
        self._client.close()


def _message(response: httpx2.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return ""
    return str(payload.get("message", "")) if isinstance(payload, dict) else ""


class GitHubForge:
    """The always-on half: read the manifest, file and label issues, read one back.

    Holds a token with `contents: read` + `issues: write` and provably not code write — verified by
    effect, not by reading the `permissions` block, which reports the *user's* role
    (`admin: true, push: true`) identically for both tokens and says nothing about the credential.
    """

    def head_commit(self, repo: str, branch: str) -> str:
        """The tip, or a clear refusal when the repository has never been committed to.

        A five-minute-old repository answers 409 `Git Repository is empty` here, which is not the
        same thing as a missing branch and needs saying so rather than surfacing as a raw conflict.
        """
        try:
            data = self._api.request("GET", f"/repos/{repo}/git/ref/heads/{branch}")
        except PermanentForgeError as exc:
            if exc.status == _CONFLICT:
                raise PermanentForgeError(
                    f"{repo}: the repository has no commits yet, so there is nothing to branch "
                    f"from",
                    _CONFLICT,
                ) from exc
            raise
        obj = data.get("object") if isinstance(data, dict) else None
        sha = obj.get("sha") if isinstance(obj, dict) else None
        if not sha:
            raise PermanentForgeError(f"{repo}: no sha for {branch}")
        return str(sha)

    def __init__(self, token: str, *, base_url: str = API) -> None:
        self._api = _GitHubAPI(token, base_url=base_url, ingest_only=True)

    def read_file(self, repo: str, path: str) -> str | None:
        """From the default branch only, and `None` when the file is not there. Item 107.

        The default branch is implicit here — GitHub's `contents` route uses it when no `ref` is
        given — which is `read_manifest`'s rule: never a ref a pull request could point at.
        """
        try:
            data = self._api.request("GET", f"/repos/{repo}/contents/{path}")
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return None
            raise
        content = data.get("content") if isinstance(data, dict) else None
        if not content:
            return None
        try:
            return base64.b64decode(content).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise PermanentForgeError(f"{repo}: {path} is not usable text") from exc

    def read_manifest(self, repo: str) -> str:
        """From the default branch only. Never a ref a pull request could point at."""
        data = self._api.request("GET", f"/repos/{repo}/contents/{MANIFEST_FILENAME}")
        content = data.get("content") if isinstance(data, dict) else None
        if not content:
            raise PermanentForgeError(f"{repo}: {MANIFEST_FILENAME} came back with no content")
        try:
            return base64.b64decode(content).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise PermanentForgeError(f"{repo}: {MANIFEST_FILENAME} is not usable text") from exc

    def ensure_labels(self, repo: str, names: dict[str, str]) -> dict[str, int]:
        """Create any missing labels and return name → id.

        GitHub attaches labels by **name** rather than by id, unlike Forgejo. The ids are returned
        anyway because the protocol is shared and core passes them around; this adapter simply does
        not need them, and inventing a different protocol for one provider would put the difference
        in core, which constitution §3 forbids.
        """
        existing: dict[str, int] = {}
        for label in self._api.request("GET", f"/repos/{repo}/labels", params={"per_page": 100}):
            if isinstance(label, dict) and label.get("name"):
                existing[str(label["name"])] = int(label.get("id", 0))
        for name, colour in names.items():
            if name in existing:
                continue
            created = self._api.request(
                "POST", f"/repos/{repo}/labels", json={"name": name, "color": colour.lstrip("#")}
            )
            existing[name] = int(created.get("id", 0)) if isinstance(created, dict) else 0
        return {name: existing.get(name, 0) for name in names}

    def create_issue(
        self, repo: str, title: str, body: str, label_ids: list[int] | None = None
    ) -> ForgeIssue:
        """Labels go on by name here; the ids core hands us are looked back up.

        Slightly awkward and deliberately contained: the alternative is a protocol that speaks both
        dialects, which pushes a provider's vocabulary up into core.
        """
        payload: dict[str, Any] = {"title": title, "body": body}
        if label_ids:
            payload["labels"] = self._names_for(repo, label_ids)
        return _issue(self._api.request("POST", f"/repos/{repo}/issues", json=payload))

    def get_issue(self, repo: str, number: int) -> ForgeIssue | None:
        try:
            return _issue(self._api.request("GET", f"/repos/{repo}/issues/{number}"))
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return None
            raise

    def merge_state(self, repo: str, number: int) -> MergeState:
        """Whether a pull request was merged, and what commit it produced. M9.

        Same field names as Forgejo — `merged`, `merge_commit_sha`, `merged_at` — which is one of
        the reasons the two adapters stay this close. A 404 answers `merged=False`, because a pull
        request somebody deleted is not merged and the watch has to survive a tidy-up.
        """
        try:
            data = self._api.request("GET", f"/repos/{repo}/pulls/{number}")
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return MergeState(merged=False)
            raise
        if not isinstance(data, dict):
            return MergeState(merged=False)
        # Same two fields as Forgejo, same meaning: `state` says open or closed, `merged` says which
        # kind of closed (item 138).
        closed = str(data.get("state", "")) == "closed"
        labels = labels_of(data)
        if not data.get("merged"):
            return MergeState(merged=False, state="closed" if closed else "open", labels=labels)
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

        **One request, unlike Forgejo's.** GitHub answers the whole tree up to its own documented
        ceiling and sets `truncated: true` when it hits it; there is no page parameter to follow. So
        the Forgejo adapter's loop would be wrong here, and this is the second place where the two
        APIs differ in a way a shared implementation would paper over — `release_contains` was the
        first, and papering over it there cost a whole milestone's central comparison.
        """
        repository = self._api.request("GET", f"/repos/{repo}")
        branch = repository.get("default_branch") if isinstance(repository, dict) else None
        if not isinstance(branch, str) or not branch:
            msg = f"{repo} reports no default branch, so there is no tree to read"
            raise PermanentForgeError(msg)
        ref = self.head_commit(repo, branch)
        data = self._api.request(
            "GET", f"/repos/{repo}/git/trees/{ref}", params={"recursive": "1"}
        )
        if not isinstance(data, dict):
            return Tree((), ref=ref)
        entries = data.get("tree")
        if not isinstance(entries, list):
            return Tree((), ref=ref)
        paths = tuple(
            entry["path"]
            for entry in entries
            if isinstance(entry, dict)
            and entry.get("type") == "blob"
            and isinstance(entry.get("path"), str)
        )
        return Tree(paths, truncated=data.get("truncated") is True, ref=ref)

    def release_contains(self, repo: str, release: str, commit: str) -> bool | None:
        """Whether `release` names code that includes `commit`. `None` when undecidable.

        **GitHub answers this directly and Forgejo does not**, which is the one place the two
        adapters genuinely differ here: `compare/base...head` returns a `status` of `behind`,
        `ahead`, `identical` or `diverged` — a word rather than a count of commits. Reading
        `total_commits` here would work by accident and break the day a release is a merge commit.

        A release that is not sha-shaped answers `None` before any request: comparing `0.4.2` to a
        commit is a 404 that reads like a missing repository.
        """
        if not SHA.fullmatch(release):
            return None
        try:
            data = self._api.request("GET", f"/repos/{repo}/compare/{commit}...{release}")
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return None
            raise
        if not isinstance(data, dict):
            return None
        status = data.get("status")
        if status in ("ahead", "identical"):
            return True
        if status in ("behind", "diverged"):
            return False
        return None

    def find_issue_by_marker(self, repo: str, fingerprint: str) -> ForgeIssue | None:
        """Search for the hidden marker.

        Two things, both measured against the real API on 2026-07-28.

        **The query must say `is:issue`.** Without it GitHub answers `422 Query must include
        'is:issue' or 'is:pull-request'` — it is not optional, and the first version of this method
        got exactly that. It also happens to solve the other problem at the source: GitHub's issue
        search otherwise returns pull requests, which the ingest credential cannot read.

        The client-side skip stays anyway. An adapter that chokes on a result it is not allowed to
        fetch stops filing anything at all, and one filter this cheap is not worth removing on the
        strength of a query string.
        """
        query = f'repo:{repo} is:issue in:body "{MARKER_PREFIX}{fingerprint}"'
        data = self._api.request(
            "GET", "/search/issues", params={"q": query, "per_page": 10}
        )
        for candidate in (data.get("items") or []) if isinstance(data, dict) else []:
            if not isinstance(candidate, dict) or candidate.get("pull_request"):
                continue
            if marker_for(fingerprint) in str(candidate.get("body") or ""):
                return _issue(candidate)
        return None

    def comment(self, repo: str, number: int, body: str) -> None:
        self._api.request("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body})

    def set_issue_state(self, repo: str, number: int, state: str) -> ForgeIssue:
        return _issue(
            self._api.request("PATCH", f"/repos/{repo}/issues/{number}", json={"state": state})
        )

    def _names_for(self, repo: str, label_ids: list[int]) -> list[str]:
        wanted = set(label_ids)
        return [
            str(label["name"])
            for label in self._api.request("GET", f"/repos/{repo}/labels", params={"per_page": 100})
            if isinstance(label, dict) and int(label.get("id", -1)) in wanted
        ]

    def can_write_code(self, repo: str) -> bool | None:
        """Whether this credential could push. **`None` here, and that is the honest answer.**

        GitHub's `permissions` block on a repository reports the *user's* role — `admin: true,
        push: true` for both of our tokens — and says nothing at all about what the token was
        granted. Measured. The only reliable check is to attempt a write, which is not something a
        credential audit gets to do to somebody's repository.

        So this reports "unknown" rather than guessing, and `unknown` is a value the audit already
        handles. A false "no" here would be worse than no answer: it would retire the one check
        item 031 exists to perform, while looking like it had passed.
        """
        return None

    def close(self) -> None:
        self._api.close()


class GitHubCodeForge:
    """The half that can change a repository. Separate credential, separate object.

    `contents: write` + `pull_requests: write`, repository-scoped. It cannot file an issue and does
    not need to: labelling a pull request works on `pull_requests` alone (verified), which was the
    one thing that might have forced issue write onto this token.
    """

    def __init__(self, token: str, *, base_url: str = API) -> None:
        self._api = _GitHubAPI(token, base_url=base_url)

    def default_branch(self, repo: str) -> str:
        data = self._api.request("GET", f"/repos/{repo}")
        branch = data.get("default_branch") if isinstance(data, dict) else None
        if not branch:
            raise PermanentForgeError(f"{repo}: no default branch reported")
        return str(branch)

    def head_commit(self, repo: str, branch: str) -> str:
        """The tip, or a clear refusal when the repository has never been committed to.

        A five-minute-old repository answers 409 `Git Repository is empty` here, which is not the
        same thing as a missing branch and needs saying so rather than surfacing as a raw conflict.
        """
        try:
            data = self._api.request("GET", f"/repos/{repo}/git/ref/heads/{branch}")
        except PermanentForgeError as exc:
            if exc.status == _CONFLICT:
                raise PermanentForgeError(
                    f"{repo}: the repository has no commits yet, so there is nothing to branch "
                    f"from",
                    _CONFLICT,
                ) from exc
            raise
        obj = data.get("object") if isinstance(data, dict) else None
        sha = obj.get("sha") if isinstance(obj, dict) else None
        if not sha:
            raise PermanentForgeError(f"{repo}: no sha for {branch}")
        return str(sha)

    def create_branch(self, repo: str, name: str, from_ref: str) -> None:
        """422 `Reference already exists` here, where Forgejo answers 409 for the same thing."""
        try:
            self._api.request(
                "POST",
                f"/repos/{repo}/git/refs",
                json={"ref": f"refs/heads/{name}", "sha": from_ref},
            )
        except PermanentForgeError as exc:
            if exc.status == _UNPROCESSABLE and "already exists" in str(exc):
                raise BranchExistsError(f"{repo}: branch {name} already exists") from exc
            raise

    def file_sha(self, repo: str, path: str, ref: str) -> str | None:
        try:
            data = self._api.request(
                "GET", f"/repos/{repo}/contents/{path}", params={"ref": ref}
            )
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
        """One commit for the whole change set, in four calls instead of one.

        There is no batch contents endpoint, so atomicity is ours: blobs, then a tree, then a
        commit, then the ref. Nothing is visible until the last step, which is what makes a partial
        failure leave no branch and no commit — the property item 035 has to demonstrate rather
        than assume.

        `FileChange.sha` is unused here. GitHub's tree API takes the new content and the base tree
        and works the rest out, and the field exists for Forgejo, which refuses an update without
        the pre-image. Ignoring it silently would be worse than saying so.
        """
        if not changes:
            raise PermanentForgeError(f"{repo}: refusing to commit an empty change set")

        parent = self.head_commit(repo, branch)
        base = self._api.request("GET", f"/repos/{repo}/git/commits/{parent}")
        base_tree = (base.get("tree") or {}).get("sha") if isinstance(base, dict) else None

        entries: list[dict[str, Any]] = []
        for change in changes:
            if change.operation == "delete":
                # A null sha is how the tree API expresses a deletion.
                entries.append(
                    {"path": change.path, "mode": _FILE_MODE, "type": "blob", "sha": None}
                )
                continue
            blob = self._api.request(
                "POST",
                f"/repos/{repo}/git/blobs",
                json={
                    "content": base64.b64encode(change.content or b"").decode(),
                    "encoding": "base64",
                },
            )
            entries.append(
                {
                    "path": change.path,
                    "mode": _FILE_MODE,
                    "type": "blob",
                    "sha": str(blob.get("sha")) if isinstance(blob, dict) else None,
                }
            )

        tree = self._api.request(
            "POST", f"/repos/{repo}/git/trees", json={"base_tree": base_tree, "tree": entries}
        )
        identity = {"name": author, "email": email}
        commit = self._api.request(
            "POST",
            f"/repos/{repo}/git/commits",
            json={
                "message": message,
                "tree": tree.get("sha") if isinstance(tree, dict) else None,
                "parents": [parent],
                "author": identity,
                "committer": identity,
            },
        )
        sha = commit.get("sha") if isinstance(commit, dict) else None
        if not sha:
            raise PermanentForgeError(f"{repo}: no sha for the new commit")
        # Only now does anything become visible. `force` stays false: a branch that moved under us
        # means the gates were run against a tree that is no longer there.
        self._api.request(
            "PATCH",
            f"/repos/{repo}/git/refs/heads/{branch}",
            json={"sha": str(sha), "force": False},
        )
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
        """A real draft field, and the forge refuses to merge one.

        Better than Forgejo's mutable `WIP:` title, and the difference is recorded rather than
        hidden: on one provider "draft" is a server refusal, on the other a convention.

        Labels need a second call — `POST /pulls` rejects them — and that call works on
        `pull_requests: write` alone, which is the finding that kept issue write off this token.
        """
        data = self._api.request(
            "POST",
            f"/repos/{repo}/pulls",
            json={"head": head, "base": base, "title": title, "body": body, "draft": True},
        )
        pull = _pull(data)
        if not pull.draft:
            raise PermanentForgeError(
                f"{repo}: asked for a draft pull request and got one that is not a draft; refusing "
                f"to leave a merge-ready pull request behind"
            )
        if label_ids:
            names = self._names_for(repo, label_ids)
            self._api.request(
                "POST", f"/repos/{repo}/issues/{pull.number}/labels", json={"labels": names}
            )
        return pull

    def _names_for(self, repo: str, label_ids: list[int]) -> list[str]:
        wanted = set(label_ids)
        return [
            str(label["name"])
            for label in self._api.request("GET", f"/repos/{repo}/labels", params={"per_page": 100})
            if isinstance(label, dict) and int(label.get("id", -1)) in wanted
        ]

    def close(self) -> None:
        self._api.close()


def _issue(data: Any) -> ForgeIssue:  # noqa: ANN401 - provider JSON
    if not isinstance(data, dict):
        raise PermanentForgeError("github sent something that is not an issue")
    return ForgeIssue(
        number=int(data.get("number", 0)),
        title=str(data.get("title", "")),
        state=str(data.get("state", "")),
        html_url=str(data.get("html_url", "")),
        body=str(data.get("body") or ""),
    )


def _pull(data: Any) -> ForgePullRequest:  # noqa: ANN401 - provider JSON
    if not isinstance(data, dict):
        raise PermanentForgeError("github sent something that is not a pull request")
    return ForgePullRequest(
        number=int(data.get("number", 0)),
        title=str(data.get("title", "")),
        html_url=str(data.get("html_url", "")),
        draft=bool(data.get("draft", False)),
    )
