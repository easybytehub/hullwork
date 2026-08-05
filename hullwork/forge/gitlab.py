"""GitLab, both halves. Item 132.

The third adapter, and it is not the second one with different nouns. Where it differs from Forgejo
and GitHub it differs in ways a shared implementation would paper over, so each one is named here:

* **A project is one segment, not two.** `/projects/{id}` takes a numeric id or the project path
  with its separators percent-encoded, which is what lets a project inside subgroups exist at all —
  and what keeps item 061's guard sound, since `%2F` is not `/`.
* **The number a person sees is `iid`.** There is also a global `id`, and reading it would produce
  plausible numbers pointing at other projects' issues.
* **A multi-file commit is one request**, like Forgejo and unlike GitHub: the Commits API takes a
  list of actions and applies them as one commit, so atomicity is the server's problem again.
* **An issue's state changes by verb.** `state_event: close`, not `state: closed`. Sending the
  protocol's word verbatim is accepted with a 200 and changes nothing.
* **A merge can arrive as a squash.** `merge_commit_sha` is null on a squashed merge request and
  `squash_commit_sha` holds the commit — so a watch reading only the first would report a merged fix
  as having no commit, and M9 cannot decide a recurrence without one.
* **Drafts are the other two mixed.** Set the Forgejo way (a title prefix) and checked the GitHub
  way (a real read-only boolean, and the forge refuses the merge). Nothing can be passed at
  creation, so the `draft is True` assertion on the response is not prudence here — it is the only
  check there is.

**What is measured and what is not.** Every line above comes from GitLab's own documentation, read
on 2026-08-03, and the status codes below are predictions until item 132's gate runs against a real
project. That is the opposite of how the other two adapters were built — both were measured against
a live instance first — and it is stated rather than implied, because the one thing this repository
does not do is let a documented shape pass for an observed one. The mapping `_may_write_code` relies
on, and the marker search, are what the gate is for.
"""

import base64
import binascii
import logging
from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

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

#: Worth another go. **No 403 in here, unlike the GitHub adapter**: GitLab answers a rate limit with
#: 429 and a `Retry-After`, so a 403 here means what it says, and calling it retryable would spend
#: an item's one attempt (DR-0003) waiting for a refusal to change its mind.
_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})

_BAD_REQUEST = 400
_CONFLICT = 409
_CLIENT_ERROR = 400

#: The access level a role needs to push. GitLab's numbers: 10 Guest, 20 Reporter, 30 Developer,
#: 40 Maintainer, 50 Owner. Named rather than inlined because the credential split for this forge
#: rests entirely on the difference between 20 and 30.
_DEVELOPER = 30

#: How a draft is declared. Three prefixes are accepted (`Draft:`, `[Draft]`, `(Draft)`); this one
#: is sent, and what comes back is checked against the `draft` field rather than against the title.
_DRAFT_PREFIX = "Draft: "

#: Entries per page for the tree route, and how many pages to follow. GitLab paginates this one like
#: Forgejo does, but reports the next page in a header rather than in the body.
_TREE_PER_PAGE = 100
_TREE_PAGES = 10


def _project(repo: str) -> str:
    """A repository name as GitLab addresses it: one path segment, separators encoded.

    `safe=""` is the whole point — `quote` leaves `/` alone by default, which would send
    `/projects/group/project/issues`, a path that matches nothing in item 061's allowlist and is
    refused before it is built. Safe direction, and a test holds it there.
    """
    return quote(repo, safe="")


class _GitLabAPI:
    """One authenticated client. Same shape as the other two adapters, GitLab's vocabulary.

    `ingest_only` is item 061 again, enforced here rather than by the two classes being separate, so
    that it holds however the token happens to be scoped.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = 20.0,
        *,
        ingest_only: bool = False,
    ) -> None:
        self._ingest_only = ingest_only
        self._client = httpx2.Client(
            base_url=base_url.rstrip("/") + "/api/v4",
            # A project access token authenticates as a bearer token. `PRIVATE-TOKEN` is
            # GitLab's older spelling; one header is enough and this is the documented one.
            headers={"Authorization": f"Bearer {token}"},
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
            raise RetryableForgeError(f"gitlab timed out: {exc}") from exc
        except httpx2.HTTPError as exc:
            raise RetryableForgeError(f"gitlab unreachable: {exc}") from exc

        if response.status_code == HTTP_NOT_FOUND:
            raise PermanentForgeError(f"{method} {path}: not found", HTTP_NOT_FOUND)
        if response.status_code in _RETRYABLE_STATUS:
            raise RetryableForgeError(
                f"{method} {path}: HTTP {response.status_code}", response.status_code
            )
        if response.status_code >= _CLIENT_ERROR:
            raise PermanentForgeError(
                f"{method} {path}: HTTP {response.status_code} {_message(response)}",
                response.status_code,
            )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise PermanentForgeError(f"{method} {path}: not JSON") from exc

    def paged(self, path: str, **kwargs: Any) -> Any:  # noqa: ANN401 - provider JSON
        """One page, and the number of the next one, which GitLab puts in a header.

        Returned as a pair rather than looped here because only `tree` paginates, and it has to stop
        at a bound and say that it did — a helper that hid the cursor would hide the truncation too.
        """
        if self._ingest_only:
            refuse_unless_ingest_may_write("GET", path)
        try:
            response = self._client.request("GET", path, **kwargs)
        except httpx2.TimeoutException as exc:
            raise RetryableForgeError(f"gitlab timed out: {exc}") from exc
        except httpx2.HTTPError as exc:
            raise RetryableForgeError(f"gitlab unreachable: {exc}") from exc
        if response.status_code >= _CLIENT_ERROR:
            raise PermanentForgeError(
                f"GET {path}: HTTP {response.status_code} {_message(response)}",
                response.status_code,
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise PermanentForgeError(f"GET {path}: not JSON") from exc
        return payload, response.headers.get("x-next-page") or ""

    def close(self) -> None:
        self._client.close()


def _message(response: httpx2.Response) -> str:
    """GitLab's error text, which arrives under two different keys.

    `message` for most routes, `error` for the ones that validate parameters. Read both and
    stringify: this ends up in an operator's terminal, and "HTTP 400" alone sends them to a search
    engine.
    """
    try:
        payload = response.json()
    except ValueError:
        return ""
    if not isinstance(payload, dict):
        return ""
    for key in ("message", "error"):
        if key in payload:
            return str(payload[key])
    return ""


class GitLabForge:
    """The always-on half: read the manifest, file and label issues, read one back.

    A Reporter with the `api` scope, if the documentation holds: `api` grants the API and **not**
    git push, and a Reporter cannot write code through either. Which would make this the first forge
    where DR-0009's split is expressible by role — Forgejo's finest grain is `write:repository` and
    carries deploy keys with it. Item 132's gate turns that sentence into a measurement.
    """

    def __init__(self, base_url: str, token: str) -> None:
        self._api = _GitLabAPI(base_url, token, ingest_only=True)

    def _default_branch(self, repo: str) -> str:
        """The branch every read below is pinned to.

        **A private helper rather than a protocol method, and one extra request per read.** GitLab's
        file route requires an explicit `ref` — there is no "whatever the default is" — so the
        choice is between asking for the default branch and letting a caller supply a ref. `Forge`
        forbids the second in writing: a ref a pull request could point at is how somebody with
        permission to open one rewrites what this instance believes about their project.
        """
        data = self._api.request("GET", f"/projects/{_project(repo)}")
        branch = data.get("default_branch") if isinstance(data, dict) else None
        if not isinstance(branch, str) or not branch:
            raise PermanentForgeError(f"{repo}: no default branch reported")
        return branch

    def _file(self, repo: str, path: str) -> dict[str, Any] | None:
        try:
            data = self._api.request(
                "GET",
                f"/projects/{_project(repo)}/repository/files/{quote(path, safe='')}",
                params={"ref": self._default_branch(repo)},
            )
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return None
            raise
        return data if isinstance(data, dict) else None

    @staticmethod
    def _text(repo: str, path: str, data: dict[str, Any]) -> str:
        content = data.get("content")
        if not content:
            raise PermanentForgeError(f"{repo}: {path} came back with no content")
        try:
            return base64.b64decode(str(content)).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise PermanentForgeError(f"{repo}: {path} is not usable text") from exc

    def read_manifest(self, repo: str) -> str:
        data = self._file(repo, MANIFEST_FILENAME)
        if data is None:
            raise PermanentForgeError(
                f"{repo}: {MANIFEST_FILENAME} is not on the default branch", HTTP_NOT_FOUND
            )
        return self._text(repo, MANIFEST_FILENAME, data)

    def read_file(self, repo: str, path: str) -> str | None:
        data = self._file(repo, path)
        return None if data is None else self._text(repo, path, data)

    def ensure_labels(self, repo: str, names: dict[str, str]) -> dict[str, int]:
        """Create any missing labels and return name → id.

        **The colour keeps its `#`,** where GitHub's route rejects it and Forgejo's ignores it. One
        character, and it is the difference between a label and a 400.
        """
        existing: dict[str, int] = {}
        for label in self._api.request(
            "GET", f"/projects/{_project(repo)}/labels", params={"per_page": 100}
        ):
            if isinstance(label, dict) and label.get("name"):
                existing[str(label["name"])] = int(label.get("id", 0))
        for name, colour in names.items():
            if name in existing:
                continue
            value = colour if colour.startswith("#") else f"#{colour}"
            created = self._api.request(
                "POST", f"/projects/{_project(repo)}/labels", json={"name": name, "color": value}
            )
            existing[name] = int(created.get("id", 0)) if isinstance(created, dict) else 0
        return {name: existing.get(name, 0) for name in names}

    def create_issue(
        self, repo: str, title: str, body: str, label_ids: list[int] | None = None
    ) -> ForgeIssue:
        """The body is a `description` here, and labels go on by name in one comma-separated string.

        Same awkwardness as the GitHub adapter, contained the same way: core passes ids because
        Forgejo needs ids, and translating here keeps one provider's vocabulary out of core
        (constitution §3).
        """
        payload: dict[str, Any] = {"title": title, "description": body}
        if label_ids:
            payload["labels"] = ",".join(self._names_for(repo, label_ids))
        return _issue(self._api.request("POST", f"/projects/{_project(repo)}/issues", json=payload))

    def get_issue(self, repo: str, number: int) -> ForgeIssue | None:
        try:
            return _issue(self._api.request("GET", f"/projects/{_project(repo)}/issues/{number}"))
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return None
            raise

    def find_issue_by_marker(self, repo: str, fingerprint: str) -> ForgeIssue | None:
        """Search the descriptions for the hidden marker.

        `in=description` narrows GitLab's default of title-and-description. The client-side check
        stays regardless, for the reason the GitHub adapter gives: a loose match would otherwise
        adopt somebody else's issue as this fingerprint's, permanently.

        **This is the method item 132's gate has to prove.** Deduplication is what stops Hullwork
        refiling the same issue on every sweep, and it rests entirely on basic search reaching the
        description on the instance under test.
        """
        data = self._api.request(
            "GET",
            f"/projects/{_project(repo)}/issues",
            params={
                "search": f"{MARKER_PREFIX}{fingerprint}",
                "in": "description",
                "per_page": 10,
            },
        )
        for candidate in data if isinstance(data, list) else []:
            if not isinstance(candidate, dict):
                continue
            if marker_for(fingerprint) in str(candidate.get("description") or ""):
                return _issue(candidate)
        return None

    def merge_state(self, repo: str, number: int) -> MergeState:
        """Whether a merge request was merged, and what commit it produced. M9.

        **`state` is a word here, not a boolean**, and the commit can be either of two fields: a
        squashed merge leaves `merge_commit_sha` null and puts the commit in `squash_commit_sha`.
        Reading only the first would hand M9 a merged fix with no commit, and without a commit a
        recurrence cannot be told from an error arriving out of a release that predates the fix —
        the confusion item 039 fixed from the other direction.
        """
        try:
            data = self._api.request("GET", f"/projects/{_project(repo)}/merge_requests/{number}")
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return MergeState(merged=False)
            raise
        if not isinstance(data, dict):
            return MergeState(merged=False)
        labels = labels_of(data)
        if data.get("state") != "merged":
            # **One word where the others have two** (item 138): GitLab's `state` is `opened`,
            # `closed`, `merged` or `locked`, so the decision is read from it directly. `locked` is
            # neither, and is reported as unknown rather than guessed.
            named = str(data.get("state", ""))
            decided: str = {"opened": "open", "closed": "closed"}.get(named, "unknown")
            return MergeState(merged=False, state=decided, labels=labels)  # type: ignore[arg-type]
        commit = data.get("merge_commit_sha") or data.get("squash_commit_sha")
        raw = data.get("merged_at")
        return MergeState(
            merged=True,
            commit=str(commit) if commit else None,
            merged_at=parsed_time(raw) if isinstance(raw, str) else None,
            state="merged",
            labels=labels,
        )

    def tree(self, repo: str) -> Tree:
        """Every file path at the head of the default branch. M8, item 104.

        Paginated like Forgejo's and bounded the same way, but the cursor is a **header**
        (`x-next-page`) rather than a `truncated` flag in the body — so running out of pages and
        reaching the end are told apart by whether that header is still set when the bound is hit.
        """
        branch = self._default_branch(repo)
        ref = self.head_commit(repo, branch)
        paths: list[str] = []
        page = "1"
        truncated = False
        for _ in range(_TREE_PAGES):
            payload, nxt = self._api.paged(
                f"/projects/{_project(repo)}/repository/tree",
                params={
                    "recursive": "true",
                    "ref": ref,
                    "per_page": _TREE_PER_PAGE,
                    "page": page,
                },
            )
            for entry in payload if isinstance(payload, list) else []:
                if (
                    isinstance(entry, dict)
                    and entry.get("type") == "blob"
                    and isinstance(entry.get("path"), str)
                ):
                    paths.append(entry["path"])
            if not nxt:
                break
            page = nxt
        else:
            truncated = True
        return Tree(tuple(paths), truncated=truncated, ref=ref)

    def release_contains(self, repo: str, release: str, commit: str) -> bool | None:
        """Whether `release` names code that includes `commit`. `None` when undecidable. M9.

        GitLab answers ancestry through `merge_base`: the common ancestor of two refs **is** the
        older commit exactly when the older one is contained in the newer. So this compares an id
        rather than reading a word (GitHub) or counting commits (which is what made Forgejo's
        version wrong before it was rewritten).

        A release that is not sha-shaped answers `None` before any request, as on both other forges:
        comparing `0.4.2` to a commit is a 404 that reads like a missing project.
        """
        if not SHA.fullmatch(release):
            return None
        try:
            data = self._api.request(
                "GET",
                f"/projects/{_project(repo)}/repository/merge_base",
                params={"refs[]": [commit, release]},
            )
        except PermanentForgeError as exc:
            if exc.status in (HTTP_NOT_FOUND, _BAD_REQUEST):
                # A ref this project does not have, or two refs with no common ancestor. Neither is
                # an answer about whether the fix shipped.
                return None
            raise
        base = data.get("id") if isinstance(data, dict) else None
        if not isinstance(base, str) or not base:
            return None
        # `commit` is an ancestor of `release` exactly when it is the merge base. Compared on the
        # shorter of the two, because a caller may hold an abbreviated sha and GitLab answers full.
        shorter = min(len(base), len(commit))
        return base[:shorter] == commit[:shorter]

    def head_commit(self, repo: str, branch: str) -> str:
        data = self._api.request(
            "GET", f"/projects/{_project(repo)}/repository/branches/{quote(branch, safe='')}"
        )
        commit = data.get("commit") if isinstance(data, dict) else None
        sha = commit.get("id") if isinstance(commit, dict) else None
        if not sha:
            raise PermanentForgeError(f"{repo}: no sha for {branch}")
        return str(sha)

    def comment(self, repo: str, number: int, body: str) -> None:
        self._api.request(
            "POST", f"/projects/{_project(repo)}/issues/{number}/notes", json={"body": body}
        )

    def set_issue_state(self, repo: str, number: int, state: str) -> ForgeIssue:
        """**A verb, not a state.** `state_event: close`. `state: closed` is accepted and ignored.

        That is the failure mode worth naming: GitLab answers 200 with the issue unchanged, so an
        adapter passing the protocol's word through would report every close as a success and leave
        every issue open. Anything unrecognised is refused here rather than sent.
        """
        events = {"closed": "close", "close": "close", "open": "reopen", "opened": "reopen"}
        event = events.get(state.strip().lower())
        if event is None:
            raise PermanentForgeError(
                f"{repo}: '{state}' is not an issue state this forge can be asked for "
                f"(expected one of: {', '.join(sorted(set(events)))})"
            )
        return _issue(
            self._api.request(
                "PUT", f"/projects/{_project(repo)}/issues/{number}", json={"state_event": event}
            )
        )

    def can_write_code(self, repo: str) -> bool | None:
        """What this credential may do to code, as far as the project route can say.

        **Better than GitHub's `None` and still not the whole answer.** A project access token
        authenticates as its own bot user, so the access level on the project *is* the token's role
        rather than some human's — which is why a level below Developer can be read as `False` here,
        while GitHub's `permissions` block, describing a person, cannot be read at all.

        A level at or above Developer stays `None`, because the scope is a second layer underneath
        the role and no endpoint declares it: `read_api` on a Developer cannot write anything, and
        this route cannot see the difference. `None` is the honest answer, and the probe in
        `credentials` is what resolves it.
        """
        try:
            data = self._api.request("GET", f"/projects/{_project(repo)}")
        except PermanentForgeError:
            return None
        permissions = data.get("permissions") if isinstance(data, dict) else None
        if not isinstance(permissions, dict):
            return None
        levels: list[int] = []
        for key in ("project_access", "group_access"):
            access = permissions.get(key)
            if isinstance(access, dict) and isinstance(access.get("access_level"), int):
                levels.append(int(access["access_level"]))
        if not levels:
            return None
        return None if max(levels) >= _DEVELOPER else False

    def _names_for(self, repo: str, label_ids: list[int]) -> list[str]:
        wanted = set(label_ids)
        return [
            str(label["name"])
            for label in self._api.request(
                "GET", f"/projects/{_project(repo)}/labels", params={"per_page": 100}
            )
            if isinstance(label, dict) and int(label.get("id", -1)) in wanted
        ]

    def close(self) -> None:
        self._api.close()


class GitLabCodeForge:
    """The half that can change a repository. Separate credential, separate object.

    A Developer with `api` + `read_repository`: the API writes the commits and git-over-HTTP only
    ever clones, so `write_repository` — which does not authenticate the API at all — is neither
    needed nor asked for.
    """

    def __init__(self, base_url: str, token: str) -> None:
        self._api = _GitLabAPI(base_url, token)

    def default_branch(self, repo: str) -> str:
        data = self._api.request("GET", f"/projects/{_project(repo)}")
        branch = data.get("default_branch") if isinstance(data, dict) else None
        if not branch:
            raise PermanentForgeError(f"{repo}: no default branch reported")
        return str(branch)

    def head_commit(self, repo: str, branch: str) -> str:
        data = self._api.request(
            "GET", f"/projects/{_project(repo)}/repository/branches/{quote(branch, safe='')}"
        )
        commit = data.get("commit") if isinstance(data, dict) else None
        sha = commit.get("id") if isinstance(commit, dict) else None
        if not sha:
            raise PermanentForgeError(f"{repo}: no sha for {branch}")
        return str(sha)

    def create_branch(self, repo: str, name: str, from_ref: str) -> None:
        """`400 Branch already exists`, where GitHub answers 422 and Forgejo 409.

        Three forges, three status codes for one condition, which is the argument for
        `BranchExistsError` being a type rather than each caller reading numbers.
        """
        try:
            self._api.request(
                "POST",
                f"/projects/{_project(repo)}/repository/branches",
                params={"branch": name, "ref": from_ref},
            )
        except PermanentForgeError as exc:
            if exc.status in (_BAD_REQUEST, _CONFLICT) and "already exists" in str(exc):
                raise BranchExistsError(f"{repo}: branch {name} already exists") from exc
            raise

    def file_sha(self, repo: str, path: str, ref: str) -> str | None:
        """The blob id, which this forge does not need and the protocol does.

        Returned honestly rather than as `None`: `commit_files` below ignores it, because GitLab's
        Commits API takes the new content and works the rest out. Saying so beats a silent `None`
        that a future reader would take for "this file does not exist".
        """
        try:
            data = self._api.request(
                "GET",
                f"/projects/{_project(repo)}/repository/files/{quote(path, safe='')}",
                params={"ref": ref},
            )
        except PermanentForgeError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return None
            raise
        blob = data.get("blob_id") if isinstance(data, dict) else None
        return str(blob) if blob else None

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
        """One commit, one request — the server's atomicity rather than ours.

        Like Forgejo and unlike GitHub, where the same commit is four calls and a partial failure
        has to be made invisible by hand. Content goes base64 so a patch with any byte in it
        survives the trip, and `FileChange.sha` is deliberately unused (see `file_sha`).

        Refuses an empty change set, as both other adapters do: the forge would accept it, move the
        branch head with an empty commit, and turn "the agent changed nothing" into a pull request
        with no diff.
        """
        if not changes:
            raise PermanentForgeError(f"{repo}: refusing to commit an empty change set")
        actions: list[dict[str, Any]] = []
        for change in changes:
            action: dict[str, Any] = {"action": change.operation, "file_path": change.path}
            if change.operation != "delete":
                action["content"] = base64.b64encode(change.content or b"").decode()
                action["encoding"] = "base64"
            actions.append(action)
        data = self._api.request(
            "POST",
            f"/projects/{_project(repo)}/repository/commits",
            json={
                "branch": branch,
                "commit_message": message,
                "actions": actions,
                "author_name": author,
                "author_email": email,
            },
        )
        sha = data.get("id") if isinstance(data, dict) else None
        if not sha:
            raise PermanentForgeError(f"{repo}: no sha for the new commit")
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
        """A title prefix on the way out, a boolean on the way back.

        There is no `draft` parameter at creation, so the prefix is the only way to ask — and the
        response's read-only `draft` field is the only way to know. Which makes the assertion below
        load-bearing rather than defensive: without it, an instance whose prefixes were configured
        away would publish merge-ready work and call it a draft, and the human-merge gate
        (constitution §1) would be a title convention.

        Labels go in at creation, as on Forgejo, and by name because that is what this API takes.
        """
        payload: dict[str, Any] = {
            "source_branch": head,
            "target_branch": base,
            "title": title if title.startswith(_DRAFT_PREFIX) else _DRAFT_PREFIX + title,
            "description": body,
        }
        if label_ids:
            payload["labels"] = ",".join(self._names_for(repo, label_ids))
        pull = _pull(
            self._api.request("POST", f"/projects/{_project(repo)}/merge_requests", json=payload)
        )
        if not pull.draft:
            raise PermanentForgeError(
                f"{repo}: asked for a draft merge request and got one that is not a draft; "
                f"refusing to leave merge-ready work behind"
            )
        return pull

    def _names_for(self, repo: str, label_ids: list[int]) -> list[str]:
        wanted = set(label_ids)
        return [
            str(label["name"])
            for label in self._api.request(
                "GET", f"/projects/{_project(repo)}/labels", params={"per_page": 100}
            )
            if isinstance(label, dict) and int(label.get("id", -1)) in wanted
        ]

    def close(self) -> None:
        self._api.close()


def _issue(data: Any) -> ForgeIssue:  # noqa: ANN401 - provider JSON
    """**`iid`, never `id`.** The global id is also in this payload and is also an integer, so the
    wrong one produces working-looking references to other projects' issues."""
    if not isinstance(data, dict):
        raise PermanentForgeError("gitlab sent something that is not an issue")
    return ForgeIssue(
        number=int(data.get("iid", 0)),
        title=str(data.get("title", "")),
        state=str(data.get("state", "")),
        html_url=str(data.get("web_url", "")),
        body=str(data.get("description") or ""),
    )


def _pull(data: Any) -> ForgePullRequest:  # noqa: ANN401 - provider JSON
    """`draft` is authoritative; `work_in_progress` is its deprecated twin and is read only as a
    fallback, so an older self-hosted GitLab does not report every draft as ready."""
    if not isinstance(data, dict):
        raise PermanentForgeError("gitlab sent something that is not a merge request")
    draft = data.get("draft")
    if draft is None:
        draft = data.get("work_in_progress")
    return ForgePullRequest(
        number=int(data.get("iid", 0)),
        title=str(data.get("title", "")),
        html_url=str(data.get("web_url", "")),
        draft=bool(draft),
    )
