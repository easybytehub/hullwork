"""GitLab: the adapter, and the four mechanisms a third forge breaks. Item 132.

**Read this before trusting a payload below.** Every shape here comes from GitLab's published API
documentation, read on 2026-08-03, and *not* from a live instance — the opposite of how
`test_forge_forgejo.py` and the GitHub adapter were built, and both of those headers say so for the
same reason. Item 132's gate is what turns these into recorded shapes; until it runs, a green suite
here means "consistent with the documentation", not "observed".

What holds independently of any of that, and would survive the payloads being wrong: the guard in
`hullwork.forge` covering GitLab's route shape and nothing else, `iid` never being `id`, the
per-provider repository rule, and which forge an instance decides it serves.
"""

import base64
import json
from collections.abc import Callable

import httpx2
import pytest
from pydantic import SecretStr

from hullwork import credentials
from hullwork.config import Settings
from hullwork.forge import (
    CredentialMisuseError,
    FileChange,
    PermanentForgeError,
    declaration_disagrees,
    kind_of,
    marker_for,
    refuse_unless_ingest_may_write,
)
from hullwork.forge.factory import configured_kind, make_code_forge, make_forge, serves
from hullwork.forge.gitlab import GitLabCodeForge, GitLabForge
from hullwork.manifest import ManifestError, parse_manifest

BASE = "https://gitlab.example"
REPO = "flagship/hullwork-sandbox"
NESTED = "flagship/labs/hullwork-sandbox"
ENCODED = "flagship%2Fhullwork-sandbox"
TOKEN = "glpat-not-a-real-token"  # noqa: S105 - fixture
FINGERPRINT = "8e2f1c0a55b4d9e3f7a61b8c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60"

Handler = Callable[[httpx2.Request], httpx2.Response]


def _client(handler: Handler) -> httpx2.Client:
    """A real client on a mock transport, **carrying the adapter's own base URL**.

    Without it every path below is relative to nothing and httpx2 rejects it — worth a line, because
    the paths are what these tests assert, so the prefix has to be the real one.
    """
    return httpx2.Client(base_url=BASE + "/api/v4", transport=httpx2.MockTransport(handler))


def _wire(request: httpx2.Request) -> str:
    """The path **as it goes on the wire**, which is the only one that means anything here.

    Measured while writing these tests, and it is why this helper exists: `httpx2.URL.path` returns
    the *decoded* path, so a project addressed as `flagship%2Fproject` reads back as
    `flagship/project` — three segments where one was sent. The encoded form is in `raw_path` and is
    what GitLab receives, so asserting on `.path` would fail a correct adapter and, worse, teach the
    next reader that the single-segment property is not real. It is: on the wire.
    """
    return request.url.raw_path.decode().split("?", 1)[0]


def _forge(handler: Handler) -> GitLabForge:
    forge = GitLabForge(BASE, TOKEN)
    forge._api._client = _client(handler)
    return forge


def _code(handler: Handler) -> GitLabCodeForge:
    forge = GitLabCodeForge(BASE, TOKEN)
    forge._api._client = _client(handler)
    return forge


def _issue_payload(iid: int = 7, description: str = "") -> dict[str, object]:
    """**`id` and `iid` deliberately far apart.** In a real project they always are, and a test
    where they coincide cannot fail when the wrong one is read."""
    return {
        "id": 91827,
        "iid": iid,
        "project_id": 4321,
        "title": "KeyError in payment reconciliation",
        "description": description,
        "state": "opened",
        "web_url": f"{BASE}/{REPO}/-/issues/{iid}",
    }


# --- the guard, which is where DR-0009 physically lives -------------------------------------------


def test_the_ingest_guard_covers_gitlabs_shape_and_nothing_more() -> None:
    """Item 061's allowlist, extended to a route shape it had never seen.

    Before this, `/projects/{id}/issues` matched nothing and a GitLab ingest client could not file
    one issue — the correct direction to fail, and why this had to be deliberate rather than
    discovered in production.
    """
    refuse_unless_ingest_may_write("POST", f"/projects/{ENCODED}/issues")
    refuse_unless_ingest_may_write("POST", f"/projects/{ENCODED}/issues/7/notes")
    refuse_unless_ingest_may_write("PUT", f"/projects/{ENCODED}/issues/7")
    refuse_unless_ingest_may_write("POST", f"/projects/{ENCODED}/labels")
    refuse_unless_ingest_may_write("POST", "/projects/4321/issues")  # numeric ids too

    for path in (
        f"/projects/{ENCODED}/repository/branches",
        f"/projects/{ENCODED}/repository/commits",
        f"/projects/{ENCODED}/merge_requests",
        f"/projects/{ENCODED}/repository/files/hullwork.yml",
    ):
        with pytest.raises(CredentialMisuseError):
            refuse_unless_ingest_may_write("POST", path)


def test_an_unencoded_project_path_is_refused_rather_than_sent() -> None:
    """The property that makes one `[^/]+` safe for a nested project.

    A project path with its slashes intact is not a GitLab route — and rather than reaching some
    other endpoint, it matches nothing in the allowlist and is refused. An adapter that forgets to
    encode therefore fails on us, loudly, at the first write.
    """
    with pytest.raises(CredentialMisuseError):
        refuse_unless_ingest_may_write("POST", f"/projects/{NESTED}/issues")


def test_the_ingest_client_cannot_reach_code_even_with_a_pushing_token() -> None:
    """The guard is on the client, not on the class, so the token's scope is irrelevant to it."""
    forge = _forge(lambda request: httpx2.Response(200, json={}))

    with pytest.raises(CredentialMisuseError):
        forge._api.request("POST", f"/projects/{ENCODED}/repository/branches")


# --- iid, which is the number, and id, which is not -----------------------------------------------


def test_the_number_is_the_iid_not_the_global_id() -> None:
    """Read `id` and every reference points at another project's issue, plausibly."""
    forge = _forge(lambda request: httpx2.Response(200, json=_issue_payload(iid=7)))

    issue = forge.get_issue(REPO, 7)

    assert issue is not None
    assert issue.number == 7, "the iid is what a person sees and what a URL carries"
    assert issue.ref == "#7"
    assert "91827" not in issue.html_url


def test_the_marker_search_asks_the_descriptions_and_checks_the_answer() -> None:
    """`in=description` narrows GitLab's default, and the client-side check stays anyway.

    Deduplication rests entirely on this: without it Hullwork refiles the same issue every sweep.
    """
    asked: list[tuple[str, str]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        asked.append((_wire(request), request.url.params.get("in", "")))
        return httpx2.Response(
            200, json=[_issue_payload(iid=7, description=f"body\n{marker_for(FINGERPRINT)}\n")]
        )

    found = _forge(handler).find_issue_by_marker(REPO, FINGERPRINT)

    assert found is not None and found.number == 7
    assert asked == [(f"/api/v4/projects/{ENCODED}/issues", "description")]


def test_a_search_hit_without_the_marker_is_not_adopted() -> None:
    """A loose match must not become this fingerprint's issue for ever."""
    forge = _forge(
        lambda request: httpx2.Response(200, json=[_issue_payload(description="other")])
    )

    assert forge.find_issue_by_marker(REPO, FINGERPRINT) is None


# --- the differences a shared implementation would paper over -------------------------------------


def test_closing_an_issue_sends_a_verb_and_not_a_state() -> None:
    """`state_event: close`. Sending `state: closed` is accepted with a 200 and changes nothing,
    which is the worst kind of wrong: every close reports success and every issue stays open."""
    sent: list[dict[str, object]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(json.loads(request.content))
        return httpx2.Response(200, json=_issue_payload())

    _forge(handler).set_issue_state(REPO, 7, "closed")

    assert sent == [{"state_event": "close"}]


def test_a_state_this_forge_cannot_be_asked_for_is_refused_before_the_request() -> None:
    """Refusing beats translating badly: an unknown word would otherwise be a silent no-op."""
    forge = _forge(lambda request: httpx2.Response(200, json=_issue_payload()))

    with pytest.raises(PermanentForgeError, match="not an issue state"):
        forge.set_issue_state(REPO, 7, "archived")


def test_a_squashed_merge_still_reports_a_commit() -> None:
    """**`merge_commit_sha` is null when the merge was squashed**, and M9 cannot decide a recurrence
    without a commit: without this, a merged fix is watched with nothing to compare against."""
    squashed = {
        "iid": 10,
        "state": "merged",
        "merge_commit_sha": None,
        "squash_commit_sha": "beed992f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
        "merged_at": "2026-08-03T09:42:11.000Z",
    }

    state = _forge(lambda request: httpx2.Response(200, json=squashed)).merge_state(REPO, 10)

    assert state.merged is True
    assert state.commit == "beed992f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
    assert state.merged_at is not None


def test_an_open_merge_request_is_not_merged() -> None:
    forge = _forge(lambda request: httpx2.Response(200, json={"iid": 10, "state": "opened"}))

    assert forge.merge_state(REPO, 10).merged is False


def test_containment_is_the_merge_base_being_the_commit_itself() -> None:
    """Ancestry by id rather than by a word (GitHub) or a count (which made Forgejo's wrong)."""
    commit = "a" * 40
    forge = _forge(lambda request: httpx2.Response(200, json={"id": commit}))

    assert forge.release_contains(REPO, "b" * 40, commit) is True


def test_a_release_that_is_not_a_sha_asks_nothing() -> None:
    """`0.4.2` against a commit is undecidable, and asking would 404 like a missing project."""

    def handler(request: httpx2.Request) -> httpx2.Response:  # pragma: no cover - not called
        raise AssertionError("no request should have been made")

    assert _forge(handler).release_contains(REPO, "0.4.2", "a" * 40) is None


def test_a_multi_file_commit_is_one_request() -> None:
    """Atomicity is the server's problem here, as on Forgejo and unlike GitHub's four calls."""
    requests: list[list[dict[str, str]]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(json.loads(request.content)["actions"])
        return httpx2.Response(201, json={"id": "c" * 40})

    sha = _code(handler).commit_files(
        REPO,
        "hullwork/item-132",
        "test: reproduce the failure",
        [
            FileChange(path="tests/test_it.py", operation="create", content=b"def test(): ..."),
            FileChange(path="src/it.py", operation="update", content=b"fixed", sha="old"),
        ],
        author="Hullwork",
        email="hullwork@example.com",
    )

    assert sha == "c" * 40
    assert len(requests) == 1, "one commit, one request"
    actions = requests[0]
    assert [action["action"] for action in actions] == ["create", "update"]
    assert base64.b64decode(actions[1]["content"]) == b"fixed"


def test_an_empty_change_set_is_refused() -> None:
    """The forge would accept it and move the branch head with an empty commit."""

    def handler(request: httpx2.Request) -> httpx2.Response:  # pragma: no cover - not called
        raise AssertionError("no request should have been made")

    with pytest.raises(PermanentForgeError, match="empty change set"):
        _code(handler).commit_files(
            REPO, "b", "m", [], author="Hullwork", email="hullwork@example.com"
        )


def test_a_draft_is_asked_for_by_prefix_and_confirmed_by_the_field() -> None:
    """The two other forges mixed: Forgejo's prefix out, GitHub's boolean back. There is no `draft`
    parameter at creation, so the assertion on the response is the only check there is."""
    sent: list[dict[str, object]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(json.loads(request.content))
        return httpx2.Response(
            201,
            json={
                "iid": 12,
                "title": "Draft: fix it",
                "web_url": f"{BASE}/x/-/merge_requests/12",
                "draft": True,
            },
        )

    pull = _code(handler).open_draft_pull_request(REPO, "head", "main", "fix it", "body")

    assert pull.draft is True and pull.number == 12
    assert sent[0]["title"] == "Draft: fix it"


def test_a_merge_request_that_came_back_ready_is_refused() -> None:
    """**The human-merge gate, not a title convention.** An instance with the prefixes configured
    away would otherwise publish merge-ready work and call it a draft."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(201, json={"iid": 12, "title": "fix it", "draft": False})

    with pytest.raises(PermanentForgeError, match="not a draft"):
        _code(handler).open_draft_pull_request(REPO, "head", "main", "fix it", "body")


def test_the_deprecated_field_is_read_only_as_a_fallback() -> None:
    """An older self-hosted GitLab answers `work_in_progress` and no `draft`; reading only the new
    name would report every draft there as ready and trip the refusal above."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            201, json={"iid": 12, "title": "Draft: fix it", "work_in_progress": True}
        )

    pull = _code(handler).open_draft_pull_request(REPO, "h", "main", "fix it", "b")

    assert pull.draft is True


def test_the_manifest_is_read_from_the_default_branch_and_never_a_given_ref() -> None:
    """GitLab's file route demands a `ref`, the one parameter `Forge` refuses to expose: a ref a
    pull request could point at is how somebody rewrites their own risk lanes."""
    asked: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        asked.append(f"{_wire(request)}?{request.url.params}")
        if _wire(request) == f"/api/v4/projects/{ENCODED}":
            return httpx2.Response(200, json={"default_branch": "trunk"})
        return httpx2.Response(200, json={"content": base64.b64encode(b"project: p\n").decode()})

    assert _forge(handler).read_manifest(REPO) == "project: p\n"
    assert "ref=trunk" in asked[-1], "the ref is the default branch, resolved here"


def test_a_reporter_is_measured_as_unable_and_a_developer_stays_unknown() -> None:
    """A project access token authenticates as its own bot user, so the access level *is* the
    token's role — which is why this answers `False` where GitHub's block cannot answer at all. At
    Developer it stays `None`: the scope is a second layer, and `read_api` cannot write anything.
    """
    reporter = _forge(
        lambda request: httpx2.Response(
            200, json={"permissions": {"project_access": {"access_level": 20}}}
        )
    )
    developer = _forge(
        lambda request: httpx2.Response(
            200, json={"permissions": {"project_access": {"access_level": 30}}}
        )
    )

    assert reporter.can_write_code(REPO) is False
    assert developer.can_write_code(REPO) is None, "never False on an unreadable scope"


# --- the probe, in its third shape ----------------------------------------------------------------


def _probe_client(handler: Handler) -> Callable[..., httpx2.Client]:
    """The probe builds its own client on purpose, so the class is replaced rather than injected."""
    real = httpx2.Client

    def make(*args: object, **kwargs: object) -> httpx2.Client:
        kwargs.pop("timeout", None)
        return real(*args, transport=httpx2.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    return make


def test_the_probe_sends_gitlabs_shape_when_the_operator_declared_gitlab(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Item 131's regression in the other direction: a self-hosted URL must not get Forgejo's
    request when the instance was declared GitLab."""
    asked: list[tuple[str, str]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        asked.append((request.method, _wire(request)))
        return httpx2.Response(403, json={"message": "403 Forbidden"})

    monkeypatch.setattr(httpx2, "Client", _probe_client(handler))

    verdict = credentials.token_may_write_code(BASE, TOKEN, REPO, declared_kind="gitlab")

    assert verdict is False
    assert asked == [("POST", f"/api/v4/projects/{ENCODED}/repository/branches")]


def test_an_invalid_ref_means_the_token_can_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """Past the role check and into validation. Nothing was created — it could not be."""
    monkeypatch.setattr(
        httpx2,
        "Client",
        _probe_client(
            lambda request: httpx2.Response(400, json={"message": "Invalid reference name"})
        ),
    )

    assert credentials.token_may_write_code(BASE, TOKEN, REPO, declared_kind="gitlab") is True


def test_a_404_stays_unknown_on_gitlab_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same trap as GitHub's: a token that cannot see the project at all is answered `404`, so
    reading it as a refusal would report a credential as safe on the strength of a typo."""
    monkeypatch.setattr(
        httpx2, "Client", _probe_client(lambda request: httpx2.Response(404, json={}))
    )

    assert credentials.token_may_write_code(BASE, TOKEN, REPO, declared_kind="gitlab") is None


# --- which forge this instance serves, now that the URL cannot say --------------------------------


def test_the_url_still_decides_for_github_and_a_declaration_cannot_move_it() -> None:
    """`api.github.com` speaks one API whatever a configuration file says."""
    assert kind_of("https://github.com", None) == "github"
    assert kind_of("https://github.com", "gitlab") == "github"
    assert declaration_disagrees("https://github.com", "gitlab") is not None


def test_no_declaration_still_means_the_gitea_family() -> None:
    """Every instance running today declares nothing and must keep working untouched."""
    assert kind_of("https://forge.example", None) == "forgejo"
    assert kind_of("https://forge.example", "gitea") == "forgejo"
    assert kind_of("https://forge.example", "gitlab") == "gitlab"
    assert declaration_disagrees("https://forge.example", None) is None


def test_a_kind_this_version_cannot_serve_is_named_rather_than_guessed() -> None:
    said = declaration_disagrees("https://forge.example", "bitbucket")

    assert said is not None
    assert "bitbucket" in said and "gitlab" in said


def test_an_instance_declared_gitlab_builds_gitlab_clients() -> None:
    settings = Settings(
        forge_url=BASE,
        forge_kind="gitlab",
        forge_token=SecretStr("ingest"),
        forge_code_token=SecretStr("code"),
    )

    read = make_forge(settings)
    write = make_code_forge(settings)

    assert isinstance(read, GitLabForge)
    assert isinstance(write, GitLabCodeForge)
    assert configured_kind(settings) == "gitlab"
    read.close()
    write.close()


def test_serves_refuses_the_two_forges_this_instance_is_not() -> None:
    """Item 124's rule with three possible answers, and no default for the unknown: `serves`
    decides whether to *refuse*, where being helpful about an unrecognised name lets it through."""
    gitlab = Settings(forge_url=BASE, forge_kind="gitlab", forge_token=SecretStr("t"))

    assert serves(gitlab, "gitlab") is True
    assert serves(gitlab, "github") is False
    assert serves(gitlab, "forgejo") is False
    assert serves(gitlab, "bitbucket") is False


# --- a project inside subgroups, end to end -------------------------------------------------------


def test_a_nested_project_is_valid_on_gitlab_and_a_typo_anywhere_else() -> None:
    """Three segments are ordinary on GitLab and a mistake on GitHub: the rule is per provider."""
    nested = parse_manifest(f"project: p\ngit: {{provider: gitlab, repo: {NESTED}}}\n")

    assert nested.git.repo == NESTED

    with pytest.raises(ManifestError, match="owner/name"):
        parse_manifest(f"project: p\ngit: {{provider: github, repo: {NESTED}}}\n")


def test_every_manifest_problem_is_still_reported_at_once() -> None:
    """**The regression this change actually caused**, caught by the suite: moving the repository
    rule into a model validator meant pydantic skipped it whenever another field had already
    failed, so a manifest with a bad provider *and* a bad repo reported only the provider."""
    with pytest.raises(ManifestError) as caught:
        parse_manifest("project: p\ngit: {provider: bitbucket, repo: not-a-repo}\nci: jenkins\n")

    joined = " ".join(caught.value.problems)

    assert "git.provider" in joined
    assert "git.repo" in joined
    assert "ci" in joined


def test_a_nested_project_addresses_as_one_segment() -> None:
    """`%2F` all the way down, which is what keeps the guard's single segment sound.

    **And the trap that comes with it, asserted rather than left for somebody to trip over.** The
    decoded view of this same request has two extra segments. Anything reading a path back from the
    client — a future check, a log-based audit, a reviewer at a terminal — sees a shape that never
    went near GitLab, and would conclude the encoding is not happening.
    """
    asked: list[str] = []
    decoded: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        asked.append(_wire(request))
        decoded.append(request.url.path)
        return httpx2.Response(200, json=_issue_payload())

    _forge(handler).get_issue(NESTED, 7)

    assert asked == ["/api/v4/projects/flagship%2Flabs%2Fhullwork-sandbox/issues/7"]
    assert decoded == ["/api/v4/projects/flagship/labs/hullwork-sandbox/issues/7"], (
        "the decoded path is not what was sent, and is not what the guard was given"
    )
