"""The Forgejo adapter, against responses recorded from a live instance.

Every payload shape here was taken from `easybyte/hullwork-sandbox` on 2026-07-27 rather than from
documentation, because GlitchTip already taught us what documentation is worth. The suite never
opens a socket: httpx2's MockTransport serves the recorded shapes.
"""

import base64
import inspect
from collections.abc import Callable
from datetime import UTC

import httpx2
import pytest

from hullwork.forge import (
    ForgeError,
    ForgeIssue,
    PermanentForgeError,
    RetryableForgeError,
    marker_for,
)
from hullwork.forge.forgejo import ForgejoForge

REPO = "easybyte/hullwork-sandbox"
TOKEN = "tok_live_not_a_real_token"  # noqa: S105 - fixture
FINGERPRINT = "8e2f1c0a55b4d9e3f7a61b8c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60"

MANIFEST_TEXT = """project: hullwork-sandbox
git:
  provider: forgejo
  repo: easybyte/hullwork-sandbox
"""


def _contents_response(text: str = MANIFEST_TEXT) -> dict[str, object]:
    """Exactly the shape a live Forgejo returned: base64 in JSON, with the sha for later updates."""
    return {
        "name": "hullwork.yml",
        "path": "hullwork.yml",
        "sha": "297a5cd9c83c0676681967a883f3b1b20ebd6f24",
        "type": "file",
        "size": len(text),
        "encoding": "base64",
        "content": base64.b64encode(text.encode()).decode(),
        "download_url": f"https://forge.example/{REPO}/raw/branch/main/hullwork.yml",
        "html_url": f"https://forge.example/{REPO}/src/branch/main/hullwork.yml",
    }


def _issue_response(number: int = 1, body: str = "") -> dict[str, object]:
    return {
        "number": number,
        "id": 1000 + number,
        "title": "KeyError in payment reconciliation",
        "body": body,
        "state": "open",
        "labels": [{"id": 83, "name": "hullwork:red", "color": "cf222e"}],
        "html_url": f"https://forge.example/{REPO}/issues/{number}",
        "url": f"https://forge.example/api/v1/repos/{REPO}/issues/{number}",
        "created_at": "2026-07-27T00:53:24+02:00",
        "updated_at": "2026-07-27T00:53:24+02:00",
        "closed_at": None,
        "comments": 0,
    }


def _forge(handler: Callable[[httpx2.Request], httpx2.Response]) -> ForgejoForge:
    return ForgejoForge(
        "https://forge.example", TOKEN, transport=httpx2.MockTransport(handler)
    )


# --- reading the manifest ------------------------------------------------------------------


def test_the_manifest_is_decoded_from_base64() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith(f"/repos/{REPO}"):
            return httpx2.Response(200, json={"default_branch": "main"})
        return httpx2.Response(200, json=_contents_response())

    assert _forge(handler).read_manifest(REPO) == MANIFEST_TEXT


def test_the_default_branch_is_asked_for_never_assumed() -> None:
    """A repo on `master` must work. Guessing `main` turns a wrong branch into "no manifest"."""
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(str(request.url))
        if request.url.path.endswith(f"/repos/{REPO}"):
            return httpx2.Response(200, json={"default_branch": "master"})
        return httpx2.Response(200, json=_contents_response())

    _forge(handler).read_manifest(REPO)

    assert any("ref=master" in url for url in seen), seen


def test_the_manifest_cannot_be_read_from_an_arbitrary_ref() -> None:
    """Structural on purpose: reading it from a PR head would let a contributor rewrite lanes.

    Enforced by the signature rather than by a comment asking nicely.
    """
    parameters = set(inspect.signature(ForgejoForge.read_manifest).parameters)

    assert parameters == {"self", "repo"}


def test_a_non_base64_body_is_refused_rather_than_guessed() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith(f"/repos/{REPO}"):
            return httpx2.Response(200, json={"default_branch": "main"})
        return httpx2.Response(200, json={"encoding": "utf-8", "content": "project: x"})

    with pytest.raises(PermanentForgeError, match="base64"):
        _forge(handler).read_manifest(REPO)


def test_a_repository_without_a_default_branch_fails_clearly() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={})

    with pytest.raises(PermanentForgeError, match="default branch"):
        _forge(handler).read_manifest(REPO)


# --- labels --------------------------------------------------------------------------------


def test_labels_are_created_only_when_missing_and_returned_as_ids() -> None:
    created: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "GET":
            return httpx2.Response(200, json=[{"id": 83, "name": "hullwork:red"}])
        created.append(str(request.url))
        return httpx2.Response(201, json={"id": 84, "name": "hullwork:green"})

    ids = _forge(handler).ensure_labels(
        REPO, {"hullwork:red": "#cf222e", "hullwork:green": "#1a7f37"}
    )

    # Ids, because the API attaches by id and silently ignores names.
    assert ids == {"hullwork:red": 83, "hullwork:green": 84}
    assert len(created) == 1  # the existing one was not recreated


def test_create_issue_sends_label_ids_not_names() -> None:
    sent: dict[str, object] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        import json

        sent.update(json.loads(request.content))
        return httpx2.Response(201, json=_issue_response())

    issue = _forge(handler).create_issue(REPO, "boom", "body", label_ids=[83])

    assert sent["labels"] == [83]
    assert isinstance(issue, ForgeIssue)
    assert issue.number == 1
    assert issue.ref == "#1"


# --- finding an issue again ------------------------------------------------------------------


def test_an_issue_is_found_by_its_hidden_marker() -> None:
    body = f"Reported by Hullwork.\n\n{marker_for(FINGERPRINT)}\n"

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json=[_issue_response(body=body)])

    found = _forge(handler).find_issue_by_marker(REPO, FINGERPRINT)

    assert found is not None
    assert found.number == 1


def test_a_search_hit_without_the_marker_is_not_accepted() -> None:
    """The search is a text match, so its results are checked rather than trusted.

    A full-text engine that matched loosely would otherwise let us attach an occurrence to somebody
    else's issue — a wrong link that looks exactly like a right one.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json=[_issue_response(body="unrelated issue, no marker here")])

    assert _forge(handler).find_issue_by_marker(REPO, FINGERPRINT) is None


def test_no_results_means_none() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json=[])

    assert _forge(handler).find_issue_by_marker(REPO, FINGERPRINT) is None


# --- failure modes ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_transient_statuses_are_retryable(status: int) -> None:
    """DR-0003 gives an item one attempt. "The forge was down" must not consume it."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status)

    with pytest.raises(RetryableForgeError):
        _forge(handler).default_branch(REPO)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
def test_client_errors_are_permanent(status: int) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status)

    with pytest.raises(PermanentForgeError):
        _forge(handler).default_branch(REPO)


@pytest.mark.parametrize("status", [400, 401, 403, 422, 500])
def test_only_a_missing_issue_reads_as_gone(status: int) -> None:
    """`get_issue` returning None means "deleted", and the caller acts on that.

    Swallowing every failure into None turned a revoked token into a silently dead reconciliation
    subsystem, with no log line anywhere (item 016). Anything that is not a 404 must propagate.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status)

    with pytest.raises(ForgeError) as caught:
        _forge(handler).get_issue(REPO, 7)
    assert caught.value.status == status


def test_a_deleted_issue_is_none_rather_than_an_error() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(404)

    assert _forge(handler).get_issue(REPO, 7) is None


def test_a_timeout_is_retryable() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.TimeoutException("too slow")

    with pytest.raises(RetryableForgeError, match="timed out"):
        _forge(handler).default_branch(REPO)


def test_the_token_never_appears_in_an_error_message() -> None:
    """Error text ends up in logs and issue comments. The credential must not travel with it."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        # A forge that echoes the auth header back in its error body — not hypothetical.
        return httpx2.Response(401, json={"message": f"bad token: {TOKEN}"})

    with pytest.raises(PermanentForgeError) as caught:
        _forge(handler).default_branch(REPO)

    assert TOKEN not in str(caught.value)


def test_a_non_json_response_is_permanent_not_a_crash() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, text="<html>a proxy error page</html>")

    with pytest.raises(PermanentForgeError, match="not JSON"):
        _forge(handler).default_branch(REPO)


# --- did it get merged, and what carried it (M9) --------------------------------------------


#: Pull request 13 of `easybyte/hullwork`, captured from the live instance on 2026-07-30 — the fix
#: Hullwork wrote for its own item 17, merged by a human an hour later. Trimmed to the fields the
#: adapter reads; the names and the formats are verbatim.
MERGED_PULL = {
    "number": 13,
    "state": "closed",
    "merged": True,
    "merge_commit_sha": "2481a8f0460e621ceb34a0b3bfd6709f367611c7",
    # **Not `Z`.** A real Forgejo answers in the instance's own offset, and a parser that only
    # handled `Z` would drop the timestamp on every merge — silently, because `MergeState` treats a
    # missing time as decoration rather than an error.
    "merged_at": "2026-07-30T19:03:17+02:00",
    "merged_by": "jmiralles",
    "html_url": "https://forge.example/easybyte/hullwork/pulls/13",
}

#: What that merge produced.
MERGE = "2481a8f0460e621ceb34a0b3bfd6709f367611c7"


def test_a_merged_pull_request_yields_its_commit_and_the_time_it_landed() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.url.path.endswith(f"/repos/{REPO}/pulls/13")
        return httpx2.Response(200, json=MERGED_PULL)

    state = _forge(handler).merge_state(REPO, 13)

    assert state.merged is True
    assert state.commit == "2481a8f0460e621ceb34a0b3bfd6709f367611c7"
    assert state.merged_at is not None
    # The offset was read, not discarded: 19:03 at +02:00 is 17:03 UTC.
    assert state.merged_at.utcoffset() is not None
    assert state.merged_at.astimezone(UTC).hour == 17


def test_an_open_pull_request_is_not_merged_and_carries_no_commit() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200, json={"number": 14, "state": "open", "merged": False, "merged_at": None}
        )

    state = _forge(handler).merge_state(REPO, 14)

    assert state.merged is False
    assert state.commit is None


def test_a_pull_request_that_no_longer_exists_reads_as_not_merged() -> None:
    """A deleted branch takes its pull request with it on some deployments.

    Not an error, for the same reason `get_issue` returns `None` on a 404: the watch would otherwise
    retry a permanent condition every six hours for the life of the instance.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(404, json={"message": "pull request does not exist"})

    assert _forge(handler).merge_state(REPO, 999).merged is False


#: A deployed release, as a project that tags its builds with a commit reports one. Both compare
#: tests use one, and that is not a convenience: only a sha-shaped release can be compared, so a
#: project whose releases are version strings gets `undecidable` and never `recurred`. Stated here
#: because it is a real precondition of M9's gate rather than a property of these tests.
DEPLOYED_SHA = "9e7fc2b9b2c9f5351b8989325e1b5007a306f762"


def _compare(answers: dict[str, int]) -> Callable[[httpx2.Request], httpx2.Response]:
    """Serve `compare/base...head` from both directions and let the adapter pick one.

    **The point of the shape.** An earlier version of these tests returned one number to whatever
    the adapter asked, so it agreed with the adapter whichever direction it used — and the adapter
    used the wrong one, reporting every genuine recurrence as old code still deployed. Serving both
    real answers turns this from a restatement of the code into a question the code can fail.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        _, _, spec = request.url.path.partition("/compare/")
        if spec not in answers:
            raise AssertionError(f"asked for {spec!r}, which is not one of the recorded directions")
        return httpx2.Response(200, json={"commits": [], "total_commits": answers[spec]})

    return handler


def test_a_release_that_contains_the_merge_says_so() -> None:
    """Measured against the live forge on 2026-07-30, with a release six commits past the merge.

    `compare/base...head` returns the commits `head` has that `base` does not, so the release
    contains the merge when `compare/{release}...{merge}` counts zero — nothing in the merge that
    the release is missing. The other direction counts six and means the opposite.
    """
    handler = _compare({f"{MERGE}...{DEPLOYED_SHA}": 6, f"{DEPLOYED_SHA}...{MERGE}": 0})

    assert _forge(handler).release_contains(REPO, DEPLOYED_SHA, MERGE) is True


def test_a_release_that_predates_the_merge_does_not_contain_it() -> None:
    """The same two directions with the numbers an older deployment produces.

    An older release is an ancestor of the merge: it is missing the merge (non-zero), and the merge
    is not missing it (zero). Read from the wrong side, this reads as containing the fix.
    """
    older = "1a66280bd489e2023bccb916541665ed5ec27329"
    handler = _compare({f"{older}...{MERGE}": 4, f"{MERGE}...{older}": 0})

    assert _forge(handler).release_contains(REPO, older, MERGE) is False


def test_a_release_identical_to_the_merge_contains_it() -> None:
    """Zero in both directions, so this one cannot distinguish a direction — and must still be True.

    Worth its own test because it is the case the two competing readings agree on: a green here with
    a red above is the signature of the inversion rather than of a broken comparison.
    """
    handler = _compare({f"{MERGE}...{MERGE}": 0})

    assert _forge(handler).release_contains(REPO, MERGE, MERGE) is True


def test_a_release_the_forge_cannot_resolve_is_undecidable_not_false() -> None:
    """`False` would read as "old code still deployed" — a claim, and the wrong one.

    A release string the forge does not know is a question with no answer, and M9 counts those in
    neither column.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(404, json={"message": "object does not exist"})

    assert _forge(handler).release_contains(REPO, DEPLOYED_SHA, MERGE) is None


def test_a_release_that_is_not_a_ref_costs_no_request() -> None:
    """Most releases in the wild are version strings. Asking about them is a request per occurrence.

    Refused before the client is touched, which is what the handler asserting proves.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:  # pragma: no cover - must not run
        raise AssertionError("the forge was asked about something that cannot be a ref")

    assert _forge(handler).release_contains(REPO, "my app 3.2 (build 77)", MERGE) is None
