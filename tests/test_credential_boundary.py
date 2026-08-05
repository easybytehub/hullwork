"""The ingest client cannot write code, whatever its token allows (item 061).

Operator instruction: make sure Hullwork does what it promises and no more, **whatever the token's
scope allows**. The trigger was Hullwork's own readiness warning on
the live instance — *"the ingest credential CAN write code to acme/checkout-api — the
credential split for this project is a fiction"* — which is the right thing to say and the wrong
kind of control on its own: it describes the operator's token, not this program's behaviour.

Every test here asserts **no request was made**, not that one returned an error. "It refused" and
"it never asked" are different guarantees, and only the second is what spec M2 §1 promises.
"""

from typing import Any

import httpx2
import pytest

from hullwork.forge import CredentialMisuseError
from hullwork.forge.forgejo import ForgejoCodeForge, ForgejoForge
from hullwork.forge.github import GitHubCodeForge, GitHubForge

SEEN: list[tuple[str, str]] = []


def _recording_transport() -> httpx2.MockTransport:
    """A transport that records anything that reaches it. Reaching it at all is the failure."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        # The path as the forge sees it. Forgejo's client prefixes `/api/v1`, so the assertions
        # below compare the tail — what matters is *whether* a request left, and where it aimed.
        SEEN.append((request.method, request.url.path))
        return httpx2.Response(200, json={})

    return httpx2.MockTransport(handler)


@pytest.fixture(autouse=True)
def _clear() -> None:
    SEEN.clear()


def _forgejo_ingest() -> ForgejoForge:
    return ForgejoForge("https://forge.example", "tok", transport=_recording_transport())


# --- what the ingest client must refuse ---------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        # Every write the code role performs, aimed at the ingest client.
        ("POST", "/repos/o/r/contents"),
        ("POST", "/repos/o/r/branches"),
        ("POST", "/repos/o/r/pulls"),
        ("POST", "/repos/o/r/git/refs"),
        ("POST", "/repos/o/r/git/trees"),
        ("PATCH", "/repos/o/r/git/refs/heads/main"),
        ("DELETE", "/repos/o/r/branches/main"),
        # And the shapes a careless path would take.
        ("POST", "/repos/o/r"),
        ("POST", "/repos/o/r/releases"),
        ("PUT", "/repos/o/r/contents/README.md"),
    ],
)
def test_the_ingest_client_never_asks_the_forge_to_write_code(method: str, path: str) -> None:
    api = _forgejo_ingest()

    with pytest.raises(CredentialMisuseError) as caught:
        api._request(method, path)

    assert SEEN == [], f"the request reached the network: {SEEN}"
    assert "must never write code" in str(caught.value)


def test_a_path_that_merely_contains_the_word_issues_is_still_refused() -> None:
    """Matched on the path's structure, not as a substring.

    `/repos/o/r/contents/issues` is a file called `issues` in the repository, and a substring rule
    would have let it through — which is the difference between a guardrail and a coincidence.
    """
    api = _forgejo_ingest()

    with pytest.raises(CredentialMisuseError):
        api._request("PUT", "/repos/o/r/contents/issues")

    assert SEEN == []


def test_the_refusal_is_not_a_forge_error() -> None:
    """A `ForgeError` is retried, degraded around, and reported as the forge being unavailable.

    This is none of those: it means Hullwork tried to do what it promised not to, so it must stop
    and be noticed rather than look like a bad afternoon on somebody's server.
    """
    from hullwork.forge import ForgeError

    api = _forgejo_ingest()

    with pytest.raises(CredentialMisuseError) as caught:
        api._request("POST", "/repos/o/r/contents")

    assert not isinstance(caught.value, ForgeError)


def test_being_the_ingest_role_is_not_a_keyword_a_caller_can_switch_off() -> None:
    """Otherwise the hole is one argument wide, and the argument would look like configuration."""
    api = ForgejoForge(
        "https://forge.example", "tok", transport=_recording_transport(), ingest_only=False
    )

    with pytest.raises(CredentialMisuseError):
        api._request("POST", "/repos/o/r/contents")


# --- what it must still be able to do -----------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/repos/o/r/issues"),
        ("POST", "/repos/o/r/issues/42/comments"),
        ("PATCH", "/repos/o/r/issues/42"),
        ("POST", "/repos/o/r/labels"),
        # Reads are never restricted: the manifest, a branch head, an issue.
        ("GET", "/repos/o/r/contents/hullwork.yml"),
        ("GET", "/repos/o/r/branches/main"),
        ("GET", "/repos/o/r/git/ref/heads/main"),
    ],
)
def test_every_legitimate_ingest_call_still_goes_through(method: str, path: str) -> None:
    api = _forgejo_ingest()

    api._request(method, path)

    assert len(SEEN) == 1
    assert SEEN[0][0] == method
    assert SEEN[0][1].endswith(path)


def test_a_query_string_does_not_change_the_verdict() -> None:
    """`ensure_labels` reads with `?limit=100`, and the rule must see the path either way."""
    api = _forgejo_ingest()

    api._request("POST", "/repos/o/r/issues?draft=false")

    assert len(SEEN) == 1
    assert SEEN[0][1].endswith("/repos/o/r/issues")


# --- and the code client is deliberately not restricted -----------------------------------------


def test_the_code_client_may_write_code_or_nothing_could_ever_be_published() -> None:
    """Confusing the two directions would be the same defect with the blast radius reversed."""
    api = ForgejoCodeForge("https://forge.example", "tok", transport=_recording_transport())

    api._request("POST", "/repos/o/r/contents")

    assert len(SEEN) == 1
    assert SEEN[0][1].endswith("/repos/o/r/contents")


# --- both providers, or it is not a guarantee ----------------------------------------------------


def _github(cls: Any) -> Any:  # noqa: ANN401 - two adapter classes with one shape
    client = cls("tok", base_url="https://api.github.test")
    client._api._client = httpx2.Client(
        base_url="https://api.github.test", transport=_recording_transport()
    )
    return client


def test_the_github_ingest_client_refuses_too() -> None:
    """A promise that holds on one provider is not a promise."""
    with pytest.raises(CredentialMisuseError):
        _github(GitHubForge)._api.request("POST", "/repos/o/r/git/refs")

    assert SEEN == []


def test_the_github_ingest_client_can_still_file_an_issue() -> None:
    _github(GitHubForge)._api.request("POST", "/repos/o/r/issues")

    assert len(SEEN) == 1
    assert SEEN[0][1].endswith("/repos/o/r/issues")


def test_the_github_code_client_may_write_code() -> None:
    _github(GitHubCodeForge)._api.request("POST", "/repos/o/r/git/trees")

    assert len(SEEN) == 1
    assert SEEN[0][1].endswith("/repos/o/r/git/trees")
