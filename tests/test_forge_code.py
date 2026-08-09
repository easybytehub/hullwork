"""The credential that can push, against responses recorded from a live instance.

Every payload shape and every status code here came from `easybyte/hullwork-sandbox` on Forgejo
15.0.5 on 2026-07-27, by making the call and reading the answer. Four of them are the reason this
file exists rather than a happy path: `draft` cannot be set, an empty change set produces an empty
commit, "branch already exists" is a 409 here and a 422 elsewhere, and three permanent errors arrive
as HTTP 500.

The suite never opens a socket: httpx2's MockTransport serves the recorded shapes.
"""

import base64
import json
from collections.abc import Callable
from typing import Any

import httpx2
import pytest

from hullwork.forge import (
    BranchExistsError,
    FileChange,
    Forge,
    ForgeCode,
    PermanentForgeError,
    RetryableForgeError,
)
from hullwork.forge.forgejo import ForgejoCodeForge, ForgejoForge

REPO = "easybyte/hullwork-sandbox"
TOKEN = "tok_code_not_a_real_token"  # noqa: S105 - fixture
BASE_SHA = "8593a28e6244bec73fb37b17ecff99abc23a23d7"
BRANCH = "hullwork/item-42-a1b2c3"
AUTHOR = "Hullwork"
EMAIL = "hullwork@localhost.invalid"


def _forge(handler: Callable[[httpx2.Request], httpx2.Response]) -> ForgejoCodeForge:
    return ForgejoCodeForge(
        "https://forge.example", TOKEN, transport=httpx2.MockTransport(handler)
    )


def _json(request: httpx2.Request) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(request.content)
    return parsed


def _branch_response(name: str = BRANCH) -> dict[str, Any]:
    return {
        "name": name,
        "commit": {"id": BASE_SHA, "message": "chore: load the queue for M2\n"},
        "protected": False,
        "user_can_push": True,
        "user_can_merge": True,
    }


def _commit_response(sha: str = "5f99c11c4e0d8a7b6c5d4e3f2a1b0c9d8e7f6a5b") -> dict[str, Any]:
    """The contents API returns the file list and the commit it landed in."""
    return {
        "files": [None],
        "commit": {
            "sha": sha,
            "message": "test: reproduce the reported failure\n",
            "author": {"name": AUTHOR, "email": EMAIL},
            "committer": {"name": AUTHOR, "email": EMAIL},
        },
    }


def _pull_response(
    number: int = 8, *, draft: bool = True, title: str = "WIP: fix it"
) -> dict[str, Any]:
    return {
        "number": number,
        "title": title,
        "body": "Closes #7",
        "state": "open",
        "draft": draft,
        "mergeable": not draft,
        "html_url": f"https://forge.example/{REPO}/pulls/{number}",
        "labels": [{"id": 83, "name": "hullwork:green"}],
    }


# --- the boundary itself ------------------------------------------------------------------------


def test_the_ingest_forge_cannot_change_code() -> None:
    """The point of implementing these as two classes rather than one.

    Item 017 split the protocols so the always-on credential could never push. If one class
    satisfied both, a bug that passed the ingest forge where a code forge belongs would *work* on
    any instance whose token happens to carry the scope — silently, and with the wrong credential.
    Two classes turn that bug into an immediate failure.
    """
    ingest = ForgejoForge("https://forge.example", TOKEN)

    assert isinstance(ingest, Forge)
    assert not isinstance(ingest, ForgeCode)
    for verb in ("create_branch", "commit_files", "open_draft_pull_request"):
        assert not hasattr(ingest, verb)


def test_the_code_forge_cannot_touch_issues() -> None:
    code = ForgejoCodeForge("https://forge.example", TOKEN)

    assert isinstance(code, ForgeCode)
    assert not isinstance(code, Forge)
    for verb in ("create_issue", "comment", "set_issue_state", "read_manifest"):
        assert not hasattr(code, verb)


def test_nothing_here_can_merge() -> None:
    # `human-merge` is a gate (constitution §1). A method for it would be one refactor away from
    # being called, so it does not exist on the protocol or the implementation.
    assert not hasattr(ForgejoCodeForge("https://forge.example", TOKEN), "merge")
    assert not hasattr(ForgeCode, "merge")


# --- reads --------------------------------------------------------------------------------------


def test_head_commit_is_the_identity_of_what_was_tested() -> None:
    forge = _forge(lambda request: httpx2.Response(200, json=_branch_response("main")))

    assert forge.head_commit(REPO, "main") == BASE_SHA


def test_a_branch_without_a_head_is_refused_rather_than_guessed() -> None:
    forge = _forge(lambda request: httpx2.Response(200, json={"name": "main"}))

    with pytest.raises(PermanentForgeError, match="no head commit"):
        forge.head_commit(REPO, "main")


# --- branching ----------------------------------------------------------------------------------


def test_a_branch_is_rooted_at_a_sha_not_at_a_moving_target() -> None:
    """`old_ref_name` takes a commit sha, which is what makes the evidence honest.

    Rooted at the sha the gates ran against, the pull request contains exactly the tree that passed
    them however much the default branch moves during an attempt — no lock, no abort, no race.
    """
    seen: dict[str, Any] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.update(_json(request))
        return httpx2.Response(201, json=_branch_response())

    _forge(handler).create_branch(REPO, BRANCH, BASE_SHA)

    assert seen == {"new_branch_name": BRANCH, "old_ref_name": BASE_SHA}


def test_a_branch_that_already_exists_says_so_in_its_own_type() -> None:
    # Live: 409 {"message":"The branch already exists."} — the one failure a caller handles rather
    # than reports, because it means a previous attempt died halfway.
    forge = _forge(
        lambda request: httpx2.Response(409, json={"message": "The branch already exists."})
    )

    with pytest.raises(BranchExistsError) as caught:
        forge.create_branch(REPO, BRANCH, BASE_SHA)

    assert caught.value.status == 409
    assert isinstance(caught.value, PermanentForgeError)


def test_a_missing_base_ref_is_not_mistaken_for_an_existing_branch() -> None:
    forge = _forge(
        lambda request: httpx2.Response(404, json={"message": "The old branch does not exist"})
    )

    with pytest.raises(PermanentForgeError) as caught:
        forge.create_branch(REPO, BRANCH, "deadbeef")

    assert not isinstance(caught.value, BranchExistsError)


# --- committing ---------------------------------------------------------------------------------


def test_an_empty_change_set_never_reaches_the_forge() -> None:
    """Live, the forge answers 201 and moves the branch head with an empty commit.

    So "the agent changed nothing" would become a real branch and a pull request with no diff in it
    — the most confusing artefact this product could hand somebody.
    """
    called = False

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal called
        called = True
        return httpx2.Response(201, json=_commit_response())

    with pytest.raises(PermanentForgeError, match="empty change set"):
        _forge(handler).commit_files(REPO, BRANCH, "m", [], author=AUTHOR, email=EMAIL)

    assert not called


def test_one_call_lands_every_change_as_one_commit() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.update(_json(request))
        return httpx2.Response(201, json=_commit_response())

    sha = _forge(handler).commit_files(
        REPO,
        BRANCH,
        "test: reproduce the reported failure",
        [
            FileChange(
                path="tests/test_item_42.py", operation="create", content=b"def test(): ..."
            ),
            FileChange(path="src/app.py", operation="update", content=b"fixed", sha="297a5cd9"),
            FileChange(path="src/dead.py", operation="delete", sha="abc123"),
        ],
        author=AUTHOR,
        email=EMAIL,
    )

    assert sha == "5f99c11c4e0d8a7b6c5d4e3f2a1b0c9d8e7f6a5b"
    assert seen["branch"] == BRANCH
    assert seen["author"] == {"name": AUTHOR, "email": EMAIL}
    assert len(seen["files"]) == 3
    created, updated, deleted = seen["files"]
    assert base64.b64decode(created["content"]) == b"def test(): ..."
    assert "sha" not in created
    assert updated["sha"] == "297a5cd9"
    assert "content" not in deleted


def test_the_sign_off_trailer_is_never_requested() -> None:
    """The API will add it, and that is exactly why we must not ask.

    `CONTRIBUTING.md` says the DCO sign-off is a human act, done at the merge gate. A machine
    that can emit the trailer can certify provenance it has no standing to certify.
    """
    seen: dict[str, Any] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.update(_json(request))
        return httpx2.Response(201, json=_commit_response())

    _forge(handler).commit_files(
        REPO,
        BRANCH,
        "m",
        [FileChange(path="tests/t.py", operation="create", content=b"x")],
        author=AUTHOR,
        email=EMAIL,
    )

    assert "signoff" not in seen


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_a_change_without_its_pre_image_sha_is_refused_before_the_round_trip(
    operation: str,
) -> None:
    forge = _forge(lambda request: httpx2.Response(201, json=_commit_response()))

    with pytest.raises(PermanentForgeError, match="pre-image blob sha"):
        forge.commit_files(
            REPO,
            BRANCH,
            "m",
            [FileChange(path="src/app.py", operation=operation, content=b"x")],  # type: ignore[arg-type]
            author=AUTHOR,
            email=EMAIL,
        )


def test_a_create_without_content_is_refused() -> None:
    forge = _forge(lambda request: httpx2.Response(201, json=_commit_response()))

    with pytest.raises(PermanentForgeError, match="needs content"):
        forge.commit_files(
            REPO,
            BRANCH,
            "m",
            [FileChange(path="tests/t.py", operation="create")],
            author=AUTHOR,
            email=EMAIL,
        )


# --- the 500 that is not a 500 ------------------------------------------------------------------


@pytest.mark.parametrize(
    "message",
    [
        pytest.param("repository file does not exist [path: nope.txt]", id="delete-missing-path"),
        pytest.param(
            "invalid file operation: rename, supported operations are create, update, delete",
            id="unknown-verb",
        ),
        pytest.param("UpdateRepoFile: ... git ls-files ... exit status 128", id="path-traversal"),
    ],
)
def test_a_permanent_refusal_dressed_as_a_500_is_not_retried(message: str) -> None:
    """All three verified live against the contents API.

    Classified by status alone, a path typo exhausts its retries and is then reported as "the forge
    was down" — the exact misclassification DR-0003's attempt accounting exists to prevent.
    """
    forge = _forge(lambda request: httpx2.Response(500, json={"message": message}))

    with pytest.raises(PermanentForgeError) as caught:
        forge.commit_files(
            REPO,
            BRANCH,
            "m",
            [FileChange(path="tests/t.py", operation="create", content=b"x")],
            author=AUTHOR,
            email=EMAIL,
        )

    assert not isinstance(caught.value, RetryableForgeError)
    # The message is matched, never echoed: an error body can carry a credential back.
    assert message not in str(caught.value)


def test_a_genuine_500_is_still_retryable() -> None:
    forge = _forge(lambda request: httpx2.Response(500, json={"message": "database is locked"}))

    with pytest.raises(RetryableForgeError):
        forge.head_commit(REPO, "main")


@pytest.mark.parametrize("status", [502, 503, 504])
def test_a_gateway_error_is_never_second_guessed(status: int) -> None:
    # These come from infrastructure in front of the application; the body says nothing about our
    # request, so a message match there would be reading tea leaves.
    forge = _forge(lambda request: httpx2.Response(status, text="does not exist"))

    with pytest.raises(RetryableForgeError):
        forge.head_commit(REPO, "main")


# --- the draft pull request ---------------------------------------------------------------------


def test_a_pull_request_is_opened_as_a_draft_and_labelled_in_one_call() -> None:
    """Labels at creation ride on `write:repository`; labelling an issue afterwards needs
    `write:issue`. Doing it here keeps issue-write off the code credential entirely."""
    seen: dict[str, Any] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.update(_json(request))
        return httpx2.Response(201, json=_pull_response())

    pull = _forge(handler).open_draft_pull_request(
        REPO, BRANCH, "main", "fix the KeyError in reconciliation", "Closes #7", [83]
    )

    assert seen["title"] == "WIP: fix the KeyError in reconciliation"
    assert "draft" not in seen  # read-only on this API; the title is the only lever
    assert seen["labels"] == [83]
    assert pull.draft
    assert pull.ref == "#8"


def test_a_pull_request_that_did_not_come_back_a_draft_fails_loudly() -> None:
    """The prefixes are instance-configurable and exposed by no endpoint.

    So `WIP:` is a guess about somebody else's configuration. Trusting it on an instance configured
    differently leaves a merge-ready pull request that the rest of the system calls a draft — which
    is worse than failing, because `human-merge` would still be reported as satisfied.
    """
    forge = _forge(
        lambda request: httpx2.Response(
            201, json=_pull_response(draft=False, title="WIP: fix it")
        )
    )

    with pytest.raises(PermanentForgeError, match="did not come back as a draft"):
        forge.open_draft_pull_request(REPO, BRANCH, "main", "fix it", "body")


def test_draft_is_read_from_the_response_and_never_assumed() -> None:
    # An older forge, or one that drops the field: absent must not read as "yes, it is a draft".
    forge = _forge(lambda request: httpx2.Response(201, json={"number": 9, "html_url": "u"}))

    with pytest.raises(PermanentForgeError, match="did not come back as a draft"):
        forge.open_draft_pull_request(REPO, BRANCH, "main", "fix it", "body")
