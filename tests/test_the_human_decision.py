"""What the reviewer decided, which is the half the funnel could not see. Item 138, M13.

The gap was not a report. `ItemState` had no value for *a human refused this*, so a pull request
closed without merging left its item in `pr-open` for ever — indistinguishable from one nobody had
opened. Waiting and refused are opposite facts, and review debt is the count of the first.
"""


import httpx2
import pytest

from hullwork import outcomes
from hullwork.forge import MergeState, labels_of
from hullwork.models import ItemState
from hullwork.states import LEGAL, IllegalTransitionError, transition

# --- the forge answer that could not express it --------------------------------------------------


def test_open_and_closed_unmerged_stopped_being_the_same_answer() -> None:
    """`merged: bool` said `False` for both, which is why an item could stay `pr-open` for ever."""
    waiting = MergeState(merged=False, state="open")
    refused = MergeState(merged=False, state="closed")

    assert waiting.merged == refused.merged
    assert waiting.state != refused.state


def test_labels_are_read_from_either_shape_a_forge_sends() -> None:
    """All three answer objects with a `name`; GitLab also answers plain strings. One parser,
    because three copies of it agree until one is widened."""
    assert labels_of({"labels": [{"name": "hullwork:rejected-scope"}]}) == (
        "hullwork:rejected-scope",
    )
    assert labels_of({"labels": ["hullwork:rejected-cost"]}) == ("hullwork:rejected-cost",)
    assert labels_of({"labels": "not a list"}) == ()
    assert labels_of(None) == ()


# --- the reason, from a closed set ---------------------------------------------------------------


def test_a_reason_comes_from_the_set_and_ignores_the_rest() -> None:
    """A repository has its own labels; a pull request carrying `needs-discussion` is not
    malformed."""
    assert outcomes.rejection_reason(["needs-discussion", "hullwork:rejected-scope"]) == (
        "excessive scope"
    )


def test_no_recognised_label_is_not_given_rather_than_other() -> None:
    """**Item 110's rule, again.** A rejection with no reason is a fact about the review, and
    folding it into a bucket would make the distribution flattering."""
    assert outcomes.rejection_reason(["wontfix"]) is None
    assert outcomes.rejection_reason([]) is None


# --- the state, and who may set it ---------------------------------------------------------------


def test_rejected_is_reachable_only_from_a_published_pull_request() -> None:
    """The state exists to be reached by a person's decision and by nothing else."""
    sources = [state for state, targets in LEGAL.items() if ItemState.REJECTED in targets]

    assert sources == [ItemState.PR_OPEN]


def test_nothing_automated_sends_a_refusal_back_to_the_agent() -> None:
    """The agent had its one attempt (DR-0003) and a human looked at the result and said no. `done`
    stays reachable — somebody fixing it by hand is the ordinary sequel to a rejection."""
    from hullwork.models import Item, ItemKind, Lane

    item = Item(
        project_id=1, fingerprint="f", title="t", state=ItemState.REJECTED,
        lane=Lane.GREEN, kind=ItemKind.BUG,
    )

    with pytest.raises(IllegalTransitionError):
        transition(item, ItemState.READY)

    transition(item, ItemState.DONE)
    assert item.state is ItemState.DONE


# --- and that each adapter actually fills it in ---------------------------------------------------


def _closed_unmerged(payload: dict[str, object]) -> httpx2.Response:
    return httpx2.Response(200, json=payload)


def test_forgejo_reports_a_closed_pull_request_as_closed() -> None:
    """**A reintroduction found this missing**: the test above proved the dataclass can hold the
    distinction, not that the adapter reads it. Forgejo answers `state` and `merged` separately."""
    from hullwork.forge.forgejo import ForgejoForge

    forge = ForgejoForge(
        "https://forge.example",
        "t",
        transport=httpx2.MockTransport(
            lambda request: _closed_unmerged(
                {"state": "closed", "merged": False,
                 "labels": [{"name": "hullwork:rejected-scope"}]}
            )
        ),
    )

    state = forge.merge_state("o/r", 1)

    assert state.merged is False
    assert state.state == "closed"
    assert outcomes.rejection_reason(state.labels) == "excessive scope"


def test_github_reports_a_closed_pull_request_as_closed() -> None:
    from hullwork.forge.github import GitHubForge

    forge = GitHubForge("t")
    forge._api._client = httpx2.Client(
        base_url="https://api.github.com",
        transport=httpx2.MockTransport(
            lambda request: _closed_unmerged({"state": "closed", "merged": False, "labels": []})
        ),
    )

    state = forge.merge_state("o/r", 1)

    assert state.state == "closed"
    assert outcomes.rejection_reason(state.labels) is None, "closed with nothing said"


def test_gitlab_reads_its_one_word_state() -> None:
    """GitLab has one field where the others have two — `opened`, `closed`, `merged` or `locked` —
    and `locked` is neither a decision nor its absence, so it is `unknown` rather than guessed."""
    from hullwork.forge.gitlab import GitLabForge

    def forge_with(state: str) -> "GitLabForge":
        forge = GitLabForge("https://gitlab.example", "t")
        forge._api._client = httpx2.Client(
            base_url="https://gitlab.example/api/v4",
            transport=httpx2.MockTransport(
                lambda request: _closed_unmerged({"iid": 1, "state": state, "labels": ["x"]})
            ),
        )
        return forge

    assert forge_with("closed").merge_state("g/p", 1).state == "closed"
    assert forge_with("opened").merge_state("g/p", 1).state == "open"
    assert forge_with("locked").merge_state("g/p", 1).state == "unknown"
