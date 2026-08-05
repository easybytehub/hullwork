"""GlitchTip's outbound webhook.

Its own documentation does not describe this payload; the shape below was read from
`apps/alerts/webhooks.py` in the GlitchTip backend on 2026-07-26. What it sends is a Slack-style
message, which means most of what we want has to be recovered from presentation:

* the issue id exists only inside the permalink,
* the severity exists only as a hex colour, and vanishes entirely below WARNING,
* there are no timestamps at all,
* and a single POST can carry several unrelated errors.

Only `title` and `title_link` are guaranteed to be present. Everything else is optional because the
payload builder drops keys whose value is None.
"""

import re
from datetime import datetime
from typing import TYPE_CHECKING, Any

from hullwork.normalise import ErrorFact, NormalisationError, Provider, derive_fingerprint

if TYPE_CHECKING:  # pragma: no cover - import cycle at runtime, needed only for the annotation
    from hullwork.tracker import TrackerIssue

PROVIDER: Provider = "glitchtip"

#: From `Issue.get_hex_color()`. Note ERROR and FATAL share a colour, so the mapping cannot be
#: inverted exactly: a fatal arrives here as "error". Recorded rather than papered over.
_COLOUR_TO_LEVEL = {
    "#4b60b4": "info",
    "#e9b949": "warning",
    "#e52b50": "error",
}

_ISSUE_ID = re.compile(r"/issues/(\d+)")


def issue_id_in(permalink: str | None) -> str | None:
    """The issue id inside a GlitchTip permalink, or `None`.

    Shared so the webhook and the inventory sweep recover it the same way. Both have a permalink; a
    second copy of this regular expression is a second thing to get subtly different.
    """
    if not permalink:
        return None
    match = _ISSUE_ID.search(str(permalink))
    return match.group(1) if match else None


def fingerprint_for(*, issue_id: str | None, title: str, culprit: str | None) -> str:
    """The identity of one GlitchTip issue, however it reached us. **DR-0011 rests on this.**

    The inventory sweep (item 080) reads the same issues the webhook reports, by a different route
    with a different JSON shape. If the two derived different fingerprints, every swept issue would
    become a **second item** for a bug that already had one — and duplicate issues are, in this
    product's own words, its cardinal sin.

    So identity lives in one function rather than in two mappers that happen to agree today. The
    parsing differs and must (camelCase against a Slack-style payload); this may not.

    The id is preferred and the title is the fallback, because the id is stable and a title is
    truncated at 100 characters by the sender and edited by humans.
    """
    return derive_fingerprint(
        PROVIDER,
        issue_id or title,
        None if issue_id else culprit,
    )


def _field(attachment: dict[str, Any], name: str) -> str | None:
    """Read one of the Slack-style `fields[]` entries by its title."""
    for entry in attachment.get("fields") or []:
        if isinstance(entry, dict) and entry.get("title") == name:
            value = entry.get("value")
            return str(value) if value is not None else None
    return None


def parse(payload: dict[str, Any], received_at: datetime) -> list[ErrorFact]:
    """Fan one delivery out into one fact per attachment.

    `received_at` is passed in rather than read from the clock so the caller owns the timestamp and
    the function stays pure — and because the value is a receipt time, not an event time.
    """
    attachments = payload.get("attachments")
    if not isinstance(attachments, list) or not attachments:
        raise NormalisationError(PROVIDER, "attachments", "expected a non-empty list")

    facts = []
    for index, attachment in enumerate(attachments):
        if not isinstance(attachment, dict):
            raise NormalisationError(PROVIDER, f"attachments[{index}]", "expected an object")
        facts.append(_one(attachment, index, payload, received_at))
    return facts


def _one(
    attachment: dict[str, Any],
    index: int,
    payload: dict[str, Any],
    received_at: datetime,
) -> ErrorFact:
    title = attachment.get("title")
    if not title:
        raise NormalisationError(PROVIDER, f"attachments[{index}].title")

    permalink = attachment.get("title_link")
    if not permalink:
        raise NormalisationError(PROVIDER, f"attachments[{index}].title_link")

    external_id = issue_id_in(str(permalink))

    # Identity: the issue id when the URL yields one, otherwise the most stable thing left. Never a
    # hash of the payload, which changes on every delivery. Through `fingerprint_for`, which the
    # inventory sweep also uses — see its docstring for why that sharing is load-bearing.
    fingerprint = fingerprint_for(
        issue_id=external_id, title=str(title), culprit=attachment.get("text")
    )

    colour = attachment.get("color")
    # An absent colour means a level below WARNING, not an error. Defaulting to "error" here is how
    # a debug line becomes a page at 3am.
    level = _COLOUR_TO_LEVEL.get(str(colour)) if colour else None

    return ErrorFact(
        provider=PROVIDER,
        project_ref=_field(attachment, "Project") or "unknown",
        title=str(title),
        culprit=attachment.get("text"),
        external_id=external_id,
        fingerprint=fingerprint,
        # Always derived: GlitchTip never sends a fingerprint of its own.
        fingerprint_derived=True,
        level=level,
        permalink=str(permalink),
        timestamps_are_receipt_time=True,
        first_seen=received_at,
        last_seen=received_at,
        occurrences=None,
        raw=payload,
    )


def from_issue(issue: "TrackerIssue", *, project_ref: str) -> ErrorFact:
    """A row of the tracker's unresolved list → one `ErrorFact`. DR-0011, item 080.

    The **second** entrance to this module, beside `parse`. Deliberately a separate function: the
    shapes disagree about more than casing — a list row has `metadata` and no `fields[]`, a real
    `status`, real timestamps and an occurrence count, while the webhook has a hex colour and a
    Slack-style attachment. One function handling both would have to guess which it was handed.

    What they must **not** disagree about is identity, and they do not: `fingerprint_for` is shared.
    That is what makes an issue arriving by both routes one item rather than two.

    Three fields are better here than they have ever been from a webhook, which is why DR-0011 says
    this improves triage as well as coverage:

    * `timestamps_are_receipt_time=False` — the tracker reports when the error actually happened.
      The webhook sends no timestamps at all, so every fact from it is stamped with our own clock.
    * `culprit` — a real location, from `metadata.filename` and `metadata.function`. Every real
      webhook measured sent `culprit: null`, and items 070 and 071 made the lane decision depend on
      having one.
    * `occurrences` — the provider's own count. The webhook never says, so a bug seen 58 times and
      one seen once were indistinguishable.
    """
    return ErrorFact(
        provider=PROVIDER,
        project_ref=project_ref,
        title=issue.title,
        culprit=issue.culprit,
        external_id=issue.external_id,
        fingerprint=fingerprint_for(
            issue_id=issue.external_id, title=issue.title, culprit=issue.culprit
        ),
        # Always derived: GlitchTip sends no fingerprint of its own by either route.
        fingerprint_derived=True,
        level=issue.level,
        permalink=issue.permalink,
        timestamps_are_receipt_time=False,
        first_seen=issue.first_seen,
        last_seen=issue.last_seen,
        occurrences=issue.occurrences,
        # What this fact was built from, and nothing more. The list row's `stats`, `firstRelease`
        # and
        # `subscriptionDetails` are presentation and would be stored on every event for ever — the
        # growth `prune` exists to undo.
        raw={
            "source": "tracker-inventory",
            "id": issue.external_id,
            "status": issue.status,
            "permalink": issue.permalink,
        },
    )
