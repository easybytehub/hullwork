"""Turn provider webhook payloads into one internal fact.

Two adapters, one output type. They share nothing on the way in: verified in both providers'
source on 2026-07-26, GlitchTip's Slack-style payload and Sentry's platform envelope have not a
single field name in common. See "Provider reality" in the m1 specification.

Pure functions: no I/O, no database, no clock beyond what the caller passes in.
"""

import hashlib
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

#: Where a fact came from. **Not the same list as the trackers this supports** — `"trace"` is a
#: stack trace a person pasted into `hullwork try` (item 140), which has no webhook, no payload and
#: no adapter. `ingest.normalise("trace", …)` therefore refuses with "no adapter for provider", and
#: that refusal is correct rather than a gap: there is nothing to normalise.
#:
#: Widening this is contained because the field is provenance and nothing routes on it downstream —
#: `Item` does not carry it (`Delivery` does), and `dedup._create` reads only the title, the
#: fingerprint and the lane. A trial that claimed to come from GlitchTip would be a lie told to the
#: one field whose whole job is saying where a thing came from.
Provider = Literal["glitchtip", "sentry", "trace"]


class NormalisationError(Exception):
    """A payload could not be understood. Names the field, because that is what gets acted on."""

    def __init__(self, provider: str, field: str, detail: str = "") -> None:
        self.provider = provider
        self.field = field
        suffix = f": {detail}" if detail else ""
        super().__init__(f"{provider} payload is missing or malformed at '{field}'{suffix}")


class ErrorFact(BaseModel):
    """One distinct error, as this system understands it, whoever reported it."""

    model_config = ConfigDict(extra="forbid")

    provider: Provider

    #: GlitchTip gives a project *name*, Sentry a numeric *id*. Not the same kind of thing, which is
    #: why the provider is always carried alongside it and they never share a lookup.
    project_ref: str

    title: str
    culprit: str | None = None

    #: The provider's own identifier for the issue, when there is one to have.
    external_id: str | None = None

    #: Identity for deduplication. Derived by us whenever the provider gives nothing usable — which
    #: for GlitchTip is always, since it never sends a fingerprint.
    fingerprint: str
    fingerprint_derived: bool

    level: str | None = None
    permalink: str | None = None

    #: True when the timestamps below are simply when *we* received the delivery, because the
    #: provider sent none. Making this visible stops a receipt time being read as an event time.
    timestamps_are_receipt_time: bool
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    #: How many times the provider says this happened. Neither provider reports it reliably today.
    occurrences: int | None = None

    raw: dict[str, Any]


def derive_fingerprint(provider: str, *parts: str | None) -> str:
    """A stable identity built from whatever the payload did give us.

    Deliberately not a hash of the whole payload: those differ on every delivery (timestamps, event
    ids), so every occurrence would look like a brand new problem — the opposite of deduplication.
    """
    material = "\x1f".join([provider, *(part or "" for part in parts)])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
