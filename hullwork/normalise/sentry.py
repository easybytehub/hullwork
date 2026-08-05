"""Sentry's Integration Platform webhook.

Envelope is `{action, installation, data, actor}`; the interesting part is `data.event`, which is
the normalised event plus four keys Sentry adds (`url`, `web_url`, `issue_url`, `issue_id`). Read
from `app_platform_event.py` and `sentry_apps/tasks/sentry_apps.py` on 2026-07-26.

`level` and `fingerprint` reach the payload through a generic dump of event data rather than being
named in the code, so they are likely but not contractual. Both are treated as optional here, and no
test asserts their presence — that would be asserting our guess rather than their behaviour.
"""

from datetime import datetime
from typing import Any

from hullwork.normalise import ErrorFact, NormalisationError, Provider, derive_fingerprint

PROVIDER: Provider = "sentry"


def parse(payload: dict[str, Any], received_at: datetime) -> list[ErrorFact]:
    """Parse one `event_alert` delivery. Returns a list for symmetry with GlitchTip's fan-out."""
    data = payload.get("data")
    if not isinstance(data, dict):
        raise NormalisationError(PROVIDER, "data", "expected an object")

    event = data.get("event")
    if not isinstance(event, dict):
        # `issue.*` resources put the payload under `data.issue` instead. Refuse clearly rather than
        # half-parsing a shape we were not asked to handle.
        detail = "expected an object (is this an issue.* hook?)"
        raise NormalisationError(PROVIDER, "data.event", detail)

    title = event.get("title")
    if not title:
        raise NormalisationError(PROVIDER, "data.event.title")

    external_id = event.get("issue_id")
    provider_fingerprint = event.get("fingerprint")

    # Sentry's own fingerprint is a list when present. Prefer the issue id: it is what its own UI
    # treats as the identity of the problem, and it is a plain string.
    if external_id:
        fingerprint = derive_fingerprint(PROVIDER, str(external_id))
        derived = True
    elif isinstance(provider_fingerprint, list) and provider_fingerprint:
        fingerprint = derive_fingerprint(PROVIDER, *(str(part) for part in provider_fingerprint))
        derived = False
    else:
        fingerprint = derive_fingerprint(PROVIDER, str(title), event.get("culprit"))
        derived = True

    timestamp = _timestamp(event.get("datetime"))

    return [
        ErrorFact(
            provider=PROVIDER,
            project_ref=str(event.get("project", "unknown")),
            title=str(title),
            culprit=event.get("culprit"),
            external_id=str(external_id) if external_id else None,
            fingerprint=fingerprint,
            fingerprint_derived=derived,
            level=event.get("level"),
            permalink=event.get("web_url") or event.get("url"),
            timestamps_are_receipt_time=timestamp is None,
            first_seen=timestamp or received_at,
            last_seen=timestamp or received_at,
            occurrences=None,
            raw=payload,
        )
    ]


def _timestamp(value: object) -> datetime | None:
    """Sentry sends ISO-8601. A malformed one is not worth failing the whole delivery over."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None
