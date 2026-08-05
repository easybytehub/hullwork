"""Normalisation, tested against the payloads the providers actually send.

The fixtures were built from the providers' source, not their documentation — GlitchTip does not
document its outbound webhook at all.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from hullwork.normalise import NormalisationError, derive_fingerprint
from hullwork.normalise import glitchtip as gt
from hullwork.normalise import sentry as sy

FIXTURES = Path(__file__).parent / "fixtures"
RECEIVED_AT = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)


def _load(name: str) -> dict[str, Any]:
    with (FIXTURES / name).open(encoding="utf-8") as handle:
        payload: dict[str, Any] = json.load(handle)
    return payload


# --- GlitchTip ---------------------------------------------------------------------------------


def test_glitchtip_single_error() -> None:
    [fact] = gt.parse(_load("webhook-glitchtip-single.json"), RECEIVED_AT)

    assert fact.provider == "glitchtip"
    assert fact.title.startswith("TypeError")
    assert fact.culprit == "app.views.checkout in process_payment"
    assert fact.project_ref == "demo"
    assert fact.level == "error"
    assert fact.external_id == "4821"


def test_glitchtip_fans_one_delivery_out_into_several_errors() -> None:
    # One POST, three distinct problems. Treating it as one event silently loses two.
    facts = gt.parse(_load("webhook-glitchtip-multi.json"), RECEIVED_AT)

    assert len(facts) == 3
    assert [f.external_id for f in facts] == ["4821", "4822", "4823"]
    assert len({f.fingerprint for f in facts}) == 3


def test_glitchtip_an_absent_colour_does_not_become_an_error() -> None:
    # No colour means a level below WARNING. Defaulting to "error" is how a debug line pages
    # someone at 3am.
    [fact] = gt.parse(_load("webhook-glitchtip-sparse.json"), RECEIVED_AT)

    assert fact.level is None
    assert fact.culprit is None


def test_glitchtip_timestamps_are_flagged_as_receipt_time() -> None:
    # GlitchTip sends none, so ours is all there is — and that must be visible, not implied.
    [fact] = gt.parse(_load("webhook-glitchtip-single.json"), RECEIVED_AT)

    assert fact.timestamps_are_receipt_time is True
    assert fact.first_seen == RECEIVED_AT


def test_glitchtip_fingerprint_is_always_marked_derived() -> None:
    # It never sends one, so claiming otherwise would misrepresent our confidence in the identity.
    [fact] = gt.parse(_load("webhook-glitchtip-single.json"), RECEIVED_AT)

    assert fact.fingerprint_derived is True


def test_glitchtip_the_same_issue_twice_has_the_same_fingerprint() -> None:
    payload = _load("webhook-glitchtip-single.json")
    [first] = gt.parse(payload, RECEIVED_AT)
    [second] = gt.parse(payload, datetime(2026, 7, 27, 9, 0, tzinfo=UTC))

    # If the fingerprint moved with time, every occurrence would look like a new problem.
    assert first.fingerprint == second.fingerprint


def test_glitchtip_a_url_without_an_issue_id_still_parses() -> None:
    payload = {
        "attachments": [{"title": "Something broke", "title_link": "https://example.com/whatever"}]
    }

    [fact] = gt.parse(payload, RECEIVED_AT)

    assert fact.external_id is None  # never guessed
    assert fact.fingerprint  # but still identifiable


def test_glitchtip_rejects_a_payload_with_no_attachments() -> None:
    with pytest.raises(NormalisationError) as caught:
        gt.parse({"text": "GlitchTip Alert"}, RECEIVED_AT)

    assert "attachments" in str(caught.value)


def test_glitchtip_names_the_missing_field() -> None:
    with pytest.raises(NormalisationError) as caught:
        gt.parse({"attachments": [{"title": "x"}]}, RECEIVED_AT)

    assert "title_link" in str(caught.value)


# --- Sentry ------------------------------------------------------------------------------------


def test_sentry_event_alert() -> None:
    [fact] = sy.parse(_load("webhook-sentry-event-alert.json"), RECEIVED_AT)

    assert fact.provider == "sentry"
    assert fact.title.startswith("TypeError")
    assert fact.external_id == "5512334"
    assert fact.permalink is not None
    assert "issues/5512334" in fact.permalink
    # project is a numeric id here, where GlitchTip gives a name — hence never a shared lookup.
    assert fact.project_ref == "4507123"


def test_sentry_uses_its_own_timestamp_when_it_sends_one() -> None:
    [fact] = sy.parse(_load("webhook-sentry-event-alert.json"), RECEIVED_AT)

    assert fact.timestamps_are_receipt_time is False
    assert fact.first_seen is not None
    assert fact.first_seen.year == 2026


def test_sentry_refuses_an_issue_shaped_payload_clearly() -> None:
    # `issue.*` hooks put things under data.issue. Better a clear refusal than a half-parse.
    with pytest.raises(NormalisationError) as caught:
        sy.parse({"action": "created", "data": {"issue": {"title": "x"}}}, RECEIVED_AT)

    assert "data.event" in str(caught.value)


def test_sentry_survives_a_malformed_timestamp() -> None:
    payload = {"data": {"event": {"title": "boom", "issue_id": "1", "datetime": "not a date"}}}

    [fact] = sy.parse(payload, RECEIVED_AT)

    # One bad field must not lose the whole delivery; it degrades to receipt time.
    assert fact.timestamps_are_receipt_time is True
    assert fact.first_seen == RECEIVED_AT


def test_sentry_works_without_level_or_fingerprint() -> None:
    # Neither is guaranteed by Sentry's code: they arrive via a generic data dump.
    payload = {"data": {"event": {"title": "boom", "issue_id": "77"}}}

    [fact] = sy.parse(payload, RECEIVED_AT)

    assert fact.level is None
    assert fact.external_id == "77"


# --- shared ------------------------------------------------------------------------------------


def test_the_same_identity_under_different_providers_is_not_the_same_fingerprint() -> None:
    # Two trackers can both call an issue "4821"; they are not the same problem.
    assert derive_fingerprint("glitchtip", "4821") != derive_fingerprint("sentry", "4821")
