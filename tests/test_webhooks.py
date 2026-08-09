"""The inbound surface, tested by trying to get past it.

Most of these are attempts to make it do the wrong thing: a tampered token, a body too large, one
nested too deep, a slug that does not exist, the same delivery twice. The happy path is one test;
the rest is the door.
"""

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy.orm import Session

from hullwork.config import get_settings
from hullwork.db import make_engine, make_session_factory
from hullwork.main import app
from hullwork.models import Delivery, Item, Lane, Project
from hullwork.security import generate_token, hash_token
from hullwork.webhooks import MAX_BODY_BYTES, MAX_JSON_DEPTH, json_depth

ROOT = Path(__file__).resolve().parent.parent
SLUG = "sandbox"

MANIFEST = {
    "project": "sandbox",
    "git": {"provider": "forgejo", "repo": "easybyte/hullwork-sandbox"},
    "errors": {"provider": "glitchtip"},
    "autofix": {
        "agent": "none",
        "sandbox": "docker",
        "lanes": {"green": ["typeerror"], "amber": [], "red": ["payment"]},
        "gates": ["tests", "lint", "human-merge"],
    },
    "ci": "none",
    "deploy": "none",
    "notify": {"channel": "none"},
    "tests": None,
    "health_url": None,
}

PAYLOAD = {
    "text": "GlitchTip Alert",
    "attachments": [
        {
            "title": "TypeError: cannot read property 'total' of undefined",
            "title_link": "https://glitchtip.example/easybyte/issues/4821",
            "text": "app.cart in total",
            "color": "#e52b50",
            "fields": [{"title": "Project", "value": "sandbox", "short": True}],
        }
    ],
}


#: **The recorded envelope, not one written for this test** (item 191). It carries its own
#: provenance in a `_comment`: read from Sentry's `app_platform_event.py` on 2026-07-26, and it is
#: the same file `test_normalise` parses. Until this item it had only ever been handed to
#: `sentry.parse` directly — never posted at the door, which is the half that was never measured.
SENTRY_PAYLOAD = json.loads(
    (ROOT / "tests/fixtures/webhook-sentry-event-alert.json").read_text(encoding="utf-8")
)


@pytest.fixture
def token() -> str:
    return generate_token()


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, token: str) -> Iterator[TestClient]:
    url = f"sqlite:///{tmp_path / 'hooks.db'}"
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    get_settings.cache_clear()
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = None
    command.upgrade(cfg, "head")

    with make_session_factory(make_engine(url))() as db:
        db.add(
            Project(
                slug=SLUG,
                forge="forgejo",
                repo="easybyte/hullwork-sandbox",
                webhook_secret_hash=hash_token(token),
                manifest=MANIFEST,
            )
        )
        db.commit()

    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def _session(tmp_path: Path) -> Session:
    return make_session_factory(make_engine(f"sqlite:///{tmp_path / 'hooks.db'}"))()


def _post(
    client: TestClient,
    token: str,
    payload: object = PAYLOAD,
    provider: str = "glitchtip",
) -> Response:
    return client.post(f"/webhooks/{provider}/{SLUG}/{token}", json=payload)


# --- the door --------------------------------------------------------------------------------


def test_a_valid_delivery_is_accepted_and_becomes_an_item(
    client: TestClient, token: str, tmp_path: Path
) -> None:
    response = _post(client, token)

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    with _session(tmp_path) as db:
        assert db.query(Delivery).count() == 1
        item = db.query(Item).one()
        # "typeerror" is green, but the culprit is not in a red area here, so green stands.
        assert item.title.startswith("TypeError")


def test_a_wrong_token_is_rejected_and_stores_nothing(
    client: TestClient, tmp_path: Path
) -> None:
    response = _post(client, generate_token())

    assert response.status_code == 401
    with _session(tmp_path) as db:
        assert db.query(Delivery).count() == 0


def test_an_unknown_project_is_a_404_that_reveals_nothing(client: TestClient, token: str) -> None:
    response = client.post(f"/webhooks/glitchtip/nope/{token}", json=PAYLOAD)

    assert response.status_code == 404
    # No hint about whether the slug or the token was the problem.
    assert "nope" not in response.text


def test_a_disabled_project_stops_accepting(
    client: TestClient, token: str, tmp_path: Path
) -> None:
    with _session(tmp_path) as db:
        db.query(Project).one().active = False
        db.commit()

    assert _post(client, token).status_code == 404


def test_an_unknown_provider_is_refused(client: TestClient, token: str) -> None:
    assert _post(client, token, provider="rollbar").status_code == 404


def test_a_sentry_delivery_with_a_valid_token_becomes_an_item(
    client: TestClient, token: str, tmp_path: Path
) -> None:
    """**The route this refused for wanting a better guarantee** (item 189, operator's choice).

    It answered `501` because verifying Sentry's HMAC means holding its client secret reversibly —
    correct, and it was written as *reversible secret or nothing*. There is a third option:
    **GlitchTip cannot sign at all**, so the token in the URL has been the credential since M1, and
    Sentry gets that same credential verified the same way. The route was declining to offer a
    guarantee better than the one the only working provider gets.
    """
    response = _post(client, token, payload=SENTRY_PAYLOAD, provider="sentry")

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    with _session(tmp_path) as db:
        assert db.query(Delivery).count() == 1
        item = db.query(Item).one()
        assert item.title.startswith("TypeError")
        # **The fields that decide something**, not only the one that displays.
        #
        # This delivery is red, and the interesting part is *why*: the recorded culprit is
        # `app.views.checkout in process_payment`, and this manifest declares `red: ["payment"]`.
        # GlitchTip's fixture describes a different error (`app.cart in total`) and comes out green,
        # so the two are not comparable and both are right.
        #
        # **The lane alone cannot say that**, which is the trap this assertion was nearly written
        # into: red is *also* what an item whose culprit never arrived would get, because anything
        # unclassified defaults to red. So the reason is what is asserted — it names the rule that
        # fired, and a lost culprit would give the default's wording instead.
        assert item.lane is Lane.RED
        assert item.lane_reason and "payment" in item.lane_reason, (
            f"the culprit did not reach triage; the lane defaulted: {item.lane_reason!r}"
        )
        # **Exact, not a substring.** CodeQL flags `"sentry.io" in url` as incomplete URL
        # sanitisation, and as a *security* finding on a test assertion it is false — but the
        # assertion is genuinely weaker than it should be: `https://sentry.io.evil.example/` would
        # satisfy it. That is item 161's real defect, in a test that checks for it.
        assert item.permalink and item.permalink.startswith("https://sentry.io/")


def test_a_wrong_token_looks_the_same_on_both_routes(
    client: TestClient, token: str
) -> None:
    """**Status and body**, because a difference between them confirms a provider by probing.

    Item 122 already established that shape for the page: a wrong token's `404` is byte-identical
    to an unknown path's. The same reasoning applies to two providers on one door — if Sentry's
    refusal read differently from GlitchTip's, the door would answer a question nobody is entitled
    to ask.
    """
    wrong = "b" * 43

    glitchtip = _post(client, wrong)
    sentry = _post(client, wrong, payload=SENTRY_PAYLOAD, provider="sentry")

    assert glitchtip.status_code == sentry.status_code
    assert glitchtip.text == sentry.text


def test_the_signature_header_is_never_read_as_authentication(
    client: TestClient, token: str
) -> None:
    """**(B) is weaker than (C) and must not pretend otherwise.**

    Sentry does sign, and this ignores it: what authenticates is the token in the path. A delivery
    carrying a plainly bogus signature is accepted, because the signature is not what was checked —
    and a reader of this test learns that the HMAC is unverified rather than inferring it from a
    silence.
    """
    response = client.post(
        f"/webhooks/sentry/{SLUG}/{token}",
        json=SENTRY_PAYLOAD,
        headers={"sentry-hook-signature": "0" * 64},
    )

    assert response.status_code == 200


# --- limits ----------------------------------------------------------------------------------


def test_an_oversized_body_is_rejected_whole(client: TestClient, token: str) -> None:
    huge = {"attachments": [{"title": "x" * (MAX_BODY_BYTES + 10), "title_link": "u"}]}

    assert _post(client, token, huge).status_code == 413


def test_a_deeply_nested_body_is_rejected_before_parsing(
    client: TestClient, token: str, tmp_path: Path
) -> None:
    nested: object = "deep"
    for _ in range(MAX_JSON_DEPTH + 5):
        nested = [nested]

    response = _post(client, token, {"attachments": nested})

    assert response.status_code == 413
    with _session(tmp_path) as db:
        assert db.query(Delivery).count() == 0


def test_json_depth_ignores_braces_inside_strings() -> None:
    """Stack traces are full of JSON-looking text. Counting it would reject ordinary payloads."""
    body = json.dumps({"title": "TypeError in {a: {b: {c: 1}}} handler"}).encode()

    assert json_depth(body) == 1


def test_json_depth_handles_escaped_quotes() -> None:
    body = rb'{"a": "he said \" { \" and left"}'

    assert json_depth(body) == 1


def test_a_body_that_is_not_json_is_a_400(client: TestClient, token: str) -> None:
    response = client.post(
        f"/webhooks/glitchtip/{SLUG}/{token}",
        content=b"not json at all",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400


def test_a_json_array_at_the_top_level_is_a_400(client: TestClient, token: str) -> None:
    assert _post(client, token, [1, 2, 3]).status_code == 400


# --- idempotency and fan-out --------------------------------------------------------------------


def test_the_same_delivery_twice_stores_one(
    client: TestClient, token: str, tmp_path: Path
) -> None:
    first = _post(client, token)
    second = _post(client, token)

    assert first.json()["status"] == "accepted"
    assert second.json()["status"] == "duplicate"
    with _session(tmp_path) as db:
        assert db.query(Delivery).count() == 1
        assert db.query(Item).count() == 1


def test_one_delivery_with_three_attachments_makes_three_items(
    client: TestClient, token: str, tmp_path: Path
) -> None:
    payload = {
        "attachments": [
            {"title": f"Error number {n}", "title_link": f"https://g.example/issues/{n}"}
            for n in (1, 2, 3)
        ]
    }

    _post(client, token, payload)

    with _session(tmp_path) as db:
        assert db.query(Item).count() == 3


# --- resumability ------------------------------------------------------------------------------


def test_an_accepted_delivery_survives_a_restart(
    client: TestClient, token: str, tmp_path: Path
) -> None:
    """The promise made by a 200 has to outlive the process that made it.

    Simulated by storing a delivery with nothing processed — exactly the state a crash between the
    response and the work would leave behind — and then starting the app.
    """
    with _session(tmp_path) as db:
        project = db.query(Project).one()
        db.add(
            Delivery(
                project_id=project.id,
                provider="glitchtip",
                provider_delivery_id="orphan",
                payload_hash="orphaned-hash",
                payload_json=json.dumps(PAYLOAD),
            )
        )
        db.commit()
        assert db.query(Item).count() == 0

    with TestClient(app):  # lifespan runs the drain
        pass

    with _session(tmp_path) as db:
        assert db.query(Item).count() == 1
        assert db.query(Delivery).filter(Delivery.processed_at.is_(None)).count() == 0


def test_a_broken_payload_is_recorded_and_does_not_block_the_queue(
    client: TestClient, token: str, tmp_path: Path
) -> None:
    with _session(tmp_path) as db:
        project = db.query(Project).one()
        db.add_all(
            [
                Delivery(
                    project_id=project.id,
                    provider="glitchtip",
                    provider_delivery_id="broken",
                    payload_hash="h1",
                    payload_json=json.dumps({"nothing": "useful"}),
                ),
                Delivery(
                    project_id=project.id,
                    provider="glitchtip",
                    provider_delivery_id="fine",
                    payload_hash="h2",
                    payload_json=json.dumps(PAYLOAD),
                ),
            ]
        )
        db.commit()

    with TestClient(app):
        pass

    with _session(tmp_path) as db:
        broken = db.query(Delivery).filter(Delivery.provider_delivery_id == "broken").one()
        assert broken.error is not None
        # The good one behind it still ran.
        assert db.query(Item).count() == 1
