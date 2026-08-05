"""Contract of the liveness endpoint — the watchdog and container probes depend on its shape."""

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from hullwork import __version__
from hullwork.config import ConfigError, Settings
from hullwork.main import _refuse_the_credential_this_process_must_not_hold, app

client = TestClient(app)


def test_health_reports_ok_and_version() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_the_service_refuses_the_credential_that_can_push() -> None:
    """Spec M2 §1: two programs, two privilege sets, and this one is the networked half.

    Refused rather than warned about, because a variable that is present and unused looks exactly
    like a boundary that has quietly been removed — and compose files get copied. There is no
    environment in which this process needs the value.
    """
    settings = Settings(forge_code_token=SecretStr("tok_code"))

    with pytest.raises(ConfigError) as caught:
        _refuse_the_credential_this_process_must_not_hold(settings)

    message = str(caught.value)
    assert "HULLWORK_FORGE_CODE_TOKEN" in message
    assert "hullwork work" in message
    # A start-up log that echoes a live credential is what item 015 was spent removing.
    assert "tok_code" not in message


def test_the_ingest_credential_alone_starts_fine() -> None:
    settings = Settings(forge_token=SecretStr("tok_ingest"))

    _refuse_the_credential_this_process_must_not_hold(settings)  # does not raise
