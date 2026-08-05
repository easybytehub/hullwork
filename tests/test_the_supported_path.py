"""Which provider can serve this harness, and which credential path is in use. Item 134.

The gap this covers is not a missing feature: it is that **the supported path has never been run**.
Every attempt this repository has measured used a Claude subscription, which the plan promises not
to support, and the promise it does make — any provider with an API key — carries a qualifier nobody
had written down: *that serves the protocol family your harness speaks*.
"""

import pytest
from pydantic import SecretStr

from hullwork import work
from hullwork.config import Settings
from hullwork.doctor import State, model_credential, model_route
from hullwork.engine import REGISTRY
from hullwork.gateway import Recording
from hullwork.gateway.protocols import Observation


def test_a_harness_declares_what_it_speaks() -> None:
    """The property that decides whether an endpoint can serve it at all, and it used to be a
    comment. Three callers need it and none can derive it."""
    assert REGISTRY["claude-code"].protocol == "anthropic"


def test_doctor_names_both_sides_and_the_rule_that_binds_them() -> None:
    """An operator pointing an OpenAI-shaped endpoint at this harness should read why before they
    run anything, not a 404 about a path they never chose."""
    said = model_route(
        Settings(model_endpoint="https://api.openai.com", model_key=SecretStr("k"))
    ).detail

    assert "claude-code" in said and "anthropic" in said
    assert "https://api.openai.com" in said
    assert "does not translate" in said or "not translate" in said


def test_doctor_ranks_no_providers() -> None:
    """**No hostname table.** Whether an endpoint serves a family is a fact about somebody's own
    deployment; a built-in list would privilege providers (DR-0004) and go stale in a quarter."""
    said = model_route(Settings(model_endpoint="https://api.openai.com")).detail.lower()

    for provider in ("kimi", "deepseek", "openrouter", "bedrock", "vertex", "groq", "mistral"):
        assert provider not in said, "the check reports configuration, it does not rank providers"


def test_the_supported_credential_is_named_as_such() -> None:
    supported = model_credential(Settings(model_key=SecretStr("k")))
    ours = model_route(Settings(model_credentials_file="/x/.credentials.json")).detail

    assert supported.state is State.OK and "supported" in supported.detail
    assert "development only" in ours, "ours is the one that has to say what it is"

    # And in the receiver, which holds no model credential by design, it claims nothing about one.
    receiver = model_route(Settings()).detail
    assert "correct for the receiver" in receiver


def test_every_call_refused_is_diagnosed_as_a_protocol_mismatch() -> None:
    """**The failure whose cause was in the recording and never read out.** The gateway refuses what
    it cannot observe, so a mismatched endpoint produces refusals from our own process — and the
    operator was told "the agent never reached a model" about a one-variable fix."""
    recording = Recording(endpoint="https://api.openai.com")
    recording.refused.append("/v1/messages")

    said = work._no_completion_reason(recording)

    assert "/v1/messages" in said
    assert "fixes the protocol" in said
    assert "HULLWORK_MODEL_ENDPOINT" in said


def test_a_run_that_reached_a_model_is_never_called_a_mismatch() -> None:
    """A metadata path refused (item 066's `count_tokens`) alongside real completions is not this,
    and saying so would send somebody to change an endpoint that works."""
    recording = Recording(endpoint="https://api.anthropic.com")
    recording.observe(Observation(model="claude-opus-5", status=200, output_tokens=10))
    recording.refused.append("/v1/messages/count_tokens")

    assert work._protocol_mismatch(recording) is None


def test_nothing_at_all_on_the_wire_keeps_its_own_sentence() -> None:
    """No refusals either: that is a network or a credential, not a protocol."""
    said = work._no_completion_reason(Recording(endpoint="https://api.anthropic.com"))

    assert "nothing was observed on the wire" in said


def test_a_harness_cannot_be_registered_without_saying_what_it_speaks() -> None:
    """**No default**, and the reintroduction is why. With `anthropic` as a default, a harness that
    speaks something else registers in silence and fails as a 404 four layers down — which is the
    failure this field exists to make readable. It is the one question a recipe cannot skip.
    """
    from hullwork.engine import Engine

    with pytest.raises(TypeError, match="protocol"):
        Engine(name="something-new", image="example/harness:1")  # type: ignore[call-arg]
