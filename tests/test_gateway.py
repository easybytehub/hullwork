"""The gateway that makes provenance an observation instead of a declaration (item 033).

Driven end to end against a fake upstream on a real socket, because every claim here is about what
happens on the wire. Asserting that a parser parses would test the easy half; what matters is that
the credential is added on this side, that the response is passed through unaltered, and that what
the endpoint actually did is recorded whether or not the harness cooperates.
"""

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx2
import pytest

from hullwork.gateway.protocols import (
    AnthropicReader,
    Observation,
    OpenAIReader,
    reader_for,
)
from hullwork.gateway.server import PROBE_PATH, Gateway

SEEN_HEADERS: dict[str, str] = {}


class _Upstream(BaseHTTPRequestHandler):
    """A pretend model endpoint. Records what reached it, answers what it was told to."""

    protocol_version = "HTTP/1.1"
    reply: bytes = b"{}"
    stream: bool = False
    #: What it answers with. A real endpoint refusing a credential is the case item 056 is about,
    #: and this fixture could only ever answer 200 — so the seal's blindness to it was untestable.
    status: int = 200

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        SEEN_HEADERS.clear()
        SEEN_HEADERS.update({k.lower(): v for k, v in self.headers.items()})
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = type(self).reply
        self.send_response(type(self).status)
        if type(self).stream:
            self.send_header("Content-Type", "text/event-stream")
        else:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def upstream() -> Iterator[str]:
    # Cleared per test: a refused request never reaches the upstream, so a leftover from the
    # previous test would make "the credential never got there" pass for the wrong reason.
    SEEN_HEADERS.clear()
    _Upstream.reply = b"{}"
    _Upstream.stream = False
    _Upstream.status = 200
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _post(gateway: Gateway, path: str, body: dict[str, Any] | None = None) -> httpx2.Response:
    return httpx2.post(f"{gateway.base_url}{path}", json=body or {"x": 1}, timeout=10)


def test_the_credential_is_added_here_and_never_in_the_sandbox(upstream: str) -> None:
    """The answer to "which key may live in the container" is none, and this is why it can be."""
    _Upstream.reply = json.dumps({"model": "m", "usage": {}}).encode()
    _Upstream.stream = False

    with Gateway(upstream, "sk-secret") as gw:
        response = _post(gw, "/v1/chat/completions")

    assert response.status_code == 200
    assert SEEN_HEADERS["authorization"] == "Bearer sk-secret"


def test_anthropic_style_auth_when_asked(upstream: str) -> None:
    _Upstream.reply = json.dumps({"model": "m"}).encode()

    with Gateway(upstream, "sk-a", auth_style="x-api-key") as gw:
        _post(gw, "/v1/messages")

    assert SEEN_HEADERS["x-api-key"] == "sk-a"
    assert "authorization" not in SEEN_HEADERS


def test_the_model_that_answered_is_read_off_the_wire(upstream: str) -> None:
    _Upstream.reply = json.dumps(
        {"model": "kimi-k2", "usage": {"prompt_tokens": 11, "completion_tokens": 3}}
    ).encode()

    with Gateway(upstream, "k") as gw:
        _post(gw, "/v1/chat/completions")
        seal = gw.recording.seal()

    assert seal["models_served"] == ["kimi-k2"]
    assert seal["input_tokens"] == 11
    assert seal["output_tokens"] == 3
    assert seal["precision"] == "undisclosed"


def test_a_different_model_answering_is_a_violation(upstream: str) -> None:
    """`allow_fallbacks: false` was a request to the provider. This is a measurement."""
    _Upstream.reply = json.dumps({"model": "cheap-model"}).encode()

    with Gateway(upstream, "k", pinned_model="expensive-model") as gw:
        _post(gw, "/v1/chat/completions")

    assert not gw.recording.clean
    kinds = [v.kind for v in gw.recording.violations]
    assert "model-drift" in kinds
    assert gw.recording.seal()["model_drift"] is True


def test_a_truncated_context_is_a_violation_not_a_note(upstream: str) -> None:
    """DR-0002 calls silent context loss the largest measured drop, and the most invisible."""
    _Upstream.reply = json.dumps(
        {"model": "m", "choices": [{"finish_reason": "length"}]}
    ).encode()

    with Gateway(upstream, "k", pinned_model="m") as gw:
        _post(gw, "/v1/chat/completions")

    assert [v.kind for v in gw.recording.violations] == ["context-truncated"]


def test_a_path_it_cannot_observe_is_refused_not_forwarded(upstream: str) -> None:
    """Forwarding it would look like it works while removing the reason this component exists."""
    with Gateway(upstream, "k") as gw:
        response = _post(gw, "/v1/embeddings")

    assert response.status_code == 501
    assert gw.recording.refused == ["/v1/embeddings"]
    assert not gw.recording.clean
    assert SEEN_HEADERS == {}  # never reached the upstream, so never spent the credential


def test_a_token_count_is_forwarded_and_counted_but_is_not_a_completion(upstream: str) -> None:
    """Item 066, found on the item 065 rehearsal and visible only because 056 renders refusals.

    `/v1/messages/count_tokens` is a real endpoint of the Anthropic protocol and the harness uses it
    to know how much context it has left. The refusal rule was written about *completions*, where
    reading which model answered is the entire point; a token count returns a number, so there is no
    provenance to lose by forwarding it and something real to lose by refusing it.
    """
    _Upstream.reply = json.dumps({"input_tokens": 812}).encode()

    with Gateway(upstream, "k", pinned_model="claude-opus-5") as gw:
        answer = _post(gw, "/v1/messages/count_tokens?beta=true")
        seal = gw.recording.seal()

    # The harness gets its answer, unaltered.
    assert answer.status_code == 200
    assert answer.json() == {"input_tokens": 812}
    # It is not refused, and it is not mistaken for a model call.
    assert seal["refused_paths"] == []
    assert seal["responses"] == 1
    assert seal["completions"] == 0
    assert seal["models_served"] == []


def test_a_token_count_does_not_rescue_an_attempt(upstream: str) -> None:
    """`never_reached_a_model` reads `models_served`, so a run that only counted tokens is still
    correctly treated as never having reached one. Asserted because forwarding a new class of
    request is exactly the change that could have broken it."""
    from hullwork.models import AttemptOutcome
    from hullwork.work import never_reached_a_model

    _Upstream.reply = json.dumps({"input_tokens": 5}).encode()

    with Gateway(upstream, "k") as gw:
        _post(gw, "/v1/messages/count_tokens")

        assert never_reached_a_model(gw.recording, AttemptOutcome.NOT_REPRODUCIBLE) is True


def test_an_unknown_path_is_still_refused(upstream: str) -> None:
    """The rule did not become "forward anything". A known non-completion of a known family is
    forwarded; a path nobody named is still refused, and still recorded as a refusal."""
    with Gateway(upstream, "k") as gw:
        assert _post(gw, "/v1/embeddings").status_code == 501
        assert gw.recording.refused == ["/v1/embeddings"]
        assert SEEN_HEADERS == {}  # it never reached the upstream, so it never spent the credential


def test_the_response_reaches_the_caller_unaltered(upstream: str) -> None:
    """It is a gateway, not an editor. A harness must see exactly what the endpoint said."""
    payload = {"model": "m", "choices": [{"message": {"content": "hello"}}], "id": "abc"}
    _Upstream.reply = json.dumps(payload).encode()

    with Gateway(upstream, "k") as gw:
        response = _post(gw, "/v1/chat/completions")

    assert response.json() == payload


def test_a_streamed_answer_is_observed_too(upstream: str) -> None:
    _Upstream.stream = True
    _Upstream.reply = (
        b'data: {"model":"kimi-k2","choices":[{"delta":{}}]}\n\n'
        b'data: {"model":"kimi-k2","usage":{"prompt_tokens":7,"completion_tokens":2},'
        b'"choices":[{"finish_reason":"stop"}]}\n\n'
        b"data: [DONE]\n\n"
    )

    with Gateway(upstream, "k", pinned_model="kimi-k2") as gw:
        _post(gw, "/v1/chat/completions")
    _Upstream.stream = False

    seal = gw.recording.seal()
    assert seal["models_served"] == ["kimi-k2"]
    assert seal["streamed"] is True
    assert seal["input_tokens"] == 7
    assert gw.recording.clean


def test_two_different_models_across_a_run_is_drift(upstream: str) -> None:
    _Upstream.reply = json.dumps({"model": "a"}).encode()
    with Gateway(upstream, "k") as gw:
        _post(gw, "/v1/chat/completions")
        _Upstream.reply = json.dumps({"model": "b"}).encode()
        _post(gw, "/v1/chat/completions")

    assert gw.recording.models_served == ["a", "b"]
    assert gw.recording.seal()["model_drift"] is True


def test_a_refused_credential_is_ten_answers_and_not_silence(upstream: str) -> None:
    """The seal must tell "nothing answered" from "everything answered 401" (item 056).

    Measured before this: a 401 whose body was JSON was counted, and a 401 whose body was plain
    text — or an HTML 502 from an intermediary — was not recorded at all. So the recording, whose
    whole job is to say what the endpoint did, said the endpoint did nothing, and the sentence it
    produced sent whoever read it looking for a network fault.
    """
    _Upstream.status = 401
    _Upstream.reply = b"Unauthorized"  # deliberately not JSON: the case that used to vanish

    with Gateway(upstream, "expired-token", pinned_model="claude-opus-5") as gw:
        for _ in range(10):
            assert _post(gw, "/v1/messages").status_code == 401
        seal = gw.recording.seal()

    assert seal["responses"] == 10
    assert seal["statuses"] == {"401": 10}
    assert seal["completions"] == 0
    # Unchanged and load-bearing: no model answered, so `never_reached_a_model` still rescues.
    assert seal["models_served"] == []


def test_an_error_body_is_counted_and_never_recorded(upstream: str) -> None:
    """An error body from an endpoint the operator configured is still untrusted text.

    It goes into a pull request. What is recorded is that a response happened and what its status
    was — never what it said.
    """
    _Upstream.status = 429
    _Upstream.reply = json.dumps(
        {"error": {"message": "rate limited: retry after 60s", "type": "rate_limit"}}
    ).encode()

    with Gateway(upstream, "k") as gw:
        _post(gw, "/v1/messages")
        seal = json.dumps(gw.recording.seal())

    assert '"429": 1' in seal
    assert "rate limited" not in seal
    assert "rate_limit" not in seal


def test_a_streamed_answer_reaches_the_journal(upstream: str, tmp_path: Path) -> None:
    """It observed in memory and never wrote the journal, which is the only way out of a container.

    Since item 054 the gateway is a container and the journal is how a recording crosses that
    boundary, so a streamed response — which is what every real harness gets — was invisible to the
    seal no matter when it was read. Found by reading `_forward`, verified here by effect.
    """
    from hullwork.gateway.journal import Journal, read

    _Upstream.stream = True
    _Upstream.reply = (
        b'data: {"model":"kimi-k2","choices":[{"delta":{}}]}\n\n'
        b'data: {"model":"kimi-k2","usage":{"prompt_tokens":7},'
        b'"choices":[{"finish_reason":"stop"}]}'
        b"\n\ndata: [DONE]\n\n"
    )

    with Gateway(upstream, "k", journal=Journal(tmp_path / "j.jsonl")) as gw:
        _post(gw, "/v1/chat/completions")
    _Upstream.stream = False

    replayed = read(tmp_path / "j.jsonl", endpoint=upstream)

    assert replayed.recording.models_served == ["kimi-k2"]
    assert replayed.recording.seal()["statuses"] == {"200": 1}
    assert replayed.recording.seal() == gw.recording.seal()


def test_the_seal_never_carries_the_credential_or_a_body(upstream: str) -> None:
    """It goes into a pull request. Source code and keys do not."""
    _Upstream.reply = json.dumps({"model": "m", "choices": [{"text": "secret source"}]}).encode()

    with Gateway(upstream, "sk-do-not-leak") as gw:
        _post(gw, "/v1/chat/completions", {"prompt": "my private source code"})
        seal = json.dumps(gw.recording.seal())

    assert "sk-do-not-leak" not in seal
    assert "private source code" not in seal
    assert "secret source" not in seal


# --- the readers, on shapes the wire does produce ------------------------------------------


def test_a_truncated_stream_keeps_what_came_before_it() -> None:
    """The last chunk being cut must not throw away every observation before it."""
    reader = OpenAIReader()
    observation = reader.read_stream_line(
        b'data: {"model":"m","usage":{"prompt_tokens":5}}', Observation()
    )
    observation = reader.read_stream_line(b'data: {"mod', observation)

    assert observation.model == "m"
    assert observation.input_tokens == 5


def test_anthropic_streaming_reads_the_message_start() -> None:
    reader = AnthropicReader()
    seen = reader.read_stream_line(
        b'data: {"type":"message_start","message":{"model":"claude-x","usage":'
        b'{"input_tokens":9}}}',
        Observation(),
    )

    assert seen.model == "claude-x"
    assert seen.input_tokens == 9
    assert seen.streamed is True


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/v1/messages", "anthropic"),
        ("/v1/chat/completions", "openai"),
        ("/openai/v1/chat/completions", "openai"),
        ("/v1/embeddings", None),
        ("/", None),
    ],
)
def test_only_known_model_paths_have_a_reader(path: str, expected: str | None) -> None:
    reader = reader_for(path)

    assert (reader.name if reader else None) == expected


@pytest.mark.parametrize(
    "path",
    [
        "/v1/messages?beta=true",
        "/v1/messages?beta=true&foo=1",
        "/v1/chat/completions?api-version=2024",
        "/v1/messages#frag",
    ],
)
def test_a_query_string_does_not_hide_a_model_call(path: str) -> None:
    """Claude Code calls `/v1/messages?beta=true`, and matching the whole target refused it.

    The gateway then did exactly what it promised — refuse what it cannot observe — and was wrong
    about what it could. Every real client eventually adds a parameter.
    """
    assert reader_for(path) is not None


def test_a_compressed_upstream_is_not_forwarded_as_compressed(upstream: str) -> None:
    """The client decompresses on the way in; keeping the header tells the caller to do it again.

    A real harness crashed with `Decompression error: ZlibError` on exactly this, which is a better
    test than any assertion about header sets: the caller here parses the body, so if the framing
    were wrong this would not return JSON at all.
    """
    _Upstream.reply = json.dumps({"model": "m", "usage": {}}).encode()

    with Gateway(upstream, "k") as gw:
        response = _post(gw, "/v1/chat/completions")

    assert "content-encoding" not in {k.lower() for k in response.headers}
    assert response.json()["model"] == "m"
    assert gw.recording.models_served == ["m"]


def test_the_client_s_own_credential_never_reaches_the_upstream(upstream: str) -> None:
    """Two credentials on one request is an ambiguity no upstream has to resolve in our favour.

    The harness sends `x-api-key: <placeholder>` because its client will not start without one, and
    injecting `Authorization` alongside it left both on the wire — the upstream validated the
    placeholder and answered `401 invalid x-api-key`. Found with a temporary probe on the real API.

    It is a containment fix as much as a correctness one: without it, anything inside the sandbox
    could send its own credential upstream through our gateway and we would forward it.
    """
    _Upstream.reply = json.dumps({"model": "m"}).encode()

    with Gateway(upstream, "the-real-one") as gw:
        httpx2.post(
            f"{gw.base_url}/v1/messages",
            json={"x": 1},
            headers={"x-api-key": "placeholder", "anthropic-version": "1999-01-01"},
            timeout=10,
        )

    assert SEEN_HEADERS["authorization"] == "Bearer the-real-one"
    assert "placeholder" not in SEEN_HEADERS.get("x-api-key", "")
    assert SEEN_HEADERS.get("x-api-key") is None
    # And our own version header wins rather than being duplicated by the client's.
    assert SEEN_HEADERS["anthropic-version"] == "2023-06-01"


# --- reachable from the sandbox, and from nowhere else (item 047) --------------------------------


def test_the_sandbox_can_prove_it_reached_the_gateway(upstream: str) -> None:
    """The probe the egress self-test uses, before the model is ever called.

    A GET rather than a POST deliberately: a POST to an unreadable path lands in
    `recording.refused`, and the provenance seal would then report a violation for a check the run
    performed on itself.
    """
    with Gateway(upstream, "sk-x") as gw:
        response = httpx2.get(f"{gw.base_url}{PROBE_PATH}", timeout=10)

        assert response.status_code == 204
        assert gw.recording.refused == []
        assert gw.recording.observations == []


def test_any_other_get_is_refused(upstream: str) -> None:
    """Not a health endpoint. It takes no input and answers about nothing."""
    with Gateway(upstream, "sk-x") as gw:
        assert httpx2.get(f"{gw.base_url}/v1/models", timeout=10).status_code == 405


def test_only_named_callers_may_use_the_gateway(upstream: str) -> None:
    """The control that pays for binding off loopback, tested by effect from a real connection.

    The gateway has to be reachable from the sandbox's network, and it holds a live model
    credential — so binding `0.0.0.0` without this offers a working model endpoint, on the
    operator's key, to every machine on their network. Loopback is the default and the cable's
    address is added by name.
    """
    _Upstream.reply = json.dumps({"model": "m"}).encode()

    with Gateway(upstream, "sk-x") as gw:
        gw.allowed_callers.clear()  # as it looks to a caller that was never named

        assert _post(gw, "/v1/messages").status_code == 403
        assert httpx2.get(f"{gw.base_url}{PROBE_PATH}", timeout=10).status_code == 403
        # A stranger's request is not the agent's, so it stays out of the recording entirely.
        assert gw.recording.refused == []
        assert gw.recording.observations == []
        assert "authorization" not in SEEN_HEADERS

        gw.allow("127.0.0.1")

        assert _post(gw, "/v1/messages").status_code == 200


# --- where a subscription credential actually lives (item 047, measured on macOS) -----------------


def test_a_file_source_is_read_every_time(tmp_path: Path) -> None:
    """Per call, because the token expires in hours and whatever owns it rewrites it."""
    from hullwork.gateway import subscription_credential

    path = tmp_path / "creds.json"
    path.write_text(json.dumps({"claudeAiOauth": {"accessToken": "first"}}), encoding="utf-8")
    read = subscription_credential(str(path))

    assert read() == "first"

    path.write_text(json.dumps({"claudeAiOauth": {"accessToken": "second"}}), encoding="utf-8")

    assert read() == "second"


def test_the_keychain_is_a_named_source_not_a_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """macOS stopped writing the file, and probing sources in order would hide that.

    Measured 2026-07-28: after a fresh `claude` login, `~/.claude/.credentials.json` was 37 days
    stale while the Keychain item had just been rewritten. Reading the file gets an expired token
    and a `401 OAuth access token has expired` that explains nothing — two runs of this milestone
    went into diagnosing it. A silent fallback would have turned that into "sometimes it works".
    """
    import shutil
    import subprocess

    from hullwork.gateway import subscription_credential

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/security")

    def _security(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert argv[1:4] == ["find-generic-password", "-s", "Claude Code-credentials"]
        return subprocess.CompletedProcess(
            argv, 0, stdout=json.dumps({"claudeAiOauth": {"accessToken": "from-keychain"}})
        )

    monkeypatch.setattr(subprocess, "run", _security)

    assert subscription_credential("keychain:Claude Code-credentials")() == "from-keychain"


def test_a_missing_keychain_item_never_prints_the_wrong_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On success stdout *is* the credential, so the failure path must not echo it."""
    import shutil
    import subprocess

    from hullwork.gateway import GatewayError, subscription_credential

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/security")

    def _absent(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 44, stdout="a-secret", stderr="not found")

    monkeypatch.setattr(subprocess, "run", _absent)

    with pytest.raises(GatewayError) as err:
        subscription_credential("keychain:nope")()

    assert "a-secret" not in str(err.value)
    assert "nope" in str(err.value)


# --- what the wire did not say (item 148) --------------------------------------------------------


def test_a_count_the_wire_never_gave_is_null_and_not_zero() -> None:
    """**Item 148, and the fifth `None ≠ 0` of 2026-08-04.**

    `_counted`'s own docstring argues against `or 0` — it "would make a seal claim a measurement it
    never made, and would silently understate a cost" — and `input_tokens` and `output_tokens` were
    summed with `or 0` two lines below it. Measured against OpenRouter, whose streamed events
    carry a zeroed `usage`: the seal said `input_tokens: 0` for an attempt that really consumed
    855 input and 1.2 million cache-read tokens. `0` was a claim; `null` is the truth.
    """
    from hullwork.gateway import Recording
    from hullwork.gateway.protocols import Observation

    silent = Recording(endpoint="https://api.example", pinned_model="m-1")
    silent.observe(Observation(model="m-1", input_tokens=None, output_tokens=12))

    sealed = silent.seal()

    assert sealed["input_tokens"] is None, "the wire said nothing, so neither does the seal"
    assert sealed["output_tokens"] == 12
    assert sealed["cache_read_tokens"] is None


def test_the_seal_names_what_the_ceiling_could_not_see() -> None:
    """A ceiling compared against a sum that treats silence as zero **cannot bind**, and the run
    that found this spent 1.2 million cache-read tokens under a 1,000,000 ceiling without firing.

    That is not fixable by counting harder — the provider never sent the numbers — so the fix is to
    say so. A reader seeing `max_tokens` beside an empty `unmeasured` knows the ceiling was real;
    the same reader seeing three categories named knows it was decorative.
    """
    from hullwork.gateway import Recording
    from hullwork.gateway.protocols import Observation

    silent = Recording(endpoint="https://api.example", pinned_model="m-1", max_tokens=1_000_000)
    silent.observe(Observation(model="m-1", input_tokens=None, output_tokens=12))

    sealed = silent.seal()

    assert sealed["unmeasured"] == ["input_tokens", "cache_write_tokens", "cache_read_tokens"]
    assert "output_tokens" not in sealed["unmeasured"], "that one was reported"
    # And it still does not refuse to run: `unmeasured` is how the gap is told, not a refusal.
    assert not silent.over_budget


def test_nothing_served_is_not_unmeasured() -> None:
    """A refused attempt reported no counts because there was nothing to count.

    Naming four missing categories there would put a warning on every attempt that never reached a
    model, which is the alarm fatigue item 073 spends its argument on.
    """
    from hullwork.gateway import Recording

    nothing = Recording(endpoint="https://api.example", pinned_model="m-1", max_tokens=10)

    assert nothing.seal()["unmeasured"] == []


def test_the_provider_s_own_response_ids_are_kept() -> None:
    """**The only bridge between an attempt and an invoice** (item 148).

    Against an endpoint whose stream zeroes `usage`, the four counts cannot be summed into money —
    so the ids the provider put on its own responses are what makes a bill checkable. Real ones,
    from the attempt on 2026-08-04 that this item came out of.

    Recorded and never resolved: asking what they cost means calling that provider's accounting
    endpoint, and DR-0004 says Hullwork integrates no provider and privileges none. The seal says
    whose they are and stops.
    """
    from hullwork.gateway import Recording
    from hullwork.gateway.protocols import Observation

    seen = Recording(endpoint="https://openrouter.ai/api", pinned_model="m-1")
    real = ("gen-1785852472-aYeXruvccN6WWlOZvcjD", "gen-1785852760-m8LDTENi0SZ0XdgsX4CE")
    for identifier in real:
        seen.observe(Observation(model="m-1", response_id=identifier, output_tokens=1))
    # The same id twice is one response reported twice, not two responses.
    seen.observe(Observation(model="m-1", response_id="gen-1785852472-aYeXruvccN6WWlOZvcjD"))

    sealed = seen.seal()

    assert sealed["response_ids"] == [
        "gen-1785852472-aYeXruvccN6WWlOZvcjD",
        "gen-1785852760-m8LDTENi0SZ0XdgsX4CE",
    ], "in arrival order, deduplicated"


def test_a_provider_that_sends_no_id_leaves_the_list_empty() -> None:
    """A fact about that provider, not a gap here — so `[]` and never a placeholder."""
    from hullwork.gateway import Recording
    from hullwork.gateway.protocols import Observation

    quiet = Recording(endpoint="https://api.example", pinned_model="m-1")
    quiet.observe(Observation(model="m-1", output_tokens=5))

    assert quiet.seal()["response_ids"] == []


def test_an_empty_id_is_not_an_id() -> None:
    """`""` in the seal would read as a measurement and answer nothing."""
    read = AnthropicReader().read_json(
        json.dumps({"id": "", "model": "m-1", "usage": {}}).encode()
    )

    assert read is not None
    assert read.response_id is None


# --- the recording survives the process that made it (item 054) ----------------------------------


def test_a_journal_replays_into_the_same_seal(tmp_path: Path) -> None:
    """The gateway moves into a container, so the recording has to cross that boundary whole."""
    from hullwork.gateway import Recording
    from hullwork.gateway.journal import Journal, read
    from hullwork.gateway.protocols import Observation

    live = Recording(endpoint="https://api.example", pinned_model="m-1")
    journal = Journal(tmp_path / "j.jsonl")
    for seen in (
        Observation(model="m-1", input_tokens=10, output_tokens=2),
        Observation(model="m-1", input_tokens=7, output_tokens=1, streamed=True),
    ):
        live.observe(seen)
        journal.observed(seen)
    live.refused.append("/v1/anything")
    journal.refused("/v1/anything")

    replayed = read(tmp_path / "j.jsonl", endpoint="https://api.example", pinned_model="m-1")

    assert replayed.unreadable == 0
    assert replayed.recording.seal() == live.seal()


def test_violations_are_derived_on_replay_and_not_stored(tmp_path: Path) -> None:
    """`observe` owns the rules that turn an observation into a violation.

    Writing the violations down too would be a second copy of those rules, and two copies of a rule
    are how they start disagreeing. Model drift is the one DR-0002 exists for.
    """
    from hullwork.gateway.journal import Journal, read
    from hullwork.gateway.protocols import Observation

    journal = Journal(tmp_path / "j.jsonl")
    journal.observed(Observation(model="something-else"))

    assert "violation" not in (tmp_path / "j.jsonl").read_text()

    replayed = read(tmp_path / "j.jsonl", endpoint="https://api.example", pinned_model="m-1")

    assert [v.kind for v in replayed.recording.violations] == ["model-drift"]


def test_a_journal_cut_off_mid_line_reports_what_it_dropped(tmp_path: Path) -> None:
    """A killed container leaves a partial line. A partial seal is worse than none *if it pretends
    to be whole*, so the reader says how much it could not read rather than moving on quietly."""
    from hullwork.gateway.journal import Journal, read
    from hullwork.gateway.protocols import Observation

    path = tmp_path / "j.jsonl"
    journal = Journal(path)
    journal.observed(Observation(model="m-1", input_tokens=5))
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"kind": "observation", "obser')

    replayed = read(path, endpoint="https://api.example")

    assert replayed.unreadable == 1
    assert replayed.recording.seal()["responses"] == 1


def test_a_journal_that_cannot_be_written_does_not_kill_the_gateway(tmp_path: Path) -> None:
    """A gateway that dies over its own bookkeeping turns a recoverable attempt into no attempt."""
    from hullwork.gateway.journal import Journal
    from hullwork.gateway.protocols import Observation

    directory = tmp_path / "gone"
    journal = Journal(directory / "j.jsonl")
    directory.rmdir()

    journal.observed(Observation(model="m-1"))  # must not raise
