"""Reading which model actually answered, out of the response body.

DR-0004 moved the provenance seal here from the harness's own event stream, and the move is the
point rather than a relocation. Parsing Claude Code's output works for exactly one harness and asks
it to vouch for itself; the moment a user brings their own, an observation degrades into a
declaration — and DR-0002 §4 exists because declarations about model identity are worthless.

Two readers cover essentially every endpoint anyone will point at this in 2026, because both
protocol families put the model that answered in the body. Anything else is **refused** rather
than forwarded unobserved: an endpoint we cannot read is unsupported, and pretending otherwise
reintroduces exactly the blindness this component was built to remove.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

log = logging.getLogger(__name__)

#: Endpoints that are model calls. Anything outside this list is not something we know how to
#: observe, so it does not go through.
ANTHROPIC_PATHS = ("/v1/messages",)
OPENAI_PATHS = ("/v1/chat/completions", "/v1/completions", "/v1/responses")

#: Endpoints of a **known** protocol family that are not completions: they answer about a request
#: rather than performing one. Forwarded, and recorded as responses that carried no model. Item 066.
#:
#: The refusal rule — *an endpoint we cannot read is unsupported* — was written about completions,
#: where reading which model answered is the entire point. A token count returns a number: there is
#: no provenance to lose by forwarding it, and something real to lose by refusing it, because the
#: harness uses it to know how much context it has left. Measured on the item 065 rehearsal: two
#: refusals of `/v1/messages/count_tokens?beta=true`, visible only because item 056 made the
#: terminal report render refused paths.
#:
#: **Still a closed list.** An unknown path is still refused; what changed is that a known
#: non-completion is no longer mistaken for an unknown one.
METADATA_PATHS = ("/v1/messages/count_tokens",)


@dataclass
class Observation:
    """What one response actually was. Every field is read, never configured."""

    model: str | None = None
    #: What the endpoint answered with. `None` means "recorded before statuses were", which is what
    #: a journal line written before item 056 looks like on replay — and it is the honest reading.
    #: Defaulting to 200 would invent a successful response for every observation already on disk.
    status: int | None = None
    #: Tokens the endpoint says it was given **and charged full rate for**. Not the context: on
    #: every provider that caches, this excludes whatever came from cache, and a harness that
    #: accumulates context has almost all of it there. Item 133 measured 936 across 31 responses
    #: on a real attempt, which is what this field looks like when read as "context served".
    input_tokens: int | None = None
    output_tokens: int | None = None
    #: The rest of the context, in the two states providers bill differently (item 133). Written to
    #: cache, and read back from it.
    #:
    #: **`None` is not `0`.** A provider that does not report caching, and a journal line written
    #: before this item, both leave these unset — and reporting an unmeasured field as zero is how a
    #: seal starts claiming a measurement it never made (the rule `precision` already follows).
    #: The provider's own id for this response, when it sends one. Item 148.
    #:
    #: **Recorded, never resolved.** Turning an id into money means calling that provider's own
    #: accounting endpoint — `/api/v1/generation` on OpenRouter — and DR-0004 says Hullwork
    #: integrates no provider and privileges none. So the seal keeps what the wire gave it and says
    #: whose it is; reconciling against a bill is the operator's, with the ids in hand.
    #:
    #: It is the only bridge there is. Against an endpoint whose stream zeroes `usage`, these are
    #: what makes an invoice checkable at all, and they cost nothing to keep.
    response_id: str | None = None
    cache_write_tokens: int | None = None
    cache_read_tokens: int | None = None
    #: Neither family discloses quantisation. Recorded as unknown rather than guessed — inventing
    #: it is the exact dishonesty DR-0002 was written against.
    precision: str = "undisclosed"
    #: Why the endpoint says it stopped. `length` here is a silent truncation with a polite name.
    stop_reason: str | None = None
    streamed: bool = False
    raw_keys: tuple[str, ...] = field(default_factory=tuple)


class ProtocolReader(Protocol):
    """How to pull an `Observation` out of one provider family's response."""

    name: str

    def handles(self, path: str) -> bool: ...

    def read_json(self, body: bytes) -> Observation | None: ...

    def read_stream_line(self, line: bytes, so_far: Observation) -> Observation: ...


def _int(value: Any) -> int | None:  # noqa: ANN401 - provider JSON
    return value if isinstance(value, int) else None


def _text(value: Any) -> str | None:  # noqa: ANN401 - provider JSON
    """A string from provider JSON, or `None` for anything else — including an empty one.

    An empty id is not an id, and storing `""` would put a value in the seal that reads as a
    measurement and answers nothing.
    """
    return value if isinstance(value, str) and value else None


def _cached_prompt_tokens(usage: dict[str, Any]) -> int | None:
    """`usage.prompt_tokens_details.cached_tokens`, or `None` when the provider is silent.

    Its own function because the nesting is the trap: `usage.get("cached_tokens")` reads `None`
    forever against a provider that reports the number one level down, and a silent `None` here is
    indistinguishable from "does not cache" — which is exactly the confusion item 133 exists to end.
    """
    details = usage.get("prompt_tokens_details")
    return _int(details.get("cached_tokens")) if isinstance(details, dict) else None


class AnthropicReader:
    """`/v1/messages`.

    The model is top-level on the response, and on `message_start` when streaming.
    """

    name = "anthropic"

    def handles(self, path: str) -> bool:
        return any(path.endswith(p) for p in ANTHROPIC_PATHS)

    def read_json(self, body: bytes) -> Observation | None:
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return None
        if not isinstance(payload, dict):
            return None
        raw_usage = payload.get("usage")
        usage: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
        return Observation(
            model=payload.get("model"),
            response_id=_text(payload.get("id")),
            input_tokens=_int(usage.get("input_tokens")),
            output_tokens=_int(usage.get("output_tokens")),
            # Siblings of `input_tokens` on this provider, and the bulk of the context whenever the
            # harness caches. Item 133.
            cache_write_tokens=_int(usage.get("cache_creation_input_tokens")),
            cache_read_tokens=_int(usage.get("cache_read_input_tokens")),
            stop_reason=payload.get("stop_reason"),
            raw_keys=tuple(sorted(payload)),
        )

    def read_stream_line(self, line: bytes, so_far: Observation) -> Observation:
        event = _sse_payload(line)
        if event is None:
            return so_far
        so_far.streamed = True
        if event.get("type") == "message_start":
            message = event.get("message")
            if isinstance(message, dict):
                so_far.model = message.get("model") or so_far.model
                so_far.response_id = _text(message.get("id")) or so_far.response_id
                usage = message.get("usage")
                if isinstance(usage, dict):
                    so_far.input_tokens = _int(usage.get("input_tokens"))
        if event.get("type") == "message_delta":
            delta = event.get("delta")
            if isinstance(delta, dict):
                so_far.stop_reason = delta.get("stop_reason") or so_far.stop_reason
            usage = event.get("usage")
            if isinstance(usage, dict):
                so_far.output_tokens = _int(usage.get("output_tokens"))
        return so_far


class OpenAIReader:
    """Chat completions and friends. Covers OpenAI, Kimi, DeepSeek, Groq, vLLM, Ollama, and the
    rest of the OpenAI-compatible world, because they all echo `model` on the response."""

    name = "openai"

    def handles(self, path: str) -> bool:
        return any(path.endswith(p) for p in OPENAI_PATHS)

    def read_json(self, body: bytes) -> Observation | None:
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return None
        if not isinstance(payload, dict):
            return None
        raw_usage = payload.get("usage")
        usage: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
        choices = payload.get("choices")
        finish = None
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            finish = choices[0].get("finish_reason")
        return Observation(
            model=payload.get("model"),
            response_id=_text(payload.get("id")),
            input_tokens=_int(usage.get("prompt_tokens")),
            output_tokens=_int(usage.get("completion_tokens")),
            # **This family reports cache reads and not cache writes**, nested under a details
            # object, and `prompt_tokens` here *includes* the cached part rather than excluding it.
            # So the read count is recorded for the price it carries, and no write count is invented
            # (item 133).
            cache_read_tokens=_cached_prompt_tokens(usage),
            stop_reason=finish,
            raw_keys=tuple(sorted(payload)),
        )

    def read_stream_line(self, line: bytes, so_far: Observation) -> Observation:
        event = _sse_payload(line)
        if event is None:
            return so_far
        so_far.streamed = True
        so_far.model = event.get("model") or so_far.model
        so_far.response_id = _text(event.get("id")) or so_far.response_id
        usage = event.get("usage")
        if isinstance(usage, dict):
            so_far.input_tokens = _int(usage.get("prompt_tokens")) or so_far.input_tokens
            so_far.output_tokens = _int(usage.get("completion_tokens")) or so_far.output_tokens
            so_far.cache_read_tokens = _cached_prompt_tokens(usage) or so_far.cache_read_tokens
        choices = event.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            so_far.stop_reason = choices[0].get("finish_reason") or so_far.stop_reason
        return so_far


def _sse_payload(line: bytes) -> dict[str, Any] | None:
    """One `data:` line of a server-sent event stream, or `None` for anything else.

    Deliberately forgiving: comments, blank lines, the `[DONE]` sentinel and a half-written line at
    the end of a truncated stream all mean "nothing to read here", never "the stream is broken".
    Losing the observation because the last chunk was cut would throw away everything before it.
    """
    text = line.strip()
    if not text.startswith(b"data:"):
        return None
    body = text[len(b"data:") :].strip()
    if not body or body == b"[DONE]":
        return None
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


#: Every family this build can observe. Order matters only for overlapping paths, and none overlap.
READERS: tuple[ProtocolReader, ...] = (AnthropicReader(), OpenAIReader())


def is_metadata(path: str) -> bool:
    """Whether this is a known endpoint that answers *about* a request rather than performing one.

    Query string stripped for the same reason `reader_for` strips it: the harness calls
    `/v1/messages/count_tokens?beta=true`, and matching the whole request target refused it once
    already.
    """
    bare = path.split("?", 1)[0].split("#", 1)[0]
    return any(bare.endswith(p) for p in METADATA_PATHS)


def reader_for(path: str) -> ProtocolReader | None:
    """The reader for this path, or `None` — which the gateway turns into a refusal, not a pass.

    **The query string is stripped first**, and that line is here because of a real refusal: Claude
    Code calls `/v1/messages?beta=true`, and matching the whole request target rejected it. The
    gateway then did exactly what it promised — refuse what it cannot observe — and was wrong about
    what it could. Every real client eventually adds a parameter.
    """
    bare = path.split("?", 1)[0].split("#", 1)[0]
    for reader in READERS:
        if reader.handles(bare):
            return reader
    return None
