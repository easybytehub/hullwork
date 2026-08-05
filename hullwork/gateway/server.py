"""The gateway process: terminate, inject the credential, observe, forward.

Built on the standard library's threading HTTP server rather than on the FastAPI stack the service
uses, for two reasons. It runs inside a short-lived command that has no event loop of its own, and
it must not gain a dependency that the *service* would then be carrying around for a component it
is forbidden from running (spec M2 §1). Small and boring beats consistent here.
"""

import ipaddress
import logging
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType

import httpx2

from hullwork.gateway import Recording
from hullwork.gateway.journal import Journal
from hullwork.gateway.protocols import Observation, is_metadata, reader_for

log = logging.getLogger(__name__)

#: Bodies can be large and slow. Long enough for a real completion, bounded so a hung upstream
#: cannot outlive the attempt that is waiting on it.
UPSTREAM_TIMEOUT_SECONDS = 300

#: Headers that belong to the hop, not to the message. Forwarding them corrupts the transfer.
#:
#: **`content-encoding` is in here and it is the one that bit.** The upstream compresses, the HTTP
#: client decompresses on the way in, and copying the header along with the decompressed body tells
#: the caller to inflate plain text — which it dutifully tries to do and fails with
#: `Decompression error: ZlibError`. Found by pointing a real harness at this and reading its
#: crash, not by reasoning about headers.
_HOP_BY_HOP = frozenset(
    {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
        "content-encoding",
    }
)

#: Headers the gateway owns absolutely: whatever the client sent is dropped, not merged.
#:
#: This is a correctness fix and a containment one. The harness in the sandbox sends
#: `x-api-key: <placeholder>` because its client refuses to start without something, and injecting
#: `Authorization` **alongside** it left both on the wire — Anthropic validated the placeholder and
#: answered `401 invalid x-api-key`. Two credentials on one request is an ambiguity no upstream has
#: to resolve in our favour.
#:
#: And the containment half: without this, anything inside the sandbox could send **its own**
#: credential upstream through our gateway, and we would forward it. The gateway holds the
#: credential; nothing else gets to supply one.
_GATEWAY_OWNED = frozenset({"authorization", "x-api-key", "api-key", "anthropic-version"})

#: A body bigger than this is not a prompt, it is a mistake or an attack.
MAX_REQUEST_BYTES = 32 * 1024 * 1024

#: The only path this process answers a GET on. Under `/__hullwork__/` so it cannot collide with a
#: real endpoint on any provider's API.
PROBE_PATH = "/__hullwork__/probe"


class _Handler(BaseHTTPRequestHandler):
    """One request. The gateway instance is attached to the server, not to the handler."""

    protocol_version = "HTTP/1.1"

    # The default implementation writes every request line to stderr. The path of a model call is
    # harmless, but this class also sees the bodies, and a logger here is one careless edit away
    # from writing somebody's source code to disk.
    def log_message(self, format: str, *args: object) -> None:
        return

    def _caller_is_allowed(self) -> bool:
        """Whether the peer on this connection may use the gateway at all.

        The gateway holds a live model credential, and the sandbox can only reach it if it is bound
        somewhere other than loopback (`net.py`: on Docker Desktop the bridge address is not the
        host). Binding `0.0.0.0` without this would offer a working model endpoint, on somebody's
        key, to every machine on their network.

        So the addresses allowed are named, one at a time, by the dispatcher — and the default is
        loopback alone, which is what the gateway did before it could be bound anywhere else. A
        source-address check is not proof of identity, and it is not claimed as one: it is the
        control that matches the exposure, and the exposure is one ephemeral port for the length of
        one attempt.
        """
        gateway: Gateway = self.server.gateway  # type: ignore[attr-defined]
        caller = self.client_address[0]
        if caller in gateway.allowed_callers:
            return True
        try:
            address = ipaddress.ip_address(caller)
        except ValueError:  # pragma: no cover - the socket gives an address or nothing
            return False
        return any(address in network for network in gateway.allowed_networks)

    def do_GET(self) -> None:
        """Answer the dispatcher's own reachability probe, and nothing else.

        The sandbox has to be able to prove it can reach the gateway *before* the model is called
        (spec M2 §4.4: a firewall nobody probes is a firewall nobody has), and the alternative was
        probing with a POST — which would land in `recording.refused` and make the provenance seal
        report a violation the run did not commit.

        Deliberately not a health endpoint: it takes no input, returns no body, and records
        nothing, so it cannot become a way to ask this process about itself from inside a sandbox.
        """
        if not self._caller_is_allowed():
            self._respond(403, b'{"error":"hullwork gateway: not an allowed caller"}')
            return
        if self.path == PROBE_PATH:
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._respond(405, b'{"error":"hullwork gateway: model calls are POSTed"}')

    def do_POST(self) -> None:
        gateway: Gateway = self.server.gateway  # type: ignore[attr-defined]
        path = self.path

        if not self._caller_is_allowed():
            # Not recorded as a refusal: `recording.refused` is about what the *agent* asked for,
            # and mixing a stranger's probe into it would put a violation in the provenance seal
            # for something the run never did.
            self._respond(403, b'{"error":"hullwork gateway: not an allowed caller"}')
            return

        reader = reader_for(path)
        metadata = reader is None and is_metadata(path)
        if reader is None and not metadata:
            # Refused, not forwarded. An endpoint we cannot read is unsupported, and passing it
            # through would look like it works while removing the only reason this exists.
            gateway.recording.refused.append(path)
            if gateway.journal is not None:
                gateway.journal.refused(path)
            self._respond(
                501,
                b'{"error":"hullwork gateway: this path is not a model call it knows how to '
                b'observe, so it will not be forwarded"}',
            )
            return

        if gateway.recording.over_budget:
            # **The one refusal that is the operator's own decision** (item 137). Enforced here
            # because this is the only process that sees every response, and it already refuses what
            # it cannot observe — a ceiling read anywhere else is a number checked after the money
            # is gone. The body names the ceiling so the agent's own transcript carries the reason,
            # and `work` reads the same fact off the seal to decide the attempt was not the agent's
            # to lose.
            spent = gateway.recording.spent
            ceiling = gateway.recording.max_tokens
            self._respond(
                429,
                f'{{"error":"hullwork gateway: this attempt has spent {spent} tokens, and its '
                f'ceiling is {ceiling} (HULLWORK_MAX_ATTEMPT_TOKENS). Nothing further will be '
                f'forwarded."}}'.encode(),
            )
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_REQUEST_BYTES:
            self._respond(413, b'{"error":"hullwork gateway: request too large"}')
            return
        body = self.rfile.read(length) if length else b""

        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in _HOP_BY_HOP and name.lower() not in _GATEWAY_OWNED
        }
        # The credential is added here and exists nowhere the sandbox can read it.
        headers.update(gateway.auth_headers())

        try:
            self._forward(gateway, reader, path, headers, body)
        except httpx2.HTTPError as exc:
            log.warning("gateway upstream failed", extra={"error": type(exc).__name__})
            self._respond(502, b'{"error":"hullwork gateway: upstream unreachable"}')

    def _forward(
        self,
        gateway: "Gateway",
        reader: object | None,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        with gateway.client.stream(
            "POST", path, content=body, headers=headers, timeout=UPSTREAM_TIMEOUT_SECONDS
        ) as upstream:
            streaming = "text/event-stream" in upstream.headers.get("content-type", "")

            if reader is None:
                # A known non-completion of a known family (item 066): forwarded, and recorded as a
                # response that carried no model. It shows up in `responses` and never in
                # `completions`, which is exactly what happened — the endpoint answered and no model
                # did. Never streamed, because none of these endpoints stream.
                payload = upstream.read()
                self._headers(upstream.status_code, upstream.headers, len(payload))
                self.wfile.write(payload)
                self._record(gateway, Observation(), upstream)
                return

            if not streaming:
                # Read first, then frame. `Content-Length` is hop-by-hop and therefore stripped
                # from what we copy, so it has to be recomputed — writing a body without it on
                # HTTP/1.1 leaves the caller waiting for an end that never comes.
                payload = upstream.read()
                self._headers(upstream.status_code, upstream.headers, len(payload))
                self.wfile.write(payload)
                # **Every response is counted, parseable or not** (item 056). Measured before this:
                # a 401 with a JSON body was recorded, and a plain-text 401 or an HTML 502 from an
                # intermediary vanished entirely — so the recording, which exists to say what the
                # endpoint did, said the endpoint did nothing. "Nothing answered" and "all of them
                # 401" are different facts about the wire and the seal must tell them apart.
                seen = reader.read_json(payload)  # type: ignore[attr-defined]
                self._record(gateway, seen if seen is not None else Observation(), upstream)
                return

            self._headers(upstream.status_code, upstream.headers, None)
            observation = Observation()
            for raw in upstream.iter_lines():
                line = raw.encode() if isinstance(raw, str) else raw
                observation = reader.read_stream_line(line, observation)  # type: ignore[attr-defined]
                chunk = line + b"\n"
                size = format(len(chunk), "X").encode()
                self.wfile.write(size + b"\r\n" + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            # Through the same call as the non-streaming branch, because this one used to observe in
            # memory and **never write the journal** — and since item 054 the journal is the only
            # way a recording leaves the gateway's container. A streamed answer is what every real
            # harness gets, so the seal was blind to exactly the common case.
            self._record(gateway, observation, upstream)

    @staticmethod
    def _record(gateway: "Gateway", observation: Observation, upstream: object) -> None:
        """One place where a response becomes evidence, in memory and on disk.

        Two copies of this were two chances to forget one of the two sinks, and the streaming branch
        had forgotten the one that survives the container.
        """
        observation.status = int(upstream.status_code)  # type: ignore[attr-defined]
        gateway.recording.observe(observation)
        if gateway.journal is not None:
            gateway.journal.observed(observation)

    def _headers(self, status: int, upstream: object, length: int | None) -> None:
        """Copy the upstream's headers, minus the ones that describe this hop rather than the
        message, and re-frame the body ourselves."""
        self.send_response(status)
        for name, value in upstream.items():  # type: ignore[attr-defined]
            if name.lower() not in _HOP_BY_HOP:
                self.send_header(name, value)
        if length is None:
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Content-Length", str(length))
        self.end_headers()

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Gateway:
    """A running gateway. Use it as a context manager; it stops when the attempt does.

    One per attempt, so the recording cannot mix two runs together and the credential is in memory
    for as long as one attempt takes and no longer.
    """

    def __init__(
        self,
        upstream: str,
        credential: "str | Callable[[], str]",
        *,
        pinned_model: str | None = None,
        allowed_models: tuple[str, ...] = (),
        max_tokens: int | None = None,
        journal: "Journal | None" = None,
        auth_style: str = "bearer",
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.recording = Recording(
            endpoint=upstream,
            pinned_model=pinned_model,
            allowed_models=allowed_models,
            max_tokens=max_tokens,
        )
        # Written down as it happens (item 054). When the gateway runs in a container the recording
        # has to survive the container, and a `docker kill` discards anything still in memory —
        # which is the case where the seal matters most.
        self.journal = journal
        self.client = httpx2.Client(base_url=upstream.rstrip("/"), follow_redirects=False)
        # A callable rather than only a string, and the reason is a measured one. A subscription's
        # access token expires — 5.5 hours when this was checked — and the tool that owns it
        # refreshes it on disk. Holding a copy taken at start-up would work for one afternoon and
        # then fail in a way that reads like a revoked credential. Resolved per request, the
        # gateway always sends whatever was last refreshed, and the refresh stays somebody else's
        # job. An API key is the degenerate case: a callable that returns a constant.
        self._credential = credential if callable(credential) else (lambda: credential)
        self._auth_style = auth_style
        # Loopback only until the dispatcher names the sandbox's cable. The default is the
        # behaviour this had before it could be bound off loopback, so binding `0.0.0.0` opens
        # nothing on its own.
        self.allowed_callers: set[str] = {"127.0.0.1", "::1"}
        #: Whole networks, for the case one address cannot be known in advance (item 054). When the
        #: gateway runs *inside* the attempt's own network, the sandbox is started after it and
        #: Docker assigns the address then — so what can be named beforehand is the network, and
        #: naming it is not a widening: the network is created per attempt and holds exactly the two
        #: containers this dispatcher put on it.
        self.allowed_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._server.gateway = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def auth_headers(self) -> dict[str, str]:
        """The credential, resolved now. Anthropic wants `x-api-key`, everyone else a bearer.

        A subscription token is a bearer, verified against the real API: 200 with the model that
        answered. It is **not** an `x-api-key` — that returns 401 `invalid x-api-key`, which is the
        kind of thing worth writing down because the two look interchangeable and are not.
        """
        secret = self._credential()
        if self._auth_style == "x-api-key":
            return {"x-api-key": secret, "anthropic-version": "2023-06-01"}
        return {"Authorization": f"Bearer {secret}", "anthropic-version": "2023-06-01"}

    def allow(self, address: str) -> None:
        """Let one more source address through — the cable's, and nothing else.

        Called after the cable exists, because its address is not known until Docker assigns it.
        The window between binding and this call is covered by the loopback-only default rather
        than by luck.
        """
        self.allowed_callers.add(address)
        log.info("gateway caller allowed", extra={"address": address})

    def allow_network(self, cidr: str) -> None:
        """Let one whole network through, for the peer whose address is assigned after we start.

        Used when the gateway runs inside the attempt's own `--internal` network. That network is
        created for one attempt and destroyed with it, and the only things on it are this gateway
        and this attempt's sandbox — so the network is a name for "the peer", not a relaxation.
        """
        self.allowed_networks.add(ipaddress.ip_network(cidr, strict=False))
        log.info("gateway caller network allowed", extra={"network": cidr})

    @property
    def port(self) -> int:
        """The port that was actually bound, which is what the cable has to be told."""
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        """What the sandbox is told to talk to. The only address it can reach."""
        address = self._server.server_address
        host = address[0].decode() if isinstance(address[0], bytes) else str(address[0])
        return f"http://{host}:{address[1]}"

    def __enter__(self) -> "Gateway":
        self._thread.start()
        log.info("gateway listening", extra={"endpoint": self.recording.endpoint})
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._server.shutdown()
        self._server.server_close()
        self.client.close()
        self._thread.join(timeout=5)
