"""Blanking secrets out of arbitrary structures, in one place.

This logic used to live inside the logging filter, which was the only thing that needed it. Item
036 makes Hullwork a *reader* of the error tracker, and a fetched event is a far more dangerous
object than a log line: it carries frame locals, `sys.argv`, `extra` and request data straight out
of somebody else's process. Copying the filter's three defences into the ingest path would have
left two implementations to drift apart — which is the failure this project has now found three
times (the gate that ran nothing, the lanes that could not match, the reserved subjects nobody
enforced). So there is one scrubber and two callers.

Three defences, because each catches what the others miss:

* **By value** — strings this instance knows are its own credentials. Catches the accidental leak
  of something we hold.
* **By field name** — `token`, `password`, `api_key` and friends. Catches the secret we have never
  seen, when whoever wrote the code at least named the field honestly.
* **By shape** — a DSN, a JWT, an `Authorization: Bearer` header, wherever they appear inside an
  ordinary-looking string. This is the one the other two cannot do, and it is not hypothetical: an
  audit of our own tracker found a **live DSN inside `sys.argv`** on a real event, in a field
  nobody would think to name as sensitive.
"""

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hullwork.config import Settings

REDACTED = "***"

#: Shared with the error-reporting layer: the same names must be blanked wherever they travel.
SENSITIVE_NAME = re.compile(
    r"(token|secret|password|passwd|api[_-]?key|apikey|dsn|authorization|credential|signature)",
    re.IGNORECASE,
)

#: Field names that are **measurements** rather than credentials, exempted by exact match. Item 057.
#:
#: The provenance seal counts tokens, and `input_tokens` contains the substring `token`, so the seal
#: rendered its own numbers as `***` on the one surface an operator watches a run on. The seal is
#: this product's differentiator and two of its fields read as though they were credentials.
#:
#: **Exact names, and only when the value is not a string.** Both halves matter:
#:
#: * *Exact*, because `SENSITIVE_NAME` must stay a substring rule — a field called `forge_token` or
#:   `model_token` is caught before anybody remembers to add it, and that is the property that has
#:   kept credentials out of this project's logs. A pattern-based exemption would be a hole that
#:   grows.
#: * *Not a string*, because this scrubber also walks frame locals and `sys.argv` from somebody
#:   else's process (item 036), where a variable's name is whatever they called it. A count is a
#:   number; a string under one of these names is not the thing this exemption is for, so it is
#:   still blanked.
MEASUREMENTS = frozenset(
    {"input_tokens", "output_tokens", "cache_write_tokens", "cache_read_tokens"}
)

#: The strings this product knows on sight to be credentials, because it put them in a path itself.
#: The webhook's was scrubbed on the way to the error tracker and not on the way to stdout, which
#: Docker writes to disk.
#:
#: **The page's token joined it in item 123**, and it was a real hole rather than a tidy-up: an
#: unhandled error inside a page route sends `request.url` to the error tracker, and item 122 had
#: put a read-everything credential in that URL. The receiver runs with `--no-access-log` for the
#: webhook's sake, which is why the tracker was the only way out — and the only one left open.
#: Anything Hullwork ever puts in a path belongs on this line the same day.
TOKEN_IN_URL = re.compile(r"(/webhooks/[^/\s]+/[^/\s]+/|/page/)[^/\s?#\"']+")

#: `NAME=value` where the name is sensitive. The gap this closes was found by a test in item 027:
#: an environment dump in a test suite's failure output — `TOKEN=gto_…` — was caught by none of the
#: three defences. Not by value, because we had never seen it; not by field name, because that rule
#: only inspects the keys of mappings and this is a line of text; not by shape, because a forge
#: token is just a string.
#:
#: An environment dump is the single most likely way a credential reaches captured output, and
#: captured output is what item 027 publishes into a pull request.
#: Three details that are all corrections of a first draft, and all found by looking at what it did
#: to ordinary text rather than to a secret:
#:
#: * the prefix is `*` and not `+` — with `+` a bare `TOKEN=…` or `api_key: …` matched nothing,
#:   because nothing preceded the keyword, while `HULLWORK_FORGE_TOKEN=` matched. The rule looked
#:   like it worked;
#: * `(?!=)` after the separator, because `assert token_count == 3` was being rewritten to
#:   `token_count=*** 3`. A redactor that corrupts source code in an evidence trail is worse than
#:   one that misses something: the reviewer is now reading a lie about what the test printed;
#: * a value of at least six characters, so `tokens=5` and `count=3` are left alone. A six-character
#:   secret is not one worth protecting at the cost of mangling everything shorter.
ASSIGNED_SECRET = re.compile(
    r"\b([A-Za-z0-9_]*"
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|DSN|CREDENTIAL|PRIVATE_KEY)"
    r"[A-Za-z0-9_]*)\s*[=:](?!=)\s*(\S{6,})",
    re.IGNORECASE,
)

#: Secrets that give themselves away by their form, wherever they are hiding. Deliberately narrow:
#: a pattern that over-matches turns an evidence trail into a wall of asterisks, and an agent
#: cannot reproduce a bug from that either.
SECRET_SHAPE = re.compile(
    r"(?:[a-z][a-z0-9+.-]*://[^:/?#\s]+:)[^@\s]+(?=@)"  # the password half of a URL credential
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?"  # JWT
    r"|(?<=Bearer )[A-Za-z0-9._~+/=-]{16,}"  # Authorization header in free text
    r"|(?<=token )[A-Za-z0-9._~+/=-]{24,}",  # Forgejo-style "token <hex>"
    re.IGNORECASE,
)

#: A fetched event is a tree that arrives from outside. Walking it without a bound turns somebody
#: else's nested payload into our stack overflow.
MAX_DEPTH = 24


def is_secret_name(key: str, value: Any = None) -> bool:  # noqa: ANN401 - payloads are arbitrary
    """Whether a field must be blanked on its name alone.

    One function, two callers — `Scrubber.scrub` and the logging filter — because both used to test
    `SENSITIVE_NAME` themselves, and this project has now found the same defect three times in a row
    from exactly that shape: two copies of one rule agreeing right up until the day one changed.
    """
    if key in MEASUREMENTS and not isinstance(value, str):
        return False
    return bool(SENSITIVE_NAME.search(key))


class Scrubber:
    """Removes secrets from strings, mappings and sequences, leaving the shape intact.

    The shape is left intact on purpose. A fetched stack frame with its `vars` blanked is still a
    stack frame, and the whole point of item 036 is that those frames are what let an agent
    reproduce a bug. Dropping the structure to be safe would buy safety with the feature.
    """

    def __init__(self, secrets: Iterable[str] = (), *, shapes: bool = False) -> None:
        # Longest first, so overlapping secrets do not leave fragments behind.
        self._secrets = sorted({s for s in secrets if s}, key=len, reverse=True)
        self._shapes = shapes

    def add_secret(self, value: str) -> None:
        """Register a value to be blanked wherever it shows up."""
        if value:
            self._secrets = sorted({*self._secrets, value}, key=len, reverse=True)

    def text(self, value: str) -> str:
        """Scrub one string: known values first, then the URL token, then shapes if enabled."""
        for secret in self._secrets:
            value = value.replace(secret, REDACTED)
        value = TOKEN_IN_URL.sub(rf"\1{REDACTED}", value)
        if self._shapes:
            value = ASSIGNED_SECRET.sub(rf"\1={REDACTED}", value)
            value = SECRET_SHAPE.sub(REDACTED, value)
        return value

    def scrub(self, value: Any, _depth: int = 0) -> Any:  # noqa: ANN401 - payloads are arbitrary
        """Scrub a whole structure. Anything deeper than `MAX_DEPTH` is replaced, not followed."""
        if _depth > MAX_DEPTH:
            return REDACTED
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {
                key: REDACTED
                if is_secret_name(str(key), item)
                else self.scrub(item, _depth + 1)
                for key, item in value.items()
            }
        if isinstance(value, list | tuple):
            return type(value)(self.scrub(item, _depth + 1) for item in value)
        return value


def instance_secrets(settings: "Settings") -> list[str]:
    """Every credential **this process** holds, for redaction by exact value.

    Two callers, one list, on purpose: the dispatcher publishing an artefact (item 027) and the
    read-only page rendering that same artefact back (item 123). A second list written for the
    second caller is how the page comes to publish, months later, a token the pull request had
    redacted.

    They do not hold the same credentials and that is by design — the receiver has no code token
    under DR-0009 — so this returns what the caller happens to have rather than what a Hullwork
    has. What it cannot name by value, `Scrubber(shapes=True)` still catches by shape, which is the
    same defence the published artefact has against a credential nobody listed.
    """
    return [
        value.get_secret_value()
        for value in (
            settings.forge_code_token,
            settings.forge_token,
            settings.tracker_token,
            settings.model_key,
        )
        if value is not None
    ]
