"""The gateway the sandbox talks to, and the only way out of it.

Item 033, DR-0004. One component doing three jobs that would otherwise be three:

* **Isolation.** It is the only address the sandbox can reach, so a harness that ignores its
  configuration reaches nothing and fails loudly instead of quietly reaching the internet.
* **Provenance.** It terminates the model route rather than tunnelling it, so it can read which
  model actually answered. A CONNECT proxy sees a hostname and then ciphertext; that is enough to
  police *where* traffic goes and blind to *what came back*, which is why the seal used to depend
  on the harness vouching for itself.
* **Enforcement.** DR-0002's anti-degradation rules stop being settings we ask a provider to
  honour and become something observed: a response from a model other than the pinned one, and a
  stop reason that means the context was cut.

**The credential lives here and never in the sandbox.** That is what makes the answer to "which
key may sit in a container that also runs the watched project's test suite" be *none*.

Two rules this module keeps that are easy to lose later:

* **Bodies are never logged.** They are the user's source code and their production data. What is
  recorded is shape — a model name, token counts, a stop reason — and never content.
* **An unreadable protocol is refused, not forwarded.** Passing something through unobserved would
  reintroduce exactly the blindness the component exists to remove, while looking like it works.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

from hullwork.gateway.protocols import Observation


class GatewayError(RuntimeError):
    """The gateway cannot do its job for this request."""


@dataclass
class Violation:
    """Something the endpoint did that DR-0002 says must not pass silently."""

    kind: str
    detail: str


@dataclass
class Recording:
    """Everything the gateway saw during one attempt.

    Held in memory and handed to the dispatcher when the attempt ends: this is short-lived by
    design, one recording per attempt, and it never outlives the process that made it.
    """

    endpoint: str
    pinned_model: str | None = None
    #: Models that may answer, beyond the pinned one. Item 137.
    #:
    #: **Not the same question as `pinned_model`**, which says what to *ask for*: DR-0002 makes
    #: anything else answering a recorded violation, which is right for an instance wanting one
    #: model. It cannot say *"any of these three and nothing else"* — what an operator with a
    #: fallback, or a team with an approved list, needs. Empty keeps DR-0002's rule untouched.
    allowed_models: tuple[str, ...] = ()
    #: What one attempt may spend before the gateway stops forwarding, counting everything the wire
    #: reported. `None` is no ceiling, which is every instance that has ever run.
    max_tokens: int | None = None
    observations: list[Observation] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)
    #: Requests refused before they left the host, by path.
    refused: list[str] = field(default_factory=list)

    def observe(self, observation: Observation) -> None:
        self.observations.append(observation)
        if (
            self.pinned_model
            and observation.model
            and observation.model != self.pinned_model
            and observation.model not in self.allowed_models
        ):
            # The documented failure DR-0002 cites, and the reason `allow_fallbacks: false` was
            # never enough on its own: it is a request to the provider, and this is a measurement.
            self.violations.append(
                Violation(
                    "model-drift",
                    f"asked for {self.pinned_model!r} and {observation.model!r} answered",
                )
            )
        if observation.stop_reason in {"length", "max_tokens"}:
            # A truncation with a polite name. DR-0002 calls silent context loss the largest
            # measured quality drop and the most invisible, so it is a violation and not a note.
            self.violations.append(
                Violation(
                    "context-truncated",
                    f"the endpoint stopped at its limit ({observation.stop_reason}), so the "
                    f"answer is cut and nothing else would have said so",
                )
            )

    def _counted(self, field_name: str) -> int | None:
        """The sum of one optional count, or `None` when **no** response reported it. Item 133.

        The distinction is the point, and it is item 110's rule applied to a number: a provider that
        does not cache, a journal written before this item, and a genuine zero are three different
        facts. Summing `or 0` over all of them reports the third for all three — which would make a
        seal claim a measurement it never made, and would silently understate a cost.
        """
        seen = [getattr(o, field_name) for o in self.observations]
        reported = [value for value in seen if value is not None]
        return sum(reported) if reported else None

    @property
    def spent(self) -> int:
        """Everything the wire reported for this attempt, in tokens. Item 137.

        One number here and four in the seal, deliberately: the seal is evidence and keeps the
        billing categories apart because they are priced apart, while a ceiling is a stop and needs
        a single quantity to compare. Summing for a limit is not the same act as summing for a bill.
        """
        return sum(
            value or 0
            for observation in self.observations
            for value in (
                observation.input_tokens,
                observation.output_tokens,
                observation.cache_write_tokens,
                observation.cache_read_tokens,
            )
        )

    @property
    def response_ids(self) -> list[str]:
        """Every provider-side response id this attempt collected, in the order they arrived.

        Deduplicated by `dict.fromkeys` rather than a set, because the order is part of the
        evidence: reading them back against a provider's log should follow the attempt.

        Empty when the provider sends none, which is a fact about that provider and not a gap here.
        """
        return list(
            dict.fromkeys(
                observation.response_id
                for observation in self.observations
                if observation.response_id
            )
        )

    @property
    def unmeasured(self) -> list[str]:
        """The billing categories **no completion reported**, so the ceiling could not see them.

        Item 148. `spent` sums an unreported count as zero, right for a limit and wrong as a claim —
        so the categories the wire stayed silent about are named instead of inferred from a
        zero. Measured on 2026-08-04: an attempt against OpenRouter spent 1.2 million cache-read
        tokens under a 1,000,000 ceiling without it firing, because none of them were ever counted.
        A ceiling that cannot bind must be visibly unable to, or it reads as a ceiling that did.

        Empty when every category was reported at least once, which is the ordinary case against a
        provider whose stream carries `usage` — and the difference between "the ceiling held" and
        "the ceiling was never in a position to hold" is exactly what this makes readable.
        """
        if not self.completions:
            # Nothing was served, so nothing is missing. A refused attempt is not an unmeasured one.
            return []
        return [
            field_name
            for field_name in (
                "input_tokens",
                "output_tokens",
                "cache_write_tokens",
                "cache_read_tokens",
            )
            if self._counted(field_name) is None
        ]

    @property
    def over_budget(self) -> bool:
        """Whether this attempt has crossed the operator's ceiling.

        Unchanged by item 148 on purpose: a ceiling is a stop and needs one quantity to compare, and
        making it refuse to run against an endpoint that reports nothing would turn a reporting gap
        into a refusal to work. `unmeasured` is how the gap is told instead.
        """
        return self.max_tokens is not None and self.spent >= self.max_tokens

    @property
    def models_served(self) -> list[str]:
        """Every distinct model that answered, in the order first seen."""
        seen: list[str] = []
        for observation in self.observations:
            if observation.model and observation.model not in seen:
                seen.append(observation.model)
        return seen

    @property
    def statuses(self) -> dict[str, int]:
        """How many times the endpoint answered with each status, lowest first.

        The fact `never_reached_a_model` needs to explain itself: *ten answers, all 401* is a
        diagnosis and *the endpoint answered nothing* sends whoever reads it to the network. Keys
        are strings because this goes into a JSON column and integer keys do not survive the trip.

        An observation replayed from a journal written before item 056 has no status, and that is
        recorded as `unknown` rather than guessed — the same rule the seal applies to precision.
        """
        counted: dict[str, int] = {}
        for observation in self.observations:
            key = str(observation.status) if observation.status is not None else "unknown"
            counted[key] = counted.get(key, 0) + 1
        return dict(sorted(counted.items()))

    @property
    def completions(self) -> int:
        """Responses that carried a model, which is the only kind that is an answer from one."""
        return sum(1 for observation in self.observations if observation.model)

    @property
    def clean(self) -> bool:
        return not self.violations and not self.refused

    def seal(self) -> dict[str, object]:
        """The provenance seal for this attempt (DR-0002 §4), built from what was seen.

        `model_requested` is the only configured value in here, and it is present precisely so it
        can be compared with the observed ones rather than stand in for them.
        """
        return {
            "endpoint": self.endpoint,
            "model_requested": self.pinned_model,
            "models_served": self.models_served,
            "model_drift": len(self.models_served) > 1
            or any(v.kind == "model-drift" for v in self.violations),
            "precision": "undisclosed",
            "responses": len(self.observations),
            # What those responses *were*. A seal that cannot tell "nothing answered" from
            # "everything answered 401" is not describing the wire, which DR-0002 §4 makes its one
            # job. `completions` is the subset that carried a model, and the gap between the two is
            # the whole diagnosis when an attempt is rescued (item 056).
            "statuses": self.statuses,
            "completions": self.completions,
            # **Four counts, because they are billed at four rates** (item 133). `input_tokens` is
            # only the input charged at full rate; on a provider that caches — and with a harness
            # that accumulates context, which is every one of them — the bulk of what was served is
            # in the two cache counts, and summing them here would hide a tenfold price difference.
            #
            # **All four through `_counted`, and two of them were not** (item 148). `_counted`'s own
            # docstring argues against `or 0` — it "would make a seal claim a measurement it never
            # made, and would silently understate a cost" — and the two lines above it did exactly
            # that. Measured on 2026-08-04 against OpenRouter, whose streamed events carry a zeroed
            # `usage`: the seal reported `input_tokens: 0` on an attempt that really consumed 855
            # input and 1.2 million cache-read tokens, so `0` was a claim rather than a silence.
            # `None ≠ 0` is item 110's rule and this is the fifth place today it had been flattened.
            "input_tokens": self._counted("input_tokens"),
            "output_tokens": self._counted("output_tokens"),
            "cache_write_tokens": self._counted("cache_write_tokens"),
            "cache_read_tokens": self._counted("cache_read_tokens"),
            # **What the wire never said, named.** The ceiling below is compared against a sum that
            # treats an unreported count as zero — correct for a limit, which needs one quantity —
            # and the consequence is that against an endpoint reporting nothing it cannot bind while
            # real tokens burn. That is not fixable by counting harder; it is fixable by saying so.
            # A reader seeing `max_tokens` beside an empty `unmeasured` knows the ceiling was real.
            "unmeasured": self.unmeasured,
            # **The provider's own ids, so an invoice can be checked** (item 148). Against an
            # endpoint whose stream zeroes `usage` — measured — the counts above cannot be summed
            # into money, and these are the only bridge between this attempt and a bill.
            #
            # Recorded, never resolved: turning an id into a figure means calling that provider's
            # accounting endpoint, and DR-0004 says Hullwork integrates no provider and privileges
            # none. So the seal says whose they are and stops. What the operator does with them is
            # reconciliation, which is their side of the same question.
            "response_ids": self.response_ids,
            "streamed": any(o.streamed for o in self.observations),
            "violations": [{"kind": v.kind, "detail": v.detail} for v in self.violations],
            "refused_paths": list(self.refused),
            # Part of the evidence, not a setting printed for tidiness: an attempt that stopped
            # because of a ceiling looks like an abandoned one, and this is the difference.
            "max_tokens": self.max_tokens,
            "tokens_spent": self.spent,
        }


#: Where a subscription credential can be read from, when it is not a file. Explicit rather than
#: guessed: DR-0002's rule is that there is no silent fallback, and a credential source that is
#: probed in order fails as "expired" when it is really "you configured the wrong one".
KEYCHAIN_PREFIX = "keychain:"


def subscription_payload(source: str) -> "dict[str, object]":
    """The whole credential document, once. **The token is inside it — treat it as a secret.**

    Split out of `subscription_credential` so the doctor can read `claudeAiOauth.expiresAt` without
    a second copy of the two-source logic (item 074). A token that expires in about five hours,
    whose refresh belongs to somebody else's CLI, arrives inside a sandbox as `401 OAuth access
    token has expired` — a message that names neither this file nor the clock. Checking the expiry
    needs the document, not the token.

    Two sources, named explicitly:

    * a **path** to the JSON file, which is what Claude Code writes on Linux;
    * **`keychain:<service>`**, because on macOS it does not. Measured 2026-07-28: after a fresh
      login, `~/.claude/.credentials.json` was **37 days stale** — untouched since June — while the
      Keychain item `Claude Code-credentials` had just been rewritten. Reading the file there gets
      an expired token and a `401 OAuth access token has expired` that says nothing about why,
      which cost this milestone two full runs to diagnose.
    """
    import json
    from pathlib import Path

    if source.startswith(KEYCHAIN_PREFIX):
        raw = _from_keychain(source[len(KEYCHAIN_PREFIX) :])
    else:
        raw = Path(source).read_text(encoding="utf-8")
    loaded = json.loads(raw)
    if not isinstance(loaded, dict):
        msg = f"{source} does not hold a JSON object"
        raise GatewayError(msg)
    return loaded


def _from_keychain(service: str) -> str:
    import shutil
    import subprocess

    binary = shutil.which("security")
    if binary is None:
        msg = "keychain: is macOS only, and `security` is not on PATH"
        raise GatewayError(msg)
    found = subprocess.run(  # noqa: S603 - argv list, no shell, binary resolved above
        [binary, "find-generic-password", "-s", service, "-w"],
        capture_output=True, text=True, check=False, timeout=30, stdin=subprocess.DEVNULL,
    )
    if found.returncode != 0:
        # Never the stdout: on success that *is* the credential, and a failure path that prints
        # the wrong stream once is a failure path that leaks it.
        msg = f"the keychain has no readable item called {service!r}"
        raise GatewayError(msg)
    return found.stdout.strip()


def subscription_credential(source: str) -> "Callable[[], str]":
    """Read a Claude Code subscription's access token, every time it is needed.

    **For testing, and said so plainly.** A product cannot tell its users to mount their Claude
    credentials; this exists because the operator asked for a way to exercise the pipeline at no
    marginal cost, and it is the one that keeps DR-0004 intact — the token stays on the host, in the
    gateway, and never enters a sandbox that also runs the watched project's test suite.

    Read per call rather than cached, because the token expires in hours and whatever owns it
    rewrites it. Caching would work for one afternoon and then fail like a revoked credential.
    """

    def read() -> str:
        payload = subscription_payload(source)
        oauth = payload.get("claudeAiOauth")
        token = oauth.get("accessToken") if isinstance(oauth, dict) else None
        if not token:
            msg = f"{source} has no claudeAiOauth.accessToken"
            raise GatewayError(msg)
        return str(token)

    return read
