"""What one attempt cost: tokens off the wire, money if the operator says what they pay, and time.

Item 133. Three facts about one attempt, in one module, because they are read together and mean
little apart — a duration next to a spend of nothing is a hung attempt, and a spend without a
duration cannot be judged at all.

**No price table ships, ever.** DR-0004 says this repository integrates no provider and privileges
none; a bundled price list privileges every provider on it, goes stale the first time anybody
repriced, and would make an instance print a *wrong* cost — which is worse than printing tokens and
letting its operator multiply. So the four prices are settings, and money simply does not appear
until they are set.

**Nothing here sums the four counts into one number.** They are billed at rates that differ by an
order of magnitude — cached reads cheapest, cache writes dearest — so one total would be a number
that is wrong on every provider rather than a simplification.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hullwork.config import Settings
    from hullwork.models import Attempt

#: Prices are quoted per million tokens by every provider anybody has asked about, so that is the
#: unit the settings take. Named because two places divide by it.
PER = 1_000_000

#: The four counts, in the order they are reported and priced. The names are the seal's keys.
COUNTS = ("input_tokens", "output_tokens", "cache_write_tokens", "cache_read_tokens")


@dataclass(frozen=True)
class Tokens:
    """What the wire reported, per billing category. `None` means **not reported**, never zero.

    That distinction is the whole of item 133 and it is load-bearing twice over: a provider that
    does not cache and a seal written before this item both leave the cache counts unset, and
    reading either as `0` produces a cost that is confidently too low.
    """

    input: int | None = None
    output: int | None = None
    cache_write: int | None = None
    cache_read: int | None = None

    @property
    def context_served(self) -> int | None:
        """Everything the model was given, which is what `input_tokens` alone is not.

        `None` when nothing at all was reported. Otherwise the sum of what was — a partial sum is
        still the best available answer to "how much context", and the fields it is missing are the
        ones the provider never disclosed.
        """
        parts = [value for value in (self.input, self.cache_write, self.cache_read)
                 if value is not None]
        return sum(parts) if parts else None

    @property
    def reported(self) -> bool:
        """Whether the wire said anything at all about this attempt."""
        return any(value is not None for value in
                   (self.input, self.output, self.cache_write, self.cache_read))

    @property
    def any_traffic(self) -> bool:
        """Whether a model actually answered. **Not the same as `reported`.**

        Found on the live instance, which is the only place it could be found: an attempt that never
        reached a model still stores a seal, with `input_tokens: 0` and `responses: 0`. That is a
        measurement — of nothing — so `reported` is `True` for it, and a summary built on `reported`
        announced *"19 attempts with model traffic on the wire"* about an instance where eleven had
        any. The zeros are honest; the label was not.
        """
        return any(bool(value) for value in
                   (self.input, self.output, self.cache_write, self.cache_read))

    @property
    def caching_unreported(self) -> bool:
        """Whether this attempt has token counts but no cache counts.

        Which is what every seal stored before item 133 looks like, and what a provider without
        caching looks like. Distinguished from zero so a reader is told rather than misled.
        """
        return self.reported and self.cache_write is None and self.cache_read is None

    @property
    def unreported(self) -> list[str]:
        """Every category this attempt has no count for, by name. Item 148.

        `caching_unreported` above named one pair because that was the only pair that could go
        missing: the seal flattened `input` and `output` to zero with `or 0`, so those two always
        carried a number even when the wire said nothing. With that fixed, *any* of the four can be
        absent — measured against OpenRouter, whose streamed events zero the whole `usage` object —
        and a message mentioning only caching would understate what is missing.
        """
        return [
            label
            for label, value in (
                ("input", self.input),
                ("output", self.output),
                ("cache write", self.cache_write),
                ("cache read", self.cache_read),
            )
            if value is None
        ]


def _ids_of(seal: "Mapping[str, Any] | None") -> list[str]:
    """The provider response ids out of a stored seal, tolerantly. Item 148.

    Absent from every seal written before this item, which is not an error: `[]` is the honest
    answer for an attempt whose provider sent none and for one sealed before anybody looked.
    """
    if not seal:
        return []
    ids = seal.get("response_ids")
    return [value for value in ids if isinstance(value, str)] if isinstance(ids, list) else []


def tokens_of(seal: Mapping[str, Any] | None) -> Tokens:
    """The four counts out of a stored seal. Tolerant by design: an old seal is missing two keys and
    a seal from an abandoned attempt may be absent entirely, and neither is an error."""
    if not seal:
        return Tokens()
    return Tokens(
        input=_count(seal.get("input_tokens")),
        output=_count(seal.get("output_tokens")),
        cache_write=_count(seal.get("cache_write_tokens")),
        cache_read=_count(seal.get("cache_read_tokens")),
    )


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


@dataclass(frozen=True)
class Prices:
    """What the operator says they pay, per million tokens, in their own currency."""

    input: float | None = None
    output: float | None = None
    cache_write: float | None = None
    cache_read: float | None = None
    currency: str = "USD"

    @classmethod
    def from_settings(cls, settings: "Settings") -> "Prices | None":
        """The configured prices, or `None` when the operator has not said anything.

        `None` rather than an object of zeros: zero is a price, and an instance that quietly reports
        every attempt as free would be worse than one that reports no money at all.
        """
        prices = cls(
            input=settings.model_price_input,
            output=settings.model_price_output,
            cache_write=settings.model_price_cache_write,
            cache_read=settings.model_price_cache_read,
            currency=settings.model_price_currency,
        )
        if all(value is None for value in
               (prices.input, prices.output, prices.cache_write, prices.cache_read)):
            return None
        return prices


@dataclass(frozen=True)
class Spend:
    """What an attempt cost in money, and what the figure is missing.

    `partial` is not a footnote. An operator who priced input and output but not cache reads gets a
    number computed from two of the four counts, and a total presented as complete when it is not is
    the same class of defect as the one this item was written to fix.
    """

    amount: float
    currency: str
    #: Counts that had tokens and no price. Empty means the figure is complete.
    unpriced: tuple[str, ...] = ()

    @property
    def partial(self) -> bool:
        return bool(self.unpriced)

    def __str__(self) -> str:
        figure = f"{self.amount:.4f} {self.currency}".rstrip()
        if not self.partial:
            return figure
        return f"{figure} (missing a price for {', '.join(self.unpriced)})"


def cost_of(tokens: Tokens, prices: "Prices | None") -> Spend | None:
    """What those tokens cost at those prices. `None` when there is no answer to give.

    Two reasons for `None`, and neither is zero: no prices configured, and nothing measured. A
    caller prints the tokens either way — the cost is the part that needs somebody's price list.
    """
    if prices is None or not tokens.reported:
        return None
    pairs = (
        ("input_tokens", tokens.input, prices.input),
        ("output_tokens", tokens.output, prices.output),
        ("cache_write_tokens", tokens.cache_write, prices.cache_write),
        ("cache_read_tokens", tokens.cache_read, prices.cache_read),
    )
    amount = 0.0
    unpriced: list[str] = []
    for name, count, price in pairs:
        if not count:
            continue
        if price is None:
            unpriced.append(name)
            continue
        amount += count / PER * price
    return Spend(amount=amount, currency=prices.currency, unpriced=tuple(unpriced))


def elapsed(attempt: "Attempt") -> timedelta | None:
    """Wall clock from start to finish, or `None` while it is still running.

    Wall clock rather than the sum of `AttemptStep.duration_ms`, and the difference is information:
    the gap between them is time spent outside the phases — waiting on a lease, building an image,
    seeding a volume. An attempt whose steps total four minutes and whose clock says four hours is
    the shape of item 097, and summing the steps would hide exactly that.
    """
    if attempt.finished_at is None:
        return None
    return attempt.finished_at - attempt.started_at


def spoken(delta: timedelta | None) -> str:
    """A duration a person reads without converting. `—` when there is none."""
    if delta is None:
        return "—"
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


@dataclass(frozen=True)
class Instance:
    """What attempts have cost on this instance. Item 133, and the shape follows item 119's rule.

    **Two figures, because there are two questions with different answers.** *What has this cost me*
    is the invoice, and rehearsals are on it — they run every gate and call a model, they just
    publish nothing. *What does an attempt cost* is for deciding whether to run another one, and a
    rehearsal is not the thing being decided about. Folding them together answers neither.

    Duration is reported as the median and the slowest, never the mean. On this instance's own
    twenty attempts the slowest is three hours forty-seven minutes of a stopped dispatcher (item
    097) against a median of twelve minutes; a mean would put the answer between them, where nothing
    actually happens.
    """

    #: Attempts with something measured on the wire, rehearsals included. The invoice.
    measured: int = 0
    total: "Tokens | None" = None
    total_cost: "Spend | None" = None
    #: Consuming attempts only — what "an attempt" costs when it is the real thing.
    fair_try: int = 0
    fair_try_cost: "Spend | None" = None
    median_duration: timedelta | None = None
    slowest: timedelta | None = None
    #: Finished attempts where no model ever answered — a seal of zeros, or no seal at all. Why is
    #: `outcomes`' job (a suite already red, infrastructure in the way, a stopped dispatcher); here
    #: they are only kept out of the averages, because a duration with no spend describes no work.
    no_model_answered: int = 0
    #: Measured attempts whose seals predate item 133, or whose provider does not cache. Their
    #: cached context was never recorded, so money computed from them is **too low and cannot be
    #: fixed retroactively** — the tokens were never stored. Counted so the figure says so, instead
    #: of reassuring somebody with the very understatement this item was written to remove.
    caching_unreported: int = 0

    #: Which categories the wire never reported, across every attempt with traffic. Item 148, and
    #: it is a set rather than a count because *which* one is missing changes what the operator can
    #: conclude: an absent cache count understates a bill, an absent input count also makes a token
    #: ceiling unenforceable.
    unreported: list[str] = field(default_factory=list)

    #: How many provider-side response ids the seals hold. Item 148. A count rather than the ids
    #: themselves, because `lines` is prose an operator reads and forty of them is not prose — the
    #: ids travel in `--json`, where something can consume them.
    provider_ids: int = 0


def per_instance(attempts: "Sequence[Attempt]", prices: "Prices | None") -> Instance:
    """Add up what a list of attempts cost. Pure, so a test can hand it four rows."""
    finished = [a for a in attempts if a.finished_at is not None]
    measured = [(a, tokens_of(a.seal)) for a in finished]
    with_wire = [(a, t) for a, t in measured if t.any_traffic]
    fair = [(a, t) for a, t in with_wire if a.consumed]
    durations = sorted(
        (d for d in (elapsed(a) for a, _ in with_wire) if d is not None),
        key=lambda d: d.total_seconds(),
    )
    return Instance(
        measured=len(with_wire),
        total=_added([t for _, t in with_wire]) if with_wire else None,
        total_cost=cost_of(_added([t for _, t in with_wire]), prices) if with_wire else None,
        fair_try=len(fair),
        fair_try_cost=cost_of(_added([t for _, t in fair]), prices) if fair else None,
        median_duration=durations[len(durations) // 2] if durations else None,
        slowest=durations[-1] if durations else None,
        no_model_answered=len(finished) - len(with_wire),
        caching_unreported=sum(1 for _, t in with_wire if t.caching_unreported),
        # Sorted and deduplicated across attempts: the reader wants "input was never counted", not a
        # per-attempt list of the same fact repeated.
        unreported=sorted({label for _, t in with_wire for label in t.unreported}),
        provider_ids=sum(len(_ids_of(a.seal)) for a, _ in with_wire),
    )


def _added(counts: "Sequence[Tokens]") -> Tokens:
    """Sum a list of counts, keeping `None` where **nothing** reported that field."""
    def total(pick: "Callable[[Tokens], int | None]") -> int | None:
        seen = [pick(t) for t in counts if pick(t) is not None]
        return sum(v for v in seen if v is not None) if seen else None

    return Tokens(
        input=total(lambda t: t.input),
        output=total(lambda t: t.output),
        cache_write=total(lambda t: t.cache_write),
        cache_read=total(lambda t: t.cache_read),
    )


def lines(summary: Instance) -> list[str]:
    """The spend in words, for a terminal. Empty when nothing has been measured.

    Silence rather than zeros, for the reason `outcomes.lines` gives: an instance that has measured
    nothing has nothing to say about cost, and a row of `0` reads as free rather than as unmeasured.
    """
    if summary.measured == 0:
        return []
    out = [f"    - {summary.measured} attempt(s) with model traffic on the wire"]
    if summary.total is not None:
        served = summary.total.context_served
        if served is not None:
            out.append(f"      context served: {served:,} tokens")
    if summary.total_cost is not None:
        out.append(f"      total spend: {summary.total_cost}")
        if summary.fair_try_cost is not None and summary.fair_try:
            each = summary.fair_try_cost.amount / summary.fair_try
            out.append(
                f"      of which {summary.fair_try} counted against an item: "
                f"{summary.fair_try_cost} ({each:.4f} {summary.fair_try_cost.currency} each)"
            )
    else:
        out.append(
            "      no prices configured, so no money is reported "
            "(HULLWORK_MODEL_PRICE_INPUT and its three siblings)"
        )
    if summary.caching_unreported:
        # **The figure above is too low by however much was cached, and nothing can recover it.**
        # Said here rather than left for a reader to infer, because the whole of item 133 is that a
        # confident understatement is worse than an admitted gap.
        out.append(
            f"      {summary.caching_unreported} of them recorded no cached context (sealed before "
            f"it was measured, or a provider that does not cache), so any figure above is a floor"
        )
    if summary.provider_ids:
        # **The bridge to an invoice** (item 148). When the wire carries no cost, these are the
        # only way to check one — and saying "ask your provider" with the ids in hand is a different
        # thing from saying nothing, which is what this printed before.
        out.append(
            f"      {summary.provider_ids} provider response id(s) recorded, so a bill can be "
            f"reconciled against these attempts — `hullwork status --json` carries them"
        )
    if summary.unreported:
        # **Says which categories, not only that some are missing** (item 148). Against an endpoint
        # whose stream zeroes `usage` — OpenRouter, measured — the input count is absent too, and
        # a ceiling set in tokens cannot see what was never counted. Naming the categories is what
        # tells an operator whether their ceiling was real or decorative.
        out.append(
            f"      the wire reported no {', no '.join(summary.unreported)} on at least one "
            f"attempt, so a ceiling in tokens could not count it — the floor above is that much "
            f"further below the truth"
        )
    if summary.median_duration is not None:
        out.append(
            f"      median {spoken(summary.median_duration)}, "
            f"slowest {spoken(summary.slowest)}"
        )
    if summary.no_model_answered:
        out.append(
            f"      {summary.no_model_answered} finished attempt(s) never reached a model, so they "
            f"are in none of the above"
        )
    return out
