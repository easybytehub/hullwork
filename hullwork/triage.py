"""Assign a risk lane to an incoming error, from the project's own manifest.

Rule-based, no model. A deterministic lane can be explained, argued with and debugged; a
probabilistic one leaves a human unable to tell a misclassification from a bad day. Where the
answer decides whether an agent may touch production code, that matters more than accuracy does.

**Anything that matches no rule is red**, unless the project has said otherwise for itself
(`autofix.unmatched`, item 072). The instance never decides that: a default that a forgotten project
inherits is a default that has to fail safe, and the safe answer is a human looking at it.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from fnmatch import fnmatch

from hullwork import territory
from hullwork.manifest import ALWAYS_RED, Manifest
from hullwork.models import Item, ItemState, Lane
from hullwork.normalise import ErrorFact
from hullwork.states import LEGAL, can, transition


@dataclass(frozen=True)
class LaneDecision:
    """A lane and the reason for it. The reason is not decoration.

    An operator who cannot see why something was classified red will either override it blindly or
    stop reading the classifications — both worse than the tool not existing.
    """

    lane: Lane
    reason: str
    #: Whether this decision could see **where in the code** the error happened. Item 070.
    #:
    #: Half of `_trustworthy` is the culprit, and a tracker's webhook routinely carries no frames —
    #: 471 characters of title and link, measured. So a lane can be chosen by a rule that was never
    #: shown the half of the error it was written about, and the reason it records ("no lane rule
    #: matched") is true and misleading in the same sentence: no rule *could* have matched.
    #:
    #: Recorded as a fact about the decision rather than inferred later from its wording, because
    #: the alternative is `relane` string-matching on prose it does not own.
    saw_code_location: bool = True


def _everything(title: str, culprit: str | None, paths: Sequence[str]) -> str:
    """Title and code location together. Used only to find reasons to be *more* careful."""
    return "\n".join([title, culprit or "", *paths]).lower()


def _matches(needle: str, haystack: str, paths: Sequence[str]) -> bool:
    """Whether a manifest pattern matches, as a substring or as a glob over one code path.

    **A project never says which kind it wrote, and item 071 refuses to make it.** `billing` and
    `services/billing/**` are both meaningful and mean different things, and a field asking which is
    which is a field somebody fills in wrong. So every pattern is tried as a substring — the rule
    that existed before territory — and one containing `*` is *additionally* tried as a glob against
    each path on its own. Additive on purpose: the pair can only ever match more than the substring
    alone, and for the red lane matching more is the safe error.

    Anchored with an implicit leading `*` unless the author anchored it themselves, because a frame
    arrives as `/app/src/acme_api/services/estimates/projection.py` and nobody writing
    `services/estimates/**` means "only if the repository is mounted at the filesystem root".

    `fnmatch`, so `*` crosses `/`. That makes a pattern broader than a shell glob would be, which is
    the right direction for red and a real edge for green — `docs/hullwork-yml.md` says so out loud
    rather than leaving an author to discover it.
    """
    if needle in haystack:
        return True
    if "*" not in needle:
        return False
    pattern = needle if needle.startswith(("*", "/")) else f"*{needle}"
    return any(fnmatch(path.lower(), pattern) for path in paths)


#: What an exception type looks like: one identifier, no spaces. `ValueError` qualifies;
#: `Order total went negative` does not, and neither does anything a form field could hold.
_EXCEPTION_TYPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def _trustworthy(title: str, culprit: str | None, paths: Sequence[str]) -> str:
    """The parts of an error that the person who triggered it did not get to write.

    Three of them, and the distinction is the whole security of this module:

    * **the exception type** — the `ValueError` in `ValueError: 'docs' is not a valid email`. It
      comes from the raising code, never from input. Everything after the colon is the message,
      which routinely carries whatever somebody typed into a form.
    * **the culprit** — the module and function, derived by the SDK from the stack.
    * **the frame paths** — added by item 071, and they belong here for exactly the same reason. A
      file path is produced by the interpreter walking a stack; there is no form field that puts one
      there. This is what makes territory declarable: `services/billing/**` is a rule about the
      codebase, which a project knows, rather than a prediction about which exceptions it will
      raise, which nobody knows.

    A title with no identifier-shaped prefix (a plain logged message, say) contributes nothing
    here. That is the safe direction: it can still match red, it just cannot earn leniency.
    """
    head, colon, _ = title.partition(":")
    kind = head.strip() if colon and _EXCEPTION_TYPE.match(head.strip()) else ""
    return "\n".join([kind, culprit or "", *paths]).lower()


def _reserved(everything: str, paths: Sequence[str]) -> tuple[str, str] | None:
    """The reserved subject this error touches, if any. Item 041.

    `ALWAYS_RED` has always described itself as the set no manifest may promote out of red, and
    until this function existed it was enforced in exactly one place: a parse-time ban on *listing*
    those words in the green or amber lane. Nothing consulted it at triage time, so a manifest
    saying `green: [typeerror]` sent a `TypeError` in `app.auth.session` — or in
    `billing.payments.charge` — to the lane where an agent acts unattended. Measured against the
    manifest this repository itself ships, which is what made it worth a work item of its own.

    **Substring matching, deliberately, and it over-matches.** `auth` also appears in `authors`, so
    a `KeyError` in a blog's author list now lands red and a human glances at it. The alternative —
    matching on word boundaries — would miss `oauth`, `authz`, `basicauth` and `payments_v2`, and
    the direction of that error is the one that hands an agent a credential path. For a set whose
    entire premise is that a wrong fix here is not a bug but a breach, over-matching is the correct
    failure.

    **Item 071 extended it from subjects to territory.** The frame paths are searched too, so a
    `KeyError` in `app/auth/session.py` is reserved on the strength of where it happened even when
    its title says nothing. Same principle as before — what must not be delegated to a config file
    is not delegated to one — applied to the half of the error that only arrives with the frames.

    The path is returned alongside the subject so the reason can name it. A message saying only
    "'auth' is a reserved subject" against a title with no `auth` in it reads as a malfunction, and
    the operator's next move is to go looking for a word that is not there.
    """
    for subject in sorted(ALWAYS_RED):
        for path in paths:
            if subject in path.lower():
                return subject, path
        if subject in everything:
            return subject, ""
    return None


def choose_lane(manifest: Manifest, fact: ErrorFact) -> LaneDecision:
    """Match a freshly reported error against the manifest's lane patterns.

    No `paths`: a tracker's webhook carries no frames, so at this point there are none to pass. They
    arrive with enrichment, which is what item 070 built the second decision for — and it is why
    territory rules (item 071) are answered by that second decision rather than this one.

    An adapter over `decide`, which takes the texts a lane rule actually reads. Item 070 has to
    decide a lane again later, from an item and a fetched occurrence, where no `ErrorFact` exists —
    and fabricating one to satisfy a signature would mean inventing a provider, a project reference
    and a fingerprint that nothing reads.
    """
    return decide(manifest, title=fact.title, culprit=fact.culprit)


def decide(
    manifest: Manifest, *, title: str, culprit: str | None, paths: Sequence[str] = ()
) -> LaneDecision:
    """Match an error against the manifest's lane patterns, most restrictive first.

    **The reserved set is checked before anything the manifest can say**, and against the whole
    error text rather than only the trustworthy part. Widening the text a rule sees can only move
    an item *towards* red, which is the safe direction and the same asymmetry the two lanes below
    already draw; and a reserved subject that a manifest cannot promote is not one a manifest should
    be able to out-rank either.

    Red is evaluated before amber and amber before green, so overlapping patterns always resolve
    towards caution rather than towards whichever rule happened to be written first.

    **The two lanes are matched against different text, and that asymmetry is the point.** Red —
    the lane that keeps a human involved — is matched against everything, title included, so any
    hint of danger counts. Green and amber — the lanes that eventually let an agent act — are
    matched only against the parts a stranger cannot write — the exception type and the code
    location. The rest of the title is the exception *message*, which routinely carries user
    input: an anonymous user of the *monitored* application who types `docs` into a form field
    could otherwise choose the lane, and in M2 the lane decides whether an agent runs against
    that error and reads that text. Letting an outsider pick that is the authorisation boundary
    handed away.
    """
    everything = _everything(title, culprit, paths)
    trustworthy = _trustworthy(title, culprit, paths)
    lanes = manifest.autofix.lanes
    # Carried on every decision this function returns, not only the ones that go red. A green match
    # on the exception type alone was also made half-blind, and which lanes deserve a second look is
    # a policy that belongs where the policy is, not in this bookkeeping.
    #
    # `culprit or paths`, and item 071 had this wrong at first: the culprit is the SDK's *summary*
    # of a stack and the frames are the stack, so an occurrence with frames and no culprit has told
    # us exactly where the code is. Reading only the culprit left such an item marked as never
    # having seen a code location — re-deciding it on every enrichment pass for the rest of its
    # life. Caught by a test written for the new capability, not by reading the diff.
    saw = bool(culprit or paths)

    reserved = _reserved(everything, paths)
    if reserved is not None:
        subject, where = reserved
        # Worded so an operator can tell this apart from a rule they wrote. A reason saying
        # "matched 'auth' in the red lane" would send somebody to edit a manifest that does not
        # contain that word, and finding nothing there is how a person concludes the tool is lying.
        # Item 071: when it was the code location that matched, the reason names the file, for the
        # same reason — the word may appear nowhere else in the error.
        found = f" in {where}" if where else ""
        return LaneDecision(
            Lane.RED,
            f"'{subject}' is a reserved subject{found} — secrets, credentials, authentication and "
            f"payments are always a human's decision, whatever any manifest says",
            saw_code_location=saw,
        )

    for pattern in lanes.red:
        needle = pattern.strip().lower()
        if needle and _matches(needle, everything, paths):
            return LaneDecision(
                Lane.RED, f"matched '{pattern}' in the red lane", saw_code_location=saw
            )

    # **The instance's own opinion, and it out-ranks a green catalogue on purpose** (M8, item 104).
    # After the manifest's red rules, because a project widening red is agreeing rather than
    # arguing — and *before* amber and green, because `green: [typeerror]` is a prediction about
    # which bugs a project will have (DR-0008's whole finding) and it must not admit a `TypeError`
    # in a schema migration. A project that means it says so in `lanes.ordinary`, which is an
    # argument about territory answered with territory.
    #
    # Reads `paths` and nothing else: a stranger can write an exception message, and cannot write a
    # frame path. That is the asymmetry the two lanes below already draw, and this preserves it for
    # free rather than by remembering to.
    derived = territory.first_sensitive(paths)
    if derived is not None:
        where, rule = derived
        if not any(
            needle and _matches(needle, where.lower(), (where,))
            for needle in (p.strip().lower() for p in lanes.ordinary)
        ):
            return LaneDecision(
                Lane.RED,
                # Named as derived, not as reserved, because the two differ in what an operator may
                # do about it: reserved is absolute, this one they can override. A reason that hides
                # which kind it was leaves them guessing whether the manifest is even consulted.
                f"{where} is {rule.pattern} — {rule.why}; this instance derives that rule rather "
                f"than reading it from a manifest, so `autofix.lanes.ordinary` can override it",
                saw_code_location=saw,
            )

    for lane, patterns in ((Lane.AMBER, lanes.amber), (Lane.GREEN, lanes.green)):
        for pattern in patterns:
            needle = pattern.strip().lower()
            if not needle:
                continue
            if _matches(needle, trustworthy, paths):
                return LaneDecision(
                    lane, f"matched '{pattern}' in the {lane.value} lane", saw_code_location=saw
                )
            if needle in everything:
                # It matched, but only in text the reporter controls. That is not evidence about
                # the code, so it buys no leniency — and saying so out loud is what lets an
                # operator fix a manifest that looked like it was working.
                return LaneDecision(
                    Lane.RED,
                    f"'{pattern}' matched only the error message, which the reporter "
                    f"controls; kept red so a human decides",
                    saw_code_location=saw,
                )

    # Nothing matched. What that means is the project's to say (item 072), and only here — after the
    # reserved check and after every red pattern, so `unmatched: attempt` can never out-rank either.
    if manifest.autofix.unmatched == "attempt":
        return LaneDecision(
            Lane.GREEN,
            "nothing matched, and this project accepts an attempt on anything its rules do not "
            "protect (autofix.unmatched: attempt)",
            saw_code_location=saw,
        )
    return LaneDecision(
        Lane.RED,
        "no lane rule matched; defaulting to red so a human decides",
        saw_code_location=saw,
    )


#: What each lane means for an item once a project has an agent to run.
_DESTINATION: dict[Lane, ItemState] = {
    Lane.GREEN: ItemState.READY,
    Lane.AMBER: ItemState.WAITING_APPROVAL,
    Lane.RED: ItemState.HUMAN_ONLY,
}


def route(item: Item, manifest: Manifest) -> ItemState:
    """Send a freshly triaged item towards an agent, towards a human, or nowhere at all.

    M1 triaged and stopped, which left `ready`, `waiting-approval` and `human-only` declared in
    the state machine and reachable by nothing. This is the missing step, and its condition matters
    more than its mapping.

    **With `agent: none` — the default — nothing moves.** The item stays `triaged` and the M1 path
    is unchanged for every project that only wants triage, which is most of them and all of the
    ones already deployed (DR-0002). A change in the default path is a change to what existing
    users already have, so it is asserted by a test rather than merely intended.

    Red goes to `human-only` rather than staying put, because on a project that *does* have an
    agent the two are different statements: "not classified yet" and "classified, and never for the
    agent". The state machine refuses to move a red item into an agent state anyway — this is the
    expressive half of a rule it already enforces.
    """
    if manifest.autofix.agent == "none":
        return item.state
    return transition(item, _DESTINATION[item.lane]).state


#: The states `route` itself leaves an item in. Anywhere else, something has already happened to the
#: item — an agent ran, a human closed it — and a machine quietly changing its lane underneath that
#: is the failure item 070 guards against. Membership here is not the whole test: `relane`'s caller
#: also requires that no attempt has been spent.
UNTOUCHED = frozenset(
    {ItemState.TRIAGED, ItemState.READY, ItemState.WAITING_APPROVAL, ItemState.HUMAN_ONLY}
)


def relane(
    item: Item, manifest: Manifest, *, culprit: str | None, paths: Sequence[str] = ()
) -> LaneDecision | None:
    """Decide the lane again, now that the code location is known. Item 070, DR-0008 part 1.

    Returns the new decision, or `None` when there was nothing to revisit — either the first one
    already saw the code location, or the item has moved somewhere `route` did not put it.

    **Both decisions end up in `lane_reason`, and the current one comes first.** An operator who saw
    an item go to a human and later finds it queued for an agent needs to read why without diffing
    two log lines; a reason that silently replaced its predecessor is how this system would lose the
    only record of a machine changing its mind about somebody's code.

    The state follows the lane through whatever route the machine allows, and that ordering matters:

    * already where the new lane points — nothing to move;
    * a legal edge to the destination — take it (`ready → human-only`, `waiting-approval → ready`);
    * no direct edge, but `reopened` is reachable — go the way a regression goes, `reopened →
      triaged → destination`. `regression` is **not** set: the bug did not come back, the evidence
      arrived, and `regression` is what declares a regression rather than the state passed through;
    * none of those — `human-only`, because a disagreement between lane and state that the machine
      cannot resolve is exactly the case a human should look at. This is the one hole in the table
      (`ready → waiting-approval`), and sending it to a human is more restrictive than the rule
      asked for, in the direction this module defaults everything else.
    """
    if item.lane_saw_code_location or (not culprit and not paths):
        return None
    if item.state not in UNTOUCHED:
        return None

    # The item's own title, not the fetched occurrence's: the title is what the fingerprint grouped
    # on, and swapping it here would let one late-arriving sample re-word the identity of the item
    # it was fetched for. What arrives new is the culprit, and that is what this reads.
    decision = decide(manifest, title=item.title, culprit=culprit, paths=paths)
    first = item.lane_reason or "(no reason recorded)"
    item.lane = decision.lane
    item.lane_saw_code_location = decision.saw_code_location
    item.lane_reason = (
        f"{decision.reason} — decided again once the code location arrived; "
        f"the first decision, made without it, was: {first}"
    )

    if manifest.autofix.agent != "none":
        item.lane_reason += _follow(item, _DESTINATION[decision.lane])
    return decision


def _follow(item: Item, target: ItemState) -> str:
    """Move the item to where its new lane points, by whatever edge the state machine allows.

    Returns whatever the record should say about the move, which is nothing at all when the state
    simply followed the lane. The caller owns `lane_reason`; this function owns the state.
    """
    if item.state is target:
        return ""
    was = item.state
    if can(item, target):
        transition(item, target)
        return ""
    # The way a regression goes, and for the same reason `resolve` goes that way: `reopened` is a
    # state an item passes through rather than rests in. This is the route out of `human-only`,
    # which is where every item triaged without evidence ends up.
    if can(item, ItemState.REOPENED) and target in LEGAL[ItemState.TRIAGED]:
        transition(item, ItemState.REOPENED)
        transition(item, ItemState.TRIAGED)
        transition(item, target)
        return ""
    if can(item, ItemState.HUMAN_ONLY):
        transition(item, ItemState.HUMAN_ONLY)
        return (
            f" — the state machine has no route from '{was.value}' to '{target.value}', so this "
            f"went to a human instead"
        )
    # Nothing legal, including the fallback. Recorded rather than raised: the lane is already more
    # accurate than it was, and killing an enrichment pass over one state edge would cost every
    # other item on that sweep its context.
    return f" — the state '{was.value}' could not follow the lane to '{target.value}'"
