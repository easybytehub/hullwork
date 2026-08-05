"""Which commit a reproduction is about, and which one a fix lands on.

Item 039. Spec M2 §5 already applies the right rigour to publishing — "a commit that silently
rebases onto whatever is there now has invalidated the gates that were just run" — and did not
apply it to reproducing. Two different requirements were collapsed into one ref:

* **reproduce-where-it-broke** — the commit production was running when the error fired;
* **fix-where-it-merges** — the tip of the default branch, because you cannot merge onto anything
  else.

They are rarely the same commit. The likely case is also the worst: a bug fixed on the default
branch but not yet deployed keeps reporting from production, the candidate test passes on the
pristine tree, and the item ends `not-reproducible` — terminal, with its one attempt consumed, for
a bug that is entirely real and already fixed. That is not a wrong answer at the margin. It is the
bucket DR-0003 calls the honest headline outcome, filling up with something else.

What the tracker gives us is a *release string*, which may be a commit, may be a package version,
and may be stale. This module's whole job is refusing to pretend it knows which.
"""

import logging
import re
from dataclasses import dataclass
from enum import StrEnum

log = logging.getLogger(__name__)

#: A full or abbreviated git object name. Seven is git's own default abbreviation; below that the
#: chance of matching the wrong object stops being theoretical in a busy repository.
_SHA = re.compile(r"^[0-9a-f]{7,40}$")

#: Release strings that are obviously a version rather than a commit. Not exhaustive and does not
#: need to be: anything that is not sha-shaped is treated as unusable anyway. This exists to give
#: a *better message* in the case we have actually met — Hullwork's own `0.1.0.dev0`.
_VERSION = re.compile(r"^v?\d+\.\d+")


class RefQuality(StrEnum):
    """How much a release string can be trusted to identify code."""

    #: Sha-shaped and present in the repository. Usable as a reproduction ref.
    RESOLVED = "resolved"
    #: Sha-shaped and **not** in the repository. A stale hand-maintained release, most likely.
    UNKNOWN_TO_THE_REPOSITORY = "unknown-to-the-repository"
    #: A version string, not a commit. Cannot identify code at all.
    NOT_A_COMMIT = "not-a-commit"
    #: Nothing was sent.
    ABSENT = "absent"


@dataclass(frozen=True)
class ReproductionRef:
    """The answer to "which tree should this bug be reproduced against?", with its provenance."""

    quality: RefQuality
    #: The commit to reproduce at, or `None` to mean "use the tip and say so".
    sha: str | None
    #: What the tracker actually sent, verbatim, for the evidence trail.
    raw: str | None
    note: str

    @property
    def usable(self) -> bool:
        return self.quality is RefQuality.RESOLVED


def classify(release: str | None, *, exists: bool | None = None) -> ReproductionRef:
    """Decide what a release string is worth.

    `exists` is the forge's answer to "is this a commit in the repository?" — `None` when nobody
    asked. A sha we could not check is **not** treated as resolved: acting on an unverified ref is
    how a reproduction ends up running against a tree that never existed here.

    A stale release is worse than a missing one, and that is the asymmetry driving every branch
    below. A missing release makes us fall back to the tip and *say so*. A stale one points the
    reproduction confidently at the wrong tree, and everything downstream — the red gate, the
    verdict, the evidence trail — is then a well-formed claim about the wrong program.
    """
    if not release or not release.strip():
        return ReproductionRef(
            RefQuality.ABSENT,
            None,
            release,
            "The tracker sent no release, so the deployed commit is unknown. Reproducing against "
            "the default branch, which may not be what was running.",
        )

    value = release.strip()
    if not _SHA.match(value):
        detail = (
            "a version string rather than a commit"
            if _VERSION.match(value)
            else "not shaped like a git object name"
        )
        return ReproductionRef(
            RefQuality.NOT_A_COMMIT,
            None,
            value,
            f"The release {value!r} is {detail}, so it cannot identify the code that ran. "
            f"Reproducing against the default branch, which may not be what was running.",
        )

    if exists is False:
        return ReproductionRef(
            RefQuality.UNKNOWN_TO_THE_REPOSITORY,
            None,
            value,
            f"The release {value!r} looks like a commit but is not in this repository. That "
            f"usually means the release is maintained by hand and has gone stale. Reproducing "
            f"against the default branch, and **not** substituting a guess.",
        )

    if exists is None:
        return ReproductionRef(
            RefQuality.UNKNOWN_TO_THE_REPOSITORY,
            None,
            value,
            f"The release {value!r} is sha-shaped but nothing confirmed it exists here, so it is "
            f"not being used. An unverified ref is how a reproduction ends up running against a "
            f"tree that never existed in this repository.",
        )

    return ReproductionRef(
        RefQuality.RESOLVED,
        value,
        value,
        f"Reproducing at {value}, the commit production was running.",
    )


def verdict_for(reproduces_at_release: bool, reproduces_at_tip: bool) -> str:
    """Name what two gate runs mean together. Returns an `AttemptOutcome` value.

    Only reached when the release resolved; otherwise there is one tree and one answer.

    The interesting cell is the top right, and it is the reason this item exists: the bug is real
    at the commit that was running and absent from the tip, which is *already fixed and not yet
    deployed* — a fact about the deployment, not about the bug and not about the agent.
    """
    if reproduces_at_tip:
        # Present at the tip: the ordinary case, and the fix is worth attempting.
        return "reproduced"
    if reproduces_at_release:
        return "already-fixed"
    return "not-reproducible"
