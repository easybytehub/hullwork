"""Build the configured tracker, or none at all.

Separate from the protocol so core keeps importing an interface, and mirroring
`hullwork.forge.factory` so that "configured" means the same thing on both boundaries.
"""

import logging

from hullwork.config import Settings
from hullwork.tracker import Tracker, TrackerInventory
from hullwork.tracker.glitchtip import GlitchTipTracker

log = logging.getLogger(__name__)


def make_tracker(settings: Settings) -> Tracker | None:
    """The tracker to read events from, or `None` when it has not been configured.

    `None` is a supported state and the default one. Everything M1 does works without it; what a
    missing tracker costs is the context an agent needs to reproduce a bug, which is the whole
    point of item 036 but is not a reason to refuse to run. A project that only wants triage —
    the shipped default under DR-0002 — never needs this credential at all.
    """
    if not settings.tracker_url or not settings.tracker_token:
        return None
    return GlitchTipTracker(
        settings.tracker_url,
        settings.tracker_token.get_secret_value(),
        organisation=settings.tracker_org or "",
    )


def make_inventory(settings: Settings) -> TrackerInventory | None:
    """The tracker seen only as "which issues are there?" — DR-0011, item 080.

    `None` unless `HULLWORK_TRACKER_ORG` is set as well, and that is the whole of the opt-in: the
    list route is addressed by organisation and project, neither of which this instance can discover
    (the least-privilege token is refused `/api/0/organizations/`, measured). An instance that has a
    tracker configured for enrichment and no organisation keeps behaving exactly as it does today.

    Handed over through the narrow protocol for the reason `make_permission_reader` exists: the
    sweep
    asks one question, and an object that can only be asked that question cannot accidentally be
    asked another.
    """
    if not settings.tracker_org:
        return None
    tracker = make_tracker(settings)
    return tracker if isinstance(tracker, TrackerInventory) else None
