"""Whether an image exists for the version this tree claims to be. Item 192.

Split from the test that uses it so the rule can be decided with no network at all: every state of a
release is a tuple of three strings, and `behind_the_registry` is a function of them. Only
`published_tags` touches the wire, and only the one test that asks for it calls it.

**This lives in `tests/` on purpose.** `scripts/` is withheld from publication, so a check that
lived there would be absent from the public tree — which is the one that gets pulled, and therefore
the one whose documentation being a release behind actually costs somebody something.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterable

#: The published package. Anonymous pulls are allowed on it, which is what makes this check runnable
#: from any checkout and any CI job without a credential to leak or rotate.
IMAGE = "easybytehub/hullwork"

_TOKEN = f"https://ghcr.io/token?scope=repository:{IMAGE}:pull&service=ghcr.io"
_TAGS = f"https://ghcr.io/v2/{IMAGE}/tags/list"

TIMEOUT_SECONDS = 20


def behind_the_registry(
    version: str, *, surface: str, published: Iterable[str] | None
) -> str | None:
    """The failure, or `None` when there is nothing to report.

    Three lines, and the middle one is the whole reason this is not a tree-local rule:

    * the surface already records this version → nothing to say;
    * **no image is published for this version** → nothing to say either, and this exempts the
      whole window between the bump and the release without a flag anybody has to clear;
    * an image is published for this version and the surface records something else → say so, naming
      the published tag.

    `published=None` is not "no images", it is "could not ask", and it raises. A check that reports
    success when it could not run is worse than no check: `docs/releasing.md` would carry a promise
    with nothing behind it, which is precisely the shape item 192 was opened about.
    """
    if published is None:
        msg = (
            "could not ask ghcr.io which versions are published, so whether this tree documents "
            "the current release is unknown — not confirmed"
        )
        raise LookupError(msg)
    if surface == version:
        return None
    if version not in set(published):
        return None
    return (
        f"ghcr.io/{IMAGE}:{version} is published and docs/published-surface.json was recorded from "
        f"{surface}, so every document here describes the release before this one. Run "
        f"`./scripts/record-the-published-surface.py {version}` and move the pins — "
        f"docs/releasing.md has both, in that order."
    )


def published_tags() -> tuple[str, ...] | None:
    """Every tag on the package, or `None` when the registry could not be asked.

    `None` rather than an exception so a caller can tell *offline* from *nothing published*, which
    are the two answers this must never blur.
    """
    try:
        token = _get(_TOKEN)["token"]
        tags = _get(_TAGS, {"Authorization": f"Bearer {token}"})["tags"]
    except (urllib.error.URLError, TimeoutError, KeyError, ValueError, OSError):
        return None
    if not isinstance(tags, list):
        # A registry answering something else is a registry that was not asked what we think.
        return None
    return tuple(str(tag) for tag in tags)


def _get(url: str, headers: dict[str, str] | None = None) -> dict[str, object]:
    request = urllib.request.Request(url, headers=headers or {})  # noqa: S310 - literal https
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        loaded = json.load(response)
    if not isinstance(loaded, dict):
        msg = f"{url} did not answer with an object"
        raise ValueError(msg)
    return loaded
