"""Build the configured forge, or none at all.

Separate from the protocol module so core keeps importing an interface rather than a constructor,
and separate from the CLI so the receiver and the command agree on what "configured" means.
"""

import logging

from hullwork.config import Settings
from hullwork.forge import Forge, ForgeCode, PermissionReader, kind_of
from hullwork.forge.forgejo import ForgejoCodeForge, ForgejoForge
from hullwork.forge.github import GitHubCodeForge, GitHubForge
from hullwork.forge.gitlab import GitLabCodeForge, GitLabForge

log = logging.getLogger(__name__)


def make_forge(settings: Settings) -> Forge | None:
    """The forge the always-on pipeline talks to, or `None` when it has not been configured.

    Built from `HULLWORK_FORGE_TOKEN`, which needs issue write and content read and **must not be
    able to push**. Anything that changes code is a `ForgeCode` from `make_code_forge` below, on a
    separate credential.

    `None` is a supported state, not a failure: ingest, deduplication and triage all work without a
    forge, and an instance still being set up should keep accepting deliveries rather than reject
    them because it cannot file issues yet. What it must never do is drop them silently — they stay
    unmaterialised in the database and get filed when the credentials arrive.
    """
    if not settings.forge_url or not settings.forge_token:
        return None
    token = settings.forge_token.get_secret_value()
    kind = kind_of(settings.forge_url, settings.forge_kind)
    if kind == "github":
        return GitHubForge(token)
    if kind == "gitlab":
        return GitLabForge(settings.forge_url, token)
    return ForgejoForge(settings.forge_url, token)


def make_code_forge(settings: Settings) -> ForgeCode | None:
    """The forge Hullwork pushes verified work through. `None` until the code token is set.

    Separate function, separate setting, separate token — so that no request handler and no sweep
    can ever end up holding a credential that can write code. It falls back to nothing rather than
    to the ingest token: an accidental fallback is exactly how the boundary would be lost, quietly,
    on the day M2 lands.

    **Two callers now, and the second one runs no agent** (item 178). `hullwork deps --open` pushes
    an upgrade the project's own suite passed, with no model and no gateway involved. This used to
    say *the forge an agent pushes through*; `config.py` carries the decision and what it costs.
    """
    if not settings.forge_url or not settings.forge_code_token:
        return None
    token = settings.forge_code_token.get_secret_value()
    kind = kind_of(settings.forge_url, settings.forge_kind)
    # A different class, not the same one on a different token: an object that does not have
    # `create_branch` cannot be mistaken for one that should (item 022).
    if kind == "github":
        return GitHubCodeForge(token)
    if kind == "gitlab":
        return GitLabCodeForge(settings.forge_url, token)
    return ForgejoCodeForge(settings.forge_url, token)


def make_permission_reader(settings: Settings) -> PermissionReader | None:
    """The ingest credential, seen only as "what may this do to code?".

    Same object and same token as `make_forge`, handed over through a narrower protocol so that the
    credential audit cannot accidentally acquire the ability to file anything while it is asking.
    """
    if not settings.forge_url or not settings.forge_token:
        return None
    token = settings.forge_token.get_secret_value()
    kind = kind_of(settings.forge_url, settings.forge_kind)
    if kind == "github":
        return GitHubForge(token)
    if kind == "gitlab":
        return GitLabForge(settings.forge_url, token)
    return ForgejoForge(settings.forge_url, token)


def serves(settings: Settings, kind: str) -> bool:
    """Whether this instance's configured forge can serve a project registered as `kind`.

    **One adapter per answer, rather than name equality.** `forgejo` and `gitea` are the same
    adapter against the same API, so asking for one on the other is fine and refusing it would be
    pedantry. Asking for anything else is not: the request goes to the configured host, which
    answers 404 about a repository it has never heard of (item 124).

    `_adapter_for` rather than `kind_of`, and the difference is why there are two functions.
    `kind_of` decides which client to *build* and needs a safe default for a name it does not know.
    This decides whether to *refuse*, where a default would let an unknown name through by being
    helpful — so an unrecognised kind matches nothing.
    """
    configured = configured_kind(settings)
    if configured is None:
        return True  # nothing configured; `_forge_for` refuses for that reason, with its own words
    return _adapter_for(kind) == configured


def configured_kind(settings: Settings) -> str | None:
    """Which forge this instance serves — `"forgejo"`, `"github"`, `"gitlab"` — or `None`.

    **It used to answer `"self-hosted"`**, which was true while there was one self-hosted API and
    became a word covering two the moment GitLab was registrable. Item 124's sentence is that an
    instance says which forge it serves, and that cannot be said with a word meaning "not GitHub".
    """
    if not settings.forge_url:
        return None
    return kind_of(settings.forge_url, settings.forge_kind)


def _adapter_for(kind: str) -> str:
    """Which adapter a project's declared kind needs, with no default for the unknown."""
    named = kind.strip().lower()
    return "forgejo" if named == "gitea" else named
