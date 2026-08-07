"""A page somebody else can read. Item 122, the surface.

`status` and `/ready` answer an operator at a terminal. Nothing answered a teammate, and
The plan M7 asks for a reviewer who did not write Hullwork to judge the evidence — which today
means ssh, a SQLite file and a CLI.

**It lives on the receiver, and there was no choice.** The dispatcher listens on nothing, and that
is the property that lets it hold a credential which can push (DR-0009); giving it a port would
undo the split. So this route sits on the half of Hullwork that an error tracker has to be able to
reach — which, with a hosted tracker, is a public address. Everything below follows from that one
sentence.

**The token is the door.** Minted by `hullwork page-token`, stored as a hash, carried in the path
like the webhook's. With no token there is no page: every path answers `404`, the same answer an
unknown path gets, so the page cannot be confirmed to exist by asking. A wrong token gets `404`
too, for the same reason — `403` would be a yes.

**The token is in the path, so the referrer is a leak.** A browser following the link to a forge or
a tracker would hand the credential to that site. `Referrer-Policy: no-referrer` on every response
is therefore not hygiene, it is the fix for a hole this design creates. `Cache-Control: no-store`
for the borrowed browser, and a CSP with no `script-src` because there is no JavaScript here at all.

**Everything rendered comes from outside.** An error title, a stack frame, a project slug: written
by somebody else's production and stored verbatim. Every interpolation goes through `html.escape`,
and a URL becomes a link only when its scheme is `http` or `https` — which is what stops a stored
`javascript:` from becoming a click. There is no template engine on purpose (principle 6): the
guard is `_h` used everywhere plus a test that renders every view with a hostile fixture, which is
a check somebody re-reads rather than a default nobody does.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from sqlalchemy import select

from hullwork import __version__, spend
from hullwork.models import Attempt as _Attempt
from hullwork.models import AttemptPhase, ItemState, PageAccess
from hullwork.models import Item as _Item
from hullwork.models import Project as _Project
from hullwork.scrub import Scrubber, instance_secrets
from hullwork.security import hash_token, verify_token

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from hullwork.config import Settings
    from hullwork.models import Attempt, Item
    from hullwork.spend import Prices

#: Where the page lives. One segment, then the token, so a proxy can route it all by prefix.
PREFIX = "/page"

#: Paid even when there is no page, so "no token configured" and "wrong token" cost the same.
_DECOY_HASH = hash_token("decoy")

#: Headers on every response. Each one is asserted by its own test, because a header nobody asserts
#: is a header that disappears in a refactor and takes its reason with it.
HEADERS = {
    # **The token is in the path.** Without this, clicking through to the forge hands it over.
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    # No script anywhere, so nothing needs `script-src`. `frame-ancestors 'none'` because a page
    # whose URL is a credential should not be embeddable in somebody else's.
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
}

#: Schemes a stored URL may be rendered as a link with. Anything else — `javascript:`, `data:`,
#: `file:` — is shown as text, because the strings here were written by a third party.
_LINKABLE = frozenset({"http", "https"})


def configured(session: Session) -> bool:
    """Whether this instance has a page at all."""
    return session.scalars(select(PageAccess).limit(1)).one_or_none() is not None


def opens(session: Session, token: str) -> bool:
    """Whether this token opens the page. Constant time, and the same cost when there is no page.

    A missing row must not answer faster than a wrong token: the difference would say *"this
    instance has a page and you have the wrong key"*, which is the one bit of information the `404`
    is there to withhold.
    """
    access = session.scalars(select(PageAccess).limit(1)).one_or_none()
    expected = access.token_hash if access is not None else _DECOY_HASH
    return verify_token(token, expected) and access is not None


def issue(session: Session, token_hash: str) -> None:
    """Store the hash of a new token, replacing any previous one. Rotation is overwriting."""
    access = session.get(PageAccess, 1)
    if access is None:
        session.add(PageAccess(id=1, token_hash=token_hash))
    else:
        access.token_hash = token_hash
    session.commit()


def _h(value: object) -> str:
    """Escape. Used at **every** interpolation, including the ones that look like numbers.

    `str(...)` first because a `None` or an `int` reaching a template is ordinary here, and
    `html.escape` wants text. Quotes escaped as well as tags: some of these land in attributes.
    """
    return html.escape(str(value), quote=True)


def _own_prose(text: str) -> str:
    """Escape, then turn `**…**` into `<strong>`. **Only ever for constants in this module.**

    A stranger evaluating the product on 2026-08-04 read four literal `**` on the served page: the
    credential-split paragraph is written in the same emphasised prose as every document here, and
    the page escaped it and served the markers. The one artefact designed to be shown to somebody
    who is not an operator was showing asterisks.

    **Escaping happens first, and the order is the safety argument.** `**` contains nothing
    `html.escape` touches, so it survives unchanged and the substitution below cannot assemble
    markup out of anything from outside — by the time it runs, every `<` is already `&lt;`. That
    holds for any input; the restriction to module constants is belt-and-braces, because the day
    somebody points this at an error title from a tracker, the reasoning above should not be the
    only thing standing there. Untrusted text goes through `_h`, which is every interpolation.
    """
    return re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", _h(text))


def _link(url: str | None, text: str | None = None) -> str:
    """A URL as a link when its scheme allows, and as escaped text when it does not.

    The strings this renders were stored from somebody else's tracker and forge. A `javascript:`
    URL in an item's permalink is a stored cross-site script with a human clicking it, and the
    cheapest defence is refusing to make it clickable at all.
    """
    label = _h(text if text is not None else url)
    if not url:
        return label
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:  # pragma: no cover - urlsplit raises only on malformed IPv6 literals
        return label
    if scheme not in _LINKABLE:
        return label
    return f'<a href="{_h(url)}" rel="noreferrer noopener">{label}</a>'


#: The whole visual system, inlined. Item 143, and it replaces a stylesheet that was deliberately
#: austere — monospace everything, no colour, no radius — which read as a terminal rather than as a
#: product somebody opens daily.
#:
#: **The real constraint is no external assets, not austerity.** One inlined stylesheet, no network,
#: no build step (principle 6), and a CSP that forbids fetching anything. None of that rules out a
#: system sans, `light-dark()`, `color-mix()` or a considered scale — all of which ship in the
#: browser and cost nothing.
#:
#: Two rules survive from the austere version because they were never about taste:
#:
#: * **Colour never carries meaning alone.** Every tinted thing is also a word. The product's core
#:   mechanic is a red/green gate; encoding that in hue only would fail at the exact point it
#:   argues, and would fail it for the reader who prints the page or cannot separate the two.
#: * **Monospace where the content is data.** SHAs, commands, paths, counts and durations are
#:   monospace so columns align and a truncated hash looks like a hash. Prose and chrome are not,
#:   because setting an entire interface in a monospace face is a costume, not a decision.
_STYLE = """
:root {
  color-scheme: light dark;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;

  --ink:    light-dark(#15171c, #e7e9ee);
  --muted:  light-dark(#5d6470, #98a0ad);
  --faint:  light-dark(#868d99, #6f7783);
  --rule:   light-dark(#e2e5ea, #262a31);
  --canvas: light-dark(#fcfcfd, #0f1115);
  --raise:  light-dark(#ffffff, #16191f);

  --waiting: light-dark(#8a5a00, #e3a83a);
  --working: light-dark(#1b5fb0, #6aa9f2);
  --passed:  light-dark(#12693a, #4fb37d);
  --refused: light-dark(#a32f26, #ec7d70);
  --human:   light-dark(#5a3ea8, #ab8df0);

  --r-card: 10px;
  --r-chip: 6px;
}
* { box-sizing: border-box; }
body {
  font: 400 15px/1.6 var(--sans);
  color: var(--ink); background: var(--canvas);
  margin: 0 auto; max-width: 78rem; padding: 2.5rem 1.5rem 5rem;
  -webkit-font-smoothing: antialiased;
}
h1 { font-size: 1.5rem; font-weight: 650; letter-spacing: -.02em; margin: 0 0 .3rem; }
h2 { font-size: .78rem; font-weight: 650; letter-spacing: .07em; text-transform: uppercase;
     color: var(--faint); margin: 2.5rem 0 .75rem; }
h3 { font-size: 1rem; font-weight: 600; letter-spacing: -.01em; margin: 0 0 .4rem; }
a { color: inherit; text-underline-offset: 3px; text-decoration-color: var(--rule); }
a:hover { text-decoration-color: currentColor; }
.sub { color: var(--muted); margin: 0 0 2rem; }
.mono { font-family: var(--mono); font-variant-numeric: tabular-nums; }
.faint { color: var(--faint); }
.bad { font-weight: 650; color: var(--refused); }

/* A band is the unit of the daily page: hairline, soft radius, and in light mode the faintest
   lift so it reads as a surface rather than as a box drawn on the page. */
.band { background: var(--raise); border: 1px solid var(--rule); border-radius: var(--r-card);
        padding: 1.1rem 1.25rem; margin: 0 0 1rem;
        box-shadow: light-dark(0 1px 2px rgb(16 18 28 / .04), none); }
.band.quiet { background: none; box-shadow: none; }

/* State chips. The tint is derived from the semantic colour so a new state needs one variable,
   and the word inside is never optional. */
.chip { display: inline-flex; align-items: center; gap: .4rem; font: 600 .75rem/1 var(--sans);
        letter-spacing: .01em; padding: .35rem .55rem; border-radius: var(--r-chip);
        border: 1px solid color-mix(in oklab, var(--c, var(--muted)) 30%, transparent);
        background: color-mix(in oklab, var(--c, var(--muted)) 12%, transparent);
        color: var(--c, var(--muted)); white-space: nowrap; }
.chip::before { content: ""; width: .4rem; height: .4rem; border-radius: 50%;
                background: currentColor; flex: none; }
.c-waiting { --c: var(--waiting); } .c-working { --c: var(--working); }
.c-passed  { --c: var(--passed);  } .c-refused { --c: var(--refused); }
.c-human   { --c: var(--human);   } .c-idle    { --c: var(--faint);   }

/* The board: one column per group, wrapping down on a narrow screen rather than scrolling out. */
.board { display: grid; gap: .75rem; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); }
.col { background: var(--raise); border: 1px solid var(--rule); border-radius: var(--r-card);
       padding: .85rem .9rem; min-height: 6.5rem; }
.col h4 { font: 650 .72rem/1 var(--sans); letter-spacing: .06em; text-transform: uppercase;
          color: var(--faint); margin: 0 0 .6rem; }
.count { font: 650 1.75rem/1 var(--mono); font-variant-numeric: tabular-nums;
         letter-spacing: -.03em; color: var(--c, var(--ink)); }
.count.zero { color: var(--faint); font-weight: 400; }
/* Item 166: a non-zero count is a link to the items it counted. It keeps the number's weight and
   colour — the underline is what says it can be clicked, and only on hover so the board still reads
   as figures rather than as a menu. */
a.count { display: inline-block; text-decoration: none; }
a.count:hover, a.count:focus-visible { text-decoration: underline; }
/* A tinted number is still a number: the column heading above it carries the meaning. */
.age { display: block; font-size: .78rem; color: var(--muted); margin-top: .35rem; }
.col.owed { border-color: color-mix(in oklab, var(--waiting) 45%, var(--rule)); }

/* The six phases of the attempt in flight. */
.phases { display: flex; flex-wrap: wrap; gap: .4rem; margin: .75rem 0 0;
          padding: 0; list-style: none; }
.phase { font: 500 .78rem/1 var(--mono); padding: .4rem .6rem; border-radius: var(--r-chip);
         border: 1px solid var(--rule); color: var(--faint); }
.phase.done { color: var(--passed);
              border-color: color-mix(in oklab, var(--passed) 35%, transparent);
              background: color-mix(in oklab, var(--passed) 10%, transparent); }
.phase.live { color: var(--working);
              border-color: color-mix(in oklab, var(--working) 45%, transparent);
              background: color-mix(in oklab, var(--working) 12%, transparent); }
.phase.failed { color: var(--refused);
                border-color: color-mix(in oklab, var(--refused) 40%, transparent);
                background: color-mix(in oklab, var(--refused) 12%, transparent); }

/* Facts: label and value, aligned, no table needed. */
.facts { display: grid; grid-template-columns: minmax(9rem, max-content) 1fr; gap: .3rem 1.25rem;
         margin: .25rem 0 0; }
.facts dt { color: var(--muted); font-size: .85rem; }
.facts dd { margin: 0; font-family: var(--mono); font-size: .85rem;
            font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }

table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }
th, td { text-align: left; padding: .45rem .7rem .45rem 0; vertical-align: top; }
th { font-weight: 600; color: var(--muted); width: 16rem; font-size: .85rem; }
ul { margin: .25rem 0 1rem; padding-left: 1.2rem; }
li { margin: .2rem 0; }
footer { margin-top: 3.5rem; padding-top: 1.25rem; border-top: 1px solid var(--rule);
         color: var(--faint); font-size: .82rem; }
/* The list has seven narrow columns, not two wide ones, so it undoes the label width above. */
table.list th { width: auto; font-size: .75rem; letter-spacing: .05em; text-transform: uppercase;
                color: var(--faint); }
table.list td { border-top: 1px solid var(--rule); font-size: .875rem; }
table.list tr:hover td { background: color-mix(in oklab, var(--ink) 4%, transparent); }
/* Captured output is somebody else's, and some of it has 300-character lines. It wraps rather
   than scrolls, because a horizontal scrollbar inside a collapsed block hides evidence. */
pre { white-space: pre-wrap; overflow-wrap: anywhere; margin: .5rem 0;
      font: .82rem/1.5 var(--mono); background: color-mix(in oklab, var(--ink) 4%, transparent);
      border-radius: var(--r-chip); padding: .7rem .85rem; }
details { margin: .4rem 0 .7rem; }
summary { cursor: pointer; color: var(--muted); font-size: .875rem; }
summary:hover { color: var(--ink); }
details > pre { border-left: 2px solid var(--rule); }
code { font-family: var(--mono); font-size: .9em; }

/* Item 166. A form is the only way to change something here, so it has to look like part of the
   page rather than like a browser default from 1998. `.linkish` is a button that reads as a link,
   for sign-out, where a button would claim more weight than the action has. */
form.inline { display: inline; }
button.linkish {
  background: none; border: 0; padding: 0; font: inherit; color: inherit;
  text-decoration: underline; cursor: pointer;
}
.decide { display: flex; gap: .6rem; flex-wrap: wrap; margin: .8rem 0 0; }
.decide button {
  font: inherit; padding: .45rem .9rem; border-radius: 6px; cursor: pointer;
  border: 1px solid var(--rule); background: var(--card); color: var(--fg);
}
.decide button.go { border-color: var(--passed); }
.decide form { margin: 0; }
.login { margin: .8rem 0 0; display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
.login input {
  font: inherit; font-family: var(--mono); padding: .4rem .5rem; min-width: 22rem;
  border: 1px solid var(--rule); border-radius: 6px; background: var(--card); color: var(--fg);
}
.next { border-left: 3px solid var(--waiting); padding-left: .8rem; margin: 1rem 0; }
/* An item the dispatcher will never pick up. Beside the state rather than instead of it: the state
   is still the truth, this is what the state cannot say on its own. */
.stuck { font: 600 .7rem/1 var(--sans); letter-spacing: .04em; text-transform: uppercase;
         color: var(--refused); border: 1px solid currentColor; border-radius: var(--r-chip);
         padding: .15rem .35rem; margin-left: .35rem; }
"""


#: The mark, as the interface document specifies it: a single glyph, `▚`, and no binary asset.
#:
#: **Inline rather than a file**, for the reason that document gives — a product that ships as a
#: wheel and renders one inlined stylesheet should not acquire a binary dependency for its own
#: name. A `data:` URI keeps the promise below: no external asset, and one request per page.
#:
#: Without this the daily page was a generic document icon in a browser tab, which is where somebody
#: with fifteen tabs open finds it. The glyph was decided and never served.
_FAVICON = (
    "data:image/svg+xml,"
    "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E"
    "%3Ctext x='8' y='13' font-size='15' text-anchor='middle'"
    "%20font-family='ui-monospace,monospace'%3E%E2%96%9A%3C/text%3E%3C/svg%3E"
)


@dataclass(frozen=True)
class Acting:
    """What the request being rendered may do. Item 166.

    **Decided in `operator`, rendered here, and defaulting to what the page was before it existed.**
    An instance with no operator key produces `Acting()` on every request, and every branch below
    then takes the path it took in 0.1.0a6 — which is the acceptance criterion that keeps this item
    from changing an instance nobody asked to change.
    """

    #: The session's CSRF token when this request may act. `None` is *read-only*, and it is the
    #: answer for a wrong cookie, an expired session and an instance with no key alike.
    csrf: str | None = None

    #: Whether an operator key exists, which is whether offering a login is honest. Without this the
    #: page would either show a login on an instance that can never accept one, or hide the one
    #: affordance the operator is looking for.
    offered: bool = False


#: A request that may read and nothing else — the default everywhere, and the whole of what this
#: page was before item 166.
READING = Acting()


def _document(title: str, body: str, *, acting: Acting = READING, up: str = "") -> str:
    """The whole page. No script, no external asset, one inlined stylesheet.

    `up` is how far this view is from `/page/<token>/`, because **every URL here is relative on
    purpose** — that is what keeps the token out of the HTML, so a saved page or a screenshot of the
    source carries no key. A form is a URL like any other: from `items/28` the sign-out has to post
    to `../logout`, and hardcoding `logout` would have posted to `items/logout` and 404'd.
    """
    footing = (
        "read-only. <strong>This URL is the credential</strong>: anyone who has it can read "
        "everything on this page. Rotate it with <code>hullwork page-token --rotate</code>."
        if acting.csrf is None
        else "<strong>signed in</strong>, so two buttons on an amber item work and nothing else "
        "does. The URL is still only a read credential: this browser holds the other one. "
        f'<form method="post" action="{up}logout" class="inline">'
        f'<input type="hidden" name="csrf" value="{_h(acting.csrf)}">'
        '<button type="submit" class="linkish">Sign out</button></form>'
    )
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f'<link rel="icon" href="{_FAVICON}">'
        f"<title>{_h(title)}</title><style>{_STYLE}</style></head><body>\n"
        f"{body}\n"
        f"<footer>Hullwork {_h(__version__)} — {footing}</footer>\n"
        "</body></html>\n"
    )


#: What each half of Hullwork holds, and what it provably cannot do. Item 136.
#:
#: **On the page rather than only in the deployment notes**, because the person asked to trust a
#: draft pull request written by a machine is exactly the person who needs to know which credential
#: wrote it. Two sentences, and the second is the measured half: `token_may_write_code` asks the
#: forge a question whose successful form cannot be constructed, on three forges (073, 131, 132),
#: and what it answers is what appears here — never the design's promise.
_SPLIT = (
    "This service holds a credential that can file issues and read code, and **listens** — the "
    "error tracker has to reach it. The half that can write code holds a different credential and "
    "**listens on nothing**: no port, no route, nothing to reach. That is DR-0009, and it is why a "
    "page can exist here at all."
)


def _what_this_instance_allows(settings: Settings) -> str:
    """The three policies, on the page. Item 137.

    A reviewer judging an artefact is judging what the instance was **allowed** to do while making
    it: an attempt with no cost ceiling and an open model list is a different thing to trust than
    one with both closed, and neither is visible in the artefact itself.
    """
    from hullwork.doctor import policies

    return f"<h2>What this instance allows</h2><p>{_h(policies(settings).detail)}</p>"


def _the_credential_split(session: Session) -> str:
    """The split, with this instance's own measurement of it rather than the promise."""
    from hullwork.models import Project

    measured: list[str] = []
    try:
        projects = list(session.scalars(select(Project).where(Project.active.is_(True))).all())
    except Exception:  # pragma: no cover - a page that cannot read projects still renders the rule
        projects = []
    for project in projects:
        # Stored by `status`'s audit rather than probed here: a page render must not spend a forge
        # request, and a reader refreshing would spend one each time.
        verdict = (project.manifest or {}).get("__ingest_can_push__") if project.manifest else None
        if verdict is not None:
            measured.append(f"{project.slug}: {'CAN push' if verdict else 'cannot push, measured'}")
    tail = (
        f'<p class="sub">{_h(" · ".join(measured))}</p>' if measured else
        '<p class="sub">Whether this instance\'s ingest credential can push is answered by '
        '<code>hullwork status</code>, which asks the forge a question whose successful form does '
        'not exist. It is not asked from this page: a render must not spend somebody\'s forge '
        'quota.</p>'
    )
    return f"<h2>Which half holds what</h2><p>{_own_prose(_SPLIT)}</p>{tail}"


#: The twelve states, grouped into the six questions a reader actually has. Item 143.
#:
#: Twelve columns is unreadable, and the grouping is a product decision rather than a display trick:
#: **each column is a different answer to "who is blocked".** Two of the six are the reader, and
#: they are why the page exists — `pr-open` gets its own rather than being folded into "open",
#: because that queue not draining is item 138's review debt, which is the product's own failure
#: mode and belongs in the reader's face rather than in a report.
#:
#: Each column also carries a **key**, because item 166 made the counts links. The operator read
#: *"Waiting on you 2"* off this board and asked *"¿y ahora qué?"*: a number with no name behind
#: it, answerable only by leaving the page, opening the list and scanning 28 rows. The key is what
#: `items?in=…` filters on, so a count leads to the items it counted.
_COLUMNS: tuple[tuple[str, str, str, tuple[ItemState, ...], bool], ...] = (
    ("Arrived", "arrived", "c-idle",
     (ItemState.NEW, ItemState.TRIAGED, ItemState.REOPENED), False),
    ("Waiting on you", "waiting", "c-waiting",
     (ItemState.WAITING_APPROVAL, ItemState.HUMAN_ONLY), True),
    ("Queued", "queued", "c-idle", (ItemState.READY,), False),
    ("Working", "working", "c-working", (ItemState.IN_PROGRESS,), False),
    ("Waiting on review", "review", "c-waiting", (ItemState.PR_OPEN,), True),
    (
        "Closed", "closed", "c-passed",
        (ItemState.DONE, ItemState.REJECTED, ItemState.FAILED, ItemState.NOT_REPRODUCIBLE),
        False,
    ),
)

#: The column keys, for the list view to look up without importing the display tuple's shape.
_IN: dict[str, tuple[ItemState, ...]] = {key: states for _, key, _, states, _ in _COLUMNS}

#: The six steps, in the order a reader watches them happen.
_PHASES: tuple[tuple[str, AttemptPhase], ...] = (
    ("baseline", AttemptPhase.BASELINE),
    ("reproduce", AttemptPhase.REPRODUCE),
    ("RED", AttemptPhase.RED_GATE),
    ("fix", AttemptPhase.FIX),
    ("GREEN", AttemptPhase.GREEN_GATE),
    ("lint", AttemptPhase.LINT_GATE),
)


def _ago(when: datetime | None) -> str:
    """How long ago, in the coarsest unit that is still true.

    `None` is *not recorded* and never a zero: on an item that predates `state_since` (item 141)
    there is no age, and inventing one from `updated_at` is exactly what that column exists to
    avoid.
    """
    if when is None:
        return "not recorded"
    seconds = (datetime.now(UTC) - when).total_seconds()
    if seconds < 90:
        return "just now"
    for size, unit in ((3600, "m"), (86400, "h"), (float("inf"), "d")):
        if seconds < size:
            divisor = {"m": 60, "h": 3600, "d": 86400}[unit]
            return f"{int(seconds // divisor)}{unit}"
    return "not recorded"  # pragma: no cover - the loop above is exhaustive


#: The states the dispatcher will ever pick an item up from. `work.py` selects `READY` items whose
#: project is active; everything else is waiting on a person or already finished.
_DISPATCHABLE = (ItemState.READY, ItemState.WAITING_APPROVAL)


def _stuck(item: _Item) -> str | None:
    """Why this item can **never** be attempted, or `None` if nothing stops it. Item 166.

    **The count was right and the reader was still misled.** `simplecheck` was disabled on
    2026-08-07 and item 15 stayed in `ready`, so the board kept counting it under *Queued* with
    an age that kept climbing — while `work.py` selects on `Project.active.is_(True)` and would
    never look at it again. A queue that cannot drain has to say so where it is displayed, not in
    the release notes of the command that disabled the project.
    """
    if item.state in _DISPATCHABLE and not item.project.active:
        return (
            f"the project '{item.project.slug}' is disabled, so the dispatcher will never "
            f"pick this up — re-register it to change that"
        )
    return None


def _board(session: Session) -> str:
    """Where everything is, and how long the oldest has been there.

    A count alone is a photograph. The age is the signal, and it is the whole reason item 141 put a
    clock on the transition.
    """
    cells = []
    for title, key, tone, states, owed in _COLUMNS:
        items = list(session.scalars(select(_Item).where(_Item.state.in_(states))).all())
        oldest = min((i.state_since for i in items if i.state_since is not None), default=None)
        count = len(items)
        age = (
            "&nbsp;"
            if not count
            else f"oldest {_h(_ago(oldest))}"
            if oldest is not None
            else "age not recorded"
        )
        # **A count of zero is not a link**, because there is nothing behind it and a link that
        # lands on "no items match" teaches a reader that the page is broken rather than that the
        # queue is empty.
        counter = (
            f'<span class="count {tone} zero">0</span>'
            if not count
            else f'<a href="items?in={key}" class="count {tone}">{count}</a>'
        )
        cells.append(
            f'<div class="col{" owed" if owed and count else ""}">'
            f"<h4>{_h(title)}</h4>{counter}"
            f'<span class="age">{age}</span></div>'
        )
    return f'<div class="board">{"".join(cells)}</div>'


def _now(session: Session, prices: Prices | None) -> str:
    """The attempt in flight, or a sentence saying there is none.

    **Never a blank band.** An interface that empties when idle reads as broken; one that reports
    calm reads as working, and on an instance with one dispatcher and one attempt at a time (item
    137) calm is the normal state.
    """
    running = session.scalars(
        select(_Item).where(_Item.state == ItemState.IN_PROGRESS).limit(1)
    ).one_or_none()
    queued = len(list(session.scalars(select(_Item).where(_Item.state == ItemState.READY)).all()))
    behind = (
        f' <span class="faint">· {queued} waiting behind it</span>'
        if running is not None and queued
        else ""
    )

    if running is None:
        last = session.scalars(
            select(_Attempt).order_by(_Attempt.id.desc()).limit(1)
        ).one_or_none()
        if last is None:
            tail = "No attempt has run on this instance yet."
        else:
            outcome = getattr(last.outcome, "value", last.outcome)
            tail = (
                f"The last one finished {_h(_ago(last.finished_at or last.started_at))} ago: "
                f"{_h(str(outcome))}."
            )
        return (
            '<div class="band"><span class="chip c-idle">nothing running</span>'
            f'<p class="sub" style="margin:.7rem 0 0">{tail}'
            + (f' {queued} item(s) are ready and waiting.' if queued else "")
            + "</p></div>"
        )

    attempt = session.scalars(
        select(_Attempt).where(_Attempt.item_id == running.id).order_by(_Attempt.id.desc()).limit(1)
    ).one_or_none()
    reached = (
        {step.phase for step in attempt.steps} if attempt is not None else set()
    )
    marks = []
    live_seen = False
    for label, phase in _PHASES:
        if phase in reached:
            marks.append(f'<li class="phase done">{_h(label)}</li>')
        elif not live_seen:
            marks.append(f'<li class="phase live">{_h(label)}</li>')
            live_seen = True
        else:
            marks.append(f'<li class="phase">{_h(label)}</li>')

    cost = ""
    if attempt is not None:
        money = spend.cost_of(spend.tokens_of(attempt.seal), prices) if prices else None
        parts = [f"started {_h(_ago(attempt.started_at))} ago"]
        if money is not None:
            parts.append(_h(str(money)))
        cost = f'<p class="sub" style="margin:.6rem 0 0">{" · ".join(parts)}</p>'

    return (
        '<div class="band"><span class="chip c-working">working</span> '
        f'<strong>{_h(running.title)}</strong>{behind}'
        f'<ul class="phases">{"".join(marks)}</ul>{cost}</div>'
    )


def _disagreements(session: Session, settings: Settings) -> str:
    """The three gaps between what was declared and what is real.

    Argo CD's interface is valuable because it renders the difference between the manifest and the
    cluster. Hullwork has three such differences and rendered none of them: a setting that was
    configured and never arrived, a model that answered without being the pinned one (DR-0002), and
    an item whose pull request the forge has already closed.

    **Empty is the normal case and empty must be visible.** *Nothing disagrees* is the most valuable
    line on this page on a good day, and a band that vanishes when clean cannot say it.
    """
    found: list[str] = []

    drifted = [
        attempt
        for attempt in session.scalars(select(_Attempt)).all()
        if _violations_in(attempt.seal)
    ]
    if drifted:
        found.append(
            f"{len(drifted)} attempt(s) recorded a model answering that was not the pinned one"
        )
    if settings.model_name is None:
        found.append(
            "no model is pinned (HULLWORK_MODEL_NAME), so nothing here can tell drift from normal"
        )

    stalled = list(
        session.scalars(select(_Item).where(_Item.state == ItemState.PR_OPEN)).all()
    )
    week = 7
    ancient = [
        i for i in stalled
        if i.state_since and (datetime.now(UTC) - i.state_since).days >= week
    ]
    if ancient:
        found.append(
            f"{len(ancient)} pull request(s) have been waiting on a human for a week or more"
        )

    if not found:
        return (
            '<h2>What does not add up</h2>'
            '<div class="band quiet"><span class="chip c-passed">nothing disagrees</span></div>'
        )
    rows = "".join(f'<li class="bad">{_h(line)}</li>' for line in found)
    return f'<h2>What does not add up</h2><div class="band"><ul>{rows}</ul></div>'


def _violations_in(seal: object) -> bool:
    """Whether this attempt's seal recorded a model other than the one asked for."""
    if not isinstance(seal, dict):
        return False
    return bool(seal.get("violations"))


def instance(
    session: Session, settings: Settings, *, error_reporting: bool, acting: Acting = READING
) -> str:
    """What `hullwork status` says, for somebody who does not have a terminal on this host.

    **Every number comes from the function `status` calls**, never from a second query written for
    this page: `readiness.check`, `outcomes.funnel`, `recurrence.counted` and `undecided`,
    `lease.state` and `reporting_of`. A page that recomputed them would drift, and the first anybody
    would know is a reader and an operator disagreeing about the same instance.
    """
    from hullwork import lease, outcomes, readiness, recurrence

    report = readiness.check(session, settings, error_reporting=error_reporting)
    merged, holding, recurred = recurrence.counted(session)
    undecided = recurrence.undecided(session)
    loop_state, loop_seen = lease.state(session)
    reporting = lease.reporting_of(session)

    problems = "".join(f"<li class=\"bad\">{_h(problem)}</li>" for problem in report.problems)
    rows = [
        ("state", "ready" if report.ready else "degraded"),
        ("version", report.version),
        ("forge", report.forge),
        ("error reporting (this service)", "on" if report.error_reporting else "off"),
        (
            "error reporting (dispatcher)",
            "not recorded" if reporting is None else ("on" if reporting else "off"),
        ),
        ("sweep", f"every {report.sweep_interval_s}s"),
        ("backlog", f"{report.backlog} item(s) owed an issue"),
        ("deliveries carrying an error", report.failed_deliveries),
        (
            "dispatcher",
            {
                "alive": f"running, last seen {loop_seen}",
                "released": "not running; the last one was stopped and gave up its lease",
                "stale": f"not running since {loop_seen}, and it did not give up its lease",
                "never": "none has ever run on this instance",
            }[loop_state],
        ),
        (
            "merged fixes",
            f"{merged} merged · {holding} held the {recurrence.WATCH_DAYS}-day window · "
            f"{recurred} came back"
            + (f" · {undecided} cannot be decided" if undecided else ""),
        ),
    ]
    table = "".join(f"<tr><th>{_h(name)}</th><td>{_h(value)}</td></tr>" for name, value in rows)
    attempts = "".join(f"<li>{_h(line)}</li>" for line in outcomes.lines(outcomes.funnel(session)))
    spent = "".join(
        f"<li>{_h(line.strip())}</li>"
        for line in spend.lines(
            spend.per_instance(
                list(session.scalars(select(_Attempt)).all()),
                spend.Prices.from_settings(settings),
            )
        )
    )

    reviewed = "".join(
        f"<li>{_h(line)}</li>" for line in outcomes.review_lines(outcomes.reviewed(session))
    )

    prices = spend.Prices.from_settings(settings)
    body = (
        "<h1>hullwork</h1>"
        # **The opening line stops being a lie when a session can act** (item 166). It said
        # "Nothing here changes anything" for two versions and it was true; saying it while two
        # buttons work would be worse than saying nothing.
        + (
            '<p class="sub">Read-only. Nothing here changes anything. '
            if acting.csrf is None
            else '<p class="sub">Signed in: an amber item can be decided here. '
        )
        + '<a href="projects">Projects</a> · '
        '<a href="items">Items and their evidence</a></p>'
        + (f"<h2>Problems</h2><ul>{problems}</ul>" if problems else "")
        # **The three bands come first, and they are the page** (item 143). What follows them is
        # the evaluator's material — provenance, cost, the credential split — which is kept whole
        # and moved below, because the reader who needs it arrives once and the reader this page
        # is for arrives daily.
        + f"<h2>Now</h2>{_now(session, prices)}"
        + f"<h2>Where everything is</h2>{_board(session)}"
        # A count is a link now, so the front page needs the way in to be here too rather
        # than only on an item: the operator arrives at this board, not at item 28.
        + (
            '<form method="post" action="login" class="login">'
            '<input type="password" name="key" autocomplete="current-password" '
            'placeholder="operator key" aria-label="operator key" required>'
            '<button type="submit">Sign in to decide</button></form>'
            if acting.offered and acting.csrf is None
            else ''
        )
        + _disagreements(session, settings)
        + f"<h2>State</h2><table>{table}</table>"
        + (f"<h2>Attempts</h2><ul>{attempts}</ul>" if attempts else "")
        + (f"<h2>What they cost</h2><ul>{spent}</ul>" if spent else "")
        + (f"<h2>What reviewers did</h2><ul>{reviewed}</ul>" if reviewed else "")
        + _the_credential_split(session)
        + _what_this_instance_allows(settings)
    )
    return _document("Hullwork — this instance", body, acting=acting)


#: How many rows a list shows. Bounded because an instance that has been running for a year has
#: thousands of items and this renders in one string, and **stated on the page** because a reader
#: who cannot see the bound reads the list as "everything" and is wrong.
MAX_ITEMS = 200


def _project_health(project: _Project) -> tuple[str, str]:
    """Two sentences a reader looking at one client needs, and neither was on any page. Item 142.

    **The credential**, from the audit `status` already stores on the project row rather than from a
    forge request here: a page render must not spend one, and a reader refreshing would spend one
    each time. `None` is *not asked yet* and is not a pass — item 073's rule, and the same
    `None != False` this project has got wrong three times.

    **The manifest**, by validating the cached copy. A project whose stored manifest no longer
    parses has every incoming error land red (`ingest._manifest_for` degrades to that silently, by
    design), and until now the only way to know was to read that function. It is the loudest thing
    that can be wrong with a project and it was invisible.
    """
    from hullwork.manifest import Manifest

    pushes = (project.manifest or {}).get("__ingest_can_push__") if project.manifest else None
    credential = {
        None: ("unknown", "not asked yet — `hullwork status` records this when it runs"),
        True: ("bad", "its ingest credential CAN push, which DR-0009 forbids"),
        False: ("good", "ingest credential reaches the repository and cannot push"),
    }[pushes if pushes is None else bool(pushes)]

    if not project.manifest:
        manifest = ("unknown", "no manifest cached — nothing can be built for this project")
    else:
        try:
            Manifest.model_validate(
                {k: v for k, v in project.manifest.items() if not k.startswith("__")}
            )
            manifest = ("good", "cached manifest validates")
        except Exception:
            manifest = (
                "bad",
                "cached manifest no longer validates, so every error from here lands red until "
                "`hullwork projects refresh` adopts a working one",
            )
    return (
        f'<li class="{credential[0]}">{_h(credential[1])}</li>'
        f'<li class="{manifest[0]}">{_h(manifest[1])}</li>',
        credential[0] + manifest[0],
    )


def _project_columns(session: Session, project_id: int) -> str:
    """The same six columns as the instance board, for one project.

    `_COLUMNS` rather than a second list, which is the point: a project's board and the instance's
    board disagreeing about what "waiting on you" means would make both useless.
    """
    cells = []
    for title, _key, tone, states, owed in _COLUMNS:
        count = len(
            list(
                session.scalars(
                    select(_Item).where(_Item.project_id == project_id, _Item.state.in_(states))
                ).all()
            )
        )
        cells.append(
            f'<div class="col{" owed" if owed and count else ""}">'
            f"<h4>{_h(title)}</h4>"
            f'<span class="count {tone}{" zero" if not count else ""}">{count}</span>'
            f'<span class="age">&nbsp;</span></div>'
        )
    return f'<div class="board">{"".join(cells)}</div>'


def _project_cost(session: Session, project_id: int, prices: Prices | None) -> str:
    """What this project's attempts cost, **through `hullwork.spend`**.

    Not a second calculation, for the reason item 136 found the hard way: the page and the pull
    request body disagreed about one attempt's cost because each had its own arithmetic.
    """
    attempts = list(
        session.scalars(
            select(_Attempt).join(_Item, _Attempt.item_id == _Item.id).where(
                _Item.project_id == project_id
            )
        ).all()
    )
    if not attempts:
        return "<p>No attempt has run for this project.</p>"
    return "<ul>" + "".join(
        f"<li>{_h(line.strip())}</li>" for line in spend.lines(spend.per_instance(attempts, prices))
    ) + "</ul>"


def projects(session: Session, settings: Settings) -> str:
    """Every project this instance serves. Item 142, and the level the tree was missing.

    The page had instance, items and one item; a project appeared as a *column* in a list. That was
    invisible while each instance watched one repository, and stops being invisible the moment
    somebody runs this across ten client repositories — the case DR-0014's second amendment calls
    ordinary. A reader there thinks per client, and there was nowhere to stand and ask how one is.

    **One instance, one forge** (DR-0009, item 125), so this never spans instances: a consultancy
    whose clients straddle two forges reads two of these. Aggregating would mean one instance
    holding another's credentials, which would undo the split that lets a page exist at all.
    """
    prices = spend.Prices.from_settings(settings)
    found = list(session.scalars(select(_Project).order_by(_Project.slug)).all())
    if not found:
        body = (
            "<h1>Projects</h1>"
            '<p class="sub"><a href=".">This instance</a> · '
            '<a href="items">Items and their evidence</a></p>'
            "<p>No project is registered. `hullwork projects add` connects one, and "
            "`hullwork propose --checkout PATH` prints a manifest to start from.</p>"
        )
        return _document("Hullwork — projects", body)

    blocks = []
    for project in found[:MAX_ITEMS]:
        health, _ = _project_health(project)
        blocks.append(
            f'<h2><a href="projects/{_h(project.slug)}">{_h(project.slug)}</a></h2>'
            f'<p class="sub">{_h(project.forge)} · {_h(project.repo)}'
            f"{'' if project.active else ' · not active'}</p>"
            f"<ul>{health}</ul>"
            f"{_project_columns(session, project.id)}"
        )
    bound = (
        f"<p>Showing {min(len(found), MAX_ITEMS)} of {len(found)}.</p>"
        if len(found) > MAX_ITEMS
        else ""
    )
    body = (
        "<h1>Projects</h1>"
        '<p class="sub">Read-only. One instance serves one forge, so this is every project '
        'on this one. <a href=".">This instance</a> · '
        '<a href="items">Items and their evidence</a></p>'
        + bound
        + "".join(blocks)
    )
    del prices
    return _document("Hullwork — projects", body)


def project(session: Session, settings: Settings, slug: str) -> str | None:
    """One project: health, board, cost, items. `None` when there is no project with that slug.

    `None` rather than a message, so the route answers the same `404` an unknown path gets — a
    distinct body would let somebody enumerate the slugs an instance serves with a valid token.
    """
    found = session.scalars(select(_Project).where(_Project.slug == slug)).one_or_none()
    if found is None:
        return None

    prices = spend.Prices.from_settings(settings)
    health, _ = _project_health(found)
    rows = list(
        session.scalars(
            select(_Item)
            .where(_Item.project_id == found.id)
            .order_by(_Item.id.desc())
            .limit(MAX_ITEMS)
        ).all()
    )
    listed = "".join(
        f"<tr><td><a href=\"../items/{item_row.id}\">{item_row.id}</a></td>"
        f"<td>{_h(item_row.title)}</td>"
        f"<td>{_h(item_row.state.value)}</td>"
        f"<td>{_h(item_row.lane.value)}</td>"
        f"<td>{_h(_ago(item_row.state_since))}</td></tr>"
        for item_row in rows
    )
    total = len(list(session.scalars(select(_Item).where(_Item.project_id == found.id)).all()))
    bound = f"<p>Showing {len(rows)} of {total}.</p>" if total > len(rows) else ""

    body = (
        f"<h1>{_h(found.slug)}</h1>"
        f'<p class="sub">{_h(found.forge)} · {_h(found.repo)}'
        f"{'' if found.active else ' · not active'} · "
        f'<a href="../projects">All projects</a> · <a href="..">This instance</a></p>'
        f"<h2>Health</h2><ul>{health}</ul>"
        f"<h2>Where everything is</h2>{_project_columns(session, found.id)}"
        f"<h2>What its attempts cost</h2>{_project_cost(session, found.id, prices)}"
        f"<h2>Items</h2>{bound}"
        + (
            "<table><tr><th>id</th><th>title</th><th>state</th><th>lane</th><th>since</th></tr>"
            f"{listed}</table>"
            if listed
            else "<p>No item has arrived for this project.</p>"
        )
    )
    return _document(f"Hullwork — {found.slug}", body)



#: The lines `evidence` emits around a collapsible block, and around the captured output inside it.
#: Recognised here rather than re-derived, so this stays a *presentation* of that module's output
#: and never a second assembly.
_FOLD_OPEN = "<details><summary>"
_FOLD_CLOSE = "</details>"
_FENCE = "```"


def _secrets_for(settings: Settings) -> list[str]:
    """What to blank by value in anything rendered here. The publisher's list, not a second one."""
    return instance_secrets(settings)


def _folded(body: str) -> str:
    """The artefact as HTML: its text verbatim, its collapsible blocks made real.

    **Every character comes from the string `evidence` produced.** The only transformation is that
    a `<details>` block a forge would fold gets folded here too, because the alternative is a
    reviewer scrolling past six hundred lines of captured output to reach the next verdict — the
    exact failure item 116 was about, reintroduced by the page that exists to fix it.

    No markdown is interpreted. A renderer would be a dependency (principle 6) and, worse, a second
    opinion about what the artefact says; a `|`-table in a monospace block is legible and is
    unarguably the same bytes the pull request carries.

    **The text inside a fold is somebody else's production output, and it is scanned for the
    marker that ends the fold.** So a stack trace containing the literal line `</details>` would
    close the block early and put the attacker's next lines in the page's own flow. The fence
    `evidence` writes around captured output is tracked for exactly that reason: inside it, that
    line is content.

    What this does **not** claim is a parser. Output that emits a closing fence of its own and then
    the marker still escapes its block, and there is no fix for that short of not rendering the
    artefact as the string it is. The reason that is acceptable, and the reason to be exact about
    it rather than to write "sanitised" here: every line goes through `_h` either way, so the worst
    an attacker achieves is moving their own escaped text out of a collapsed block — a page that
    looks wrong, not a page that runs anything. The forge renders the same document with the same
    property.
    """
    out: list[str] = []
    plain: list[str] = []
    folded: list[str] | None = None
    fenced = False
    summary = ""

    def flush() -> None:
        while plain and not plain[-1].strip():
            plain.pop()
        if plain:
            out.append(f"<pre>{_h("\n".join(plain))}</pre>")
        plain.clear()

    for line in body.splitlines():
        if folded is None:
            if line.startswith(_FOLD_OPEN) and line.endswith("</summary>"):
                flush()
                summary = line[len(_FOLD_OPEN) : -len("</summary>")]
                folded = []
            else:
                plain.append(line)
        elif fenced:
            fenced = not line.startswith(_FENCE)
            folded.append(line)
        elif line == _FOLD_CLOSE:
            out.append(
                f"<details><summary>{_h(summary)}</summary>"
                f"<pre>{_h("\n".join(folded).strip())}</pre></details>"
            )
            folded = None
        else:
            fenced = line.startswith(_FENCE)
            folded.append(line)

    if folded is not None:
        # Unclosed: the artefact was truncated mid-block by `MAX_BODY_CHARS`. Shown open, and said
        # so, rather than silently dropped — the truncation is a fact about the artefact.
        out.append(
            f"<details open><summary>{_h(summary)}</summary>"
            f"<pre>{_h("\n".join(folded))}</pre>"
            "<p class=\"sub\">This block is not closed: the artefact was truncated here.</p>"
            "</details>"
        )
    flush()
    return "".join(out)


def artefact(
    item: Item, attempt: Attempt, secrets: list[str], prices: Prices | None = None
) -> str:
    """The document this attempt published, rebuilt by the module that published it.

    Which of the two an attempt got is not a rendering choice: an attempt that opened a pull
    request carried `pull_request_body` there, and one that did not carried `issue_comment` to the
    issue. Asking the same question the publisher asked keeps the page showing what happened rather
    than what would happen if it ran now.
    """
    from hullwork import evidence
    from hullwork.work import verdict_detail

    if attempt.pull_request_ref:
        return evidence.pull_request_body(
            item, attempt, detail=verdict_detail(attempt), secrets=secrets, prices=prices
        )
    return evidence.issue_comment(
        item, attempt, detail=verdict_detail(attempt), secrets=secrets, prices=prices
    )


#: What the page cannot show, said in the page's own words. Item 079 decided not to store the
#: agent's prose or the brief it was given — a decision about privacy and database size, not an
#: oversight — and a page that rendered the rest without a word would be claiming to be the
#: artefact while being a subset of it. The pull request has both; this says so and points there.
_NOT_STORED = (
    "Two parts of the published artefact are missing here, and they are missing from the database "
    "rather than from this page: the agent's own account of what it did, and the brief it was "
    "given. Neither is stored (item 079). Everything else below is assembled from the recorded "
    "steps by the same function that wrote the pull request — which is why the agent's prose was "
    "never load-bearing for a merge decision in the first place."
)


def items(session: Session, *, only: str | None = None, acting: Acting = READING) -> str:
    """Every item this instance has, most recent first. The view a reviewer lands on.

    `only` is one of the board's column keys, which is what makes a count on the front page lead
    somewhere. An unrecognised key shows everything rather than nothing: this arrives from a URL,
    and a typo in a hand-edited address should not read as an empty instance.
    """
    from sqlalchemy import func
    from sqlalchemy.orm import joinedload

    from hullwork.models import Attempt, Item

    states = _IN.get(only) if only else None
    counting = select(func.count()).select_from(Item)
    listing = select(Item).options(joinedload(Item.project))
    if states is not None:
        counting = counting.where(Item.state.in_(states))
        listing = listing.where(Item.state.in_(states))

    total = session.scalar(counting) or 0
    rows = list(session.scalars(listing.order_by(Item.last_seen.desc()).limit(MAX_ITEMS)).all())
    pulls: dict[int, str] = {}
    if rows:
        for item_id, ref in session.execute(
            select(Attempt.item_id, Attempt.pull_request_ref)
            .where(Attempt.item_id.in_([row.id for row in rows]))
            .where(Attempt.pull_request_ref.is_not(None))
            .order_by(Attempt.id)
        ):
            pulls[item_id] = ref

    body_rows = []
    for row in rows:
        reached = (
            _h(pulls[row.id])
            if row.id in pulls
            else (_h(row.forge_issue_ref) if row.forge_issue_ref else "—")
        )
        state = _h(row.state.value) + (
            ' <span class="stuck">never</span>' if _stuck(row) else ""
        )
        body_rows.append(
            "<tr>"
            f'<td><a href="items/{row.id}">#{row.id}</a></td>'
            f"<td>{_h(row.project.slug)}</td>"
            f"<td>{state}</td>"
            f"<td>{_h(row.lane.value)}</td>"
            f"<td>{_h(row.title.splitlines()[0] if row.title else '')}</td>"
            f"<td>{_h(row.last_seen)}</td>"
            f"<td>{reached}</td>"
            "</tr>"
        )

    scope = "" if states is None else f" in <strong>{_h(only)}</strong>"
    if rows:
        table = (
            '<table class="list"><tr><th>item</th><th>project</th><th>state</th><th>lane</th>'
            "<th>title</th><th>last seen</th><th>issue / pull</th></tr>"
            + "".join(body_rows)
            + "</table>"
        )
        # The bound, stated. Silently showing 200 of 4,000 is how a page teaches a reader that an
        # instance has done less than it has.
        shown = (
            f"Showing all {total} item(s)"
            if total <= MAX_ITEMS
            else f"Showing the {len(rows)} most recently seen of {total} item(s)"
        )
    else:
        table = ""
        shown = (
            "Nothing here now"
            if states is not None
            else "No items yet. Nothing has arrived from the error tracker on this instance"
        )

    everything = '' if states is None else ' · <a href="items">All items</a>'
    body = (
        "<h1>Items</h1>"
        f'<p class="sub">{shown}{scope}. Most recently seen first. '
        f'<a href="./">Instance</a>{everything}</p>' + table
    )
    return _document("Hullwork — items", body, acting=acting)


def _above_the_fold(attempt: Attempt, prices: Prices | None) -> str:
    """The four facts a reviewer should not have to unfold a block to read. Item 136.

    **Which model answered and from where** is DR-0004's whole argument and the one claim here that
    cannot be checked any other way: the gateway read it off the wire rather than taking the
    harness's word. Item 123 put it on the page inside the artefact, which is correct — the reader
    sees the artefact rather than a summary — and left it seven rows down behind a click.

    Cost and duration join it because they are the two questions asked before "is this fix any
    good": what did this cost me, and how long did it take. Both come from `hullwork.spend`, which
    reads the same seal the artefact does, so there is no second source to drift from.

    Nothing else goes here. A header that grew into a second description of the attempt would undo
    the reason the artefact is rendered at all.
    """
    seal = attempt.seal or {}
    served = seal.get("models_served") or []
    tokens = spend.tokens_of(seal)
    money = spend.cost_of(tokens, prices)
    duration = spend.elapsed(attempt)
    facts: list[str] = []
    if served:
        facts.append(f"model <code>{_h(', '.join(map(str, served)))}</code>")
    if seal.get("endpoint"):
        facts.append(f"via <code>{_h(str(seal['endpoint']))}</code>")
    if money is not None:
        facts.append(f"cost {_h(money)}")
    elif tokens.context_served is not None:
        facts.append(f"{_h(f'{tokens.context_served:,}')} tokens served")
    if not facts and duration is not None:
        # **A duration on its own is the shape of a hung attempt** (item 133, attempt 18: three
        # hours and forty-seven minutes with no seal at all). Saying why there is no spend beside it
        # is what stops a reader reading the clock as work.
        facts.append("no model answered")
    if duration is not None:
        facts.append(f"took {_h(spend.spoken(duration))}")
    if not facts:
        return ""
    return '<p class="sub">' + " · ".join(facts) + "</p>"


#: What each state is waiting for, in the second person, because the reader is the one waiting.
#:
#: **Item 166 exists because the page hedged where the state does not.** On an amber item it printed
#: *"Either this item is waiting for the dispatcher, or its lane says a human takes it"* — and the
#: state answers that. The operator read the board, saw two items twenty-one hours old, and asked
#: *"¿y ahora qué?"*; this table is the answer, on the item, in one sentence.
_WAITING_FOR: dict[ItemState, str] = {
    ItemState.NEW: "triage, which happens on the next sweep. Nothing to do.",
    ItemState.TRIAGED: "its lane to be decided, which happens on the next sweep. Nothing to do.",
    ItemState.WAITING_APPROVAL: (
        "**you**. Its lane is amber: an agent may attempt it, but only once somebody says so. "
        "Approving costs one attempt — money on the wire and a pull request for a person to read."
    ),
    ItemState.HUMAN_ONLY: (
        "**a person**, and no agent will touch it. Either its lane says so, or somebody decided so "
        "here."
    ),
    ItemState.READY: "the dispatcher, which takes one item at a time. Nothing to do.",
    ItemState.IN_PROGRESS: "the attempt running now. The phases are on the front page.",
    ItemState.PR_OPEN: (
        "**a reviewer**. Merging it accepts the fix; closing it with a label refuses it, and the "
        "label is the reason this instance records."
    ),
    ItemState.REOPENED: "triage again: it came back after being closed.",
}


def _next_action(found: Item, acting: Acting, *, up: str) -> str:
    """What is blocking this item and what a person can do about it, right here. Item 166."""
    stuck = _stuck(found)
    waiting = _WAITING_FOR.get(found.state)
    parts: list[str] = []
    if waiting:
        parts.append(f"<p><strong>Waiting for</strong> {_own_prose(waiting)}</p>")
    if stuck:
        parts.append(f'<p class="sub">But {_h(stuck)}.</p>')
    if found.state is ItemState.WAITING_APPROVAL and not stuck:
        parts.append(_decide(found, acting, up=up))
    if not parts:
        return ""
    return f'<div class="next">{"".join(parts)}</div>'


def _decide(found: Item, acting: Acting, *, up: str) -> str:
    """The two buttons, a login, or the command — whichever this request has earned.

    Three states and each one is honest about itself: a signed-in operator gets the buttons; an
    instance with a key and no session gets a login; an instance with **no operator key** gets the
    command, because that is the only way to act on it and pretending otherwise would send a reader
    looking for a login that cannot exist.
    """
    if acting.csrf is not None:
        forms = "".join(
            f'<form method="post" action="{up}items/{found.id}/{route}">'
            f'<input type="hidden" name="csrf" value="{_h(acting.csrf)}">'
            f'<button type="submit"{extra}>{label}</button></form>'
            for route, label, extra in (
                ("approve", "Let the agent try it", ' class="go"'),
                ("human", "I will take this one", ""),
            )
        )
        return f'<div class="decide">{forms}</div>'
    if acting.offered:
        return (
            f'<form method="post" action="{up}login" class="login">'
            '<input type="password" name="key" autocomplete="current-password" '
            'placeholder="operator key" aria-label="operator key" required>'
            '<button type="submit">Sign in to decide</button></form>'
        )
    return (
        '<p class="sub">This instance has no operator key, so nothing here can act. Either run '
        f"<code>hullwork approve {_h(found.project.slug)} {_h(found.id)}</code> on the host, or "
        "give the page a key with <code>hullwork operator-key</code>.</p>"
    )


def item(
    session: Session, settings: Settings, item_id: int, *, acting: Acting = READING
) -> str | None:
    """One item and every attempt on it. `None` when there is no such item, which the route 404s.

    The facts first, because a reviewer decides whether this is worth reading before reading it;
    then the attempts, oldest first, because the second attempt only makes sense after the first.
    """
    from hullwork.models import Attempt, Item

    found = session.get(Item, item_id)
    if found is None:
        return None
    tries = list(
        session.scalars(
            select(Attempt).where(Attempt.item_id == found.id).order_by(Attempt.id)
        ).all()
    )
    secrets = _secrets_for(settings)
    scrub = Scrubber(secrets, shapes=True)
    prices = spend.Prices.from_settings(settings)

    facts = [
        ("project", _h(found.project.slug)),
        ("state", _h(found.state.value)),
        ("lane", _h(found.lane.value) + (
            f" — {_h(scrub.text(found.lane_reason))}" if found.lane_reason else ""
        )),
        ("kind", _h(found.kind.value)),
        ("seen", f"{_h(found.occurrences)} time(s), first {_h(found.first_seen)}, "
                 f"last {_h(found.last_seen)}"),
        ("issue", _issue_link(settings, found)),
        ("in the tracker", _link(found.permalink) if found.permalink else "—"),
    ]
    table = "".join(f"<tr><th>{name}</th><td>{value}</td></tr>" for name, value in facts)

    blocks = []
    for number, attempt in enumerate(tries, start=1):
        heading = (
            f"Attempt {number} — {_h(attempt.outcome.value if attempt.outcome else 'no outcome')}"
            f", reached <code>{_h(attempt.phase_reached.value)}</code>"
        )
        marks = []
        if attempt.rehearsal:
            marks.append("a rehearsal: it published nothing and counts towards nothing")
        if not attempt.consumed:
            marks.append(
                "did not use up this item's one attempt"
                + (f" — {_h(scrub.text(attempt.not_consumed_reason))}"
                   if attempt.not_consumed_reason else "")
            )
        if attempt.pull_request_ref:
            marks.append(f"pull request {_h(attempt.pull_request_ref)}")
        if attempt.merge_commit:
            marks.append(f"merged as <code>{_h(attempt.merge_commit[:12])}</code>")
        blocks.append(
            f"<h2>{heading}</h2>"
            f'<p class="sub">Started {_h(attempt.started_at)}'
            + ("".join(f" · {mark}" for mark in marks))
            + "</p>"
            + _above_the_fold(attempt, prices)
            + (
                _folded(artefact(found, attempt, secrets, prices))
                if attempt.steps
                else '<p class="sub">No steps were recorded: this attempt stopped before it ran '
                     "anything, so there is no evidence trail to show.</p>"
            )
        )

    title = found.title.splitlines()[0] if found.title else f"item {found.id}"
    body = (
        f"<h1>#{_h(found.id)} {_h(title)}</h1>"
        f'<p class="sub"><a href="../items">All items</a> · <a href="../">Instance</a></p>'
        f"<table>{table}</table>"
        + _next_action(found, acting, up="../")
        + (
            f'<p class="sub">{_h(_NOT_STORED)}</p>' + "".join(blocks)
            if blocks
            # **No longer "either … or".** What it is waiting for is stated above, from the state,
            # and this line now says only the thing the state cannot: that there is no evidence
            # trail yet because nothing has run.
            else '<p class="sub">No attempts yet, so there is no evidence to read here.</p>'
        )
    )
    return _document(f"Hullwork — item {found.id}", body, acting=acting, up="../")


def _issue_link(settings: Settings, found: Item) -> str:
    """The item's issue, as a link when this instance can say where its own forge keeps them.

    Built from the forge's base URL and the repository rather than stored, because nothing stores
    it — and a link that is wrong is a dead click, while no link at all is a reviewer copying a
    number into a search box.
    """
    ref = found.forge_issue_ref
    if not ref:
        return "never filed"
    number = ref.lstrip("#")
    if not number.isdigit():
        return _h(ref)
    repo = found.project.repo
    if found.project.forge == "github":
        return _link(f"https://github.com/{repo}/issues/{number}", ref)
    base = str(settings.forge_url).rstrip("/") if settings.forge_url else ""
    if not base:
        return _h(ref)
    # GitLab puts `-` between the project path and the resource. Without it the link resolves to a
    # subgroup of that name: a 404 that reads like a deleted issue (item 132).
    if found.project.forge == "gitlab":
        return _link(f"{base}/{repo}/-/issues/{number}", ref)
    return _link(f"{base}/{repo}/issues/{number}", ref)
