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
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from sqlalchemy import func, select

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


#: The path segment that means *ask my session instead of a token* (DR-0021). Short, and shorter
#: than anything `generate_token` can produce, which is what stops a minted token ever
#: colliding with it — a collision would open the page for anybody signed in and close it for the
#: person
#: holding the link.
MINE = "me"


def opens(session: Session, token: str, *, acting: Acting | None = None) -> bool:
    """Whether this request may read the page. Constant time, and the same cost when there is no
    page.

    A missing row must not answer faster than a wrong token: the difference would say *"this
    instance has a page and you have the wrong key"*, which is the one bit of information the `404`
    is there to withhold.

    **And a token is not the only way in** (DR-0021). The person who ran `page-token` reached it
    through a shell on the host — they can already read this database, the environment file and the
    Docker socket, so withholding their own page's URL from them protects nothing they do not
    have. An operator with a session reads at `MINE`, and the token keeps the job it is good at:
    handing
    reading to somebody with no account, revocably.

    Reading, not acting. `Acting` is what the renderer decides the second question from, and this
    function answers only the first — item 166's split, which DR-0021 keeps.

    **The `MINE` door exists only where a password is configured.** Everything else answers `404`,
    including a wrong token, so the page cannot be found by probing; a login at a fixed path would
    end that for every instance rather than for the ones that opted in. `offered` is exactly that
    opt-in — `operator.configured` — so an instance with no password is as undiscoverable as before.
    """
    if token == MINE:
        return bool(acting and acting.csrf)
    access = session.scalars(select(PageAccess).limit(1)).one_or_none()
    expected = access.token_hash if access is not None else _DECOY_HASH
    return verify_token(token, expected) and access is not None


def the_url_is_the_credential(token: str) -> bool:
    """Whether this request is reading through a minted URL rather than through its session.

    **Asked by the one action that revokes it** (item 250). `page-token` mints a new read link and
    stops every old one — including, when the answer is served at one of them, the URL it is being
    read on: every link on that answer is correctly written and every one of them answers `404`.
    Saying so is the difference between a reader who opens the new link and one who clicks.

    Here rather than in the route, because `MINE` is this module's reserved word and a route that
    knows it is a route with an opinion about the gate — which is the property
    `test_there_is_one_gate_and_not_ten` exists to keep, at four days' cost across items 193, 194,
    200 and 203.
    """
    return token != MINE


def offers_a_login(token: str, acting: Acting | None) -> bool:
    """Whether a request that may not read should be shown the login rather than a `404`.

    **Two questions, and collapsing them is the bug I wrote first** (item 204). *May this request
    see the page* and *may it be told there is a login* are different, and answering the second with
    the first rendered the whole instance to anybody who typed `/page/me/`.

    So: the content needs a session, and the door needs only the opt-in. An instance with no
    password
    configured offers nothing and is `404` like everything else, which is the property DR-0021
    spends
    nothing of.
    """
    return token == MINE and bool(acting and acting.offered)


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
    return _emphasised(_h(text))


def _emphasised(already_escaped: str) -> str:
    """The `**…**` half of `_own_prose`, on text that has been through `_h` already.

    Separate because `_as_code` needs it and had already escaped and inserted its own `<code>`
    tags: running the whole of `_own_prose` over that would escape the markup this module just
    wrote, and serve `&lt;code&gt;` to a reader.
    """
    return re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", already_escaped)


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
/* The visual system, inlined. Item 169 rebuilt it after the operator's verdict on item 167's
   information design: "sigue siendo horriblemente fea". He was right — that pass fixed what the
   page said and never touched how it looked, so it inherited item 143's austere tokens and read as
   unstyled HTML with a brown link colour.

   The direction is an instrument panel, and the first decision is that there is no decorative
   accent: Colour means state here and nothing else: amber is the operator's own queue, blue the
   machine, green and red the outcomes. A page about whether a robot may touch your code has no
   business having a brand hue competing with those four.

   The lede was set in the monospace face for one revision, on the theory that the page's headline
   is the machine's own summary of itself and a machine's voice is monospace. Rendered, it read as
   terminal output rather than as a headline: mono at display size with negative tracking fights
   itself, and two wrapped lines of it look like a log. It is sans now, with the weight and tracking
   a headline needs, and mono keeps the job it is good at — data, ages, identifiers, commands.

   No external asset, no script, one stylesheet, both themes from one set of tokens. */

:root {
  color-scheme: light dark;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;

  /* Neutrals with a cool bias, chosen rather than inherited: a pure grey reads as nobody's
     decision, and this page is a panel rather than a document. */
  --ink:    light-dark(#101319, #e9ebf0);
  --muted:  light-dark(#5a6270, #979fae);
  /* Was #8b93a1/#666e7d, which carried the footer at 2.73:1 light and 3.90:1 dark —
     under AA, on the sentence that explains what the URL is. Measured, not adjusted
     by eye: these are the nearest values clearing 4.5:1 on all three surfaces. */
  --faint:  light-dark(#656d7b, #7d8593);
  --rule:   light-dark(#dfe3ea, #232833);
  --canvas: light-dark(#eef1f5, #070910);
  --raise:  light-dark(#ffffff, #14171e);
  --sunk:   light-dark(#f0f2f6, #10131a);

  --waiting: light-dark(#9a5b00, #f0b352);
  --working: light-dark(#1a56c4, #7cb0f7);
  --passed:  light-dark(#0f6b39, #52bb83);
  --refused: light-dark(#ab2f22, #f0847a);
  --human:   light-dark(#5638ad, #b193f5);

  /* The type scale (item 213). Twelve size/weight pairs were on one page and twenty distinct
     sizes in this stylesheet, eight of them two-decimal one-offs: each reasonable where it was
     written, none of them reasonable together. Nine steps, and a rule may only name a step. */
  --t-2xs:  .6875rem;
  --t-xs:   .75rem;
  --t-sm:   .8125rem;
  --t-md:   .875rem;
  --t-base: .9375rem;
  --t-lg:   1.0625rem;
  --t-xl:   1.375rem;
  --t-2xl:  1.75rem;
  --t-3xl:  2.25rem;

  /* How wide a line of prose is allowed to get. The shell fills the window; sentences do not. */
  --measure: 68ch;

  --r: 8px;
  --r-chip: 5px;
  --pad: 1.15rem;
}

* { box-sizing: border-box; }

html { -webkit-text-size-adjust: 100%; }

body {
  margin: 0;
  background: var(--canvas);
  color: var(--ink);
  font: 400 var(--t-base)/1.55 var(--sans);
  font-synthesis-weight: none;
  -webkit-font-smoothing: antialiased;
}

/* The shell (item 213). At 1680px the work used 43% of the window: a 62rem measure is a width
   for a document, and this is a panel. The window is filled and the sentences inside it are held
   to `--measure`, because the fix for dead margins is not 120-character lines. */
.wrap { max-width: 108rem; margin: 0 auto; padding: 0 2rem 4rem; }
.sheet > p, .sheet > .sub, .sheet .why, footer { max-width: var(--measure); }
/* And the same measure inside a fold. A child selector cannot see them: everything a `<details>`
   holds is one level deeper than the sheet, so the prose under an open fold ran the full 1500px
   while the identical sentence above it was held to 68ch.
   `.folded` and not `details >`, because `_fold` wraps its body in that div — the first version of
   this rule named a structure the page does not have, and the browser found it in ten seconds. */
.sheet .folded > p, .sheet .folded > .sub { max-width: var(--measure); }
/* A headline needs a shorter measure than a paragraph, and `ch` is relative to the element's own
   size: 68ch at 28px came out 1170px wide, which is a measure in name only. */
.sheet .lede { max-width: 34ch; }

a { color: inherit; text-decoration-thickness: 1px; text-underline-offset: 3px;
    text-decoration-color: color-mix(in oklab, currentColor 35%, transparent); }
a:hover { text-decoration-color: currentColor; }
:focus-visible { outline: 2px solid var(--working); outline-offset: 2px; border-radius: 3px; }

/* --- the top edge, which the page did not have ----------------------------------------------- */

.bar {
  display: flex; align-items: center; gap: .7rem;
  padding: 1rem 0 .9rem; margin-bottom: 1.6rem;
  border-bottom: 1px solid var(--rule);
}
.mark { font: 600 var(--t-lg)/1 var(--mono); color: var(--ink); text-decoration: none;
        /* WCAG 2.2 AA 2.5.8 asks 24x24 CSS px, and this measured 10x17 (item 215). It is
           a standalone control rather than a link inside a sentence, so the Inline
           exception does not reach it. */
        display: inline-flex; align-items: center; justify-content: center;
        min-width: 24px; min-height: 24px; }
.word { font: 600 var(--t-base)/1 var(--sans); letter-spacing: .01em; }
.bar .spacer { flex: 1; }
.pill {
  font: 550 var(--t-2xs)/1 var(--sans); letter-spacing: .07em; text-transform: uppercase;
  padding: .32rem .5rem; border-radius: var(--r-chip);
  border: 1px solid color-mix(in oklab, var(--c, var(--faint)) 40%, transparent);
  background: color-mix(in oklab, var(--c, var(--faint)) 9%, transparent);
  color: var(--c, var(--muted));
}
.pill.ok   { --c: var(--passed); }
.pill.bad  { --c: var(--refused); }
.pill.mine { --c: var(--waiting); }

/* The gate, as one line. A test that failed against unmodified code passes with the change applied:
   that sentence is the whole claim this product makes, and it is the only decoration on the page.
   Two pixels, under the header, and nowhere else — a motif that repeats is wallpaper. */
.bar { position: relative; border-bottom: 0; padding-bottom: 1rem; }
.bar::after {
  content: ""; position: absolute; left: 0; right: 0; bottom: 0; height: 3px;
  /* A hard-ish transition rather than a long fade: the gate is a change of state, not a gradient,
     and a 1500px-wide blend reads as no colour at all. */
  background: linear-gradient(90deg,
    var(--refused) 0%, var(--refused) 26%,
    color-mix(in oklab, var(--refused) 40%, var(--passed)) 44%,
    var(--passed) 62%, var(--passed) 100%);
  border-radius: 3px;
}

/* --- what this instance has proved, which is what a stranger came for ------------------------ */

.proof {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(7.5rem, 1fr));
  background: var(--raise); border: 1px solid var(--rule); border-radius: var(--r);
  margin: 0 0 1.4rem; overflow: hidden;
}
.cell { padding: 1rem var(--pad) .95rem; border-right: 1px solid var(--rule);
        display: flex; flex-direction: column; gap: .15rem; }
.cell:last-child { border-right: 0; }
.big {
  /* Sans, and this is the one place mono loses. Menlo and its neighbours draw a slashed zero, which
     is right in a terminal and reads as Ø at 2.4rem — a different glyph in the middle of a figure,
     and `font-feature-settings: "zero" 0` does not turn it off because for that face it is not a
     feature, it is the glyph. Tabular numerals keep the columns aligned, which was the reason for
     mono here in the first place. */
  font: 600 var(--t-3xl)/1 var(--sans); font-variant-numeric: tabular-nums lining-nums;
  letter-spacing: -.035em; color: var(--ink);
}
/* Green only when there is something to be green about: a green `0` under HELD says "good" where it
   means "none has cleared the window yet", which is the kind of figure that flatters itself. */
.cell.won  .big { color: var(--passed); }
.cell.won.none .big, .cell.lost.none .big { color: var(--ink); }
.cell.lost .big { color: var(--refused); }
.name { font: 550 var(--t-2xs)/1 var(--sans); letter-spacing: .08em; text-transform: uppercase;
        color: var(--muted); margin-top: .35rem; }
.gloss { font: 400 var(--t-xs)/1.35 var(--sans); color: var(--faint); }

/* --- the answer ------------------------------------------------------------------------------ */

.answer {
  background: var(--raise); border: 1px solid var(--rule); border-radius: var(--r);
  border-left: 3px solid var(--c, var(--faint));
  padding: var(--pad) calc(var(--pad) + .2rem);
  margin: 0 0 1.5rem;
}
.answer.mine { --c: var(--waiting); }
.answer.bad  { --c: var(--refused); }
.answer.calm { --c: var(--passed); }
/* The sentence is set in ink and the stripe on the panel carries the state. Colouring 1.7rem of
   text amber is what made this look dated, and it was redundant: the reader already knows whose
   queue it is from the stripe, and colour is worth more where it is scarce. A problem is the one
   exception, below, because red there is the message and not a label. */
.lede {
  font: 450 var(--t-2xl)/1.28 var(--sans);
  letter-spacing: -.022em; margin: 0; text-wrap: pretty; max-width: 44ch;
  color: var(--ink);
}
.lede.bad { color: var(--refused); }
.lede .also { font: 400 var(--t-base)/1 var(--sans); color: var(--muted); letter-spacing: 0; }
.answer .sub { margin: .7rem 0 0; }

/* --- the decisions --------------------------------------------------------------------------- */

/* One card with divided rows, not one card per row: six equally-bordered boxes on a screen is the
   same failure as six equally-weighted columns, in a different shape. */
/* --- what this instance has switched on (items 203, 208) ------------------------------------
   A panel, not the `decisions` list it borrowed at first: that one carries a fixed amber left
   border because it means *waiting for you*, so a `cannot` row sat inside an amber stripe and the
   severity read as the panel's rather than the row's.

   Two columns, and the point of them is the first: the states line up on one edge, so the panel is
   scanned down rather than read across. The stripe is per row for the same reason. */
.standing {
  list-style: none;
  padding: 0;
  margin: 0 0 1.4rem;
  background: var(--raise);
  border: 1px solid var(--rule);
  border-radius: var(--r);
  overflow: hidden;
}
.standing li {
  display: grid;
  grid-template-columns: 6.2rem 1fr;
  gap: 0 .85rem;
  align-items: baseline;
  padding: .8rem var(--pad) .8rem calc(var(--pad) - 3px);
  border-left: 3px solid var(--c, var(--faint));
  border-top: 1px solid var(--rule);
}
.standing li:first-child { border-top: 0; }
/* A disclosure inside a row spans it (item 236). Left in the first column it inherits the pill's
   6.2rem and sets its summary five words deep, one word per line. */
.standing li > details { grid-column: 1 / -1; margin: .5rem 0 0; border: 0; background: none; }
.standing li > details > summary { padding: 0; font-size: var(--t-md); }
.standing li > details > .folded { padding: .4rem 0 0; }
.standing .pill { justify-self: start; color: var(--c, var(--faint)); border-color: currentColor; }
.standing .name { font-weight: 550; color: var(--ink); }
/* A sentence is not a label (item 242). `.name` is set in small caps because it holds a thing's
   name — `CRYPTOGRAPHY 48.0.1` — and the history holds whole sentences, which small caps makes
   slower to read and louder than the thing they describe. */
.standing .said { color: var(--ink); text-transform: none; letter-spacing: 0;
                  font: 400 var(--t-md)/1.45 var(--sans); }
.standing .why {
  grid-column: 2;
  color: var(--muted);
  font-size: var(--t-md);
  margin: .2rem 0 0;
  /* These are read, not scanned, so they get a measure. Seen only by opening the page: the rows
     ran to about 110 characters on a wide window, which is a paragraph pretending to be a row. */
  max-width: 62ch;
}
/* Tight horizontally on purpose. Seen on screen: `.3em` of padding pushes a following comma far
   enough away to read as a typographic error — `page-token ,` — so the chip is snug and earns its
   separation from the background rather than from space. */
.standing code {
  font: var(--t-sm)/1.35 var(--mono);
  background: var(--sunk);
  padding: .05em .18em;
  border-radius: 3px;
  border: 1px solid var(--rule);
}
@media (max-width: 34rem) {
  .standing li { grid-template-columns: 1fr; gap: .35rem 0; }
  .standing .why { grid-column: 1; }
}

/* --- the subject table (DR-0028) ------------------------------------------------------------
   A component and not this view's markup: the same shape is going to the door, to Errors, to This
   instance and to Projects, and a table invented four times is four tables that drift.

   The row is the subject. Everything known about it is in it, at a fixed height, aligned in
   columns — 42px against the 164px the card-paragraph it replaces spent on three facts. What made
   that view 12.6 screens was not the amount of information; it was that each fact was a paragraph
   and the outcome lived in a second list. */
.tally {
  display: flex; flex-wrap: wrap; gap: .3rem 1.1rem;
  font-size: var(--t-sm); color: var(--muted);
  padding: .55rem .8rem; margin: 0 0 1.3rem;
  background: var(--raise); border: 1px solid var(--rule); border-radius: var(--r);
}
.tally b { color: var(--ink); font-variant-numeric: tabular-nums; margin-right: .15rem; }
.band { margin: 0 0 1.5rem; }
/* The heading carries the sentence, once. A row that repeats it is the column that must not
   exist. */
.band h3 {
  display: flex; align-items: baseline; gap: .6rem;
  margin: 0 0 .2rem; font: 600 var(--t-md)/1.4 var(--sans); color: var(--ink);
}
.band h3 em { font-style: normal; font-weight: 400; color: var(--faint); font-size: var(--t-sm);
              flex: 1; }
.band h3 > b { font: 400 var(--t-sm)/1 var(--sans); color: var(--faint);
               font-variant-numeric: tabular-nums; }
/* Fixed, so one long row cannot set the width of the table. A package pinned three times and fixed
   on four branches stretched it to 7,208px before the model stopped pairing every version with
   every destination — and a table that can be widened by its contents will be, eventually. */
.subjects { width: 100%; border-collapse: collapse; table-layout: fixed; }
.subjects tr { border-top: 1px solid var(--rule); }
.subjects tr:hover { background: var(--sunk); }
.subjects td { padding: 0 .6rem; height: 2.6rem; vertical-align: middle; }
.subjects td:first-child { padding-left: 0; }
.subjects td:last-child { padding-right: 0; text-align: right; }
.dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; margin-right: .55rem;
       background: var(--c, var(--faint)); vertical-align: 1px; }
.dot.passed  { --c: var(--passed); }
.dot.refused { --c: var(--refused); }
.dot.human   { --c: var(--human); }
.dot.working { --c: var(--working); }
.dot.waiting { --c: var(--waiting); }
.dot.faint   { --c: var(--faint); }
.who { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.who .thing { font-weight: 550; margin-right: .5rem; }
/* Versions and paths are compared, not read: monospaced so a digit sits under a digit. */
.who .was, .who .to, .at { font: var(--t-sm)/1.4 var(--mono); }
.who .was { color: var(--muted); }
.who .to { color: var(--ink); }
.who .arr { color: var(--faint); margin: 0 .35rem; }
.who .note { color: var(--refused); font-size: var(--t-sm); margin-left: .55rem; }
/* A row whose subject is a sentence rather than a name: the item's own title. It takes the space
   the versions take on a dependency row, and it is the one thing in the row allowed to be long. */
.who .said { color: var(--muted); margin-left: .55rem; }
.subjects .do a { font-size: var(--t-sm); }
/* Context, and it has a known maximum — a lock file's path, or a slug and a lane. Given a width,
   the subject takes everything else; without one a fixed table split the remainder evenly and cut
   the item's title at eight words while `hullwork · amber` sat in twelve rem of air. */
.at { color: var(--faint); text-align: right; white-space: nowrap; width: 15rem;
      overflow: hidden; text-overflow: ellipsis; }
.subjects .fold { width: 3rem; text-align: right; }
.subjects details.adv { border: 0; background: none; margin: 0; display: inline-block;
                        position: relative; }
.subjects details.adv > summary {
  padding: .05rem .4rem; font: var(--t-xs)/1.5 var(--sans); color: var(--faint);
  font-variant-numeric: tabular-nums; border: 1px solid var(--rule); border-radius: var(--r-chip);
}
.subjects details.adv[open] > summary { color: var(--ink); border-color: var(--faint); }
.subjects details.adv > .folded {
  position: absolute; right: 0; z-index: 3; width: min(30rem, 70vw); text-align: left;
  margin-top: .35rem; padding: .6rem .8rem;
  background: var(--raise); border: 1px solid var(--rule); border-radius: var(--r);
  box-shadow: 0 10px 28px light-dark(rgba(16,19,25,.13), rgba(0,0,0,.5));
  font-size: var(--t-sm); list-style: none;
}
.subjects details.adv > .folded li { margin: .35rem 0; color: var(--muted); }
.subjects details.adv > .folded li a { font: var(--t-xs)/1.4 var(--mono); margin-right: .4rem; }
.subjects .do { width: 9.5rem; }
/* A subject that is a sentence needs the width a button was holding. An item's title is the
   most informative thing in its row and eighteen of twenty-eight were being cut at eight words,
   while the column beside them held `#24`. The dependency table keeps the wider one: its action is
   a button with words in it. Two contents, two widths, one component. */
.subjects.narrow .do { width: 4.5rem; }

/* A figure and what it counts (item 248). The number is the thing being compared, so it is
   tabular, right-aligned in its own column, and set at the size the strip uses — the six sections
   that were prose bullets put it mid-sentence, where two of them never line up. */
.figures { width: 100%; border-collapse: collapse; }
.figures tr { border-top: 1px solid var(--rule); }
.figures tr:first-child { border-top: 0; }
.figures td { padding: .22rem 0; vertical-align: baseline; }
/* Set at body size rather than at the strip's: the strip has five numbers and this has five rows,
   so what makes one scannable here is the column and the tabular figures, not the size. Rendered
   large with the caveat on its own line it made this view *taller* than the bullets it replaced,
   which is the opposite of the point. */
.fig { width: 3.2rem; text-align: right; padding-right: .8rem !important;
       font: 600 var(--t-base)/1.45 var(--sans); font-variant-numeric: tabular-nums;
       color: var(--ink); }
.means { color: var(--ink); }
.caveat { color: var(--faint); font-size: var(--t-sm); margin-left: .5rem; }
.subjects.narrow .at { width: 13rem; }
.subjects .do form { margin: 0; }
.subjects .do button { font-size: var(--t-sm); padding: .25rem .6rem; }
/* Below this the row stops being a row (item 221's rule, kept). Hiding the context instead was
   tried and is worse: the project, the lane and the time are how a reader tells two failures of the
   same kind apart, and a list that drops them is a list of titles. Two lines rather than the seven
   the old table stacked — the subject, then everything about it, then anything to do. */
@media (max-width: 46rem) {
  .subjects, .subjects tbody, .subjects tr, .subjects td { display: block; }
  .subjects tr.subject { padding: .5rem 0; }
  .subjects td { height: auto; padding: 0; width: auto; text-align: left; }
  .subjects .who { white-space: normal; overflow: visible; }
  .subjects .at, .subjects .fold {
    display: inline-block; width: auto; text-align: left; margin: .25rem .7rem 0 0;
    font-size: var(--t-xs);
  }
  .subjects .do { margin-top: .35rem; }
  .subjects .do:empty { margin: 0; }
}

/* --- the rail (item 212, DR-0023) -----------------------------------------------------------
   Furniture. It does not scroll away and it does not move between pages, so what exists is never
   something a person has to remember.

   Two shapes, one markup: down the left where there is room, which is the shape the decision
   named and the one that leaves the whole width to the work; a row of tabs under a narrow window,
   where a column of five nouns would cost more of the screen than the page it navigates. */
.rail {
  display: flex;
  flex-direction: row;
  gap: 0 1.4rem;
  padding: .3rem 0 0;
  margin: 0 0 1.4rem;
  border-bottom: 1px solid var(--rule);
  overflow-x: auto;
}
.rail a {
  padding: .5rem .1rem;
  color: var(--muted);
  text-decoration: none;
  white-space: nowrap;
  border-bottom: 2px solid transparent;
}
.rail a:hover { color: var(--ink); }
.rail a[aria-current="page"] {
  color: var(--ink);
  font-weight: 550;
  border-bottom-color: var(--ink);
}

@media (min-width: 60rem) {
  .wrap {
    display: grid;
    grid-template-columns: 13.5rem minmax(0, 1fr);
    column-gap: 3rem;
    align-items: start;
  }
  .bar, footer { grid-column: 1 / -1; }
  .rail {
    grid-column: 1;
    flex-direction: column;
    gap: .1rem;
    padding: 0;
    margin: 0;
    border-bottom: 0;
    overflow-x: visible;
    position: sticky;
    top: 1.5rem;
  }
  .rail a {
    padding: .35rem .6rem;
    border-bottom: 0;
    border-left: 2px solid transparent;
    border-radius: 0 var(--r) var(--r) 0;
  }
  .rail a:hover { background: var(--raise); }
  .rail a[aria-current="page"] {
    border-left-color: var(--ink);
    background: var(--raise);
  }
  .sheet { grid-column: 2; min-width: 0; }
}

/* How much is behind each name (item 235). Tabular so the column of numbers lines up, and pushed
   to the right edge of the link so the words stay left-aligned and scannable. */
.rail a { display: flex; align-items: baseline; gap: .5rem; }
.rail .count {
  margin-left: auto;
  font: 500 var(--t-2xs)/1 var(--sans);
  font-variant-numeric: tabular-nums;
  color: var(--faint);
}
.rail a[aria-current="page"] .count, .rail a:hover .count { color: var(--muted); }

/* A feature's section (item 235, DR-0027): a label, the sentence under it, then the thing.
   The gap above a section is what separates two features on a page that no longer folds them. */
.feature { margin: 2.4rem 0 0; }
.feature:first-of-type { margin-top: 1.6rem; }
.feature > h2 { margin-top: 0; }
.says { margin: -.35rem 0 .9rem; max-width: var(--measure);
        font-size: var(--t-md); color: var(--muted); }

/* The heading row and the primary action on it (item 214). The action wraps under the title on a
   narrow window rather than squeezing both, because a button that is half a word wide is not a
   button. */
.head { display: flex; flex-wrap: wrap; align-items: baseline;
        justify-content: space-between; gap: .75rem 1.5rem; }
.head h1 { margin-bottom: .2rem; }
details.primary { margin: 0 0 .6rem; }
details.primary > summary {
  display: inline-block; list-style: none; cursor: pointer;
  font: 550 var(--t-md)/1 var(--sans); padding: .55rem .9rem;
  border: 1px solid color-mix(in oklab, var(--working) 40%, var(--rule));
  border-radius: var(--r-chip); background: var(--raise); color: var(--working);
}
details.primary > summary::-webkit-details-marker { display: none; }
details.primary > summary::before { content: "+"; margin-right: .4rem; font-weight: 600; }
details.primary[open] > summary::before { content: "\\2212 "; }
details.primary > summary:hover { background: var(--sunk); }
details.primary[open] {
  flex: 1 1 100%; background: var(--raise); border: 1px solid var(--rule);
  border-radius: var(--r); padding: var(--pad); margin-top: .4rem;
}
details.primary[open] > summary { border: 0; background: none; padding: .2rem 0 .4rem;
                                  min-height: 24px; }

/* The one control on the page that creates something (item 213). */
.new { display: flex; flex-wrap: wrap; align-items: end; gap: .75rem; margin: 1.4rem 0 0; }
.field { display: flex; flex-direction: column; gap: .3rem; margin: 0; }
.field label { font: 550 var(--t-2xs)/1 var(--sans); letter-spacing: .06em;
               text-transform: uppercase; color: var(--muted); }
.field input {
  font: 400 var(--t-md)/1 var(--mono); padding: .5rem .6rem; min-width: 12rem;
  border: 1px solid var(--rule); border-radius: var(--r-chip);
  background: var(--canvas); color: var(--ink);
}
.new button { align-self: end; }

/* A limit reads as description, not as a blocker (item 220). They sit beside the reason a feature
   is off and they are a different kind of sentence: true either way, and the honest half. */
.why.limit { color: var(--muted); padding-left: .8rem; border-left: 2px solid var(--rule); }

.decisions {
  list-style: none; padding: 0; margin: 0 0 1.4rem;
  background: var(--raise); border: 1px solid var(--rule); border-radius: var(--r);
  border-left: 3px solid var(--waiting); overflow: hidden;
}
.decision { padding: .85rem var(--pad); border-top: 1px solid var(--rule); }
.decision:first-child { border-top: 0; }
.decision .what { display: block; font-weight: 550; font-size: var(--t-base); }
.decision .meta { display: block; font: 400 var(--t-sm)/1.5 var(--mono); color: var(--muted);
                  margin-top: .3rem; }
.decision .decide { margin-top: .7rem; }
.decision .sub { margin: .5rem 0 0; }
/* The "how to sign in" line belongs to the card above it, not to the gap below. */
.decisions + .how { margin: -1.1rem 0 1.4rem; padding: 0 var(--pad);
                    font-size: var(--t-sm); color: var(--muted); }

/* --- what it is doing ------------------------------------------------------------------------ */

.band {
  background: var(--raise); border: 1px solid var(--rule); border-radius: var(--r);
  padding: var(--pad); margin: 0 0 1.1rem;
}
.band.quiet { background: var(--sunk); }
.band > :first-child { margin-top: 0; }
.band > :last-child { margin-bottom: 0; }

.phases { display: flex; flex-wrap: wrap; gap: .35rem; margin: .8rem 0 0; padding: 0;
          list-style: none; }
.phase { font: 500 var(--t-xs)/1 var(--mono); letter-spacing: .02em;
         padding: .38rem .5rem; border-radius: var(--r-chip);
         border: 1px solid var(--rule); color: var(--faint); }
.phase.done { color: var(--passed);
              border-color: color-mix(in oklab, var(--passed) 35%, transparent);
              background: color-mix(in oklab, var(--passed) 9%, transparent); }
.phase.live { color: var(--working);
              border-color: color-mix(in oklab, var(--working) 45%, transparent);
              background: color-mix(in oklab, var(--working) 11%, transparent); }

.chip { display: inline-flex; align-items: center; gap: .35rem;
        font: 550 var(--t-xs)/1 var(--sans); letter-spacing: .02em;
        padding: .34rem .5rem; border-radius: var(--r-chip);
        border: 1px solid color-mix(in oklab, var(--c, var(--faint)) 35%, transparent);
        background: color-mix(in oklab, var(--c, var(--faint)) 9%, transparent);
        color: var(--c, var(--muted)); }
.chip::before { content: "●"; font-size: var(--t-2xs); }
.c-working { --c: var(--working); } .c-waiting { --c: var(--waiting); }
.c-passed  { --c: var(--passed);  } .c-refused { --c: var(--refused); }
.c-idle    { --c: var(--faint);   } .c-human   { --c: var(--human);   }

/* --- the machine, as one row ----------------------------------------------------------------- */

/* The live queue, and it must not look like the record above it. Same figures, different job:
   that one is what this instance has proved, this one is what is in flight right now. Sunk, no
   border, smaller — a caption to the page rather than a headline. */
.strip {
  display: flex; flex-wrap: wrap; gap: 0 1.6rem;
  padding: .7rem var(--pad); margin: 0 0 1.2rem;
  background: var(--sunk); border-radius: var(--r);
}
.tally { display: flex; align-items: baseline; gap: .4rem; }
.fig { font: 550 var(--t-lg)/1 var(--mono); font-variant-numeric: tabular-nums; color: var(--ink);
       font-feature-settings: "zero" 0; text-decoration: none; }
a.fig { text-decoration-color: color-mix(in oklab, currentColor 35%, transparent); }
a.fig:hover { text-decoration: underline; }
.fig.zero { color: var(--faint); font-weight: 400; }
.cap { font: 400 var(--t-xs)/1 var(--sans); color: var(--muted); letter-spacing: .01em; }

/* --- the item's own views, which the first pass of item 169 left behind ---------------------- */

/* An audit of emitted classes against defined selectors found four orphans after the stylesheet was
   rewritten: this one, .board, .age and .faint. The markup kept emitting them and nothing styled
   them, so the item view and the project view rendered as bare tables while the front page had been
   redressed. Measured by comparing the two sets rather than by clicking around. */
.next {
  background: var(--raise); border: 1px solid var(--rule); border-radius: var(--r);
  border-left: 3px solid var(--waiting);
  padding: var(--pad); margin: 1.2rem 0;
}
.next > :first-child { margin-top: 0; }
.next > :last-child { margin-bottom: 0; }
.next .decide { margin-top: .8rem; }

/* The project view's own copy of the board, which shares `_COLUMNS` with the instance strip so the
   two can never disagree about what a column means. */
/* Six tallies in a wrapping row of five left `closed` alone across the full width, and two-word
   labels broke over two lines so one row's cards stood taller than the next. A grid that fits its
   own columns can do neither. */
.board { display: grid; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr));
         gap: .6rem; margin: 0 0 1.2rem; }
.col { background: var(--raise); border: 1px solid var(--rule);
       border-radius: var(--r); padding: .8rem var(--pad); }
/* `.count` had no rule at all — so a project's numbers rendered at paragraph size under labels
   set in caps — the label outranking the number it labels, on the one view where you compare them.
   The instance report sets the same pair at 34px and 11.5px. */
.count { display: block; font: 600 var(--t-2xl)/1 var(--sans); color: var(--ink);
         font-variant-numeric: tabular-nums; }
.count.zero { color: var(--faint); font-weight: 450; }
.col.owed { border-left: 3px solid var(--waiting); }
.age { display: block; font: 400 var(--t-xs)/1 var(--sans); color: var(--muted);
       margin-top: .4rem; }
.faint { color: var(--faint); }

/* --- the line that says the checks ran ------------------------------------------------------- */

.settled { display: flex; align-items: baseline; gap: .45rem;
           font-size: var(--t-sm); color: var(--muted); margin: 0 0 1.4rem; }
.settled::before { content: "✓"; color: var(--passed); font-weight: 600; }

/* --- everything the evaluator wants, as one block rather than five rules --------------------- */

.more { border: 1px solid var(--rule); border-radius: var(--r); background: var(--raise);
        margin: 1.6rem 0 0; overflow: hidden; }
.more > details { border: 0; border-top: 1px solid var(--rule); }
.more > details:first-child { border-top: 0; }
details > summary {
  cursor: pointer; padding: .8rem var(--pad); list-style: none;
  font: 500 var(--t-md)/1.4 var(--sans); color: var(--muted);
  display: flex; align-items: center; gap: .55rem;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "+"; font: 400 var(--t-md)/1 var(--mono); color: var(--faint);
                            width: .7rem; text-align: center; }
/* The typographic minus, which pairs the + above rather than a hyphen. */
/* The escape is doubled for Python before it is an escape for CSS (item 219): this is an ordinary
   triple-quoted string, so a single-backslash 2212 is read as an octal escape first. The served
   stylesheet carried a raw U+0091 control character and a literal digit — the stray 2 beside every
   open fold, on every release so far. Comments here reach the browser: no markdown, no escapes. */
details[open] > summary::before { content: "\\2212 "; }
details > summary:hover { color: var(--ink); background: var(--sunk); }
.folded { padding: 0 var(--pad) 1.1rem; }
.folded > :first-child { margin-top: 0; }

/* --- type --------------------------------------------------------------------------------- */

h1 { font: 600 var(--t-xl)/1.25 var(--sans); letter-spacing: -.015em; margin: 0 0 .3rem;
     text-wrap: balance; }
h2 { font: 600 var(--t-sm)/1 var(--sans); letter-spacing: .07em; text-transform: uppercase;
     color: var(--faint); margin: 1.8rem 0 .7rem; }
h4 { font: 550 var(--t-xs)/1 var(--sans); letter-spacing: .06em; text-transform: uppercase;
     color: var(--faint); margin: 0 0 .5rem; }
/* A thing's own name, not a section label (item 213). `h2` is styled for headings like *what does
   not add up*, and reusing it for a project gave a project the weight of a caption. */
h2.name { font: 600 var(--t-lg)/1.25 var(--sans); letter-spacing: 0; text-transform: none;
          color: var(--ink); margin: 2rem 0 .15rem; }
/* A heading that is also a link is still a heading: underlined at rest it reads as body text that
   happens to be big. The underline arrives on hover, where it answers "can I click this". */
h2.name a { text-decoration: none; }
h2.name a:hover { text-decoration: underline; }
p { margin: .7rem 0; }
.sub { font-size: var(--t-md); color: var(--muted); }
.sub a { color: var(--ink); }
.bad { color: var(--refused); }
.mono { font-family: var(--mono); font-variant-numeric: tabular-nums; }
code { font: 400 var(--t-sm)/1.4 var(--mono); background: var(--sunk); padding: .12em .32em;
       border-radius: 4px; }
ul, ol { margin: .7rem 0; padding-left: 1.2rem; }
li { margin: .25rem 0; }
time { font-variant-numeric: tabular-nums; }

/* --- tables, which are data and should look like it ----------------------------------------- */

table { border-collapse: collapse; width: 100%; font-size: var(--t-md); }
th { text-align: left; font-weight: 500; color: var(--muted); vertical-align: top;
     padding: .4rem 1rem .4rem 0; white-space: nowrap; }
td { padding: .4rem 0; vertical-align: top; }
table.list { font-size: var(--t-md); }
table.list th { border-bottom: 1px solid var(--rule); padding-bottom: .5rem;
                font: 550 var(--t-2xs)/1 var(--sans); letter-spacing: .05em;
                text-transform: uppercase; }
table.list td { border-bottom: 1px solid var(--rule); padding: .5rem .8rem .5rem 0; }
table.list tr:hover td { background: var(--sunk); }
.wide { overflow-x: auto; }

.facts { display: grid; grid-template-columns: auto 1fr; gap: .35rem 1rem; margin: 0; }
.facts dt { color: var(--muted); font-size: var(--t-md); }
.facts dd { margin: 0; font-family: var(--mono); font-size: var(--t-md); }

/* --- the forms that decide ------------------------------------------------------------------- */

form.inline { display: inline; }
button.linkish { background: none; border: 0; padding: 0; font: inherit; color: inherit;
                 text-decoration: underline; cursor: pointer; }
.decide { display: flex; gap: .5rem; flex-wrap: wrap; }
.decide form { margin: 0; }
.decide button, .login button, .new button {
  font: 550 var(--t-md)/1 var(--sans); padding: .5rem .85rem; border-radius: var(--r-chip);
  cursor: pointer; border: 1px solid var(--rule); background: var(--raise); color: var(--ink);
}
.decide button:hover, .login button:hover, .new button:hover { background: var(--sunk); }
.decide button.go { border-color: color-mix(in oklab, var(--passed) 45%, transparent);
                    color: var(--passed); }
.decide button.go:hover { background: color-mix(in oklab, var(--passed) 9%, transparent); }
.login { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; margin: 0; }
.login input {
  font: 400 var(--t-md)/1 var(--mono); padding: .5rem .6rem; min-width: 18rem; flex: 1 1 18rem;
  border: 1px solid var(--rule); border-radius: var(--r-chip);
  background: var(--canvas); color: var(--ink);
}
/* WCAG 2.2 AA 2.5.8 asks 24x24, and a row's link measured 17x17 (item 221). The *Inline* exception
   covers a link inside a sentence; the only way to open an item is not that. */
.list td a { display: inline-block; min-width: 24px; min-height: 24px; line-height: 24px; }

.stuck { font: 600 var(--t-2xs)/1 var(--sans); letter-spacing: .05em; text-transform: uppercase;
         color: var(--refused); border: 1px solid currentColor; border-radius: var(--r-chip);
         padding: .16rem .34rem; margin-left: .35rem; }

/* --- the evidence, which is somebody else's output and must not be styled into prose --------- */

details.evidence > summary { font-family: var(--mono); }
pre { background: var(--sunk); border: 1px solid var(--rule); border-radius: var(--r);
      padding: .9rem 1rem; overflow-x: auto; font: 400 var(--t-sm)/1.5 var(--mono);
      margin: .8rem 0; }
details > pre { border-left-width: 3px; }

footer {
  margin: 2.5rem 0 0; padding-top: 1.1rem; border-top: 1px solid var(--rule);
  font-size: var(--t-sm); color: var(--faint);
}
footer strong { color: var(--muted); font-weight: 550; }

@media (prefers-reduced-motion: no-preference) {
  a, button, summary { transition: color 120ms ease, background 120ms ease; }
}

/* The item list stops being a table where a table stops working (item 221). Seven columns on a
   390px screen wrapped titles to five lines and pushed `issue / pull` behind a sideways scroll
   nobody discovers — which is not the same as not breaking the page, and is a lower bar.

   One markup, two shapes: the labels come from `data-label`, so nothing here is a second template
   that has to be kept in step with the first. */
@media (max-width: 46rem) {
  .list, .list tbody { display: block; width: auto; }
  .list tr:first-child { display: none; }
  .list tr {
    display: flex; flex-direction: column;
    background: var(--raise); border: 1px solid var(--rule); border-radius: var(--r);
    padding: .7rem var(--pad); margin: 0 0 .6rem;
  }
  .list td { border: 0; padding: .15rem 0; }
  /* The title identifies the item, so it leads — `order` rather than a second markup, which is the
     whole reason the cells carry their own labels. */
  .list td[data-label="title"] {
    order: -1; font: 550 var(--t-base)/1.35 var(--sans); padding-bottom: .35rem;
  }
  .list td:not([data-label="title"])::before {
    content: attr(data-label) " ";
    display: inline-block; min-width: 6.5rem;
    font: 550 var(--t-2xs)/1.6 var(--sans); letter-spacing: .06em;
    text-transform: uppercase; color: var(--faint);
  }
}

@media (max-width: 40rem) {
  .wrap { padding: 0 1rem 3rem; }
  .lede { font-size: var(--t-xl); }
  .tally { flex: 1 1 45%; border-right: 0; border-bottom: 1px solid var(--rule); }
}
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

    #: Whether a password has been set, which is whether a login is worth offering. Item 167 had no
    #: use for this — a one-time link needs nothing stored — and item 168 needs it again: a login
    #: form on an instance that cannot accept one is a dead end, and telling a reader to run
    #: `hullwork password` is the honest alternative.
    offered: bool = False

    #: Minutes left on a lockout, when there is one. **Reported rather than hidden**, unlike a wrong
    #: password: an operator who has typed it wrong ten times needs to know the door is shut and for
    #: how long, and somebody guessing already knows they have been guessing.
    locked_minutes: int | None = None


#: A request that may read and nothing else — the default everywhere, and the whole of what this
#: page was before item 166.
READING = Acting()


def _document(
    title: str,
    body: str,
    *,
    acting: Acting = READING,
    up: str = "",
    state: tuple[str, str] | None = None,
    here: str = "",
    counts: Counts | None = None,
    inside: str | None = None,
    projects: Sequence[tuple[str, int]] = (),
) -> str:
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
        else "<strong>signed in</strong> for twelve hours, so two buttons on an amber item work "
        "and nothing else does. The URL is still only a read credential: the session is what "
        "acts, and it lives in this browser. "
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
        '<div class="wrap">\n'
        f"{_bar(up=up, state=state)}\n"
        # **Every page, from here** (item 212). Rendering it per view is four chances to grow four
        # opinions about what this product contains, which is the drift five items this week each
        # cost a day to.
        f"{_rail(acting, here=here, up=up, counts=counts, inside=inside, projects=projects)}\n"
        # **And the way in, for the same reason.** It lived inside the instance report, so moving
        # the front door left a locked-out operator landing on a page that said nothing about the
        # lockout — a working lockout looking like a broken login, which is the exact failure item
        # 168 fixed once already.
        f'<main class="sheet">{_signing_in(acting, up=up)}\n{body}</main>\n'
        f"<footer>Hullwork {_h(__version__)} — {footing}</footer>\n"
        "</div>\n"
        "</body></html>\n"
    )


#: The nouns this product has, and the order somebody meets them. Item 212, DR-0023.
#:
#: Navigation as furniture: a person should never have to remember what exists. The last two are the
#: operator's — DR-0021 gives a read link the instance and nothing that administers it — and a
#: control that leads to a `404` is worse than one that is not there, so a reader is shown neither.
_NOUNS: tuple[tuple[str, str, bool], ...] = (
    ("./", "What needs you", False),
    ("projects", "All projects", False),
    ("instance", "This instance", False),
    ("doctor", "Diagnostics", True),
    ("config", "Configuration", True),
)

#: A project's features, in the order somebody works through them, and where each lives **under**
#: `projects/<slug>/`. Item 237, and it is the operator's own correction of item 235:
#:
#:   *¿No será mejor plantear esto mismo, pero a nivel de proyecto? Es decir, tú entras en un
#:   proyecto, y ves todas las features. Así no mezclamos cosas.*
#:
#: He is right, and the reason is the one item 235 got wrong: a page called *Dependencies* holding
#: every project's advisories one after another is a wall at two projects and unusable at ten.
#: Nobody works by feature across clients — they work on a client. The feature names were the fix;
#: the axis was not.
_IN_A_PROJECT: tuple[tuple[str, str, bool], ...] = (
    ("", "Overview", False),
    ("errors", "Errors", False),
    ("fixes", "Fixes", False),
    ("dependencies", "Dependencies", False),
    ("deliveries", "Deliveries", False),
    ("settings", "Settings", True),
)


@dataclass(frozen=True)
class Counts:
    """How much there is of each of a project's features, for the rail. Item 235, item 237.

    **A number in the navigation is what makes it a map rather than a list of words.** It answers
    *is there anything in there* before a click, which is the question that had a reader opening
    four folds to find out that three of them were empty.

    Zero renders as nothing at all, not as `0`: item 073's rule is that a signal which is always on
    is not a signal, and its corollary is that a badge reading zero on every page is furniture
    pretending to be information.
    """

    errors: int = 0
    fixes: int = 0
    dependencies: int = 0
    deliveries: int = 0

    def of(self, where: str) -> int:
        return {
            "errors": self.errors,
            "fixes": self.fixes,
            "dependencies": self.dependencies,
            "deliveries": self.deliveries,
        }.get(where, 0)


def how_much_of_each(session: Session, project_id: int) -> Counts:
    """Four counts for one project's rail. Item 237.

    Read here rather than passed in by every view, because a rail that is right on three pages and
    stale on the fourth is worse than no rail: five views growing five opinions about what this
    product contains is the drift DR-0023 exists to stop.
    """
    from hullwork.models import Delivery, DependencyReport

    def count(what: object, where: object) -> int:
        try:
            return int(
                session.scalar(select(func.count()).select_from(what).where(where)) or 0  # type: ignore[arg-type]
            )
        except Exception:  # pragma: no cover - a rail must never be what breaks a page
            return 0

    report = session.get(DependencyReport, project_id)
    # **The number in the rail has to be the number in the view** (item 247). It counted *findings*
    # beside a view that counts *packages* — `Dependencies 25` next to `20 packages`, two true
    # numbers of two different things in one eye-line. A package pinned three times is three
    # findings and one row, and the row is what a click leads to.
    findings = (
        len({str(one.get("package") or "") for one in (report.findings or [])})
        if report is not None and report.asked
        else 0
    )
    return Counts(
        errors=count(_Item, _Item.project_id == project_id),
        fixes=count(
            _Attempt,
            _Attempt.item_id.in_(select(_Item.id).where(_Item.project_id == project_id)),
        ),
        dependencies=findings,
        deliveries=count(Delivery, Delivery.project_id == project_id),
    )


def each_project(session: Session) -> list[tuple[str, int]]:
    """Every project and how much is waiting in it, for the rail outside a project. Item 237.

    The number is **what needs a person**, not how much exists: a count of items would read the
    same on a project that is fine and one that is stuck, and the whole of the front door is
    *which of these wants me*.
    """
    waiting = (ItemState.WAITING_APPROVAL, ItemState.HUMAN_ONLY)
    out: list[tuple[str, int]] = []
    for project in session.scalars(select(_Project).order_by(_Project.slug)).all():
        how_many = int(
            session.scalar(
                select(func.count())
                .select_from(_Item)
                .where(_Item.project_id == project.id, _Item.state.in_(waiting))
            )
            or 0
        )
        out.append((project.slug, how_many))
    return out


def _rail(
    acting: Acting,
    *,
    here: str = "",
    up: str = "",
    counts: Counts | None = None,
    inside: str | None = None,
    projects: Sequence[tuple[str, int]] = (),
) -> str:
    """The sidebar every page carries, from one function.

    Four pages growing four opinions about what this product contains is the drift items 193, 194,
    200, 203 and 211 each cost a day to. This is that lesson applied before it happens rather than
    after.

    **Two modes, and the project is the axis** (item 237). Outside a project it lists the projects
    and what belongs to the instance; `inside` a project it lists that project's features and
    nothing else, so nothing on screen is ever about two projects at once.

    Item 235 named the features and put them on pages that spanned every project, which is the same
    mistake one level up: a reader does not go looking for *dependencies*, they go looking for
    *simplecheck*.
    """
    if inside is not None:
        return _the_projects_rail(acting, here=here, up=up, counts=counts, slug=inside)
    links = ""
    for slug, how_many in projects:
        badge = f'<span class="count">{how_many}</span>' if how_many else ""
        links += f'<a href="{up}projects/{_h(slug)}">{_h(slug)}{badge}</a>'
    if projects:
        links = (
            f'<span class="group">Projects</span>{links}'
            '<span class="group">This instance</span>'
        )
    for where, name, operators_only in _NOUNS:
        if operators_only and not acting.csrf:
            continue
        links += (
            f'<a href="{up}{where}"'
            + (' aria-current="page"' if where == here else "")
            + f">{_h(name)}</a>"
        )
    return f'<nav class="rail" aria-label="Sections">{links}</nav>'


def _the_projects_rail(
    acting: Acting, *, here: str, up: str, counts: Counts | None, slug: str
) -> str:
    """Inside a project: its features, and the way back out. Item 237.

    The way out is first and it is a link rather than a heading, because a rail that replaces itself
    has to say what it replaced — otherwise somebody two levels in has no cue that the other
    projects still exist.
    """
    links = (
        f'<a class="out" href="{up}./">&larr; All projects</a>'
        f'<span class="group">{_h(slug)}</span>'
    )
    for where, name, operators_only in _IN_A_PROJECT:
        if operators_only and not acting.csrf:
            continue
        how_many = counts.of(where) if counts is not None else 0
        # Zero is rendered as nothing, not as `0`. Item 073's rule, one turn further: a badge that
        # is on every row all the time is furniture pretending to be information.
        badge = f'<span class="count">{how_many}</span>' if how_many else ""
        links += (
            f'<a href="{up}projects/{_h(slug)}{"/" + where if where else ""}"'
            + (' aria-current="page"' if where == here else "")
            + f">{_h(name)}{badge}</a>"
        )
    return f'<nav class="rail" aria-label="Sections">{links}</nav>'


def _bar(*, up: str, state: tuple[str, str] | None) -> str:
    """The top edge, which the page did not have. Item 169.

    **A page that opens with a sentence and no header reads as an email**, which is what the
    operator was looking at when he called the redesign ugly: item 167 removed the
    `<h1>hullwork</h1>` and put nothing in its place, so there was no anchor, no mark, and nothing
    saying which instance this is.

    The mark is the one the interface document specifies — `▚`, no binary asset — and the pill on
    the right is the instance's own state, which is the second thing a reader wants after *does this
    need me* and was previously buried in a folded table.
    """
    badge = (
        f'<span class="pill {_h(state[1])}">{_h(state[0])}</span>' if state is not None else ""
    )
    return (
        '<header class="bar">'
        f'<a class="mark" href="{up}./" aria-label="This instance">▚</a>'
        f'<span class="word">hullwork</span>'
        '<span class="spacer"></span>'
        f"{badge}</header>"
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

    return _section(
        "What it allows",
        "The three policies an attempt runs under, which is what a reviewer is judging when they "
        "judge its artefact.",
        f"<p>{_h(policies(settings).detail)}</p>",
    )


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
        verdict = project.ingest_token_can_push
        if verdict is not None:
            measured.append(f"{project.slug}: {'CAN push' if verdict else 'cannot push, measured'}")
    tail = (
        f'<p class="sub">{_h(" · ".join(measured))}</p>' if measured else
        '<p class="sub">Whether this instance\'s ingest credential can push is answered by '
        '<code>hullwork status</code>, which asks the forge a question whose successful form does '
        'not exist. It is not asked from this page: a render must not spend somebody\'s forge '
        'quota.</p>'
    )
    return _section(
        "The two halves",
        "Which credential each half holds, and what this instance measured about them rather than "
        "what the design promises.",
        f"<p>{_own_prose(_SPLIT)}</p>{tail}",
    )


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


def _since(when: datetime | None) -> str:
    """`_ago`'s answer as a phrase that reads after a verb: *3h ago*, or *just now*.

    Item 247, found on the deployed door: `_ago` answers `just now` for anything under a minute, and
    every caller appending " ago" to it produced **just now ago**.
    """
    said = _ago(when)
    return said if said in ("just now", "not recorded") else f"{said} ago"


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


def _proof(session: Session, *, merged: int, holding: int, recurred: int, watch: int) -> str:
    """The instrument's own record, in figures, as the striking thing on the page. Item 170.

    **The page is a proof rather than a panel, and this is the proof.** Two readers arrive here and
    until now only one was served: the operator, daily, asking what needs them. The other is a
    stranger who has installed nothing and is deciding whether this is real — and for an open-source
    product that reader is the whole distribution channel. What convinces them is not a feature
    list, it is *this instance's* count of fixes that were merged and then did not come back.

    Same content, both readers. The operator reads it as state; the stranger reads it as evidence.

    The figures are set in mono at display size because they are **measurements**, and an instrument
    should shout its measurements rather than its name. The order is the product's own sequence —
    found, tried, merged, held — so the row is a funnel read left to right, and the red-to-green
    seam under it is the gate every one of those merges had to pass.
    """
    from sqlalchemy import func

    items = session.scalar(select(func.count()).select_from(_Item)) or 0
    tried = session.scalar(
        select(func.count(func.distinct(_Attempt.item_id))).where(_Attempt.rehearsal.is_(False))
    ) or 0
    # Four words at most. The figure is the message; the gloss is there so a stranger does not have
    # to guess what was counted, and a sentence under each one turns the row back into prose.
    cells = (
        ("found", items, "errors seen", ""),
        ("tried", tried, "agent let loose", ""),
        ("merged", merged, "a human accepted", "won"),
        ("held", holding, f"{watch} days, no recurrence", "won"),
        ("came back", recurred, "merged, then recurred", "lost" if recurred else ""),
    )
    figures = "".join(
        f'<div class="cell {tone}{" none" if not count else ""}">'
        f'<span class="big">{count}</span>'
        f'<span class="name">{_h(name)}</span>'
        f'<span class="gloss">{_h(gloss)}</span></div>'
        for name, count, gloss, tone in cells
    )
    return f'<section class="proof">{figures}</section>'


def _figures(rows: Sequence[tuple[int, str, str]]) -> str:
    """A count, what it counts, and the caveat under it. DR-0028, item 248.

    **The second skin of a structure the terminal already prints as sentences** — the same pattern
    item 050 used for the artefact, and for the same reason: one construction, two skins, because a
    second *computation* is what comes apart. `outcomes.Desk` and `outcomes.Funnel` are the
    construction; `desk_lines` is the terminal's skin and this is the page's.

    Rows with a zero are not passed in. A row of noughts reads like a failure rather than like a
    beginning, which is `desk_lines`'s own rule and the one thing both skins must agree on.
    """
    if not rows:
        return ""
    lines = "".join(
        f'<tr class="figure"><td class="fig">{count}</td>'
        f'<td class="means">{_h(means)}'
        + (f'<span class="caveat">{_h(caveat)}</span>' if caveat else "")
        + "</td></tr>"
        for count, means, caveat in rows
    )
    # In the container the rule asks for (item 215): every table on this page sits in something
    # that scrolls on its own, and a two-column table being unable to overflow is a reason to
    # believe it rather than a reason to exempt it.
    return f'<div class="wide"><table class="figures">{lines}</table></div>'


def _desk_figures(counted: object) -> str:
    """What arrived and how much left, as figures rather than as four sentences. Item 248."""
    rows: list[tuple[int, str, str]] = []
    arrived = int(getattr(counted, "arrived", 0))
    if not arrived:
        return ""
    rows.append((arrived, "claims arrived", ""))
    left = int(getattr(counted, "left_with_evidence", 0))
    if left:
        change = int(getattr(counted, "with_a_change", 0))
        refusal = int(getattr(counted, "with_a_refusal", 0))
        how = []
        if change:
            how.append(f"{change} with a change")
        if refusal:
            how.append(f"{refusal} with a reasoned refusal and the runs behind it")
        rows.append((left, "left your desk with evidence attached", " · ".join(how)))
    for field, means in (
        ("still_waiting", "still in the queue"),
        ("running", "being attempted now"),
    ):
        value = int(getattr(counted, field, 0))
        if value:
            rows.append((value, means, ""))
    handed = int(getattr(counted, "handed_over", 0))
    if handed:
        # **Never rounded into good news** (`desk_lines`'s rule): this is the one figure here that
        # can embarrass the product, and it keeps its own words.
        rows.append((
            handed, "went onto your desk rather than off it",
            "red lane, or a pull request somebody read and refused",
        ))
    return _figures(rows)


def _funnel_figures(counted: object) -> str:
    """Every attempt, by how it ended. Item 248."""
    rows: list[tuple[int, str, str]] = []
    fair = int(getattr(counted, "fair_try", 0))
    if fair:
        parts = []
        for field, said in (
            ("pull_requests", "opened a pull request"),
            ("not_reproducible", "found nothing to reproduce"),
            ("failed", "could not produce a passing suite"),
        ):
            value = int(getattr(counted, field, 0))
            if value:
                parts.append(f"{value} {said}")
        rows.append((fair, "attempts got a fair try", " · ".join(parts)))
    pulls = int(getattr(counted, "pull_requests", 0))
    merged = int(getattr(counted, "merged", 0))
    if pulls:
        # **Counts, never a percentage** (item 119): four attempts are not a rate, and a percentage
        # invites comparing instances running different code over different repositories.
        rows.append((merged, f"of those {pulls} pull request(s) were merged", ""))
    never = getattr(counted, "never_counted", None)
    if isinstance(never, Mapping) and never:
        why = " · ".join(f"{n} {_h(str(name))}" for name, n in never.items())
        rows.append((sum(int(n) for n in never.values()), "never counted against an item", why))
    rehearsals = int(getattr(counted, "rehearsals", 0))
    if rehearsals:
        rows.append((
            rehearsals, "rehearsals",
            "they publish nothing and are counted in none of the above",
        ))
    running = int(getattr(counted, "in_flight", 0))
    if running:
        rows.append((running, "started and not finished", ""))
    return _figures(rows)


def _review_figures(counted: object, said: Sequence[str]) -> str:
    """What became of the pull requests, as figures where they are counts. Item 248.

    **Two of its lines are counts and one is a duration**, so this keeps the sentences for what is
    not a count rather than forcing a table onto a median. The rule the whole item runs on: a figure
    goes in the column, and prose that is genuinely prose stays prose.
    """
    rows: list[tuple[int, str, str]] = []
    merged = int(getattr(counted, "merged", 0))
    if merged:
        rows.append((merged, "merged by a human", ""))
    waiting = int(getattr(counted, "waiting", 0))
    if waiting:
        rows.append((waiting, "waiting for a human", "this is the review debt"))
    rejected = getattr(counted, "rejected", None)
    if isinstance(rejected, Mapping) and rejected:
        why = " · ".join(f"{n} {_h(str(name))}" for name, n in rejected.items())
        rows.append((sum(int(n) for n in rejected.values()), "refused, with a reason", why))
    rest = "".join(
        f"<p class=\"sub\">{_h(line)}</p>" for line in said if line[:1].isalpha()
    )
    return _figures(rows) + rest


def _section(label: str, says: str, body: str) -> str:
    """A feature's section: a label you can scan, the sentence under it, then the thing. Item 235.

    **The headings were sentences** — *What is published against what it pins*, *What arrived, and
    how much left your desk* — and an eye moving down the page could not use one of them. They were
    accurate and they were load-bearing for navigation, which prose cannot do.

    Nothing this product says about what it measured is deleted here. The sentence moves one line
    down and into grey, where it explains rather than labels, and the label is a word somebody would
    have searched for.
    """
    said = f'<p class="says">{says}</p>' if says else ""
    return f'<section class="feature"><h2>{_h(label)}</h2>{said}{body}</section>'


def _fold(summary: str, body: str) -> str:
    """A closed disclosure, native, no JavaScript. Item 167.

    **Everything below the first screen is the evaluator's**, and the interface document
    already said so: *"the daily reader must never pay for the evaluator's questions."*
    It was not true — the
    configuration table started in the second half of the first screen. `<details>` is how a page
    with no script keeps a promise like that: closed, one line, and the summary says what is inside
    so it is not a mystery box.
    """
    return f"<details><summary>{_h(summary)}</summary><div class=\"folded\">{body}</div></details>"


def entered(*, signed_in: bool) -> str:
    """What a sign-in link renders. Item 167.

    **The same page either way, minus the good news.** A spent link, a forged one and an expired one
    all land here, and this route is reachable by anybody, so it must not report on whether a token
    was ever real.
    """
    line = (
        "<p class=\"lede calm\">This browser can decide now.</p>"
        "<p>Go back to your Hullwork page and reload it. The two buttons are on any item waiting "
        "for a decision, and nothing else on the page changes anything.</p>"
        "<p class=\"sub\">The session lasts twelve hours. To end it everywhere at once, run "
        "<code>hullwork sign-in --end-all</code>.</p>"
        if signed_in
        else "<p class=\"lede\">This link cannot be used.</p>"
        "<p>A sign-in link works <strong>once</strong>, and stops working ten minutes after it is "
        "printed. If this one was already opened, the browser that opened it is the one that is "
        "signed in.</p>"
        "<p class=\"sub\">Run <code>hullwork sign-in</code> on the host for another.</p>"
    )
    return _document("Hullwork — sign in", f"<h1>Sign in</h1>{line}")


def _when(when: datetime | None) -> str:
    """A timestamp a person reads, with the exact one in `title` for anybody who needs it.

    **Item 167, and what it replaces was on the evidence page for two milestones**: `seen` printed
    `6 time(s), first 2026-08-05 09:57:43.866473+00:00, last 2026-08-05 10:27:43.866473+00:00` — two
    thirty-two-character strings, with microseconds, at the same weight as the lane and its reason.
    Nobody parses that, so nobody read the line it was in.

    The full value is not thrown away: it is the tooltip, because the one reader who wants
    microseconds is comparing this page against a log and should not have to leave.
    """
    if when is None:
        return "not recorded"
    return (
        f'<time datetime="{_h(when.isoformat())}" title="{_h(when.isoformat())}">'
        f"{_h(when.strftime('%-d %b %H:%M'))}</time>"
    )


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



#: How many items waiting on the operator the front page lists before it stops and links instead.
#: Five is a screenful of decisions. Past that the answer is not "here they all are" but "you have
#: a backlog", and a backlog is worked in the list view.
DECISIONS_SHOWN = 5


def does_this_need_you(
    session: Session, settings: Settings, acting: Acting, *, error_reporting: bool
) -> tuple[str, tuple[str, str]]:
    """The answer, and the work behind it. Item 212, DR-0023.

    This was the top of the instance report, which is where everything was. Moving the front door
    to the items would have left it behind — so a person opening the page would meet a table of
    rows and have to read them to learn whether any of it wanted them, which is the question item
    167 built the lede to answer without reading.

    It computes its own readiness rather than taking it, because the front door has no report to
    hand it. **`error_reporting` is passed and not assumed**: the first version hardcoded `False`
    here, so the front door opened on a red headline — *HULLWORK_ERROR_DSN is set but error
    reporting is not running* — about an instance where it was running. Seen on the deployed page,
    not by any test, which is why the test below compares the two views' answers instead of
    asserting a shape.
    """
    from hullwork import readiness

    report = readiness.check(session, settings, error_reporting=error_reporting)
    waiting = list(
        session.scalars(
            select(_Item)
            .where(_Item.state == ItemState.WAITING_APPROVAL)
            .order_by(_Item.state_since.is_(None), _Item.state_since)
        ).all()
    )
    # The pill goes with it, because it answers the reader's second question — *is this thing
    # working* — and it was on the bar of the view that stopped being the front door.
    badge = ("ready", "ok") if report.ready else ("degraded", "bad")
    return _lede(session, report, waiting=waiting) + _deciding(waiting, acting), badge


def _lede(session: Session, report: object, *, waiting: list[_Item]) -> str:
    """One sentence, in the largest type on the page, answering *does this need me*. Item 167.

    **A number in a box is a tally; a sentence is an answer.** The board this replaces put the
    operator's own queue in the second of six identical cards, told apart by a faint border tint —
    so finding it meant reading six labels, which is what *"extremadamente liosa"* was describing.

    Severity decides what the sentence is about, and only one thing can be first: a problem outranks
    a decision, a decision outranks the machine, and *nothing needs you* is a real answer that
    deserves saying rather than being left to be inferred from six zeroes.
    """
    problems = list(getattr(report, "problems", []))
    if problems:
        rest = len(problems) - 1
        also = f' <span class="also">and {rest} more</span>' if rest else ""
        return _answer("bad", f"{_h(problems[0])}{also}")
    if waiting:
        oldest = min((i.state_since for i in waiting if i.state_since is not None), default=None)
        how_long = f" The oldest has waited {_h(_ago(oldest))}." if oldest is not None else ""
        count = len(waiting)
        thing = "item needs" if count == 1 else "items need"
        return _answer("mine", f"{count} {thing} a decision from you.{how_long}")
    reviewing = len(
        list(session.scalars(select(_Item).where(_Item.state == ItemState.PR_OPEN)).all())
    )
    if reviewing:
        pulls = "pull request is" if reviewing == 1 else "pull requests are"
        return _answer("", f"{reviewing} {pulls} waiting for a reviewer.")
    return _answer("calm", "Nothing needs you.")


def _answer(tone: str, sentence: str) -> str:
    """The lede, in a panel with a state stripe rather than floating above a hairline. Item 169."""
    return (
        f'<section class="answer {tone}"><p class="lede {tone}">{sentence}</p></section>'
    )


def _deciding(waiting: list[_Item], acting: Acting) -> str:
    """The items waiting on the operator, named, with their buttons. Item 167.

    **This is the fix item 166 got half right.** That item made the count a link, so *"waiting on
    you 2 — and now what?"* became one click instead of a dead end. But three items cost three
    lines, which is less space than the card that counts them: the front page should show the work
    rather than the tally, and then the click is not needed at all.
    """
    if not waiting:
        return ""
    rows = []
    for found in waiting[:DECISIONS_SHOWN]:
        title = found.title.splitlines()[0] if found.title else f"item {found.id}"
        stuck = _stuck(found)
        rows.append(
            '<li class="decision">'
            f'<a class="what" href="items/{found.id}">{_h(title)}</a>'
            f'<span class="meta">{_h(found.project.slug)} · waiting {_h(_ago(found.state_since))}'
            + (' · <span class="stuck">never runs</span>' if stuck else "")
            + "</span>"
            + ("" if stuck else _decide(found, acting, up=""))
            + "</li>"
        )
    how = _how_to_decide(acting)
    hidden = len(waiting) - DECISIONS_SHOWN
    more = (
        f'<p class="sub"><a href="items?in=waiting">and {hidden} more</a></p>'
        if hidden > 0
        else ""
    )
    return f'<ul class="decisions">{"".join(rows)}</ul>{more}{how}'


def _strip(session: Session) -> str:
    """Where everything else is, as one line of figures. Item 167.

    Six equal cards became one sentence of numbers, and the demotion is the design: *arrived*,
    *queued* and *working* are the machine's business, *in review* is somebody else's, and *closed*
    is history. None of them is an action, so none should carry the weight of one — the operator's
    own queue is above this, in prose, and it is the only amber thing on the page.
    """
    cells = []
    for title, key, _tone, states, _owed in _COLUMNS:
        if key == "waiting":
            # **Not skipped and not repeated.** The lede and the list above count the items waiting
            # for a *decision*; this counts the ones a human has already taken, which is a different
            # fact and the only place it appears. Counting the whole column again here would put the
            # same number in three places on one screen with two different meanings.
            mine = len(
                list(
                    session.scalars(
                        select(_Item).where(_Item.state == ItemState.HUMAN_ONLY)
                    ).all()
                )
            )
            if mine:
                cells.append(
                    f'<span class="tally"><a class="fig" href="items?in=waiting">{mine}</a>'
                    '<span class="cap">yours to fix</span></span>'
                )
            continue
        count = len(list(session.scalars(select(_Item).where(_Item.state.in_(states))).all()))
        label = "in review" if key == "review" else title.lower()
        figure = (
            '<span class="fig zero">0</span>'
            if not count
            else f'<a class="fig" href="items?in={key}">{count}</a>'
        )
        cells.append(f'<span class="tally">{figure}<span class="cap">{_h(label)}</span></span>')
    return f'<div class="strip">{"".join(cells)}</div>'


def what_it_has_been_doing(session: Session, *, limit: int = 8) -> str:
    """The last few things this instance did, newest first. Item 242.

    **Merged from what is already stored** — a verdict's `tried_at`, an attempt's `finished_at`, a
    dependency report's `taken_at` — rather than from a log table nobody writes to. A second record
    of the same events could disagree with them, and then a reader has to decide which to believe.

    It is the answer to the question a verdict cannot answer on its own: *when did that happen, and
    what else was going on around it*.
    """
    from hullwork.models import DependencyReport, UpgradeVerdict

    where: dict[int, str] = {
        one.id: one.slug for one in session.scalars(select(_Project)).all()
    }
    events: list[tuple[datetime, str, str]] = []
    for verdict in session.scalars(
        select(UpgradeVerdict).order_by(UpgradeVerdict.tried_at.desc()).limit(limit)
    ).all():
        said, colour = _WHAT_IT_MEANT.get(
            verdict.outcome, (f"ended as {verdict.outcome}", "c-idle")
        )
        events.append((
            verdict.tried_at,
            colour,
            f"{_h(where.get(verdict.project_id, '?'))} · tried "
            f"{_h(verdict.package)} {_h(verdict.was)} → {_h(verdict.to)} — {_h(said)}",
        ))
    for attempt, item_row in session.execute(
        select(_Attempt, _Item)
        .join(_Item, _Attempt.item_id == _Item.id)
        .order_by(_Attempt.id.desc())
        .limit(limit)
    ).all():
        outcome = getattr(attempt.outcome, "value", attempt.outcome)
        events.append((
            attempt.finished_at or attempt.started_at,
            "c-passed" if str(outcome) == "pr-open" else "c-idle",
            f"{_h(where.get(item_row.project_id, '?'))} · attempted "
            f"{_h(item_row.title[:48])} — {_h(str(outcome or 'still running'))}",
        ))
    for report in session.scalars(select(DependencyReport)).all():
        events.append((
            report.taken_at,
            "c-idle" if report.asked else "c-refused",
            f"{_h(where.get(report.project_id, '?'))} · "
            + (
                f"asked OSV about {report.pinned} pinned version(s), "
                f"{len(report.findings or [])} with something published"
                if report.asked
                else "could not ask OSV"
            ),
        ))
    if not events:
        return ""
    # **A thing that happened is a subject too** (DR-0028), so it is a row of the same table the
    # other views use rather than a card with a paragraph in it.
    rows = "".join(
        f'<tr class="subject"><td class="who">'
        f'<span class="dot {_h(colour.removeprefix("c-"))}"></span>'
        f'<span class="said">{said}</span></td>'
        f'<td class="fold"><time datetime="{_h(when)}" title="{_h(when)}">{_h(_ago(when))}'
        f"</time></td></tr>"
        for when, colour, said in sorted(events, key=lambda one: one[0], reverse=True)[:limit]
    )
    return _section(
        "What it has been doing",
        "Newest first, across every project.",
        f'<table class="subjects narrow">{rows}</table>',
    )


def _what_it_says_it_is_doing(session: Session) -> str:
    """The dispatcher's own sentence about what it is doing, or `""` when there is none. Item 242.

    **Its word, not an inference.** Everything a page could deduce — the heartbeat, an attempt with
    no `finished_at`, a verdict appearing — has the same hole in the middle: between two writes
    there is nothing to read, and that gap is exactly the four minutes somebody is watching.

    A stale heartbeat is not busy. A dispatcher killed mid-sentence leaves its last one behind, and
    rendering that as *now* would be this page's own version of the defect it is fixing — so the
    lease's own reading of itself decides, and a stale one says so instead.
    """
    from hullwork import lease as lease_module
    from hullwork.models import DispatcherLease

    row = session.get(DispatcherLease, 1)
    state, when = lease_module.state(session)
    if row is None or not row.doing:
        # **Idle is a fact and being unreachable is a different one.** A door that renders nothing
        # in both cases answers *is it running?* with silence, which is the question the operator
        # opened it to ask.
        if state == "alive":
            return (
                '<div class="band"><span class="chip c-idle">nothing running</span>'
                # **`_ago` returns a phrase, not a duration**, and one of its answers is
                # `just now` — which this rendered as *just now ago*, on the door, for anybody
                # looking at an idle instance.
                f'<p class="sub" style="margin:.7rem 0 0">The dispatcher answered '
                f"{_h(_since(when))}.</p></div>"
            )
        if state in ("stale", "never"):
            return (
                '<div class="band"><span class="chip c-refused">no dispatcher</span>'
                '<p class="sub" style="margin:.7rem 0 0">'
                + (
                    f"Nothing has claimed the lease since {_h(_since(when))}. "
                    if state == "stale"
                    else "No dispatcher has ever run against this instance. "
                )
                + "Nothing will be attempted or verified until one does.</p></div>"
            )
        return ""

    if state != "alive":
        return (
            '<div class="band"><span class="chip c-refused">dispatcher not answering</span>'
            f'<p class="sub" style="margin:.7rem 0 0">The last thing it said it was doing was '
            f"<em>{_h(row.doing)}</em>, {_h(_since(row.doing_since))}. Its heartbeat has "
            "stopped, so that is what it was doing rather than what it is doing.</p></div>"
        )
    return (
        '<div class="band"><span class="chip c-working">working</span>'
        f'<p style="margin:.7rem 0 0">{_h(row.doing)}</p>'
        f'<p class="sub" style="margin:.2rem 0 0">for {_h(_ago(row.doing_since))}</p></div>'
    )


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
                f"The last one finished {_h(_since(last.finished_at or last.started_at))}: "
                f"{_h(str(outcome))}."
            )
        # **What the dispatcher says it is doing, before concluding it is doing nothing** (item
        # 242). This band read `Item.state == IN_PROGRESS`, and a dependency verification is not an
        # item — so it printed *nothing running* through five minutes of building an image and
        # running somebody's suite twice. A page that reports calm during four minutes of work is
        # not missing a feature; it is answering wrongly.
        busy = _what_it_says_it_is_doing(session)
        if busy:
            return busy
        return (
            '<div class="band"><span class="chip c-idle">nothing running</span>'
            f'<p class="sub" style="margin:.7rem 0 0">{tail}'
            + (f" {queued} item(s) are ready and waiting." if queued else "")
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
        parts = [f"started {_h(_since(attempt.started_at))}"]
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

    # **Item 167 kept the assertion and dropped the band.** The paragraph above is right that empty
    # has to be *visible* — an absent section cannot tell a reader whether the check ran or whether
    # it was skipped — and it does not follow that saying so needs a heading and a full-width card.
    # On a good day, which is most days, this is one line.
    if not found:
        return '<p class="settled">Nothing disagrees: the three checks ran and found nothing.</p>'
    rows = "".join(f'<li class="bad">{_h(line)}</li>' for line in found)
    return _section(
        "What disagrees",
        "Where two things this instance recorded cannot both be true.",
        f'<div class="band"><ul>{rows}</ul></div>',
    )


def _violations_in(seal: object) -> bool:
    """Whether this attempt's seal recorded a model other than the one asked for."""
    if not isinstance(seal, dict):
        return False
    return bool(seal.get("violations"))


_TERMINAL_CODE = re.compile(r"`([^`]+)`")


def _as_code(said: str) -> str:
    """`like this` becomes code, because these sentences were written for a terminal.

    Seen by opening the page rather than by reading the source: every detail in both panels comes
    from a string a command prints, where a backtick is punctuation an eye skips. Rendered into HTML
    they are literal backticks, and a literal backtick beside a command name reads as a typo in the
    product rather than as a quotation in it.

    Escaped first, then marked up — never the other way round, or a detail containing `<` would be
    escaping something this function had just written.

    The same is true of the emphasis, and this function did not handle it: `deliveries` says a
    tracker is configured and no delivery has ever arrived, with the second half emphasised, and
    the page served two pairs of literal asterisks. `_own_prose` carries the argument for why this
    is safe on any input — by the time the substitution runs every `<` is already `&lt;`, so it
    cannot assemble markup out of a project slug that came from somebody else's tracker.
    """
    return _emphasised(
        _TERMINAL_CODE.sub(lambda found: f"<code>{found.group(1)}</code>", _h(said))
    )


def _titled(one: object) -> str:
    """A finding calls it `check` and a standing calls it `name`; both mean the same thing."""
    return str(getattr(one, "check", None) or getattr(one, "name", ""))


def as_a_block(text: str) -> str:
    """Text whose line breaks are the point, marked so `_outcome` keeps them. Item 223.

    `_outcome` renders a sentence, and a sentence in a paragraph is right for every other answer on
    this page. A proposed manifest is not a sentence: it is forty-one lines somebody copies.
    """
    return _BLOCK + text


#: The marker, rather than a second parameter threaded through four routes for one caller.
_BLOCK = "\x00block\x00"


def _outcome(said: str | None) -> str:
    """What the last action answered, verbatim. Item 219.

    **Every refusal in this product already carries its own sentence**, so this renders whatever it
    was given rather than composing one. A page that replaced *`--give-up` needs `--why`* with
    *something went wrong* would be throwing away the only part worth reading.
    """
    if not said:
        return ""
    if said.startswith(_BLOCK):
        return f'<pre class="wide outcome"><code>{_h(said[len(_BLOCK):])}</code></pre>'
    return f'<p class="sub outcome">{_as_code(said)}</p>'


def what_this_can_do(session: Session, project: _Project, settings: Settings) -> str:
    """`hullwork features`, for the project a reader is looking at. Item 220, item 218 §2.

    The command answers for the checkout it is run in; a page serves an instance that may watch
    somebody else's repositories entirely, so the answer has to be per project. The manifest is the
    instance's own copy (DR-0012) and the variable names are this process's.

    **Unmet means three different things here and only one is a defect**, which is what `Need.reads`
    names. A checkout-shaped requirement cannot be answered at all — item 142 forbids a forge
    request per render — so it says *not asked yet* rather than *no*, the same answer the credential
    audit gives one section up. And a credential the dispatcher owns is downgraded exactly as
    `doctor.not_from_here` downgrades it, because reporting the model key missing on an instance
    where the half that uses it holds it sends somebody to repair a working machine.
    """
    from hullwork import features as features_module
    from hullwork.manifest import parse_manifest

    manifest = None
    if project.manifest:
        try:
            manifest = parse_manifest(json.dumps(project.manifest))
        except Exception:  # a stored manifest that no longer parses is `projects refresh`'s to say
            manifest = None
    checkout = features_module.Checkout(
        paths=(),
        manifest=manifest,
        configured=frozenset(_configured_here(settings)),
    )
    elsewhere = _the_dispatchers_to_answer(session)

    rows = []
    for answer in features_module.examine(checkout):
        rows.append(_one_feature(answer, elsewhere=elsewhere))
    return _fold(
        f"What Hullwork can do for {project.slug}, and what it cannot",
        f'<ul class="standing">{"".join(rows)}</ul>',
    )


def _configured_here(settings: Settings) -> list[str]:
    """The **names** of the variables this process received, never their values.

    `Checkout.configured` is names only by design — that is what lets this say *needs a model
    credential, and none is configured* without ever holding one.
    """
    from hullwork.features import CODE_TOKEN, MODEL_KEY

    here = []
    if settings.model_key is not None:
        here.append(MODEL_KEY)
    if settings.forge_code_token is not None:
        here.append(CODE_TOKEN)
    return here


def _the_dispatchers_to_answer(session: Session) -> bool:
    """Whether a dispatcher is alive, which is the only thing that licenses a downgrade.

    `doctor.not_from_here`'s rule, not a second one: ownership rather than location. With no
    dispatcher alive nothing is downgraded — the absence of one is exactly when somebody needs to
    know what is missing.
    """
    from hullwork import lease as lease_module

    try:
        state, _ = lease_module.state(session)
    except Exception:  # any failure here means "cannot tell", whatever its class
        return False
    return state == "alive"


def _one_feature(answer: object, *, elsewhere: bool) -> str:
    """One feature, its state, what is in the way, and its limits — which are printed either way.

    **A limit is true whether or not the feature is available.** Rendering them only for what is off
    would turn them into excuses instead of the description they are.
    """
    feature = answer.feature  # type: ignore[attr-defined]
    missing = list(answer.missing) + list(answer.withheld)  # type: ignore[attr-defined]
    unanswerable = [need for need in missing if need.reads == "checkout"]
    theirs = [need for need in missing if need.reads == "instance"] if elsewhere else []
    real = [need for need in missing if need not in unanswerable and need not in theirs]

    if real:
        word, tone = "no", "refused"
    elif theirs or unanswerable:
        word, tone = "not from here" if theirs else "not asked yet", "idle"
    else:
        word, tone = "yes", "idle"

    said = [
        f'<li class="c-{tone}"><span class="pill">{_h(word)}</span>'
        f'<span class="name">{_h(feature.name)}</span>'
        f'<p class="why">{_as_code(feature.does)}</p>'
    ]
    for need in real:
        said.append(f'<p class="why">needs {_as_code(need.what)} — {_as_code(need.fix)}</p>')
    for need in theirs:
        said.append(
            f'<p class="why">{_as_code(need.what)}: not from here — a dispatcher is running and '
            f"this is a resource it uses, not one this process does.</p>"
        )
    for need in unanswerable:
        said.append(
            f'<p class="why">{_as_code(need.what)}: not asked yet — nothing on this instance '
            f"reads your tree, and a page render does not spend a forge request to find out. "
            f"{_as_code('`hullwork features --checkout .`')} answers it where the code is.</p>"
        )
    for limit in feature.limits:
        said.append(f'<p class="why limit">{_as_code(limit)}</p>')
    said.append("</li>")
    return "".join(said)


def _why_it_is_empty(session: Session) -> str:
    """Why there are no items, from the table that knows. Item 231.

    **The old sentence was a guess.** *Nothing has arrived from the error tracker on this instance*
    was written before anything asked, and it is one of three states an empty list is consistent
    with — the other two being *things arrived carrying no error* and *things arrived and could not
    be understood*, which have different causes and different fixes.
    """
    from hullwork.models import Delivery

    arrived = session.scalar(select(func.count()).select_from(Delivery)) or 0
    if not arrived:
        return (
            "No items yet, and no delivery has ever been accepted. A call with the wrong secret is "
            "refused before anything is written down, so this says none arrived with a working "
            "secret rather than that nobody knocked"
        )
    unread = (
        session.scalar(
            select(func.count()).select_from(Delivery).where(Delivery.error.is_not(None))
        )
        or 0
    )
    if unread:
        return (
            f"No items yet. {arrived} delivery(s) arrived and {unread} could not be understood — "
            f"each carries its own reason on its project"
        )
    return (
        f"No items yet. {arrived} delivery(s) arrived and none of them carried an error, which is "
        f"a tracker sending something that is not one"
    )


def what_arrived_for(session: Session, project: _Project) -> str:
    """What the tracker actually sent, and what became of it. Item 231.

    **The page kept saying `nothing has arrived` without asking.** Three states are consistent with
    an empty front door — nothing arrived, things arrived carrying no error, things arrived and
    could not be understood — and only the first is what that sentence claims.

    **A refused secret leaves no row.** `webhooks.py` answers `401` before anything is written, so
    an empty list here means nobody knocked *with a working secret*, and saying more than that would
    be the same lie as an advisory list rendered empty after a failed request.

    No body and no hash: this table keeps payloads verbatim, and a page whose whole audience is
    people who are not the operator has no business rendering somebody else's error payload.
    """
    from hullwork.models import Delivery, Event

    rows = list(
        session.scalars(
            select(Delivery)
            .where(Delivery.project_id == project.id)
            .order_by(Delivery.received_at.desc())
            .limit(20)
        ).all()
    )
    total = session.scalar(
        select(func.count()).select_from(Delivery).where(Delivery.project_id == project.id)
    ) or 0
    if not rows:
        return (
            "<p>No delivery has ever been accepted for this project. That is not the same as "
            "nobody having knocked: a call with the wrong secret is refused before anything is "
            "written down, so this list can only say that none arrived <strong>with a working "
            "secret</strong>. The rejection is in this instance's log.</p>"
        )

    counted = session.execute(
        select(Event.delivery_id, func.count())
        .where(Event.delivery_id.in_([one.id for one in rows]))
        .group_by(Event.delivery_id)
    ).all()
    facts: dict[int, int] = dict(counted)  # type: ignore[arg-type]
    listed = "".join(
        '<tr><td data-label="arrived">'
        f'<time datetime="{_h(one.received_at)}" title="{_h(one.received_at)}">'
        f"{_h(_ago(one.received_at))}</time></td>"
        f'<td data-label="understood">'
        + (
            f'<span class="stuck">{_h(one.error[:80])}</span>'
            if one.error
            else ("yes" if one.processed_at else "not yet")
        )
        + f'</td><td data-label="facts in it">{_h(facts.get(one.id, 0))}</td>'
        f'<td data-label="tries">{_h(one.attempts)}</td></tr>'
        for one in rows
    )
    carried = sum(facts.values())
    return (
        f'<p class="sub">{total} delivery(s) accepted, carrying {carried} fact(s).</p>'
        '<div class="wide"><table class="list"><tr><th>arrived</th><th>understood</th>'
        f"<th>facts in it</th><th>tries</th></tr>{listed}</table></div>"
        '<p class="sub">A delivery carrying no fact is a tracker sending something that is not an '
        "error, which is ordinary. One that was never understood carries its own reason.</p>"
    )


#: What each verdict means **in the reader's terms**, and the colour it is allowed to wear.
#:
#: **Four states that do not collapse into two** (DR-0026). `clean` is *your suite passed before and
#: after* and not *this is safe*. `will-not-install` is the build refusing, which is a different
#: fact from the suite failing — painting it red would be this product telling somebody their code
#: is broken when what broke was an install. `already-red` is a suite that was failing before
#: anything was touched, so no claim can be made either way, and the colour says *this needs a
#: person* rather than *this is bad news*.
_WHAT_IT_MEANT: dict[str, tuple[str, str]] = {
    "clean": ("your suite passed, before and after", "c-passed"),
    "breaks": ("your suite fails on it", "c-refused"),
    "will-not-install": ("the build refused it, so your suite never ran", "c-idle"),
    "already-red": ("your suite was already failing, so nothing can be claimed", "c-human"),
    "cannot-rewrite": ("the pin could not be rewritten without breaking the install", "c-idle"),
    "cannot-move": ("the pin could not be moved to it", "c-idle"),
}


def _may_open_upgrades(project: _Project) -> bool:
    """Whether this project's manifest permits opening an upgrade. DR-0019, item 245.

    Read from the copy the instance holds, which is the copy every other decision reads (DR-0012).
    A project that declares nothing permits nothing: `open_upgrades` is `false` by default because
    having the credential is not the same as having agreed.
    """
    manifest = getattr(project, "manifest", None)
    if not isinstance(manifest, Mapping):
        return False
    autofix = manifest.get("autofix")
    return bool(isinstance(autofix, Mapping) and autofix.get("open_upgrades"))


#: The states a pinned package can be in, in the order a reader can act on them. DR-0028.
#:
#: **The order is the grouping.** A reader opens this view to find out what to do, so what can be
#: done comes first and what nobody can do comes last — never the order the report happens to list.
#: The sentence beside each state is said **once**, in the heading: a column repeating the same
#: sentence twenty-seven times is a column that should not exist, which is the fault the first
#: prototype of this decision found in itself.
_BANDS: tuple[tuple[str, str, str, str], ...] = (
    ("ready", "Ready to open", "passed your suite before the change and after it", "passed"),
    ("asked", "Opening", "asked for — the dispatcher opens it on its next turn", "human"),
    ("open", "Already open", "a draft pull request is waiting for a person", "working"),
    # **The two the forge answers, which nothing used to ask** (item 253). Without them a merged
    # pull request sat in the band above asking for a review that had already happened, and a
    # closed one sat there for ever displaying somebody's "no" as work they still owed.
    ("merged", "Merged",
     "the pull request was merged; the advisory goes when the next report is taken", "passed"),
    ("declined", "You closed these",
     "opened, and closed by a person without merging — each row says what they gave as the reason",
     "refused"),
    # **The one band whose reason is per row rather than per group** (item 178's rule, kept): a
    # request that produced nothing is either already open from an earlier run or something the
    # forge refused, and those are different sentences. Never silence — a row that was asked for
    # and shows neither outcome is a row somebody presses again.
    ("refused", "Asked for, and not opened", "each row says what stopped it", "refused"),
    ("breaks", "Breaks your suite", "the upgrade applied and your tests stopped passing",
     "refused"),
    ("install", "Would not install", "the build refused it, so your suite never ran", "faint"),
    ("stuck", "The pin would not move",
     "the resolver refused the version, or your manifest forbids it", "faint"),
    ("stale", "Verified before this instance kept the files",
     "passed your suite before the change and after it, and is re-measured on the next report "
     "so it can be opened", "faint"),
    # **Item 234, as a band.** The honest answer about a project whose own test suite was already
    # failing is *nothing can be claimed either way*, and it is about the project rather than about
    # any upgrade — so it is said once, in this heading, and the packages it covers are still named.
    # Rendering it per row is what produced fifty identical lines in an hour.
    ("baseline", "Nothing could be claimed",
     "this project's own test suite was already failing before anything was touched", "human"),
    ("untried", "Not tried yet", "the queue reaches one per idle turn", "faint"),
    ("nofix", "Nothing published to upgrade to",
     "an advisory with no fixed version — a person decides", "refused"),
)

#: Which state wins when one package is pinned at versions in different states: **the one that most
#: needs a person**. A row is a place to act, and a reader scanning for what to do must not have a
#: package hidden under its quietest version.
_BAND_RANK: dict[str, int] = {key: n for n, (key, _, _, _) in enumerate(_BANDS)}

#: The states whose row has a pull request behind it. `open` invites a review; the other two are
#: evidence of one that happened, and both are worth a click (item 253).
_CARRY_A_LINK = ("open", "merged", "declined")


def _state_of(verdicts: Sequence[Any], fixed: Sequence[str]) -> tuple[str, str | None, str | None]:
    """The state of one pinned version, what it would move to, and where its pull request went.

    Every rule the two lists this replaces had encoded, now in one place:

    * a build refusing is **not** a broken suite — `will-not-install` is its own state (item 233);
    * `already-red` claims nothing either way and is said about the **project**, so it never reaches
      a row (item 234);
    * a `clean` verdict with nothing kept cannot be opened and says so, rather than offering a
      control the write path would refuse (item 245);
    * an outcome this page does not recognise falls through to `stuck`, which says *the pin would
      not move* — and the verdict itself is still rendered in the row, so nothing is swallowed.
    """
    # **What the forge last said, before what this instance did** (item 253). `opened_where` alone
    # meant *waiting for a person* for ever: a merged pull request kept asking for a review that had
    # happened, and one a person closed without merging displayed their "no" as work they owed.
    # Both are terminal and neither is *open*, so both are read first.
    settled = [v for v in verdicts if getattr(v, "opened_state", None) in ("merged", "closed")]
    if settled:
        one = settled[0]
        where = str(one.opened_where) if one.opened_where else None
        return ("merged" if one.opened_state == "merged" else "declined"), str(one.to), where
    opened = [v for v in verdicts if getattr(v, "opened_where", None)]
    if opened:
        return "open", str(opened[0].to), str(opened[0].opened_where)
    refused = [v for v in verdicts if getattr(v, "open_note", None)]
    if refused:
        return "refused", str(refused[0].to), None
    asked = [v for v in verdicts if getattr(v, "asked_to_open_at", None) is not None]
    if asked:
        return "asked", str(asked[0].to), None
    clean = [v for v in verdicts if v.outcome == "clean"]
    openable = [v for v in clean if getattr(v, "artefact", None)]
    if openable:
        return "ready", str(openable[0].to), None
    if clean:
        return "stale", str(clean[0].to), None
    breaks = [v for v in verdicts if v.outcome == "breaks"]
    if breaks:
        return "breaks", str(breaks[0].to), None
    refused = [v for v in verdicts if v.outcome == "will-not-install"]
    if refused:
        return "install", str(refused[0].to), None
    if not fixed:
        return "nofix", None, None
    moved = [v for v in verdicts if v.outcome in ("cannot-move", "cannot-rewrite")]
    if moved:
        return "stuck", str(moved[0].to), None
    unknown = [v for v in verdicts if v.outcome != "already-red"]
    if unknown:
        # **A verdict `bump` adds tomorrow must not vanish because this table was not updated.** An
        # unknown state is still a state, and rendering nothing would report *not tried yet*, which
        # is the one thing it is not. The outcome goes in the row, in its own words.
        return "stuck", str(unknown[0].to), f"it ended as {unknown[0].outcome}"
    if verdicts:
        return "baseline", str(verdicts[0].to), None
    return "untried", str(fixed[0]), None


def _packages_of(
    session: Session, project: _Project, findings: Sequence[Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    """One row per package, and how many pairs said the project's own suite was already failing.

    **The package is the subject** (DR-0028). `brace-expansion` pinned at three versions in one lock
    is one row carrying three versions, not three rows that share a name — and the report itself
    hands the same `(package, version)` twice, which this collapses on the way in.
    """
    from hullwork.models import UpgradeVerdict

    held = {
        (one.package, one.was, one.to): one
        for one in session.query(UpgradeVerdict)
        .filter(UpgradeVerdict.project_id == project.id)
        .all()
    }
    rows: dict[str, dict[str, Any]] = {}
    already_red = 0
    for finding in findings:
        package = str(finding.get("package") or "")
        was = str(finding.get("version") or "")
        source = str(finding.get("source") or "")
        raw = finding.get("advisories")
        advisories = raw if isinstance(raw, list) else []
        # De-duplicated for the reason two identifiers are one advisory: *fixed in 49.0.0, 49.0.0,
        # 50.0.0* is a list that has been counted wrong.
        fixed = list(
            dict.fromkeys(
                str(version) for one in advisories for version in (one.get("fixed") or [])
            )
        )
        mine = [held[(package, was, to)] for to in fixed if (package, was, to) in held]
        already_red += sum(1 for one in mine if one.outcome == "already-red")
        state, to, said = _state_of(mine, fixed)
        # A merged or closed pull request still has somewhere to go, and that is where the reader
        # goes to see what happened (item 253) — the link is the evidence, not the invitation.
        where = said if state in _CARRY_A_LINK else None
        row = rows.setdefault(package, {
            "package": package, "sources": [], "pinned": [], "to": [], "states": [],
            "advisories": [], "where": None, "verdict": None, "note": None,
        })
        if source and source not in row["sources"]:
            row["sources"].append(source)
        # **Every published destination, not only the one whose verdict won the row.** OSV publishes
        # two fixed versions when an advisory was fixed on two release branches, and they are two
        # answers; showing the winner's alone loses one of them from the page.
        # **Two sets, never their product.** Pairing every pinned version with every published
        # destination is a cartesian explosion the moment a package is pinned three times and fixed
        # on four branches: `brace-expansion` rendered its version thirty times and stretched the
        # table to 7,208px. What a reader needs is *these versions are pinned, and they move here*.
        #
        # The pinned version is kept even when there is nowhere to move it: the one row nobody can
        # act on was also the one rendering an empty span where its version should be.
        if was and was not in row["pinned"]:
            row["pinned"].append(was)
        for destination in fixed or ([to] if to else []):
            if destination and destination not in row["to"]:
                row["to"].append(destination)
        row["states"].append(state)
        row["where"] = row["where"] or where
        if not row.get("note"):
            if state in ("refused", "declined"):
                # `declined` keeps its reason on the same column `refused` does: the reviewer's
                # words, or the fact that they gave none. Item 178's rule, item 253's state.
                row["note"] = next(
                    (str(one.open_note) for one in mine if getattr(one, "open_note", None)), None
                )
            elif state not in _CARRY_A_LINK and said:
                row["note"] = said
        for one in advisories:
            if one.get("id") not in {seen.get("id") for seen in row["advisories"]}:
                row["advisories"].append(one)
        if state == "ready" and row["verdict"] is None:
            openable = [
                one for one in mine
                if one.outcome == "clean" and getattr(one, "artefact", None)
                and not one.opened_where and one.asked_to_open_at is None
            ]
            row["verdict"] = openable[0].id if openable else None

    ordered = []
    for row in rows.values():
        row["state"] = min(row["states"], key=lambda s: _BAND_RANK[s])
        ordered.append(row)
    ordered.sort(key=lambda r: r["package"])
    return ordered, already_red


def _subject(row: Mapping[str, Any], colour: str, *, project: _Project, acting: Acting,
             permitted: bool) -> str:
    """One package, one row: what it is, where, what it would move to, and the one thing to do."""
    # Both sides are capped for the same reason: a row is scanned, and the enumeration is what the
    # fold and the project's own lock file are for.
    pinned = [_h(one) for one in row["pinned"][:2]]
    if len(row["pinned"]) > 2:
        pinned.append(f"+{len(row['pinned']) - 2}")
    froms = " · ".join(pinned)
    # **Three destinations and a count, not eleven.** OSV publishes a fixed version per release
    # branch, so a package pinned across a major version can land in a dozen places — and a reader
    # deciding whether to look needs *there is somewhere to go*, not the enumeration.
    landings = [_h(one) for one in row["to"][:2]]
    rest = len(row["to"]) - len(landings)
    if rest > 0:
        landings.append(f"+{rest}")
    move = (
        f'<span class="was">{froms}</span><span class="arr">→</span>'
        f'<span class="to">{" · ".join(landings)}</span>'
        if landings
        else f'<span class="was">{froms}</span>'
    )
    says = "".join(
        f'<li><a href="https://osv.dev/vulnerability/{_h(one.get("id"))}" rel="noreferrer">'
        f'{_h(one.get("id"))}</a> {_h(one.get("summary") or "")}</li>'
        for one in row["advisories"][:8]
    )
    rest = len(row["advisories"]) - 8
    if rest > 0:
        says += f'<li class="more">and {rest} more</li>'
    fold = (
        f'<details class="adv"><summary>{len(row["advisories"])}</summary>'
        f'<ul class="folded">{says}</ul></details>'
        if row["advisories"] else ""
    )
    # **The one thing a row says in prose**, because each refusal differs: *already open from an
    # earlier run* and *the forge refused it* are not the same sentence, so this cannot move to a
    # heading the way every other state's explanation did.
    note = (
        f'<span class="note">{_h(row["note"])}</span>' if row.get("note") else ""
    )
    return (
        f'<tr class="subject">'
        f'<td class="who"><span class="dot {_h(colour)}"></span>'
        f'<span class="thing">{_h(row["package"])}</span>{move}{note}</td>'
        f'<td class="at">{_h(" · ".join(row["sources"]))}</td>'
        f'<td class="fold">{fold}</td>'
        f'<td class="do">'
        f"{_action_for(row, project=project, acting=acting, permitted=permitted)}</td>"
        f"</tr>"
    )


def _action_for(row: Mapping[str, Any], *, project: _Project, acting: Acting,
                permitted: bool) -> str:
    """The one control this row has, or nothing at all.

    **No column of empty cells** (DR-0028): the action column was empty in twenty-five rows out of
    twenty-six, paying width to say nothing. It renders where it exists and the cell collapses
    everywhere else.
    """
    if row["state"] in _CARRY_A_LINK and row["where"]:
        return (
            f'<a href="{_h(row["where"])}" rel="noreferrer">'
            f'#{_h(str(row["where"]).rsplit("/", 1)[-1])} ↗</a>'
        )
    if row["state"] != "ready" or not permitted or not acting.csrf or not row["verdict"]:
        return ""
    csrf = f'<input type="hidden" name="csrf" value="{_h(acting.csrf)}">'
    return (
        # **`dependencies`, which is the URL this view is served from** (item 250). It posted to
        # `../<slug>` and the handler answered with this view — a document written for
        # `projects/<slug>/dependencies`, carrying `../../`, returned from one level up. Every link
        # on the page that came back resolved outside the token's prefix entirely.
        f'<form method="post" action="dependencies" class="decide">{csrf}'
        f'<input type="hidden" name="verdict" value="{int(row["verdict"])}">'
        '<button type="submit" name="action" value="open-upgrade">Open a draft PR</button></form>'
    )


def _the_packages(
    session: Session,
    project: _Project,
    findings: Sequence[Mapping[str, Any]],
    *,
    acting: Acting,
) -> str:
    """Every package with something published against it, grouped by what can be done. DR-0028."""
    rows, already_red = _packages_of(session, project, findings)
    if not rows:
        return ""
    permitted = _may_open_upgrades(project)
    bands, tally = [], []
    for key, title, says, colour in _BANDS:
        here = [row for row in rows if row["state"] == key]
        if not here:
            continue
        tally.append(
            f'<span class="one"><span class="dot {colour}"></span>'
            f'<b>{len(here)}</b> {_h(title.lower())}</span>'
        )
        lines = "".join(
            _subject(row, colour, project=project, acting=acting, permitted=permitted)
            for row in here
        )
        bands.append(
            f'<section class="band"><h3><span>{_h(title)}</span>'
            f'<em>{_h(says)}</em><b>{len(here)}</b></h3>'
            f'<table class="subjects">{lines}</table></section>'
        )
    ready = sum(1 for row in rows if row["state"] == "ready")
    return (
        f'<p class="tally">{"".join(tally)}</p>{"".join(bands)}'
        f"{_baseline_note(already_red, rows)}"
        f"{_about_opening(ready, permitted=permitted, acting=acting)}"
        # **Said once, at the end, and it is not decoration**: the claim this half of the product
        # rests on is that nothing here happens on a clock. DR-0026 is the decision; this is where a
        # reader who never opens a decision record finds out.
        '<p class="sub">Each upgrade was applied in a clone, built, and measured against this '
        "project's own suite. This instance verifies on its own clock and <strong>never opens one "
        "by itself</strong> — what gets opened, a person asks for, and nobody merges it but "
        "you.</p>"
    )


def _baseline_note(already_red: int, rows: Sequence[Mapping[str, Any]]) -> str:
    """How many pairs the red-baseline band covers, said once. Item 234.

    **About the project, not about the upgrade.** A repository whose own tests are red gives one
    answer to every pair in the queue, and rendering it per row buries whatever else is there —
    which is why the sentence lives in that band's heading. This adds only the arithmetic the
    heading cannot carry: a band lists *packages*, and the queue answered *pairs*.
    """
    if not already_red or not any(row["state"] == "baseline" for row in rows):
        return ""
    return (
        f'<p class="sub c-human">That covers {already_red} upgrade(s), measured once and asked '
        f"again when the next dependency report is taken.</p>"
    )


def _about_opening(ready: int, *, permitted: bool, acting: Acting) -> str:
    """What a reader can do with what passed, or why they cannot. Item 245, DR-0019.

    **The count goes in front of the refusal**, which is the order the terminal uses and the reason
    it reads as a decision rather than as a part that is missing.
    """
    if not ready:
        return ""
    if not acting.csrf:
        return (
            f'<p class="sub">{ready} of these can be opened as draft pull requests. Signing in is '
            f"what offers the control.</p>"
        )
    if not permitted:
        return (
            f'<p class="sub c-human">{ready} passed your suite and <strong>none can be '
            f"opened</strong>: this project has not permitted it. Set "
            f"<code>autofix: {{open_upgrades: true}}</code> in its manifest if you want that "
            f"button. It is false by default because having the credential is not the same as "
            f"having agreed.</p>"
        )
    return ""


def what_is_published_against_it(
    session: Session, project: _Project, *, acting: Acting = READING
) -> str:
    """What OSV had published against what this project pins, and when that was asked. DR-0024.

    **The half an evaluator can use on their first day**, which until item 230 left no trace in a
    running instance at all: `hullwork deps` opened no session, stored nothing, and could not run
    inside the container.

    Three states and they are not two. *Nothing published* is good news; *nothing pinned* is a
    different sentence about a different problem; and **could not ask** is neither — an advisory
    list that silently reads empty when OSV was unreachable says *you are fine* on no evidence, and
    is the failure this feature must not have.

    **No longer folded** (item 235, DR-0027). This is a feature, and a feature one click away is
    what made this page difficult three times running: it returns the block, and the page it belongs
    to decides where the block goes.
    """
    from hullwork.models import DependencyReport

    report = session.get(DependencyReport, project.id)
    if report is None:
        return (
            "<p>Not asked yet. This instance reads what you pin and asks OSV on its own clock, "
            "within six hours of a project being connected.</p>"
        )

    when = f'<p class="sub">Asked {_h(_ago(report.taken_at))}.</p>'
    if not report.asked:
        return (
            f'<p class="bad">Could not ask: '
            f'{_as_code(report.note or "the reason was not recorded")}</p>{when}'
            "<p>This is not an empty report. Nothing here says your dependencies are fine; it "
            "says the question did not reach an answer.</p>"
        )
    if not report.pinned:
        return f'<p>Nothing pins a version. {_as_code(report.note or "")}</p>{when}'
    if not report.findings:
        return (
            f"<p>OSV has nothing published against any of the {report.pinned} pinned version(s) "
            f"this repository declares.</p>{when}"
            '<p class="sub">It reads what you pinned, so a dependency your build resolves at '
            "install time is invisible to it — and it asks one database.</p>"
        )
    # **One list, not two** (DR-0028). What OSV publishes about a package and what this instance did
    # about it were two sections six screens apart, so the questions a reader asks — what is
    # wrong with this one, was it tried, what happened, can I do anything — were answered in two
    # places that had to be joined from memory.
    packages, _ = _packages_of(session, project, report.findings)
    return (
        f'<p class="sub">{report.pinned} versions pinned · {len(packages)} package(s) with '
        f"something published · asked {_h(_ago(report.taken_at))}.</p>"
        f"{_the_packages(session, project, report.findings, acting=acting)}"
    )


def _the_rest_of_its_life(project: _Project, acting: Acting) -> str:
    """The four things item 207 built routes for and buttons for nothing. Item 223.

    **Every one of them was reachable only by `curl`.** The route took `refresh`, `disable`,
    `set-tracker` and `rotate-secret`; the tests posted straight at it, which is a fair test of a
    route and no test at all of a page. An operator on this view could do none of it.

    Rotating is separated from the other three and says what it breaks **before** it is pressed: the
    tracker's current webhook URL stops working the moment it succeeds, and the new secret is shown
    once.
    """
    if not acting.csrf:
        return ""
    csrf = f'<input type="hidden" name="csrf" value="{_h(acting.csrf)}">'
    # **`settings`, which is the URL this view is served from** (items 249 and 250). Item 249 found
    # these posting to `../projects/<slug>` — `projects/projects/<slug>`, a route that does not
    # exist, so all five controls posted into a 404 — and corrected them to `../<slug>`. That was
    # the minimum: a route that exists. This is the right one, because the answer to a press is
    # served at the URL it posted to, and the document for that URL is this view. `../<slug>`
    # answered with the project's overview and bounced a reader out of settings after every action.
    where = "settings"
    tracker = _h(project.tracker_project or "")
    return (
        f'<form method="post" action="{where}" class="decide">{csrf}'
        '<button type="submit" name="action" value="refresh">Re-read its manifest</button>'
        + "</form>"
        + (
            # Two submissions, like `prune`: the first says what stopping means, the second does
            # it. And a disabled project is offered the way back rather than the way out.
            f'<form method="post" action="{where}" class="decide">{csrf}'
            '<button type="submit" name="action" value="disable-preview">'
            "What stopping it means</button>"
            '<button type="submit" name="action" value="disable">Stop watching it</button></form>'
            if project.active
            else f'<p class="sub">Not watched. No error from it becomes an item and the sweep '
            "skips it; nothing was deleted.</p>"
            f'<form method="post" action="{where}" class="decide">{csrf}'
            '<button type="submit" name="action" value="enable">Watch it again</button></form>'
        )
        + f'<form method="post" action="{where}" class="new">{csrf}'
        '<p class="field"><label for="tracker-name">Its name in the tracker</label>'
        f'<input id="tracker-name" name="tracker_project" value="{tracker}"></p>'
        '<button type="submit" name="action" value="set-tracker">Name it</button></form>'
        '<p class="sub">Rotating the webhook secret <strong>stops the URL your tracker is using '
        "now</strong>, and the new one is shown once and never again — only its hash is kept.</p>"
        f'<form method="post" action="{where}" class="decide">{csrf}'
        '<button type="submit" name="action" value="rotate-secret">Issue a new secret</button>'
        "</form>"
    )


def _sweeping(project: _Project, acting: Acting) -> str:
    """The tracker's unresolved list, for a project the webhook cannot have told the whole truth
    about. DR-0011, item 219.

    **Counted before it is filed, and the count is what you confirm.** The webhook fires when an
    issue is created and never again, so a bug that was already failing when Hullwork was installed
    never arrives by that door. Sweeping is how it does — and a project with three hundred open
    issues becomes three hundred forge issues in one pass unless somebody sees the number first.
    """
    if not acting.csrf or not project.tracker_project:
        return ""
    csrf = f'<input type="hidden" name="csrf" value="{_h(acting.csrf)}">'
    return (
        # **`settings`, the URL this view is served from** (items 249, 250). It posted to
        # `../projects/<slug>` — `projects/projects/<slug>`, which is not a route, so every control
        # in this section was dead — and then to `../<slug>`, which exists but is a different view.
        f'<form method="post" action="settings" class="decide">{csrf}'
        '<button type="submit" name="action" value="sweep">What the tracker still has</button>'
        '<button type="submit" name="action" value="sweep-confirm">File them</button></form>'
    )


def _reading_the_repository(project: _Project, acting: Acting) -> str:
    """The two answers that come from the repository itself, on request. Item 222.

    **Each spends one forge read, and only when somebody presses it.** Item 142's rule is about a
    *render* — a reader refreshing would spend one each time — and these are actions, the same shape
    `projects refresh` has had since item 206. Reading that rule as a ban on both was mine, and it
    parked two commands behind a decision they never needed.

    Neither stores anything. The lane policy especially: a derived policy kept on disk would be a
    snapshot of *which code is dangerous*, and `territory.py` says why that fails in the direction
    that matters.
    """
    if not acting.csrf:
        return ""
    csrf = f'<input type="hidden" name="csrf" value="{_h(acting.csrf)}">'
    return (
        # **`settings`, the URL this view is served from** (items 249, 250). Same two corrections as
        # the block above: first to a route that exists, then to the one this view is.
        f'<form method="post" action="settings" class="decide">{csrf}'
        '<button type="submit" name="action" value="lanes">Which files keep a human on</button>'
        '<button type="submit" name="action" value="propose">Read a manifest from its CI</button>'
        "</form>"
    )


def _housekeeping(session: Session, acting: Acting) -> str:
    """The instance's own upkeep: the lease, and the only destructive control on this page.

    Folded, because none of it is what somebody came for — item 203's rule about what is above a
    fold and what is below one. Shown to nobody without a session (DR-0021).
    """
    if not acting.csrf:
        return ""
    from hullwork import lease as lease_module

    holder = lease_module.holder_of(session)
    who = (
        f"Held by <code>{_h(holder)}</code>."
        if holder
        else "No dispatcher holds it."
    )
    csrf = f'<input type="hidden" name="csrf" value="{_h(acting.csrf)}">'
    body = (
        f"<p>{who} Releasing it means the next dispatcher does not wait for the expiry.</p>"
        f'<form method="post" action="instance" class="decide">{csrf}'
        '<input type="hidden" name="action" value="lease-release">'
        "<button type=\"submit\">Release the lease</button></form>"
        '<p class="sub">Verdicts the dispatcher reached and could not send are finished by '
        "publishing them again. The attempt is already spent either way.</p>"
        f'<form method="post" action="instance" class="decide">{csrf}'
        '<input type="hidden" name="action" value="republish">'
        "<button type=\"submit\">Publish what is stranded</button></form>"
        "<p>The read link is a shared key: anyone holding it reads every item and captured "
        "output here. Issuing a new one <strong>stops the URL anybody is using now</strong>, "
        "which is what you press it for — and the new one is shown once.</p>"
        f'<form method="post" action="instance" class="decide">{csrf}'
        '<input type="hidden" name="action" value="page-token">'
        '<button type="submit">Issue a new read link</button></form>'
        "<p>Forgetting the verbatim bodies of old deliveries keeps every row, fingerprint and "
        "issue reference. It is the only thing on this page that destroys anything, so it "
        "says what it would drop first.</p>"
        f'<form method="post" action="instance" class="new">{csrf}'
        '<p class="field"><label for="older-than">Older than (days)</label>'
        '<input id="older-than" name="older_than_days" value="30" inputmode="numeric"></p>'
        '<button type="submit" name="action" value="prune-preview">What would go</button>'
        '<button type="submit" name="action" value="prune">Forget them</button></form>'
    )
    return _fold("Upkeep: the lease, stranded verdicts, and forgetting old bodies", body)


def _rows_for_standing(rows: Sequence[object]) -> str:
    """The panel's rows, for both views. Items 203 and 208.

    **One renderer, because two that happen to look alike is how the borrowed list ended up in
    both of them** — and how a fix to one would leave the other painting a `cannot` amber.

    Takes anything with `check`/`name`, a state and a `detail`, which is what `doctor.Finding` and
    `features.Standing` both are. A decision reads quiet and a fault reads red: DR-0019 in colour,
    because painting a choice somebody made as a defect tells them to go and repair it.
    """
    said = []
    for one in rows:
        state = getattr(one, "state", "")
        word = getattr(state, "value", state)
        broken = word in ("broken", "cannot")
        said.append(
            f'<li class="c-{"refused" if broken else "idle"}">'
            f'<span class="pill">{_h(word)}</span>'
            f'<span class="name">{_h(_titled(one))}</span>'
            f'<p class="why">{_as_code(getattr(one, "detail", ""))}</p></li>'
        )
    return "".join(said)


def why_it_will_not_work(
    session: Session, settings: Settings, *, acting: Acting = READING
) -> str:
    """`doctor`, for somebody without a shell. Item 208, DR-0022.

    **The findings, not a second diagnosis.** `doctor.examine` already returns them and item 199's
    pre-flight already renders them elsewhere; a page that asked its own questions would drift from
    the command an operator quotes in a bug report.

    `not_from_here`'s downgrade comes with them and must: the receiver is not the dispatcher, and a
    page reporting the model credential missing — on an instance where it is present in the half
    that uses it — sends somebody to repair a working machine.
    """
    from hullwork import doctor as doctor_module

    found = doctor_module.examine(
        session,
        settings,
        code_forge=None,
        env_file=Path(settings.deployment_env_file or ".env"),
        compose_file=(
            Path(settings.deployment_compose_file) if settings.deployment_compose_file else None
        ),
    )
    worrying = [one for one in found if one.state is not doctor_module.State.OK]
    rows = _rows_for_standing(worrying)
    body = (
        '<h1>Diagnostics</h1><p class="says">Every check this instance runs on itself, and what '
        "each one would stop working if it failed.</p>"
        + (
            f'<ul class="standing">{rows}</ul>'
            f'<p class="sub">{len(found) - len(worrying)} of {len(found)} check(s) are fine.</p>'
            if worrying
            else f'<p class="sub">All {len(found)} check(s) are fine.</p>'
        )
    )
    return _document(
        "Hullwork — doctor", body, acting=acting, here="doctor",
        projects=each_project(session),
    )


def what_it_received(settings: Settings, *, acting: Acting = READING) -> str:
    """`config`, for somebody without a shell. Item 208.

    **No credential is printed**, and that is `settings_report`'s property rather than this
    function's: a secret reads `set` or `not set` before it ever reaches here. Worth saying because
    `config` reads like the most disclosing thing in the product and is in fact the most carefully
    disclosing thing in it.
    """
    from hullwork import settings_report

    rows = "".join(
        f"<tr><th>{_h(name)}</th><td>{_h(value)}</td>"
        f"<td>{_h(source)}</td><td>{_h(reaches)}</td></tr>"
        for name, value, source, reaches in settings_report.rows(settings)
    )
    body = (
        "<h1>What it received</h1>"
        '<p class="sub">What this process was handed, which is a different question from what you '
        "wrote in a file. No credential is printed: a secret reads <code>set</code> or "
        "<code>not set</code>.</p>"
        '<div class="wide"><table><tr><th>variable</th><th>value</th><th>from</th>'
        f"<th>reaches</th></tr>{rows}</table></div>"
    )
    return _document(
        "Hullwork — configuration", body, acting=acting, here="config"
    )


def _what_this_instance_has_switched_on(session: Session, settings: Settings) -> str:
    """The feature-by-feature standing, worst first. Item 203.

    **From `features.on_this_instance`, which the terminal prints too**, so the page and
    `hullwork status` cannot come to disagree about the same instance — the rule `instance`'s own
    docstring states about its numbers, applied to its states.

    An instance with everything on says so in one line: fourteen green rows is a wall a reader stops
    looking at, and the thing they came for is whichever one is not green.
    """
    from hullwork import features

    standing = features.on_this_instance(session, settings)
    worrying = [one for one in standing if one.state is not features.ON]
    if not worrying:
        return (
            '<p class="sub">Every feature this instance can have is on. '
            f"{len(standing)} of {len(standing)}.</p>"
        )
    rows = _rows_for_standing(worrying)
    on = len(standing) - len(worrying)
    return (
        f'<ul class="standing">{rows}</ul>'
        f'<p class="sub">{on} of {len(standing)} feature(s) on.</p>'
    )


def instance(
    session: Session,
    settings: Settings,
    *,
    error_reporting: bool,
    acting: Acting = READING,
    said: str | None = None,
) -> str:
    """What `hullwork status` says, for somebody who does not have a terminal on this host.

    **Every number comes from the function `status` calls**, never from a second query written for
    this page: `readiness.check`, `outcomes.desk`, `outcomes.funnel`, `recurrence.counted` and
    `undecided`, `lease.state` and `reporting_of`. A page that recomputed them would drift, and the
    first anybody would know is a reader and an operator disagreeing about the same instance.
    """
    from hullwork import lease, outcomes, readiness, recurrence

    report = readiness.check(session, settings, error_reporting=error_reporting)
    merged, holding, recurred = recurrence.counted(session)
    undecided = recurrence.undecided(session)
    loop_state, loop_seen = lease.state(session)
    reporting = lease.reporting_of(session)

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
    # **The number DR-0017 is measured by** (item 183), and it was in the terminal and not here —
    # which is the same defect item 136 already found on this page once: a fact the instance knew,
    # put where nobody reading would find it. The interface design says this surface exists
    # to show what was verified and what was not; a count of attempts is not that, and this is.
    # **The page's skin of the same structure the terminal prints as sentences** (item 248). Six
    # sections of prose bullets were 500 of this view's 779 words, and every bullet was a number
    # with a sentence wrapped around it — so a reader comparing this week to last had to parse eight
    # of them to find two figures.
    desk = _desk_figures(outcomes.desk(session))
    attempts = _funnel_figures(outcomes.funnel(session))
    spent = "".join(
        f"<li>{_h(line.strip())}</li>"
        for line in spend.lines(
            spend.per_instance(
                list(session.scalars(select(_Attempt)).all()),
                spend.Prices.from_settings(settings),
            )
        )
    )

    counted_reviews = outcomes.reviewed(session)
    reviewed = _review_figures(counted_reviews, outcomes.review_lines(counted_reviews))

    prices = spend.Prices.from_settings(settings)

    #: **The order is the item, and not the order this page had.** the interface document
    #: asks three questions — on fire, what is it doing, is anything waiting on me — and it answered
    #: in that order with six equal cards, which is how the third became invisible. Answer first,
    #: context second: a problem or a decision is something to *do*, and what the machine is busy
    #: with is something to *know*.
    body = (
        _outcome(said)
        # Every other view has one, and this is the busiest (item 223): a page whose first landmark
        # is missing is the one where a screen reader has furthest to go.
        + "<h1>This instance</h1>"
        # The answer and the decisions are the front door's now (item 212). They are still here,
        # from the same function, because an operator who opens the report on a bad morning should
        # not have to go back to learn whether anything wants them.
        + does_this_need_you(session, settings, acting, error_reporting=error_reporting)[0]
        + _proof(
            session,
            merged=merged,
            holding=holding,
            recurred=recurred,
            watch=recurrence.WATCH_DAYS,
        )
        + _now(session, prices)
        + _strip(session)
        + _disagreements(session, settings)
        # **Above the folds, not inside one** (item 203). What is off and what cannot work is the
        # reason somebody opened this; the configuration table below is what they read afterwards.
        + _what_this_instance_has_switched_on(session, settings)
        # The link row that used to live here is the rail now (item 212): two sets of navigation
        # on one page is two places to add the next noun to, and one of them will be forgotten.
        + '<div class="more">'
        # **Sections rather than folds** (item 235, DR-0027). Five disclosures titled with
        # sentences — *What arrived, and how much left your desk*, *Which half holds what, and what
        # this instance allows* — is a page where every answer is one click and one guess away, and
        # the guess is the part a reader cannot make.
        + _section(
            # **Renamed once a real configuration page existed** (item 211). These seven rows are
            # state — version, forge, sweep, backlog — and calling them *configured* was harmless
            # while nothing else claimed the word. `/config` claims it now, and two things with one
            # name is the drift this repository has spent a week removing.
            "How it is now",
            "What this process is, and what it is wired to, at this moment.",
            f'<div class="wide"><table>{table}</table></div>',
        )
        # Before the attempts block, exactly as `status` orders them: this one has *what arrived*
        # as its denominator and that one has *what was attempted*, so a reader who opens one
        # should meet the wider question first.
        + (
            _section(
                "What left your desk",
                "Of everything that arrived, how much this instance took off you.",
                desk,
            )
            if desk
            else ""
        )
        + (
            _section(
                "What attempts came to",
                "Every attempt this instance has made, by how it ended.",
                attempts,
            )
            if attempts
            else ""
        )
        + (
            _section("What they cost", "In tokens and in money, through one arithmetic.",
                     f"<ul>{spent}</ul>")
            if spent
            else ""
        )
        + (
            _section("What reviewers did", "What became of the pull requests it opened.", reviewed)
            if reviewed
            else ""
        )
        + _the_credential_split(session)
        + _what_this_instance_allows(settings)
        + _housekeeping(session, acting)
        + "</div>"
    )
    # The instance's own state, on the bar rather than in a folded table: it is the second question
    # a reader has, and item 167 had buried it under a disclosure.
    badge = ("ready", "ok") if report.ready else ("degraded", "bad")
    return _document(
        "Hullwork — this instance", body, acting=acting, state=badge, here="instance",
        projects=each_project(session),
    )


#: How many rows a list shows. Bounded because an instance that has been running for a year has
#: thousands of items and this renders in one string, and **stated on the page** because a reader
#: who cannot see the bound reads the list as "everything" and is wrong.
MAX_ITEMS = 200


def _project_health(project: _Project, settings: Settings) -> tuple[str, str]:
    """What is wrong with this project, and nothing else. Items 142 and 228.

    **The credential**, from the column the sweep writes rather than from a forge request here: a
    page render must not spend one, and a reader refreshing would spend one each time. `None` is
    *not measured* and is not a pass — item 073's rule, and the same `None != False` this project
    has got wrong three times.

    **It said *not asked yet* forever**, because it read a key inside the manifest JSON that nothing
    ever wrote — so the command it told you to run would not have changed it either. The sweep
    measures it now, on `forge_recheck_seconds`.

    **And a state that is fine says nothing at all.** `cached manifest validates` was three internal
    words describing a normal state at the volume of a fault; the operator asked what it meant,
    which is the answer.

    **The manifest**, by validating the cached copy. A project whose stored manifest no longer
    parses has every incoming error land red (`ingest._manifest_for` degrades to that silently, by
    design), and until now the only way to know was to read that function. It is the loudest thing
    that can be wrong with a project and it was invisible.
    """
    from hullwork.manifest import Manifest

    pushes = project.ingest_token_can_push
    # **Only what is not fine, and a count of what is** (item 203, applied here by item 228). A
    # project whose credential is correctly narrow does not need a line saying so at the same
    # volume as everything else; a project whose credential can push needs a loud one.
    credential = {
        None: (
            "unknown",
            "not measured yet — this instance asks the forge on its own clock, within "
            f"{max(settings.forge_recheck_seconds, 60) // 60} minute(s) of a project being "
            "connected",
        ),
        True: (
            "bad",
            "the ingest **token** can write code to this repository — measured, not inferred: a "
            "request only a code scope allows was accepted. DR-0009 is what that breaks",
        ),
        False: ("good", ""),
    }[pushes if pushes is None else bool(pushes)]

    if not project.manifest:
        manifest = ("unknown", "no manifest cached — nothing can be built for this project")
    else:
        try:
            Manifest.model_validate(
                {k: v for k, v in project.manifest.items() if not k.startswith("__")}
            )
            manifest = ("good", "")
        except Exception:
            manifest = (
                "bad",
                "cached manifest no longer validates, so every error from here lands red until "
                "`hullwork projects refresh` adopts a working one",
            )
    # `_as_code`, not `_h` (item 213). These two sentences were written for a terminal — one of
    # them names `hullwork projects refresh` — and escaping them served the backticks, which beside
    # a command name reads as a typo in the product rather than as a quotation of it.
    said = "".join(
        f'<li class="{tone}">{_as_code(text)}</li>' for tone, text in (credential, manifest) if text
    )
    return said, credential[0] + manifest[0]


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


def _what_was_rotated(rotated: tuple[str, str | None] | None) -> str:
    """A new webhook secret, once — and what it broke, before the value rather than after.

    Minting one is item 206's problem and this is that plus one: rotating **stops the URL the
    tracker is currently posting to**. Somebody who reads the new value and not that sentence has a
    working instance that receives nothing, which is the failure this product exists to notice and
    the worst one to cause.
    """
    if rotated is None or rotated[1] is None:
        return ""
    slug, token = rotated
    return (
        f'<h2 class="name">{_h(slug)} has a new webhook secret</h2>'
        "<p><b>The URL your tracker was posting to has stopped working</b> — update it before the "
        "next error, or nothing arrives. <b>This is the only time the new one is shown</b>: only "
        "its hash is stored.</p>"
        f'<pre class="wide"><code>/webhooks/glitchtip/{_h(slug)}/{_h(token)}</code></pre>'
    )


def _refusal(said: str | None) -> str:
    """A refusal in the command's own words. Item 206.

    `add_project` raises with a sentence per problem — a manifest that does not parse names the key,
    a repository the token cannot read says which, a slug already taken says so. A page that
    replaced
    those with *something went wrong* would send somebody to a shell to find out what it already
    knew, which is the whole thing DR-0022 is closing.
    """
    return f'<p class="sub c-refused">{_h(said)}</p>' if said else ""


def _the_form(acting: Acting, *, answered: str = "") -> str:
    """The primary action: a button above the list, and the three fields behind it. Item 214.

    It was a form at the bottom of this page, under every project the instance already had, so
    registering the second one meant scrolling past the first. DR-0023 read the opposite off
    GlitchTip — *the primary action is a button, top right, always* — and item 212 built everything
    in that decision except this.

    **`answered` is what came back from the last submission**, and it is why the drawer has a state
    at all. A form behind a disclosure that re-renders closed returns the reader to a button with
    the refusal hidden inside it, which reads as a page that ignored them; and a webhook secret is
    shown once, so a closed drawer over one is data loss wearing a layout bug's clothes.

    No form for a reader with a link: DR-0021 gives them reading, and a control they cannot submit
    is
    worse than one that is not there. The CSRF token is the session's, exactly as the two decisions
    on an item carry it.
    """
    if not acting.csrf:
        return ""
    # **A visible label, not only an `aria-label`** (item 213). The assistive name was there; what
    # was missing is the one a sighted person needs — a placeholder disappears exactly when it is
    # needed, which is the moment somebody has typed into the field and looks up to check.
    fields = "".join(
        f'<p class="field"><label for="new-{name}">{_h(label)}</label>'
        f'<input id="new-{name}" name="{name}"{extra}></p>'
        for name, label, extra in (
            ("slug", "Name it here", ' placeholder="shop" required'),
            ("repo", "Repository", ' placeholder="owner/name" required'),
            ("forge", "Forge", ' value="forgejo"'),
        )
    )
    return (
        f'<details class="primary"{" open" if answered else ""}>'
        "<summary>Connect a project</summary>"
        + answered
        + '<form method="post" action="projects" class="new">'
        + f'<input type="hidden" name="csrf" value="{_h(acting.csrf)}">'
        + fields
        + "<button type=\"submit\">Connect it</button></form>"
        + '<p class="sub">It reads <code>hullwork.yml</code> from the default branch and refuses '
        "anything it cannot validate. Nothing is written to your repository.</p>"
        + "</details>"
    )


def _what_was_just_made(made: object) -> str:
    """The webhook URL, once. Item 206, and the sentence DR-0022 requires beside it.

    A copy-exactly-once value is worse in a browser than in a terminal — scrollback, history, a
    screenshot — so this says plainly that it is the only time, rather than being withheld. Only the
    hash is stored, exactly as the command stores it, so no later view can show it again.
    """
    if made is None:
        return ""
    project = getattr(made, "project", None)
    token = getattr(made, "token", "")
    slug = getattr(project, "slug", "")
    return (
        f'<h2 class="name">{_h(slug)} is connected</h2>'
        "<p>Point your error tracker's webhook at this. <b>This is the only time it is shown</b> — "
        "only its hash is stored, so nobody, including this page, can print it again. Lose it and "
        "<code>hullwork projects rotate-secret</code> issues another, which stops the old one.</p>"
        f'<pre class="wide"><code>/webhooks/glitchtip/{_h(slug)}/{_h(token)}</code></pre>'
    )


def _a_project_page(
    session: Session,
    slug: str,
    where: str,
    label: str,
    says: str,
    body: Callable[[_Project], str],
    *,
    acting: Acting,
    said: str | None = None,
    refused: str | None = None,
    rotated: tuple[str, str | None] | None = None,
) -> str | None:
    """One feature, one project, one page. Item 237.

    **The operator's own correction of item 235**: that item named the features and then put each
    on a page holding every project's, which is a wall at two projects and unusable at ten. Nobody
    works by feature across clients; they work on a client.

    `None` when there is no project with that slug, so the route answers the same `404` an unknown
    path gets — a distinct body would let somebody enumerate the slugs an instance serves.
    """
    found = session.scalars(select(_Project).where(_Project.slug == slug)).one_or_none()
    if found is None:
        return None
    return _document(
        f"Hullwork — {found.slug} {label.lower()}",
        f'<h1>{_h(found.slug)} <span class="also">{_h(label)}</span></h1>'
        # **Above the body, because it is the answer to what was just pressed** (item 245). A
        # sentence below eight hundred words of report is a sentence nobody sees, and this one says
        # the pull request does not exist yet — which is the part a reader has to read.
        #
        # **A refusal answers here too** (item 250). It used to answer with the list of projects,
        # rendered at this URL: six dead links handed to somebody whose forge had just gone down.
        f'<p class="says">{says}</p>'
        f"{_refusal(refused)}{_what_was_rotated(rotated)}{_outcome(said)}" + body(found),
        acting=acting,
        here=where,
        # **Three levels down from `/page/<token>/`** — `projects/<slug>/<feature>` — and every URL
        # on this page is relative on purpose, which is what keeps the token out of the HTML. Item
        # 227 was this arithmetic being wrong by one; it 404s every link in the rail when it is.
        up="../../",
        inside=found.slug,
        counts=how_much_of_each(session, found.id),
    )


def dependencies(
    session: Session,
    settings: Settings,
    slug: str,
    *,
    acting: Acting = READING,
    said: str | None = None,
    refused: str | None = None,
) -> str | None:
    """What is published against what this project pins, and what came of trying the fixes."""
    del settings
    return _a_project_page(
        session,
        slug,
        "dependencies",
        "Dependencies",
        "What OSV publishes against the versions this project pins, and what happened when this "
        "instance tried the published fix. Asked on its own clock, every six hours.",
        lambda one: what_is_published_against_it(session, one, acting=acting),
        acting=acting,
        said=said,
        refused=refused,
    )


def deliveries(
    session: Session, settings: Settings, slug: str, *, acting: Acting = READING,
    said: str | None = None, refused: str | None = None,
) -> str | None:
    """What this project's tracker sent, and whether it was understood. Item 231's feature."""
    del settings
    return _a_project_page(
        session,
        slug,
        "deliveries",
        "Deliveries",
        "What this project's error tracker has sent, and whether it could be read. A call with the "
        "wrong secret is refused before anything is written, so an empty list means nobody knocked "
        "<strong>with a working secret</strong> — not that nobody knocked.",
        lambda one: what_arrived_for(session, one),
        acting=acting,
        said=said,
        refused=refused,
    )


def _fixes_for(session: Session, project: _Project, prices: Prices | None) -> str:
    """Every attempt this project has had, with what it reached and what it cost.

    **`consumed` is the column that matters** and it is not derivable from the outcome (DR-0003): a
    run that never reached the model must not spend the item's one attempt, whatever went wrong
    afterwards, and a page that inferred it from the verdict would tell somebody their one try is
    gone when it is not.
    """
    rows = list(
        session.execute(
            select(_Attempt, _Item)
            .join(_Item, _Attempt.item_id == _Item.id)
            .where(_Item.project_id == project.id)
            .order_by(_Attempt.id.desc())
            .limit(MAX_ITEMS)
        ).all()
    )
    if not rows:
        return (
            "<p>No attempt has run for this project. An item is attempted when it is queued and "
            "the dispatcher is running; an amber one waits for you first.</p>"
        )
    listed = "".join(
        # **Two levels up, because this view is three deep** (item 249). `projects/<slug>/fixes`
        # resolving `items/27` gives `projects/<slug>/items/27`, which is a 404 — the arithmetic
        # item 227 was written about, on the one view its guard did not reach. `_its_items`, one
        # route along, has had `../../` since it was written.
        f'<tr><td data-label="item"><a href="../../items/{one.item_id}">'
        f"{_h(bug.title[:70])}</a></td>"
        f'<td data-label="reached">{_h(one.phase_reached.value)}</td>'
        f'<td data-label="ended">{_h(one.outcome.value if one.outcome else "still running")}</td>'
        f'<td data-label="its one try">{"spent" if one.consumed else "not spent"}</td>'
        f'<td data-label="when">{_h(_ago(one.started_at))}</td></tr>'
        for one, bug in rows
    )
    cost = _project_cost(session, project.id, prices)
    return (
        '<div class="wide"><table class="list"><tr><th>item</th><th>reached</th><th>ended</th>'
        f"<th>its one try</th><th>when</th></tr>{listed}</table></div>{cost}"
    )


def fixes(
    session: Session, settings: Settings, slug: str, *, acting: Acting = READING,
    said: str | None = None, refused: str | None = None,
) -> str | None:
    """What this instance tried on this project, how far each got, and what it cost. Item 235.

    The attempts existed only as a cost summary and a phase strip on an item. *What has this thing
    actually done* had no page, which for a product whose claim is **a fix that was run** is the
    page a reader wants second.
    """
    prices = spend.Prices.from_settings(settings)
    return _a_project_page(
        session,
        slug,
        "fixes",
        "Fixes",
        "Every attempt this instance has made on this project, how far it got through the gates, "
        "and whether it spent the item's one try. An attempt that never reached the model does not "
        "spend it (DR-0003), which is why that column is recorded rather than inferred.",
        lambda one: _fixes_for(session, one, prices),
        acting=acting,
        said=said,
        refused=refused,
    )


def errors(
    session: Session, settings: Settings, slug: str, *, acting: Acting = READING,
    said: str | None = None, refused: str | None = None,
) -> str | None:
    """This project's bugs, newest first. Item 237.

    Separated from the board above it because they answer different questions: the board is *who is
    blocked*, this is *what is there*, and a view holding both is the one the operator kept saying
    he could not read.
    """
    del settings
    return _a_project_page(
        session,
        slug,
        "errors",
        "Errors",
        "The bugs this project's error tracker sent. Hullwork calls each one an <em>item</em>: the "
        "bug, plus everything it has done about it.",
        lambda one: _its_items(session, one),
        acting=acting,
        said=said,
        refused=refused,
    )


def _its_items(session: Session, project: _Project) -> str:
    """The project's items as a table, bounded and saying so."""
    rows = list(
        session.scalars(
            select(_Item)
            .where(_Item.project_id == project.id)
            .order_by(_Item.id.desc())
            .limit(MAX_ITEMS)
        ).all()
    )
    if not rows:
        return "<p>No item has arrived for this project.</p>"
    total = int(
        session.scalar(
            select(func.count()).select_from(_Item).where(_Item.project_id == project.id)
        )
        or 0
    )
    listed = "".join(
        f'<tr><td data-label="id"><a href="../../items/{one.id}">{one.id}</a></td>'
        f'<td data-label="title">{_h(one.title)}</td>'
        f'<td data-label="state">{_h(one.state.value)}</td>'
        f'<td data-label="lane">{_h(one.lane.value)}</td>'
        f'<td data-label="since">{_h(_ago(one.state_since))}</td></tr>'
        for one in rows
    )
    bound = f"<p>Showing {len(rows)} of {total}.</p>" if total > len(rows) else ""
    return (
        bound + '<div class="wide"><table class="list"><tr><th>id</th><th>title</th><th>state</th>'
        f"<th>lane</th><th>since</th></tr>{listed}</table></div>"
    )


def settings_for(
    session: Session, settings: Settings, slug: str, *, acting: Acting = READING,
    said: str | None = None, refused: str | None = None,
    rotated: tuple[str, str | None] | None = None,
) -> str | None:
    """Everything this instance will do to this project on command. Item 237.

    **Where a rotated secret is shown** (item 250). It was shown on the list of every project,
    rendered at this project's URL — so the one answer in this product that can never be repeated
    arrived on a page whose every link was dead.
    """
    return _a_project_page(
        session,
        slug,
        "settings",
        "Settings",
        "Everything this instance will do to this project when told to, and nothing it does on its "
        "own.",
        lambda one: _the_rest_of_its_life(one, acting)
        + _sweeping(one, acting)
        + _reading_the_repository(one, acting)
        + what_this_can_do(session, one, settings),
        acting=acting,
        said=said,
        refused=refused,
        rotated=rotated,
    )


def projects(
    session: Session,
    settings: Settings,
    *,
    acting: Acting = READING,
    just_made: object = None,
    refused: str | None = None,
    said: str | None = None,
) -> str:
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
    # **A rotated secret is not answered here** (item 250). It was, and this view is written for
    # `/page/<token>/projects` — returned from `projects/<slug>` its every link resolved one level
    # too deep. It is shown where the button is, on that project's settings.
    answered = _what_was_just_made(just_made) + _refusal(refused)
    if not found:
        body = (
            '<div class="head"><h1>Projects</h1>'
            + _the_form(acting, answered=answered)
            + "</div><p>No project is registered yet.</p>"
        )
        return _document(
            "Hullwork — projects", body, acting=acting, here="projects",
            projects=each_project(session),
        )

    blocks: list[str] = [_outcome(said)]
    for project in found[:MAX_ITEMS]:
        health, _ = _project_health(project, settings)
        blocks.append(
            f'<h2 class="name"><a href="projects/{_h(project.slug)}">{_h(project.slug)}</a></h2>'
            f'<p class="sub">{_h(project.forge)} · {_h(project.repo)}'
            f"{'' if project.active else ' · not active'}</p>"
            + (f"<ul>{health}</ul>" if health else "")
            + f"{_project_columns(session, project.id)}"
            # **A list is a list** (items 223 and 225). The controls went to the project's own
            # view first; the feature block followed, because it was 85% of this page and rendered
            # once per project. On a list a reader is not looking *at* a project — they are looking
            # *for* one.
        )
    bound = (
        f"<p>Showing {min(len(found), MAX_ITEMS)} of {len(found)}.</p>"
        if len(found) > MAX_ITEMS
        else ""
    )
    body = (
        '<div class="head"><h1>Projects</h1>'
        + _the_form(acting, answered=answered)
        + "</div>"
        '<p class="sub">Read-only. One instance serves one forge, so this is every project '
        "on this one.</p>"
        + bound
        + "".join(blocks)
    )
    del prices
    return _document(
        "Hullwork — projects", body, acting=acting, here="projects",
        projects=each_project(session),
    )


def project(
    session: Session,
    settings: Settings,
    slug: str,
    *,
    acting: Acting = READING,
    said: str | None = None,
) -> str | None:
    """A project's overview: what is wrong, where everything is, and what each feature holds.

    **The overview, and not the whole project** (item 237). Every feature has its own page under
    this one now; what is here is the answer to *how is this project* and a way into each of them.

    `None` rather than a message, so the route answers the same `404` an unknown path gets — a
    distinct body would let somebody enumerate the slugs an instance serves with a valid token.
    """
    found = session.scalars(select(_Project).where(_Project.slug == slug)).one_or_none()
    if found is None:
        return None

    health, _ = _project_health(found, settings)
    counts = how_much_of_each(session, found.id)
    # **The rail says how much; this says what it is.** A reader who has just arrived on a project
    # should not have to read a sidebar's badges to find out which of its five features has anything
    # in it, and a link that says what it holds is one they can decide about before clicking.
    where_to = "".join(
        f'<li class="{"c-refused" if how_many else "c-idle"}">'
        f'<span class="pill">{how_many if how_many else "—"}</span>'
        f'<span class="name"><a href="{_h(found.slug)}/{where}">{_h(name)}</a></span>'
        f'<p class="why">{says}</p></li>'
        for where, name, how_many, says in (
            (
                "errors", "Errors", counts.errors,
                "the bugs its tracker sent, and what state each is in",
            ),
            (
                "fixes", "Fixes", counts.fixes,
                "what this instance attempted, how far it got, and what it cost",
            ),
            (
                "dependencies", "Dependencies", counts.dependencies,
                "what OSV publishes against what it pins, and what came of trying the fix",
            ),
            (
                "deliveries", "Deliveries", counts.deliveries,
                "what its tracker actually sent, and whether it could be read",
            ),
        )
    )
    body = (
        _outcome(said)
        + f'<h1>{_h(found.slug)} <span class="also">Overview</span></h1>'
        f'<p class="sub">{_h(found.forge)} · {_h(found.repo)}'
        f"{'' if found.active else ' · not active'}</p>"
        # **Nothing to say is the common case now** (item 228): a project whose credential is
        # narrow and whose manifest reads is a project with no health section at all, rather than
        # two green lines at the volume of a fault.
        + (_section("What is wrong", "", f"<ul>{health}</ul>") if health else "")
        + _section(
            "Where everything is",
            "Every item this project has, by who it is waiting on.",
            _project_columns(session, found.id),
        )
        + _section(
            "What it holds",
            "Each of this project's features, and how much is in it.",
            f'<ul class="standing">{where_to}</ul>',
        )
    )
    return _document(
        f"Hullwork — {found.slug}",
        body,
        acting=acting,
        here="",
        # **How far this view is from `/page/<token>/`** (item 227). Every URL on this page is
        # relative on purpose — that is what keeps the token out of the HTML — so a view one level
        # down that does not say so sends every rail link to `projects/<noun>`, and all of them 404.
        up="../",
        inside=found.slug,
        counts=counts,
    )


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


def front_door(
    session: Session,
    settings: Settings,
    *,
    acting: Acting = READING,
    error_reporting: bool = False,
    said: str | None = None,
) -> str:
    """What needs you, and then one line per project. Item 237.

    **The door answers one question and lists one thing.** Before this it was every item on the
    instance in one table, which is a list nobody wants first: with two projects it is already two
    projects\' bugs interleaved, and *whose* is the column a reader has to scan for.

    The number against a project is **what is waiting on a person**, not how much exists. A count of
    items reads the same on a project that is fine and one that is stuck, and the whole of a front
    door is *which of these wants me*.
    """
    from hullwork.models import DependencyReport

    answer, badge = does_this_need_you(session, settings, acting, error_reporting=error_reporting)
    found = list(session.scalars(select(_Project).order_by(_Project.slug)).all())
    rows = ""
    for one in found:
        counts = how_much_of_each(session, one.id)
        # **Two states, two sentences, because they are two different things** (item 247). This
        # summed `waiting-approval` and `human-only` and called both *waiting on you*, two lines
        # under a headline that counts only the first and had just said **Nothing needs you**. Both
        # numbers were right; one name for them was not. A decision is owed on the first; the second
        # is work no agent may attempt, and nothing is owed until somebody chooses to do it.
        # Bound rather than closed over: `one` is the loop variable, and a closure reading it would
        # answer for whichever project the loop was on when it ran (the shape of the bug item 233's
        # `_read` carries a comment about).
        def _in(*states: ItemState, project_id: int = one.id) -> int:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(_Item)
                    .where(_Item.project_id == project_id, _Item.state.in_(states))
                )
                or 0
            )

        waiting = _in(ItemState.WAITING_APPROVAL)
        only_you = _in(ItemState.HUMAN_ONLY)
        report = session.get(DependencyReport, one.id)
        said_of: list[str] = []
        if waiting:
            said_of.append(f"<strong>{waiting} awaiting your decision</strong>")
        if only_you:
            said_of.append(f"{only_you} only a person can do")
        if counts.errors:
            said_of.append(f"{counts.errors} item(s)")
        # **Three states, and *could not ask* is one of them** (DR-0024). A project whose report
        # failed must not read the same as one with nothing published against it.
        if report is None:
            said_of.append("dependencies not asked about yet")
        elif not report.asked:
            said_of.append('<span class="bad">could not ask OSV</span>')
        elif report.findings:
            packages = len({str(one.get("package") or "") for one in report.findings})
            said_of.append(f"{packages} package(s) with something published")
        if not one.active:
            said_of.append("not watched")
        # **What is waiting on a person is the action**, so it sits where an action sits and leads
        # to the items it counted (item 166). Everything else about the project is context.
        owed = (
            f'<a href="items?in=waiting">{waiting} waiting</a>' if waiting else ""
        )
        rows += (
            '<tr class="subject"><td class="who">'
            f'<span class="dot {"waiting" if waiting else "faint"}"></span>'
            f'<a class="thing" href="projects/{_h(one.slug)}">{_h(one.slug)}</a>'
            f'<span class="said">{" · ".join(said_of) or "nothing to report"}</span></td>'
            f'<td class="do">{owed}</td></tr>'
        )
    body = (
        _outcome(said)
        + answer
        # **What it is doing, above what there is** (item 242): the operator watching a five-minute
        # verification through `docker logs` had no other way to see it.
        + _what_it_says_it_is_doing(session)
        + _section(
            "Projects",
            # **The paragraph explaining the list is documentation** (DR-0028): it was re-read every
            # day by somebody who had understood it the first time.
            "One line each. Everything else about a project lives inside it.",
            f'<table class="subjects narrow">{rows}</table>'
            if found
            else "<p>No project is connected yet.</p>",
        )
        + what_it_has_been_doing(session)
    )
    return _document(
        "Hullwork",
        body,
        acting=acting,
        here="./",
        state=badge,
        projects=each_project(session),
    )


#: What each of `_COLUMNS` means, for the heading that now carries the grouping. DR-0028.
#:
#: **The words are the reader's question, not the state machine's.** `pr-open` is not a state a
#: person cares about; *a draft pull request is waiting for somebody to read it* is.
_WHO_IS_BLOCKED: dict[str, str] = {
    "waiting": "a decision from you, or work no agent may attempt",
    "review": "a draft pull request is waiting for somebody to read it",
    "arrived": "triaged and not queued yet",
    "queued": "eligible, and the dispatcher takes one per turn",
    "working": "an attempt is running now",
    "closed": "merged, rejected, or answered — nothing owed",
}


def _items_by_who_is_blocked(rows: Sequence[_Item], pulls: Mapping[int, str]) -> str:
    """Every item, grouped by who is blocked and ordered by whether that is you. DR-0028, item 247.

    **`_COLUMNS` is the grouping, and it already existed.** Inventing a second vocabulary for this
    list is how it and the strip on the front page would come to disagree about what *waiting* means
    — which is the drift DR-0027 spent an item undoing. So the six columns are the six bands, in an
    order this view chooses: **what the reader owns first, `closed` last**.

    The chronological order the flat table used put the one item waiting for a person at the top by
    luck — it happened to be the most recently seen. At two hundred items that is wherever the clock
    left it.
    """
    owned = [one for one in _COLUMNS if one[4]]
    rest = [one for one in _COLUMNS if not one[4] and one[1] != "closed"]
    closed = [one for one in _COLUMNS if one[1] == "closed"]
    bands = []
    for title, key, colour, states, _ in [*owned, *rest, *closed]:
        here = [row for row in rows if row.state in states]
        if not here:
            continue
        lines = "".join(_an_item(row, colour, pulls) for row in here)
        bands.append(
            f'<section class="band"><h3><span>{_h(title)}</span>'
            f'<em>{_h(_WHO_IS_BLOCKED.get(key, ""))}</em><b>{len(here)}</b></h3>'
            f'<table class="subjects narrow">{lines}</table></section>'
        )
    return "".join(bands)


def _an_item(row: _Item, colour: str, pulls: Mapping[int, str]) -> str:
    """One item, one row: which one, whose, what it says, when, and where it reached.

    **No state column** (DR-0028): it is the heading above this row, and printing it here is the
    twenty-five identical words the decision is named after. The lane stays — it is what
    distinguishes two rows inside one band, which is the test a column has to pass to exist.
    """
    reached = (
        f'<a href="items/{row.id}">{_h(pulls[row.id])}</a>'
        if row.id in pulls
        else (_h(row.forge_issue_ref) if row.forge_issue_ref else "")
    )
    # **`never` is a fact about the item, not context about it** (item 166): this one can never be
    # attempted. Rendered in the context cell it was clipped to `N…` by that column's ellipsis, and
    # a truncated warning is worse than none — it reads as a rendering fault rather than a state.
    stuck = ' <span class="stuck">never</span>' if _stuck(row) else ""
    title = _h(row.title.splitlines()[0] if row.title else "")
    return (
        '<tr class="subject">'
        f'<td class="who"><span class="dot {_h(colour.removeprefix("c-"))}"></span>'
        f'<a class="thing" href="items/{row.id}">#{row.id}</a>'
        f'<span class="said">{title}</span>{stuck}</td>'
        f'<td class="at">{_h(row.project.slug)} · {_h(row.lane.value)}</td>'
        f'<td class="fold"><time datetime="{_h(row.last_seen)}" title="{_h(row.last_seen)}">'
        f"{_h(_ago(row.last_seen))}</time></td>"
        f'<td class="do">{reached}</td>'
        "</tr>"
    )


def items(
    session: Session,
    *,
    only: str | None = None,
    acting: Acting = READING,
    here: str = "",
    settings: Settings | None = None,
    front: bool = False,
    error_reporting: bool = False,
) -> str:
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

    grouped = _items_by_who_is_blocked(rows, pulls)

    scope = "" if states is None else f" in <strong>{_h(only)}</strong>"
    if rows:
        table = grouped
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
            else _why_it_is_empty(session)
        )
        # **The emptiness has a cause and the cause has an action** (item 214). On an instance with
        # no projects the sentence above is true and useless: nothing arrived because nothing is
        # connected, and what to do about it was two clicks and a scroll away. Only offered to
        # somebody who could act on it, and only when there is genuinely nothing to connect from.
        if states is None and front and acting.csrf and not session.scalar(
            select(func.count()).select_from(_Project)
        ):
            shown += (
                '. <a href="projects">Connect a project</a> and its errors land here'
            )

    everything = '' if states is None else ' <a href="items">All items</a>'
    # **The answer first, and only where this is the front door** (item 212). On `items?in=queued`
    # it would be answering a question the reader did not ask. Asked for by the route rather than
    # inferred from `settings` being present, because a headline that vanishes when a caller forgets
    # an argument is a first screen that can silently stop saying the one thing it is for.
    if front and settings is None:  # pragma: no cover - a wiring mistake, not a state
        raise TypeError("the front door needs settings: it renders the instance's own answer")
    answer, badge = (
        does_this_need_you(session, settings, acting, error_reporting=error_reporting)
        if front and settings
        else ("", None)
    )
    # **Only what is true of what is on screen.** *Most recently seen first* under an empty list
    # describes an order there is nothing to order, and the link to the instance was a second copy
    # of a noun the rail already carries.
    # **It said *most recently seen first* and that stopped being true** (item 247): the list is
    # grouped by who is blocked, and the clock only decides inside a group.
    order = " Grouped by who is blocked; newest first inside each." if rows else ""
    # **A link and the page it reaches have to be called the same thing** (item 235). The rail said
    # *Items* and so did this heading, and neither is a word somebody arriving with a broken
    # checkout would look for. *Errors* is what they are; *item* is what this product calls one, and
    # that sentence is worth one line rather than a heading nobody can navigate by.
    body = (
        answer + "<h1>Errors</h1>"
        '<p class="says">The bugs your error tracker sent. Hullwork calls each one an '
        "<em>item</em>.</p>"
        f'<p class="sub">{shown}{scope}.{order}{everything}</p>' + table
    )
    return _document(
        "Hullwork — errors", body, acting=acting, here=here, state=badge,
        projects=each_project(session),
    )


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
    # **The one state `requeue` exists for** (item 093), and it had a route and no button until
    # item 223: an item left `human-only` by a red baseline holds an attempt it never spent, and the
    # only way to give it back was an `UPDATE` against a SQLite file inside a Docker volume.
    if found.state is ItemState.HUMAN_ONLY and acting.csrf:
        parts.append(
            f'<form method="post" action="{up}items/{found.id}" class="decide">'
            f'<input type="hidden" name="csrf" value="{_h(acting.csrf)}">'
            '<button type="submit" name="action" value="requeue">Queue it again</button></form>'
            '<p class="sub">Only when what stopped it was the environment. Its attempt was never '
            "spent, so it still has one.</p>"
        )
    if found.state is ItemState.WAITING_APPROVAL and not stuck:
        # The buttons when there is a session, and otherwise how to get them — here as well as on
        # the front page, because a reader can arrive straight at an item from a forge issue.
        parts.append(_decide(found, acting, up=up) or _how_to_decide(acting, found, up=up))
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
    # **Nothing per item when there is no session.** The instruction is the same sentence for every
    # item on the page, and rendering it beside each one turned two decisions into two paragraphs of
    # identical prose — the exact noise this item exists to remove. It is printed once, above the
    # list, by `_how_to_decide`.
    return ""


def just_the_login(acting: Acting, *, going_to: str = "") -> str:
    """The login and nothing else, for the door that replaces the token (DR-0021, item 204).

    **Nothing about the instance is on it.** A page showing a name, a version or a count beside the
    password would answer questions for somebody who has not signed in — and the whole reason
    this path may exist at all is that it discloses one thing: this host has a login.

    Reuses `_login` and `_document` because a second form would be a second thing to keep correct,
    and the correct one has `autocomplete="current-password"` and a real `<form>` in it for reasons
    item 168 measured.

    **And it does not use `_document`.** Written that way first, and the visible text came out
    as `▚ hullwork · Hullwork 0.1.0a8 — read-only…` — the instance's name
    and its exact version, on the one page a prober can reach. A version tells somebody which
    advisories to go and read. Found by a test that asserted the principle and had to be fixed
    before it could measure it.
    """
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f'<link rel="icon" href="{_FAVICON}">'
        f"<title>Sign in</title><style>{_STYLE}</style></head><body>\n"
        '<div class="wrap">'
        f'<h1 class="what">Sign in</h1>{_login(acting, up="", going_to=going_to)}'
        "</div></body></html>\n"
    )


def _login(acting: Acting, *, up: str, going_to: str = "") -> str:
    """The login, or what to run when there is nothing to log in to. Item 168.

    **`autocomplete="current-password"` and a real `<form>` are the whole feature.** A browser
    offers to save a password it sees submitted in a form and fills it in next time — which turns
    item 167's eight steps into two: open the page, click. There is no username field
    because there is no user: an instance has one operator and no notion of identity, and inventing
    one to satisfy a manager's heuristics would be inventing a product.
    """
    if acting.locked_minutes is not None:
        return (
            f'<p class="sub">Too many wrong passwords. This waits '
            f"{_h(acting.locked_minutes)} more minute(s) before it will try again.</p>"
        )
    # **Where they were going** (item 224). Signing in used to land on the front door whatever URL
    # you had opened, which on an instance you reach by bookmark means finding the view again by
    # hand every twelve hours.
    onward = (
        f'<input type="hidden" name="going_to" value="{_h(going_to)}">' if going_to else ""
    )
    return (
        f'<form method="post" action="{up}login" class="login">{onward}'
        '<input type="password" name="password" autocomplete="current-password" '
        'placeholder="operator password" aria-label="operator password" required>'
        '<button type="submit">Sign in</button></form>'
    )


#: The views a `going_to` may name, so a redirect after signing in cannot be pointed anywhere else.
#: A literal list rather than a pattern: `../` and `//host` and `%2e%2e` are all things a pattern
#: written in a hurry lets through, and there are eight of these.
WHERE_YOU_CAN_LAND: tuple[str, ...] = (
    "", "items", "instance", "projects", "doctor", "config",
)


def where_it_may_land(asked: str | None) -> str:
    """The tail of a path this instance will send somebody to after they sign in, or `""`.

    **Anything it does not recognise becomes the front door**, silently: a login that argues with
    you about where you were going is worse than one that takes you home, and an open redirect is
    the classic way a sign-in form becomes somebody else's.
    """
    if not asked:
        return ""
    tail = asked.removeprefix(f"{PREFIX}/{MINE}/").strip("/")
    if tail in WHERE_YOU_CAN_LAND:
        return tail
    # One shape beyond the flat list, because it is where half the work is: a project of its own.
    named = tail.removeprefix("projects/")
    if tail.startswith("projects/") and "/" not in named and named.replace("-", "").isalnum():
        return tail
    return ""


def _signing_in(acting: Acting, *, up: str = "") -> str:
    """A way in that does not depend on there being something to decide. Item 168.

    **Found by opening the deployed page on a calm day.** The login lived inside the list of
    decisions, so an instance with nothing waiting offered no way to sign in at all — and a lockout
    had nowhere to be reported either, which made a working lockout look like a broken login. A
    `<details>` keeps the calm page calm and still always reachable, with no script.
    """
    if acting.csrf is not None:
        return ""
    if acting.locked_minutes is not None:
        return (
            '<details open><summary>Sign in</summary><div class="folded">'
            f'<p class="sub bad">Too many wrong passwords. This waits '
            f"{_h(acting.locked_minutes)} more minute(s) before it will try again.</p>"
            "</div></details>"
        )
    nothing_set = (
        '<p class="sub">No password is set on this instance. Run <code>hullwork password</code> on '
        "the host, once, and this becomes a login.</p>"
    )
    inside = _login(acting, up=up) if acting.offered else nothing_set
    return f'<details><summary>Sign in</summary><div class="folded">{inside}</div></details>'


def _how_to_decide(acting: Acting, found: Item | None = None, *, up: str = "") -> str:
    """How to get the buttons, said once for the whole page rather than once per item.

    `found` names the command exactly when there is one item in question, which on an item's own
    page there is: `hullwork approve checkout-api 12` is something to run, and
    `hullwork approve <project> <item>` is something to translate first.
    """
    if acting.csrf is not None:
        return ""
    if acting.offered:
        return _login(acting, up=up)
    command = (
        f"hullwork approve {_h(found.project.slug)} {_h(found.id)}"
        if found is not None
        else "hullwork approve &lt;project&gt; &lt;item&gt;"
    )
    return (
        '<p class="sub how">No password is set on this instance, so nothing here can act. Run '
        "<code>hullwork password</code> on the host to sign in from a browser, or decide from "
        f"there — <code>{command}</code>.</p>"
    )


def the_error_itself(session: Session, item_id: int) -> str:
    """The full error as the tracker recorded it. Item 232, item 036's table finally on the page.

    **The webhook cuts the title at 100 characters**, and for a `KeyError` or a `ValueError` the
    half it cuts is often the input that reproduces the bug. The item's title is the cut one; this
    is the whole one, and it is nowhere else on this page.

    **Nothing is scrubbed here.** The adapter does it on the way in, which is what that table exists
    to say after an audit found a live DSN in one field and this product's own webhook token in
    another, on real events. A second scrubber would be a second thing to keep correct.
    """
    from hullwork.models import FetchedEvent

    seen = list(
        session.scalars(
            select(FetchedEvent)
            .where(FetchedEvent.item_id == item_id)
            .order_by(FetchedEvent.occurred_at.desc().nullslast(), FetchedEvent.id.desc())
        ).all()
    )
    if not seen:
        return ""

    newest = seen[0]
    # **`prune` empties this row and keeps it** (item 231's neighbour): rendering *no frames* for a
    # pruned event would report an error with no stack rather than one whose stack this instance
    # chose to forget. Different sentences, and the second is the true one.
    forgotten = not newest.frames and not newest.packages
    said = []
    if newest.message:
        said.append(
            f'<p class="sub">The whole message, untruncated — the webhook cuts it at 100 '
            f"characters and the half it cuts is often what reproduces the bug:</p>"
            f'<pre class="wide"><code>{_h(newest.message)}</code></pre>'
        )
    facts = [
        (label, value)
        for label, value in (
            ("type", newest.exception_type),
            ("where", newest.culprit),
            ("level", newest.level),
            ("handled", None if newest.handled is None else ("yes" if newest.handled else "no")),
            ("release", newest.release),
            ("host", newest.server_name),
            ("happened", _ago(newest.occurred_at) if newest.occurred_at else None),
        )
        if value
    ]
    said.append(
        "<ul>"
        + "".join(f"<li>{_h(label)}: <code>{_h(value)}</code></li>" for label, value in facts)
        + "</ul>"
    )
    if len(seen) > 1:
        said.append(
            f'<p class="sub">{len(seen)} occurrences of this are stored. Two samples of one bug '
            "are worth more than one: what differs between them is usually the input that "
            "triggers it, and the tracker notifies once per issue and never again.</p>"
        )
    if forgotten:
        said.append(
            '<p class="sub">Its frames, its locals and its pinned versions were forgotten by '
            "<code>hullwork prune</code>. The error is not missing them — this instance stopped "
            "keeping them.</p>"
        )
    else:
        said.append(_the_frames(newest.frames))
        if newest.packages:
            said.append(
                _fold(
                    f"What was installed when it failed — {len(newest.packages)} version(s)",
                    '<div class="wide"><table class="list"><tr><th>package</th>'
                    "<th>version</th></tr>"
                    + "".join(
                        f'<tr><td data-label="package">{_h(name)}</td>'
                        f'<td data-label="version">{_h(version)}</td></tr>'
                        for name, version in sorted(newest.packages.items())
                    )
                    + "</table></div>",
                )
            )
    return _fold("The error, as the tracker recorded it", "".join(said))


def _the_frames(frames: list[dict[str, object]]) -> str:
    """The stack, innermost last, with the line each one stopped on.

    The locals get their own disclosure: scrubbed, and still the thing a reader is least often
    looking for and most likely to be surprised to find rendered.
    """
    if not frames:
        return '<p class="sub">No frames were recorded for this occurrence.</p>'
    said = []
    for frame in frames:
        where = _h(str(frame.get("filename") or frame.get("module") or "?"))
        line = frame.get("lineno")
        held = frame.get("variables")
        said.append(
            f'<li><code>{where}</code>'
            + (f" line {_h(line)}" if line else "")
            + (f" in <code>{_h(frame.get('function'))}</code>" if frame.get("function") else "")
            + (
                f'<pre class="wide"><code>{_h(frame.get("context_line"))}</code></pre>'
                if frame.get("context_line")
                else ""
            )
            + (
                _fold(
                    "What the code was holding here",
                    '<div class="wide"><table class="list">'
                    + "".join(
                        f'<tr><td data-label="name">{_h(name)}</td>'
                        f'<td data-label="was">{_h(value)}</td></tr>'
                        for name, value in dict(held).items()
                    )
                    + "</table></div>",
                )
                if isinstance(held, dict) and held
                else ""
            )
            + "</li>"
        )
    return f"<h2>Where it stopped</h2><ol>{''.join(said)}</ol>"


def item(
    session: Session,
    settings: Settings,
    item_id: int,
    *,
    acting: Acting = READING,
    said: str | None = None,
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
        ("seen", f"{_h(found.occurrences)} time(s) · first {_when(found.first_seen)}"
                 f" · last {_when(found.last_seen)}"),
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
        _outcome(said)
        + f"<h1>#{_h(found.id)} {_h(title)}</h1>"
        f'<p class="sub"><a href="../items">All items</a> · <a href="../">Instance</a></p>'
        f'<div class="band"><table>{table}</table></div>'
        + _next_action(found, acting, up="../")
        + the_error_itself(session, found.id)
        + (
            f'<p class="sub">{_h(_NOT_STORED)}</p>' + "".join(blocks)
            if blocks
            # **No longer "either … or".** What it is waiting for is stated above, from the state,
            # and this line now says only the thing the state cannot: that there is no evidence
            # trail yet because nothing has run.
            else '<p class="sub">No attempts yet, so there is no evidence to read here.</p>'
        )
    )
    # The item's own state on the bar, in the colour its column uses on the front page: a reader who
    # arrived from a forge issue has not seen the board, and this is the fastest way to say where
    # it is.
    tone = {
        ItemState.WAITING_APPROVAL: "mine",
        ItemState.HUMAN_ONLY: "mine",
        ItemState.PR_OPEN: "mine",
        ItemState.DONE: "ok",
        ItemState.FAILED: "bad",
        ItemState.REJECTED: "bad",
    }.get(found.state, "")
    return _document(
        f"Hullwork — item {found.id}",
        body,
        acting=acting,
        up="../",
        state=(found.state.value, tone),
        projects=each_project(session),
    )


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
