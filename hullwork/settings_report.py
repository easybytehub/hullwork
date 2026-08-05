"""What this instance is set to, on one screen. Item 146, last of DR-0014's four.

**The question that took a session to answer by hand.** On 2026-08-04, moving two instances onto a
third-party API key meant reading a compose file, an environment file, `config.py` and a container's
environment side by side — because nothing could say *what is this instance set to*. Three defects
came out of that gap, every one of them the same shape: the code supported a setting and no
installation could use it.

`doctor` reports what is **broken**. `status` reports what has **happened**. Neither reports what
the instance **is**, and that is the third question an operator has.

**No secret is ever printed.** A `SecretStr` renders as *set* or *not set*, which answers the only
question a terminal can answer about a credential: whether it is there. Whether it is the *right*
value is asked of the far end, by `doctor`'s forge and model checks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import SecretStr

from hullwork.config import Settings
from hullwork.scaffold import REACH, Reach

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Field names whose value is a credential, derived from the annotation rather than listed.
#:
#: A `SecretStr` added tomorrow is redacted without anybody remembering to come here — and a
#: hand-kept list going stale against the model is exactly what item 145 was about.
SECRETS: frozenset[str] = frozenset(
    name
    for name, field in Settings.model_fields.items()
    if field.annotation is SecretStr or "SecretStr" in str(field.annotation)
)

_FROM_ENVIRONMENT = "environment"
_FROM_DEFAULT = "default"

#: Where a long value is cut. Values here are URLs and comma-separated lists; the useful half is the
#: front, and a reader who needs all of it has the environment file.
_VALUE_WIDTH = 44


def rows(settings: Settings) -> Iterator[tuple[str, str, str, str]]:
    """Every setting: its variable, its value, where it came from, which half needs it.

    Sorted by name, because *is X set* is asked about one variable and should be findable without
    reading the screen.

    **`model_fields_set` rather than a comparison against the default.** A value that happens to
    equal its default was still set, and an operator who typed it wants to see that it took effect.
    """
    for name in sorted(Settings.model_fields):
        variable = f"HULLWORK_{name.upper()}"
        raw = getattr(settings, name)
        if name in SECRETS:
            shown = "set" if raw is not None else "not set"
        elif raw is None:
            shown = "not set"
        elif isinstance(raw, tuple | list | frozenset | set):
            shown = ", ".join(str(part) for part in raw) or "empty"
        else:
            shown = str(raw)
        source = _FROM_ENVIRONMENT if name in settings.model_fields_set else _FROM_DEFAULT
        yield variable, shown, source, REACH.get(name, Reach.BOTH).value


def lines(settings: Settings) -> list[str]:
    """The report, as an operator reads it.

    Aligned from the data rather than with a table library: this has to work inside a container with
    nothing installed, which is where somebody most often wants it.
    """
    found = list(rows(settings))
    width = max(len(variable) for variable, _, _, _ in found)

    out = [
        "What this instance is set to. No credential is printed:",
        "a secret reads `set` or `not set`.",
        "",
        f"  {'VARIABLE'.ljust(width)}  {'VALUE'.ljust(_VALUE_WIDTH)}  FROM         REACHES",
    ]
    for variable, value, source, reach in found:
        shown = value if len(value) <= _VALUE_WIDTH else value[: _VALUE_WIDTH - 1] + "…"
        out.append(
            f"  {variable.ljust(width)}  {shown.ljust(_VALUE_WIDTH)}"
            f"  {source.ljust(11)}  {reach}"
        )
    out += [
        "",
        f"  {len(found)} setting(s). `reaches` is which half of Hullwork the deployment",
        "  passes it to (DR-0009). Whether it arrived is `hullwork doctor`.",
    ]
    return out
