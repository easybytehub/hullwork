"""Every command and flag the published documentation shows can be run by the image it pins.

Item 165, and the rule it enforces is in `CONTRIBUTING.md`: **documentation describes the released
artefact, not the working tree.**

Three times the tree could do something the image could not, and each was found by a person running
the artefact rather than by a check:

* `0.1.0a1` shipped without the `telemetry` and `postgres` extras, so `HULLWORK_ERROR_DSN` made the
  container exit 3 and a Postgres URL died in a traceback — both documented in three places each
  (item 150);
* `projects add --credential-file` was documented in `docs/connecting-a-project.md` while every
  version of the docs pinned `0.1.0a5`, which answers `unrecognized arguments: --credential-file`
  (item 163's fix landed after that release).

The common shape: the sentence was true of `main` and false of the thing a reader pulls. A test
against the local parser would have passed in all three cases, because in all three cases the local
parser was right. So this reads `docs/published-surface.json`, which
`scripts/record-the-published-surface.py` records **from the image itself**.

What that buys, concretely: adding a flag and documenting it in the same commit now fails here, and
the way to make it pass is to release — which is the correct order, because until then the sentence
is a promise nobody can keep.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SURFACE = json.loads((ROOT / "docs/published-surface.json").read_text(encoding="utf-8"))

#: What a stranger reads. Listed rather than globbed so adding a document is a decision: a new one
#: is either declared here — and bound by everything below — or held back by the publication step,
#: and `test_every_document_is_either_published_or_withheld` fails until it is one or the other.
PUBLISHED = (
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "PRIVACY.md",
    "CODE_OF_CONDUCT.md",
    "LICENSE.md",
    "PULL_REQUEST_TEMPLATE.md",
    "docs/README.md",
    "docs/an-attempt-end-to-end.md",
    "docs/connecting-a-project.md",
    "docs/deployment-notes.md",
    "docs/faq.md",
    "docs/hullwork-yml.md",
    "docs/install.md",
    "docs/releasing.md",
    "docs/status.md",
)

def _withheld() -> set[str]:
    """What the publication step removes, read from that step rather than copied out of it.

    **The first version listed those paths here and the export refused it**, which was the right
    answer: a public test naming every withheld document tells a reader exactly what is being held
    back, and that is most of what withholding buys. So the list is parsed from the script that owns
    it, and in the public tree — where the script is absent along with the files — this returns
    nothing and the check below becomes *everything present is published*, which is stricter.

    Withholding is not an exemption from the rule either way: a plan may describe what does not
    exist yet, because that is what a plan is, and nobody pulls an image expecting it.
    """
    script = ROOT / "scripts/publish.sh"
    if not script.exists():
        return set()
    text = script.read_text(encoding="utf-8")
    array = re.search(r"^WITHHELD=\((?P<body>.*?)^\)", text, re.S | re.M)
    return set(re.findall(r'"([^"]+)"', array.group("body"))) if array else set()

#: A moving tag on purpose (item 160): it follows `main`, and pinning documentation to it would be
#: pinning to nothing. Excluded from the agreement between pins rather than silently ignored.
MOVING = "edge"

IMAGE = "ghcr.io/easybytehub/hullwork"
PIN = re.compile(rf"{re.escape(IMAGE)}:(?P<tag>[\w.\-]+)")
OPTION = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")
WORD = re.compile(r"^[a-z][a-z0-9-]*$")

#: Where one shell command ends and the next begins. Without this, `hullwork status | grep -c ok`
#: donates `grep`'s flags to `status`.
BREAKS = ("|", "&&", "||", ";", ">", "<", "#")


def _text(name: str) -> str:
    path = ROOT / name
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _joined(text: str) -> list[str]:
    """Lines, with shell continuations folded into the line they continue.

    The case this exists for is real and is the one that got through: `--credential-file` sat on the
    second line of a two-line invocation, so a line-by-line reader saw a command with no flags and a
    flag with no command.
    """
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        lines.append(pending + line)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


def _code(text: str) -> list[str]:
    """Only what is marked as code: fenced blocks, and inline spans in prose.

    **Prose is excluded because prose is not a command.** Reading every line found
    `hullwork is a self-hosted…` in `docs/install.md` and reported `hullwork is a` as a command the
    image does not have — true, and useless. A sentence about Hullwork is not a promise about a
    subcommand; a backtick is what makes it one.
    """
    pieces: list[str] = []
    fenced = False
    for line in _joined(text):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            pieces.append(line)
        else:
            pieces += re.findall(r"`([^`]+)`", line)
    return pieces


def _invocations() -> list[tuple[str, str, list[str]]]:
    """Every `hullwork …` in the published documents, as (document, command, flags).

    Tokenised rather than matched with one big expression, because the interesting inputs are
    `hullwork projects add --slug x --credential-file /run/secrets/y` and `` `hullwork status` `` in
    the middle of a sentence, and one pattern that handles both handles neither well.
    """
    found: list[tuple[str, str, list[str]]] = []

    for name in PUBLISHED:
        for line in _code(_text(name)):
            tokens = line.replace("`", " ").replace("(", " ").replace(")", " ").split()
            for start, word in enumerate(tokens):
                if word != "hullwork":
                    continue

                words: list[str] = []
                flags: list[str] = []
                for candidate in tokens[start + 1 :]:
                    if candidate in BREAKS or candidate.startswith(BREAKS):
                        break
                    if OPTION.fullmatch(candidate):
                        flags.append(candidate)
                        continue
                    if not flags and WORD.match(candidate):
                        words.append(candidate)
                        continue
                    # A path, a value, a placeholder: not part of the command's name and not a flag.
                    continue

                found.append((name, " ".join(["hullwork", *words]), flags))

    return found


def _known(command: str) -> str | None:
    """The longest prefix of a written invocation that the image actually has as a command.

    `hullwork projects add` names a command; `hullwork projects refresh myproject` names one too,
    with an argument that is not a subcommand. Walking back is how the second is recognised without
    a list of which commands take arguments.
    """
    words = command.split()
    while len(words) > 1:
        if " ".join(words) in SURFACE["commands"]:
            return " ".join(words)
        words.pop()
    return "hullwork" if "hullwork" in SURFACE["commands"] else None


def test_the_surface_was_recorded_from_an_image_and_not_from_this_checkout() -> None:
    """The file this whole test rests on. If it were generated locally it would agree with the docs
    in exactly the cases that matter, so its provenance is asserted rather than assumed.
    """
    assert SURFACE["image"].startswith(f"{IMAGE}:")
    assert SURFACE["image"].endswith(SURFACE["version"]), (
        "the recorded version is not the tag it was recorded from — hand-edited, or recorded wrong"
    )
    assert len(SURFACE["commands"]) > 10, "too few commands to be a real recording"


def test_every_documented_command_exists_in_the_published_image() -> None:
    """A written command is either one the image has, or one of its commands plus an argument.

    The second half is what `command.split()[:2]` compares: `hullwork projects refresh myproject`
    walks back to `hullwork projects refresh`, but `hullwork projects invent` walks back to
    `hullwork projects` and is caught, because its first two words are not the ones written.
    """
    unknown = set()
    for document, command, _ in _invocations():
        known = _known(command)
        if known is None or command.split()[:2] != known.split()[:2]:
            unknown.add(f"{document}: `{command}`")

    assert not unknown, (
        "these documents name a command the published image does not have — release first, or "
        "stop documenting it:\n  " + "\n  ".join(sorted(unknown))
    )


def test_every_documented_flag_exists_in_the_published_image() -> None:
    """The one that would have caught `--credential-file`.

    Reported per document and per flag, because the fix differs: an unreleased flag needs a release,
    a renamed one needs an edit, and a typo needs neither.
    """
    missing: list[str] = []
    for document, command, flags in _invocations():
        known = _known(command)
        if known is None:
            continue  # the test above owns this failure
        allowed = set(SURFACE["commands"][known]) | {"--help"}
        missing += [f"{document}: `{known} {flag}`" for flag in flags if flag not in allowed]

    assert not missing, (
        f"the image the documentation pins ({SURFACE['version']}) does not accept these:\n  "
        + "\n  ".join(sorted(set(missing)))
        + "\n\nA flag that exists in this tree and not in that image is a promise nobody can keep "
        "yet. Release it, then re-record with scripts/record-the-published-surface.py."
    )


def test_every_pin_names_the_version_the_surface_was_recorded_from() -> None:
    """Three files pin the image and they have disagreed before. The version is what makes the two
    tests above mean anything: pinning `0.1.0a5` while checking against `0.1.0a6`'s surface would
    prove the docs match an image nobody is told to pull.
    """
    pins: dict[str, set[str]] = {}
    for name in ("README.md", "docker-compose.yml", "docs/install.md", "docs/faq.md"):
        tags = {found.group("tag") for found in PIN.finditer(_text(name))} - {MOVING}
        if tags:
            pins[name] = tags

    assert pins, "nothing pins the image any more, so nothing here is checking anything"

    disagree = {name: sorted(tags) for name, tags in pins.items() if tags != {SURFACE["version"]}}
    assert not disagree, (
        f"the surface was recorded from {SURFACE['version']} and these pin something else: "
        f"{disagree}"
    )


def test_every_document_is_either_published_or_withheld() -> None:
    """A document added without a decision defaults to invisible, which is the wrong default.

    In the public tree there is nothing to withhold, so this reads as *everything here is declared
    published* — and a document that arrived without being declared fails rather than shipping
    unchecked.
    """
    present = {
        str(path.relative_to(ROOT))
        for path in [*(ROOT / "docs").glob("*.md"), *ROOT.glob("*.md")]
    }
    unaccounted = sorted(present - set(PUBLISHED) - _withheld())

    assert not unaccounted, (
        "declare these: add to PUBLISHED, and they become bound by the rule above — or add to the "
        f"publication step's own list, and they do not ship at all: {unaccounted}"
    )


@pytest.mark.parametrize("document", PUBLISHED)
def test_every_environment_variable_named_in_the_documents_exists(document: str) -> None:
    """The settings half, checked against the code rather than the image.

    An environment variable appears in no `--help` page, so the surface file cannot answer for it.
    That makes this weaker than the flag test on purpose — it catches a name that never existed or
    that was renamed, not one that exists here and not in the release.
    """
    from hullwork.config import Settings

    real = {f"HULLWORK_{field.upper()}" for field in Settings.model_fields}
    # Prefix mentions — `HULLWORK_MODEL_*`, `HULLWORK_MODEL_…` — name a family rather than a
    # variable, and a family has no value to read.
    written = {
        name
        for name in re.findall(r"HULLWORK_[A-Z][A-Z_]*", _text(document))
        if not name.endswith("_")
    }

    assert not (written - real), f"{document} names settings that do not exist: {written - real}"
