"""What a project pinned, read from its own lock files. Item 172, DR-0016.

**Lock files rather than declarations**, and the distinction is the whole reason this module can
say anything useful: `requests>=2.0` is a range, and a range does not tell you what is installed.
Only a lock says what a build actually resolved to, which is what a vulnerability database can be
asked about.

**Pure functions over a `read` callable**, which is `propose`'s pattern and is here for the same
reason: the identical code then serves a local checkout and a forge tree, so the answer cannot
differ depending on which door the question came through.

**Nothing here reaches the network**, and nothing here needs to. The sandbox has none by design
(`sandbox/image.py` — *"the build has network; the attempt does not"*), so DR-0016 puts this step
in the dispatcher, before any container exists. This module does not even know a container is
coming.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass

#: What this reads, named so a checkout with none of them can be told what was looked for. An empty
#: list reads as "you have no dependencies", which is a different claim.
#:
#: The ecosystem lives in each reader rather than beside the filename: **OSV's own strings**
#: (`npm`, `PyPI`) go straight into the query, and a translation table between our names and
#: theirs would be a second thing to keep correct for no gain.
#:
#: The last two entries are shapes rather than names, and item 180 is why: matching only the exact
#: basename `requirements.txt` missed every layout Python projects actually use. This list is for a
#: person to read; `is_requirements` below is what decides.
WHAT_IS_LOOKED_FOR: tuple[str, ...] = (
    "package-lock.json",
    "uv.lock",
    "poetry.lock",
    "requirements.txt",
    "requirements-*.txt and *-requirements.txt",
    "any *.txt inside a requirements/ directory",
)

#: `name==version`, and nothing else. Extras and environment markers are stripped before the match
#: because `httpx[http2]==0.27.0 ; python_version >= "3.8"` pins `httpx`, and refusing to read that
#: line would drop a real pin over punctuation.
_PINNED = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")

#: A requirement line that is not a comment, not blank, and not an option.
#:
#: **The leading `-` is excluded deliberately**, and a test is why: with it in the class, `-e .`
#: counted as a requirement this reader could not pin, so a file whose every real line was pinned
#: still reported an unpinned one. `-e`, `-r other.txt` and `--index-url` are pip options, not
#: dependencies, and no package name begins with a hyphen.
_A_REQUIREMENT = re.compile(r"^\s*[A-Za-z0-9._]")


#: The leading numeric core of a version — `5.0.6` out of `5.0.6-rc1+build.7`. Both ecosystems this
#: product reads spell that part the same way, which is why one function serves npm and PyPI.
_CORE = re.compile(r"^\s*v?(\d+(?:\.\d+)*)")


def newer(candidate: str, than: str) -> bool | None:
    """Whether `candidate` is a later version than `than`, or `None` when it cannot be told.

    **`None` is the point of this signature.** A version neither side can parse is not a version to
    drop silently: OSV carries `1.2.3.RELEASE`, `2024-11-01` and `0.9.0.beta` among the ordinary
    ones, and a comparison that guessed would either try nonsense or hide a real fix. Unknown means
    *try it*, and the caller says so.

    Numbers as numbers, because `5.0.10` sorts before `5.0.9` as a string, and a rule built on that
    would skip the one upgrade that mattered.
    """
    here, there = _CORE.match(candidate), _CORE.match(than)
    if here is None or there is None:
        return None
    left = [int(part) for part in here.group(1).split(".")]
    right = [int(part) for part in there.group(1).split(".")]
    width = max(len(left), len(right))
    left += [0] * (width - len(left))
    right += [0] * (width - len(right))
    return left > right


@dataclass(frozen=True)
class Dependency:
    """One pinned package, and which file said so.

    `source` is carried because a project can pin the same name in two files at different
    versions, and a report that cannot say which one it read is a report nobody can act on.
    """

    ecosystem: str
    name: str
    version: str
    source: str


def _from_package_lock(text: str, source: str) -> list[Dependency]:
    """npm's lock, versions 2 and 3, which both carry the flat `packages` map.

    The `""` key is the project itself rather than a dependency of it. Including it would have
    Hullwork ask OSV about the repository being scanned.
    """
    try:
        document = json.loads(text)
    except ValueError:
        return []
    packages = document.get("packages")
    if not isinstance(packages, dict):
        return []

    found: list[Dependency] = []
    for path, entry in packages.items():
        if not path or not isinstance(entry, dict):
            continue
        version = entry.get("version")
        # An entry with no version appears in the file and pins nothing — a link or a workspace
        # member — so it is not something to ask a vulnerability database about.
        if not isinstance(version, str) or not version:
            continue
        # `node_modules/@scope/pkg` → `@scope/pkg`, and nested paths keep only the last package.
        name = path.split("node_modules/")[-1]
        found.append(Dependency("npm", name, version, source))
    return found


def _from_toml_lock(text: str, source: str) -> list[Dependency]:
    """`uv.lock` and `poetry.lock`, which are the same two keys under `[[package]]`.

    One reader rather than two: they differ in everything except the part this needs, and a second
    reader would be a second thing to keep correct for a difference that does not exist here.
    """
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    packages = document.get("package")
    if not isinstance(packages, list):
        return []

    found: list[Dependency] = []
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name, version = entry.get("name"), entry.get("version")
        if isinstance(name, str) and isinstance(version, str) and name and version:
            found.append(Dependency("PyPI", name, version, source))
    return found


def _from_requirements(text: str, source: str) -> list[Dependency]:
    """The weakest reader, and the one most projects will actually hit.

    Only `==` pins. Everything else is a range, and a range cannot be asked about — see
    `unpinned`, which is how the caller says how much of the file it could not use.
    """
    found: list[Dependency] = []
    for line in text.splitlines():
        matched = _PINNED.match(line)
        if matched:
            found.append(Dependency("PyPI", matched.group(1), matched.group(2), source))
    return found


def unpinned(text: str) -> int:
    """How many requirement lines were **not** `==` pins.

    Reporting four packages out of a file with six requirement lines, without saying so, would
    understate the answer silently — which is the failure mode this whole repository is about.
    """
    return sum(
        1
        for line in text.splitlines()
        if _A_REQUIREMENT.match(line) and not _PINNED.match(line)
    )


_READERS: dict[str, Callable[[str, str], list[Dependency]]] = {
    "package-lock.json": _from_package_lock,
    "uv.lock": _from_toml_lock,
    "poetry.lock": _from_toml_lock,
    "requirements.txt": _from_requirements,
}

#: `requirements-dev.txt`, `dev-requirements.txt`, `requirements_test.txt` — the word at **one end
#: or the other**, never buried in the middle.
#:
#: The first version of this was `(?:.+[-_])?requirements(?:[-_].+)?\.txt`, whose comment claimed it
#: would not take `install-requirements-guide.txt`. It did: prefix `install-`, the word, suffix
#: `-guide`. The comment was the assertion, and a comment is not one — a test caught it the moment
#: the near miss was written down. So the alternation is explicit: the name *starts* with the word,
#: or it *ends* with it.
_NAMED_REQUIREMENTS = re.compile(r"^(?:requirements(?:[-_].+)?|.+[-_]requirements)\.txt$")

#: A directory whose whole job is to hold them. `requirements/base.txt` and `requirements/prod.txt`
#: are the layout this repository itself uses, and item 180 found them unread.
_REQUIREMENTS_DIR = "requirements"


def is_requirements(path: str) -> bool:
    """Whether this path is a pip requirements list. Item 180.

    **Widened from one exact basename, and safe because the reader is strict.** `_from_requirements`
    takes only `name==version` lines, so a `.txt` that is not a requirements file contributes zero
    dependencies rather than nonsense — which is what makes casting a wider net cost nothing. The
    alternative, matching one name, cost this repository three of its own pinned packages in
    silence.

    Two shapes, because those are the two conventions: the word in the file name, and a directory
    named for it. Anything else with a `.txt` extension is left alone — a report about a changelog
    would be worse than the miss.
    """
    parts = path.split("/")
    name = parts[-1]
    if not name.endswith(".txt"):
        return False
    if len(parts) >= 2 and parts[-2] == _REQUIREMENTS_DIR:
        return True
    return bool(_NAMED_REQUIREMENTS.match(name))


def _reader_for(path: str) -> Callable[[str, str], list[Dependency]] | None:
    """Which reader owns this path, or `None` when nothing does.

    The exact-name table first, because three of the four entries are lock files whose names are
    fixed by their own tooling and cannot be pattern-matched without inviting a false positive.
    """
    reader = _READERS.get(path.rsplit("/", 1)[-1])
    if reader is not None:
        return reader
    return _from_requirements if is_requirements(path) else None


def read_lockfiles(
    paths: Sequence[str], read: Callable[[str], str | None]
) -> list[Dependency]:
    """Every pinned dependency the tree declares, in the order the files were found.

    A file that cannot be parsed contributes nothing rather than raising: a project with a broken
    `requirements.txt` still has a `package-lock.json` worth reading, and one unreadable file must
    not cost the whole answer.
    """
    found: list[Dependency] = []
    for path in paths:
        # Matched on the file name so a lock in a subdirectory is read too — a monorepo pins per
        # package, and only reading the root would report a fraction of the truth as the whole.
        # Item 180: that same sentence is why `requirements/prod.txt` is read as well, and it took
        # running this against its own repository to notice that it was not.
        reader = _reader_for(path)
        if reader is None:
            continue
        text = read(path)
        if text is None:
            continue
        found.extend(reader(text, path))
    return found
