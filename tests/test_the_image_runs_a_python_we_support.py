"""The base image and `requires-python` are one fact in two files. Item 254.

Dependabot proposed `python:3.12-slim` → `3.14-slim` and **every check on that pull request was
green**, because no workflow that runs on a pull request builds the image — only `release.yml` and
`edge.yml` do, on a tag and on a schedule. The image does not build:

    ERROR: Package 'hullwork' requires a different Python: 3.14.7 not in '<3.13,>=3.12'

So the first sign would have been a release failing, or a nightly nobody reads.

The Dockerfile already said *"Dependabot proposes the bump; a human takes it"*, and item 017 is the
answer to that: **a guardrail that depends on somebody remembering is not a guardrail.** This one
takes three seconds and runs on every pull request.

Verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import Version

HERE = Path(__file__).resolve().parent.parent

#: `FROM python:<version>-slim@sha256:…`, in either stage. The digest is what makes the build
#: reproducible (Scorecard, Pinned-Dependencies) and the tag beside it is what a reader believes, so
#: the tag is what this reads: a digest that disagreed with its own comment would be a different
#: defect and one no test can see from here.
_BASE = re.compile(r"^FROM\s+python:(\d+\.\d+)-slim", re.M)


def _supported() -> SpecifierSet:
    with (HERE / "pyproject.toml").open("rb") as source:
        return SpecifierSet(tomllib.load(source)["project"]["requires-python"])


def test_every_stage_builds_on_a_python_this_package_supports() -> None:
    """**Both stages, not only the first.** The build stage is where `pip install` refuses, so a
    test that read one `FROM` would catch the bump that breaks the build and miss the one that ships
    a runtime whose interpreter cannot import the virtualenv the build stage produced.
    """
    found = _BASE.findall((HERE / "Dockerfile").read_text(encoding="utf-8"))

    assert len(found) >= 2, f"the Dockerfile has {len(found)} python stages; it had two"
    supported = _supported()
    for version in found:
        assert Version(version) in supported, (
            f"the image is built on python {version}, which is outside this package's "
            f"requires-python ({supported}). `pip install .` refuses, so the image does not build "
            f"— and no workflow that runs on a pull request would have told you."
        )


def test_the_guard_reads_both_files_rather_than_restating_either() -> None:
    """**No copy of the supported version anywhere in this file's code.** A test that hard-codes
    what it is checking is a third place the fact lives, and the one nobody updates: it would keep
    passing against a `requires-python` that had moved, which is the failure this file exists to
    prevent wearing the other hat.

    Asserted over the code rather than the whole file, because the prose above quotes a measured
    error message and a rule that forbids naming a version in a sentence forbids explaining
    anything. The first version of this test failed on its own docstring, which is the distinction
    arriving the hard way.
    """
    import ast

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    prose = {
        said
        for node in [tree, *ast.walk(tree)]
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef)
        and (said := ast.get_docstring(node, clean=False)) is not None
    }
    written = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and node.value not in prose
        and re.fullmatch(r"\d+\.\d+(\.\d+)?", node.value.strip())
    ]

    assert not written, f"this test writes {written} into its code instead of reading it"
    assert "requires-python" in (HERE / "pyproject.toml").read_text(encoding="utf-8")
