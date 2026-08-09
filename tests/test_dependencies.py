"""What the project pinned, and what OSV says about it. Item 172, DR-0016.

**The suite never opens a socket.** httpx2's `MockTransport` serves the recorded shapes, exactly as
`test_forge_code.py` does — an OSV client tested against the real service would be a test whose
result depends on somebody else's database changing.

**Lockfiles rather than declarations**, because a declaration is a range and a range is not a fact.
Two of the four readers below are checked against files that actually exist in this repository
rather than only against fixtures written for the test, which is the same rule `test_propose.py`
runs on: a reader tested only against its own fixtures is a reader tested against itself.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path

import httpx2

from hullwork import dependencies, osv
from hullwork.manifest import Manifest, parse_manifest

ROOT = Path(__file__).resolve().parent.parent

PACKAGE_LOCK = """
{
  "name": "thing",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "thing", "version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/x"},
    "node_modules/@scope/pkg": {"version": "2.1.0"},
    "node_modules/no-version": {"resolved": "https://registry.npmjs.org/y"}
  }
}
"""

POETRY_LOCK = """
[[package]]
name = "jinja2"
version = "2.4.1"
description = "A templating engine"

[[package]]
name = "requests"
version = "2.31.0"
"""

REQUIREMENTS = """
# a comment
jinja2==2.4.1
requests>=2.0          ; not a pin
django ~= 4.2          ; not a pin either
lodash==4.17.20

-e .
"""


def _read(files: dict[str, str]) -> Callable[[str], str | None]:
    def read(path: str) -> str | None:
        return files.get(path)

    return read


# --- the readers --------------------------------------------------------------------------


def test_package_lock_gives_up_its_packages_without_the_root_entry() -> None:
    """The `""` key is the project itself, not a dependency of it.

    Including it would have Hullwork ask OSV about the repository being scanned, which is both
    wrong and slightly embarrassing.
    """
    found = dependencies.read_lockfiles(
        ["package-lock.json"], _read({"package-lock.json": PACKAGE_LOCK})
    )

    assert [(d.name, d.version) for d in found] == [
        ("lodash", "4.17.20"),
        ("@scope/pkg", "2.1.0"),
    ]
    assert {d.ecosystem for d in found} == {"npm"}
    assert all(d.source == "package-lock.json" for d in found)


def test_a_package_lock_entry_with_no_version_is_not_a_pin() -> None:
    """It appears in the file and pins nothing, so it is not something to ask about."""
    found = dependencies.read_lockfiles(
        ["package-lock.json"], _read({"package-lock.json": PACKAGE_LOCK})
    )
    assert "no-version" not in {d.name for d in found}


def test_poetry_and_uv_are_the_same_two_keys() -> None:
    """Both are TOML with `[[package]]`, `name` and `version`. One reader, not two."""
    found = dependencies.read_lockfiles(["poetry.lock"], _read({"poetry.lock": POETRY_LOCK}))

    assert [(d.name, d.version) for d in found] == [("jinja2", "2.4.1"), ("requests", "2.31.0")]
    assert {d.ecosystem for d in found} == {"PyPI"}


def test_this_repositorys_own_uv_lock_reads(tmp_path: Path) -> None:
    """**The measurement that stops this being tested against itself.**

    Not a fixture: `uv.lock` as this repository actually pins it. If the format moves under us,
    this is what says so.
    """
    del tmp_path
    text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    found = dependencies.read_lockfiles(["uv.lock"], _read({"uv.lock": text}))

    names = {d.name for d in found}
    assert {"alembic", "httpx2", "pydantic"} <= names
    assert all(d.version for d in found), "a package with no version is not a pin"
    assert all(d.ecosystem == "PyPI" for d in found)


def test_requirements_counts_what_it_could_not_pin() -> None:
    """**The honest half of the weakest reader.**

    A line that is not `==` is not a pin and is skipped — but reporting four packages from a file
    with six requirement lines, without saying so, would understate the answer silently.
    """
    found = dependencies.read_lockfiles(
        ["requirements.txt"], _read({"requirements.txt": REQUIREMENTS})
    )

    assert [(d.name, d.version) for d in found] == [
        ("jinja2", "2.4.1"),
        ("lodash", "4.17.20"),
    ]
    assert dependencies.unpinned(REQUIREMENTS) == 2, "requests and django are ranges, not pins"


def test_a_checkout_with_no_lockfile_is_told_what_was_looked_for() -> None:
    """An empty list reads as "you have no dependencies", which is a different claim."""
    assert dependencies.read_lockfiles(["README.md"], _read({"README.md": "#"})) == []
    for name in ("package-lock.json", "uv.lock", "poetry.lock", "requirements.txt"):
        assert name in dependencies.WHAT_IS_LOOKED_FOR


# --- OSV ----------------------------------------------------------------------------------


def _osv(handler: Callable[[httpx2.Request], httpx2.Response]) -> osv.Osv:
    return osv.Osv(transport=httpx2.MockTransport(handler))


def test_it_batches_the_query_and_asks_for_detail_only_on_what_came_back() -> None:
    """One batch for N packages, then one detail call per id — not per package."""
    calls: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("/querybatch"):
            return httpx2.Response(200, json={"results": [{"vulns": [{"id": "GHSA-x"}]}, {}]})
        return httpx2.Response(200, json={
            "id": "GHSA-x",
            "summary": "template injection",
            "affected": [{
                "package": {"name": "jinja2", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.11.3"}]}],
            }],
        })

    deps = [
        dependencies.Dependency("PyPI", "jinja2", "2.4.1", "poetry.lock"),
        dependencies.Dependency("PyPI", "requests", "2.31.0", "poetry.lock"),
    ]
    found = _osv(handler).affected(deps)

    assert len(calls) == 2, "one batch and one detail, never one call per package"
    assert [f.dependency.name for f in found] == ["jinja2"]
    assert found[0].advisories[0].fixed == ("2.11.3",)


def test_a_vulnerability_with_no_published_fix_says_so() -> None:
    """There is no bump to attempt, and proposing the next release and hoping is not an answer."""
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/querybatch"):
            return httpx2.Response(200, json={"results": [{"vulns": [{"id": "GHSA-y"}]}]})
        return httpx2.Response(200, json={
            "id": "GHSA-y",
            "summary": "unfixed",
            "affected": [{
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"events": [{"introduced": "0"}]}],
            }],
        })

    deps = [dependencies.Dependency("npm", "lodash", "4.17.20", "package-lock.json")]
    found = _osv(handler).affected(deps)

    assert found[0].advisories[0].fixed == ()
    assert found[0].advisories[0].has_a_fix is False


def test_several_fixed_versions_are_all_reported_and_none_is_chosen() -> None:
    """**Where honesty is cheap to lose.**

    Choosing would mean comparing versions across two ecosystems' ordering rules, and a wrong
    choice is a bump that does not fix what it claims to. All of them, and a person decides.
    """
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/querybatch"):
            return httpx2.Response(200, json={"results": [{"vulns": [{"id": "GHSA-z"}]}]})
        return httpx2.Response(200, json={
            "id": "GHSA-z",
            "summary": "two branches",
            "affected": [{
                "package": {"name": "jinja2", "ecosystem": "PyPI"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "2.11.3"}]},
                    {"events": [{"introduced": "3.0"}, {"fixed": "3.1.3"}]},
                ],
            }],
        })

    deps = [dependencies.Dependency("PyPI", "jinja2", "2.4.1", "poetry.lock")]
    found = _osv(handler).affected(deps)

    assert found[0].advisories[0].fixed == ("2.11.3", "3.1.3")
    assert found[0].advisories[0].has_a_fix is True


def test_an_advisory_about_another_package_does_not_become_this_ones_fix() -> None:
    """One advisory can name several packages; only the matching one decides this bump.

    Reintroducing this defect made a jinja2 finding claim npm's fixing version, which is the kind
    of wrong answer that looks entirely plausible in a report.
    """
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/querybatch"):
            return httpx2.Response(200, json={"results": [{"vulns": [{"id": "GHSA-multi"}]}]})
        return httpx2.Response(200, json={
            "id": "GHSA-multi",
            "summary": "affects two ecosystems",
            "affected": [
                {"package": {"name": "lodash", "ecosystem": "npm"},
                 "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]},
                {"package": {"name": "jinja2", "ecosystem": "PyPI"},
                 "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.11.3"}]}]},
            ],
        })

    deps = [dependencies.Dependency("PyPI", "jinja2", "2.4.1", "poetry.lock")]
    found = _osv(handler).affected(deps)

    assert found[0].advisories[0].fixed == ("2.11.3",)


def test_nothing_affected_asks_for_no_detail_at_all() -> None:
    """A clean project costs one request, not one plus zero-length follow-ups."""
    calls: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(str(request.url))
        return httpx2.Response(200, json={"results": [{}, {}]})

    deps = [
        dependencies.Dependency("npm", "a", "1.0.0", "package-lock.json"),
        dependencies.Dependency("npm", "b", "1.0.0", "package-lock.json"),
    ]
    assert _osv(handler).affected(deps) == []
    assert len(calls) == 1


def test_one_advisory_shared_by_two_packages_is_fetched_once() -> None:
    """**The test the call-counting one above did not make redundant.**

    That test has a single affected package, so the id cache is never asked the same question
    twice and removing it left every assertion green. A lock file with two packages under the
    same advisory is the case that pays for the cache — and it is the common one, since a flaw in
    a library is published once and hits everything that pins it.
    """
    calls: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("/querybatch"):
            return httpx2.Response(200, json={
                "results": [{"vulns": [{"id": "GHSA-same"}]}, {"vulns": [{"id": "GHSA-same"}]}],
            })
        return httpx2.Response(200, json={
            "id": "GHSA-same",
            "summary": "one flaw, two pins",
            "affected": [
                {"package": {"name": "a", "ecosystem": "npm"},
                 "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1.0"}]}]},
                {"package": {"name": "b", "ecosystem": "npm"},
                 "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2.0"}]}]},
            ],
        })

    deps = [
        dependencies.Dependency("npm", "a", "1.0.0", "package-lock.json"),
        dependencies.Dependency("npm", "b", "2.0.0", "package-lock.json"),
    ]
    found = _osv(handler).affected(deps)

    detail_calls = [c for c in calls if "/vulns/" in c]
    assert len(detail_calls) == 1, "the same advisory must not be fetched once per package"
    # And each package still gets its own fixing version out of the one document.
    assert found[0].advisories[0].fixed == ("1.1.0",)
    assert found[1].advisories[0].fixed == ("2.2.0",)


# --- the requirements files nobody read (item 180) --------------------------------------------


def test_the_layouts_python_projects_actually_use_are_all_read() -> None:
    """Item 180, found by running `deps` against this repository.

    `requirements/build.txt` is tracked here, pins three packages, and was read as none of them —
    with a confident count printed above the silence. Item 172 matched the exact basename, and its
    own reasoning for matching on a name at all condemns that: *"a monorepo pins per package, and
    only reading the root would report a fraction of the truth as the whole."*
    """
    files = {
        "requirements.txt": "a==1.0\n",
        "requirements/base.txt": "b==2.0\n",
        "requirements/prod.txt": "c==3.0\n",
        "requirements-dev.txt": "d==4.0\n",
        "dev-requirements.txt": "e==5.0\n",
        "backend/requirements/test.txt": "f==6.0\n",
    }

    found = dependencies.read_lockfiles(list(files), lambda p: files.get(p))

    assert {d.name for d in found} == {"a", "b", "c", "d", "e", "f"}
    # And each one says which file said so, because a report that cannot is a report nobody can act
    # on — a project can pin the same name in two files at two versions.
    assert {d.source for d in found} == set(files)


def test_a_text_file_that_is_not_a_requirements_list_is_not_read_at_all() -> None:
    """The bound on item 180's widening, and the first version of this test did not test it.

    **It used prose containing no line that looks like a pin**, so it passed whether the matcher
    was careful or `^.*\\.txt$` — verified by making it exactly that and watching nothing go red.
    A changelog is the realistic hazard and it *does* carry pin-shaped lines at the start of a
    line, which is where `_PINNED` looks.

    What it would cost is not a wrong count. `--verify` would try to rewrite that line, and
    `--open` would offer somebody a pull request editing their release notes.
    """
    changelog = (
        "2.10.1 — 2026-01-01\n"
        "===================\n"
        "jinja2==2.10.1 is now the minimum supported version.\n"
        "requests==2.31.0 was dropped from the extras.\n"
    )

    read = dependencies.read_lockfiles(["docs/notes.txt", "CHANGELOG.txt"], lambda _p: changelog)

    assert read == []
    assert not dependencies.is_requirements("CHANGELOG.txt")
    assert not dependencies.is_requirements("docs/notes.txt")
    # And the near misses, which are the ones a looser pattern would take.
    assert not dependencies.is_requirements("install-requirements-guide.txt")
    assert not dependencies.is_requirements("requirements.md")

    # The same text under a name that *is* a requirements file is read, which is what makes the
    # assertions above about the name rather than about the content.
    assert len(dependencies.read_lockfiles(["requirements/prod.txt"], lambda _p: changelog)) == 2


def test_one_package_pinned_twice_in_two_files_is_two_facts() -> None:
    """A real thing, and merging them would hide the disagreement rather than report it."""
    files = {
        "requirements/base.txt": "jinja2==2.4.1\n",
        "requirements/dev.txt": "jinja2==3.1.4\n",
    }

    found = dependencies.read_lockfiles(list(files), lambda p: files.get(p))

    assert sorted((d.version, d.source) for d in found) == [
        ("2.4.1", "requirements/base.txt"),
        ("3.1.4", "requirements/dev.txt"),
    ]


def test_this_repositorys_own_requirements_directory_reads() -> None:
    """The falsifiable gate, as a test. Item 180.

    Against the real file rather than a fixture, for `test_this_repositorys_own_uv_lock_reads`'s
    reason: a reader tested only against its own fixtures is a reader tested against itself. This
    one is also the exact file that produced the finding.
    """
    path = ROOT / "requirements" / "build.txt"
    found = dependencies.read_lockfiles(
        ["requirements/build.txt"], lambda _p: path.read_text(encoding="utf-8")
    )

    assert len(found) >= 3
    assert all(d.source == "requirements/build.txt" for d in found)
    assert "build" in {d.name for d in found}


# --- the build context a verification gets (item 182) -----------------------------------------


def test_verify_hands_the_source_to_a_build_that_reads_it(
    tmp_path: Path, monkeypatch: object
) -> None:
    """Item 113's fix, on the path that never inherited it. Found on the first third-party tree.

    The build context holds the **declared dependency files and never the source**, and three
    ordinary installers read the source anyway: a `requirements.txt` that begins `-e .`, a `Gemfile`
    that says `gemspec`, and `mvn test`. Item 113 measured all three and fixed the attempt path;
    `deps --verify` was written afterwards and passed `source=None` unconditionally.

    Measured on `encode/httpx`, whose first requirement is `-e .[brotli,cli,http2,socks,zstd]`:

        ERROR: file:///work does not appear to be a Python project:
               neither 'setup.py' nor 'pyproject.toml' found.

    Reported to the reader as *your own environment does not build*, which was true of what we built
    and false of the project. Ruby, Java and PHP are all on the roadmap as stacks whose attempts
    work, and every one of them reaches this the same way.

    Driven through `image.build` rather than through Docker: what is under test is **what the
    verification asks for**, and a daemon would prove the same call more slowly.
    """
    import pytest

    from hullwork import cli
    from hullwork.manifest import parse_manifest

    asked: list[dict[str, object]] = []

    class Built:
        tag = "img:1"

    def watch(runtime: object, files: object, engine: object, **kwargs: object) -> Built:
        asked.append(kwargs)
        return Built()

    (tmp_path / "requirements.txt").write_text("-e .\njinja2==2.4.1\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\nversion='1'\n")
    manifest = parse_manifest(
        "project: p\ngit: {provider: github, repo: o/r}\n"
        'tests: "pytest"\ntest_path: tests\n'
        "runtime: {base: python-3.12, install: pip, dependencies: [requirements.txt], "
        "install_needs_source: true}\n"
    )
    from hullwork.sandbox import image as image_module

    monkeypatch.setattr(image_module, "build", watch)  # type: ignore[attr-defined]
    # The first build is the baseline and is the only one this needs: it either carries the source
    # or it does not, and everything after it is the same call.
    with pytest.raises(Exception):  # noqa: B017 - it stops at the sandbox, after the build
        cli._verify_one(
            tmp_path, ["requirements.txt"], lambda p: (tmp_path / p).read_text(),
            manifest,
            dependencies.Dependency("PyPI", "jinja2", "2.4.1", "requirements.txt"),
            ["2.10.1"], io.StringIO(),
        )

    assert asked, "no image was built at all"
    assert asked[0]["source"] is not None, "the build got no source to install from"
    assert asked[0]["source_ref"] is not None, (
        "an image whose source is not in its tag is an image reused across commits"
    )


def test_a_project_whose_install_does_not_read_the_source_still_gets_none(
    tmp_path: Path, monkeypatch: object
) -> None:
    """The cheap path stays cheap: the tag does not move and the image is reused between runs."""
    import pytest

    from hullwork import cli
    from hullwork.manifest import parse_manifest
    from hullwork.sandbox import image as image_module

    asked: list[dict[str, object]] = []

    class Built:
        tag = "img:1"

    def watch(runtime: object, files: object, engine: object, **kwargs: object) -> Built:
        asked.append(kwargs)
        return Built()

    (tmp_path / "requirements.txt").write_text("jinja2==2.4.1\n")
    manifest = parse_manifest(
        "project: p\ngit: {provider: github, repo: o/r}\n"
        'tests: "pytest"\ntest_path: tests\n'
        "runtime: {base: python-3.12, install: pip, dependencies: [requirements.txt]}\n"
    )
    monkeypatch.setattr(image_module, "build", watch)  # type: ignore[attr-defined]
    with pytest.raises(Exception):  # noqa: B017
        cli._verify_one(
            tmp_path, ["requirements.txt"], lambda p: (tmp_path / p).read_text(),
            manifest,
            dependencies.Dependency("PyPI", "jinja2", "2.4.1", "requirements.txt"),
            ["2.10.1"], io.StringIO(),
        )

    assert asked and asked[0]["source"] is None
    assert asked[0]["source_ref"] is None


# --- what cannot be verified at all, said before anything is built (item 182) ------------------


def _manifest(declared: str) -> Manifest:
    return parse_manifest(
        "project: p\ngit: {provider: github, repo: o/r}\n"
        'tests: "pytest"\ntest_path: tests\n'
        f"runtime: {{base: python-3.12, install: pip, dependencies: {declared}}}\n"
    )


def test_a_pin_in_a_file_the_image_never_installs_cannot_be_verified() -> None:
    """**The false artefact this whole product exists to prevent, produced by the product.**

    `pallets/flask` pins four of its five advisory-carrying packages in
    `examples/celery/requirements.txt`, which its image is not built from. Rewriting a version
    there changes no byte the build reads: `dependency_digest` does not move, the image is reused,
    and the suite passes exactly as it passed before — so the verdict is `clean` and the queue says
    *ready to take*.

    Measured against a real daemon on 2026-08-09, on a tree declaring `requirements.txt` and
    carrying `extras/requirements.txt`:

        [ready to take] jinja2 2.4.1 → 2.10.1
        $ docker run --rm <image> python -c "import jinja2"
        ModuleNotFoundError: No module named 'jinja2'

    A package **not installed in the environment its suite ran in**, offered as ready to merge —
    and with item 178's `--open`, as a pull request. Item 174 found the same false verdict by the
    other route, where the box was reused; this one needs no box at all.
    """
    from hullwork import cli

    outside = dependencies.Dependency("PyPI", "jinja2", "2.4.1", "extras/requirements.txt")

    refusal = cli._cannot_be_verified(outside, _manifest("[requirements.txt]"), ["2.10.1"])

    assert refusal is not None
    assert "not one of the files your image is built from" in refusal
    assert "requirements.txt" in refusal


def test_a_pin_the_image_does_install_is_verified_as_before() -> None:
    """The refusal must not swallow the ordinary case, which is every project with one file."""
    from hullwork import cli

    inside = dependencies.Dependency("PyPI", "jinja2", "2.4.1", "requirements.txt")

    assert cli._cannot_be_verified(inside, _manifest("[requirements.txt]"), ["2.10.1"]) is None


def test_a_project_that_installs_nothing_cannot_have_an_upgrade_measured() -> None:
    """**The worse half of the same finding, and `install: none` is the default value.**

    The generated Dockerfile copies no dependency file and runs no installer when `install` is
    `none`, so the environment is `runtime.base` exactly as it comes. DR-0007 makes *the project
    brings its own image* the primary path, so this is most projects rather than an edge.

    Measured on 2026-08-09 against a base image carrying `jinja2 3.0.0`, on a checkout pinning
    `jinja2==2.4.1`:

        [ready to take] jinja2 2.4.1 → 2.10.1
        $ docker run --rm <both sandbox images> python -c "import jinja2; print(__version__)"
        3.0.0
        3.0.0

    **Neither version in the claim was ever installed.** The verdict said the suite passed before
    the change and after it, which was true and was about nothing.
    """
    from hullwork import cli
    from hullwork.manifest import parse_manifest

    own_image = parse_manifest(
        "project: p\ngit: {provider: github, repo: o/r}\n"
        'tests: "pytest"\ntest_path: tests\n'
        "runtime: {base: python-3.12, install: none, dependencies: []}\n"
    )
    anywhere = dependencies.Dependency("PyPI", "jinja2", "2.4.1", "requirements.txt")

    refusal = cli._cannot_be_verified(anywhere, own_image, ["2.10.1"])

    assert refusal is not None
    assert "install: none" in refusal
    assert "rebuilding it" in refusal, "it has to say what a person does instead"


def test_a_refusal_is_counted_rather_than_only_printed() -> None:
    """"I could not verify this" is a first-class answer, so it has to be in the tally.

    **Driven through `_verify_upgrades`, because the first version of this was not.** That one
    asserted `needs_of` and `summary` over a hand-built report — both already true — so it passed
    with the `reports.append` deleted. What it claims to check is that the refusal *reaches* the
    queue, and only the function that builds the queue can say.

    A refusal that only reached the terminal left the summary saying `0 blocked` for a run that
    could verify none of them, and that count is the one number in this command a person acts on.
    No Docker: every refusal here is answered before anything is built.
    """
    from hullwork import bump, cli, osv

    outside = dependencies.Dependency("PyPI", "jinja2", "2.4.1", "extras/requirements.txt")
    findings = [
        osv.Finding(
            dependency=outside,
            advisories=(osv.Advisory(id="GHSA-x", summary="", fixed=("2.10.1",)),),
        )
    ]
    printed = io.StringIO()

    reports = cli._verify_upgrades(
        Path("/nowhere"), ["extras/requirements.txt"], lambda _p: None,
        _manifest("[requirements.txt]"), findings, printed,
    )

    assert len(reports) == 1, "the refusal never reached the queue"
    assert bump.needs_of(reports[0]) is bump.Needs.BLOCKED
    assert bump.summary(reports)[bump.Needs.BLOCKED] == 1
    assert "not one of the files your image is built from" in printed.getvalue()
