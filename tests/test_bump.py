"""Does the upgrade survive the project's own suite. Item 173, DR-0016.

**No test here needs Docker**, and that is the same trade `dispatch` makes: the function is handed
a box and a directory, so a double serves it. The Docker path is measured once by hand and written
into the item, because a mocked container proves the wiring and not the claim.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hullwork import bump
from hullwork.sandbox.run import RunResult


class FakeBox:
    """A sandbox that answers with whatever the test queued, in order."""

    def __init__(self, worktree: Path, *results: RunResult) -> None:
        self.worktree = worktree
        self._results = list(results)
        self.commands: list[str] = []

    def run(self, command: str, timeout: int = 0) -> RunResult:
        del timeout
        self.commands.append(command)
        return self._results.pop(0)


def _ok(output: str = "12 passed") -> RunResult:
    return RunResult(command="pytest", exit_code=0, output=output, duration_ms=10)


def _red(output: str = "FAILED tests/test_a.py::test_one\n1 failed") -> RunResult:
    return RunResult(command="pytest", exit_code=1, output=output, duration_ms=10)


def _checkout(tmp_path: Path, text: str = "jinja2==2.4.1\n") -> Path:
    (tmp_path / "requirements.txt").write_text(text, encoding="utf-8")
    return tmp_path


# --- the edit -----------------------------------------------------------------------------


def test_a_pin_is_rewritten_and_everything_else_on_the_line_survives() -> None:
    """Extras, environment markers and trailing comments all outlive the upgrade.

    Only the version group is replaced, which is why this works at all — a line rebuilt from its
    parsed parts would quietly drop the marker and change what gets installed on other platforms.
    """
    line = 'httpx[http2]==0.27.0 ; python_version >= "3.8"  # pinned by hand\n'
    out = bump.rewrite_pin(line, "httpx", "0.28.1")

    assert out == 'httpx[http2]==0.28.1 ; python_version >= "3.8"  # pinned by hand\n'


def test_only_the_named_package_moves() -> None:
    text = "jinja2==2.4.1\nrequests==2.31.0\njinja2-time==0.2.0\n"
    out = bump.rewrite_pin(text, "jinja2", "2.10.1")

    assert "jinja2==2.10.1" in out
    assert "requests==2.31.0" in out
    assert "jinja2-time==0.2.0" in out, "a longer name that starts the same is a different package"


def test_a_hashed_pin_is_refused_rather_than_broken() -> None:
    """The hash describes the artefact pinned. Change the version and it will not install."""
    text = "jinja2==2.4.1 --hash=sha256:abc\n"
    with pytest.raises(bump.CannotRewriteError, match="hash"):
        bump.rewrite_pin(text, "jinja2", "2.10.1")


def test_a_package_that_is_not_pinned_here_is_not_silently_ignored() -> None:
    with pytest.raises(bump.CannotRewriteError, match="no `django==…` line"):
        bump.rewrite_pin("jinja2==2.4.1\n", "django", "5.0")


@pytest.mark.parametrize("name", ["Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock"])
def test_a_lock_with_no_resolver_is_still_refused_by_name(name: str) -> None:
    """**The allow-list is the point.**

    Item 175 gave `package-lock.json`, `uv.lock` and `poetry.lock` a resolver, so those are no
    longer refused. Everything else still is — and stating the rule as *only lists are editable*
    rather than as three named refusals is what makes that true for a lock file nobody has taught
    this about yet. The unsafe answer must never be the default.
    """
    with pytest.raises(bump.CannotRewriteError) as caught:
        bump.can_rewrite(f"path/to/{name}")

    assert name in str(caught.value)
    assert "cannot install" in str(caught.value)


@pytest.mark.parametrize("name", ["package-lock.json", "uv.lock", "poetry.lock"])
def test_a_lock_with_a_resolver_is_no_longer_refused(name: str) -> None:
    """Item 175 lifted the refusal for these: their own tool can move the graph."""
    bump.can_rewrite(f"path/to/{name}")


def test_requirements_is_not_refused() -> None:
    bump.can_rewrite("requirements.txt")
    bump.can_rewrite("deep/nested/requirements.txt")


@pytest.mark.parametrize(
    "name",
    [
        "requirements/base.txt",
        "requirements/prod.txt",
        "requirements-dev.txt",
        "dev-requirements.txt",
        "backend/requirements/test.txt",
    ],
)
def test_every_layout_the_reader_accepts_is_editable_by_hand(name: str) -> None:
    """The consequence item 180 created, caught before it shipped.

    Widening the reader without widening this made `can_rewrite` refuse every one of these — and
    refuse them with a sentence that is **false**: *"it is a resolved graph rather than a list of
    versions"*. They are lists of versions; that is the whole reason the reader can read them. The
    cost would have been the entire `--verify` / `--open` / `--fix` chain going quiet on any project
    using a layout other than a root `requirements.txt`, with a wrong reason printed for each.

    One predicate for both, so a layout that becomes readable becomes editable in the same edit.
    """
    bump.can_rewrite(name)


def test_a_hash_pinned_line_is_still_refused_by_name_in_any_layout() -> None:
    """The refusal that existed and had never had the chance to fire. Item 180's last criterion.

    `requirements/build.txt` in this repository pins by hash, and until the reader read that file
    nothing could reach this. Now that something can, the refusal has to be the one about hashes —
    specific and actionable — rather than the generic one about resolved graphs.
    """
    with pytest.raises(bump.CannotRewriteError, match="hash"):
        bump.rewrite_pin("build==1.2.1 --hash=sha256:abc\n", "build", "1.3.0")


# --- the three phases ---------------------------------------------------------------------


def test_a_suite_that_is_already_red_stops_before_anything_is_rewritten(tmp_path: Path) -> None:
    """**Before the edit and before a second build is paid for.**

    A suite already failing cannot support "passed before and passes after", and blaming the
    upgrade for it is the error `dispatch` made until item 043.
    """
    checkout = _checkout(tmp_path)
    box = FakeBox(checkout, _red())
    rebuilt: list[str] = []

    answer = bump.attempt(
        lambda: box, tests="pytest", source="requirements.txt", package="jinja2",
        was="2.4.1", to="2.10.1", rebuild=rebuilt.append,
    )

    assert answer.verdict is bump.Verdict.ALREADY_RED
    assert rebuilt == [], "nothing may be rebuilt once the baseline is red"
    assert (checkout / "requirements.txt").read_text() == "jinja2==2.4.1\n", "not rewritten"
    assert "FAILED tests/test_a.py::test_one" in answer.detail


def test_a_clean_upgrade_says_exactly_what_it_measured(tmp_path: Path) -> None:
    """**The wording is asserted so it cannot drift.**

    DR-0016 fixes it: *the suite passed before this change and passes after it*. Never "safe", and
    never "fixes the vulnerability" — a suite that never exercised the library says so by staying
    green, and widening the claim here is the defect item 171 removed.
    """
    checkout = _checkout(tmp_path)
    box = FakeBox(checkout, _ok(), _ok())

    answer = bump.attempt(
        lambda: box, tests="pytest", source="requirements.txt", package="jinja2",
        was="2.4.1", to="2.10.1", rebuild=lambda text: None,
    )

    assert answer.verdict is bump.Verdict.CLEAN
    assert "passed before this change and passes after it" in answer.says
    assert "not that the upgrade is safe" in answer.says
    # **The tree is left as it was found, even on a clean verdict.** This measures; it does not
    # apply. Leaving the rewrite in place would make one candidate's result describe the next
    # one's baseline — which is what a real run did, reporting `already-red` about a suite that
    # had been green a minute earlier.
    assert (checkout / "requirements.txt").read_text() == "jinja2==2.4.1\n"


def test_a_clean_verdict_carries_the_file_the_passing_run_actually_saw(tmp_path: Path) -> None:
    """The seam between measuring an upgrade and opening one. Item 178.

    **These bytes exist for about two lines.** The tree is restored on the way out — the test above
    asserts that, and it has to stay true — so anything that wants to publish what passed has to be
    handed it before the restore. Working the diff out afterwards would mean running the resolver a
    second time, and a lock regenerated twice can differ: a version published in between, a
    different ordering, a registry that answered differently. Publishing files that are not the ones
    the suite passed against is the defect item 045 is named after.

    Verified by reintroducing the defect, and it is the worst kind: with these dropped, `upgrades`
    finds nothing eligible and `deps --open` opens nothing at all — silently, with every other test
    in both files still green.
    """
    checkout = _checkout(tmp_path)
    box = FakeBox(checkout, _ok(), _ok("248 passed in 30.44s"))

    answer = bump.attempt(
        lambda: box, tests="pytest", source="requirements.txt", package="jinja2",
        was="2.4.1", to="2.10.1", rebuild=lambda text: None,
    )

    assert answer.files == {"requirements.txt": b"jinja2==2.10.1\n"}, "the upgraded file, not the "
    # …and the tree it was read from is back to what it was, which is what makes the two facts
    # different rather than redundant.
    assert (checkout / "requirements.txt").read_text() == "jinja2==2.4.1\n"
    assert answer.runs is not None
    assert (answer.runs.before_exit, answer.runs.after_exit) == (0, 0)
    assert answer.runs.after_summary == "248 passed in 30.44s"
    assert answer.runs.command == "pytest"


def test_a_verdict_that_is_not_clean_carries_no_files_to_publish(tmp_path: Path) -> None:
    """Nothing that broke has a tree anybody should be offered. Item 178's rule, at the source."""
    checkout = _checkout(tmp_path)
    box = FakeBox(checkout, _ok(), _red())

    answer = bump.attempt(
        lambda: box, tests="pytest", source="requirements.txt", package="jinja2",
        was="2.4.1", to="2.10.1", rebuild=lambda text: None,
    )

    assert answer.verdict is bump.Verdict.BREAKS
    assert answer.files == {}
    # The runs are still carried: a reader of the report wants the exit codes either way.
    assert answer.runs is not None and answer.runs.after_exit == 1


def test_a_breaking_upgrade_names_the_tests_it_broke(tmp_path: Path) -> None:
    """The finding, and the reason anybody would install this."""
    checkout = _checkout(tmp_path)
    box = FakeBox(checkout, _ok(), _red("FAILED tests/test_render.py::test_escape\n1 failed"))

    answer = bump.attempt(
        lambda: box, tests="pytest", source="requirements.txt", package="jinja2",
        was="2.4.1", to="2.10.1", rebuild=lambda text: None,
    )

    assert answer.verdict is bump.Verdict.BREAKS
    assert "tests/test_render.py::test_escape" in answer.detail
    assert "breaks your suite" in answer.says


def test_a_build_that_fails_is_not_the_same_as_a_suite_that_fails(tmp_path: Path) -> None:
    """And the file is put back, so a refused upgrade leaves the checkout as it was found."""
    checkout = _checkout(tmp_path)
    box = FakeBox(checkout, _ok())

    answer = bump.attempt(
        lambda: box, tests="pytest", source="requirements.txt", package="jinja2",
        was="2.4.1", to="2.10.1",
        rebuild=lambda text: "no matching distribution found for jinja2==2.10.1",
    )

    assert answer.verdict is bump.Verdict.WILL_NOT_INSTALL
    assert "no matching distribution" in answer.detail
    assert (checkout / "requirements.txt").read_text() == "jinja2==2.4.1\n", "put back"


def test_the_rebuild_is_handed_the_rewritten_text(tmp_path: Path) -> None:
    """The caller builds the image, and it must build the file that will be tested.

    Reintroducing this defect — handing `rebuild` the original text — produced a green verdict for
    an upgrade that had never been installed, which is the worst answer this module could give.
    """
    checkout = _checkout(tmp_path)
    box = FakeBox(checkout, _ok(), _ok())
    seen: list[str] = []

    def rebuild(text: str) -> None:
        seen.append(text)

    bump.attempt(
        lambda: box, tests="pytest", source="requirements.txt", package="jinja2",
        was="2.4.1", to="2.10.1", rebuild=rebuild,
    )

    assert seen == ["jinja2==2.10.1\n"], "the build must see the upgrade, not the old pin"


def test_a_lock_file_is_refused_before_the_baseline_is_paid_for(tmp_path: Path) -> None:
    """No build, no suite run: a project whose only pins are locked is told at once."""
    box = FakeBox(tmp_path, _ok())

    with pytest.raises(bump.CannotRewriteError):
        bump.attempt(
            lambda: box, tests="pytest", source="Cargo.lock", package="jinja2",
            was="2.4.1", to="2.10.1", rebuild=lambda text: None,
        )

    assert box.commands == [], "nothing may run before the file is known to be rewritable"


def test_two_spellings_of_one_package_are_one_package() -> None:
    """PEP 503: `Jinja2`, `jinja_2` and `jinja.2` all name the same distribution.

    OSV answers with the canonical name, and a requirements file carries whichever spelling its
    author typed. Comparing raw strings refuses to rewrite a pin that is plainly there — which
    reads as "no such dependency" about a line the reader can see.
    """
    assert bump.rewrite_pin("Jinja2==2.4.1\n", "jinja2", "2.10.1") == "Jinja2==2.10.1\n"
    assert bump.rewrite_pin("ruamel_yaml==0.1\n", "ruamel-yaml", "0.2") == "ruamel_yaml==0.2\n"
    # And the spelling the project chose survives the rewrite: this edits a file a person owns.
    assert "Jinja2" in bump.rewrite_pin("Jinja2==2.4.1\n", "jinja2", "2.10.1")


# --- trying the candidates ------------------------------------------------------------------


class _Advisory:
    def __init__(self, *fixed: str) -> None:
        self.fixed = fixed


def test_the_candidates_are_every_published_fix_without_repeats() -> None:
    """Item 172's deferred question, answered by execution rather than by comparison.

    That item prints every fixed version and chooses none, because choosing means comparing
    versions under two ecosystems' rules. Here each is tried and the suite decides.
    """
    assert bump.candidates([_Advisory("2.11.3", "3.1.3"), _Advisory("2.11.3")]) == [
        "2.11.3",
        "3.1.3",
    ]


def test_it_stops_at_the_first_candidate_that_leaves_the_suite_green(tmp_path: Path) -> None:
    """**And does not keep going.**

    The remaining candidates are higher versions of the same fix, and upgrading further than the
    advisory asks for is taking a larger change than the problem requires.
    """
    tried: list[str] = []

    def make_box(version: str) -> bump.Box:
        # Called twice per candidate — once for the baseline, once for the rebuilt image — so each
        # box answers exactly one run, which is what a real box does.
        tried.append(version)
        _checkout(tmp_path)
        first = tried.count(version) == 1
        if first:
            return FakeBox(tmp_path, _ok())
        return FakeBox(tmp_path, _red("FAILED tests/test_x.py::test_y") if version == "2.11.3"
                       else _ok())

    report = bump.verify(
        tests="pytest", source="requirements.txt", package="jinja2", was="2.4.1",
        versions=["2.11.3", "3.1.3", "9.9.9"], make_box=make_box, rebuild=lambda text: None,
    )

    assert tried == ["2.11.3", "2.11.3", "3.1.3", "3.1.3"], "9.9.9 must never be attempted"
    assert report.settled is not None
    assert report.settled.to == "3.1.3"
    assert [a.verdict for a in report.answers] == [bump.Verdict.BREAKS, bump.Verdict.CLEAN]


def test_a_red_baseline_does_not_burn_through_every_candidate(tmp_path: Path) -> None:
    """The suite is broken, not the candidate. Asking it again gets the same answer.

    Reintroducing this ran a full build per published version against a suite that could never
    answer — on lodash's seven advisories that is seven builds to learn nothing.
    """
    tried: list[str] = []

    def make_box(version: str) -> bump.Box:
        tried.append(version)
        _checkout(tmp_path)
        return FakeBox(tmp_path, _red())

    report = bump.verify(
        tests="pytest", source="requirements.txt", package="jinja2", was="2.4.1",
        versions=["2.11.3", "3.1.3"], make_box=make_box, rebuild=lambda text: None,
    )

    assert tried == ["2.11.3"], "a red baseline is about the project, not the candidate"
    assert report.settled is None
    assert report.answers[0].verdict is bump.Verdict.ALREADY_RED


def test_nothing_clean_means_nothing_settled(tmp_path: Path) -> None:
    calls: list[str] = []

    def make_box(version: str) -> bump.Box:
        _checkout(tmp_path)
        calls.append(version)
        return FakeBox(tmp_path, _ok() if calls.count(version) == 1 else _red())

    report = bump.verify(
        tests="pytest", source="requirements.txt", package="jinja2", was="2.4.1",
        versions=["2.11.3", "3.1.3"], make_box=make_box, rebuild=lambda text: None,
    )

    assert report.settled is None
    assert len(report.answers) == 2, "every candidate is tried when none is clean"


def test_the_second_run_happens_in_a_box_the_rebuild_produced(tmp_path: Path) -> None:
    """**The defect a real Docker run found and nineteen unit tests did not.**

    `attempt` used to take a box rather than a factory, so the green gate ran in the container
    built *before* the upgrade: the suite of an upgraded project measured against the environment
    it replaced. It reported `clean` for `jinja2 3.0.3 → 3.1.6` against a suite importing
    `jinja2.Markup`, which 3.1 removed — a green verdict for a version that was never installed.

    A double has no image, which is exactly why nothing in this file could have noticed. What it
    *can* assert is the shape that made it possible: the factory is called again after the
    rebuild, and the second run happens somewhere else.
    """
    _checkout(tmp_path)
    handed: list[FakeBox] = []
    order: list[str] = []

    def make_box() -> bump.Box:
        box = FakeBox(tmp_path, _ok())
        handed.append(box)
        return box

    def rebuild(text: str) -> None:
        order.append("rebuild")

    bump.attempt(
        make_box, tests="pytest", source="requirements.txt", package="jinja2",
        was="2.4.1", to="2.10.1", rebuild=rebuild,
    )

    assert len(handed) == 2, "the box the baseline ran in cannot be the box the verdict runs in"
    assert handed[0] is not handed[1]
    assert [len(b.commands) for b in handed] == [1, 1], "one run each, in its own environment"


def test_no_second_box_is_built_when_the_rebuild_failed(tmp_path: Path) -> None:
    """There is nothing to run in: the image the verdict needs does not exist."""
    _checkout(tmp_path)
    handed: list[FakeBox] = []

    def make_box() -> bump.Box:
        box = FakeBox(tmp_path, _ok())
        handed.append(box)
        return box

    answer = bump.attempt(
        make_box, tests="pytest", source="requirements.txt", package="jinja2",
        was="2.4.1", to="2.10.1", rebuild=lambda _text: "no matching distribution",
    )

    assert answer.verdict is bump.Verdict.WILL_NOT_INSTALL
    assert len(handed) == 1


def test_a_broken_candidate_does_not_describe_the_next_one(tmp_path: Path) -> None:
    """**The second defect the real Docker run found.**

    A candidate that breaks the suite used to leave its own pin in the tree, so the next
    candidate's baseline ran against it and reported `already-red` — about a suite that had been
    green a minute before. One candidate must not be able to describe the next.
    """
    _checkout(tmp_path)
    seen: list[str] = []

    def make_box(version: str) -> bump.Box:
        seen.append((tmp_path / "requirements.txt").read_text())
        return FakeBox(tmp_path, _ok() if len(seen) % 2 else _red())

    bump.verify(
        tests="pytest", source="requirements.txt", package="jinja2", was="2.4.1",
        versions=["2.11.3", "3.1.3"], make_box=make_box, rebuild=lambda _t: None,
    )

    baselines = [text for i, text in enumerate(seen) if i % 2 == 0]
    assert all(t == "jinja2==2.4.1\n" for t in baselines), (
        f"every candidate must start from the original pin, saw {baselines}"
    )


# --- the ranked report. DR-0018 step 2. -------------------------------------------------------


def _report(package: str, *answers: bump.Answer) -> bump.Report:
    return bump.Report(package, "1.0.0", answers)


def _answer(verdict: bump.Verdict, detail: str = "") -> bump.Answer:
    return bump.Answer(verdict, "p", "1.0.0", "2.0.0", detail=detail)


def test_what_a_verdict_asks_of_a_person() -> None:
    """Ordered by what was established, not by a severity nobody here has read."""
    assert bump.needs_of(_report("a", _answer(bump.Verdict.ALREADY_RED))) is (
        bump.Needs.FIX_YOUR_SUITE
    )
    assert bump.needs_of(_report("b", _answer(bump.Verdict.CLEAN))) is bump.Needs.JUST_TAKE_IT
    assert bump.needs_of(_report("c", _answer(bump.Verdict.BREAKS, "FAILED x"))) is (
        bump.Needs.NEEDS_WORK
    )
    assert bump.needs_of(_report("d", _answer(bump.Verdict.CANNOT_MOVE))) is bump.Needs.BLOCKED


def test_a_candidate_that_broke_does_not_outrank_one_that_later_passed() -> None:
    """Trying three versions and settling on the third is `ready to take`, not `needs work`.

    Reintroducing this put every package that ever saw a red candidate into the section a person
    has to work — which on lodash's seven advisories is most of them, and all of them wrongly.
    """
    settled = _report(
        "lodash", _answer(bump.Verdict.BREAKS, "FAILED a"), _answer(bump.Verdict.CLEAN)
    )
    assert bump.needs_of(settled) is bump.Needs.JUST_TAKE_IT


def test_the_queue_is_ordered_worst_first_and_easiest_within_that() -> None:
    """**The answer to the complaint Renovate cannot answer.**

    *"Here is every update, you decide"* is noise because nothing in it is ranked, and ranking
    needs knowing what each one does. Within `needs work`, fewest broken tests first: the two-test
    upgrade is the one somebody closes this afternoon, and burying it under a twelve-test one
    hides the achievable behind the daunting.
    """
    reports = [
        _report("easy", _answer(bump.Verdict.BREAKS, "FAILED a\nFAILED b")),
        _report("clean", _answer(bump.Verdict.CLEAN)),
        _report("stuck", _answer(bump.Verdict.CANNOT_MOVE, "constrained")),
        _report("hard", _answer(bump.Verdict.BREAKS, "\n".join(f"FAILED {i}" for i in range(12)))),
        _report("red", _answer(bump.Verdict.ALREADY_RED)),
    ]

    assert [r.package for r in bump.ranked(reports)] == [
        "red",    # nothing else can be decided until this is fixed
        "easy",   # needs a person, and is the cheapest of those
        "hard",
        "stuck",  # nothing to try
        "clean",  # nothing to decide
    ]


def test_the_summary_is_the_sentence_that_replaces_the_queue() -> None:
    reports = [
        _report("a", _answer(bump.Verdict.CLEAN)),
        _report("b", _answer(bump.Verdict.CLEAN)),
        _report("c", _answer(bump.Verdict.BREAKS, "FAILED x")),
        _report("d", _answer(bump.Verdict.WILL_NOT_INSTALL)),
    ]

    counted = bump.summary(reports)

    assert counted[bump.Needs.JUST_TAKE_IT] == 2
    assert counted[bump.Needs.NEEDS_WORK] == 1
    assert counted[bump.Needs.BLOCKED] == 1
    assert counted[bump.Needs.FIX_YOUR_SUITE] == 0
    # Every bucket is present even at zero: a reader must be able to tell "none" from "not counted".
    assert set(counted) == set(bump.Needs)
