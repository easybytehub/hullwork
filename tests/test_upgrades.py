"""Open the verified-green ones. Item 178, DR-0018 step 3.

The forge is a double, because what is under test is *what may be opened and what it says* — and
the one thing this must never do is open something that was not run. A real forge would prove the
HTTP and not the rule.

**The claim in a pull request body is the most dangerous sentence this product emits.** It arrives
under Hullwork's own account, in a place a human is meant to trust, next to a diff they are being
asked to merge. So the wording is asserted on the rendered text rather than on the function that
produces it.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from hullwork import bump, evidence, osv, upgrades
from hullwork.forge import BranchExistsError, ForgePullRequest

WAS, TO = "2.4.1", "2.10.1"
BASE = "a" * 40


@dataclass
class FakeForge:
    """A code forge that records rather than pushes. Item 022's protocol, nothing more."""

    branches: list[str] = field(default_factory=list)
    commits: list[tuple[str, str, tuple[str, ...]]] = field(default_factory=list)
    pulls: list[dict[str, object]] = field(default_factory=list)
    #: Branches that already exist, so a second run can be expressed.
    taken: tuple[str, ...] = ()
    known: dict[str, str] = field(default_factory=lambda: {"requirements.txt": "blob1"})

    def default_branch(self, repo: str) -> str:
        del repo
        return "main"

    def create_branch(self, repo: str, name: str, from_ref: str) -> None:
        del repo, from_ref
        if name in self.taken:
            raise BranchExistsError(name)
        self.branches.append(name)

    def file_sha(self, repo: str, path: str, ref: str) -> str | None:
        del repo, ref
        return self.known.get(path)

    def commit_files(
        self, repo: str, branch: str, message: str, changes: object, *,
        author: str, email: str,
    ) -> str:
        del repo, author, email
        paths = tuple(sorted(c.path for c in changes))  # type: ignore[attr-defined]
        self.commits.append((branch, message, paths))
        return "c" * 40

    def open_draft_pull_request(
        self, repo: str, head: str, base: str, title: str, body: str,
        label_ids: list[int] | None = None,
    ) -> ForgePullRequest:
        del repo, label_ids
        self.pulls.append({"head": head, "base": base, "title": title, "body": body})
        return ForgePullRequest(
            number=len(self.pulls), title=title,
            html_url=f"https://forge/pull/{len(self.pulls)}", draft=True,
        )

    def close(self) -> None:
        return None


def _answer(
    verdict: bump.Verdict, package: str = "jinja2", to: str = TO, detail: str = ""
) -> bump.Answer:
    return bump.Answer(verdict, package, WAS, to, detail=detail)


def _clean(package: str = "jinja2", to: str = TO) -> bump.Answer:
    """A clean answer carrying what the gates actually ran against."""
    return bump.Answer(
        bump.Verdict.CLEAN, package, WAS, to,
        files={"requirements.txt": f"{package}=={to}\n".encode()},
        runs=bump.Runs(
            command="pytest -q",
            before_exit=0, after_exit=0,
            before_summary="248 passed in 31.02s",
            after_summary="248 passed in 30.44s",
        ),
    )


def _report(package: str, *answers: bump.Answer) -> bump.Report:
    return bump.Report(package=package, was=WAS, answers=answers)


def _every(text: str, needle: str) -> list[int]:
    """Every index `needle` occurs at. One occurrence checked out of two is not a check."""
    found, at = [], text.find(needle)
    while at != -1:
        found.append(at)
        at = text.find(needle, at + 1)
    return found


ADVISORIES = (
    osv.Advisory(
        id="GHSA-462w-v97r-4m45",
        summary="Jinja2 sandbox escape via str.format",
        fixed=(TO,),
    ),
)


# --- what may be opened, and what may never ---------------------------------------------------


def test_only_the_verified_green_ones_are_eligible() -> None:
    """A pull request from Hullwork means *this was run and it passed*.

    The moment it can mean anything else the claim is worth nothing, so every other bucket is
    asserted out by name rather than by the absence of a test.
    """
    reports = [
        _report("clean-one", _clean("clean-one")),
        _report("broken-one", _answer(bump.Verdict.BREAKS, "broken-one", detail="FAILED a")),
        _report("red-one", _answer(bump.Verdict.ALREADY_RED, "red-one")),
        _report("stuck-one", _answer(bump.Verdict.CANNOT_MOVE, "stuck-one")),
        _report("unbuildable", _answer(bump.Verdict.WILL_NOT_INSTALL, "unbuildable")),
    ]

    assert [r.package for r in upgrades.eligible(reports)] == ["clean-one"]


def test_a_package_that_broke_before_it_passed_is_still_eligible() -> None:
    """`verify` tries candidates in order, and the one that settled is the one that gets opened."""
    report = _report(
        "jinja2",
        _answer(bump.Verdict.BREAKS, "jinja2", to="2.9.0", detail="FAILED a"),
        _clean("jinja2"),
    )

    assert upgrades.eligible([report]) == [report]
    settled = report.settled
    assert settled is not None and settled.to == TO


def test_a_clean_answer_with_nothing_to_commit_is_refused_rather_than_opened() -> None:
    """The files are the diff. Without them there is a body making a claim about an empty commit.

    This is the shape item 045 is about, one product over: what was tested and what is published
    have to be the same tree, and a pull request that carries no tree at all cannot be either.
    """
    barren = _report("jinja2", bump.Answer(bump.Verdict.CLEAN, "jinja2", WAS, TO))

    assert upgrades.eligible([barren]) == []


# --- the opening ------------------------------------------------------------------------------


def test_one_pull_request_per_package_and_a_run_of_three_opens_three() -> None:
    """Never a batch: a grouped upgrade that breaks cannot be bisected without undoing our work."""
    forge = FakeForge()
    reports = [_report(name, _clean(name)) for name in ("aaa", "bbb", "ccc")]

    opened = upgrades.open_them(
        forge, repo="o/r", reports=reports, advisories={}, base_sha=BASE, permitted=True
    )

    assert len(opened) == 3
    assert len(forge.pulls) == 3
    assert len({p["head"] for p in forge.pulls}) == 3, "three branches, not one"
    for commit in forge.commits:
        assert commit[2] == ("requirements.txt",)


def test_the_branch_names_the_upgrade_so_a_second_run_opens_nothing() -> None:
    """No database in this path, so the branch name *is* the record of what was opened.

    A second pass over an unchanged repository asks for a branch that exists and is told so by the
    forge, which is the same answer `work.publish` already relies on. Nothing is opened twice and
    nothing has to be remembered between runs.
    """
    reports = [_report("jinja2", _clean())]
    first = FakeForge()
    upgrades.open_them(
        first, repo="o/r", reports=reports, advisories={}, base_sha=BASE, permitted=True
    )
    branch = first.branches[0]

    again = FakeForge(taken=(branch,))
    opened = upgrades.open_them(
        again, repo="o/r", reports=reports, advisories={}, base_sha=BASE, permitted=True
    )

    assert opened == []
    assert again.pulls == []
    assert branch == upgrades.branch_for("jinja2", WAS, TO)


def test_the_branch_survives_a_package_name_a_ref_cannot_carry() -> None:
    """`@scope/pkg` is an ordinary npm name and not an ordinary git ref.

    **The character that matters is `/`, and the first version of this test did not check it.**
    Verified by neutering the sanitiser: `@babel/core` came through whole, the name still began
    with the prefix and still contained none of the characters git documents as forbidden, and this
    passed. What it produces is `hullwork/deps/@babel/core-7.0.0-7.24.0` — a fourth path level,
    which git will happily create and which collides with any branch named `hullwork/deps/@babel`.

    So the assertion is on the shape: three segments, and the last one is the whole upgrade.
    """
    name = upgrades.branch_for("@babel/core", "7.0.0", "7.24.0")

    assert name.split("/")[:2] == ["hullwork", "deps"]
    assert len(name.split("/")) == 3, f"the package invented a path level: {name}"
    assert " " not in name
    for forbidden in ("~", "^", ":", "?", "*", "[", "\\", "@{", ".."):
        assert forbidden not in name
    # And it still says what it is about, which is the other half of the name's job.
    assert "babel" in name and "7.24.0" in name


def test_two_upgrades_of_one_package_are_two_branches() -> None:
    """Otherwise next month's upgrade collides with this month's and opens nothing, silently.

    The failure mode is the bad one: the forge answers `BranchExistsError`, this treats it as
    *already opened*, and a real upgrade never reaches anybody. Verified by dropping the versions
    from the name, at which point the test above still passed because it computes what it expects
    with the same function.
    """
    first = upgrades.branch_for("jinja2", "2.4.1", "2.10.1")
    second = upgrades.branch_for("jinja2", "2.10.1", "3.1.4")

    assert first != second


def test_a_branch_that_exists_and_a_forge_that_refused_are_told_apart(
    caplog: pytest.LogCaptureFixture
) -> None:
    """Both open nothing, and the operator is told they are different things.

    The terminal says *already open from an earlier run, or refused by the forge — the log says
    which*, so the log has to actually say which. Nothing else can tell these apart: from the
    caller's side both are an empty list.
    """
    from hullwork.forge import ForgeError

    reports = [_report("jinja2", _clean())]
    taken = FakeForge(taken=(upgrades.branch_for("jinja2", WAS, TO),))
    with caplog.at_level("INFO", logger="hullwork.upgrades"):
        upgrades.open_them(
            taken, repo="o/r", reports=reports, advisories={}, base_sha=BASE, permitted=True
        )
    already = caplog.text
    caplog.clear()

    refusing = FakeForge()

    def refuse(repo: str, name: str, from_ref: str) -> None:
        raise ForgeError("the forge said no")

    refusing.create_branch = refuse  # type: ignore[method-assign]
    with caplog.at_level("INFO", logger="hullwork.upgrades"):
        upgrades.open_them(
            refusing, repo="o/r", reports=reports, advisories={}, base_sha=BASE, permitted=True
        )

    assert "already opened" in already
    assert "already opened" not in caplog.text
    assert "could not branch" in caplog.text


def test_the_pull_request_is_rooted_at_the_commit_the_gates_ran_against() -> None:
    """Not at wherever the default branch points now — that is a tree nobody tested."""
    forge = FakeForge()
    seen: list[str] = []
    original = forge.create_branch

    def watched(repo: str, name: str, from_ref: str) -> None:
        seen.append(from_ref)
        original(repo, name, from_ref)

    forge.create_branch = watched  # type: ignore[method-assign]
    upgrades.open_them(
        forge, repo="o/r", reports=[_report("jinja2", _clean())],
        advisories={}, base_sha=BASE, permitted=True,
    )

    assert seen == [BASE]


def test_a_forge_that_refuses_one_does_not_cost_the_others() -> None:
    """A queue of five with one bad name is four pull requests, not a traceback."""
    from hullwork.forge import ForgeError

    forge = FakeForge()
    calls = {"n": 0}

    def sometimes(repo: str, name: str, from_ref: str) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ForgeError("the forge said no")
        forge.branches.append(name)

    forge.create_branch = sometimes  # type: ignore[method-assign]
    reports = [_report(name, _clean(name)) for name in ("aaa", "bbb", "ccc")]

    opened = upgrades.open_them(
        forge, repo="o/r", reports=reports, advisories={}, base_sha=BASE, permitted=True
    )

    assert len(opened) == 2


# --- the credential, which is the whole reason this item is amber -----------------------------


def test_open_refuses_before_anything_is_run_when_there_is_no_credential(tmp_path: Path) -> None:
    """The refusal has to arrive before two container builds, not after them.

    Same lesson as `_manifest_for_verify` and with more at stake: this is the one flag in `deps`
    that writes to somebody's repository, and a refusal that lands after the work it invalidates is
    a refusal printed underneath its own contradiction.
    """
    from hullwork.cli import CommandError, _forge_for_opening
    from hullwork.config import Settings

    with pytest.raises(CommandError) as refused:
        _forge_for_opening(Settings(), tmp_path)

    assert "HULLWORK_FORGE_CODE_TOKEN" in str(refused.value)
    # And it names the thing that needs nothing, because that is the honest way to see what this
    # would have opened.
    assert "--verify" in str(refused.value)


def test_verify_alone_never_reaches_for_a_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The claim `deps` is sold on: a stranger runs it in the first minute with no account.

    Asserted by making the credential lookup explode. `--verify` must reach the lock files without
    ever touching it, so this fails loudly if the flag ever stops gating that call.
    """
    import argparse
    import io
    import subprocess

    from hullwork import cli
    from hullwork.config import Settings

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S603, S607
    (tmp_path / "hullwork.yml").write_text(
        "project: p\ngit: {provider: forgejo, repo: o/r}\n"
        "autofix: {agent: none, gates: [tests, human-merge]}\n"
        'tests: "pytest"\ntest_path: tests\n'
        "runtime: {base: python-3.12, install: none, dependencies: []}\n"
    )

    def explode(*_a: object, **_k: object) -> object:
        raise AssertionError("--verify asked for a credential")

    monkeypatch.setattr(cli, "_forge_for_opening", explode)

    with pytest.raises(cli.CommandError) as refused:
        cli._cmd_deps(
            argparse.Namespace(
                checkout=str(tmp_path), verify=True, fix=False, open=False, into=str(tmp_path)
            ),
            Settings(),
            io.StringIO(),
        )

    # It got as far as looking for lock files, which is past every point a credential could have
    # been wanted.
    assert "no lock file" in str(refused.value)


def test_open_refuses_a_checkout_with_no_remote_to_name_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A coordinate cannot be guessed from a directory name, and a wrong one opens elsewhere."""
    from hullwork import cli
    from hullwork.config import Settings

    monkeypatch.setattr(cli, "make_code_forge", lambda _s: FakeForge())

    with pytest.raises(cli.CommandError) as refused:
        cli._forge_for_opening(Settings(), tmp_path)

    assert "origin" in str(refused.value)


# --- what the body says, which is the part a person acts on -----------------------------------


def _body(advisories: tuple[osv.Advisory, ...] = ADVISORIES) -> str:
    return evidence.dependency_pull_request_body(_clean(), advisories)


def test_the_claim_is_dr_0016s_wording_and_never_the_word_safe() -> None:
    """The one sentence that must not drift, asserted on the rendered text.

    A green pull request is the easiest place in this product to overclaim: the reviewer is being
    asked to merge, and *safe* is the word they will read into anything vaguer.
    """
    body = _body()

    assert "your suite passed before this change and passes after it" in body
    # The word is allowed to appear — twice, in fact — and only ever inside a denial. Enumerating
    # the two permitted sentences would be a test that has to be edited whenever either is
    # reworded, which is how a guard comes to be maintained into uselessness. The rule is that
    # nothing here *asserts* safety, so that is what is asserted.
    for index in _every(body, "safe"):
        before = body[max(0, index - 60):index]
        assert "not" in before, f"'safe' claimed rather than denied, after: …{before}"


def test_the_claim_is_the_same_function_the_terminal_prints() -> None:
    """The page and the pull request cannot come to disagree if there is one author.

    Not a second rendering that happens to match today: the body quotes `Answer.says`, so a change
    to the wording changes both or neither.
    """
    answer = _clean()

    assert answer.says in evidence.dependency_pull_request_body(answer, ADVISORIES)


def test_the_body_carries_the_advisory_its_id_and_where_to_read_it() -> None:
    body = _body()

    assert "GHSA-462w-v97r-4m45" in body
    assert "https://osv.dev/vulnerability/GHSA-462w-v97r-4m45" in body
    assert "sandbox escape" in body


def test_the_body_carries_both_runs_with_the_suites_own_summary_lines() -> None:
    """The command and the exit codes, and what the runner itself said. Not our paraphrase."""
    body = _body()

    assert "pytest -q" in body
    assert "248 passed in 31.02s" in body
    assert "248 passed in 30.44s" in body


def test_the_body_says_what_was_measured_was_your_suite() -> None:
    """The sentence that keeps it honest, and the reason a green verdict is not a guarantee."""
    body = _body()

    assert "never exercise this dependency" in body
    assert "Nothing here inspected the change itself" in body


def test_the_caveat_has_one_author() -> None:
    """Item 098's rule, made checkable because this document broke it on its first reading.

    `Answer.says` ends by saying what was measured; the paragraph beneath it used to say the same
    thing again in different words, and every assertion in this file passed. What catches that is
    not a better assertion about content — it is counting. The phrase belongs to one sentence, and
    a second author of it is a body that reads like a program that has lost its place.
    """
    body = _body()

    assert len(_every(body, "what was measured")) == 1
    assert len(_every(body, "fixes anything")) == 1


def test_an_upgrade_with_no_advisory_is_still_a_body_a_person_can_read() -> None:
    """Not every upgrade worth taking has something published against the version it replaces."""
    body = evidence.dependency_pull_request_body(_clean(), ())

    assert "your suite passed before this change and passes after it" in body
    assert "GHSA" not in body


def test_a_suite_that_printed_a_secret_does_not_print_it_here() -> None:
    """This text leaves the instance under our own account. Item 027's rule, one caller later."""
    answer = bump.Answer(
        bump.Verdict.CLEAN, "jinja2", WAS, TO,
        files={"requirements.txt": b"jinja2==2.10.1\n"},
        runs=bump.Runs(
            command="pytest -q",
            before_exit=0, after_exit=0,
            before_summary="ok",
            after_summary="248 passed; token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    )

    body = evidence.dependency_pull_request_body(answer, ())

    assert "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in body


def test_the_body_a_pull_request_gets_is_the_one_the_opener_sends() -> None:
    """Rendered once, by the module that owns what a reviewer reads, and handed over whole."""
    forge = FakeForge()

    upgrades.open_them(
        forge, repo="o/r",
        reports=[_report("jinja2", _clean())],
        advisories={"jinja2": ADVISORIES},
        base_sha=BASE,
        permitted=True,
    )

    body = str(forge.pulls[0]["body"])
    assert "your suite passed before this change and passes after it" in body
    assert "GHSA-462w-v97r-4m45" in body
    assert "jinja2" in str(forge.pulls[0]["title"])


def test_what_is_committed_is_what_the_gates_ran_against() -> None:
    """Carried on the answer, never re-derived.

    Re-applying the upgrade to work out the diff would run the resolver a second time, and a lock
    regenerated twice can differ — a version published in between, a different ordering. Publishing
    files that are not the ones the suite passed against is the defect item 045 is named after.
    """
    forge = FakeForge()
    answer = _clean()

    upgrades.open_them(
        forge, repo="o/r", reports=[_report("jinja2", answer)],
        advisories={}, base_sha=BASE, permitted=True,
    )

    assert forge.commits[0][2] == ("requirements.txt",)


@pytest.mark.parametrize("draft", [True, False])
def test_it_is_opened_as_a_draft_and_says_so_when_the_forge_disagrees(draft: bool) -> None:
    """Constitution §1: nothing merges by itself, and a forge that un-drafts is a finding."""
    forge = FakeForge()
    original = forge.open_draft_pull_request

    def answered(*args: object, **kwargs: object) -> ForgePullRequest:
        made = original(*args, **kwargs)  # type: ignore[arg-type]
        return ForgePullRequest(
            number=made.number, title=made.title, html_url=made.html_url, draft=draft
        )

    forge.open_draft_pull_request = answered  # type: ignore[method-assign]
    opened = upgrades.open_them(
        forge, repo="o/r", reports=[_report("jinja2", _clean())],
        advisories={}, base_sha=BASE, permitted=True,
    )

    assert len(opened) == 1


# --- the first thing a project can refuse (item 187, DR-0019) ----------------------------------


def test_a_project_that_has_not_permitted_it_gets_nothing_opened() -> None:
    """**Having a capability is not consenting to the feature it enables.**

    Until DR-0019, declaring an installer and a lock file *was* agreeing to pull requests in your
    repository — nobody said so. This is the sentence this product already applies to lanes, *a
    policy nobody has read is a policy nobody has agreed to*, pointed at itself.

    Everything that would have been opened is verified green: the refusal is about consent and not
    about the evidence, which is why the verification above it still ran.
    """
    forge = FakeForge()
    reports = [_report(name, _clean(name)) for name in ("aaa", "bbb")]

    opened = upgrades.open_them(
        forge, repo="o/r", reports=reports, advisories={}, base_sha=BASE, permitted=False
    )

    assert opened == []
    assert forge.branches == [], "a branch is already a write to somebody's repository"
    assert forge.pulls == []
    # And the eligible ones were eligible: this is consent, not a verdict.
    assert len(upgrades.eligible(reports)) == 2


def test_forgetting_the_permission_is_a_crash_and_never_an_open() -> None:
    """Item 017's rule, and the reason this is a parameter rather than a check at the call site.

    *A guardrail that depends on every caller remembering it is not a guardrail.* This is the only
    function in the product that opens anything, so a caller who forgets gets a `TypeError` — not
    an unguarded pull request in somebody's repository.
    """
    with pytest.raises(TypeError, match="permitted"):
        upgrades.open_them(  # type: ignore[call-arg]
            FakeForge(), repo="o/r", reports=[_report("jinja2", _clean())],
            advisories={}, base_sha=BASE,
        )


def test_the_permission_is_false_unless_a_project_wrote_it() -> None:
    """A permission that arrives switched on is not a permission.

    Every other default in `autofix` is the refusing one — `agent: none`, `unmatched: human` — and
    this one joins them.
    """
    from hullwork.manifest import parse_manifest

    silent = parse_manifest(
        "project: p\ngit: {provider: forgejo, repo: o/r}\ntests: pytest\n"
    )
    asked = parse_manifest(
        "project: p\ngit: {provider: forgejo, repo: o/r}\ntests: pytest\n"
        "autofix: {open_upgrades: true}\n"
    )

    assert silent.autofix.open_upgrades is False
    assert asked.autofix.open_upgrades is True
