"""A verdict the instance reached can become a pull request. Item 245, DR-0026's other half.

DR-0026 said *open stays a button somebody presses* and the button had nowhere to press: the
receiver that renders the page cannot hold a credential that pushes, and the artefact a clean
verification produced was thrown away on the way out of `verify_next`. So forty-one clean verdicts
sat on a page that told the reader, correctly, that nothing had been opened.

What is under test is **that the pull request contains what was verified** — the files the suite
passed with and the commit it ran at — and that the two-process boundary is not quietly crossed to
achieve it. The forge is a double: a real one would prove the HTTP and not the rule.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from hullwork import bump, cli, evidence, page, upgrades
from hullwork.forge import BranchExistsError, ForgeError, ForgePullRequest
from hullwork.models import DependencyReport, Project, UpgradeVerdict

WAS, TO = "48.0.1", "49.0.0"
BASE = "b" * 40
LOCK = "backend/uv.lock"


@dataclass
class FakeForge:
    """A code forge that records rather than pushes."""

    branches: list[str] = field(default_factory=list)
    commits: list[tuple[str, str, tuple[str, ...]]] = field(default_factory=list)
    pulls: list[dict[str, object]] = field(default_factory=list)
    taken: tuple[str, ...] = ()
    rooted_at: list[str] = field(default_factory=list)
    refuse: bool = False

    def default_branch(self, repo: str) -> str:
        del repo
        return "main"

    def create_branch(self, repo: str, name: str, from_ref: str) -> None:
        del repo
        if name in self.taken:
            raise BranchExistsError(name)
        if self.refuse:
            raise ForgeError("the forge said no")
        self.rooted_at.append(from_ref)
        self.branches.append(name)

    def file_sha(self, repo: str, path: str, ref: str) -> str | None:
        del repo, path, ref
        return None

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


def _clean(files: dict[str, bytes] | None = None) -> bump.Answer:
    """A clean answer carrying what the gates ran against."""
    return bump.Answer(
        bump.Verdict.CLEAN, "cryptography", WAS, TO,
        detail="646 passed",
        files={LOCK: b'name = "cryptography"\nversion = "49.0.0"\n'} if files is None else files,
        runs=bump.Runs(
            command="pytest -q",
            before_exit=0, after_exit=0,
            before_summary="646 passed in 49.9s",
            after_summary="646 passed in 48.9s",
        ),
    )


def _project(session: Session, *, permitted: bool = True, slug: str = "acme") -> Project:
    project = Project(
        slug=slug, forge="forgejo", repo=f"acme/{slug}",
        webhook_secret_hash="x" * 64,
        manifest={
            "project": slug,
            "git": {"provider": "forgejo", "repo": f"acme/{slug}"},
            "errors": {"provider": "glitchtip"},
            "runtime": {
                "base": "python:3.12",
                "install": "pip install -r requirements.txt",
                "dependencies": ["requirements.txt"],
            },
            "tests": "pytest",
            "autofix": {"open_upgrades": permitted},
        },
        active=True,
    )
    session.add(project)
    session.commit()
    return project


def _pinned(session: Session, project: Project, *, package: str = "cryptography") -> None:
    session.merge(
        DependencyReport(
            project_id=project.id, taken_at=datetime.now(UTC), asked=True, pinned=1051,
            findings=[
                {
                    "package": package, "version": WAS, "source": LOCK,
                    "advisories": [
                        {"id": "GHSA-g6cj-pr64-35w5", "summary": "a Bleichenbacher oracle",
                         "fixed": [TO]},
                    ],
                }
            ],
        )
    )
    session.commit()


def _verdict(session: Session, project: Project, **kept: object) -> UpgradeVerdict:
    verdict = UpgradeVerdict(
        project_id=project.id, package="cryptography", was=WAS, to=TO,
        outcome="clean", detail="646 passed",
        artefact=upgrades.keepable(_clean()), base_sha=BASE,
        **kept,
    )
    session.add(verdict)
    session.commit()
    return verdict


class TestWhatAVerificationKeeps:
    """The artefact, without which the button can only re-run the resolver."""

    @pytest.mark.parametrize(
        "verdict",
        [bump.Verdict.BREAKS, bump.Verdict.WILL_NOT_INSTALL, bump.Verdict.ALREADY_RED],
    )
    def test_only_a_clean_verdict_keeps_anything(self, verdict: bump.Verdict) -> None:
        answer = bump.Answer(verdict, "cryptography", WAS, TO, files={LOCK: b"x"})
        assert upgrades.keepable(answer) is None

    def test_a_clean_verdict_keeps_the_files_and_the_runs(self) -> None:
        kept = upgrades.keepable(_clean())
        assert kept is not None
        assert kept["files"] == {LOCK: 'name = "cryptography"\nversion = "49.0.0"\n'}
        # **The runs are the evidence the artefact is for.** Keeping the files alone would open a
        # pull request quietly thinner than the terminal's, which nobody would ever notice.
        assert kept["runs"] == {
            "command": "pytest -q", "before_exit": 0, "after_exit": 0,
            "before_summary": "646 passed in 49.9s", "after_summary": "646 passed in 48.9s",
        }

    def test_a_file_that_is_not_text_keeps_nothing_rather_than_part(self) -> None:
        answer = _clean(files={LOCK: b"ok", "vendor/blob": b"\xff\xfe\x00"})
        assert upgrades.keepable(answer) is None

    def test_the_answer_comes_back_whole(self, session: Session) -> None:
        project = _project(session)
        rebuilt = upgrades.answer_from(_verdict(session, project))
        assert rebuilt is not None
        assert rebuilt.files == {LOCK: b'name = "cryptography"\nversion = "49.0.0"\n'}
        assert rebuilt.runs is not None
        assert rebuilt.runs.after_summary == "646 passed in 48.9s"

    def test_the_body_a_reviewer_reads_is_the_same_one(self, session: Session) -> None:
        """The point of keeping the runs, asserted where it is visible. Item 245.

        A pull request opened from a stored verdict must not be thinner than the one the terminal
        opens from a live one. Rendering both from the same function is what makes that true, so
        this compares the rendered text rather than the fields.
        """
        project = _project(session)
        rebuilt = upgrades.answer_from(_verdict(session, project))
        assert rebuilt is not None
        live = evidence.dependency_pull_request_body(_clean())
        stored = evidence.dependency_pull_request_body(rebuilt)
        assert stored == live
        assert "646 passed in 48.9s" in stored

    def test_a_verdict_with_no_artefact_is_not_an_answer(self, session: Session) -> None:
        project = _project(session)
        bare = UpgradeVerdict(
            project_id=project.id, package="cryptography", was=WAS, to=TO, outcome="clean"
        )
        session.add(bare)
        session.commit()
        assert upgrades.answer_from(bare) is None

    def test_an_artefact_with_no_files_is_not_an_answer(self, session: Session) -> None:
        project = _project(session)
        empty = UpgradeVerdict(
            project_id=project.id, package="cryptography", was=WAS, to=TO, outcome="clean",
            artefact={"files": {}, "runs": None},
        )
        session.add(empty)
        session.commit()
        # Reaching `_open_one` with no files would branch, commit nothing, and open a pull request
        # claiming an upgrade it does not contain.
        assert upgrades.answer_from(empty) is None


class TestAskingForIt:
    """The button, which opens nothing by itself."""

    def test_asking_records_the_request_and_says_it_is_not_open_yet(
        self, session: Session
    ) -> None:
        project = _project(session)
        verdict = _verdict(session, project)
        said = cli.ask_to_open(session, project.slug, verdict.id)
        assert verdict.asked_to_open_at is not None
        assert verdict.opened_where is None
        assert "No pull request exists yet" in said

    def test_asking_twice_does_not_move_the_request(self, session: Session) -> None:
        project = _project(session)
        verdict = _verdict(session, project)
        cli.ask_to_open(session, project.slug, verdict.id)
        first = verdict.asked_to_open_at
        said = cli.ask_to_open(session, project.slug, verdict.id)
        assert verdict.asked_to_open_at == first
        assert "already asked for" in said

    def test_a_verdict_that_did_not_pass_cannot_be_asked_for(self, session: Session) -> None:
        project = _project(session)
        broke = UpgradeVerdict(
            project_id=project.id, package="cryptography", was=WAS, to=TO, outcome="breaks",
            artefact=upgrades.keepable(_clean()),
        )
        session.add(broke)
        session.commit()
        with pytest.raises(ValueError, match="nothing to open"):
            cli.ask_to_open(session, project.slug, broke.id)

    def test_a_verdict_whose_files_were_forgotten_cannot_be_asked_for(
        self, session: Session
    ) -> None:
        project = _project(session)
        verdict = _verdict(session, project)
        verdict.artefact = None
        session.commit()
        with pytest.raises(ValueError, match="not kept any more"):
            cli.ask_to_open(session, project.slug, verdict.id)

    def test_a_verdict_belonging_to_another_project_is_not_found(self, session: Session) -> None:
        mine = _project(session, slug="mine")
        theirs = _project(session, slug="theirs")
        verdict = _verdict(session, theirs)
        with pytest.raises(ValueError, match="no verdict"):
            cli.ask_to_open(session, mine.slug, verdict.id)

    def test_one_already_open_is_not_asked_for_again(self, session: Session) -> None:
        project = _project(session)
        verdict = _verdict(session, project, opened_where="https://forge/pull/1")
        with pytest.raises(ValueError, match="already open"):
            cli.ask_to_open(session, project.slug, verdict.id)


class TestOpeningWhatWasAsked:
    """The dispatcher's half: the credential is here and the decision was not."""

    def test_it_opens_what_was_verified_at_the_commit_it_was_verified_at(
        self, session: Session
    ) -> None:
        project = _project(session)
        _pinned(session, project)
        verdict = _verdict(session, project, asked_to_open_at=datetime.now(UTC))
        forge = FakeForge()

        said = upgrades.open_requested(session, forge)

        assert said is not None and "https://forge/pull/1" in said
        assert verdict.opened_where == "https://forge/pull/1"
        # **Rooted at the sha the suite ran against**, never at the forge's idea of `main`.
        assert forge.rooted_at == [BASE]
        assert forge.commits[0][2] == (LOCK,)
        assert "GHSA-g6cj-pr64-35w5" in str(forge.pulls[0]["body"])
        # The pull request holds those files now, so a second copy in the database is cost.
        assert verdict.artefact is None

    def test_the_emptied_artefact_is_empty_to_sql_as_well(self, session: Session) -> None:
        """**Found by measuring the live instance one minute after the first pull request.**

        A plain `JSON` column writes the text `null` for `None`: the storage is released and Python
        reads `None`, but `WHERE artefact IS NOT NULL` still counts the row — which is how a check
        reported two artefacts against a database holding one. `forget_stale` filters on that
        predicate, so the column has to answer it honestly.
        """
        project = _project(session)
        _pinned(session, project)
        verdict = _verdict(session, project, asked_to_open_at=datetime.now(UTC))

        upgrades.open_requested(session, FakeForge())

        assert verdict.opened_where is not None
        counted = (
            session.query(UpgradeVerdict)
            .filter(UpgradeVerdict.artefact.is_not(None))
            .count()
        )
        assert counted == 0

    def test_nothing_asked_for_does_nothing(self, session: Session) -> None:
        project = _project(session)
        _pinned(session, project)
        _verdict(session, project)
        forge = FakeForge()
        assert upgrades.open_requested(session, forge) is None
        assert forge.branches == []

    def test_no_credential_leaves_the_request_standing(self, session: Session) -> None:
        project = _project(session)
        _pinned(session, project)
        verdict = _verdict(session, project, asked_to_open_at=datetime.now(UTC))
        assert upgrades.open_requested(session, None) is None
        # Spending somebody's request on a misconfigured afternoon would make them press a button
        # that can never work twice.
        assert verdict.open_note is None
        assert verdict.asked_to_open_at is not None

    def test_a_project_that_has_not_permitted_it_refuses_and_says_so(
        self, session: Session
    ) -> None:
        project = _project(session, permitted=False)
        _pinned(session, project)
        verdict = _verdict(session, project, asked_to_open_at=datetime.now(UTC))
        forge = FakeForge()
        said = upgrades.open_requested(session, forge)
        assert said is not None and "has not permitted" in said
        assert forge.branches == []
        assert verdict.open_note is not None and "open_upgrades" in verdict.open_note

    def test_a_version_no_longer_pinned_is_not_opened(self, session: Session) -> None:
        project = _project(session)
        _pinned(session, project, package="something-else")
        verdict = _verdict(session, project, asked_to_open_at=datetime.now(UTC))
        forge = FakeForge()
        said = upgrades.open_requested(session, forge)
        assert said is not None and "not what this project pins" in said
        assert forge.branches == []
        assert verdict.opened_where is None

    def test_a_branch_that_already_exists_is_reported_rather_than_silent(
        self, session: Session
    ) -> None:
        project = _project(session)
        _pinned(session, project)
        verdict = _verdict(session, project, asked_to_open_at=datetime.now(UTC))
        forge = FakeForge(taken=(upgrades.branch_for("cryptography", WAS, TO),))
        said = upgrades.open_requested(session, forge)
        assert said is not None and "already open from an earlier run" in said
        assert verdict.open_note is not None

    def test_one_per_turn(self, session: Session) -> None:
        project = _project(session)
        _pinned(session, project)
        first = _verdict(session, project, asked_to_open_at=datetime.now(UTC))
        second = UpgradeVerdict(
            project_id=project.id, package="cryptography", was=WAS, to="50.0.0",
            outcome="clean", artefact=upgrades.keepable(_clean()), base_sha=BASE,
            asked_to_open_at=datetime.now(UTC),
        )
        session.add(second)
        session.commit()
        upgrades.open_requested(session, FakeForge())
        assert first.opened_where is not None
        assert second.opened_where is None


class TestForgettingWhatWentStale:
    """An artefact about a version nobody pins any more."""

    def test_a_version_no_longer_pinned_loses_its_artefact_and_its_request(
        self, session: Session
    ) -> None:
        project = _project(session)
        verdict = _verdict(session, project, asked_to_open_at=datetime.now(UTC))
        forgotten = upgrades.forget_stale(
            session, project.id, [{"package": "cryptography", "version": "50.0.0"}]
        )
        assert forgotten == 1
        assert verdict.artefact is None
        # *Never asked* is the honest state: nobody asked for a pull request against a version this
        # project stopped pinning.
        assert verdict.asked_to_open_at is None

    def test_one_still_pinned_is_left_alone(self, session: Session) -> None:
        project = _project(session)
        verdict = _verdict(session, project, asked_to_open_at=datetime.now(UTC))
        assert upgrades.forget_stale(
            session, project.id, [{"package": "cryptography", "version": WAS}]
        ) == 0
        assert verdict.artefact is not None
        assert verdict.asked_to_open_at is not None

    def test_another_project_is_not_touched(self, session: Session) -> None:
        mine = _project(session, slug="mine")
        theirs = _project(session, slug="theirs")
        ours = _verdict(session, mine)
        yours = _verdict(session, theirs)
        upgrades.forget_stale(session, mine.id, [])
        assert ours.artefact is None
        assert yours.artefact is not None


class TestWhatThePageOffers:
    """The control, and the three states of a row."""

    def test_a_clean_verdict_offers_the_control(self, session: Session) -> None:
        project = _project(session)
        _pinned(session, project)
        _verdict(session, project)
        shown = page.what_is_published_against_it(
            session, project, acting=page.Acting(csrf="t0ken")
        )
        assert 'value="open-upgrade"' in shown
        assert "Ready to open" in shown

    def test_a_reader_who_cannot_act_is_not_offered_it(self, session: Session) -> None:
        project = _project(session)
        _pinned(session, project)
        _verdict(session, project)
        shown = page.what_is_published_against_it(session, project)
        assert "open-upgrade" not in shown
        assert "Signing in is what offers the control" in shown

    def test_a_project_that_has_not_permitted_it_reads_as_a_decision(
        self, session: Session
    ) -> None:
        project = _project(session, permitted=False)
        _pinned(session, project)
        _verdict(session, project)
        shown = page.what_is_published_against_it(
            session, project, acting=page.Acting(csrf="t0ken")
        )
        assert "open-upgrade" not in shown
        # The count in front of the refusal, which is what makes it a decision rather than a part
        # that is missing.
        assert "1 passed your suite" in shown
        assert "open_upgrades: true" in shown

    def test_one_that_was_asked_for_says_which_process_will_do_it(self, session: Session) -> None:
        project = _project(session)
        _pinned(session, project)
        _verdict(session, project, asked_to_open_at=datetime.now(UTC))
        shown = page.what_is_published_against_it(
            session, project, acting=page.Acting(csrf="t0ken")
        )
        assert "the dispatcher opens it on its next turn" in shown
        assert 'value="open-upgrade"' not in shown

    def test_one_that_is_open_is_a_link_and_not_a_button(self, session: Session) -> None:
        project = _project(session)
        _pinned(session, project)
        _verdict(
            session, project,
            asked_to_open_at=datetime.now(UTC), opened_where="https://forge/pull/7",
        )
        shown = page.what_is_published_against_it(
            session, project, acting=page.Acting(csrf="t0ken")
        )
        assert 'href="https://forge/pull/7"' in shown
        assert 'value="open-upgrade"' not in shown

    def test_a_verdict_with_nothing_kept_is_not_offered(self, session: Session) -> None:
        """**Found by deploying it**: 41 clean verdicts on the live instance, 0 with an artefact,
        because every one of them was measured before this was kept. Offering the control on those
        would be a button whose write path answers *the files were not kept*."""
        project = _project(session)
        _pinned(session, project)
        before = _verdict(session, project)
        before.artefact = None
        session.commit()
        shown = page.what_is_published_against_it(
            session, project, acting=page.Acting(csrf="t0ken")
        )
        assert 'value="open-upgrade"' not in shown
        assert "Verified before this instance kept the files" in shown
        # And it is not counted as openable either: a number nobody can act on is the same lie.
        assert "Ready to open" not in shown

    def test_a_refusal_is_shown_in_the_row_that_carries_it(self, session: Session) -> None:
        project = _project(session)
        _pinned(session, project)
        _verdict(
            session, project,
            asked_to_open_at=datetime.now(UTC), open_note="the forge refused it",
        )
        shown = page.what_is_published_against_it(
            session, project, acting=page.Acting(csrf="t0ken")
        )
        # **The one sentence a row still says in prose** (DR-0028): each refusal differs, so it
        # cannot move to a heading the way every other state's explanation did.
        assert "Asked for, and not opened" in shown
        assert "the forge refused it" in shown

    def test_the_footer_no_longer_claims_nothing_can_be_opened(self, session: Session) -> None:
        project = _project(session)
        _pinned(session, project)
        _verdict(session, project)
        shown = page.what_is_published_against_it(session, project)
        assert "it does not propose one" not in shown
        assert "never opens one by itself" in shown
