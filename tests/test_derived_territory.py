"""Lanes a project does not have to write. M8, item 104.

The sequel to `test_territory.py`, which covers territory a project **declares** (item 071, DR-0008
part 2). This covers territory the **instance derives**, which is the half that makes a project
declaring nothing fully configured — DR-0008's own unfinished sentence: *"a project that names none
is
fully configured, which today it is not."*

Two properties, pulling in opposite directions on purpose.

**A project that declares nothing gets an opinion.** Before this, an empty `autofix.lanes` meant
every
error fell through to *"no lane rule matched; defaulting to red"*, and the only escape — `unmatched:
attempt` — made **everything** dispatchable, schema migrations included.

**And the opinion is the instance's, so it out-ranks a green catalogue.** A `TypeError` in
`alembic/versions/` is not admitted by `green: [typeerror]`, because DR-0008's finding is that an
exception-type catalogue predicts which bugs you will have and the code location does not have to. A
project that disagrees says so in `autofix.lanes.ordinary`: territory answered with territory.

What this file does not claim: that the derived policy makes anything safe. The gates protect a
merge;
a lane decides how often that chain is exercised.

Every test here was verified by reintroducing the defect it covers.
"""

from __future__ import annotations

import pytest

from hullwork import territory
from hullwork.manifest import Manifest, ManifestError, parse_manifest
from hullwork.models import Lane
from hullwork.triage import decide

#: A manifest that declares **nothing** about lanes, and opts into attempting what nothing protects.
#:
#: `unmatched: attempt` is here because DR-0008 part 3 is an operator decision this milestone does
#: not
#: get to revisit: the *instance* default stays red-by-default and a project opts in. So the plan's
#: M8 gate — "an error in an ordinary module lands green on an empty manifest" — is read as holding
#: for a project that opted in, and the derived policy is what makes opting in defensible. Before
#: it,
#: `unmatched: attempt` put an agent one step from `alembic/versions/` with only `ALWAYS_RED`
#: between.
OPTED_IN = """
project: p
git: {provider: forgejo, repo: o/r}
autofix:
  unmatched: attempt
"""

#: The same, plus a green catalogue of the kind DR-0008 measured as a poor predictor.
WITH_CATALOGUE = """
project: p
git: {provider: forgejo, repo: o/r}
autofix:
  unmatched: attempt
  lanes:
    green: [typeerror, valueerror]
"""


def _manifest(text: str) -> Manifest:
    return parse_manifest(text)


# --- the gate ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/app/src/myapp/migrations/0003_add_column.py",
        "/app/alembic/versions/b8e3c07d5f14_does_the_fix_hold.py",
        "/srv/app/db/migrate/20260730_backfill.rb",
        "/app/.github/workflows/deploy.yml",
        "/app/Dockerfile",
        "/app/terraform/production/main.tf",
        "/app/conftest.py",
        "/app/pyproject.toml",
        "/app/package-lock.json",
        "/app/LICENSE",
        "/app/CODEOWNERS",
    ],
)
def test_an_error_in_sensitive_code_is_born_red_on_a_manifest_that_declares_nothing(
    path: str,
) -> None:
    """M8's gate, positively. The manifest says nothing and the instance still knows."""
    verdict = decide(_manifest(OPTED_IN), title="TypeError: boom", culprit="mod.fn", paths=[path])

    assert verdict.lane is Lane.RED
    # Not the old sentence. "no lane rule matched" sends an operator off to write a rule, which is
    # exactly the work this milestone exists to remove.
    assert "no lane rule matched" not in verdict.reason
    assert path in verdict.reason


def test_an_error_in_ordinary_code_is_born_dispatchable_on_the_same_manifest() -> None:
    """The other half: a policy that classes everything as sensitive is a policy that does
    nothing."""
    verdict = decide(
        _manifest(OPTED_IN),
        title="TypeError: boom",
        culprit="myapp.services.report.render",
        paths=["/app/src/myapp/services/report.py"],
    )

    assert verdict.lane is Lane.GREEN


def test_the_reason_names_the_rule_and_says_it_is_the_instance_s_to_override() -> None:
    """A reason an operator can act on: which file, why, and what they can do about it.

    Distinct from the reserved wording on purpose. *Reserved* means no manifest reaches it;
    *derived*
    means the instance decided and `autofix.lanes.ordinary` can say otherwise. Hiding which kind it
    was leaves an operator unable to tell a policy from a law.
    """
    verdict = decide(
        _manifest(OPTED_IN),
        title="OperationalError: no such column",
        culprit=None,
        paths=["/app/alembic/versions/f7c2d94ab153_the_item_carries.py"],
    )

    assert "irreversible against real data" in verdict.reason
    assert "autofix.lanes.ordinary" in verdict.reason
    assert "reserved subject" not in verdict.reason


def test_a_green_catalogue_does_not_admit_an_error_in_sensitive_code() -> None:
    """The ordering that makes this worth having. DR-0008's finding, enforced.

    `green: [typeerror]` is what a competent engineer writes when asked which exceptions matter, and
    the exception type says nothing about how dangerous a fix would be — *"a `TypeError` in a log
    formatter and a `TypeError` in a price calculation are the same string"*. So the derived policy
    is consulted before the green lane, not after it.
    """
    verdict = decide(
        _manifest(WITH_CATALOGUE),
        title="TypeError: unsupported operand",
        culprit="myapp.db.migrate",
        paths=["/app/src/myapp/migrations/0007_split_table.py"],
    )

    assert verdict.lane is Lane.RED
    assert "migrations" in verdict.reason


# --- the gate, negatively ---------------------------------------------------------------------


def test_a_path_in_the_error_message_does_not_move_the_lane() -> None:
    """DR-0008 gate 4, preserved for free rather than by remembering to.

    The exception *message* carries user input: an anonymous user of the watched application types
    whatever they like into a form field. The derived policy reads `paths`, and a stranger cannot
    write a frame path — so the asymmetry is a property of what the policy looks at, not a branch
    somebody has to maintain.
    """
    verdict = decide(
        _manifest(OPTED_IN),
        title="ValueError: could not parse migrations/versions/0001_initial.py",
        culprit="myapp.services.upload.parse",
        paths=["/app/src/myapp/services/upload.py"],
    )

    assert verdict.lane is Lane.GREEN


def test_an_override_makes_a_derived_rule_ordinary() -> None:
    """The escape hatch, and the reason the lane reason names it.

    A project whose `migrations/` directory holds documentation is not wrong; the policy is, about
    that project.
    """
    override = """
project: p
git: {provider: forgejo, repo: o/r}
autofix:
  unmatched: attempt
  lanes:
    ordinary: [migrations]
"""
    verdict = decide(
        _manifest(override),
        title="TypeError: boom",
        culprit="docs.build",
        paths=["/app/docs/migrations/notes.py"],
    )

    assert verdict.lane is Lane.GREEN


def test_a_reserved_path_wins_over_an_override_that_would_have_freed_it() -> None:
    """`ALWAYS_RED` is checked before the derived policy, so an override cannot reach it.

    Asserted from both ends: the parse-time refusal is the message an operator gets for naming a
    reserved *word*, and this is the behaviour for a reserved *path* that an accepted override would
    otherwise have covered.
    """
    with pytest.raises(ManifestError, match="cannot be promoted out of the red lane"):
        _manifest("""
project: p
git: {provider: forgejo, repo: o/r}
autofix:
  lanes:
    ordinary: [auth]
""")

    override = """
project: p
git: {provider: forgejo, repo: o/r}
autofix:
  unmatched: attempt
  lanes:
    ordinary: [migrations]
"""
    verdict = decide(
        _manifest(override),
        title="KeyError: missing key",
        culprit=None,
        paths=["/app/src/myapp/auth/migrations/0001_initial.py"],
    )

    assert verdict.lane is Lane.RED
    assert "reserved subject" in verdict.reason


def test_a_project_that_has_not_opted_in_still_lands_red_for_ordinary_code() -> None:
    """M8 does not flip the instance default, and that is DR-0008 part 3 rather than an oversight.

    The operator reversed the proposal on 2026-07-29 — invert it, but **opt-in per project** —
    because opt-out means a project inherits the risky answer by being forgotten. So a project that
    has not opted in gets red for ordinary code too, with the old sentence, and nothing in this
    milestone changes that. Where the plan's M8 gate reads otherwise, the later operator decision
    wins.
    """
    not_opted_in = """
project: p
git: {provider: forgejo, repo: o/r}
"""
    verdict = decide(
        _manifest(not_opted_in),
        title="TypeError: boom",
        culprit="myapp.services.report.render",
        paths=["/app/src/myapp/services/report.py"],
    )

    assert verdict.lane is Lane.RED
    assert "no lane rule matched" in verdict.reason


# --- the policy itself ------------------------------------------------------------------------


def test_a_dependency_s_own_files_are_not_this_project_s_territory() -> None:
    """A traceback through `site-packages` is a frame in somebody else's library.

    Classing a `pyproject.toml` inside a dependency as this project's packaging would send every
    error passing through an installed package's machinery to a human, on the strength of a filename
    that is not theirs.
    """
    assert territory.sensitivity("/usr/lib/python3.12/site-packages/pip/pyproject.toml") is None
    assert territory.sensitivity("/app/node_modules/left-pad/package.json") is None
    assert territory.sensitivity("/app/.venv/lib/python3.12/site-packages/x/conftest.py") is None
    # And the project's own copy of the same filename is claimed.
    assert territory.sensitivity("/app/pyproject.toml") is not None


def test_where_the_application_lives_is_not_sensitive() -> None:
    """The policy has to stay narrow enough that an operator keeps it.

    A policy classing `models/`, `services/` and `api/` as dangerous is a policy that attempts
    nothing, dressed as caution — and one an operator overrides wholesale, which is worse than a
    narrow one they keep.
    """
    for path in (
        "/app/src/myapp/models/order.py",
        "/app/src/myapp/services/pricing.py",
        "/app/src/myapp/api/routes.py",
        "/app/src/myapp/core/engine.py",
        "/app/tests/test_pricing.py",
    ):
        assert territory.sensitivity(path) is None, path


def test_the_first_sensitive_frame_is_the_one_reported() -> None:
    """Ordered by the frames as given, not by which rule is worst.

    The reason names where the error happened, and an operator matching that sentence against a
    stack trace needs the frame the tracker showed them.
    """
    found = territory.first_sensitive(
        [
            "/app/src/myapp/services/report.py",
            "/app/src/myapp/migrations/0003.py",
            "/app/Dockerfile",
        ]
    )

    assert found is not None
    path, rule = found
    assert path.endswith("migrations/0003.py")
    assert rule.pattern == "migrations"


def test_a_payload_that_is_not_a_list_of_strings_is_not_a_crash() -> None:
    """`paths` reaches this from a tracker payload, which is a shape somebody else controls."""
    assert territory.first_sensitive(None) is None
    assert territory.first_sensitive("migrations/x.py") is None
    assert territory.first_sensitive([None, 3, {"path": "x"}]) is None
    assert territory.first_sensitive([None, "/app/Dockerfile"]) is not None


def test_the_tree_listing_is_sorted_and_deduplicated() -> None:
    """What `hullwork projects lanes` prints. Never consulted to decide a lane — see the module."""
    claimed = territory.sensitive_tree(
        ["pyproject.toml", "pyproject.toml", "src/app.py", "migrations/0001.py"]
    )

    assert [path for path, _ in claimed] == ["migrations/0001.py", "pyproject.toml"]
    assert territory.sensitive_tree("not a list") == []


def test_every_rule_explains_itself() -> None:
    """A reason of the form *a wrong automated fix here is not a bug*, or it does not belong.

    Mechanical, and it guards the next person to add a rule: a `why` that is a category rather than
    a
    sentence produces a lane reason nobody can act on, and the only place that gets noticed is in
    front of an operator.
    """
    for rule in territory.POLICY:
        assert rule.globs, rule.pattern
        assert len(rule.why.split()) >= 8, f"{rule.pattern}: {rule.why!r} is a label, not a reason"
        assert not rule.why.endswith("."), rule.pattern
