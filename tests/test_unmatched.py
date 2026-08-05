"""What happens to an error no rule mentions. Item 072, DR-0008 part 3.

The only part of DR-0008 that was a risk decision rather than a fix, and the operator took it on
2026-07-29 in a different shape from the one proposed: the instance default does not change, a
project opts in. That reversal is the mitigation, not a smaller version of the change — opt-out
would mean a project inherits the risky answer *by being forgotten*, and forgetting is the adversary
this part names.

What is being accepted, stated plainly because the tests should not be the only place it is written
down: an agent will read and modify code in modules nobody thought to declare. It still cannot merge
any of it.
"""

from hullwork.manifest import Manifest, parse_manifest
from hullwork.models import Lane
from hullwork.triage import decide

_BASE = """
project: {name}
git: {{provider: forgejo, repo: o/{name}}}
tests: pytest
runtime: {{base: python-3.12}}
autofix:
  agent: claude-code
{extra}  lanes:
    green: [typeerror]
    red: ['services/billing/**']
"""

#: `hullwork` opts in — own code, no client. `acme` does not, and changes nothing to say so.
OPTED_IN = _BASE.format(name="hullwork", extra="  unmatched: attempt\n")
DEFAULT = _BASE.format(name="acme", extra="")

#: The error that started all of this: on no list, in no declared territory.
UNLISTED = "DivisionByZero: [<class 'decimal.DivisionByZero'>]"
SOMEWHERE_ORDINARY = ("/app/src/api/services/estimates/projection.py",)


def _manifest(source: str) -> Manifest:
    return parse_manifest(source)


def test_the_default_is_unchanged_and_needs_no_field() -> None:
    """Compatibility is the first requirement, and it is asserted rather than assumed.

    Every project already connected reaches `decide` through this path. If the field's absence meant
    anything new, item 072 would be a change to what existing users have rather than something they
    can choose.
    """
    manifest = _manifest(DEFAULT)

    assert manifest.autofix.unmatched == "human"

    decision = decide(manifest, title=UNLISTED, culprit=None, paths=SOMEWHERE_ORDINARY)
    assert decision.lane is Lane.RED
    assert decision.reason == "no lane rule matched; defaulting to red so a human decides"


def test_one_instance_two_projects_two_answers() -> None:
    """**Gate 2 of DR-0008.** The same error, the same delivery path, two verdicts.

    This is the whole shape of the decision: the appetite belongs to a codebase and its owner, not
    to the instance watching both.
    """
    opted_in = decide(_manifest(OPTED_IN), title=UNLISTED, culprit=None, paths=SOMEWHERE_ORDINARY)
    default = decide(_manifest(DEFAULT), title=UNLISTED, culprit=None, paths=SOMEWHERE_ORDINARY)

    assert opted_in.lane is Lane.GREEN
    assert default.lane is Lane.RED


def test_the_reason_says_which_of_the_two_things_happened() -> None:
    """An operator must be able to tell "a green rule matched" from "nothing did, and I allowed it".

    Otherwise the only record of why an agent was let near a module is a lane letter, and the first
    surprising PR has no explanation attached to it.
    """
    matched = decide(_manifest(OPTED_IN), title="TypeError: bad", culprit=None, paths=())
    unmatched = decide(_manifest(OPTED_IN), title=UNLISTED, culprit=None, paths=())

    assert matched.lane is unmatched.lane is Lane.GREEN
    assert matched.reason == "matched 'typeerror' in the green lane"
    assert "autofix.unmatched: attempt" in unmatched.reason
    assert matched.reason != unmatched.reason


def test_a_reserved_path_is_still_red_with_the_field_set() -> None:
    """**The negative gate, and the one that matters.**

    Without this the opt-in is unbounded, and the opt-in is the only thing standing between this and
    the fail-open case DR-0008 argued against. `auth` appears nowhere in the title.
    """
    decision = decide(
        _manifest(OPTED_IN),
        title=UNLISTED,
        culprit=None,
        paths=("/app/src/api/routers/auth.py",),
    )

    assert decision.lane is Lane.RED
    assert "reserved subject" in decision.reason
    assert "/app/src/api/routers/auth.py" in decision.reason


def test_declared_territory_is_still_red_with_the_field_set() -> None:
    """A project's own red list is not weakened by its own opt-in. Both are its statements."""
    decision = decide(
        _manifest(OPTED_IN),
        title=UNLISTED,
        culprit=None,
        paths=("/app/src/api/services/billing/charge.py",),
    )

    assert decision.lane is Lane.RED
    assert "services/billing/**" in decision.reason


def test_a_message_only_match_is_still_refused_with_the_field_set() -> None:
    """The authorisation boundary does not move because a project raised its own appetite.

    An end user typing a green word still earns nothing, and the message-only branch answers
    **before** the project's own default is ever asked — so this stays red rather than reaching
    green by the back door, and the reason names the branch rather than crediting a stranger's text.
    """
    decision = decide(
        _manifest(OPTED_IN),
        title="RuntimeError: typeerror while rendering",
        culprit=None,
        paths=(),
    )

    assert decision.lane is Lane.RED
    assert "matched only the error message" in decision.reason


def test_the_field_is_rejected_if_it_is_not_one_of_the_two_answers() -> None:
    """A typo must not silently become the permissive one. Closed set, refused at parse time."""
    import pytest

    from hullwork.manifest import ManifestError

    with pytest.raises(ManifestError):
        parse_manifest(_BASE.format(name="p", extra="  unmatched: yes\n"))
