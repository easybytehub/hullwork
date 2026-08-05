"""Lanes declaring territory instead of a catalogue of failures. Item 071, DR-0008 part 2.

The measured case these answer: `acme` declared `typeerror, valueerror, attributeerror, docs`
— what a competent engineer writes when asked which exceptions matter — and the first real failure
was a `decimal.DivisionByZero` from an Earned-Value index quantising to zero. A green lane written
as a catalogue of exception types asks a project to predict which bugs it will have, and the ones it
can name are the ones it already expected.

What a project *does* know is where it hurts. `services/billing/**` is a fact about a codebase,
readable today; it does not go stale when somebody writes a new function that raises a new thing.

**Every leniency test here has a negative twin.** A test that only proves a path can earn green
would pass against a `decide` that handed green to everything with a path in it.
"""

from hullwork.manifest import Manifest, parse_manifest
from hullwork.models import Lane
from hullwork.triage import decide

TERRITORY_ONLY = """
project: p
git: {provider: forgejo, repo: o/r}
tests: pytest
runtime: {base: python-3.12}
autofix:
  agent: claude-code
  lanes:
    red: ['services/billing/**', 'routers/admin_*.py', tenant]
"""

MIXED = """
project: p
git: {provider: forgejo, repo: o/r}
tests: pytest
runtime: {base: python-3.12}
autofix:
  agent: claude-code
  lanes:
    green: [typeerror, 'services/estimates/**']
    red: ['services/billing/**']
"""


def _manifest(source: str) -> Manifest:
    return parse_manifest(source)


def test_a_project_that_names_no_exception_type_is_fully_configured() -> None:
    """Gate 1 of DR-0008. An empty green list is a configuration, not an omission.

    A manifest declaring only where it hurts has said everything item 071 asks of it. If this
    raised, degraded, or warned, territory would not be a way of configuring a project — it would be
    a second thing to fill in alongside the catalogue.
    """
    manifest = _manifest(TERRITORY_ONLY)

    assert manifest.autofix.lanes.green == []
    assert manifest.autofix.lanes.red == [
        "services/billing/**", "routers/admin_*.py", "tenant",
    ]


def test_an_exception_type_never_seen_before_is_decided_by_where_it_happened() -> None:
    """Gate 1, the half that matters. `DivisionByZero` is on no list anywhere.

    Red, because the frames landed in declared territory — not because anybody predicted the
    exception. That is the whole of DR-0008 part 2 in one assertion.
    """
    decision = decide(
        _manifest(TERRITORY_ONLY),
        title="DivisionByZero: [<class 'decimal.DivisionByZero'>]",
        culprit=None,
        paths=("/app/src/api/services/billing/invoices.py",),
    )

    assert decision.lane is Lane.RED
    assert "services/billing/**" in decision.reason
    assert decision.saw_code_location is True


def test_the_same_error_outside_that_territory_is_not_red_for_this_reason() -> None:
    """The negative twin. Without it, a `decide` that reddened everything would pass the above."""
    decision = decide(
        _manifest(TERRITORY_ONLY),
        title="DivisionByZero: [<class 'decimal.DivisionByZero'>]",
        culprit=None,
        paths=("/app/src/api/services/reports/render.py",),
    )

    assert decision.lane is Lane.RED, "still red — nothing matched, and the default is red"
    assert "services/billing" not in decision.reason
    assert "no lane rule matched" in decision.reason


def test_declared_territory_beats_a_green_exception_type() -> None:
    """Gate 3. The most boring exception in the world, in the one directory that matters."""
    decision = decide(
        _manifest(MIXED),
        title="TypeError: unsupported operand",
        culprit=None,
        paths=("/app/src/api/services/billing/charge.py",),
    )

    assert decision.lane is Lane.RED
    assert "services/billing/**" in decision.reason


def test_the_same_green_type_elsewhere_still_earns_green() -> None:
    """Gate 3's twin: territory must narrow the green lane, not abolish it."""
    decision = decide(
        _manifest(MIXED),
        title="TypeError: unsupported operand",
        culprit=None,
        paths=("/app/src/api/services/reports/render.py",),
    )

    assert decision.lane is Lane.GREEN
    assert "typeerror" in decision.reason


def test_territory_can_earn_green_on_its_own() -> None:
    """A path is trustworthy: the interpreter walks a stack to produce it, no form field does."""
    decision = decide(
        _manifest(MIXED),
        title="SomethingNobodyListed: boom",
        culprit=None,
        paths=("/app/src/api/services/estimates/projection.py",),
    )

    assert decision.lane is Lane.GREEN
    assert "services/estimates/**" in decision.reason


def test_a_territory_pattern_typed_into_the_message_earns_nothing() -> None:
    """Gate 4, and the boundary this whole module is built around.

    An anonymous user of the watched application writes exception messages, and a path is a
    particularly convincing thing to be able to type.

    **The pattern here has no glob on purpose.** The first version of this test used
    `services/estimates/**` and passed against a `decide` with the message-only branch deleted — not
    because the boundary held, but because a literal `**` never appears in a message. It asserted
    nothing. A plain word can be typed, so this version actually distinguishes.
    """
    decision = decide(
        _manifest(MIXED.replace("'services/estimates/**'", "projection")),
        title="ValueError: could not load the projection for this account",
        culprit=None,
        paths=(),
    )

    assert decision.lane is Lane.RED
    assert "matched only the error message" in decision.reason


def test_a_red_pattern_typed_into_the_message_is_still_red() -> None:
    """Gate 4's twin. Red reads everything, so a typed red word may only ever make things worse."""
    decision = decide(
        _manifest(MIXED),
        title="ValueError: could not open services/billing/invoices.py",
        culprit=None,
        paths=(),
    )

    assert decision.lane is Lane.RED


def test_a_reserved_subject_in_the_path_is_red_and_the_reason_names_the_file() -> None:
    """Reserved territory, overriding any manifest. The message has no `auth` anywhere in it.

    Naming the file is not decoration: an operator told only that `auth` is reserved, against a
    title with no `auth` in it, goes looking through their manifest for a word that is not there
    and concludes the tool is malfunctioning.
    """
    decision = decide(
        _manifest(MIXED),
        title="TypeError: unsupported operand",
        culprit=None,
        paths=("/app/src/api/routers/auth.py",),
    )

    assert decision.lane is Lane.RED
    assert "reserved subject" in decision.reason
    assert "/app/src/api/routers/auth.py" in decision.reason


def test_a_glob_only_matches_the_paths_it_should() -> None:
    """`routers/admin_*.py` is a shape, and shapes have edges worth asserting."""
    manifest = _manifest(TERRITORY_ONLY)

    hit = decide(
        manifest, title="KeyError: x", culprit=None,
        paths=("/srv/app/routers/admin_impersonation.py",),
    )
    miss = decide(
        manifest, title="KeyError: x", culprit=None, paths=("/srv/app/routers/sites.py",),
    )

    assert hit.lane is Lane.RED
    assert "routers/admin_*.py" in hit.reason
    assert "routers/admin" not in miss.reason


def test_a_plain_word_still_matches_a_path_as_a_substring() -> None:
    """`tenant` is not a glob and never was. Territory is additive to the old rule, not a swap.

    This is what lets a project write `billing` and mean it, without a field asking whether they
    intended a path or a subject — the question item 071 refuses to ask.
    """
    decision = decide(
        _manifest(TERRITORY_ONLY),
        title="KeyError: 42",
        culprit=None,
        paths=("/app/src/api/db/tenant_scope.py",),
    )

    assert decision.lane is Lane.RED
    assert "'tenant'" in decision.reason


def test_a_plain_word_in_the_green_lane_matches_a_path_too() -> None:
    """The other half of "additive": paths belong in `_trustworthy`, not only in the glob check.

    A glob pattern reaches a path through `_matches`'s second branch. A plain word can only reach
    one by being searched for in the trustworthy text — so this is the test that fails if frame
    paths stop being part of it, and without it that only showed up in `test_relane.py` by accident.
    """
    decision = decide(
        _manifest(MIXED.replace("'services/estimates/**'", "projection")),
        title="SomethingNobodyListed: boom",
        culprit=None,
        paths=("/app/src/api/services/estimates/projection.py",),
    )

    assert decision.lane is Lane.GREEN
    assert "'projection'" in decision.reason


def test_no_paths_at_all_behaves_exactly_as_before() -> None:
    """Compatibility, asserted rather than assumed: every M1 project reaches `decide` this way.

    A webhook carries no frames, so this is the shape of every first decision in production.
    """
    with_none = decide(_manifest(MIXED), title="TypeError: boom", culprit=None, paths=())
    with_culprit = decide(_manifest(MIXED), title="TypeError: boom", culprit="app.x in f")

    assert with_none.lane is Lane.GREEN
    assert with_none.saw_code_location is False
    assert with_culprit.saw_code_location is True
