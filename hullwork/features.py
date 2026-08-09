"""What this can do for your project, and what it cannot. Item 186.

**Hullwork is modular and never said so.** `hullwork.yml` is the switchboard and almost everything
is off by default — `autofix.agent: none`, no `lint`, `notify.channel: none`,
`autofix.unmatched: human`, `runtime.install: none`. A project that declares nothing gets filing and
nothing else, deliberately.

What did not exist is the other half of the operator's framing: **each feature has its
limitations**. Nothing declared what it needed or what it could not do, so every limitation was
found by walking into it — and three items measured what that costs. Item 182 found a **false
verdict** produced for a project whose image Hullwork does not build; item 184 found a missing
credential reported after four container builds, as a traceback; item 185 found `propose` writing a
manifest under which nothing could be measured, silently.

Each was fixed where it happened, and none of those is a place a person looks *before* deciding
whether this is for them.

**The shape is `projects lanes --checkout .`**, which prints this instance's lane policy against
your tree with no credential of any kind, because *"a policy nobody has read is a policy nobody has
agreed to"*. Same rules here: a checkout, no credential, nothing executed, nothing written and no
socket opened.

**Declaring a limitation is not accepting it**, and this module must never read as an excuse. That
dependency verification needs Hullwork to build the image is a real limit *and* a consequence of
building on the path DR-0007 demoted to sugar. Saying so is honest; leaving it there is a decision
nobody has taken.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from hullwork.manifest import Manifest


@dataclass(frozen=True)
class Need:
    """One thing a feature requires, and what to do when it is missing.

    `met` is asked of the checkout and the manifest and **nothing else**: no network, no daemon, no
    credential. A requirement this cannot answer from those two is not a requirement this module
    states — it is `doctor`'s, and `INSTANCE_SHAPED` names those rather than guessing at them.
    """

    what: str
    #: What to do about it, in the words a person would type. Never "configure it correctly".
    fix: str
    met: Callable[[Checkout], bool]


@dataclass(frozen=True)
class Feature:
    """One thing Hullwork can do, what it needs, and what it cannot do even when it can.

    **Two fields and they must not blend.** `needs` is checkable and either met or not; `limits` is
    true whatever the answer, and is stated either way. The second is the half the operator's
    framing names and the half that had no home anywhere in this repository.

    Declared as data, like `resolve.RESOLVERS` and `image.INSTALL_COMMANDS`, so a feature is a row.
    """

    name: str
    #: One line, for somebody deciding whether they want it.
    does: str
    needs: tuple[Need, ...] = ()
    #: What the **project** must have permitted, as opposed to what it must be able to do (DR-0019).
    #: Unmet here is a third answer and not a fourth kind of missing part: *available, and this
    #: project has not said yes*. Empty for every feature that writes nothing to a repository.
    permits: tuple[Need, ...] = ()
    #: What it cannot do with everything in place. **Never empty**: a feature with no limits has to
    #: say that in words, because an empty list reads as "nobody wrote them down" — which, until
    #: this module, was true of all of them.
    limits: tuple[str, ...] = ()


@dataclass(frozen=True)
class Checkout:
    """Everything this module is allowed to look at. Deliberately three fields.

    A checkout's tracked paths, its manifest if it has one, and **which instance variables are
    set** — never their values. That last one is why this can say *"needs a model credential, and
    none is configured"* without holding one, and why it can be run by somebody who has configured
    nothing at all.
    """

    paths: tuple[str, ...] = ()
    manifest: Manifest | None = None
    #: Names of environment variables that have a value. Names only, never values.
    configured: frozenset[str] = field(default_factory=frozenset)

    def has(self, *names: str) -> bool:
        """Whether the checkout tracks a file with one of these base names."""
        wanted = set(names)
        return any(path.rsplit("/", 1)[-1] in wanted for path in self.paths)


def _manifest_says(check: Callable[[Manifest], bool]) -> Callable[[Checkout], bool]:
    """A need that is about the manifest. False when there is none, which is the honest answer."""

    def met(checkout: Checkout) -> bool:
        return checkout.manifest is not None and check(checkout.manifest)

    return met


def _installs_from_a_pinned_file(manifest: Manifest) -> bool:
    """Whether an upgrade could reach the environment the suite runs in. Item 182's finding.

    With `install: none` the image is `runtime.base` exactly as it comes and nothing is installed
    from a lock file, so rewriting a pinned version changes nothing the suite would run against.
    Measured: a checkout pinning `jinja2==2.4.1`, a base carrying 3.0.0, and a verdict saying the
    suite passed before the change and after it — about a version never installed.
    """
    runtime = manifest.runtime
    return runtime is not None and runtime.install != "none" and bool(runtime.dependencies)


#: What a lock file is called, borrowed from the reader rather than restated — a second list is a
#: second thing to keep correct, and this one would go stale the day an ecosystem is added.
def _pins_anything(checkout: Checkout) -> bool:
    from hullwork import dependencies

    return any(
        path.rsplit("/", 1)[-1] in {"package-lock.json", "uv.lock", "poetry.lock"}
        or dependencies.is_requirements(path)
        for path in checkout.paths
    )


#: The variable each credential-shaped need looks for. Names, never values (`Checkout.configured`).
MODEL_KEY = "HULLWORK_MODEL_KEY"
CODE_TOKEN = "HULLWORK_FORGE_CODE_TOKEN"  # noqa: S105 - a variable's name, never its value

#: Features whose answer is about an **instance** rather than about a checkout, named rather than
#: guessed at. `doctor` owns these: whether the forge answers, whether the tracker is reachable,
#: whether the database has a schema, whether a dispatcher holds the lease. A checkout cannot know
#: any of it, and a report that pretended to would be worse than one that says whose question it is.
INSTANCE_SHAPED: tuple[str, ...] = (
    "filing a production error as an issue",
    "the daily page",
    "notifications",
    "the recurrence watch",
)

FEATURES: tuple[Feature, ...] = (
    Feature(
        name="dependency report",
        does="says which of your pinned versions have a published advisory, and what fixes each",
        needs=(
            Need(
                what="a lock file or a pinned requirements file, committed",
                fix="commit one, or pin with `==` — a declaration is a range and a range is not a "
                "fact about what your build resolved to",
                met=_pins_anything,
            ),
        ),
        limits=(
            "It reads what you pinned, so a dependency your build resolves at install time is "
            "invisible to it.",
            "It asks OSV, which is one database. An advisory nobody published is an advisory this "
            "cannot know about.",
        ),
    ),
    Feature(
        name="dependency verification",
        does="applies each published fix and runs your own suite against it, in a sandbox",
        needs=(
            Need(
                what="a lock file or a pinned requirements file, committed",
                fix="commit one, or pin with `==`",
                met=_pins_anything,
            ),
            Need(
                what="a hullwork.yml naming an image (`runtime.base`) and your test command",
                fix="`hullwork propose --checkout .` writes one from your CI configuration",
                met=_manifest_says(
                    lambda m: m.runtime is not None and bool(m.runtime.base) and bool(m.tests)
                ),
            ),
            Need(
                what="an installer that reads the file your versions are pinned in",
                fix="name `runtime.install` and the file in `runtime.dependencies`. **Keep your "
                "own image as the `base`** — this is one line on top of it, in your own words, not "
                "a rebuild from scratch. Without it the image is your base exactly as it comes, so "
                "changing a pin changes nothing your suite would run against",
                met=_manifest_says(_installs_from_a_pinned_file),
            ),
        ),
        limits=(
            "What is measured is **your suite**. If it does not exercise the dependency it stays "
            "green without ever loading the new version, and the verdict would read the same.",
            "A phase has no network, so a suite that reaches the internet cannot be run here, and "
            "is reported as a suite that does not pass rather than as a verdict about the upgrade.",
            "It can only measure an upgrade it can **install**, so the image has to be refreshed "
            "from the file that pins. That does not mean Hullwork must build your image: your own "
            "image as the base, plus the one line that reinstalls your dependencies, is measured "
            "the same way (item 188).",
        ),
    ),
    Feature(
        name="fixing an upgrade that breaks your suite",
        does="asks an agent to change your code so the upgrade fits, then runs your suite again",
        needs=(
            Need(
                what="everything dependency verification needs",
                fix="see above — nothing is fixed until something has been measured breaking",
                met=lambda c: _pins_anything(c)
                and _manifest_says(_installs_from_a_pinned_file)(c),
            ),
            Need(
                what="a model credential on the instance that runs it",
                fix=f"set {MODEL_KEY} to an API key from any provider (DR-0004)",
                met=lambda c: MODEL_KEY in c.configured,
            ),
            Need(
                what="`autofix.agent` naming an engine this instance holds",
                fix="set `autofix: {agent: claude-code}` — it is `none` by default, which is the "
                "whole product for a project that wants nothing else",
                met=_manifest_says(lambda m: m.autofix.agent != "none"),
            ),
        ),
        limits=(
            "One attempt per upgrade and then a person (DR-0003). A failure does not buy a second.",
            "It may not touch your dependency files, so an upgrade that can only be made to fit by "
            "changing the pin is reported as a revert rather than attempted.",
            "It writes what it produced to disk and opens nothing anywhere.",
        ),
    ),
    Feature(
        name="opening the upgrades that pass",
        does="opens one draft pull request per package whose suite passed, and never any other",
        needs=(
            Need(
                what="everything dependency verification needs",
                fix="see above — nothing is opened that was not run",
                met=lambda c: _pins_anything(c)
                and _manifest_says(_installs_from_a_pinned_file)(c),
            ),
            Need(
                what="a credential able to write to your repository",
                fix=f"set {CODE_TOKEN}. It is the one thing here that writes anything anywhere",
                met=lambda c: CODE_TOKEN in c.configured,
            ),
            Need(
                what="an `origin` remote, so the repository can be named",
                fix="add one — a coordinate cannot be guessed from a directory name, and a wrong "
                "guess opens a pull request somewhere else",
                met=lambda c: "origin" in c.configured,
            ),
        ),
        permits=(
            Need(
                what="`autofix.open_upgrades`, which this project has not set",
                fix="set `autofix: {open_upgrades: true}` in hullwork.yml. It is false by default "
                "because having the credential is not the same as having agreed (DR-0019), and "
                "this is the only thing here that writes to your repository",
                met=_manifest_says(lambda m: m.autofix.open_upgrades),
            ),
        ),
        limits=(
            "Only what passed. Nothing that broke, nothing blocked, no suite that was already red.",
            "One pull request per package, never a batch — a grouped upgrade that breaks cannot be "
            "bisected without undoing the work.",
            "Every one is a draft. Nothing here merges anything, ever (constitution principle 1).",
        ),
    ),
    Feature(
        name="fixing a production error",
        does="reproduces a reported error with a failing test, fixes it, and opens a draft pull "
        "request carrying both",
        needs=(
            Need(
                what="a hullwork.yml naming an image and your test command",
                fix="`hullwork propose --checkout .` writes one from your CI configuration",
                met=_manifest_says(
                    lambda m: m.runtime is not None and bool(m.runtime.base) and bool(m.tests)
                ),
            ),
            Need(
                what="`autofix.agent` naming an engine this instance holds",
                fix="set `autofix: {agent: claude-code}` — `none` is the default",
                met=_manifest_says(lambda m: m.autofix.agent != "none"),
            ),
            Need(
                what="a model credential on the instance that runs it",
                fix=f"set {MODEL_KEY} to an API key from any provider (DR-0004)",
                met=lambda c: MODEL_KEY in c.configured,
            ),
        ),
        limits=(
            "It will not attempt anything in the red lane, and an error it cannot classify is red. "
            "`hullwork projects lanes --checkout .` prints that policy against your own tree.",
            "No fix without a test that fails first on untouched code (DR-0003). *I could not "
            "reproduce this* is a result rather than a failure, and is the answer more often "
            "than not.",
            "One attempt per error, then a person.",
        ),
    ),
)


@dataclass(frozen=True)
class Answer:
    """Whether one feature is available here, whether it is permitted, and what is in the way.

    **Three answers and not two** (DR-0019). *Available* is about what this project and instance
    can do; *permitted* is about what the project has agreed to. Blending them would report a
    decision somebody made as a part that is missing, which is the one way this report could
    insult its reader.
    """

    feature: Feature
    missing: tuple[Need, ...]
    withheld: tuple[Need, ...] = ()

    @property
    def available(self) -> bool:
        return not self.missing

    @property
    def permitted(self) -> bool:
        return not self.withheld


def examine(checkout: Checkout, features: Sequence[Feature] = FEATURES) -> list[Answer]:
    """Which features this checkout can have, in the order they are declared.

    **Every need, not the first one that fails.** A reader who fixes one thing and runs this again
    to find a second is a reader doing the work this command exists to save them.
    """
    return [
        Answer(
            feature,
            tuple(need for need in feature.needs if not need.met(checkout)),
            tuple(need for need in feature.permits if not need.met(checkout)),
        )
        for feature in features
    ]


def lines(answers: Sequence[Answer]) -> list[str]:
    """The report, for a terminal.

    **The limits are printed whether or not the feature is available**, which is the whole of the
    operator's framing: a feature you can have and a feature you cannot both have things they will
    not do, and the first is the one where nobody thinks to look.
    """
    said: list[str] = []
    for answer in answers:
        if not answer.available:
            mark = "no"
        elif not answer.permitted:
            # **A decision, spelled as one.** `no` here would read as a part that is missing, and
            # somebody chose this.
            mark = "not permitted here"
        else:
            mark = "yes"
        said.append(f"[{mark}] {answer.feature.name} — {answer.feature.does}")
        for need in answer.missing:
            said.append(f"       needs: {need.what}")
            said.append(f"          →   {need.fix}")
        for need in answer.withheld:
            said.append(f"       this project has not permitted it: {need.what}")
            said.append(f"          →   {need.fix}")
        for limit in answer.feature.limits:
            said.append(f"       limit: {limit}")
        said.append("")
    return said
