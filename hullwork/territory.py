"""Which code is dangerous, decided by the instance rather than asked of the project. M8, item 104.

**The question this answers.** A project that declares no lanes is not configured today: every
error falls through to *"no lane rule matched; defaulting to red so a human decides"*, and the only
escape is `unmatched: attempt`, which makes **everything** dispatchable including the code where a
wrong fix is a breach. Both ends are the same gap — the instance has no opinion of its own, so it
makes the operator supply one before it will do anything useful. DR-0008 named it in one sentence:
*"a project that names none is fully configured, which today it is not."*

**Why this is a pure function of a path and not a cached list.** The obvious implementation of
The plan's *"lanes computed from the repository's own tree"* is to fetch the tree once, derive
patterns, store them on the project and match against the stored copy. That design fails in the
fail-open direction: the day the repository grows `services/payouts/`, a stored policy does not
know, and the item that lands there goes green. DR-0008 part 3 names *forgetting* as the adversary
of green-by-default, and a cache is a machine that forgets on the project's behalf. A function of
the path cannot go stale — a directory added this morning is classified this afternoon.

The tree is still worth reading, for the other half of the problem: `hullwork lanes <slug>` applies
this policy to a repository's real directories so an operator can read it **before** trusting it.
That is a question a person asks, not a step in a decision, so it lives in the CLI and not here.

**What earns a place in the policy.** Each rule needs a reason of the form *a wrong automated fix
here is not a bug*, and the list stays short enough that the printed preview is readable. Breadth is
not free: every rule here is code an agent will not be allowed to touch unattended, and a policy
that classes half a repository as sensitive is a policy an operator overrides wholesale — which is
worse than a narrow one they keep.

**This is not `ALWAYS_RED`, and the difference is what an operator may do about it.** The reserved
subjects are absolute: no manifest reaches them, at parse time or at triage. These rules are the
*instance's* opinion, and a project that disagrees may say so in `autofix.lanes.ordinary`. Saying
which kind a decision was is the difference between a tool a person can work with and one that
seems arbitrary.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from fnmatch import fnmatch


@dataclass(frozen=True)
class Rule:
    """One derived rule: what it matches, and why an agent is kept out of there.

    `why` is a sentence rather than a category because it is read by a person deciding whether to
    override it, and *"migrations"* does not answer that while *"irreversible against real data"*
    does. It goes into the lane reason verbatim.
    """

    #: Shown to an operator, so it reads like something they could have written themselves.
    pattern: str
    why: str
    #: `fnmatch` globs, tried against the whole path and against its basename. Several per rule
    #: because one concern has more than one spelling in the wild (`alembic/versions/` and
    #: `db/migrate/` are the same decision).
    globs: tuple[str, ...]

    def matches(self, path: str) -> bool:
        """Whether this rule claims `path`.

        Matched against the path **and** its basename, so `Dockerfile` catches a root `Dockerfile`
        without a rule for every directory it might sit in. Case-folded: the same file is
        `LICENSE` on one project and `license` on the next.

        **Every glob gets an implicit leading `*`**, which is the same rule `triage._matches` states
        for manifest patterns and for the same measured reason: a frame arrives as
        `/app/src/myapp/…`, so `.github/workflows/*` anchored at the root matches nothing a tracker
        ever reports. Caught by the parametrised gate test, which is the only reason this rule is
        here once rather than spelled into eleven globs — and spelling it into globs is how the
        twelfth one, written by somebody else next year, would be wrong.
        """
        low = path.lower().lstrip("/")
        base = posixpath.basename(low)
        return any(
            fnmatch(low, glob if glob.startswith("*") else f"*{glob}") or fnmatch(base, glob)
            for glob in self.globs
        )


#: The policy. Ordered by how badly a wrong fix goes, which is the order an operator reads it in.
#:
#: Deliberately absent: `models/`, `services/`, `api/`, `core/` and every other word that means
#: "where the application lives". Classing those as sensitive would be a policy that refuses to
#: attempt anything, dressed as caution — the gates are what protect a merge (DR-0008's threat
#: model), and a lane only decides how often that chain is exercised.
POLICY: tuple[Rule, ...] = (
    Rule(
        "migrations",
        "a schema migration is irreversible against real data, and a green suite proves nothing "
        "about the production table it would rewrite",
        (
            "*migrations/*",
            "*alembic/versions/*",
            "*db/migrate/*",
            "*/migrate/*",
        ),
    ),
    Rule(
        "ci and deployment",
        "this is the pipeline that would run the fix, so a wrong change here is a change to every "
        "later verdict rather than to one behaviour",
        (
            ".github/workflows/*",
            ".forgejo/workflows/*",
            ".gitea/workflows/*",
            ".gitlab-ci.yml",
            "dockerfile",
            "dockerfile.*",
            "docker-compose*.yml",
            "docker-compose*.yaml",
            "*terraform/*",
            "*.tf",
            "*helm/*",
            "*k8s/*",
            "*kubernetes/*",
            "*/manifests/*",
        ),
    ),
    Rule(
        "the project's own gates",
        "a fix that relaxes the suite passes the suite — item 046's concern, from the side where "
        "the configuration lives rather than the tests",
        (
            "conftest.py",
            "pytest.ini",
            "tox.ini",
            "setup.cfg",
            "ruff.toml",
            ".ruff.toml",
            "mypy.ini",
            ".pre-commit-config.yaml",
            ".editorconfig",
            "eslint.config.*",
            ".eslintrc*",
        ),
    ),
    Rule(
        "dependencies and packaging",
        "these decide what every gate runs against, so a change here is a change to the meaning of "
        "the results rather than to the code",
        (
            "pyproject.toml",
            "setup.py",
            "requirements*.txt",
            "poetry.lock",
            "uv.lock",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "go.mod",
            "go.sum",
            "cargo.toml",
            "cargo.lock",
            "gemfile",
            "gemfile.lock",
            "composer.json",
            "composer.lock",
        ),
    ),
    Rule(
        "licence, ownership and security policy",
        "these are the project's commitments to other people, and nobody delegates those to an "
        "unattended process",
        (
            "license*",
            "licence*",
            "copying",
            "notice",
            "codeowners",
            ".github/codeowners",
            "docs/codeowners",
            "security.md",
            ".github/security.md",
            "dco",
        ),
    ),
)

#: A frame's path as a tracker reports it: absolute inside whatever the deployment mounts, with the
#: repository somewhere in the middle (`/app/src/acme_api/services/…`). Nothing here can know
#: where the repository root is, which is why every glob above is written to match unanchored.
#:
#: Not a validation — a path this cannot read is simply not classified, and an unclassified path is
#: not evidence of safety: `decide` still has the reserved check and the manifest's own rules.
_UNINTERESTING = re.compile(r"(^|/)(site-packages|node_modules|\.venv|venv|dist-packages)(/|$)")


def sensitivity(path: str) -> Rule | None:
    """The rule that classes `path` as sensitive, or `None` if it is ordinary code.

    Third-party paths answer `None` deliberately. A traceback through `site-packages` is a frame in
    somebody else's library, and a `pyproject.toml` **inside** a dependency is not this project's
    packaging — classing it sensitive would send every error that passes through a dependency's
    installer machinery to a human on the strength of a filename that is not theirs.
    """
    if not path or _UNINTERESTING.search(path.lower()):
        return None
    for rule in POLICY:
        if rule.matches(path):
            return rule
    return None


def first_sensitive(paths: object) -> tuple[str, Rule] | None:
    """The first frame that lands in sensitive code, with the rule that claims it.

    Ordered by the frames as given rather than by rule severity: the reason names *where the error
    happened*, and an operator matching the sentence against a stack trace needs the frame the
    tracker showed them, not the worst one this module could find.

    Takes `object` and checks, because the caller is triage and its `paths` come from a tracker
    payload — a shape somebody else controls, on the path where a wrong assumption becomes a lane.
    """
    if not isinstance(paths, (list, tuple)):
        return None
    for path in paths:
        if not isinstance(path, str):
            continue
        rule = sensitivity(path)
        if rule is not None:
            return path, rule
    return None


def sensitive_tree(paths: object) -> list[tuple[str, Rule]]:
    """Every path in a repository tree this policy claims, for `hullwork lanes` to print.

    Sorted, deduplicated by path, and never consulted to decide a lane — this exists so an operator
    can read the policy against their own directories before trusting it. If it were the decision,
    it would be a snapshot, and a snapshot of "which code is dangerous" is the fail-open failure
    this module's docstring refuses.
    """
    if not isinstance(paths, (list, tuple)):
        return []
    found: dict[str, Rule] = {}
    for path in paths:
        if isinstance(path, str):
            rule = sensitivity(path)
            if rule is not None:
                found.setdefault(path, rule)
    return sorted(found.items())
