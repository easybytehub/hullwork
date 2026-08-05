# `hullwork.yml` — project manifest specification (schema version 1)

One file at the root of each connected repository declares everything variable. Connecting a project = adding this file (plus its error-tracker DSN as a secret). No per-project code.

Unknown keys are refused rather than ignored, so a typo cannot leave you believing you have a guardrail you do not have. Every problem in the file is reported at once.

**The whole file, for a project of any language that already has a CI image.** Everything else in this document is optional or has a default:

```yaml
project: myproject
git: { provider: forgejo, repo: owner/myproject }
tests: make test
lint: make lint
runtime: { base: ghcr.io/acme/ci-base:2026.7, install: none }
```

Go, Rust, Ruby, PHP, Elixir, Java — the manifest names the *environment* the tests run in, never the ecosystem the project belongs to, which is why no list here has to grow for a new language (DR-0007). And you do not have to write even this by hand: **`hullwork propose owner/myproject`** reads the repository's own CI configuration and prints it.

**Measured on eight public repositories** in those languages (items 111–113): seven produce a manifest that parses and names a base and a test command, and **six of them run their own suites green in the sandbox built from it**, with nobody editing anything — `gorilla/mux` (Go), `expressjs/express` (Node), `dtolnay/anyhow` (Rust), `elixir-ecto/ecto` (Elixir), `sinatra/sinatra` (Ruby) and `google/gson` (Java).

The two that do not are the sandbox being right, not a stack this cannot serve:

- **`psf/requests`** builds, and its suite *runs* and fails: parts of it reach the internet, and a phase has no network by design. That is a correct `baseline-red` — the project's own suite does not pass on an untouched checkout **in this environment**, and the item keeps its attempt.
- **`briannesbitt/carbon`** needs one line a reader cannot guess — its test command exists only as a CI matrix expansion — and with that line its suite **runs**: 5375 tests, 5372 passing. The three that fail are its own PHPStan wrapper, which reports severe errors in this environment; that is a `baseline-red`, which keeps the item's attempt and tells you which three. PHP works because `install_needs_source` also makes anything the build installed under `/work` survive the mount (item 114) — `vendor/` stays where PHP looks for it.

Read what `propose` gives you before committing it; it is a proposal, and the comments say which parts it inferred — including `install_needs_source`, which puts your whole checkout in the image and costs a rebuild per attempt. It is set only for installers that read your source, and it is the difference between Ruby and Java working and not.

```yaml
# hullwork.yml
version: 1                        # optional; absent means 1, and will keep meaning 1 for ever
project: demo                 # unique slug across the Hullwork instance

errors:
  provider: glitchtip             # glitchtip | sentry-compatible webhook
  # DSN lives in the project's own environment, never in this file

git:
  provider: forgejo               # forgejo | gitea | github   (v0)
  repo: acme/demo

ci: forgejo-actions               # forgejo-actions | github-actions | none

deploy: compose                   # compose | ftp | argocd | none  (informational in v0)

autofix:
  # DR-0002: `none` is the DEFAULT. Ingest, dedup, triage and queueing work with no external
  # model call at all — the fix attempt is what you opt into, and you choose where it runs.
  # An agent is NAMED, never supplied. There is no `custom: "<command>"`: this file comes from a
  # repository, so a field carrying a command would let anyone able to merge there choose what the
  # Hullwork host executes. Adding an engine is a decision for whoever runs the instance.
  agent: claude-code              # none | claude-code | openhands
  sandbox: docker                 # docker (only option in v0)

  # Risk lanes. **Declare where your code hurts, not which exceptions you expect.**
  #
  # A list of exception types is a prediction about which bugs you are going to have, and the ones
  # you can name in advance are the ones you already expected. Measured: a project declared
  # `typeerror, valueerror, attributeerror` — what anyone writes when asked — and its first real
  # failure was a `DivisionByZero` from an accounting index rounding to zero. Nobody writes that on
  # a list beforehand. Territory does not have that problem: `services/billing/**` is a fact about
  # your repository, true today and still true after somebody adds a function that raises something
  # new. **A manifest that names no exception type at all is fully configured.**
  #
  # Each entry is matched case-insensitively, and you never say which kind you wrote:
  #   * as a **substring** of the error — exception type, culprit, frame paths;
  #   * and, if it contains `*`, additionally as a **glob against each frame path**, with an implicit
  #     leading `*` unless you anchor it yourself (a frame arrives as an absolute container path).
  # The two are additive, so a pattern can only ever match more than the substring alone.
  #
  # `*` crosses `/`, so `services/*` also covers `services/billing/charge.py`. For red that is the
  # safe direction. For green it is a real edge: prefer the narrowest pattern you mean.
  #
  # Red is matched against the whole error, title included, so any hint of danger counts.
  # **Green and amber are matched only against the exception type, the culprit and the frame
  # paths** — never the exception message, which routinely carries user input. An anonymous user of
  # your application typing `docs`, or a plausible file path, into a form must not be able to pick
  # the lane an agent will act on. A green pattern that matches only the message keeps the item red
  # and says so in the issue.
  #
  # Frame paths arrive with the tracker's full event, not with its webhook, so a territory rule is
  # answered when that arrives and the lane is decided a second time (item 070). Both decisions stay
  # in the issue. Without `errors.tracker` configured there are no frames, and territory rules can
  # only match the culprit.
  lanes:
    green:                        # autonomous (still lands as a PR)
      - services/reports/**      # territory: where an agent may work
      - app/api/formatting.py
      - typeerror                # still allowed, and still a prediction
    amber:                        # requires per-item human approval
      - migrations/**
      - alembic
    red:                          # never the agent — always a human
      - services/billing/**      # territory: where it must not
      - routers/admin_*.py
      - tenant
    ordinary:                     # code the *instance's* derived policy calls sensitive and you
      - docs/migrations/**        # do not — see the paragraph below
  # `secret`, `secrets`, `token`, `credential`, `auth`, `payment` and `payments` are reserved: they
  # are red whatever this file says, and as of item 071 that includes matching a **frame path**, so
  # an error in `routers/auth.py` is a human's whatever its title claims. The issue names the file.
  #
  # **You do not have to write any of this.** As of M8 the instance has its own opinion about which
  # code is dangerous, derived from the path an error came from rather than from anything you
  # declare: schema migrations, CI and deployment definitions, your own test and lint configuration,
  # dependency manifests, and licence/ownership/security files. Each one is red because a wrong
  # automated fix there is not a bug — a migration is irreversible against real data, and a fix that
  # relaxes your suite passes your suite. `hullwork projects lanes <slug>` prints the policy applied
  # to **your** tree, file by file, with the reason for each rule; run it before you trust an
  # instance with a repository.
  #
  # The derived policy is consulted after your red rules and *before* green and amber, so
  # `green: [typeerror]` does not admit a `TypeError` in `alembic/versions/`. If it reads your layout
  # wrong — a `migrations/` directory holding documentation, a vendored `package.json` that is
  # nobody's dependency — say so in `ordinary` and it becomes ordinary code. `ordinary` cannot reach
  # the reserved subjects above: that is refused when this file is parsed.

  # What happens to an error that matched nothing above. `human` — the default, and what every
  # project has unless it says otherwise — sends it to you.
  #
  # `attempt` says: *try anything my rules do not protect*. The lanes stop being an allow-list and
  # become the exceptions to a default of trying. **What you are accepting, plainly: an agent will
  # read and modify code in modules you did not think to declare** — though as of M8 the instance's
  # derived policy stands between it and the code where that is worst, which is what makes this a
  # decision rather than a leap. It still cannot merge any of it —
  # one attempt, a green baseline required, a failing test before the fix, a draft PR, your merge —
  # and reserved subjects and your own red territory still override this. But "nobody thought about
  # that module" is a real cost and it is yours to accept, per project, deliberately.
  #
  # Why per project rather than per instance: an opt-*out* would mean a repository inherits the
  # riskier answer by being forgotten, and forgetting is the failure this guards against. One
  # Hullwork also watches several projects, and only some of them have somebody depending on them.
  unmatched: human                # human | attempt
  # A closed set: tests | lint | human-merge. A misspelling is refused rather than dropped, so a
  # guardrail cannot be lost to a typo. `human-merge` is mandatory and cannot be removed, and
  # `tests` cannot be removed either once an agent is named (DR-0003: the fix *is* the test).
  #
  # **A gate must have something to run.** Naming `lint` without a `lint:` command below is
  # refused. Until item 021 it was accepted and defaulted on, and it ran nothing — for everybody.
  # Default when this key is absent: [tests, human-merge].
  #
  # Gates govern agent attempts, so with `agent: none` they are inert and unchecked.
  gates: [tests, lint, human-merge]

tests: "pytest"                     # the command that decides red and green
lint: "ruff check . && mypy ."      # the command behind the `lint` gate, if you name it

# Where a reproducing test may be created, and nowhere else. Default: `tests`.
# The agent's reproduction phase may only add NEW files under this path: a phase allowed to modify
# anything can reach a failing test by breaking working code instead of by reproducing the bug.
#
# It is **not** the guard on the fix phase, and the difference matters. This field is untrusted
# input, so narrowing it would weaken the check that stops a fix from editing pre-existing test
# code — that check uses an instance-owned pattern table instead (item 046).
test_path: tests

# What the sandbox that runs your tests is built from. Required once an agent is named:
# without it there is nowhere for `pytest` to come from, and the baseline run that must pass
# before the agent is called cannot pass at all.
#
# **The shortest correct answer is one line: the image your CI already runs your tests in.**
#
#     runtime: { base: ghcr.io/acme/ci-base:2026.7, install: none }
#
# That is the primary path, not the fallback, and it is the one that works for any language on earth
# without Hullwork learning anything about it. Nothing below is needed for it — no installer, no
# packages, no dependency files, because the image already has them. If you have such an image,
# stop reading here.
#
# The rest is **sugar for a project that has no image**: name what your project is made of and
# Hullwork writes the Dockerfile. Since item 068 all three fields are open — `base` is any image
# reference, `install` is any command, `packages` are package names — so the sugar has no ceiling
# either; it is just longer than one line. DR-0007's decision, in the operator's words: any stack
# connects.
#
# **`hullwork propose <owner/repo>` writes the whole block for you** (`--forge` for a non-default one)
# by reading the repository's
# own CI configuration (Forgejo, Gitea, GitHub Actions or GitLab CI): the container it runs in, the
# install step, the test command, the linter. `hullwork projects add` prints it unasked when the
# repository has no manifest yet. What it observed is written; what it inferred is commented out —
# read it before committing it.
#
# What replaced the closed sets is a **grammar**, and it is not cosmetic. These values are interpolated
# into Dockerfile instructions that are joined with newlines, so the character that matters is the
# newline: a `base` or an `install` containing one would append instructions of your choosing rather
# than naming an image or running a command. A package name starting with `-` would reach `apt-get
# install` as a flag. Those are refused when the manifest is read, and the message says which field.
#
# **Two things the image must be**, and they are checked at `projects add` rather than found at build
# time: it must have a shell (every phase runs `sh -lc`, so `distroless` and `scratch` are out
# permanently — that is what the harness *is*), and it must be built for the architecture this
# instance runs on. Where Docker cannot be asked — the receiver holds no socket by design — you are
# told the check did not run, rather than told it passed.
#
# The short names below stay as sugar: `python-3.12` resolves to the image this instance recommends.
runtime:
  base: python-3.12               # a short name, or any image reference: ghcr.io/acme/ci:2026.7
  install: uv                     # pip | uv | poetry | npm | pnpm | none — or your own command
  dependencies: [pyproject.toml, uv.lock]   # also the cache key: change one, the image rebuilds
  # Tools your *test command* needs that the language runtime does not provide (item 053). Empty by
  # default, so a manifest written before this field means exactly what it meant.
  #
  # Package names, installed as root at build time. Whatever you would write in your own Dockerfile:
  # `libpq-dev`, `imagemagick`, `g++`. This instance keeps a short alias table for the cases where
  # apt's name and the obvious name differ, and passes everything else through.
  #
  # **The installer is probed, not assumed**: `apt-get`, then `apk`, then `dnf` — so a Debian, an
  # Alpine and a Fedora base all work, and an image with none of the three fails saying so instead of
  # `apt-get: not found`. Three package managers cover essentially every Linux image in use; if yours
  # is the exception, put your own line in `install` or bring an image with the tools already in it.
  packages: [git]
  # A recipe has to fit the base's family — `npm` on a Python base is a manifest that cannot work, and
  # you are told at parse time. **Your own command is your business on any base**, and the build is
  # where a wrong one is found out; a failed build names the base, the install and the packages.
  #
  # Two limits on that build, because it runs as root with the network open: 900 seconds, and 8 GiB of
  # image. An install that fills your disk is your project's doing — hanging the host without saying
  # anything would be Hullwork failing to do what it promises. Raise the size with
  # HULLWORK_BUILD_SIZE_LIMIT_GIB.
  #
  # An operator can narrow all of this back down with HULLWORK_ALLOWED_BASE_IMAGES and
  # HULLWORK_ALLOWED_PACKAGES, which are empty — no narrowing — unless they say otherwise. That is for
  # somebody watching repositories they do not control, or inside a network with one reachable
  # registry.
  # Services that must be running for your test command to pass (item 052). Empty by default.
  #
  # A closed set — postgres-16 | postgres-15 | redis-7 | mysql-8 — and a name this build does not
  # know is refused at `hullwork projects add`, naming it, rather than at attempt time.
  #
  # You name a service; the instance decides what the name means. It starts one per **phase**, on an
  # internal network with no egress, with no port published to the host, and tells your suite where
  # it is: `DATABASE_URL` plus the `PG*` set for Postgres, `REDIS_URL` for Redis. Per phase and not
  # per attempt, deliberately — a database the baseline wrote to and the green gate read would make
  # "this test failed before and passes after" a comparison of two different databases.
  #
  # The database is blank. This unblocks "the suite creates its own schema against an empty server";
  # it does not unblock "the suite expects a seeded database", which is your fixtures' job.
  services: [postgres-16]

health_url: https://demo.example.com/health   # registered with the watchdog

notify:
  channel: console                # none | console | telegram | email
                                  # telegram and email parse but are not deliverable yet
```

## Settled: any project, any stack (DR-0007, ACCEPTED 2026-07-31)

`base`, `install` and `packages` were closed sets until item 068, which meant this file could only
describe Python 3.12/3.13 and Node 22/24 projects. DR-0007
is accepted and built: the three fields keep their names and are no longer enumerations. What the
instance holds instead is a policy — `HULLWORK_ALLOWED_BASE_IMAGES` and `HULLWORK_ALLOWED_PACKAGES`,
empty by default — so narrowing is the operator's decision rather than the schema's.

**The order of the two paths is the part worth reading.** The agnostic one is primary: a project
brings its own image, or Hullwork reads the file that already describes one (`hullwork propose`).
`install` and `packages` are sugar for projects with no image, and sugar is allowed to be
incomplete. That ordering is what makes this a translation rather than a treadmill — the formats
that describe an environment are about three and language-neutral, while ecosystems are about fifty
and keep arriving.

**The one frontier that will not move**: any Linux image with a shell, on this instance's
architecture. Both are checked when you register, and `distroless`/`scratch` are permanently out.

`services` is deliberately not in scope: it is a closed set, and a name this build does not know is
refused at `hullwork projects add` naming it.

## Settled since this file was first written

- **Versioning**: `version:` is optional and an absent value means 1, permanently. A manifest
  claiming a higher version than the running Hullwork understands is refused with a message saying
  so, rather than a wall of complaints about fields that do not exist yet (item 020).
- **`autofix.trigger` will not exist.** A manifest cannot make anything happen at 02:00 — only a
  scheduler can — so the field would describe configuration it cannot enforce. When an attempt runs
  is a line in the operator's crontab; whether one may run at all is `agent` and the lanes
  (spec M2 §1.1).
- **An agent is named, never supplied.** There is no way to put a command in this file that the
  Hullwork host will execute. Commands in this file (`tests`, `lint`) run **inside the sandbox**, on
  the repository's own code, which the sandbox already executes by design (item 017, spec M2 §4).
- **`install: pip` is refused unless the first dependency file is a `.txt`.** `pip` means
  `pip install -r`, and `-r` reads a requirements file; handed a `pyproject.toml` it answers
  `Invalid requirement: '[build-system]'`. This repository's own manifest declared exactly that
  combination for weeks and nobody noticed, because nothing ever built the image — so the parser
  refuses the combination now, where it costs nothing to fix (item 051). Use `uv` or `poetry` for a
  pyproject or a lock file.
- **An installer has to fit its base**, and a mismatch is refused at parse time rather than
  discovered at attempt time: `pip`, `uv`, `poetry` and `none` for a Python base; `npm`, `pnpm` and
  `none` for Node. And any installer other than `none` needs at least one dependency file.

## Open questions

- Per-lane attempt caps and budgets (inherit instance defaults vs. per-repo).
- Whether `deploy` becomes actionable (smoke + rollback lane) or stays informational.
- Secrets discovery convention for the sandboxed test environment.
