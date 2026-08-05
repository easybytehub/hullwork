# Contributing

This repository is in private pre-alpha development by [EasyByte](https://easybyte.es). External
contributions open when the repo does.

## Conventions

- English everywhere: code, comments, commits, issues.
- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`…).
- Definition of done: `ruff check . && mypy . && pytest` green. No exceptions.
- **`uv.lock` is the source of truth and CI installs from it**: `uv sync --frozen --extra dev`,
  exactly what the workflow runs, so the gates you see are the gates it sees. A dependency change is a
  reviewed commit to the lock rather than whatever PyPI served that morning. `.python-version` pins
  the interpreter for the same reason — the lock alone resolved 3.13 while CI said 3.12, and those are
  not the same environment.
- `pip install -e ".[dev]"` still works and is fine for a quick look. It resolves fresh, so if it ever
  disagrees with CI, the lock is right and your resolution is the difference.
- **Run `pytest` on a host that has Docker, and read the skip lines.** The sandbox tests are marked
  `needs_docker` and skip silently without a daemon, so a green run on a machine without one has not
  exercised the part of this product that builds containers. CI says so in its own log now, because
  two of those tests were broken for an unknown length of time and the person who found out was a
  stranger evaluating the product rather than anybody here.
- They touch **host-global Docker state**. A test that leaves a volume or a network behind poisons
  the next run *in any checkout on that machine* — that is how the two above hid each other. If you
  add one, clean up in a `finally`, and label what you create so the reaper can tell it from a live
  attempt's debris.
- Every inbound surface (webhook, API endpoint) ships with its threat model noted in the PR description.
- Specs before code, per the project's constitution.

## Signing off your work

We use the [Developer Certificate of Origin](https://developercertificate.org/) 1.1 — the full text is
in [`DCO`](DCO). Sign off every commit:

```bash
git commit -s
```

That appends a `Signed-off-by: Your Name <your@email>` line, which is your statement that you wrote the
contribution or otherwise have the right to submit it. CI checks the trailer on pull requests.

The pull request template carries the other half: a licence grant that lets us ship your contribution as
part of Hullwork. You keep ownership of your work. Together, the sign-off and that grant are the whole
agreement.

### Why no CLA

**There is no form to sign, no bot, and no service collecting your signature.** We looked hard at the
alternative and decided against it, so here is the reasoning rather than just the rule:

- The authors of the licence this project ships under (Sentry, who wrote the FSL) do not use a CLA either.
- A CLA is not actually enforceable on Forgejo — the usual signature service is GitHub-only and declined
  support for other forges years ago. Adopting one would mean either building that infrastructure or
  quietly making the GitHub mirror the real home of contributions.
- The ecosystem this project lives in — Forgejo, Gitea, GitLab's open code — runs on DCO. Asking for a
  signed agreement where you expect `git commit -s` is friction we would rather not add.

The full decision record, including what this trade-off costs us, is DR-0001 — kept in the
project's own repository rather than published, and available on request.

One honest wrinkle: the DCO text says "open source license", and the FSL is source-available rather than
OSI-approved. The licence "indicated in the file" for this project is the FSL — that is what you are
certifying you have the right to submit under, and it is why the grant in the pull request template
exists alongside the sign-off.

### Contributions written with an AI agent

Allowed, and we do it ourselves — this project is built partly by its own worker. Two rules:

- Credit the tool with a `Co-Authored-By:` trailer.
- **The sign-off is yours, not the agent's.** A `Signed-off-by` line means a human read the change and
  takes responsibility for it. An agent cannot certify provenance; you can.
