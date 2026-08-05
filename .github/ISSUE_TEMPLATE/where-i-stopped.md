---
name: Where I stopped
about: You tried Hullwork and hit a wall. This is the most useful issue you can open.
title: "friction: "
labels:
  - friction
---

<!-- Nothing here is required. A single sentence in the first box is a complete report and more
     useful than a polished one you never send. -->

## Where did you stop, and why?

<!-- The one question this project cannot answer from the inside. "The compose file needed a
     variable I did not have" is a finding. "It didn't work" is one too — say that and stop. -->

## What did you expect to happen instead?

## What did you run, and what came back?

```
$ hullwork …

```

<!-- These three answer almost everything, and none of them needs a credential:

       hullwork config     what this process actually received
       hullwork doctor     what it thinks is broken
       hullwork status     how it is, and its exit code

     Paste them if they say anything. `config` redacts every secret to `set` / `not set`, so it is
     safe to paste whole — if you find a value in there that should not be, that is a security
     report and SECURITY.md is the faster route. -->

## Your setup

- Host / OS and architecture:
- Docker version (`docker version --format '{{.Server.Version}}'`):
- Forge, if you got that far (Forgejo / Gitea / GitHub / GitLab / none):
- Model provider, if you got that far:

---

**Why this template exists.** Until 2026-08-04 nobody outside this project had installed Hullwork, so
every claim about its friction was measured on the person who wrote it — the weakest possible
evidence. The first outside attempt stopped before reaching the product at all, and produced nineteen
findings that no amount of internal review had surfaced. A wall you hit and did not report is a wall
the next person hits too.

Please do **not** paste tokens, API keys, `deploy.env`, or a page URL: a page URL *is* a credential.
