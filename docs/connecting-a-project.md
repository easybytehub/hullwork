# Connecting a project — any project, in any language

**Hullwork does not need to know your stack.** It needs a container image with a shell in it, and the
commands that test and lint your code. Everything else is sugar.

## The manifest

The whole thing, for a project that already has a CI image:

```yaml
project: myproject
git: { provider: forgejo, repo: owner/myproject }
tests: make test
lint: make lint
runtime: { base: ghcr.io/acme/ci-base:2026.7, install: none }
```

That works for Go, Rust, Ruby, PHP, Elixir, Java or anything else, today, without a line of Hullwork
changing — because it names an *environment* instead of describing an *ecosystem*. If your project has
no such image, `runtime.install` and `runtime.packages` build one (any command, any package, three
package managers probed in turn), which is longer but not narrower.

The one permanent limit: a Linux image with a shell, on this instance's architecture. `distroless` and
`scratch` never will work, because every phase runs `sh -lc`.

Every field is in **[hullwork-yml.md](hullwork-yml.md)**.

## You do not have to write it from scratch

Hullwork reads the file that already answers most of this — your CI configuration:

```bash
hullwork propose --checkout .            # a local directory, no credential
hullwork propose owner/myproject         # or a repository on your forge
# Reads .forgejo/ .gitea/ .github/workflows/ or .gitlab-ci.yml and prints a manifest:
# the container it runs in, the install step, the test command, the linter.
```

What it observed is written; what it could only infer is commented out with what was seen, so you can
tell the two apart before committing it. It **prints** and never writes: a manifest belongs in your
repository, committed by somebody who read it.

## Registering

```bash
hullwork projects add --slug myproject --repo owner/myproject
# --forge defaults to forgejo; gitea, github and gitlab are the others. The adapter is chosen from
# HULLWORK_FORGE_URL, plus HULLWORK_FORGE_KIND — a self-hosted GitLab and a self-hosted Forgejo
# look identical in a URL.
```

If the repository has no `hullwork.yml` yet, `projects add` prints the proposal itself rather than just
refusing. A refusal that could have shown you the answer is a bad refusal.

It reads the manifest from the repository's **default branch**, refuses to register anything whose
manifest does not validate, refuses an engine name this instance does not hold, checks the base image
can host a phase — it needs a shell, and it must match this host's architecture; you are told when that
could not be checked rather than told it passed — and prints a webhook URL:

```
Registered 'myproject' (owner/myproject on forgejo).
  Manifest read and valid. Lanes: 2 green, 1 amber, 3 red. Agent: none.

  This URL is the credential. It is shown once and cannot be recovered:

    https://hullwork.example.com/webhooks/glitchtip/myproject/<token>
```

## That URL is a bearer credential

GlitchTip cannot sign its webhooks — there is no header, no secret, no setting that enables one — so the
token in the path is what authenticates the sender. It is shown once, stored only as a hash, and
replaceable at any time:

```bash
hullwork projects rotate-secret myproject
```

⚠️ **A secret in a URL ends up in access logs.** Yours, your reverse proxy's, and possibly your error
tracker's outbound logs. That is inherent to the mechanism, not a bug anybody can fix, so plan for it:
exclude `/webhooks/` from access logging (or run uvicorn with `--no-access-log`), and rotate the token
if logs are ever shared. Hullwork's own structured logs redact it; it cannot reach into your proxy.

Sentry signs its webhooks properly and would be verified by HMAC. That route is **not enabled** — see
[status.md](status.md) for why.

### Where that URL goes

Into an alert on your tracker whose recipient is a **webhook**, pointed at the URL the CLI printed.
Hullwork is the receiver; nothing polls, so until that alert exists no error can arrive.

In GlitchTip that is an alert on the project with one webhook recipient. Through its API, which is what
we use, because clicking it is not repeatable:

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"hullwork","timespanMinutes":1,"quantity":1,"uptime":false,
       "alertRecipients":[{"recipientType":"webhook","url":"<the URL projects add printed>"}]}' \
  "$GLITCHTIP/api/0/projects/<org>/<project>/alerts/1/"
```

Two things about that call cost us time and are in [deployment-notes.md](deployment-notes.md): the
recipient key is **camelCase** and snake_case is rejected with a 422, and an empty `POST` to the same
endpoint creates an alert with null fields instead of failing — so check what you created rather than
trusting the status code.

Then make something fail. `hullwork status` counts deliveries, and `doctor` says whether any arrived —
which is how you tell "no errors yet" from "the alert was never wired".

## The lane policy, before you hand anything over

This instance has its own opinion about which code is dangerous, read from the path an error came from
rather than from a list you maintain. Read it applied to your own tree first, with no credential:

```bash
hullwork projects lanes --checkout .
```

`autofix.lanes` in your manifest is an override, empty by default, and `autofix.lanes.ordinary` is how
you tell an instance it read your layout wrong.

## The rest of the commands

```bash
hullwork projects list
hullwork projects disable <slug>    # deactivates; never deletes history
hullwork projects refresh <slug>    # adopt an edited manifest
```

`refresh` prints what changed in `base`, `install` and `packages` before adopting it, because the
manifest is **adopted, not followed**: nothing re-reads it from your forge in order to act, so a
repository cannot change what your host builds behind your back
(DR-0012).

An operator who cannot commit to a repository can hand the same file over instead:

```bash
hullwork projects add --slug myproject --repo owner/myproject --manifest ./their-hullwork.yml
```

The instance then says, wherever it lists that project, that the manifest came from an operator rather
than from the repository.
