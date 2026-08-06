# Deploying Hullwork next to a self-hosted error tracker

> **The installation procedure is not here.** It lives in
> [install.md § 3](install.md#3-a-real-deployment), as seven ordered steps, and this document used to
> hold a copy of it — two copies of one sequence is how a sequence drifts. What is here is what to read
> **when one of those steps does not behave**, ordered by how likely that is.
>
> Four things the procedure states without arguing, argued here because each was measured:
>
> **The socket mount on `init`** (item 135). `init` reads the Docker socket's group off *this* host so
> the dispatcher can open it later, and it runs in a container — without that volume it cannot see the
> host's socket, writes a placeholder, and every attempt later fails while building its sandbox.
> Measured: with the mount it wrote `989`, without it a placeholder.
>
> **`up -d` starts one container** (item 135). The dispatcher sits behind a profile because it refuses
> to start without a model key — correctly, and `restart: unless-stopped` used to turn that refusal into
> a crash loop on every first installation.
>
> **`--user "$(id -u)"` on `init`** (item 127). The image runs as uid 10001 and your directory does not
> belong to it; without it, `init` refuses with the `chown` you would need. Measured on the first
> installation nobody arranged in advance.
>
> **The two `BUILD_` variables** (item 127), because the deployment directory is not the checkout:
> `BUILD_SOURCE` is where the image is built from, and `BUILD_EXTRAS=[telemetry]` is what makes
> `HULLWORK_ERROR_DSN` usable — set the DSN without it and the receiver refuses to start, deliberately,
> rather than pretend it is being watched.

The quickstart in the README is an evaluation stack: one command, loopback, SQLite. This is what
changes when you put it on a real box, written from doing it on the deployment host with GlitchTip on
2026-07-27. **Every problem below was found by deploying, not by reasoning** — the test suite was
fully green throughout.

## The short version

Three things bite when the tracker and Hullwork live on the same private network:

1. GlitchTip refuses to send webhooks to private IPs.
2. A container does not inherit your VPN's DNS.
3. Resolving an address is not the same as having a route to it.

## 1. GlitchTip will not call a private address

Its outbound webhooks go through an SSRF check (`glitchtip/url_validation.py`) that rejects private,
loopback, link-local, reserved and multicast targets. If Hullwork is on `10.x`, `172.16.x` or
`192.168.x`, the alert simply refuses to save with *"URLs targeting private or internal IPs are not
allowed"*.

There is a flag for it:

```yaml
GLITCHTIP_ALLOW_PRIVATE_IPS: "True"
```

**Understand what you are turning off.** That check exists to stop somebody with an account using
webhook alerts to probe your internal network — cloud metadata endpoints, admin panels, anything on
loopback. Enabling it is defensible on a single-operator instance with registration closed and no
access from outside. On a shared instance it is an exfiltration channel with a nice UI.

The alternative, if you would rather not: give Hullwork a publicly resolvable hostname with TLS in
front and let the webhook go out and back in. More moving parts, no flag.

## 2. Containers do not inherit VPN DNS

If your forge lives on a VPN name (ours is on Tailscale MagicDNS), the container will not resolve it:
Docker hands containers its own resolver, not the host's. Point it at the VPN resolver:

```yaml
dns:
  - 100.100.100.100   # Tailscale MagicDNS
```

The symptom is a `RetryableForgeError` and a log line saying the forge is unavailable, which reads
like the forge being down rather than like DNS.

## 3. Resolving is not routing

Fixing DNS gets you a correct IP that the container still cannot reach: it sits on Docker's bridge
network with no route into the VPN. The fix we used is host networking:

```yaml
network_mode: host
command: ["uvicorn", "hullwork.main:app", "--host", "10.0.0.5", "--port", "8000"]
```

**Bind explicitly to the VPN address.** With `network_mode: host` there is no port mapping left to
protect you, and the machine has a public IP — `--host 0.0.0.0` would publish your webhook endpoint,
token and all, to the internet. The healthcheck has to be overridden to match, since the one baked
into the image assumes port 8000.

## Production compose, in full

```yaml
services:
  api:
    build: .
    image: hullwork:dev
    network_mode: host
    # Keep --no-access-log: the webhook token is a path segment (see "Access logs" below).
    command: ["uvicorn", "hullwork.main:app", "--host", "10.0.0.5", "--port", "8000",
              "--no-access-log"]
    healthcheck:
      # /ready, not /health: the second can never fail, so it reports a healthy container
      # with a dead subsystem behind it. See "Knowing it broke" below.
      test: ["CMD", "python", "-c", "import urllib.request as r; r.urlopen('http://10.0.0.5:8000/ready').read()"]
      interval: 30s
      timeout: 5s
      start_period: 10s
    restart: unless-stopped
    environment:
      HULLWORK_BASE_URL: "http://10.0.0.5:8000"
      HULLWORK_FORGE_URL: "https://forge.internal"
      HULLWORK_FORGE_TOKEN: "…"
      HULLWORK_LOG_FORMAT: "json"
    volumes:
      - hullwork-data:/data

volumes:
  hullwork-data:
```

Keep the credentials in a `.env` beside it with mode 600, not in the compose file.

## The two credentials, and the one that surprised us

Hullwork holds two forge credentials and they are not interchangeable. This table is the whole
arrangement:

| | `HULLWORK_FORGE_TOKEN` (ingest) | `HULLWORK_FORGE_CODE_TOKEN` (dispatcher) |
|---|---|---|
| Held by | the always-on service — in memory whenever it is up, reachable by anything that reaches the webhook path | the `hullwork work` command, which exits |
| Needs | `read:repository` + `write:issue` | `write:repository` |
| Must **not** have | `write:repository` | — |
| Where it goes | the service's environment | a separate file, mode 600, read only by the dispatcher |
| Unset means | issues are queued in the database and filed when it arrives | no fixes are attempted, which is the default |

**Check that the first one really cannot push, because ours could.** `config.py` has promised in
writing since M1 that the ingest credential "should never be able to push". The code was built
around that sentence — two protocols, two classes, deliberately no code-write verb on the ingest one
— and on our own deployment the token behind it created a branch and committed to the default branch
on the first try. The guarantee was in the source and not in the credential.

`hullwork status` now asks the forge on every run and says so. Two things it cannot tell you, so
they are said here instead:

- It reads `permissions.push`, which is the **account's** access to that repository. A token's
  scope is a second layer underneath, and no Forgejo endpoint *declares* a token's own scope to the
  token. So "no" is trustworthy and "yes" is only half an answer.

  **This paragraph used to say more than it could support, and the correction is worth reading
  before you act on a warning.** It reported a push-capable account as *"the ingest credential CAN
  write code — the credential split for this project is a fiction"*, and on 2026-07-29 that was
  measured false on this very deployment: the account is an owner, and the token, scoped to reads
  and issues, is refused with `token does not have at least one of required scope(s):
  [write:repository]`. The split was real; the check could not see it. So a scope-limited token gets
  a warning it can never clear, and until item 073 that warning also failed `hullwork status` — a
  signal that is permanently on is not a signal, so it no longer affects the exit code.

  To find out which of the two you actually have, ask the forge for something only a code scope
  allows and read the refusal. A `403` naming `write:repository` means your token is correct
  whatever the warning says. **`status` now asks that question itself**, on both forges, with a
  request whose successful form does not exist — so a correctly scoped token is silent rather than
  warned at. On GitHub the answer only became askable in item 131: GitHub's `permissions` block
  reports the account's role and never the token's grants, so until then the audit said *"could not
  confirm that the ingest credential is unable to push — treat it as unknown, not as safe"*, which
  was the honest thing to say and impossible to clear.
- On Forgejo there is no code-only scope to trim: `write:repository` is the finest grain and also
  grants releases, webhooks and deploy keys. The split has to be made by **leaving it out** of the
  ingest token, not by narrowing it. Tokens can be limited to named repositories, which is the
  containment that does exist and is worth using for both.

The arrangement to aim for, cheapest first: **an ingest token without `write:repository`**, on the
account you already have. That is one screen in the web interface and it is what actually stops the
push — measured above. A dedicated machine account with pull-only access is stronger, because it
holds regardless of how the token is later edited, but it is a second identity to provision and the
earlier version of this page prescribed it as if it were the only option. Minting a token needs basic
auth in the web interface — a token cannot mint a token — so either way it is a job for a human, once.

## Turning on the second program, which is not a flag

`docker compose up` gives you ingest, deduplication, triage and issues. It does **not** attempt
fixes, and there is no setting that makes it: attempting a fix needs the Docker daemon, and a
long-lived network-reachable service with access to the Docker socket is root-equivalent on its host.

So Hullwork is two programs (spec M2 §1), and turning on the second one is **a second service in the
same compose file** — not a separate installation:

```bash
docker compose up -d dispatcher
```

It runs from the image you already built, so there is one version of the code and `docker image
inspect` can name it. `restart: unless-stopped` brings it back after a reboot without anybody
logging in.

> [!warning] **Your compose file is not the one in the repository root, and a deploy will overwrite
> it.** The root `docker-compose.yml` is the evaluation stack: loopback, no dispatcher, no
> `HULLWORK_ERROR_DSN`. A real deployment keeps its own beside it — this one is
> `the compose file `hullwork init` writes` — and copies it into place. Any file-syncing deploy (`rsync`,
> `git pull`) puts the evaluation file back on top of it, so **the copy is part of every deploy,
> not part of the first one**:
>
> ```bash
> rsync -a --exclude .git --exclude .venv ./ host:/opt/hullwork/
> ssh host 'cd /opt/hullwork \
>   && cp the compose file `hullwork init` writes docker-compose.yml \
>   && docker compose --env-file deploy.env up -d --build'
> ```
>
> **Measured on 2026-08-01**, by leaving the `cp` out of exactly one deploy: `up -d` recreated the
> receiver from the evaluation file, which silently dropped its error DSN — the instance came up
> healthy and `hullwork status` said `error reporting: off`. Nothing failed; a capability just went
> quiet. That line in `status` is what caught it, which is the argument for printing capabilities
> rather than only failures.

> [!warning] **No `--delete`, and no `-a` as root.** The deployment directory is not only a copy of
> the repository: it holds `deploy.env`, the database backups, and the directory the dispatcher
> bind-mounts its model credential from. `rsync --delete` removes every one of them — measured
> twice, on 2026-07-30 and again on **2026-08-02**, when it took out `model-credential/` and the
> dispatcher went into a restart loop saying, correctly, that there was no credential to read.
>
> Two things about recovering from that are worth knowing:
>
> * **Recreating the directory is not enough.** The bind mount resolves to the inode the container
>   was created with, so `docker compose up -d dispatcher` starts the *same* container against the
>   deleted directory and fails identically. It takes `up -d --force-recreate dispatcher`.
> * **`rsync -a` over `ssh root@` copies your laptop's uid/gid**, so the whole tree ends up owned by
>   a user that does not exist on the host — which breaks the refresh job that has to write into it.
>   Sync without `-o -g` (`rsync -rlptD` does it), or `chown -R root:root` afterwards **and then put
>   the credential's group back**.
> * **`chown -R root:root` breaks the model credential, and this file used to recommend it without
>   saying so.** Measured 2026-08-03, on this deployment: the dispatcher reads
>   `model-credential/.credentials.json` as group `MODEL_CREDENTIALS_GID` (1000 here, via
>   `group_add`), and the file is mode 640 — so moving it to group 0 makes it unreadable and the
>   dispatcher refuses to start with `Permission denied`, correctly and permanently. The fix is
>   `chown root:1000 model-credential model-credential/.credentials.json`, 750 on the directory and
>   640 on the file. It looks like the expiry failure and is not: an expired token comes back on its
>   own, and this one never does.

## The read-only page, and who can open it

`hullwork status` answers you at a terminal. Nothing answered a teammate until item 122, and the
page it added is **off until you turn it on**:

```bash
hullwork page-token
```

It prints one URL, once, and stores only its hash. That URL is the credential — anyone who has it
reads every item, attempt and captured output this instance holds, and nothing behind it changes
anything. `hullwork page-token --rotate` replaces it and breaks every link handed out so far.

Three views, and every link between them is relative so that the token is never written into the
HTML — a saved page, a screenshot of the source or a copy mailed to a colleague carries no key:

| | |
|---|---|
| `…/page/<token>/` | what `hullwork status` prints, from the same functions |
| `…/page/<token>/items` | every item, most recently seen first, bounded and saying so |
| `…/page/<token>/items/<id>` | the item, and for each attempt **the artefact it published** |

The last one is the reason the page exists: it is `evidence.pull_request_body` — or
`issue_comment`, for an attempt that opened no pull request — rendered from the recorded steps by
the same function that wrote the forge's copy. Two parts of that document are not stored (item
079), the agent's prose and the brief it was given; the page says so rather than presenting the
remainder as the whole. Attempts that never reached a forge, such as a baseline-red one, are
readable here and nowhere else.

Three things about it are deliberate and worth knowing before you expose it:

* **It is on the receiver**, because the dispatcher listens on nothing and that is what lets it hold
  a credential that can push. So the page sits on the half of Hullwork your tracker has to be able
  to reach — which, with a hosted tracker, is a public address.
* **Everything without the token gets `404`**, including a wrong token, so the page cannot be found
  by probing. `hullwork status` prints `page: on` or `page: off`, because otherwise nothing could
  tell you whether the door exists.
* **The token is a path segment.** Put a reverse proxy with TLS in front before handing the URL to
  anybody: over plain HTTP it is on the wire in the clear. Responses carry `Referrer-Policy:
  no-referrer` so that following a link out does not hand the token to the site being linked to.
  The receiver already runs with `--no-access-log` for the webhook's sake, which keeps this one out
  of the logs too — and since item 123 the scrubber blanks `/page/<token>` on the way to an error
  tracker, which is where it was still reaching until somebody looked.

**This page used to prescribe a virtualenv on the host and `pip install -e /opt/hullwork`, and that
is what item 076 exists to remove.** What that produced, measured on the live instance: an *editable*
install pointing at a directory that was not a git checkout, so the running code was whatever had
last been copied there by hand, reporting `0.1.0.dev0` for every state it had ever been in — a
version string that cannot identify code. It was also started with `nohup setsid`, which survives the
SSH session that typed it and nothing else: the receiver came back after a reboot and the dispatcher
did not, silently.

**What made the container look impossible was a sentence on this page, and it was stale.** It said a
socket mount *"would defeat the sandbox silently anyway — a bind mount of a path the daemon cannot see
yields an empty directory and exit 0"*. The observation is right and the conclusion was backwards: the
fix is not to keep the dispatcher on the host, it is to stop bind mounting. Item 055 moved the
worktree to a named volume seeded with `docker cp` (a tar stream over the socket, no path for the
daemon to resolve), item 082 did the contract, and item 089 did the last two — the gateway's
credential and its journal. Measured with the defect deliberately restored inside the container: the
daemon creates a *directory* called `credential`, the gateway opens it as a file, and it dies before
it listens. Every attempt would be abandoned with a message about the network.

**Two prerequisites the container does not remove.**

**The image must be present on the daemon**, because the recording gateway runs from it — the gateway
*is* Hullwork code and needs the package and its HTTP client (`sandbox/net.py:GATEWAY_IMAGE`,
`hullwork:dev`). `docker compose up -d --build` gives you this for free on the same host, and it is a
missing prerequisite if the daemon is elsewhere. It fails loudly at `docker run` rather than quietly.

**The two programs must open the same database, and the path is not the same string on both sides.**
Inside the containers it is the volume's mount point; from the host — where you run `hullwork doctor`
and `hullwork status` — it is the volume's path on the host, four slashes, because an absolute path in
a SQLite URL needs its own leading one:

```bash
# .env, for CLI runs on the host
HULLWORK_DATABASE_URL=sqlite:////var/lib/docker/volumes/hullwork_hullwork-data/_data/hullwork.db
```

Leave that out and SQLite creates an empty `hullwork.db` in whatever directory you were standing in,
and every command answers about *that* file. `readiness` passes it — writable, plenty of disk — which
is why `hullwork doctor` checks for the tables instead, and why `work --loop` now refuses to start
against a schema it does not recognise rather than claiming items in it. On Postgres none of this
arises, which is one more reason it is the production answer.

**Migrations belong to the receiver, and the wheel deliberately contains none.**
`[tool.hatch.build.targets.wheel] packages = ["hullwork"]` means the wheel is the package: no
`migrations/`, no `alembic.ini`. That is not an omission to fix. The image copies both separately and
runs `alembic upgrade head` in its entrypoint, for the reason written there — *"the app should not be
deciding to alter its own database, and with more than one replica they would race each other doing
it"*. So the receiver owns the schema and the dispatcher only uses it, which is why the dispatcher's
answer to an unrecognised schema is to refuse rather than to migrate. If you add migrations to the
wheel to make that refusal go away, you have given two programs the right to alter one schema.

### Trying it before you trust it

`hullwork work --no-publish` runs the whole sequence and publishes nothing (item 049,
DR-0006). Every gate runs — the baseline must pass, the red
gate must fail *as a reproduction*, the green gate must pass, the lint gate must pass — and the
artefact is written to disk and printed to the terminal instead of opened as a pull request. The item
goes back in the queue and **the attempt is not consumed**, so this costs you nothing but wall clock.

It clones with `HULLWORK_FORGE_TOKEN`, the read credential, and refuses to start if you have not set
it. It does **not** need `HULLWORK_FORGE_CODE_TOKEN`: evaluating the fix half must not require a
credential that can write anywhere, which is the whole point of the mode.

```bash
set -a; . /etc/hullwork/dispatcher.env; set +a
hullwork work --no-publish --project myproject
```

Budget **tens of minutes**: two agent phases plus four suite runs, and the first run also builds the
sandbox image. `HULLWORK_LOG_FORMAT=console` makes it readable while you watch.

It needs three things the service deliberately does not have, and it says so if you run it without
them:

| | Why the service does not have it |
|---|---|
| `HULLWORK_FORGE_CODE_TOKEN` | one flaw in the webhook receiver would otherwise reach a credential that can push |
| `HULLWORK_MODEL_KEY` (any provider) | the always-on process has no reason to hold a model credential |
| The Docker daemon | see above: the socket is root on the host |

Its own environment file, separate from the service's, because the point of the split is that these
two sets of variables never sit in one place:

```bash
sudo install -m 600 /dev/null /etc/hullwork/dispatcher.env
sudo tee /etc/hullwork/dispatcher.env >/dev/null <<'EOF'
HULLWORK_DATABASE_URL=postgresql+psycopg://hullwork:...@127.0.0.1/hullwork
HULLWORK_FORGE_URL=https://forgejo.example
HULLWORK_FORGE_TOKEN=...          # ingest: it comments on the issue, which the code token cannot
HULLWORK_FORGE_CODE_TOKEN=...     # code: branches, commits, pull requests
HULLWORK_MODEL_ENDPOINT=https://api.anthropic.com
HULLWORK_MODEL_AUTH_STYLE=x-api-key
HULLWORK_MODEL_NAME=...           # pinned, so a different model answering is a recorded violation
HULLWORK_MODEL_KEY=...
# Optional. How many turns the agent gets per phase, overriding the engine's own default (30).
# The only real bound on what one attempt can spend — two phases at this ceiling, plus four gate
# runs. Measured on this repository: an attempt that used all thirty cost ~26,000 output tokens.
# HULLWORK_MAX_TURNS=60
#
# Optional, and the one to set first if you are on a prepaid balance (item 137). A ceiling on
# what ONE attempt may spend, in tokens, counting everything the wire reported. The gateway stops
# forwarding once it is crossed, and the attempt ends `abandoned` **without consuming the item** —
# so it is safe to set low and raise on measurement. Unset means no ceiling.
#
# It binds on what the wire reports, and SOME ENDPOINTS REPORT NOTHING. Measured against
# OpenRouter's Anthropic-compatible route: streamed messages carry a zeroed `usage`, and one
# attempt spent 1.2M cache-read tokens under a 1M ceiling without it noticing. The seal says
# `null` for what it could not see and lists the categories in `unmeasured` — empty means the
# ceiling was real, populated means it was decorative. Read that before trusting this number.
# HULLWORK_MAX_ATTEMPT_TOKENS=4000000
#
# Optional. Models that may answer, beyond the pinned one — comma-separated. A different question
# from MODEL_NAME, which says what to *ask for*. Empty keeps DR-0002's rule exactly: only the
# pinned name is acceptable. Set it when a provider aliases model names, or you keep a fallback.
# HULLWORK_MODEL_ALLOWED=
#
# Optional, and the only way money ever appears (item 133). What YOU pay, per million tokens, one
# price per billing category — they differ by an order of magnitude, so one number would be a lie.
# No price table ships with Hullwork and none will: DR-0004 privileges no provider, a bundled list
# goes stale on the first repricing, and an instance printing a *wrong* cost is worse than one
# printing tokens. Unset means `status` reports tokens and duration and no figure.
# HULLWORK_MODEL_PRICE_INPUT=
# HULLWORK_MODEL_PRICE_OUTPUT=
# HULLWORK_MODEL_PRICE_CACHE_WRITE=
# HULLWORK_MODEL_PRICE_CACHE_READ=
# HULLWORK_MODEL_PRICE_CURRENCY=USD
EOF
```

> [!warning] Enumerate every one of these in your compose file, or they cannot arrive.
> A compose `environment:` block lists variables one at a time, so a setting named in your env
> file and **not** in the compose is silently dropped — it is set, and the process never sees it.
> Measured on both of this project's own instances on 2026-08-04: the seven settings above had
> been added by items 133 and 137, neither compose enumerated them, and the cost ceiling was
> therefore unreachable from any installation that had one.
>
> `hullwork doctor --env-file <file> --compose-file <file>` compares the two lists and names what
> is assigned in one and absent from the other. Run it **from the host**, against the paths as the
> host sees them — inside the container neither file exists, which is why nobody had run it.

Both tokens, on purpose. Measured on GitHub: a `contents`+`pull_requests` token gets **403**
commenting on an issue, and DR-0003 makes that comment a first-class outcome — `not-reproducible` is
an answer, and an answer only a database can see is one nobody acts on.

### The schedule is yours

There is no `trigger:` field in the manifest and there will not be one. A file in a repository
cannot make anything happen at 02:00; only a scheduler can, and a field that *describes*
configuration it cannot *enforce* is the decorative guardrail this project keeps deleting.

```cron
# Attempt one item a night, and mail the operator if the run could not do its job.
17 2 * * *  set -a; . /etc/hullwork/dispatcher.env; set +a; hullwork work --limit 1
# Once a week, free anything whose dispatcher was killed mid-attempt. The attempt record survives.
23 4 * * 0  set -a; . /etc/hullwork/dispatcher.env; set +a; hullwork work --release-stale
```

`set -a; . file; set +a` rather than cron's own `EnvironmentFile`, because cron does not have one.
The exit code is the answer, as it is for `hullwork status`: zero means the run did what it was
scheduled to do, and non-zero means it did not — including the case where items are waiting and
something in the configuration means nothing will ever pick them up.

### The dispatcher is a container, and it is not isolated from your host

**Corrected 2026-08-01.** This section used to say Hullwork ships no dispatcher container and never
will. It ships one — `the compose file `hullwork init` writes`, since item 082 — so the paragraph was
describing a product that had stopped existing, in the document an operator uses to deploy it.

What has not changed is the trade, and it is the part worth reading twice:

> **A container with `/var/run/docker.sock` mounted is not isolated from its host.** That socket is
> root: anything holding it can start a container that mounts `/`. The dispatcher is *the component
> whose entire job is running other people's code*, so putting it in a container buys you process
> hygiene, restart-on-boot and one version of the code — **not** a security boundary.

So the rule is about the **host**, not about the container: run this where you accept that
Hullwork's dispatcher is effectively root. The sandbox boundary is a real one and it is somewhere
else entirely — it protects you from the *watched project's* code and from the agent, which run in a
container that has no socket, no network but the gateway, and no credential.

The receiver is the other half of the split and it holds neither the socket nor the code token,
by design (DR-0009, spec M2 §1). It refuses to start holding the code token at all.

### What it checks about its own network, every time

Before the model is called, the dispatcher creates an internal Docker network, attaches the **gateway**
to it (a container of its own, on that network and on the bridge, holding the key), and
then **probes the network from inside it**: the gateway must answer and `api.anthropic.com` must
not. A failure abandons the attempt without consuming it, because a misconfigured network says
nothing about whether the bug is reproducible.

Two things worth knowing about that arrangement:

- **The gateway holds the model credential and is bound off loopback**, because the sandbox has to
  reach it. What pays for that is a caller allowlist: it answers loopback and the cable's addresses,
  and returns 403 to everything else. Verified by effect from a LAN address.
- **On Linux, a container on an internal network can still reach other daemons on the host** that
  are bound to `0.0.0.0` — Docker documents it. That is the one thing `internal: true` leaves open,
  and it is worth being exact about what was measured from inside a sandbox on the live host:
  the internet, Hullwork's receiver and the tracker are all unreachable; **the host is reachable
  through the bridge's own gateway address, SSH included**.

  It is host configuration rather than something the tool installs. Not out of caution — item 082
  makes it impossible: the dispatcher is a container now, and rewriting the host's firewall from
  inside one needs `NET_ADMIN` on the host's network namespace, which is a bigger prize than the hole
  it closes. Host configuration is also the *better* control: it cannot be forgotten by a code path
  and it covers attempts this dispatcher has not thought of.

  ```
  # /etc/ufw/before.rules, in the ufw-before-input chain, AFTER the RELATED,ESTABLISHED accept
  -A ufw-before-input -i br+ -m conntrack --ctstate NEW -j DROP
  ```

  **Three details that each cost a measurement.** `br+` is a wildcard on purpose: it covers bridges
  that do not exist yet, so a new attempt is covered the moment it creates one. `--ctstate NEW` is not
  decoration — a bare `-I INPUT -i br+ -j DROP` also drops the **replies** to connections the *host*
  opened, and if anything on that host is reached through a published port on a Docker bridge (on ours,
  GlitchTip is), it goes quiet with every dashboard still green. And it belongs in `before.rules`
  rather than in a live `iptables -I`, because `iptables` does not survive a reboot and a control that
  disappears on restart is worse than one you know you do not have.

  Verified on the deployment host with the rule in place: a sandbox's connection to the gateway's `:22` times out,
  container-to-container traffic is unaffected (so the recording gateway still works), the tracker and
  the receiver both answer 200, and a full attempt's cable completes with a real completion through it.
  Install it with somebody watching the tracker anyway — that is cheap and this is the kind of rule
  that is only wrong in ways you find out about later.

## Making `human-merge` a guarantee rather than a promise

Hullwork never calls a merge endpoint. That is a property of the code, and code changes. If you want
the forge to enforce it, three settings do, and all three are needed — verified on Forgejo 15.0.5
against a token whose user was a site administrator, which is the hardest case there is:

1. **Merge whitelist** on the default branch, with the Hullwork account left off it. Merging then
   returns 405 `User not allowed to merge PR`.
2. **Push whitelist**, so it cannot bypass the pull request and commit to the branch directly.
3. The Hullwork account has **Write, not Admin** — branch protection rules require admin, so an
   account that could edit them could remove the first two.

Two fields will mislead you while you check this. `user_can_merge` on `GET /branches/{branch}`
reflects only the merge whitelist: it reported `true` while merges were being refused for missing
approvals. And `mergeable` on a pull request means "git can merge this", never "you may merge this"
— it stays `true` through every refusal.

Drafts are a separate, weaker thing and worth understanding as such. Forgejo derives `draft` from
the title (`WIP:` or `[WIP]` by default; `Draft:` does **not** work), and it does refuse to merge a
draft with a real 405. But any account with pull-request write can rename the title. It is a safety
interlock, not a permission.

## Wiring the alert

GlitchTip's alert API takes the recipient in camelCase and rejects snake_case with a 422:

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"hullwork","timespanMinutes":1,"quantity":1,"uptime":false,
       "alertRecipients":[{"recipientType":"webhook","url":"<the URL the CLI printed>"}]}' \
  "$GLITCHTIP/api/0/projects/<org>/<project>/alerts/1/"
```

Note that an empty `POST` to that endpoint creates an alert with null fields rather than failing, so
check what you actually created.

## Access logs

The webhook token is in the URL path, so an access log writes a live credential to disk on every
delivery. The image's default command therefore carries `--no-access-log`, and **if you override
`command:` you must keep the flag** — we did not, on our own first deployment, and found the token
sitting in `docker logs` after pointing Hullwork at itself.

Your reverse proxy needs the same treatment: exclude `/webhooks/` from its access log. Hullwork
redacts the token from its own structured logs and can do nothing about anyone else's.

## 4. Host networking breaks the way back in, and your firewall is why

Host networking fixes Hullwork's **outbound** route to the forge and breaks the tracker's
**inbound** one. Deliveries stop arriving, silently, because from the tracker's side there is
nothing to log.

The tempting diagnosis is "the port mapping is gone". It is the wrong one, and it costs a rebuild
to find out. Hullwork is still listening on `10.0.0.5:8000` — the same address the tracker was
told to call. What changed is the path the packet takes to get there: it now arrives at the host on
the **bridge** interface rather than the VPN one, and a host firewall that defaults to deny-incoming
while allowing the VPN interface drops it on the floor.

Ours did exactly that:

```
Default: deny (incoming), allow (outgoing), deny (routed)
Anywhere on tailscale0     ALLOW IN    Anywhere
```

**The test that tells you which it is**, run from inside the tracker's container:

```python
import socket; s = socket.socket(); s.settimeout(4)
s.connect(("10.0.0.5", 8000))   # the address the webhook URL points at
```

A **timeout** means something dropped the packet. *Connection refused* would mean it arrived and
nothing was listening. Aim the same test at the bridge gateway (`172.18.0.1`) on a port where
nothing listens: if that also times out instead of being refused, it is the firewall, not the app.
Do not expect a log line to confirm it — ufw logs blocked packets to the kernel log, and on a box
without rsyslog there is no `/var/log/ufw.log` to grep.

The fix is one rule, not a redeploy:

```bash
ufw allow from 172.18.0.0/16 to 10.0.0.5 port 8000 proto tcp \
    comment "tracker container -> Hullwork webhook"
```

Narrower than it looks, and worth keeping narrow: source is the tracker's Docker network,
destination is the VPN address and that one port. **Leave uvicorn bound to the VPN address anyway.**
The bind and the firewall are two independent controls, and the earlier advice here — bind to
`0.0.0.0` and let the firewall be the only thing between your webhook endpoint and the internet —
made the firewall a single point of failure for no benefit.

Pin the subnet in the tracker's compose so the rule cannot drift out from under you when the
network is recreated:

```yaml
networks:
  default:
    ipam:
      config:
        - subnet: 172.18.0.0/16
```

### The rule above is an `INPUT` rule, and the packet may not be an input

**Measured on our own deployment, 2026-08-06, nine days after deliveries silently stopped.** The
`ufw allow` rule was present and correct:

```
10.0.0.5 8000/tcp        ALLOW       172.18.0.0/16
```

and the socket test from inside the tracker's container still timed out — including the control test
against the bridge gateway on a dead port, which is what this section says means *firewall*.

`ufw allow` writes into `ufw-user-input`, and `iptables -L ufw-user-input -n` confirms the ACCEPT is
there. What is also there:

```
DEFAULT_FORWARD_POLICY="DROP"
Chain FORWARD (policy DROP)
```

`ufw route allow from 172.18.0.0/16 to 10.0.0.5 port 8000 proto tcp` — the `FORWARD` equivalent —
was added and **did not fix it either**, so the drop is somewhere else again: Tailscale's own
`ts-input` chain does not drop this source, and the host's routing table will not answer for a
container source at all.

**What this section can honestly tell you today**: the two-line diagnosis above (timeout versus
refused) is right and the one-rule fix is not always enough. If both rules are in place and the
timeout persists, the topology is the problem rather than a rule — a receiver on `network_mode: host`
bound to a VPN address is reachable from the host and not necessarily from a container on a bridge,
and the choices are all trade-offs:

* **bind `0.0.0.0`** and let the firewall be the only thing between the webhook endpoint and the
  internet — which this document argues against, for the reason it gives above;
* **give the receiver a container address on the tracker's network**, which means giving up
  `network_mode: host` and solving the outbound VPN route another way;
* **use the inventory sweep as the input** and accept that webhooks do not arrive in this topology —
  workable, and it is what our instance had been doing unknowingly for nine days.

Whichever you pick, `hullwork doctor` now reports the state per project — *never configured*, *never
arrived*, and *arrived and then stopped* — so the choice is at least visible. That check exists
because this failure was invisible for nine days on the instance whose own documentation describes it.


Add that with the stack **down**. `docker compose up -d` on a running stack recreates the network
but leaves the existing containers attached to nothing usable: ours came back with no IP address at
all and the web container crash-looped on `failed to lookup address information`, which reads like a
database problem and is not one. `docker compose down && docker compose up -d` fixes it, and named
volumes are not touched by `down`.

The alternatives are still there if a firewall rule is not to your taste: put both containers on one
user-defined network and solve the forge route separately (most correct, most moving parts), or run
the tracker on host networking too (symmetrical, and a tracker UI is a bigger thing to leave exposed
by mistake).

Whichever you pick, verify **both** directions afterwards: an event reaching an item, *and* that item
reaching an issue. Testing one and assuming the other is exactly how this was missed.

## 5. When the instrumented application lives somewhere else

Everything above assumes the tracker and Hullwork share a host. The application usually does not,
and then the tracker has to be reachable from wherever it runs. Ours is on a VPS with no membership
of the private network, so the tracker got a public name — and **only its ingest route**.

That distinction is the whole design. An SDK needs exactly one endpoint,
`POST /api/<project_id>/envelope/` (verified in `glitchtip/urls.py`; the legacy `store/` route is
gone in GlitchTip 6). The dashboard, the admin API and the auth pages need nothing from the
internet. So the edge publishes one path and refuses everything else:

```caddyfile
errors.example.com {
	@ingest path_regexp ^/api/[0-9]+/envelope/?$
	handle @ingest {
		log_skip                        # the DSN key can ride in ?sentry_key=
		request_body { max_size 5MB }
		reverse_proxy web:8000
	}
	handle {
		respond "not found" 404
	}
}
```

Run it on the tracker's own Docker network so it reaches `web:8000` by name — that keeps the
firewall out of it entirely. Then check what you published, from outside, path by path: the ingest
route should answer from the application (405 to a `GET`, since it only takes `POST`) and `/`,
`/admin/`, `/api/0/…` and the health endpoints should all be 404s from the edge.

Two things to do at the same time:

- **Set `ALLOWED_HOSTS`.** GlitchTip defaults to `*` and warns about it in the log. Once anything is
  public, list the hostnames — including the private address you still use for the dashboard, or
  you will lock yourself out of it.
- **The DSN key is public by design** (SDKs in browsers ship it), so publishing ingest does not leak
  a credential. It does mean anyone who has the key can post events into that project. Keep the DSN
  server-side if your instrumentation is server-side, as ours is.

## 6. Knowing it broke

Everything above was found by luck. Three silent failures in one day of deployment — a firewall
dropping deliveries, a container reporting healthy with its error reporting inert, and items whose
issues were never filed — and in each case the only detector installed was somebody happening to
look. So:

**`GET /ready` can fail, and `/health` cannot.** The second is a liveness probe and is right to
depend on nothing; point your container healthcheck and your monitoring at the first. It answers
503, with the numbers behind the verdict, when the forge is unreachable, the database is not
writable, the disk is nearly full, the retry clock has stopped or is switched off, an item has been
owed an issue for more than fifteen minutes, or `HULLWORK_ERROR_DSN` is set and nothing is
listening to it.

It reports `last_delivery_age_s` and **never fails on it**. Tempting as a silence alarm and wrong
for this product: with one notification per issue per lifetime, days without a delivery is normal.

**Point your tracker's uptime monitor at `/ready`.** This is the cheap trick worth doing: the check
then leaves the tracker's own container and travels the identical path a webhook does — same
network, same firewall, same address — which is exactly the path that dropped ours for three hours
with nothing to show for it. GlitchTip's alerts have an `"uptime": true` form for this.

> Send that alert somewhere other than the Hullwork webhook. An alarm routed through the road it is
> reporting on does not go off.

**`hullwork status`** is the same picture for a human, plus the detail a probe cannot carry: which
items are stuck and why, which deliveries failed and whether they will be retried, and which
projects have asked for a notification channel this build cannot deliver to. It exits 1 when
degraded, so `hullwork status || mail -s "hullwork" you@example.com` in a cron line is a complete
monitoring setup for a single-container tool. It reads the database directly and does not ask the
server, so it still works when the thing you are debugging will not answer.

**`hullwork doctor`** answers the other question: not *"is it working?"* but *"why not?"*. It makes
the opposite trade to `status` deliberately — it spends a subprocess, a forge call per repository and
two file reads — because a person types it when something is already wrong, and because every failure
it checks for cost hours to find by hand:

```
docker compose exec dispatcher hullwork doctor
```

**Run it where the dispatcher runs**, and that is why the command above is not just `hullwork doctor`.
Three of its checks — `git`, Docker, and the model credential — are about resources the *dispatcher*
uses, and two of the three are paths. A path means different things in the two places it can be read
from: on this deployment the model credential's configured path is the bind mount's **destination**, so
it exists inside the container and not on the host. From the host the check therefore reported
`BROKEN` and the command exited 1, on an instance where the same check inside the container was `ok`.
Both answers were right.

A red line on a correct installation is not a diagnosis, it is noise that will still be red on the day
the credential really expires — the same reasoning that removed a whole check in item 073. So when
those checks fail *and a dispatcher is running that is not this process*, they report `unknown` and
say so: **"not from here"**, with what was measured and where to ask. The test is ownership rather
than location: the lease's holder is deliberately random and names no machine, so there is nothing to
compare a hostname against and nothing should be. With no dispatcher alive, nothing is downgraded —
that is exactly when somebody needs the whole diagnosis.

**And only failures that are about the machine** (item 105). The first version of that rule downgraded
every failure in those three checks, and on 2026-07-31 it cost eleven hours: the dispatcher's token had
expired, `docker compose exec dispatcher hullwork doctor` was run — inside the dispatcher, the right
place — and the answer was `unknown … not from here … run the doctor where the dispatcher runs`. The
advice was to go where it already was. *"There is no file at this path"* is a fact about a filesystem
and reading it elsewhere may legitimately differ; **an expiry is a fact about the token** and is the
same number in every process that can open the file. Downgrading that does not lose information, it
asserts a reason that cannot be true. `hullwork status` had the same defect from the other side and
now goes through the same test.

### The single-file bind mount that freezes a credential

**If you mount a credential as a file, and anything ever rewrites that file, the container stops
seeing updates — permanently, silently, until you recreate it.** Docker binds the source **inode**, and
the usual way to rewrite a secret safely is to write a new file and rename it over the old one, which
replaces the inode.

Measured here on 2026-07-31, after a cron had been refreshing the token correctly for a whole night:

| | inode | token expires |
|---|---|---|
| host | 310925 | valid |
| dispatcher | 310981 | eleven hours earlier |

Four correct refreshes, every one of them into a file the container was not reading. It had appeared to
work only because that week's deployments kept recreating the container, so the fix was credited to the
cron and delivered by a coincidence.

**Mount the directory instead**, and the path is resolved on every open:

```yaml
- ${MODEL_CREDENTIALS_DIR:-./model-credential}:/home/hullwork/.claude:ro
```

Use a **dedicated** directory holding only the credential — not `~/.claude`, which on the machine this
was found on carried 63 MB of conversation transcripts that have no business in the process that builds
sandboxes. Whatever refreshes the token copies it there.

This is not specific to a subscription token or to this deployment: it is true of any secret file you
bind and anything else rotates. The supported path — an API key in `HULLWORK_MODEL_KEY` — has no inode
and cannot hit it, which is part of why it is the supported one.

**To check it, replace the file on the host and read it inside the container without recreating
anything.** If the old contents come back, the mount is a file. That is the whole test.

It proves the preconditions **by doing them**, which is the only way any of them can be believed:

| check | the failure it caught |
|---|---|
| `git` on `PATH` | the `api` image had none, which is why the dispatcher used to run on the host; the image carries `git` and the Docker CLI since item 082, and the check stays because an image built before that starts and cannot clone |
| the Docker **daemon**, not the binary | a client present with an unreachable socket is the ordinary failure, and it has a different remedy from a missing client |
| this build's tables, not a live database | a dispatcher started without `HULLWORK_DATABASE_URL` made itself an empty SQLite file beside the real one, and every liveness check passed on it |
| the **code** token reading each active repository | `403 token does not have at least one of required scope(s)` arrived four layers down, inside an attempt that had already been spent |
| the model credential present **and unexpired** | a subscription token lives about five hours and its expiry arrives as `401 OAuth access token has expired`, naming neither the file nor the clock |

Then it reports the **effective configuration**: which `HULLWORK_*` variable your `.env` sets that
this process is not running on, and which one the neighbouring `docker-compose.yml` never passes to
the service. That second half is the one worth having. A variable can be correct in the file,
correctly read by `config.py`, and still never arrive, because the compose file lists variables one
at a time and a missing line is silent — which is how `HULLWORK_TRACKER_URL` and
`HULLWORK_TRACKER_TOKEN` were set for a day while the enrichment they enable had never once run, with
`tracker_configured: false` as the only clue. That sentence is true of the process and false of the
machine, and it sends you looking in the wrong place.

`status` prints that inventory too — it is two local file reads, cheap enough for a cron.

> **`HULLWORK_FORGE_CODE_TOKEN` is reported as `expected`, not as a gap.** Its absence from the
> service is correct and the service refuses to boot with it (see "The two credentials" above). It is
> reported rather than hidden because a gap nobody mentions gets closed by the next person reading
> the compose file — which is precisely what happened here, and the service then would not start.
> Its absence from the *dispatcher* is a real failure, and the `code token` check is what catches
> that.

An `unknown` never sets the exit code. A check that cannot answer says so and stands aside: an alarm
with no action available to clear it stops being read, which is the lesson `hullwork status` learned
the expensive way.

### A verdict that could not be posted

`status` can report this, and it is the one warning that used to be impossible to clear:

```
attempt(s) [11] reached a verdict and could not publish it, so a result DR-0003 calls
first-class is where only this database sees it. The attempt was spent
```

Publishing is the last step of an attempt and the only one that can fail *after* a verdict exists.
`publish` records the failure on the attempt rather than raising — deliberately, so a lost comment
cannot turn a recorded verdict into an abandoned attempt — which leaves the verdict real, spent, and
nowhere anybody can read it.

```
hullwork republish
```

No sandbox, no gates, no model call: the verdict is already a fact and this sends it where it was
always going. On success the publication failure is removed from the attempt and **the verdict text
stays** — they share one column, so clearing the wrong one either loses the verdict or leaves `status`
reporting a publication that has happened.

Two limits, both deliberate:

- **`pr-open` is refused.** Rebuilding a pull request needs the files the agent wrote, and nothing
  stores them (item 079). Attempting it would push two empty commits and claim a fix that is not
  there, which is worse than a stranded verdict because it would look finished.
- **A retry cannot fix a destination that does not exist.** If the issue was deleted, the 404 is
  permanent. For that, and only with a reason recorded on the attempt:

```
hullwork republish --attempt 11 --give-up --why "issue #3 does not exist"
```

That writes down the decision — the verdict stays, what failed stays readable — and stops the report.
It needs `--attempt`, there is no `--all`, and it refuses an attempt whose publication never failed.
Writing off a first-class result is a decision about one thing, not a way to clear a list.

## 7. Backing up, and what you lose without one

There was no backup instruction anywhere in this repository until now, which is a poor look for a
tool whose entire job is not losing things. The database is small and irreplaceable:

```bash
docker compose exec -T api python -c "import sqlite3; s=sqlite3.connect('/data/hullwork.db'); \
  d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close(); s.close()"
docker compose cp api:/data/backup.db ./hullwork-$(date +%F).db
```

Use the backup API, not `cp`: copying a live SQLite file gets you a torn one. On Postgres, `pg_dump`
as usual.

**This used to say `sqlite3 … ".backup …"` and that command does not work**, because the CLI is not
in the image — a slim Python base has the module and not the binary. Found on the M2 deployment, by
running the instruction in these docs and watching it fail with `executable file not found`. The
Python module's `backup()` is the same online-backup API the CLI wraps, so the guarantee is
unchanged; only the way to reach it is.

**What is gone if you lose it**, in order of how much it hurts:

- every **fingerprint**, so tomorrow every error you already know about looks new again;
- every **`forge_sync_pending`** intent — and per item 013 that flag is the only place in the
  world where "this needs an issue" survives, because the tracker will never re-notify;
- every **`webhook_secret_hash`**, so every project token must be rotated and every alert in the
  tracker re-pointed by hand.

Take one **before `docker compose up --build`**: the entrypoint runs `alembic upgrade head` and
stops the container if it fails, which is the right behaviour and no help at all if the migration
half-applied.

**Keeping it small.** `hullwork prune --older-than-days 90` forgets the stored *bodies* of old
deliveries and events, keeping every row, fingerprint, counter and issue reference. The body exists
so a delivery accepted before a restart survives one — a purpose measured in minutes — and nothing
expired it, while `events.raw` stores the whole delivery once per error inside it. Measured: 2,000
attachments in one 160 KB request became a 322 MB database.

## 8. Your tracker will not retry, so a lost delivery is a lost error

Worth knowing before you decide how much care the network deserves. GlitchTip's alert query
(`apps/alerts/tasks.py`) carries `.exclude(notification__project_alert=alert)`: **an issue that has
been notified once is excluded from that alert permanently.** Not a cooldown, not a window.

Three consequences:

- A delivery that fails while your firewall is wrong is not delayed, it is gone. Two of our
  GlitchTip issues were notified into the void and can never be sent again.
- Hullwork's occurrence counters barely move on the GlitchTip path, because repeats of a known
  error never generate a second delivery. The deduplication that matters here is against redelivery
  and restart, not against volume.
- The **reopen-as-regression** path cannot be triggered by GlitchTip either: the returning error
  belongs to an issue that has already used up its one notification.

This is why Hullwork sweeps on a clock of its own (`HULLWORK_SWEEP_INTERVAL_SECONDS`, default 60)
rather than only when a delivery arrives. Its database is the only place the intent to file an issue
survives a failure.

### The first sweep of a project is yours to run

**A project Hullwork has never swept is skipped by the clock, on purpose, until you say so.** This is
a setup step and it is easy to mistake for a broken connection — measured on this deployment: the
receiver polled one project every sixty seconds for twenty minutes while a second, correctly
configured project with a fresh issue was never asked about at all.

```bash
hullwork sweep <slug>              # shows the count, writes nothing
hullwork sweep <slug> --confirm    # files what it found
hullwork sweep <slug> --from-now   # start from today, leave the backlog unfiled
```

The reason for the gate is the first pass, not the steady state: a project with three hundred open
issues would get three hundred forge issues on the afternoon somebody connected it, which is DR-0006's
adoption failure arriving from the other direction. So the count comes first and the writing needs a
word from you:

```
acme: 1 issue(s) would be filed and 0 are already known. **Nothing was written.**
  This is the first sweep of this project, so it needs --confirm. Or --from-now to start from
  today and leave the backlog alone.
```

Every pass after that one happens on the receiver's clock without being asked. `--from-now` is the
answer for a project whose backlog you do not intend to work through: it marks the project as swept
up to this moment, so only errors from now on become items.

## 8a. The release annotation, and why a version string is not one

Your application tells the tracker which version it is running. Hullwork reads that string twice,
for two different questions, and **a string that is not a commit makes both of them undecidable**:

- *"does the bug still exist at the tip of the default branch?"* — item 039. If the deployed ref and
  the branch tip are the same commit, a fix is a fix; if they differ, an error may simply be one you
  already fixed and have not deployed. Hullwork says so instead of attempting it (`already-fixed`),
  and the artefact prints both refs side by side: **Production was running** and **Gates ran
  against**.
- *"did the merged fix hold?"* — M9. A recurrence only means the fix failed if the code it came from
  **contains** the merge, which the forge answers by comparing two commits.

So annotate releases with the **commit sha**, and generate it at deploy time rather than typing it:

```bash
# in your deploy, however you build the image
export SENTRY_RELEASE="$(git rev-parse HEAD)"     # your app's SDK reads this
```

A package version (`2026.7.1`, `v3-hotfix`) is not wrong, it is *undecidable*: the recurrence watch
records that verdict and puts the fix in neither column, which is the honest answer and a less
useful one than you could have had.

**Hullwork's own instance is the cautionary tale.** Its events were annotated `0.1.0.dev0`, from
`release=__version__` in its Sentry SDK setup — a real string that never changes, so the watch could
never have decided anything about any of its own four merged fixes. `HULLWORK_RELEASE` fixes it: the
deployment sets it to the commit it is deploying, and it overrides the package version.

```bash
# what this deployment does, in deploy.env
HULLWORK_RELEASE=4707744
```

Without it, Hullwork falls back to the package version rather than refusing to start — a wrong
release annotation degrades a measurement, and refusing to run over it would be worse.

## 8b. Connecting a project whose stack nobody here has run

Hullwork does not need to know your language. It needs an image with a shell in it, and the commands
that test and lint your code. Two commands do the whole thing, and both of them read before writing.

**Let it write the manifest.** `hullwork propose owner/name` reads the repository's own CI
configuration — `.forgejo/workflows/`, `.gitea/workflows/`, `.github/workflows/` or `.gitlab-ci.yml` —
and prints a `hullwork.yml`. What it observed goes in as fields; what it inferred goes in **commented
out**, with the reason. Read it before you commit it: it is a proposal, not a detection.

```bash
docker compose exec receiver hullwork propose owner/name
```

The same output appears unasked when you register a repository that has no manifest yet, because a
refusal that could have shown you the answer is a bad refusal.

**Two things about the image are checked at registration**, not at build time where the answer costs
minutes:

```
Not checked here: whether ghcr.io/acme/ci:2026.7 has a shell and matches this host's architecture
— ghcr.io/acme/ci:2026.7 is not on this host yet, and registering a project is not a reason to
download it (`docker pull ghcr.io/acme/ci:2026.7` first for the answer now). The build where the
dispatcher runs is what establishes both; a failure there will name whichever one it was.
```

That sentence is the **normal** case and not a warning: `projects add` is typed on the receiver, which
holds no Docker socket by design (§"The dispatcher is a container, and it is not isolated
from your host"), so there is nothing to ask.
Where Docker *can* be asked and the image is already local, you get a real answer, and a bad image is
refused with the reason:

- **No shell.** Permanent, not a gap: every phase runs `sh -lc`, so `distroless` and `scratch` images
  cannot host a phase. Any image your CI runs tests in already has a shell.
- **Wrong architecture.** The harness bundle is built per architecture, and a mismatch used to fail
  inside the sandbox with a misleading message about the executable. Both architectures are named.

**Adopting an edited manifest.** The manifest is *adopted*, not followed — nothing re-reads it from
your forge in order to act, so editing `hullwork.yml` changes nothing until you run:

```bash
docker compose exec receiver hullwork projects refresh <slug>
#   The build environment changed:
#     install: 'uv' → 'make bootstrap'
#     packages: [] → ['libpq-dev']
```

Read those lines. They are the whole mitigation for `base`, `install` and `packages` being open
fields: a repository cannot change what this host builds without you adopting the change, and now you
cannot adopt one without seeing it. When nothing changed it says so, because silence about a check
reads as the check not having happened.

## 9. The model, and which credentials are supported

**One answer: bring an API key.** Any provider that issues one, which is all of them.

Switching provider is three settings and nothing else. The sandbox only ever sees the gateway's
address, and the engine image only ever sees a base URL — Hullwork integrates no provider and
privileges none (DR-0004).

```yaml
HULLWORK_MODEL_ENDPOINT: "https://api.openai.com"   # or any of the below
HULLWORK_MODEL_AUTH_STYLE: "bearer"                 # bearer | x-api-key
HULLWORK_MODEL_NAME: "gpt-…"                        # pinned; a different model answering is a finding
HULLWORK_MODEL_KEY: "…"                             # your key, held by the gateway only
```

| Provider | Endpoint | Auth |
|---|---|---|
| Anthropic | `https://api.anthropic.com` | `x-api-key` |
| OpenAI | `https://api.openai.com` | `bearer` |
| Moonshot / Kimi | `https://api.moonshot.ai` | `bearer` |
| DeepSeek | `https://api.deepseek.com` | `bearer` |
| Groq | `https://api.groq.com/openai` | `bearer` |
| Mistral | `https://api.mistral.ai` | `bearer` |
| OpenRouter | `https://openrouter.ai/api` | `bearer` |
| vLLM · Ollama · llama.cpp | wherever you serve it | `bearer` |

> [!warning] **The harness fixes the protocol, so that table is where to point it and not what will
> work** (item 134). The gateway terminates, injects your key, observes and **forwards** — it does not
> translate between protocol families. So every call carries the shape of whatever harness you run,
> and the endpoint has to serve that shape.
>
> The only registered harness is `claude-code`, which speaks the **Anthropic** family
> (`POST /v1/messages`). Against an endpoint that does not serve it, every call is refused by
> Hullwork's own gateway — most providers above publish a compatible route, and you have to point
> `HULLWORK_MODEL_ENDPOINT` at *that* one rather than at their default. Check your provider's own
> documentation; this project ships no list of who serves what, because it would privilege providers
> (DR-0004) and be wrong within a quarter.
>
> `hullwork doctor` prints both sides — harness, protocol family, endpoint and which credential path
> is in use — so the mismatch is readable before an attempt is spent on it.

> [!warning] **Nobody has run the supported path yet.** Every attempt this project has measured used
> the development-only subscription credential, because that is what its author already pays for.
> The API key path is what the product promises and what this section documents; the first person to
> run it will find whatever we have not. Said here rather than discovered by you.

The key is held by the gateway — a container per attempt, reached only over that attempt's internal
network, given the key as a mode-600 file inside a volume of its own (item 089). **It never enters
the sandbox**, which also runs your project's own test command — so nothing your tests execute can read
it, and there is nothing in the container worth stealing.

### What is not supported, and why

**A Claude subscription is not a supported credential.** Not an oversight: its access token expires
in about five hours and the refresh belongs to the CLI that wrote it, so making it work for you would
mean Hullwork storing and rotating your Claude account credential. That is a different product with a
different blast radius — the failure mode is your account rather than one attempt.

If you want to use a subscription anyway, `claude setup-token` produces a long-lived token that works
through `HULLWORK_MODEL_KEY` like any other. Whether a subscription may power an automated
maintenance bot is a question about Anthropic's terms, not ours, so this documentation neither
recommends it nor stands in your way.

**Never mount a credentials file into the sandbox.** `HULLWORK_MODEL_CREDENTIALS_FILE` exists, is how
Hullwork's own dogfood runs at no marginal cost, and logs a warning at start-up saying it is not a
supported configuration. The **gateway** reads it — a different container from the sandbox, on a
different network, mounted at mode 600 (item 054). A credential inside the *sandbox* would be readable
by the watched project's test suite, which is the arrangement DR-0004 was written to remove.

One operational catch, if you use this path: **the token expires in about five hours and the CLI that
wrote it is what refreshes it.** Nothing in Hullwork refreshes anything. If nobody has run `claude` on
that host recently, the gateway forwards requests that all come back 401 — and since item 056 the
provenance seal says exactly that (*ten answers, all 401*) instead of reporting that the endpoint
answered nothing, which is what sent one diagnosis into the network for three rounds.

### What the gateway does with it

Every model call goes through it, and it records **which model actually answered** — read from the
response body, not copied from your configuration. Two consequences worth knowing:

- if your endpoint serves something other than the model you pinned, the attempt carries a
  `model-drift` finding and the pull request says so. `allow_fallbacks: false` is a request to a
  provider; this is a measurement;
- if a response stops because the context was cut, that is a `context-truncated` finding rather than
  a silent shortfall.

A path the gateway cannot read is **refused**, not forwarded. An endpoint it cannot observe is
unsupported, and passing traffic through unobserved would look like it works while removing the only
reason the component exists.
