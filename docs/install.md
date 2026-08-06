# Installing Hullwork

Three ways in, in the order that costs you least. Each says what it needs before it says what to type,
because what it needs is the decision you are making.

| | needs | gives you |
|---|---|---|
| **1. Try the agent half** | Docker, a model key, a checkout | the fix loop on your own code, no account anywhere |
| **2. The evaluation stack** | Docker | the receiver running: ingest, triage, the CLI, the page |
| **3. A real deployment** | Docker on a Linux host, a forge token | both halves, filing issues in your forge |

You do not have to do them in order, and you never have to do 3 to have judged 1 and 2.

## Before you start

Four requirements, stated once. Three of them are hard limits rather than preferences, and the fourth
only applies to way 3.

| | |
|---|---|
| **Python 3.12** | `>=3.12,<3.13`, deliberately narrow. Not `python3` — on macOS that is usually 3.13, and `pip install -e .` fails with a resolver error that does not mention the version. |
| **The Docker daemon** | Reachable from wherever the dispatcher runs. The sandbox is the product's boundary, so this is not removable (DR-0004). |
| **A test image with a shell** | Whatever image your CI already uses, built for **this instance's architecture**. `distroless` and `scratch` cannot work — the harness needs a shell — and both are refused at registration rather than at attempt time ([`hullwork.yml`](hullwork-yml.md)). |
| **A Linux host** — way 3 only | The dispatcher joins the daemon's group to reach the socket, which is a Linux mechanism. Docker Desktop on macOS ignores `group_add`, so ways 1 and 2 work on a Mac and a real deployment does not. |

What you do **not** need: an account with us, a hosted anything, a forge account for way 1, or a
credential that can push for ways 1 and 2.

---

## 1. Try the agent half

**No forge account of any kind** (DR-0006). A checkout, a stack
trace you already have, and two things that are not removable: **the Docker daemon** and **a model
key**. The claim this product makes is a test that failed against unmodified code and passes with the
change, run in a sandbox, by a model whose identity was read off the wire — faking either would make
this a demo of itself.

Your checkout needs a `hullwork.yml`. This is the smallest one that reaches an attempt:

```yaml
project: myproject
git: { provider: forgejo, repo: owner/myproject }   # a coordinate; nothing is contacted
tests: pytest                                       # your real test command
runtime: { base: python-3.12 }                      # any Linux image with a shell
autofix:
  agent: claude-code        # `none` is the DEFAULT, and with it nothing is ever attempted
  lanes:
    green: [keyerror]       # error types you accept an agent trying. Unlisted ⇒ red ⇒ refused
```

`hullwork propose --checkout PATH` writes most of that from your CI configuration, with no credential.

**Those last three lines are the ones people leave out.** `agent: none` means no agent runs at all, and
an error matching no lane defaults to **red**, which is never handed to an agent by anything. Both are
deliberate (DR-0008), and both make `try`
print a refusal rather than a fix. It names which one and what to change.

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e .
export HULLWORK_MODEL_KEY="…"                      # any provider (DR-0004)

hullwork try /path/to/your/checkout --error trace.txt
```

Every gate runs — the baseline must pass, the red gate must fail as a reproduction, the green gate must
pass, the lint gate must pass — and what it produced goes to a directory (`--into`, default
`hullwork-trial` beside the checkout) instead of opening a pull request. Nothing is written outside it,
no database is created, and your checkout is left clean.

> **Run this on your host, not in the stack below.** It needs the Docker daemon, and that container
> deliberately has no socket — DR-0009, not an omission.
>
> **Use `python3.12`, not `python3`.** The suite is green on 3.12 and red on 3.14 for reasons that are
> being fixed rather than hidden; see the note in `CONTRIBUTING.md`.

Two more that need no credential at all, on any checkout:

```bash
hullwork projects lanes --checkout .   # which of your files this instance keeps a human on, and why
hullwork propose --checkout .          # a manifest read from your CI configuration
```

---

## 2. The evaluation stack

**One file and a published image — no clone, no build.** It is **one container**: the receiver, which
is the half that answers webhooks. Nothing here can push to anything.

```bash
curl -O https://raw.githubusercontent.com/easybytehub/hullwork/main/docker-compose.yml
docker compose up -d
curl http://127.0.0.1:8000/health
# {"status":"ok","version":"0.1.0a3"}
```

The image is `ghcr.io/easybytehub/hullwork:0.1.0a3`, built for amd64 and arm64, pinned in that compose
file rather than floating on `latest`. From a clone, `docker compose up -d --build` builds your own
instead — which is what you want if you are testing a change.

**No credentials are required to start it.** With no forge configured, migrations run, `/health`
answers and `/ready` answers 200 with `"forge":"unknown"`. Ingest and triage work; items wait
unmaterialised until credentials arrive, and `hullwork status` says so in a sentence.

What you cannot do without a forge token is *register a project* — and a project is what mints a
webhook token, so there is no ingest either until you have one. So the honest order for a first look is
this stack to see the receiver run, part 1 above to see the agent work, and a forge token when you want
the two joined.

Three optional variables, if you have them:

```bash
export HULLWORK_FORGE_URL="https://forge.example.com"
export HULLWORK_FORGE_TOKEN="…"   # issue write + content read; it does NOT need code write
export HULLWORK_BASE_URL="https://hullwork.example.com"   # where YOUR instance is reachable
```

The database lives on a named volume, so `docker compose down` and `up` keeps every fingerprint.
Losing them would make every already-known error look new tomorrow morning.

### Asking it how it is

The CLI lives *inside* the container in this stack, so every command is reached the same way:

```bash
docker compose exec api hullwork status   # how it is           — exit 1 when degraded
docker compose exec api hullwork doctor   # what is broken      — a sentence per check
docker compose exec api hullwork config   # what it is set to   — every variable, source, and half
```

`status` exiting 1 when degraded is what makes `hullwork status || mail me` a whole monitoring setup,
and **an instance with no forge configured counts as degraded**: it can never file an issue, so silence
there would be the wrong answer. `GET /ready` serves the same verdict with the numbers behind it;
`/health` is liveness only and cannot fail, so point a healthcheck at `/ready`.

`doctor` and `config` are the two worth knowing *before* anything goes wrong. The first says what is
broken; the second says what this process actually received, which is a different question from what
you wrote in a file.

### A page a teammate can read

`hullwork page-token` mints one URL, prints it once and stores only its hash. Behind it is what
`status` says, read from the same functions, plus the evidence of every attempt. It is **off until you
run that command**, and everything without the token — including a wrong token — gets the same `404` an
unknown path gets, so it cannot be found by probing.

That URL **is** the credential. Anyone who has it can read every item and captured output on this
instance. It is read-only, and rotating replaces it.

### Two things about the port

It is published on loopback only. The webhook endpoint is real, so put your own reverse proxy with TLS
in front of it before anything on the internet can reach it.

Every minute (`HULLWORK_SWEEP_INTERVAL_SECONDS`, `0` to disable) the instance finishes what an earlier
pass could not: deliveries interrupted by a restart, and items still owed an issue because the forge
was unreachable when they arrived. That clock is not optional politeness — error trackers notify once
per issue and never again, so an item this database forgets is an error nobody ever sees.

---

## 3. A real deployment

**From a host with nothing on it but Docker and git.** Seven steps, in this order. `hullwork` is a
command of a package that is not installed yet, so the image comes first.

```bash
# 1 — the image. `hullwork init` runs from inside it.
git clone <this repository> hullwork-src && cd hullwork-src
docker build --tag hullwork:dev .

# 2 — the deployment directory, which is NOT the clone: this repository ships a
#     docker-compose.yml of its own (the evaluation stack) and `init` will keep it.
mkdir -p ~/my-instance

# 3 — write the two files. Both volumes are load-bearing; see below.
docker run --rm --volume ~/my-instance:/out --user "$(id -u)" \
  --volume /var/run/docker.sock:/var/run/docker.sock:ro \
  --entrypoint hullwork hullwork:dev init --into /out

cd ~/my-instance
```

**4 — fill in `deploy.env` by hand.** `init` writes every variable named and empty, and prints which
ones only a person can supply. The four that stop it starting:

| | |
|---|---|
| `HULLWORK_FORGE_URL`, `HULLWORK_FORGE_TOKEN` | your forge, and a token that can file issues and **provably not push** |
| `HULLWORK_BASE_URL` | where this instance is reachable — it goes into the links it writes |
| `BUILD_SOURCE` | the path to the clone from step 1. This directory has no `Dockerfile`. |
| `BUILD_EXTRAS=[telemetry]` | only if you set `HULLWORK_ERROR_DSN`. Set the DSN without it and the receiver **refuses to start**, deliberately, rather than pretend it is being watched. |

**5 — let the container read that file.** It holds credentials, so `init` writes it mode 640, and the
image runs as uid 10001. The compose file mounts it read-only so `doctor` can compare what you
configured against what actually arrived, and that mount is unreadable until the group matches:

```bash
sudo chown :10001 deploy.env      # `init` prints this when it cannot do it itself
```

**6 — start the half you have credentials for.** `up -d` starts **one** container: the receiver, which
does ingest, deduplication, triage and issues. The dispatcher sits behind a profile because it refuses
to start without a model key, and `restart: unless-stopped` would turn that correct refusal into a
crash loop on a first installation.

```bash
set -a; . ./deploy.env; set +a; docker compose up -d --build
docker compose exec api hullwork doctor        # 7 — ask it what is still missing
```

Migrations are not a step: the receiver's entrypoint runs `alembic upgrade head` before starting, so the
schema is built and owned by the half that serves. The dispatcher only uses it.

Later, once a code token and a model key exist:

```bash
docker compose --profile autofix up -d
```

### Why two of those commands look odd

**The socket mount on `init` is not decoration.** `init` reads the Docker socket's *group* off this host
so the dispatcher can open it later, and it runs inside a container — without that volume it cannot see
the host's socket, writes a placeholder, and every attempt later fails while building its sandbox.
Measured: with the mount it wrote `989`; without it, a placeholder.

**`--user "$(id -u)"` is not decoration either.** The image runs as uid 10001 and your directory does
not belong to it. Without this, `init` refuses and prints the `chown` you would need.

A deployment next to a self-hosted tracker on a private network then has traps a green test suite will
not warn you about — DNS, routes, and a tracker that refuses to call private addresses.
**[deployment-notes.md](deployment-notes.md)** is the record of every one we hit, in the order they bit,
with what fixed each. Read it when something above does not behave; it is not a second procedure.

**The two halves hold different credentials, and that is the product**
(DR-0009). The receiver answers webhooks and refuses to start
if it finds a credential that can push. The dispatcher holds that credential, mounts the Docker socket,
and listens on nothing — which is the property that makes it safe, not the socket. The generated compose
puts the dispatcher behind a profile, so `docker compose up -d` still starts one container:

```bash
docker compose --profile autofix up -d   # when you want the fix half as well
```

The dispatcher needs a Linux host with a real Docker socket. On macOS `init` says so and writes the
file for the host you will deploy on.

---

## Configuration

**Every setting is discoverable from the instance itself**, which is deliberate rather than lazy:

```bash
hullwork config          # every variable, its value, where it came from, and which half receives it
```

A credential renders as `set` or `not set`, never as a value. Listing all thirty-five here instead
would be a second copy of `config.py`'s own comments — and two copies of a reason are how they start
disagreeing, which is the same argument the generated compose file makes about itself.

Four are worth naming here anyway, because nothing else tells you they exist:

| variable | what it is |
|---|---|
| `HULLWORK_DEPLOYMENT_COMPOSE_FILE` | Path on the **host** to your compose file. `hullwork doctor` compares the variables it assigns against the ones the environment file names, and it is the check that catches *"the setting is in the file and never reached the container"*. Unset means that comparison is skipped and `doctor` says so rather than reporting a pass. |
| `HULLWORK_DEPLOYMENT_ENV_FILE` | The other half of the same comparison: path on the host to `deploy.env`. Defaults to `.env` in the working directory, which inside a container is usually the wrong place — `init` writes `deploy.env`. |
| `HULLWORK_FORGE_RECHECK_SECONDS` | How stale the forge's last known state may get before the sweep asks it again. A healthy idle instance has no reason to call the forge, so without this a revoked token would only surface on the day something needed filing. |
| `HULLWORK_TRACKER_ORG` | The organisation the tracker's projects live under, needed only by the inventory sweep. It cannot be discovered: the `event:read` token this uses is refused the organisations and projects routes, which is correct least privilege. Unset simply means no sweep. |

The two `DEPLOYMENT_` paths are read on the host and never passed into a container — a process told
about a filesystem it cannot see learns nothing.

## Where to go next

- **[Connecting a project](connecting-a-project.md)** — the manifest, registration, the webhook URL.
- **[The manifest reference](hullwork-yml.md)** — every field.
- **[Deployment notes](deployment-notes.md)** — what went wrong on a real box, and what fixed it.
- **[What works and what does not](status.md)** — before you rely on any of this.
