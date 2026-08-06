# Security policy

Hullwork's whole value proposition is running an autonomous pipeline safely. Security reports are the
highest-priority input this project has.

- Report vulnerabilities privately to **contact@easybyte.es**. Please do not open public issues for
  security matters. One mailbox on purpose: a policy pointing at an address nobody reads is worse than
  one pointing at an address that is obviously a person's, and there are two of us.

## The attack class this is designed against

**Every input to this pipeline is attacker-authored, by construction.** An error title, a stack trace,
a frame's local variables, an issue body, a commit message: all of them arrive from somebody else's
production, and on a public application some of them arrive from whoever chose to send them. That text
then goes into a coding agent's prompt, because a fix for an error the agent cannot read is not a thing.

So **prompt injection is assumed rather than prevented.** There is no filter, and adding one would be
worse than useless: natural language cannot be sanitised, and a filter that half-works converts a known
exposure into a believed-safe one. The defence is what an injected instruction can *reach*, not what it
can say — and that is why the properties below are structural rather than textual.

### What a successful injection still cannot do

Each of these is a property of the code, and the file that implements it explains why it is there.

- **No credential is in the sandbox.** No forge token, no model key, no Docker socket
  (`sandbox/run.py`). The first two would be readable by the project's own test suite, which the agent
  runs; the third is root on the host. The model is reached through a gateway container that holds the
  key and the sandbox never sees it (DR-0002).
- **Egress is the gateway or nothing.** The phase runs on an internal Docker network with no default
  route, so a harness told to call somewhere else reaches nothing and fails loudly rather than quietly
  exfiltrating (`sandbox/net.py`, with a measured self-test on every attempt).
- **The only way out is `(path, bytes)`** (item 040). `git apply` on the host is forbidden — it would
  be a host process parsing attacker-authored content — and every file the sandbox produces is checked
  against where it is allowed to land (`UnsafePathError`).
- **A reproducing test may only be written under the project's declared `test_path`.** A phase allowed
  to write anywhere can reach a red gate by breaking something rather than by reproducing anything.
- **Risk lanes bound what is attempted at all.** The manifest decides which error types an agent may
  touch; anything unmatched defaults to **red** and is never handed to an agent by any code path or
  flag. The derived territory policy over-matches on purpose for authentication, tokens, signatures,
  migrations and CI — read the policy applied to your own tree with
  `hullwork projects lanes --checkout .`, which needs no credential.
- **The red-green gate is evidence, not assertion.** A change ships only if a test failed against
  unmodified code and passes with it, in the sandbox, recorded.
- **Nothing is merged.** Hullwork opens a draft pull request and never calls a merge endpoint. Note
  honestly that a draft is a weak interlock rather than a permission — see `docs/deployment-notes.md`, which
  names the three forge settings that make it enforceable, and says so plainly.
- **The two halves hold different credentials** (DR-0009). The half that answers webhooks — the one an
  attacker can reach — cannot push, and refuses to start if it finds a credential that can. The half
  that can push listens on nothing.

### What leaves the instance

Two things, and neither of them can carry your code.

- **A hosted model endpoint gets your source and your stack traces**, if you point Hullwork at one.
  That is not a leak, it is what asking a hosted model to read your code *is* — and it is why
  `autofix.agent: none` is the default, why a local endpoint is a supported configuration, and why the
  seal records which endpoint answered every attempt (DR-0002).
- **The image we publish reports Hullwork's own crashes to us.** Not yours: the payload is *built* from
  an enumerated set of fields — exception class, our own stack frames, our version, your Python
  version, a random installation identifier, four row counts — so there is no field an error message,
  a URL, a hostname or a repository name could occupy (`hullwork/upstream.py`, about 350 bytes on the
  wire). The terminal says so before anything is sent; `hullwork config --telemetry` prints the exact
  payload; `HULLWORK_TELEMETRY=off` stops it; and an image you build yourself has no destination in it
  at all, which a test enforces against the whole source tree. [PRIVACY.md](PRIVACY.md) is the detail.

### What is not covered, stated rather than implied

- **A human reads the artefact.** The gate is a person, and a person can be misled by a convincing
  diff. That is a real limit of this design and the reason the evidence trail is built to be read
  rather than trusted.
- **Model output is not verified beyond the gates.** A change that passes a reproducing test and a lint
  gate can still be wrong in ways tests do not catch.
- **The agent's own harness is third-party software** running in the sandbox. Its provenance is the
  publisher's image, recorded in the seal.
- **No third-party security review has been done.** Nobody outside this project has examined any of
  the above. Until that changes, everything here is a claim the code supports and nobody has audited.

If you find a hole in any of it, the address is at the top of this file.
