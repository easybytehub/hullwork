"""Instance configuration: read from the environment, validated once, at startup.

A malformed setting stops the process with a readable message. It never falls back to a default
that quietly makes the instance less safe — a webhook receiver that starts with no secret is worse
than one that refuses to start.
"""

import os
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LogFormat = Literal["json", "console"]


class ConfigError(RuntimeError):
    """The environment does not describe a runnable instance."""


class Settings(BaseSettings):
    """Everything an instance needs to know about itself.

    Read from `HULLWORK_`-prefixed environment variables, or a local `.env` during development.
    Unknown `HULLWORK_*` variables are an error, not a shrug: a typo in a security-relevant setting
    must fail loudly rather than leave the operator believing it took effect.
    """

    #: **`extra="ignore"`, and the reason is a `.env` that belongs to somebody else.**
    #:
    #: `extra="forbid"` was here so that a *typo* in a security-relevant variable fails loudly
    #: rather than being ignored — `HULLWORK_FORGE_TOKN` must not read as "no token configured".
    #: **That property never depended on it**: `get_settings` refuses any unknown `HULLWORK_*` name
    #: in the environment already, through `_unknown_variables`, and still does.
    #:
    #: What it also did, and nobody meant, was reject every **unprefixed** key in the `.env` file it
    #: reads from the working directory. Measured on 2026-08-04: any `hullwork` command run from a
    #: directory whose `.env` belongs to another project — Odoo credentials, a Cloudflare token, an
    #: FTP password — died with a raw pydantic traceback, twenty lines of `Extra inputs are not
    #: permitted`. `hullwork try` is documented as the thing you run **on your host, in your own
    #: project**, and a project directory with a `.env` is the ordinary case, not the exception.
    #:
    #: So the `.env` this reads is *filtered* to our own prefix, and a foreign one is now inert.
    model_config = SettingsConfigDict(
        env_prefix="HULLWORK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


    log_level: LogLevel = "INFO"
    log_format: LogFormat = "json"

    #: Which instance this is, when a host runs more than one. Item 125.
    #:
    #: **It exists because the Docker daemon is shared and the lease is not.** Every sandbox object
    #: is labelled with this, and the reaper removes only objects carrying its own — without it, a
    #: second instance restarting reaps the *live* attempt of the first, including the volume
    #: holding its model credential. The lease cannot prevent that: it lives in a database and each
    #: instance has its own.
    #:
    #: A boring default, so a host with one instance behaves exactly as it did. Anything that is a
    #: valid Docker label value; keep it short and stable, because changing it orphans the objects
    #: the previous value labelled.
    instance: str = "default"

    # Used to build callback URLs the outside world must be able to reach.
    base_url: str = "http://127.0.0.1:8000"

    # SQLite by default so the quickstart needs no database server; Postgres in production.
    database_url: str = "sqlite:///./hullwork.db"

    # The forge this instance talks to. In M1 the token needs issue write and content read, and
    # deliberately NOT code write: the always-on ingest credential should never be able to push.
    forge_url: str | None = None
    forge_token: SecretStr | None = None

    #: Which forge that URL is, when the URL cannot say. Item 132.
    #:
    #: Needed the moment a third forge became registrable: a self-hosted GitLab and a self-hosted
    #: Forgejo are indistinguishable by URL, and `hullwork.forge.kind_of` explains why the answer is
    #: a declaration rather than a probe — an autodetection that guesses wrong sends one forge's
    #: request shape at another, silently, which is the regression item 131 exists to have caught.
    #:
    #: Unset means the Gitea family, which is what a self-hosted URL has meant since M1, so no
    #: instance running today has to learn this variable. It is ignored for GitHub, whose host
    #: speaks one API whatever this says — and `status` reports the disagreement rather than
    #: resolving it quietly.
    forge_kind: str | None = None

    # The credential Hullwork pushes **verified work** through, kept apart from the one above on
    # purpose. The ingest token is held by the request path and the sweep — it is in memory
    # whenever the service is up — so it must never be able to write code. There is no fallback to
    # `forge_token`, because a convenient fallback is how a boundary is lost.
    #
    # **This used to say "the credential an agent pushes through", and item 178 made that false.**
    # `hullwork deps --open` opens a pull request for an upgrade that passed the project's own
    # suite, with **no agent having run** — no model, no gateway, no brief. Reusing this token was
    # the operator's decision on 2026-08-09, over a third one of its own, and the argument is that
    # a third token would need exactly the same scope (`write:repository`): an audit boundary
    # rather than a capability boundary, which is not what the split above is. That one is real and
    # was measured (item 073, and `credentials.py` records how).
    #
    # What the rewrite costs, said plainly so nothing goes on relying on it: **nobody may infer
    # that a model was called from the fact that something was pushed.** Two paths hold this token
    # now — an agent's fix and a verified upgrade — and only the attempt trail can tell them apart.
    forge_code_token: SecretStr | None = None

    # The error tracker's READ api (item 036). Optional: without it Hullwork behaves exactly as it
    # did in M1 — ingest, dedup, triage, file — and the agent simply has less to work with. The
    # token needs `event:read` and nothing else; the one this replaced held all sixteen scopes and
    # could delete any issue or project in the organisation.
    tracker_url: str | None = None
    tracker_token: SecretStr | None = None

    # The organisation the tracker's projects live under, needed only by the inventory sweep
    # (DR-0011). It cannot be discovered: the `event:read` token this uses is refused
    # `/api/0/organizations/` and `/api/0/projects/` — measured, 403 — which is correct least
    # privilege and means an operator has to say it. Unset simply means no sweep.
    tracker_org: str | None = None

    # --- the model, and any provider you like -------------------------------------------------
    #
    # DR-0004: Hullwork integrates no provider and privileges none. All model traffic goes through
    # its own gateway, so switching provider is these three settings and nothing else — the sandbox
    # only ever sees the gateway's address, and the engine image only ever sees a base URL.
    #
    #   Anthropic          https://api.anthropic.com          bearer      claude-…
    #   OpenAI             https://api.openai.com             bearer      gpt-…
    #   Moonshot / Kimi    https://api.moonshot.ai            bearer      kimi-…
    #   DeepSeek           https://api.deepseek.com           bearer      deepseek-…
    #   Groq               https://api.groq.com/openai        bearer      llama-…
    #   OpenRouter         https://openrouter.ai/api          bearer      any/model
    #   vLLM / Ollama      http://your-box:11434              bearer      whatever you serve
    #
    # The gateway reads which model actually answered off the wire for both protocol families, so
    # the seal works the same whichever of these you point it at.
    model_endpoint: str = "https://api.anthropic.com"
    model_auth_style: Literal["bearer", "x-api-key"] = "bearer"
    #: Pinned explicitly (DR-0002). A response from anything else is a recorded violation, not a
    #: shrug — `allow_fallbacks: false` is a request to a provider and this is a measurement.
    model_name: str | None = None
    #: **The supported way to authenticate** (DR-0004, amended 2026-07-28). Any provider that
    #: issues an API key, which is all of them.
    model_key: SecretStr | None = None

    #: What the operator pays, per **million** tokens, one price per billing category (item 133).
    #:
    #: **No price table ships with Hullwork and none ever will.** DR-0004: this repository
    #: integrates no provider and privileges none; a bundled list would privilege every one on it,
    #: go stale on the first repricing, and make an instance print a *wrong* cost — worse than
    #: printing tokens and letting its operator multiply. Unset means money never appears.
    #:
    #: Four rather than two because they are billed at rates differing by an order of magnitude: a
    #: cached read is the cheapest thing on the invoice and a cache write the most expensive. An
    #: operator who prices only some of them gets a figure that says which ones it is missing.
    model_price_input: float | None = Field(default=None, ge=0)
    model_price_output: float | None = Field(default=None, ge=0)
    model_price_cache_write: float | None = Field(default=None, ge=0)
    model_price_cache_read: float | None = Field(default=None, ge=0)
    #: Whatever the operator is billed in. Printed, never converted: an exchange rate is a number
    #: that would be wrong by the time anybody read it.
    model_price_currency: str = "USD"

    #: What one attempt may spend before the gateway stops forwarding, in tokens, counting
    #: everything the wire reports (item 137). Unset means no ceiling — which is how every instance
    #: has run until now, so nothing changes for anybody who does not set it.
    #:
    #: **Enforced at the gateway**, the one process that sees every response, and the attempt it
    #: stops is `abandoned` and **does not consume the item's one try**: the agent was working when
    #: the operator's own budget cut it off, and DR-0003's accounting is about the agent. A ceiling
    #: that silently spent items is a ceiling nobody would dare set.
    #:
    #: **It can only bind on what the wire reports, and some endpoints report nothing** (item 148).
    #: Measured against OpenRouter's Anthropic-compatible route: every streamed message carries a
    #: zeroed `usage`, the real accounting arrives in the harness's closing event, and one attempt
    #: spent 1.2 million cache-read tokens under a one-million ceiling without it noticing because
    #: none of them were counted. Nothing is assumed in place of the missing numbers: the seal says
    #: `null` where the wire said nothing, and carries `unmeasured` naming the categories that no
    #: completion reported. **An empty `unmeasured` means the ceiling was real; a populated one
    #: means it was decorative**, and that is the thing to read before relying on this.
    max_attempt_tokens: int | None = Field(default=None, gt=0)

    #: Models that may answer, beyond the pinned one (item 137). Comma-separated; empty keeps
    #: DR-0002's rule exactly — only `model_name` is acceptable and anything else is a violation.
    #:
    #: A different question from `model_name`, which says what to *ask for*. This says what is
    #: acceptable to have *answered*, which is what an operator with a fallback needs to express.
    model_allowed: str | None = None

    #: Where this deployment's own two files are, **as this process sees them**. Item 144.
    #:
    #: `doctor` has compared what an environment file assigns against what the compose passes on
    #: since item 074, and had **never once run**: its paths defaulted to `./.env` and
    #: `./docker-compose.yml`, relative to the working directory, which inside the container is
    #: `/app` — and the real files are on the host. So the mechanism that would have caught every
    #: defect of 2026-08-04, all of them *configured and never arrived*, was pointed at a directory
    #: it could not see, and reported nothing rather than reporting that it could not look.
    #:
    #: Bind-mount them read-only and name them here. Unset is not an error and not a pass: `doctor`
    #: says the deployment was not checked, and why.
    deployment_env_file: str | None = None
    deployment_compose_file: str | None = None

    #: How many turns the agent gets per phase, overriding the engine's own default. Item 062.
    #:
    #: **The only real bound on what one attempt can spend**, so it is the number an operator most
    #: needs to be able to try — and until this existed it was a literal in `engine.REGISTRY`, which
    #: meant answering item 059's open question required a source edit and a redeploy. Absent leaves
    #: each engine's own number alone, so an instance that sets nothing behaves exactly as before.
    #:
    #: Instance configuration and never the manifest's: a repository that could raise this would be
    #: spending the operator's tokens, which is DR-0004's rule about endpoints applied to the same
    #: question.
    max_turns: int | None = Field(default=None, gt=0)

    #: Every optional field an operator can leave blank in a compose file or an environment file.
    #: Item 115, and it is item 082's lesson finished rather than repeated.
    #:
    #: That item wrote the same validator for `max_turns` and its docstring claimed the problem was
    #: *"fine for every `str | None` field here"*. **It is not fine for a `SecretStr`**: pydantic
    #: turns `""` into `SecretStr("")`, which is not `None` and is **truthy as an object**, so every
    #: `if settings.token` in this codebase reads an unset credential as a set one.
    #:
    #: Measured the moment `hullwork init` existed, because a scaffold names every variable and
    #: leaves it empty — which is what an operator does too. `HULLWORK_ERROR_DSN=` with nothing
    #: after it stopped the receiver from starting at all: *"HULLWORK_ERROR_DSN is set but the
    #: error-reporting SDK is not installed"*, on a deployment that had never asked for it. The
    #: same shape would have handed the forge an empty token and turned "not configured" into a
    #: 401 four layers away.
    _BLANKABLE = (
        "forge_url", "forge_token", "forge_code_token", "forge_kind",
        "tracker_url", "tracker_token", "tracker_org",
        "model_name", "model_key", "model_credentials_file", "model_price_currency",
        "model_allowed",
        "deployment_env_file", "deployment_compose_file",
        "error_dsn", "release",
        # `HULLWORK_UPSTREAM_DSN=` in an environment file is how somebody switches off the reporting
        # baked into a published image, and it has to mean *unset* rather than an empty destination.
        "upstream_dsn",
    )

    @field_validator(*_BLANKABLE, mode="before")
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        """`FOO=` in an environment file means *not configured*, to every operator on earth."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator(
        "max_turns", "max_attempt_tokens",
        "model_price_input", "model_price_output",
        "model_price_cache_write", "model_price_cache_read",
        mode="before",
    )
    @classmethod
    def _absent_is_not_empty(cls, value: object) -> object:
        """An empty string means "not configured", not "malformed". Item 082.

        **The compose file cannot express absence.** Every variable there is written
        `"${HULLWORK_X:-}"`, which passes an *empty string* when the operator has not set it —
        fine for every `str | None` field here, and a hard start-up failure for a numeric one:
        `Input should be a valid integer`. Measured as a restart loop the first time the dispatcher
        was containerised.

        This does not weaken this module's opening rule. Falling back to a default that makes the
        instance *less safe* is what that rule forbids; `None` here means "leave the engine's own
        ceiling alone", which is precisely what an unset variable is asking for. A value that is
        present and malformed — `"sixty"` — still stops the process, which is the case the rule is
        about.

        **Every numeric setting, not just `max_turns`** — measured in production on
        2026-08-04, trying to plumb items 133 and 137 into a live instance. Both items added
        numeric settings and neither reached this list, so writing them into a compose file the
        ordinary way put two containers into the restart loop this validator exists to prevent:
        *"model_price_input: Input should be a valid number … input_value=''"*. That is why those
        five settings had never been plumbed anywhere — the first person to try could not start the
        process, and the ceiling of item 137 was unreachable from any installation as a result.

        `_BLANKABLE` above is the same rule for string fields. A numeric setting added in future
        belongs in this decorator on the day it is added; a string one belongs in that tuple.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    #: **Development only, and not a supported configuration** (DR-0004, amended 2026-07-28). Reads
    #: a Claude Code subscription's access token from disk on every request, which is how Hullwork's
    #: own dogfood runs at no marginal cost. Setting it logs a warning at start-up.
    #:
    #: It is not supported because the token expires in about five hours and its refresh belongs to
    #: the CLI that wrote it — so making it work for a user would mean Hullwork storing and rotating
    #: somebody's Claude account credential. `claude setup-token` produces a long-lived token that
    #: works through `model_key` like any other; that is the user's own call to make, and the docs
    #: do not recommend it either way.
    model_credentials_file: str | None = None

    # Hullwork's own errors. Unset means no reporting at all and no SDK loaded — the tool does not
    # phone anywhere unless told to. Setting it requires `pip install hullwork[telemetry]`, and
    # start-up fails loudly if it is set without that, rather than quietly reporting nothing.
    error_dsn: SecretStr | None = None

    # **Where Hullwork's own crashes are reported to *us*. Item 152, and it is not in this file.**
    #
    # There is no default and there never may be one: this repository contains no destination, which
    # is why `test_no_destination_is_hidden_in_the_source_tree` can check by reading rather than
    # asking anybody to trust the code. A build made from a checkout has nowhere to send anything.
    #
    # The published image is the exception, and it is deliberate: the release workflow bakes a DSN
    # into it from a repository secret, so the artefact we hand out reports its own defects and a
    # build you make yourself does not. Extracting it from the image is expected — a Sentry DSN is a
    # public write-only key — which is why the ingest in front of it is rate-limited (item 154).
    #
    # What travels is not an event: `upstream.upstream_payload` constructs it out of an enumerated
    # set of fields, and cannot carry a message, a local, a URL or a hostname.
    upstream_dsn: SecretStr | None = None

    # The switch, for the operator who wants the published image and not the reporting. `off` stops
    # it; anything else leaves it as the build set it.
    #
    # A separate variable rather than `HULLWORK_UPSTREAM_DSN=`, because the two say different
    # things:
    # emptying the DSN is *"I built this and there is nowhere to send it"*, while this is *"I have
    # your build and I am declining"*. `hullwork init` writes it, so it is a line somebody reads
    # before it is a line somebody searches for.
    telemetry: str = "on"

    # **Narrowing, for the operator whose situation requires it** — DR-0007's *"default open,
    # narrowable"*, item 068. Empty means no narrowing at all, which is the default and the shipped
    # behaviour: a project names its base image and its apt packages and this instance builds them.
    #
    # Who needs these: somebody running Hullwork against repositories they do not control, or inside
    # a
    # network where only one registry is reachable. Nobody else should have to think about them,
    # which
    # is why they are off rather than a starter list somebody has to widen.
    #
    # Enforced at `hullwork projects add` and `refresh` — the moment a manifest is read and an
    # operator
    # is present to be told — and not at build time, where the refusal would arrive after an item
    # was
    # claimed and an attempt started (the shape item 048 fixed for engines).
    allowed_base_images: list[str] = Field(default_factory=list)
    allowed_packages: list[str] = Field(default_factory=list)

    # How large a sandbox image may get, in GiB. Raise it for a project that really is that big; the
    # bound exists so a runaway install is named rather than silent (item 068).
    build_size_limit_gib: int = Field(default=8, ge=1)

    # Labels this instance's own reports. Only meaningful alongside `error_dsn`.
    environment: str = "production"

    # What to call the deployed code in this instance's own reports. Unset means the package
    # version, which is what it was before M9 and is wrong for the one question M9 asks: a version
    # string cannot be compared to a merge commit, so every recurrence of an error Hullwork reported
    # about *itself* resolved to `undecidable` for ever. Measured on the live instance — seven
    # events tagged `0.1.0.dev0` against four merged fixes, none of them decidable.
    #
    # A commit here makes them decidable, and there is nowhere else the sha can come from: the
    # container has no git directory, so the deployment has to say. Optional on purpose — an
    # instance that does not set it keeps the old behaviour rather than failing to start.
    release: str | None = None

    # How often to finish work that an earlier pass could not: deliveries left mid-flight, and
    # items still owed an issue because the forge was unreachable at the time. A clock of our own
    # is required rather than convenient — an error tracker notifies once per issue and never
    # again, so waiting for the next delivery can mean waiting forever. 0 disables it, which is
    # only correct when something external drives the sweep.
    sweep_interval_seconds: int = Field(default=60, ge=0)

    # How long before an item's forge issue is worth asking about again. The sweep runs every
    # minute; asking the forge about every open item that often would be one API call per item per
    # minute for as long as the item lives, to learn something that changes once.
    forge_recheck_seconds: int = Field(default=600, ge=0)


def _render(exc: ValidationError) -> str:
    """Turn a pydantic error into something an operator can act on without reading a traceback."""
    lines = ["Invalid configuration. Fix the environment and start again:"]
    for error in exc.errors():
        name = ".".join(str(part) for part in error["loc"]) or "(root)"
        variable = f"HULLWORK_{name.upper()}"
        lines.append(f"  {variable}: {error['msg']}")
    return "\n".join(lines)


#: The one sub-namespace inside `HULLWORK_*` that is **not** a setting. It carries the harness
#: contract into an agent phase — which phase, where tests may be written, what the lint gate runs —
#: and it is read by a shell script inside the sandbox, never by `Settings`.
#:
#: **Why a prefix rather than a list of the five names in use** (item 099): a list is right until
#: somebody adds the sixth, and the failure mode is not a mistake anybody sees. Measured: five
#: variables in that namespace were handed to an agent phase, `_unknown_variables` rejected them
#: correctly, and about four hundred of this project's own tests errored at setup *inside the phase
#: whose whole purpose is to run them*. The gates never saw it, because `_run_gate` passes no
#: environment at all — so the one place the suite is supposed to be runnable was the only place it
#: was not, and the only trace was the agent mentioning it in prose.
AGENT_PREFIX = "HULLWORK_AGENT_"


def _unknown_variables() -> list[str]:
    """Find `HULLWORK_*` variables that match no setting.

    `extra="forbid"` does not cover this: it applies to the `.env` file and to explicit arguments,
    while unmapped environment variables are simply ignored. So a typo in a security-relevant
    variable would look like it took effect. We check for it ourselves.

    `HULLWORK_AGENT_*` is exempt and named as such — see `AGENT_PREFIX`. The guard keeps its meaning
    for everything else, which is the point: this widens the namespace by one documented sub-prefix
    rather than weakening the check that has caught two real typos.
    """
    known = {f"HULLWORK_{name.upper()}" for name in Settings.model_fields}
    return sorted(
        name
        for name in os.environ
        if name.startswith("HULLWORK_")
        and not name.startswith(AGENT_PREFIX)
        and name not in known
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load and cache the settings, or fail with a message instead of a stack trace."""
    if unknown := _unknown_variables():
        listed = ", ".join(unknown)
        raise ConfigError(
            "Invalid configuration. Fix the environment and start again:\n"
            f"  unknown variable(s), likely a typo: {listed}"
        )
    try:
        return Settings()
    except ValidationError as exc:
        raise ConfigError(_render(exc)) from exc
