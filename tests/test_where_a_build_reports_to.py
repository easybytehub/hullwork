"""The destination lives in the artefact, not in the source. Item 152.

The operator's criterion, and it is the whole item: **the build we publish reports to us; a build
you make yourself sends nothing, and you control the environment either way.**

That shape was chosen because it is verifiable by reading. A variable with a hidden default asks
somebody to trust a codebase; a DSN that exists only in a published image is a fact anybody can
check with `grep` — which is what `test_no_destination_is_hidden_in_the_source_tree` does, in the
suite, so it stays true rather than having been true once.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import SecretStr

from hullwork import settings_report, telemetry, upstream
from hullwork.config import Settings

ROOT = Path(__file__).resolve().parent.parent

#: A DSN, as a reader would recognise one: a scheme, a key, an `@`, a host, a project number.
DSN_SHAPED = re.compile(r"https?://[A-Za-z0-9]{4,}@[A-Za-z0-9.\-]+(?::\d+)?/\d+")

#: Hosts a DSN-shaped string in this repository is allowed to point at: the loopback, and the names
#: RFC 2606 and RFC 6761 reserve so that no real machine can ever answer them.
#:
#: **Suffixes rather than a list of names**, which the first version got wrong: it enumerated
#: `example.com` and then failed on `errores.example.com` — a reserved name by construction. A rule
#: that rejects reserved subdomains teaches people to add exceptions, which is how a whitelist rots.
RESERVED = (".example", ".example.com", ".example.org", ".example.net", ".invalid", ".test")
LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def _is_unroutable(host: str) -> bool:
    """A host that cannot be a real destination, whoever typed it."""
    if host in LOOPBACK or host.startswith("127."):
        return True
    return host.endswith(RESERVED) or host in {"example.com", "example.org", "example.net"}


#: Directories that are not this project's source: a virtualenv holds thousands of files and any DSN
#: in one belongs to somebody else's package.
NOT_OURS = frozenset({".git", ".venv", "venv", "__pycache__", "node_modules", ".mypy_cache",
                      ".ruff_cache", ".pytest_cache", "htmlcov", "dist", "build"})


def _source_files() -> list[Path]:
    """Every file in the tree, whatever this checkout is.

    **A walk rather than `git ls-files`, and that is a correction.** The first version asked git and
    failed in the one tree where it matters most: the derived public tree, which is built by
    `scripts/publish.sh` and is not a repository until the moment it is pushed. A release tarball is
    not one either.

    A walk is also stricter. `git ls-files` cannot see a file somebody forgot to add, and a file
    somebody forgot to add is exactly where an experiment with a real DSN would still be sitting.
    """
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not NOT_OURS & set(path.relative_to(ROOT).parts)
    ]


def _crash_in_our_own_code() -> dict[str, Any]:
    return {
        "exception": {
            "values": [
                {
                    "type": "ManifestError",
                    "value": "acme/checkout-api at tracker.cliente-real.es",
                    "stacktrace": {
                        "frames": [
                            {
                                "module": "hullwork.manifest",
                                "function": "parse_manifest",
                                "lineno": 707,
                                "vars": {"text": "registry.cliente-real.es"},
                            }
                        ]
                    },
                }
            ]
        },
        "server_name": "srv-acme-01",
    }


# --------------------------------------------------------------------------------------------
# The property that makes the claim checkable rather than promised
# --------------------------------------------------------------------------------------------


def test_no_destination_is_hidden_in_the_source_tree() -> None:
    """**The item's first criterion, and the reason the design is shaped this way.**

    Every tracked file, not the ones somebody thought to check: a default in `config.py` is the
    obvious place, and a constant in `scaffold.py`, a compose file or a documented example would do
    the same job while looking like documentation.

    Text files only, and a size bound: this walks the whole repository, and the images are not where
    a DSN would be typed.
    """
    found: list[str] = []
    for path in _source_files():
        big = path.stat().st_size > 2_000_000
        if big or path.suffix in {".png", ".svg", ".ico", ".whl", ".gz"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for dsn in DSN_SHAPED.findall(text):
            host = dsn.split("@", 1)[1].split("/")[0].split(":")[0]
            if not _is_unroutable(host):
                found.append(f"{path.relative_to(ROOT)}: {host}")

    assert not found, (
        "a destination is in the source tree, so 'a build you make yourself sends nothing' is no "
        f"longer true: {found}"
    )


def test_a_checkout_has_nowhere_to_send_anything() -> None:
    """The same property from the other side: the settings a plain checkout produces."""
    settings = Settings(database_url="sqlite://")

    assert settings.upstream_dsn is None
    assert upstream.destination(settings) is None
    assert telemetry.configure_error_reporting(settings) is False


def test_the_release_workflow_bakes_the_destination_from_a_secret() -> None:
    """The drift guard the pinning rule got, and for the same reason.

    Asserted on the workflow's text because there is no way to run it here — and by name, because
    the failure of an unset secret is an image that reports nowhere, which looks exactly like
    success.
    """
    text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "--build-arg UPSTREAM_DSN=" in text, "the release does not bake a destination at all"
    assert "secrets.UPSTREAM_DSN" in text, "the value has to come from a repository secret"
    assert 'UPSTREAM_DSN: ${{ secrets.UPSTREAM_DSN }}' in text, (
        "pass it through the step's environment, not interpolated into the shell script"
    )
    assert text.index("secrets.UPSTREAM_DSN") < text.index("docker buildx build"), (
        "the secret has to be in the environment before the build that reads it"
    )


def test_the_dockerfile_takes_it_as_a_build_argument_and_defaults_to_nothing() -> None:
    """`ARG UPSTREAM_DSN=` with nothing after it: the default is no destination.

    The pair matters — an `ARG` nothing turns into an `ENV` is inert, and an `ENV` with a literal in
    it would be the thing this whole item exists to avoid.
    """
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert re.search(r"^ARG UPSTREAM_DSN=\s*$", text, re.MULTILINE), (
        "the build argument must exist and must default to empty"
    )
    assert 'ENV HULLWORK_UPSTREAM_DSN="${UPSTREAM_DSN}"' in text, (
        "the argument has to reach the setting, and only through the argument"
    )


# --------------------------------------------------------------------------------------------
# Four combinations, because two destinations must not silence each other
# --------------------------------------------------------------------------------------------

OURS = "https://clavepublica@errores.example.com/3"
THEIRS = "https://k@tracker.example/1"


@pytest.mark.parametrize(
    ("error_dsn", "upstream_dsn", "telemetry_setting", "sends_upstream", "reports_theirs"),
    [
        (None, None, "on", False, False),
        (None, OURS, "on", True, False),
        (THEIRS, None, "on", False, True),
        (THEIRS, OURS, "on", True, True),
        (THEIRS, OURS, "off", False, True),
        (None, OURS, "off", False, False),
    ],
)
def test_the_two_destinations_are_independent(
    error_dsn: str | None,
    upstream_dsn: str | None,
    telemetry_setting: str,
    sends_upstream: bool,
    reports_theirs: bool,
) -> None:
    """**Neither one silences the other**, in every combination the item names.

    Declining ours must not turn off a tracker the operator configured, and configuring theirs
    must not be a way to accidentally stop reporting defects to us — a mistake that would be easy to
    make and impossible to notice from either end.
    """
    settings = Settings(
        database_url="sqlite://",
        error_dsn=SecretStr(error_dsn) if error_dsn else None,
        upstream_dsn=SecretStr(upstream_dsn) if upstream_dsn else None,
        telemetry=telemetry_setting,
    )

    assert (upstream.destination(settings) is not None) is sends_upstream
    assert (settings.error_dsn is not None) is reports_theirs


@pytest.mark.parametrize("declined", ["off", "OFF", " off ", "false", "0", "no", ""])
def test_declining_is_generous_about_how_it_is_written(declined: str) -> None:
    """Somebody switching this off is declining, and a decline that did not take effect because they
    wrote `false` instead of `off` is the worst outcome available here.
    """
    settings = Settings(
        database_url="sqlite://", upstream_dsn=SecretStr(OURS), telemetry=declined
    )
    assert upstream.destination(settings) is None


def test_an_emptied_dsn_is_no_destination_rather_than_an_empty_one() -> None:
    """`HULLWORK_UPSTREAM_DSN=` in an environment file, which is how somebody edits it out."""
    settings = Settings(database_url="sqlite://", upstream_dsn="")  # type: ignore[arg-type]
    assert settings.upstream_dsn is None
    assert upstream.destination(settings) is None


# --------------------------------------------------------------------------------------------
# What an operator can see
# --------------------------------------------------------------------------------------------


def test_config_names_the_host_and_never_the_key() -> None:
    """The item's fourth criterion. An operator is entitled to know where their instance talks to
    without being handed a credential to read out — and *"set"* would be the honest answer to a
    question nobody asked.
    """
    settings = Settings(database_url="sqlite://", upstream_dsn=SecretStr(OURS))
    printed = "\n".join(settings_report.lines(settings))

    assert "errores.example.com" in printed
    assert "clavepublica" not in printed
    assert "reports to" in printed


def test_config_says_when_it_has_been_declined() -> None:
    """A destination that is present and switched off must not read as one that is sending."""
    settings = Settings(
        database_url="sqlite://", upstream_dsn=SecretStr(OURS), telemetry="off"
    )
    printed = "\n".join(settings_report.lines(settings))

    assert "declined" in printed
    assert "clavepublica" not in printed


def test_the_scaffold_writes_the_switch_with_the_sentence_that_explains_it() -> None:
    """`hullwork init` is where somebody meets this, so the variable arrives with its reason.

    A switch nobody can find is not a choice, and the file `init` writes is the one place an
    operator reads every variable in order.
    """
    from hullwork import scaffold

    env = scaffold.environment(docker_gid=None)

    assert "HULLWORK_TELEMETRY=on" in env
    assert "upstream.py" in env, "point at the file, because it is short and it is the whole of it"
    for promise in ("hostname", "message", "constructed"):
        assert promise in env, f"the notice has to say what it cannot carry: {promise}"


def test_the_settings_report_covers_the_new_variables() -> None:
    """Both appear on the one screen that answers *what is this instance set to* (item 146)."""
    printed = "\n".join(settings_report.lines(Settings(database_url="sqlite://")))

    assert "HULLWORK_UPSTREAM_DSN" in printed
    assert "HULLWORK_TELEMETRY" in printed


# --------------------------------------------------------------------------------------------
# The wire, measured rather than assumed
# --------------------------------------------------------------------------------------------


def test_what_the_sdk_would_have_added_after_before_send() -> None:
    """**The defect this design was corrected for, kept as a test.**

    The first version handed the constructed payload to `sentry_sdk.Client.capture_event`, on the
    reasoning that a fresh dict returned from `before_send` is exactly what travels. Measured
    against a local ingest on 2026-08-06: what arrived was the payload **plus `environment` and
    `server_name`** — the client adds both *after* the hook — so the operator's environment name and
    their machine's hostname went upstream from a payload that contained neither.

    This asserts the property that replaced it: `Destination` builds the envelope itself, so what is
    sent is what `rendered` returns and nothing else. Checked by comparing keys against the render
    rather than by sending, because the network is not what is in question here.
    """
    destination = upstream.Destination(OURS, operation="receiver")
    rendered = destination.rendered(_crash_in_our_own_code())
    assert rendered is not None

    assert "server_name" not in rendered
    assert "environment" not in rendered
    assert "modules" not in rendered
    assert "sdk" not in rendered, "the SDK's own version block is added by the client, not by us"

    blob = json.dumps(rendered)
    for theirs in ("srv-acme-01", "acme/checkout-api", "cliente-real"):
        assert theirs not in blob


def test_the_envelope_carries_the_key_in_the_header_and_not_in_the_body() -> None:
    """A stored envelope should hold no credential — item 154's relay stores these."""
    destination = upstream.Destination(OURS, operation="receiver")

    # Private methods on purpose: what is being asserted is the URL and the key this DSN implies,
    # and neither has a public accessor because neither is anybody's business but the sender's.
    assert destination._ingest_url() == "https://errores.example.com/api/3/envelope/"
    assert destination._key() == "clavepublica"
    assert destination.host == "errores.example.com"


@pytest.mark.parametrize("dsn", ["file:///etc/passwd", "gopher://x@host/1", "ftp://k@host/1"])
def test_a_dsn_that_is_not_http_is_refused(dsn: str) -> None:
    """A DSN is configuration, and a `file:` URL reaching `urlopen` would make a crash report read a
    path instead of sending one.
    """
    with pytest.raises(ValueError, match="http"):
        upstream.Destination(dsn, operation="receiver")._ingest_url()


def test_the_ceiling_stops_a_crash_loop_at_twenty() -> None:
    """These leave somebody else's network and arrive at ours. A crash loop under
    `restart: unless-stopped` would otherwise spend their bandwidth to say one sentence.
    """
    destination = upstream.Destination(OURS, operation="receiver", ceiling=3)
    crash = _crash_in_our_own_code()

    assert [destination.rendered(crash) is not None for _ in range(5)] == [
        True,
        True,
        True,
        False,
        False,
    ]


def test_nothing_upstream_is_attempted_for_a_crash_that_is_not_ours() -> None:
    """The rule from item 151, through the destination: not our frames, not our defect."""
    destination = upstream.Destination(OURS, operation="receiver")
    theirs = {
        "exception": {
            "values": [
                {
                    "type": "KeyError",
                    "stacktrace": {
                        "frames": [{"module": "acme.billing", "function": "charge", "lineno": 88}]
                    },
                }
            ]
        }
    }

    assert destination.rendered(theirs) is None
    assert destination.offer(theirs) is False


def test_an_unreachable_database_still_lets_a_crash_travel_uncounted() -> None:
    """**The first run is the one most worth hearing about**, and it has no identifier yet.

    Item 150 measured what a broken database does to a running instance. Asking it again per event,
    inside a crash handler, would turn one failure into a connection attempt per report — so the
    answer is remembered, including when the answer was *no*.
    """
    asked = []

    def factory() -> object:
        asked.append(1)
        msg = "no such table: installation"
        raise RuntimeError(msg)

    destination = upstream.Destination(OURS, operation="receiver", session_factory=factory)

    first = destination.rendered(_crash_in_our_own_code())
    second = destination.rendered(_crash_in_our_own_code())

    assert first is not None and second is not None
    assert first["tags"]["installation"] == "unknown"
    assert len(asked) == 1, "the database was asked twice after it had already failed"


def test_the_compose_file_the_scaffold_writes_still_parses() -> None:
    """Cheap, and it has caught worse: the deploy environment gained a block in this item."""
    from hullwork import scaffold

    parsed = yaml.safe_load(scaffold.compose(docker_gid="998"))
    assert "services" in parsed
