"""Said before the first event, not after somebody finds out. Item 153.

The published image reports without being asked, which was the operator's decision and item 152's
criterion. **The difference between that being acceptable and being a scandal is entirely in this
file and the documents it checks**, not in the payload or the destination.

Next.js, Homebrew and the .NET CLI report by default and are broadly accepted; Gatsby and Audacity
did the same and were not. What differed was never the default — it is whether the terminal tells
you before anything is sent, and whether one variable stops it. This project can go further than any
of them, because the exact bytes are printable.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest
from pydantic import SecretStr

from hullwork import upstream
from hullwork.cli import main
from hullwork.config import Settings

ROOT = Path(__file__).resolve().parent.parent

OURS = "https://clavepublica@errores.example.com/3"

#: The sentence that was true until 2026-08-06. It may appear **struck**, because a claim made in
#: public is not something to quietly edit — but never as a live claim.
THE_OLD_CLAIM = "There is no telemetry to us"


def test_the_terminal_says_it_before_the_sdk_is_armed() -> None:
    """**Ordering, and it is structural rather than remembered.**

    The notice is printed inside `configure_error_reporting`, before `sentry_sdk.init` — so at the
    moment reporting becomes possible, the sentence has already been written. A notice printed by
    the caller afterwards would be correct on every path somebody remembered.
    """
    import sentry_sdk

    from hullwork import telemetry

    said = io.StringIO()
    try:
        assert telemetry.configure_error_reporting(
            Settings(database_url="sqlite://", upstream_dsn=SecretStr(OURS)),
            operation="receiver",
            notify=said,
        )
    finally:
        sentry_sdk.init(dsn=None)  # leave no live client behind for the rest of the suite

    printed = said.getvalue()
    assert "errores.example.com" in printed, "nobody can check a destination they are not told"
    assert "HULLWORK_TELEMETRY=off" in printed, "a notice without the switch is an announcement"
    assert "hullwork config --telemetry" in printed
    assert "clavepublica" not in printed


def test_the_notice_names_what_cannot_be_sent_and_not_only_what_can() -> None:
    """*"We collect anonymous usage data"* is the sentence nobody believes, and rightly.

    The claim that earns trust is the negative one, so the notice makes it: no message, no locals,
    no URLs, no hostname, no repository names, nothing from the operator's own errors.
    """
    printed = upstream.notice("errores.example.com")

    for promise in ("message", "local variables", "URLs", "hostname", "repository names"):
        assert promise in printed, f"the notice does not say it cannot send: {promise}"
    assert "build yourself" in printed, "the strongest fact is that their own build sends nothing"


def test_a_build_with_no_destination_says_nothing_at_all() -> None:
    """No notice in a checkout, because there is nothing to disclose and a paragraph about telemetry
    that does not happen is its own kind of noise.
    """
    from hullwork import telemetry

    said = io.StringIO()
    plain = Settings(database_url="sqlite://")

    assert telemetry.configure_error_reporting(plain, notify=said) is False
    assert said.getvalue() == ""


# --------------------------------------------------------------------------------------------
# `hullwork config --telemetry`: the project's own standard, applied to itself
# --------------------------------------------------------------------------------------------


def test_config_telemetry_prints_the_payload_and_not_a_description(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """**Asked, not assumed** — the rule this project applies to operators, applied to us.

    A prose description of a payload is exactly the kind of claim the product exists to distrust. So
    the command prints the object, parses as JSON, and the test reads it as one.
    """
    monkeypatch.setenv("HULLWORK_UPSTREAM_DSN", OURS)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", f"sqlite:///{tmp_path / 'x.db'}")
    from hullwork.config import get_settings

    get_settings.cache_clear()

    said = io.StringIO()
    assert main(["config", "--telemetry"], out=said) == 0
    printed = said.getvalue()

    found = re.search(r"\{\n.*?\n\}", printed, re.DOTALL)
    assert found, f"no payload was printed:\n{printed}"
    payload = json.loads(found.group())

    assert set(payload) == upstream.KEYS, "what is printed is not what would be sent"
    assert payload["operation"] == "cli:config"
    assert payload["frames"], "an empty stack proves nothing about what a real crash would send"
    assert all(frame["module"].startswith("hullwork") for frame in payload["frames"])
    assert "clavepublica" not in printed
    assert "errores.example.com" in printed, "say where, so the reader can check it themselves"

    get_settings.cache_clear()


def test_looking_does_not_enrol_you(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """**The command that exists so somebody can decide must not decide for them.**

    `installation_id` mints on first use, and the first use would otherwise be this command — so
    running `config --telemetry` to find out what would be sent would create the row that identifies
    the person asking. It reads with `mint=False`, and this is that assertion.
    """
    import argparse as _argparse

    from alembic import command
    from alembic.config import Config

    url = f"sqlite:///{tmp_path / 'looking.db'}"
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.cmd_opts = _argparse.Namespace(x=[f"url={url}"])
    command.upgrade(config, "head")

    monkeypatch.setenv("HULLWORK_UPSTREAM_DSN", OURS)
    monkeypatch.setenv("HULLWORK_DATABASE_URL", url)
    from hullwork.config import get_settings

    get_settings.cache_clear()

    said = io.StringIO()
    assert main(["config", "--telemetry"], out=said) == 0
    printed = said.getvalue()

    import sqlite3

    rows = sqlite3.connect(tmp_path / "looking.db").execute(
        "select count(*) from installation"
    ).fetchone()[0]
    assert rows == 0, "asking what would be sent created the row that identifies the asker"
    assert '"installation": null' in printed
    assert "does not create one" in printed, "explain the null, or it reads as a bug"

    get_settings.cache_clear()


def test_config_telemetry_in_a_build_with_no_destination_says_so(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HULLWORK_DATABASE_URL", f"sqlite:///{tmp_path / 'x.db'}")
    monkeypatch.delenv("HULLWORK_UPSTREAM_DSN", raising=False)
    from hullwork.config import get_settings

    get_settings.cache_clear()

    said = io.StringIO()
    assert main(["config", "--telemetry"], out=said) == 0
    printed = said.getvalue()

    assert "no destination" in printed
    assert "{" not in printed, "there is no payload to print, so printing one would be a fiction"

    get_settings.cache_clear()


def test_config_telemetry_says_when_it_has_been_declined(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A destination present and switched off is a third state, and it must not read as either
    of the other two.
    """
    monkeypatch.setenv("HULLWORK_UPSTREAM_DSN", OURS)
    monkeypatch.setenv("HULLWORK_TELEMETRY", "off")
    monkeypatch.setenv("HULLWORK_DATABASE_URL", f"sqlite:///{tmp_path / 'x.db'}")
    from hullwork.config import get_settings

    get_settings.cache_clear()

    said = io.StringIO()
    assert main(["config", "--telemetry"], out=said) == 0
    assert "declined with HULLWORK_TELEMETRY" in said.getvalue()

    get_settings.cache_clear()


# --------------------------------------------------------------------------------------------
# The documents. A documentation change nothing enforces is how the last one went stale.
# --------------------------------------------------------------------------------------------


def test_the_faq_no_longer_makes_the_claim_it_can_no_longer_make() -> None:
    """**The one failure this project cannot afford.**

    It sells checkable claims. Leaving *"There is no telemetry to us"* standing while the published
    image reports would be an uncheckable claim in the opposite direction — worse than never having
    made it, because somebody verified it once.

    Struck text is allowed and deletion is not: the sentence was published, and the honest record is
    that it was true and stopped being true on a date.
    """
    faq = (ROOT / "docs/faq.md").read_text(encoding="utf-8")

    assert THE_OLD_CLAIM in faq, "the old claim was deleted rather than struck; the record matters"
    assert f"~~{THE_OLD_CLAIM}" in faq, f"{THE_OLD_CLAIM!r} still reads as a live claim"
    assert "2026-08-06" in faq, "say when it stopped being true"

    for owed in ("hullwork config --telemetry", "HULLWORK_TELEMETRY=off", "PRIVACY.md"):
        assert owed in faq, f"the FAQ answer does not give the reader: {owed}"


def test_the_readme_corrects_its_second_principle_near_the_top() -> None:
    """*"Nothing leaves your network unless you configure it to"* was principle 2, and a correction
    in a footnote would be a worse failure than the original sentence.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Nothing leaves your network unless you configure it to" not in readme
    principle = readme[readme.index("2. **Your infrastructure, your keys.**") :][:1200]
    assert "reports" in principle and "HULLWORK_TELEMETRY=off" in principle
    assert "PRIVACY.md" in principle


def test_security_md_says_it_where_a_reader_looking_for_it_would_look() -> None:
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

    assert "### What leaves the instance" in security
    section = security[security.index("### What leaves the instance") :]
    assert "upstream.py" in section
    assert "HULLWORK_TELEMETRY=off" in section
    assert "hosted model" in section, "the bigger disclosure belongs beside the smaller one"


def test_the_privacy_note_answers_the_five_questions() -> None:
    """What, why, how long, how to stop, and who to ask. Short, and in the repository.

    A privacy page on a website nobody finds is a compliance artefact. This one sits beside
    `SECURITY.md`, which is where somebody evaluating this project is already reading.
    """
    privacy = (ROOT / "PRIVACY.md").read_text(encoding="utf-8")

    assert '"installation"' in privacy, "print the payload, do not describe it"
    assert "90 days" in privacy, "retention"
    assert "HULLWORK_TELEMETRY=off" in privacy, "how to stop it"
    assert "contact@easybyte.es" in privacy, "an address"
    assert "hash of a hostname is still the hostname" in privacy, "why the identifier is random"
    assert len(privacy.split()) < 1200, "a privacy note nobody finishes is not a disclosure"


def test_the_payload_in_the_privacy_note_is_the_payload_the_code_builds() -> None:
    """**The document could go stale and nothing would notice** — which is how the FAQ's sentence
    survived two days past being true.

    So the JSON block in `PRIVACY.md` is parsed and its keys compared against the enumerated set.
    Adding a field to the payload without editing this page fails here.
    """
    privacy = (ROOT / "PRIVACY.md").read_text(encoding="utf-8")

    block = re.search(r"```json\n(\{.*?\n\})\n```", privacy, re.DOTALL)
    assert block, "the privacy note no longer prints a payload"
    documented = json.loads(block.group(1))

    assert set(documented) == upstream.KEYS
    assert set(documented["counts"]) == upstream.COUNT_KEYS
    assert set(documented["frames"][0]) == upstream.FRAME_KEYS
    assert documented["schema"] == upstream.SCHEMA, (
        "the payload's schema changed and the page documenting it did not"
    )
