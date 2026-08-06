"""The findings from the first CodeQL run that were real, kept as tests. Item 161.

**100 alerts, and the honest arithmetic**: 89 were one quality rule firing on `migrations/versions`,
where every Alembic migration declares four module-level names its framework reads by name; 6 were
OpenSSF Scorecard's own policy scores, uploaded into the code-scanning tab by a workflow that no
longer does that; 1 was a false positive about a variable assigned two lines above its use.

What was left is what this file is about, and it was worth the noise:

* three constants that were fossils of superseded designs — two of them *contradicting* the comment
  beside the code that replaced them, in a codebase whose whole habit is explaining why;
* `is_github` deciding by substring, so `https://github.com.evil.example/` answered yes;
* a slug from a URL path reaching the log with its control characters intact.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from hullwork.forge import is_github
from hullwork.logging import RedactingFilter

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    ("url", "github"),
    [
        ("https://github.com/owner/repo", True),
        ("https://api.github.com", True),
        ("https://api.github.com/", True),
        ("github.com", True),
        ("https://www.github.com/owner", True),
        # **The four the substring version got wrong.** Each one answered `True`, and what that
        # answer decides is which client shape is built and which scope probe is sent (item 131) —
        # so a spoofable classification is a request shaped for one forge arriving at another.
        ("https://github.com.evil.example/owner/repo", False),
        ("https://notgithub.com/owner", False),
        ("https://forgejo.example.org/?upstream=github.com", False),
        ("https://gitea.example.org/github.com/owner", False),
    ],
)
def test_a_forge_is_github_by_its_host_not_by_a_substring(url: str, github: bool) -> None:
    assert is_github(url) is github


def test_the_hosts_that_are_not_github_are_still_not_github() -> None:
    """The negative case for the whole change: nothing legitimate stopped being recognised."""
    others = ("https://forgejo.easybyte.example", "https://gitlab.com/owner", "http://localhost:1")
    for url in others:
        assert is_github(url) is False


def _line(**fields: object) -> logging.LogRecord:
    record = logging.LogRecord(
        name="hullwork.test", level=logging.WARNING, pathname=__file__, lineno=1,
        msg="rejected webhook", args=(), exc_info=None,
    )
    for key, value in fields.items():
        setattr(record, key, value)
    return record


def test_a_newline_from_a_url_path_cannot_forge_a_log_line() -> None:
    """**The one CodeQL called `py/log-injection`, and it was right about one of the two formats.**

    `webhooks.py` logs the project slug of a *rejected* delivery, and a slug comes from the URL
    path, where `%0A` is decoded to a real newline before FastAPI hands it over. In `json` format
    the serialiser escapes it and nothing happens. In `text` format — what a person tails — a single
    request could write a second line indistinguishable from an entry of ours.

    Asserted at the filter rather than at the call site, because there is one filter and dozens of
    call sites, and the next field somebody logs from a request will not remember this.
    """
    forged = "innocent\n2026-08-06 12:00:00 WARNING  everything is fine"
    record = _line(project=forged, provider="glitchtip")

    assert RedactingFilter().filter(record) is True

    assert "\n" not in record.project  # type: ignore[attr-defined]
    assert "everything is fine" in record.project, (  # type: ignore[attr-defined]
        "the attempt is not dropped: a log that hides what it could not print is worse"
    )


def test_control_characters_are_flattened_everywhere_a_log_looks() -> None:
    """Nested, because `extra=` carries dicts and lists as often as strings."""
    record = _line(
        detail={"slug": "a\rb", "chain": ["c\nd", "e\x1b[2Jf"]},
        note=("g\th",),
    )

    assert RedactingFilter().filter(record) is True

    flat = f"{record.detail}{record.note}"  # type: ignore[attr-defined]
    for control in ("\r", "\n", "\x1b", "\t"):
        assert control not in flat


def test_the_message_itself_is_flattened_too() -> None:
    """`%`-formatted messages carry request data as often as `extra=` does."""
    record = logging.LogRecord(
        name="hullwork.test", level=logging.WARNING, pathname=__file__, lineno=1,
        msg="rejected %s", args=("slug\nWARNING forged",), exc_info=None,
    )

    assert RedactingFilter().filter(record) is True
    assert "\n" not in record.msg


def test_the_three_fossils_are_gone_and_stay_gone() -> None:
    """Named, because a dead constant is easy to reintroduce and its comment reads as authority.

    Each was the losing half of a design decision the code beside it had already made:
    `_PYTEST` was the one clever regex that `_PATTERNS` replaced *with a comment saying why*;
    `_MAVEN_SELECTORS` described carrying flags across, which the function it sat above stopped
    doing; `_CABLE_PROGRAM` was forty lines of socket forwarder for a container that runs
    `hullwork gateway`.
    """
    for module, fossil in (
        ("hullwork/testoutput.py", "_PYTEST"),
        ("hullwork/propose.py", "_MAVEN_SELECTORS"),
        ("hullwork/sandbox/net.py", "_CABLE_PROGRAM"),
    ):
        text = (ROOT / module).read_text(encoding="utf-8")
        assert fossil not in text, f"{fossil} is back in {module}"


def test_the_codeql_configuration_says_what_it_excludes_and_why() -> None:
    """An exclusion nobody can read is indistinguishable from an oversight.

    89 of 100 alerts were one rule on `migrations/versions`, and the cost of excluding it — those
    files are no longer analysed at all — is stated in the file rather than implied by its absence.
    """
    config = ROOT / ".github/codeql/config.yml"
    text = config.read_text(encoding="utf-8")

    assert "migrations/versions" in text
    assert "Alembic" in text, "the reason has to name the framework whose API those names are"
    assert "cost of this exclusion" in text, "and what it costs, or it is a silent narrowing"
