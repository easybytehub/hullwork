"""Redaction is a property of the logging pipeline, so these tests try to leak on purpose."""

import json
import logging

import pytest

from hullwork.logging import REDACTED, JsonFormatter, RedactingFilter, configure_logging

SECRET = "hw_live_4f9c2b7e1a"  # noqa: S105 - fixture value, not a real credential


def _emit(caplog: pytest.LogCaptureFixture, extra: dict[str, object]) -> logging.LogRecord:
    logger = logging.getLogger("test.redaction")
    with caplog.at_level(logging.INFO, logger="test.redaction"):
        logger.info("event happened", extra=extra)
    return caplog.records[-1]


def test_a_field_named_like_a_secret_is_redacted_whatever_it_holds(
    caplog: pytest.LogCaptureFixture,
) -> None:
    record = _emit(caplog, {"api_key": "anything at all", "project": "demo"})
    RedactingFilter().filter(record)

    assert record.__dict__["api_key"] == REDACTED
    assert record.__dict__["project"] == "demo"


def test_a_known_secret_is_redacted_even_mid_message() -> None:
    redactor = RedactingFilter([SECRET])
    record = logging.LogRecord(
        name="t", level=logging.INFO, pathname=__file__, lineno=1, msg=f"calling with {SECRET} now",
        args=None, exc_info=None,
    )

    redactor.filter(record)

    assert SECRET not in record.getMessage()
    assert REDACTED in record.getMessage()


def test_a_secret_nested_in_a_dict_field_does_not_escape() -> None:
    redactor = RedactingFilter([SECRET])
    record = logging.LogRecord(
        name="t", level=logging.INFO, pathname=__file__, lineno=1, msg="config loaded",
        args=None, exc_info=None,
    )
    record.__dict__["payload"] = {"nested": {"value": SECRET}, "token": "another one"}

    redactor.filter(record)

    dumped = json.dumps(record.__dict__["payload"])
    assert SECRET not in dumped
    assert record.__dict__["payload"]["token"] == REDACTED


def test_the_seal_s_token_counts_survive_and_a_real_token_does_not() -> None:
    """Both halves on one record, because one without the other is how this comes back (item 057).

    The seal counts tokens, `input_tokens` contains the substring `token`, and the redactor works by
    name — so the provenance seal rendered its own numbers as `***` on the one surface an operator
    watches a run on. Measured on the rehearsal of 2026-07-29: the database held 936 and 25066 and
    the log said `'input_tokens': '***'`.

    The exemption must not widen the hole it fixes, so this asserts the neighbours too: a field
    whose name merely *ends* the same way is still blanked, because `SENSITIVE_NAME` staying a
    substring rule is what catches the credential nobody remembered to name.
    """
    redactor = RedactingFilter()
    record = logging.LogRecord(
        name="t", level=logging.INFO, pathname=__file__, lineno=1, msg="attempt finished",
        args=None, exc_info=None,
    )
    record.__dict__["seal"] = {
        "models_served": ["claude-opus-5"],
        "input_tokens": 936,
        "output_tokens": 25066,
        "responses": 31,
    }
    record.__dict__["forge_token"] = "gto_a_real_one"  # noqa: S105 - fixture, not a credential
    record.__dict__["model_token"] = 4242
    record.__dict__["input_tokens"] = "not-a-number"

    redactor.filter(record)

    seal = record.__dict__["seal"]
    assert seal["input_tokens"] == 936
    assert seal["output_tokens"] == 25066
    assert seal["models_served"] == ["claude-opus-5"]
    # A credential-shaped name is still blanked, and so is a numeric one nothing exempted.
    assert record.__dict__["forge_token"] == REDACTED
    assert record.__dict__["model_token"] == REDACTED
    # And an exempted name holding a *string* is not what the exemption is for: the same scrubber
    # walks frame locals out of somebody else's process, where a name is whatever they called it.
    assert record.__dict__["input_tokens"] == REDACTED


def test_secrets_registered_after_startup_are_honoured() -> None:
    redactor = RedactingFilter()
    redactor.add_secret(SECRET)
    record = logging.LogRecord(
        name="t", level=logging.INFO, pathname=__file__, lineno=1, msg=f"late {SECRET}",
        args=None, exc_info=None,
    )

    redactor.filter(record)

    assert SECRET not in record.getMessage()


def test_json_output_is_one_parseable_object_carrying_the_extras() -> None:
    record = logging.LogRecord(
        name="hullwork.test", level=logging.WARNING, pathname=__file__, lineno=1,
        msg="something", args=None, exc_info=None,
    )
    record.__dict__["item_id"] = 42

    parsed = json.loads(JsonFormatter().format(record))

    assert parsed["level"] == "WARNING"
    assert parsed["logger"] == "hullwork.test"
    assert parsed["message"] == "something"
    assert parsed["item_id"] == 42
    assert "ts" in parsed


def test_configure_logging_installs_exactly_one_handler() -> None:
    configure_logging(level="DEBUG", log_format="json", secrets=[SECRET])
    root = logging.getLogger()

    assert len(root.handlers) == 1
    assert root.level == logging.DEBUG

    configure_logging()  # restore defaults for the rest of the suite
