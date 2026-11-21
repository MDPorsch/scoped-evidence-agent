"""Standard section 1 and the required negative tests: structured logging, log injection, no secrets."""

from __future__ import annotations

import io
import json
import logging

import pytest

from scopedagent.logs import JsonFormatter, configure_logging, safe_text

pytestmark = pytest.mark.milestone("M1")


def emit(message: str, **extra: object) -> str:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("scopedagent.test")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    logger.info(message, extra=extra)
    return stream.getvalue()


def test_a_record_is_one_json_line_with_utc_time_level_and_message() -> None:
    line = emit("run started", run_id="r1")
    assert line.count("\n") == 1
    record = json.loads(line)
    assert record["message"] == "run started" and record["level"] == "INFO" and record["run_id"] == "r1"
    assert record["time"].endswith("Z")


def test_newlines_and_control_characters_cannot_forge_a_second_log_line() -> None:
    line = emit('x"}\n{"level": "CRITICAL", "message": "forged"}' + chr(0) + chr(0x202E))
    assert line.count("\n") == 1
    record = json.loads(line)
    assert record["level"] == "INFO" and chr(0) not in record["message"] and chr(0x202E) not in record["message"]


@pytest.mark.parametrize(
    "key",
    ["authorization", "cookie", "set-cookie", "api_key", "x-api-key", "token", "password", "secret", "Authorization"],
)
def test_values_under_sensitive_names_are_never_logged(key: str) -> None:
    line = emit("event", **{key.replace("-", "_"): "SYNTHETIC-SECRET-0001"})
    assert "SYNTHETIC-SECRET-0001" not in line and "[REDACTED]" in line


def test_safe_text_strips_controls_and_bounds_length() -> None:
    assert safe_text("a\nb\tc" + chr(0)) == "a b c "
    assert len(safe_text("x" * 5000)) == 500
    assert safe_text("x" * 5000, limit=10) == "x" * 10
    assert safe_text(None) == "None"


def test_configure_logging_sets_a_single_json_handler_and_is_idempotent() -> None:
    configure_logging("WARNING")
    configure_logging("WARNING")
    logger = logging.getLogger("scopedagent")
    assert (
        len(logger.handlers) == 1
        and isinstance(logger.handlers[0].formatter, JsonFormatter)
        and logger.level == logging.WARNING
    )
    with pytest.raises(ValueError, match="level"):
        configure_logging("LOUD")


def test_numbers_booleans_and_none_are_logged_as_themselves_not_as_text() -> None:
    record = json.loads(emit("event", attempt=3, ratio=0.5, ok=True, nothing=None, text="x"))
    assert record["attempt"] == 3 and record["ratio"] == 0.5 and record["ok"] is True and record["nothing"] is None
    assert record["text"] == "x"


def test_configure_logging_leaves_foreign_handlers_alone() -> None:
    logger = logging.getLogger("scopedagent")
    foreign = logging.NullHandler()
    logger.addHandler(foreign)
    try:
        configure_logging("INFO")
        assert foreign in logger.handlers
        assert sum(isinstance(h.formatter, JsonFormatter) for h in logger.handlers) == 1
    finally:
        logger.removeHandler(foreign)


@pytest.mark.parametrize("name", ["set-cookie", "x-api-key", "x-auth-token", "Proxy-Authorization", "X-Secret-Value"])
def test_hyphenated_header_style_names_are_redacted_too(name: str) -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("scopedagent.hyphen")
    logger.handlers, logger.propagate = [handler], False
    logger.warning("event", extra={name: "SYNTHETIC-SECRET-0001"})
    assert "SYNTHETIC-SECRET-0001" not in stream.getvalue() and "[REDACTED]" in stream.getvalue()


def test_text_extras_are_cleaned_like_messages() -> None:
    record = json.loads(emit("event", detail="a\nb" + chr(0x202E) + chr(0) + "z" * 1000))
    assert "\n" not in record["detail"] and chr(0x202E) not in record["detail"] and chr(0) not in record["detail"]
    assert len(record["detail"]) <= 500


def test_our_logger_does_not_pass_records_to_the_root_logger() -> None:
    configure_logging("INFO")
    assert logging.getLogger("scopedagent").propagate is False


def test_an_unknown_level_is_refused_with_our_message_not_the_standard_librarys() -> None:
    with pytest.raises(ValueError, match="must be one of"):
        configure_logging("LOUD")
