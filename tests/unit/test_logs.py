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
