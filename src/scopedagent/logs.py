"""Structured logging: one JSON object per line, no way to forge a second line, no secret values."""

from __future__ import annotations

import json
import logging
import sys
import unicodedata
from datetime import UTC, datetime
from typing import Any

_CONTROL = {"Cc", "Cf", "Zl", "Zp"}
_SENSITIVE = ("authorization", "cookie", "api_key", "apikey", "token", "password", "passwd", "secret", "credential")
_STANDARD = set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {"message", "asctime"}
LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def safe_text(value: object, limit: int = 500) -> str:
    """Printable, single-line text of bounded length: control, format and line-separator characters become spaces."""
    text = str(value)[:limit]
    return "".join(" " if unicodedata.category(ch) in _CONTROL else ch for ch in text)


def _is_sensitive(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return any(word in lowered for word in _SENSITIVE)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "time": datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": safe_text(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD or key.startswith("_"):
                continue
            if _is_sensitive(key):
                payload[key] = "[REDACTED]"
            elif isinstance(value, bool | int | float) or value is None:
                payload[key] = value
            else:
                payload[key] = safe_text(value)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


def configure_logging(level: str = "INFO") -> None:
    if level not in LEVELS:
        raise ValueError(f"level must be one of {', '.join(LEVELS)}")
    logger = logging.getLogger("scopedagent")
    for handler in list(logger.handlers):
        if isinstance(handler.formatter, JsonFormatter):
            logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
