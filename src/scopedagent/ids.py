"""Identifiers: random UUIDv4 in hex form. They carry no identity, time or order."""

from __future__ import annotations

import uuid


def new_id() -> str:
    return uuid.uuid4().hex
