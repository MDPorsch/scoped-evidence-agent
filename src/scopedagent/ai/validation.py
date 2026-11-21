"""Checks on what a model hands back (docs/ai-adapter.md). Every check is code.

An item that fails is dropped; the rule's sentence stands.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence

from scopedagent.ai.protocol import ModelUnavailable, RewordRequest

MAX_REPLY_CHARS = 100_000
MAX_PLACEHOLDERS = 26
_BASE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;'()-")
# words of verdict or escalation a model may not introduce (a word the original already uses may stay)
PROTECTED_WORDS = frozenset(
    {
        "confirmed",
        "verified",
        "proven",
        "proof",
        "exploit",
        "exploited",
        "exploitable",
        "critical",
        "severe",
        "definitely",
        "certainly",
        "guaranteed",
        "urgent",
        "immediately",
        "payload",
        "bypass",
    }
)
_TOKEN = re.compile(
    "|".join(
        [
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",  # a timestamp
            r"TLSv\d(?:\.\d)?",  # a protocol version
            r"HOST_[A-Z]",  # a masked host
            r"CWE-\d+",
            r"[A-Z][A-Za-z]*(?:-[A-Z][A-Za-z]*)+",  # a header name
            r"/[A-Za-z0-9._~/-]*[A-Za-z0-9_~/-]",  # a path (a final full stop belongs to the sentence)
            r"[A-Za-z0-9_-]+\.(?:txt|json)",  # a file name
            r"[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)*",  # a capitalised abbreviation
            r"\d+(?:\.\d+)*",  # a number
            r"[a-z0-9-]+(?:\.[a-z0-9-]+)+",  # a host-like name
        ]
    )
)
_WORD = re.compile(r"[A-Za-z]+")


def _words(text: str) -> set[str]:
    return {w.lower() for w in _WORD.findall(text)}


def protected_tokens(text: str) -> set[str]:
    """What a reworded sentence must keep exactly and may not add: numbers, dates, versions, names, paths, hosts."""
    return set(_TOKEN.findall(text))


def validate_item(original: str, reworded: str, *, limit: int, secrets: Sequence[str] = ()) -> str | None:
    """None when the wording is acceptable, else the reason: empty, secret, characters, length, words or tokens."""
    allowed = _BASE | set(original)
    checks: tuple[tuple[str, Callable[[], bool]], ...] = (
        ("empty", lambda: not reworded.strip()),
        ("secret", lambda: any(secret and secret in reworded for secret in secrets)),
        ("characters", lambda: any(ch not in allowed for ch in reworded)),
        ("length", lambda: len(reworded) > min(limit, 2 * len(original) + 60)),
        ("words", lambda: bool(_words(reworded) - _words(original) & PROTECTED_WORDS)),
        ("tokens", lambda: protected_tokens(original) != protected_tokens(reworded)),
    )
    return next((reason for reason, failed in checks if failed()), None)  # in this order, the first that fails


def parse_reply(raw: str, request: RewordRequest) -> dict[str, str]:
    """The reply as {id: text}, or `ModelUnavailable('invalid')`. Only JSON of exactly the requested shape is read."""
    if len(raw) > MAX_REPLY_CHARS:
        raise ModelUnavailable("invalid", "the reply was too large")
    try:
        data = json.loads(raw)
    except ValueError:
        raise ModelUnavailable("invalid", "the reply was not JSON") from None
    items = data.get("items") if isinstance(data, dict) and set(data) == {"items"} else None
    if not isinstance(items, list):
        raise ModelUnavailable("invalid", "the reply was not the requested shape")
    texts: dict[str, str] = {}
    for item in items:
        if not (isinstance(item, dict) and set(item) == {"id", "text"}):
            raise ModelUnavailable("invalid", "an item was not the requested shape")
        item_id, text = item["id"], item["text"]
        if not (isinstance(item_id, str) and isinstance(text, str)) or item_id in texts:
            raise ModelUnavailable("invalid", "an item had a bad or repeated id")
        texts[item_id] = text
    if set(texts) != {i.id for i in request.items} or len(items) != len(request.items):
        raise ModelUnavailable("invalid", "the ids were not the ids sent")
    return texts


def mask_hosts(texts: Sequence[str], hosts: Sequence[str]) -> tuple[list[str], dict[str, str]]:
    """Replace each host in the texts by a placeholder (longest first, at most 26): (texts, {placeholder: host})."""
    masked = list(texts)
    mapping: dict[str, str] = {}
    for host in sorted(set(hosts), key=lambda h: (-len(h), h)):
        if len(mapping) >= MAX_PLACEHOLDERS:
            break
        pattern = re.compile(rf"(?<![A-Za-z0-9.-]){re.escape(host)}(?![A-Za-z0-9-]|\.[A-Za-z0-9])", re.IGNORECASE)
        if not any(pattern.search(t) for t in masked):
            continue
        placeholder = f"HOST_{chr(65 + len(mapping))}"
        mapping[placeholder] = host
        masked = [pattern.sub(placeholder, t) for t in masked]
    return masked, mapping


def unmask(text: str, mapping: dict[str, str]) -> str:
    """Put each host back where its placeholder stands. A placeholder that was not issued stays as it is."""
    return re.sub(r"HOST_[A-Z]", lambda m: mapping.get(m.group(0), m.group(0)), text)
