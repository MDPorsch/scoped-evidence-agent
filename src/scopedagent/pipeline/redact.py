"""Redaction (D-E12, D-E14): secrets are replaced before anything is stored. Best effort, and said so (LIMITATIONS
SE-05).

A sensitive header's value is replaced whatever it looks like. In text, known secret shapes and the value after
a sensitive key are replaced. An e-mail address is replaced unless it belongs to the target's own host: a role
address such as the contact in `security.txt` is public by design, a personal or third-party address is not.

Every pattern is length-bounded, so no input can make a match take more than linear time per position (a test
feeds it inputs built to do exactly that). The marker is `[REDACTED]`; a stable keyed fingerprint is added only
if a feature needs one (D-E14).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

REDACTED = "[REDACTED]"

_EXACT = frozenset(
    {
        "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token",
        "x-xsrf-token", "x-amz-security-token", "x-access-token",
    }
)  # fmt: skip
_WORDS = ("token", "secret", "password", "passwd", "api-key", "apikey", "credential")
_NOT_SENSITIVE_PREFIXES = ("x-ratelimit", "ratelimit", "retry-after")  # counts of tokens or requests, not credentials
_NOT_SENSITIVE_NAMES = frozenset({"access-control-allow-credentials"})  # a CORS policy flag (true), not a credential

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,2048}\.[A-Za-z0-9_-]{5,2048}\.[A-Za-z0-9_-]{5,2048}")
_VENDOR = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|(?:AKIA|ASIA)[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,255})\b")
_BEARER = re.compile(r"\b(?:[Bb]earer|[Bb]asic)\s{1,8}[A-Za-z0-9._~+/=-]{8,2048}")
_KEY_VALUE = re.compile(
    r"(\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|authorization|auth[_-]?token|client[_-]?secret)\b"
    r"""["']?\s{0,4}[:=]\s{0,4}["']?)(?!\[REDACTED\])[^\s"',;&]{4,512}""",
    re.IGNORECASE,
)  # group 1 is the key and its separator: it is kept, only the value is replaced
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24})")
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----")  # the whole marker, never a BEGIN line's tail
_PEM_UNTERMINATED = 4096


@dataclass(frozen=True)
class RedactionResult:
    text: str
    count: int


def is_sensitive_header(name: str) -> bool:
    lowered = name.lower()
    if lowered in _NOT_SENSITIVE_NAMES or lowered.startswith(_NOT_SENSITIVE_PREFIXES):
        return False
    return lowered in _EXACT or any(word in lowered for word in _WORDS)


def _replace(pattern: re.Pattern[str], text: str) -> tuple[str, int]:
    return pattern.subn(REDACTED, text)


def _redact_pem(text: str) -> tuple[str, int]:
    """Replace each private-key block. Scans forward once, so many BEGIN markers cannot make it quadratic."""
    pieces: list[str] = []
    position = count = 0
    ends_exist = True
    for begin in _PEM_BEGIN.finditer(text):
        if begin.start() < position:
            continue
        end = _PEM_END.search(text, begin.end()) if ends_exist else None
        if end is None:
            ends_exist = False
            stop = min(
                len(text), begin.end() + _PEM_UNTERMINATED
            )  # an unterminated block: remove what follows it, bounded
        else:
            stop = end.end()
        pieces.extend((text[position : begin.start()], REDACTED))
        position, count = stop, count + 1
    pieces.append(text[position:])
    return "".join(pieces), count


def redact_text(text: str, *, own_host: str | None = None) -> RedactionResult:
    """Replace secrets in `text`. E-mail addresses at `own_host` (the target's host) or a subdomain are kept."""
    total = 0
    text, n = _redact_pem(text)
    total += n
    for pattern in (_JWT, _VENDOR, _BEARER):
        text, n = _replace(pattern, text)
        total += n
    text, n = _KEY_VALUE.subn(lambda m: m.group(1) + REDACTED, text)
    total += n
    kept = 0

    def email(match: re.Match[str]) -> str:
        nonlocal kept
        domain = match.group(1).lower()
        if own_host and (domain == own_host or domain.endswith("." + own_host)):
            return match.group(0)
        kept += 1
        return REDACTED

    text = _EMAIL.sub(email, text)
    return RedactionResult(text, total + kept)


def redact_headers_counted(
    headers: Mapping[str, Sequence[str]], *, own_host: str | None = None
) -> tuple[dict[str, list[str]], int]:
    """Lower-case the names, replace every value of a sensitive header, and scrub secret shapes from the rest."""
    out: dict[str, list[str]] = {}
    count = 0
    for name, values in headers.items():
        key = name.lower()
        bucket = out.setdefault(key, [])
        if is_sensitive_header(key):
            bucket.extend(REDACTED for _ in values)
            count += len(values)
        else:
            for value in values:
                result = redact_text(value, own_host=own_host)
                bucket.append(result.text)
                count += result.count
    return out, count


def redact_headers(headers: Mapping[str, Sequence[str]], *, own_host: str | None = None) -> dict[str, list[str]]:
    return redact_headers_counted(headers, own_host=own_host)[0]
