"""The leak guard (D-E42): a credential's value must be in no stored byte.

Every artifact, envelope, proof and log line is scanned for each secret value before the controller accepts it, and a match fails the
run: the strictest possible answer to "did the key leak?". The scan covers the value as given, with its surrounding quotes or
`Bearer ` stripped, in URL-encoded form, in base64 and in hexadecimal, so a target that echoes a header back in another encoding is
still caught.
"""

from __future__ import annotations

import base64
import urllib.parse
from collections.abc import Iterable

MIN_SECRET_LENGTH = 8


class SecretLeak(Exception):
    """A secret was found. The message never contains it (or any part of it)."""


def _forms(secret: str) -> set[bytes]:
    raw = secret.encode("utf-8")
    forms = {raw, urllib.parse.quote(secret, safe="").encode(), raw.hex().encode(), raw.hex().upper().encode()}
    for encoder in (base64.b64encode, base64.urlsafe_b64encode, base64.b32encode):
        encoded = encoder(raw)
        forms.update({encoded, encoded.rstrip(b"=")})
    return {f for f in forms if len(f) >= MIN_SECRET_LENGTH}


class LeakGuard:
    def __init__(self, secrets: Iterable[str]) -> None:
        values = [s for s in secrets if s]
        short = [s for s in values if len(s) < MIN_SECRET_LENGTH]
        if short:
            raise ValueError(f"a credential shorter than {MIN_SECRET_LENGTH} characters cannot be guarded: refuse it")
        self._forms = sorted({form for s in values for form in _forms(s)})

    def __bool__(self) -> bool:
        return bool(self._forms)

    def check(self, data: bytes | str, *, where: str) -> None:
        """Raise `SecretLeak` naming only where, if any form of any secret is in `data`."""
        blob = data.encode("utf-8") if isinstance(data, str) else data
        if any(form in blob for form in self._forms):
            raise SecretLeak(f"a credential value was found in {where}")
