"""What must hold before any adapter may run (AE-01, D-E01, D-E02). The scope is a restriction, not proof."""

from __future__ import annotations

import re
from datetime import datetime

from scopedagent.errors import ErrorCode, PolicyError, ScopeError
from scopedagent.policy.scope import LoadedScope, check_not_expired

AUTHORIZATION_NOTICE = (
    "the scope file is a restriction, not proof of authorization. This tool cannot verify that anyone authorized the "
    "test: confirm authorization outside it."
)
_SHA256 = re.compile(r"[0-9a-f]{64}")


def check_run_allowed(loaded: LoadedScope, *, now: datetime, expected_sha256: str | None) -> None:
    """Refuse live mode, a changed scope file, and an expired scope. Each refusal happens before any adapter."""
    if loaded.config.mode != "offline":
        raise PolicyError(ErrorCode.POLICY_001, "live mode is not available in this version (D-E01)")
    if expected_sha256 is None or not _SHA256.fullmatch(expected_sha256) or expected_sha256 != loaded.sha256:
        raise ScopeError(ErrorCode.SCOPE_010, "the scope file does not match the one that was validated")
    check_not_expired(loaded.config.expires_at, now)
