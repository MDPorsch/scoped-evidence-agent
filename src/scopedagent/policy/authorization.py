"""What must hold before any adapter may run (AE-01, D-E01, D-E02). The scope is a restriction, not proof."""

from __future__ import annotations

import re
from datetime import datetime

from scopedagent.errors import ErrorCode, LiveRefused, PolicyError, ScopeError
from scopedagent.policy.scope import LoadedScope, check_not_expired

AUTHORIZATION_NOTICE = (
    "the scope file is a restriction, not proof of authorization. This tool cannot verify that anyone authorized the "
    "test: confirm authorization outside it."
)
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _shown(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def check_run_allowed(loaded: LoadedScope, *, now: datetime, expected_sha256: str | None, live: bool = False) -> None:
    """Refuse a mode that is not the command's, a changed scope file and an expired scope, before any adapter.

    `run` is offline only and never opens a socket (D-E37); `live run` is the only way to start a live scope.
    """
    if live and loaded.config.mode != "live":
        raise PolicyError(ErrorCode.POLICY_001, "live run needs a scope with mode live")
    if not live and loaded.config.mode != "offline":
        raise PolicyError(ErrorCode.POLICY_001, "a live scope is run only with `scoped-agent live run` (D-E37)")
    if expected_sha256 is None or not _SHA256.fullmatch(expected_sha256) or expected_sha256 != loaded.sha256:
        raise ScopeError(ErrorCode.SCOPE_010, "the scope file does not match the one that was validated")
    check_not_expired(loaded.config.expires_at, now)


def check_live_authorization(loaded: LoadedScope, *, now: datetime, acknowledged: bool) -> None:
    """The window and the acknowledgement of a live run (D-E41). The approval is checked against the database."""
    authorization = loaded.config.authorization
    if authorization is None:  # pragma: no cover - a live scope cannot be built without one
        raise LiveRefused(ErrorCode.LIVE_002, "mode live needs an authorization block")
    if not acknowledged:
        raise LiveRefused(
            ErrorCode.LIVE_002, "--ack-authorization is required on every live run: it is you saying yes, now"
        )
    if authorization.not_before is not None and now < authorization.not_before:
        raise LiveRefused(
            ErrorCode.LIVE_002,
            f"the authorization window has not started (not_before {_shown(authorization.not_before)})",
        )
    if now >= authorization.not_after:
        raise LiveRefused(
            ErrorCode.LIVE_002, f"the authorization window has expired (not_after {_shown(authorization.not_after)})"
        )


def attestation(loaded: LoadedScope) -> str:
    """What a live report quotes: a declaration by the operator, never a verified fact."""
    authorization = loaded.config.authorization
    if authorization is None:  # pragma: no cover - a live scope cannot be built without one
        raise LiveRefused(ErrorCode.LIVE_002, "mode live needs an authorization block")
    start = _shown(authorization.not_before) if authorization.not_before is not None else "the start of the run"
    return (
        f"Authorization was declared by the operator for engagement {authorization.engagement} "
        f"(valid from {start} to {_shown(authorization.not_after)}), acknowledged with --ack-authorization "
        "and approved by a recorded approval. The tool does not and cannot verify it."
    )
