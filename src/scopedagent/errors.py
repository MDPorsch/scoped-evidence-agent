"""The failure taxonomy: stable codes, and the exit code each kind of failure maps to (D-E09).

A message names a code and, where useful, the field. It never carries the offending value of a text field:
a secret typed into the wrong place must not be echoed into a terminal or a log.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar


class ErrorCode(StrEnum):
    SCOPE_001 = "SCOPE-001"  # unreadable, too large, not UTF-8, not valid YAML
    SCOPE_002 = "SCOPE-002"  # forbidden YAML construct
    SCOPE_003 = "SCOPE-003"  # unknown field or wrong type
    SCOPE_004 = "SCOPE-004"  # expired, not a complete UTC timestamp, or too far ahead
    SCOPE_005 = "SCOPE-005"  # ambiguous or forbidden host
    SCOPE_006 = "SCOPE-006"  # bad port, scheme, path, or an ambiguous scheme and port combination
    SCOPE_007 = "SCOPE-007"  # a limit is out of range
    SCOPE_008 = "SCOPE-008"  # follow_redirects is not false
    SCOPE_009 = "SCOPE-009"  # an allowed operation no target can use
    SCOPE_010 = "SCOPE-010"  # the scope changed after it was validated
    POLICY_001 = "POLICY-001"  # live mode is not available in this version
    POLICY_002 = "POLICY-002"  # a reference is missing or belongs to another run or engagement
    POLICY_003 = "POLICY-003"  # an argument is out of range
    STORE_001 = "STORE-001"  # no database (run `db upgrade`)
    STORE_002 = "STORE-002"  # unknown or missing schema revision
    STORE_003 = "STORE-003"  # permissions looser than documented
    STORE_004 = "STORE-004"  # an artifact path is invalid, escapes its root, or is a link
    STORE_005 = "STORE-005"  # an artifact could not be written, or its bytes do not match its hash
    STORE_006 = "STORE-006"  # an artifact is too large
    STATE_001 = "STATE-001"  # the transition is not allowed, or the object does not exist
    STATE_002 = "STATE-002"  # the object changed since it was read
    STATE_003 = "STATE-003"  # this actor may not do that
    STATE_004 = "STATE-004"  # a review needs a reviewer, a reason and evidence
    BUDGET_001 = "BUDGET-001"  # the request budget is spent
    AUDIT_001 = "AUDIT-001"  # the audit chain is broken


class ScopedAgentError(Exception):
    """Base of every error the tool raises on purpose. `exit_code` is the process exit code for it."""

    exit_code: ClassVar[int] = 2

    def __init__(self, code: ErrorCode, message: str, *, path: str | None = None) -> None:
        self.code = code
        self.message = message
        self.path = path
        super().__init__(str(self))

    def __str__(self) -> str:
        where = f"{self.path}: " if self.path else ""
        return f"{self.code.value}: {where}{self.message}"


class ScopeError(ScopedAgentError):
    exit_code = 1


class PolicyError(ScopedAgentError):
    exit_code = 1


class StateError(ScopedAgentError):
    exit_code = 1


class AuditError(ScopedAgentError):
    exit_code = 1


class StoreError(ScopedAgentError):
    exit_code = 2


class BudgetError(ScopedAgentError):
    exit_code = 2
