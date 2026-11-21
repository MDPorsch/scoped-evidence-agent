"""Error statuses, coverage and the exit code (D-E09): an incomplete collection is never a clean one."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import IntEnum, StrEnum


class ErrorStatus(StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    DNS_FAILURE = "dns_failure"
    TLS_FAILURE = "tls_failure"
    HTTP_ERROR = "http_error"
    REFUSED_BY_POLICY = "refused_by_policy"
    BUDGET_EXHAUSTED = "budget_exhausted"
    SIZE_LIMIT = "size_limit"
    PARSE_ERROR = "parse_error"
    ADAPTER_ERROR = "adapter_error"


class ExitCode(IntEnum):
    OK = 0
    VALIDATION = 1
    INCOMPLETE = 2
    REVIEW = 3


@dataclass(frozen=True)
class Coverage:
    """What was planned, what succeeded, and every other outcome counted by its status."""

    planned: int
    ok: int
    by_status: Mapping[ErrorStatus, int]

    @property
    def complete(self) -> bool:
        return self.planned > 0 and self.ok == self.planned and not self.by_status


def coverage_from(planned: int, statuses: Iterable[ErrorStatus]) -> Coverage:
    counts = Counter(statuses)
    ok = counts.pop(ErrorStatus.OK, 0)
    return Coverage(planned=planned, ok=ok, by_status=dict(counts))


def exit_code_for(coverage: Coverage, *, drafts_needing_review: int, infrastructure_failure: bool = False) -> ExitCode:
    if drafts_needing_review < 0:
        raise ValueError("drafts_needing_review cannot be negative")
    if infrastructure_failure or not coverage.complete:
        return ExitCode.INCOMPLETE
    return ExitCode.REVIEW if drafts_needing_review > 0 else ExitCode.OK
