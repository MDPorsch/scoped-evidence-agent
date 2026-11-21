"""AE-10 and D-E09: errors are not clean, an incomplete collection never exits 0, codes are stable."""

from __future__ import annotations

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scopedagent.domain.outcome import Coverage, ErrorStatus, ExitCode, coverage_from, exit_code_for
from scopedagent.errors import (
    AuditError,
    BudgetError,
    ErrorCode,
    PolicyError,
    ScopedAgentError,
    ScopeError,
    StateError,
    StoreError,
)

pytestmark = pytest.mark.milestone("M1")

NON_OK = [s for s in ErrorStatus if s is not ErrorStatus.OK]


def test_error_codes_are_stable_unique_and_well_formed() -> None:
    values = [c.value for c in ErrorCode]
    assert len(values) == len(set(values))
    assert all(re.fullmatch(r"[A-Z]+-\d{3}", v) for v in values)
    assert {f"SCOPE-{n:03d}" for n in range(1, 11)} <= set(values)
    assert {"POLICY-001", "STORE-001", "STORE-002", "STORE-003", "STORE-004", "STORE-005", "STORE-006"} <= set(values)
    assert {"STATE-001", "STATE-002", "STATE-003", "STATE-004", "BUDGET-001", "AUDIT-001"} <= set(values)


@pytest.mark.parametrize(
    ("error_class", "code", "exit_code"),
    [
        (ScopeError, ErrorCode.SCOPE_005, 1),
        (PolicyError, ErrorCode.POLICY_001, 1),
        (StateError, ErrorCode.STATE_001, 1),
        (AuditError, ErrorCode.AUDIT_001, 1),
        (StoreError, ErrorCode.STORE_003, 2),
        (BudgetError, ErrorCode.BUDGET_001, 2),
    ],
)
def test_each_error_class_maps_to_its_exit_code(
    error_class: type[ScopedAgentError], code: ErrorCode, exit_code: int
) -> None:
    error = error_class(code, "message")
    assert error.exit_code == exit_code and error.code is code


def test_an_error_renders_its_code_path_and_message_and_nothing_else() -> None:
    assert str(ScopeError(ErrorCode.SCOPE_005, "a wildcard is not allowed", path="allowed_targets[0].host")) == (
        "SCOPE-005: allowed_targets[0].host: a wildcard is not allowed"
    )
    assert str(StoreError(ErrorCode.STORE_001, "no database")) == "STORE-001: no database"


def test_exit_codes_are_the_documented_numbers() -> None:
    assert (ExitCode.OK, ExitCode.VALIDATION, ExitCode.INCOMPLETE, ExitCode.REVIEW) == (0, 1, 2, 3)


def test_the_error_statuses_are_the_documented_set() -> None:
    assert {s.value for s in ErrorStatus} == {
        "ok",
        "timeout",
        "dns_failure",
        "tls_failure",
        "http_error",
        "refused_by_policy",
        "budget_exhausted",
        "size_limit",
        "parse_error",
        "adapter_error",
    }


def test_a_fully_successful_collection_is_complete() -> None:
    coverage = coverage_from(5, [ErrorStatus.OK] * 5)
    assert coverage == Coverage(planned=5, ok=5, by_status={}) and coverage.complete


@pytest.mark.parametrize("status", NON_OK)
def test_any_error_status_makes_the_collection_incomplete_and_never_exits_zero(status: ErrorStatus) -> None:
    coverage = coverage_from(5, [ErrorStatus.OK] * 4 + [status])
    assert not coverage.complete and coverage.by_status == {status: 1}
    assert exit_code_for(coverage, drafts_needing_review=0) is ExitCode.INCOMPLETE
    assert exit_code_for(coverage, drafts_needing_review=7) is ExitCode.INCOMPLETE  # incomplete beats "review"


def test_operations_that_never_ran_make_the_collection_incomplete() -> None:
    coverage = coverage_from(5, [ErrorStatus.OK] * 3)
    assert not coverage.complete and coverage.ok == 3 and coverage.planned == 5
    assert exit_code_for(coverage, drafts_needing_review=0) is ExitCode.INCOMPLETE


def test_more_results_than_planned_is_not_complete() -> None:
    assert not coverage_from(2, [ErrorStatus.OK] * 3).complete


def test_an_empty_plan_is_not_a_clean_run() -> None:
    assert not coverage_from(0, []).complete
    assert exit_code_for(coverage_from(0, []), drafts_needing_review=0) is ExitCode.INCOMPLETE


def test_complete_with_nothing_to_review_exits_zero_and_with_drafts_exits_three() -> None:
    complete = coverage_from(3, [ErrorStatus.OK] * 3)
    assert exit_code_for(complete, drafts_needing_review=0) is ExitCode.OK
    assert exit_code_for(complete, drafts_needing_review=1) is ExitCode.REVIEW


def test_an_infrastructure_failure_is_never_zero_or_review() -> None:
    complete = coverage_from(3, [ErrorStatus.OK] * 3)
    assert exit_code_for(complete, drafts_needing_review=0, infrastructure_failure=True) is ExitCode.INCOMPLETE
    assert exit_code_for(complete, drafts_needing_review=9, infrastructure_failure=True) is ExitCode.INCOMPLETE


def test_negative_draft_counts_are_refused() -> None:
    with pytest.raises(ValueError, match="drafts"):
        exit_code_for(coverage_from(1, [ErrorStatus.OK]), drafts_needing_review=-1)


@given(
    planned=st.integers(min_value=0, max_value=30),
    statuses=st.lists(st.sampled_from(list(ErrorStatus)), max_size=40),
    drafts=st.integers(min_value=0, max_value=5),
    failure=st.booleans(),
)
def test_exit_zero_requires_a_complete_collection_with_no_failure_and_no_drafts(
    planned: int, statuses: list[ErrorStatus], drafts: int, failure: bool
) -> None:
    coverage = coverage_from(planned, statuses)
    code = exit_code_for(coverage, drafts_needing_review=drafts, infrastructure_failure=failure)
    all_ok = planned > 0 and len(statuses) == planned and all(s is ErrorStatus.OK for s in statuses)
    assert coverage.complete == all_ok
    assert (code is ExitCode.OK) == (all_ok and not failure and drafts == 0)
    assert (code is ExitCode.REVIEW) == (all_ok and not failure and drafts > 0)


@pytest.mark.parametrize(
    "extra", [ErrorStatus.TIMEOUT, ErrorStatus.DNS_FAILURE, ErrorStatus.ADAPTER_ERROR, ErrorStatus.OK]
)
def test_more_results_than_planned_are_never_complete_even_when_the_planned_ones_all_succeeded(
    extra: ErrorStatus,
) -> None:
    # found by mutation: a Hypothesis property only caught this by luck. Five planned, five ok, and one more result.
    coverage = coverage_from(5, [ErrorStatus.OK] * 5 + [extra])
    assert not coverage.complete
    assert exit_code_for(coverage, drafts_needing_review=0) is ExitCode.INCOMPLETE


def test_an_error_alongside_a_full_set_of_successes_makes_the_collection_incomplete() -> None:
    coverage = coverage_from(3, [ErrorStatus.OK, ErrorStatus.OK, ErrorStatus.OK, ErrorStatus.TIMEOUT])
    assert coverage.ok == 3 and coverage.planned == 3 and coverage.by_status == {ErrorStatus.TIMEOUT: 1}
    assert not coverage.complete
