"""AE-01 and D-E01/D-E02: what must hold before any adapter may run."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from scopedagent.errors import ErrorCode, PolicyError, ScopeError
from scopedagent.policy.authorization import AUTHORIZATION_NOTICE, check_run_allowed
from scopedagent.policy.scope import parse_scope
from tests.support import NOW, dump, scope_dict, scope_text
from tests.unit.test_scope_live import live_dict

pytestmark = pytest.mark.milestone("M1")


def test_a_current_offline_scope_may_run() -> None:
    loaded = parse_scope(scope_text(), now=NOW)
    check_run_allowed(loaded, now=NOW, expected_sha256=loaded.sha256)


def test_run_refuses_a_live_scope_and_live_run_refuses_an_offline_one() -> None:
    loaded = parse_scope(dump(live_dict()), now=NOW)
    with pytest.raises(PolicyError) as caught:
        check_run_allowed(loaded, now=NOW, expected_sha256=loaded.sha256)
    assert caught.value.code is ErrorCode.POLICY_001 and caught.value.exit_code == 1 and "live run" in str(caught.value)
    check_run_allowed(loaded, now=NOW, expected_sha256=loaded.sha256, live=True)  # the live command accepts it
    offline = parse_scope(scope_text(), now=NOW)
    with pytest.raises(PolicyError) as caught:
        check_run_allowed(offline, now=NOW, expected_sha256=offline.sha256, live=True)
    assert caught.value.code is ErrorCode.POLICY_001 and "mode live" in str(caught.value)


def test_a_scope_that_expired_after_validation_is_refused_at_run_time() -> None:
    loaded = parse_scope(scope_text(), now=NOW)
    later = loaded.config.expires_at + timedelta(seconds=1)
    with pytest.raises(ScopeError) as caught:
        check_run_allowed(loaded, now=later, expected_sha256=loaded.sha256)
    assert caught.value.code is ErrorCode.SCOPE_004


def test_the_moment_of_expiry_is_already_expired() -> None:
    loaded = parse_scope(scope_text(), now=NOW)
    with pytest.raises(ScopeError):
        check_run_allowed(loaded, now=loaded.config.expires_at, expected_sha256=loaded.sha256)


def test_a_scope_file_changed_after_validation_is_refused() -> None:
    validated = parse_scope(scope_text(), now=NOW)
    data = scope_dict()
    data["allowed_targets"][0]["allowed_paths"].append("/admin")
    changed = parse_scope(dump(data), now=NOW)
    with pytest.raises(ScopeError) as caught:
        check_run_allowed(changed, now=NOW, expected_sha256=validated.sha256)
    assert caught.value.code is ErrorCode.SCOPE_010


def test_a_missing_expected_hash_is_refused_not_skipped() -> None:
    loaded = parse_scope(scope_text(), now=NOW)
    with pytest.raises(ScopeError) as caught:
        check_run_allowed(loaded, now=NOW, expected_sha256=None)
    assert caught.value.code is ErrorCode.SCOPE_010


@pytest.mark.parametrize("bad", ["", "abc", "g" * 64, "A" * 64, "0" * 63])
def test_a_malformed_expected_hash_never_matches(bad: Any) -> None:
    loaded = parse_scope(scope_text(), now=NOW)
    with pytest.raises(ScopeError):
        check_run_allowed(loaded, now=NOW, expected_sha256=bad)


def test_the_notice_says_the_scope_is_not_authorization() -> None:
    assert "not proof of authorization" in AUTHORIZATION_NOTICE
    assert "cannot verify" in AUTHORIZATION_NOTICE
