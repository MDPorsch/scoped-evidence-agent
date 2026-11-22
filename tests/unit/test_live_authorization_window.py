"""D-E41: the window of a live run is half-open, [not_before, not_after), and every live run must be acknowledged."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from scopedagent.errors import ErrorCode, LiveRefused
from scopedagent.policy.authorization import check_live_authorization
from scopedagent.policy.scope import LoadedScope, parse_scope
from tests.support import NOW, dump
from tests.unit.test_scope_live import AUTH, live_dict

pytestmark = pytest.mark.milestone("M6")

NOT_BEFORE = datetime.fromisoformat(AUTH["not_before"])
NOT_AFTER = datetime.fromisoformat(AUTH["not_after"])
SECOND = timedelta(seconds=1)


def loaded_live() -> LoadedScope:
    # The scope itself outlives the window, so only the window can refuse a run between the two.
    assert parse_scope(dump(live_dict()), now=NOW).config.expires_at > NOT_AFTER
    return parse_scope(dump(live_dict()), now=NOW)


def refused(now: datetime, *, acknowledged: bool = True) -> LiveRefused:
    with pytest.raises(LiveRefused) as caught:
        check_live_authorization(loaded_live(), now=now, acknowledged=acknowledged)
    assert caught.value.code is ErrorCode.LIVE_002 and caught.value.exit_code == 1
    return caught.value


def test_the_last_second_before_not_after_is_inside_the_window() -> None:
    check_live_authorization(loaded_live(), now=NOT_AFTER - SECOND, acknowledged=True)


def test_not_after_itself_is_already_outside_the_window() -> None:
    assert "expired" in str(refused(NOT_AFTER)) and "not_after" in str(refused(NOT_AFTER))


def test_a_moment_after_not_after_is_refused_even_though_the_scope_has_not_expired() -> None:
    assert "expired" in str(refused(NOT_AFTER + SECOND))
    assert "expired" in str(refused(NOT_AFTER + timedelta(days=10)))


def test_not_before_itself_is_inside_the_window() -> None:
    check_live_authorization(loaded_live(), now=NOT_BEFORE, acknowledged=True)


def test_the_second_before_not_before_is_refused() -> None:
    assert "not started" in str(refused(NOT_BEFORE - SECOND))


def test_an_unacknowledged_run_is_refused_inside_the_window() -> None:
    assert "--ack-authorization" in str(refused(NOT_BEFORE + SECOND, acknowledged=False))
