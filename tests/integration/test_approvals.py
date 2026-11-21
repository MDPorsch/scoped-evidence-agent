"""M6, D-E41: an approval is a human's recorded pause, bound to one scope hash, ending at a time, revocable and never editable."""

from __future__ import annotations

import sqlite3
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from typer.testing import CliRunner

from scopedagent.cli import AppContext, app
from scopedagent.domain.models import Approval
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, LiveRefused, StateError
from scopedagent.policy.scope import parse_scope
from scopedagent.storage.approvals import grant_approval, list_approvals, require_approval, revoke_approval, status_of
from scopedagent.storage.audit import verify_chain
from tests.support import NOW, dump, scope_dict
from tests.unit.test_scope_live import live_dict

pytestmark = pytest.mark.milestone("M6")

HUMAN = Actor(ActorType.HUMAN, "alice")
UNTIL = NOW + timedelta(days=7)  # inside the window of the fixture authorization (until 2026-12-04T23:59:59Z)


def loaded(**edits: Any) -> Any:
    data = live_dict()
    data.update(edits)
    return parse_scope(dump(data), now=NOW)


def grant(env: Any, scope: Any | None = None, until: Any = UNTIL, actor: Actor = HUMAN) -> Any:
    with env[0].begin() as session:
        return grant_approval(session, scope or loaded(), until=until, actor=actor, now=NOW).id


# ------------------------------------------------------------------------------------------- granting ----
def test_a_human_grants_an_approval_bound_to_the_scope_hash_and_the_engagement(env: Any) -> None:
    approval_id = grant(env)
    with env[0].begin() as session:
        row = session.execute(text("SELECT scope_sha256, engagement, granted_by, expires_at FROM approvals")).one()
    assert (
        row[0] == loaded().sha256
        and row[1] == "ACME-2026-114"
        and row[2] == "alice"
        and row[3].startswith("2026-11-27")
    )
    assert len(approval_id) == 32


def test_granting_is_audited_on_the_run_less_chain(env: Any) -> None:
    approval_id = grant(env)
    with env[0].begin() as session:
        rows = session.execute(text("SELECT action, decision, reason, run_id FROM audit_events")).all()
        assert verify_chain(session, None) == 1
    assert rows == [
        ("approval.grant", "allowed", f"{approval_id} scope {loaded().sha256[:12]} until 2026-11-27T12:00:00Z", None)
    ]


@pytest.mark.parametrize("actor", [Actor(ActorType.WORKER, "collector"), Actor(ActorType.MODEL, "claude")])
def test_only_a_human_may_grant_and_the_refusal_is_kept(env: Any, actor: Actor) -> None:
    with pytest.raises(StateError) as caught, env[0].begin() as session:
        grant_approval(session, loaded(), until=UNTIL, actor=actor, now=NOW)
    assert caught.value.code is ErrorCode.STATE_003
    with env[0].begin() as session:
        assert session.execute(text("SELECT count(*) FROM approvals")).scalar_one() == 0
        denied = session.execute(text("SELECT action, decision FROM audit_events")).all()
    assert denied == [("approval.grant", "denied")]


def test_an_offline_scope_cannot_be_approved(env: Any) -> None:
    with pytest.raises(LiveRefused, match="mode live"), env[0].begin() as session:
        grant_approval(session, parse_scope(dump(scope_dict()), now=NOW), until=UNTIL, actor=HUMAN, now=NOW)


@pytest.mark.parametrize(
    "until",
    [NOW, NOW - timedelta(days=1), NOW + timedelta(days=30), NOW + timedelta(seconds=1) + timedelta(days=366)],
)
def test_an_approval_must_end_in_the_future_and_no_later_than_the_authorization_and_the_scope(
    env: Any, until: Any
) -> None:
    with pytest.raises(LiveRefused, match="must end in the future"), env[0].begin() as session:
        grant_approval(session, loaded(), until=until, actor=HUMAN, now=NOW)


def test_an_approval_may_end_exactly_at_the_authorization_not_after(env: Any) -> None:
    scope = loaded()
    assert grant(env, scope, until=scope.config.authorization.not_after)


def test_the_scope_expiry_also_limits_an_approval(env: Any) -> None:
    data = live_dict()
    data["expires_at"] = "2026-11-25T00:00:00Z"
    scope = parse_scope(dump(data), now=NOW)
    with pytest.raises(LiveRefused), env[0].begin() as session:
        grant_approval(session, scope, until=NOW + timedelta(days=6), actor=HUMAN, now=NOW)
    assert grant(env, scope, until=NOW + timedelta(days=4))


# ------------------------------------------------------------------------------------------- requiring ----
def test_a_valid_approval_for_this_exact_scope_is_accepted(env: Any) -> None:
    approval_id = grant(env)
    with env[0].begin() as session:
        assert require_approval(session, approval_id, loaded(), now=NOW + timedelta(days=1)).id == approval_id


def test_a_missing_approval_is_refused_with_the_way_to_make_one(env: Any) -> None:
    with pytest.raises(LiveRefused, match="approvals grant"), env[0].begin() as session:
        require_approval(session, "0" * 32, loaded(), now=NOW)


def test_editing_the_scope_invalidates_the_approval(env: Any) -> None:
    approval_id = grant(env)
    edited = live_dict()
    edited["max_requests"] = 11
    with pytest.raises(LiveRefused, match="scope changed"), env[0].begin() as session:
        require_approval(session, approval_id, parse_scope(dump(edited), now=NOW), now=NOW)


def test_an_expired_approval_is_refused(env: Any) -> None:
    approval_id = grant(env)
    with env[0].begin() as session:
        require_approval(session, approval_id, loaded(), now=UNTIL - timedelta(seconds=1))
        with pytest.raises(LiveRefused, match="expired"):
            require_approval(session, approval_id, loaded(), now=UNTIL)


def test_a_revoked_approval_is_refused_and_kept(env: Any) -> None:
    approval_id = grant(env)
    with env[0].begin() as session:
        revoke_approval(
            session, approval_id, actor=HUMAN, reason="the client asked us to stop", now=NOW + timedelta(hours=1)
        )
    with env[0].begin() as session:
        with pytest.raises(LiveRefused, match="revoked"):
            require_approval(session, approval_id, loaded(), now=NOW + timedelta(hours=2))
        assert session.execute(text("SELECT revoked_by, reason FROM approval_revocations")).one() == (
            "alice",
            "the client asked us to stop",
        )
        assert session.execute(text("SELECT count(*) FROM approvals")).scalar_one() == 1


# ------------------------------------------------------------------------------------------ revoking ----
def test_a_revocation_needs_a_human_a_reason_and_an_approval_that_is_there_and_not_already_revoked(env: Any) -> None:
    approval_id = grant(env)
    for actor in (Actor(ActorType.WORKER, "w"), Actor(ActorType.MODEL, "m")):
        with pytest.raises(StateError), env[0].begin() as session:
            revoke_approval(session, approval_id, actor=actor, reason="x", now=NOW)
    for reason in ("", "   ", "\n\t"):
        with pytest.raises(LiveRefused, match="needs a reason"), env[0].begin() as session:
            revoke_approval(session, approval_id, actor=HUMAN, reason=reason, now=NOW)
    with pytest.raises(LiveRefused, match="no such approval"), env[0].begin() as session:
        revoke_approval(session, "f" * 32, actor=HUMAN, reason="x", now=NOW)
    with env[0].begin() as session:
        revoke_approval(session, approval_id, actor=HUMAN, reason="done", now=NOW)
    with pytest.raises(LiveRefused, match="already revoked"), env[0].begin() as session:
        revoke_approval(session, approval_id, actor=HUMAN, reason="again", now=NOW)


def test_a_secret_in_a_reason_is_not_what_is_stored_beyond_the_safe_text_rule(env: Any) -> None:
    approval_id = grant(env)
    with env[0].begin() as session:
        revoke_approval(session, approval_id, actor=HUMAN, reason="line\nbreak\x07", now=NOW)
        stored = session.execute(text("SELECT reason FROM approval_revocations")).scalar_one()
    assert "\n" not in stored and "\x07" not in stored


def test_the_list_says_valid_expired_or_revoked(env: Any) -> None:
    valid, other, third = grant(env), grant(env, until=NOW + timedelta(days=1)), grant(env)
    with env[0].begin() as session:
        revoke_approval(session, third, actor=HUMAN, reason="no", now=NOW)
    with env[0].begin() as session:
        states = {a.id: s for a, s in list_approvals(session, now=NOW + timedelta(days=2))}
        assert status_of(session, session.get(Approval, valid), now=NOW) == "valid"
    assert states == {valid: "valid", other: "expired", third: "revoked"}


# ------------------------------------------------------------------------------- append-only below the code ----
def test_an_approval_and_its_revocation_can_never_be_edited_or_deleted(env: Any) -> None:
    approval_id = grant(env)
    with env[0].begin() as session:
        revoke_approval(session, approval_id, actor=HUMAN, reason="done", now=NOW)
    for sql in (
        "UPDATE approvals SET expires_at = '2099-01-01T00:00:00.000000Z'",
        "DELETE FROM approvals",
        "UPDATE approval_revocations SET reason = 'changed'",
        "DELETE FROM approval_revocations",
    ):
        with pytest.raises(DBAPIError, match="append-only"), env[0].begin() as session:
            session.execute(text(sql))


def test_the_database_refuses_a_bad_approval(env: Any) -> None:
    columns = "(id, scope_sha256, engagement, granted_by, granted_at, expires_at)"
    good = ("a" * 32, "b" * 64, "e", "alice", "2026-11-20T12:00:00.000000Z", "2026-11-21T12:00:00.000000Z")
    for bad in (
        (*good[:1], "short", *good[2:]),
        (*good[:3], "", *good[4:]),
        (*good[:3], "x" * 129, *good[4:]),
        (*good[:4], "2026-11-21T12:00:00.000000Z", "2026-11-20T12:00:00.000000Z"),
    ):
        with pytest.raises(DBAPIError), env[0].begin() as session:
            session.execute(
                text(f"INSERT INTO approvals {columns} VALUES (:a, :b, :c, :d, :e, :f)"),
                dict(zip("abcdef", bad, strict=True)),
            )
    with env[0].begin() as session:
        session.execute(
            text(f"INSERT INTO approvals {columns} VALUES (:a, :b, :c, :d, :e, :f)"),
            dict(zip("abcdef", good, strict=True)),
        )
        with pytest.raises(DBAPIError):
            session.execute(
                text("INSERT INTO approval_revocations VALUES ('no-such', 'alice', '2026-11-21T00:00:00.000000Z', 'x')")
            )


def test_a_database_made_before_approvals_upgrades_and_keeps_its_data(tmp_path: Any) -> None:
    from alembic import command  # noqa: PLC0415

    from scopedagent.storage.database import DataDir, _alembic_config, upgrade_database  # noqa: PLC0415

    data_dir = DataDir(tmp_path / "old")
    data_dir.root.mkdir(mode=0o700)
    data_dir.db_path.touch(mode=0o600)
    command.upgrade(_alembic_config(data_dir.db_path), "0004")
    connection = sqlite3.connect(data_dir.db_path)
    try:
        connection.execute(
            "INSERT INTO engagements VALUES ('e1','lab','ref-123',?, '{}', '2026-12-31T00:00:00.000000Z', '2026-11-20T00:00:00.000000Z', 'active')",
            ("a" * 64,),
        )
        connection.commit()
    finally:
        connection.close()
    assert upgrade_database(data_dir) == "0005"
    connection = sqlite3.connect(data_dir.db_path)
    try:
        assert connection.execute("SELECT label FROM engagements").fetchall() == [("lab",)]
        names = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    finally:
        connection.close()
    assert {"approvals", "approval_revocations", "live_runs"} <= names


# ------------------------------------------------------------------------------------------------- CLI ----
CTX = AppContext(clock=lambda: NOW, user=lambda: "alice")
runner = CliRunner()


def invoke(*args: str, input: str | None = None) -> Any:
    return runner.invoke(app, list(args), obj=CTX, input=input)


@pytest.fixture
def live_scope(tmp_path: Any) -> Any:
    path = tmp_path / "live.yaml"
    path.write_text(dump(live_dict()), encoding="utf-8")
    return path


def test_the_grant_command_asks_for_the_start_of_the_hash_and_records_the_approval(
    tmp_path: Any, live_scope: Any
) -> None:
    data = str(tmp_path / "data")
    assert invoke("db", "upgrade", "--data-dir", data).exit_code == 0
    sha = parse_scope(live_scope.read_text(), now=NOW).sha256
    out = invoke(
        "approvals",
        "grant",
        "--scope",
        str(live_scope),
        "--until",
        "2026-11-27T12:00:00Z",
        "--data-dir",
        data,
        input=sha[:8] + "\n",
    )
    assert out.exit_code == 0, out.output
    assert (
        sha in out.output
        and "Authorization was declared by the operator" in out.output
        and "recorded until 2026-11-27T12:00:00Z" in out.output
    )
    listed = invoke("approvals", "list", "--data-dir", data).output
    assert sha[:8] in listed and "valid" in listed and "alice / ACME-2026-114" in listed


@pytest.mark.parametrize("typed", ["", "nope", "ABCDEFGH", "x"])
def test_any_other_answer_records_nothing(tmp_path: Any, live_scope: Any, typed: str) -> None:
    data = str(tmp_path / "data")
    invoke("db", "upgrade", "--data-dir", data)
    out = invoke(
        "approvals",
        "grant",
        "--scope",
        str(live_scope),
        "--until",
        "2026-11-27T12:00:00Z",
        "--data-dir",
        data,
        input=typed + "\n",
    )
    assert out.exit_code == 1 and "nothing was recorded" in out.output
    assert invoke("approvals", "list", "--data-dir", data).output.strip() == "no approvals"


@pytest.mark.parametrize(
    "until", ["tomorrow", "2026-11-27", "2026-11-27 12:00:00", "2026-11-20T12:00:00Z", "2020-01-01T00:00:00Z"]
)
def test_a_bad_until_is_refused_before_anything_is_asked(tmp_path: Any, live_scope: Any, until: str) -> None:
    data = str(tmp_path / "data")
    invoke("db", "upgrade", "--data-dir", data)
    out = invoke("approvals", "grant", "--scope", str(live_scope), "--until", until, "--data-dir", data)
    assert out.exit_code == 1 and "POLICY-003" in out.output and "Type the first" not in out.output


def test_revoking_by_command_and_listing_it(tmp_path: Any, live_scope: Any) -> None:
    data = str(tmp_path / "data")
    invoke("db", "upgrade", "--data-dir", data)
    sha = parse_scope(live_scope.read_text(), now=NOW).sha256
    out = invoke(
        "approvals",
        "grant",
        "--scope",
        str(live_scope),
        "--until",
        "2026-11-27T12:00:00Z",
        "--data-dir",
        data,
        input=sha[:8] + "\n",
    )
    approval_id = next(w for w in out.output.split() if len(w) == 32)
    assert invoke("approvals", "revoke", approval_id, "--reason", "stopped", "--data-dir", data).exit_code == 0
    assert "revoked" in invoke("approvals", "list", "--data-dir", data).output
    again = invoke("approvals", "revoke", approval_id, "--reason", "stopped", "--data-dir", data)
    assert again.exit_code == 1 and "LIVE-002" in again.output


def test_the_list_command_without_a_database_says_so_and_exits_two(tmp_path: Any) -> None:
    out = invoke("approvals", "list", "--data-dir", str(tmp_path / "nothing"))
    assert out.exit_code == 2 and "STORE-001" in out.output and "Traceback" not in out.output
