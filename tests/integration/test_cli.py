"""docs/cli.md: the M1 commands, their output and their exit codes. The clock and user are injected, never read from the environment."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from scopedagent.cli import AppContext, app
from scopedagent.domain.state_machine import Actor, ActorType, RunState
from scopedagent.policy.scope import parse_scope
from scopedagent.storage.repositories import create_run, register_engagement, transition_run
from tests.support import NOW, SCOPE_FILES, dump, healthy_loaded, raw_connection, scope_dict, scope_text

pytestmark = pytest.mark.milestone("M1")

runner = CliRunner()
CTX = AppContext(clock=lambda: NOW, user=lambda: "alice")


def invoke(*args: str, ctx: AppContext = CTX) -> Any:
    return runner.invoke(app, list(args), obj=ctx)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    return tmp_path / "data"


def init(data_dir: Path) -> None:
    result = invoke("db", "upgrade", "--data-dir", str(data_dir))
    assert result.exit_code == 0, result.output


# ------------------------------------------------------------------------------------ db upgrade ----
def test_db_upgrade_creates_the_store_and_reports_the_revision(data_dir: Path) -> None:
    result = invoke("db", "upgrade", "--data-dir", str(data_dir))
    assert result.exit_code == 0 and "revision 0004" in result.output and str(data_dir) in result.output
    assert (data_dir / "evidence.sqlite").exists()


def test_db_upgrade_twice_is_fine(data_dir: Path) -> None:
    init(data_dir)
    assert invoke("db", "upgrade", "--data-dir", str(data_dir)).exit_code == 0


def test_a_loose_data_directory_is_an_infrastructure_failure_with_its_code(data_dir: Path) -> None:
    data_dir.mkdir(mode=0o755)
    data_dir.chmod(0o755)
    result = invoke("db", "upgrade", "--data-dir", str(data_dir))
    assert result.exit_code == 2 and "STORE-003" in result.output


# ----------------------------------------------------------------------------------- scope validate ----
@pytest.mark.parametrize("name", ["healthy", "misconfigured", "poisoned"])
def test_validating_each_committed_scope_succeeds(name: str) -> None:
    result = invoke("scope", "validate", str(SCOPE_FILES[name]))
    assert result.exit_code == 0, result.output
    assert "mode: offline" in result.output and "scope sha256:" in result.output


def test_validate_prints_the_engagement_hash_plan_and_the_authorization_notice() -> None:
    result = invoke("scope", "validate", str(SCOPE_FILES["healthy"]))
    loaded = healthy_loaded()
    assert "engagement: lab-healthy-001" in result.output
    assert "expires: 2026-12-31T23:59:00Z" in result.output
    assert f"scope sha256: {loaded.sha256}" in result.output
    assert "planned operations: 5 (dns 1, tls 1, http 3)" in result.output and "max_requests: 12" in result.output
    assert "not proof of authorization" in result.output


def test_validate_warns_when_the_plan_exceeds_the_budget_but_still_succeeds(tmp_path: Path) -> None:
    data = scope_dict()
    data["max_requests"] = 3
    path = tmp_path / "s.yaml"
    path.write_text(dump(data), encoding="utf-8")
    result = invoke("scope", "validate", str(path))
    assert (
        result.exit_code == 0
        and "warning" in result.output
        and "incomplete" in result.output
        and "exit 2" in result.output
    )


def test_validate_does_not_create_or_touch_any_data_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert invoke("scope", "validate", str(SCOPE_FILES["healthy"])).exit_code == 0
    assert not (tmp_path / "home").exists()


@pytest.mark.parametrize(
    ("mutate", "code", "path_text"),
    [
        (lambda d: d["allowed_targets"][0].update(host="*.example.invalid"), "SCOPE-005", "allowed_targets[0].host"),
        (lambda d: d.update(expires_at="2020-01-01T00:00:00Z"), "SCOPE-004", "expires_at"),
        (lambda d: d.update(follow_redirects=True), "SCOPE-008", "follow_redirects"),
        (lambda d: d.update(max_requests=0), "SCOPE-007", "max_requests"),
        (lambda d: d["allowed_targets"][0].update(allowed_paths=["/a/../b"]), "SCOPE-006", "allowed_paths"),
    ],
)
def test_a_refused_scope_exits_1_with_its_code_and_the_field(
    tmp_path: Path, mutate: Any, code: str, path_text: str
) -> None:
    data = scope_dict()
    mutate(data)
    path = tmp_path / "s.yaml"
    path.write_text(dump(data), encoding="utf-8")
    result = invoke("scope", "validate", str(path))
    assert result.exit_code == 1 and f"error {code}" in result.output and path_text in result.output


def test_a_missing_scope_file_exits_1() -> None:
    result = invoke("scope", "validate", "/nonexistent/scope.yaml")
    assert result.exit_code == 1 and "SCOPE-001" in result.output


def test_validate_uses_the_injected_clock_not_the_system_clock() -> None:
    later = AppContext(clock=lambda: parse_scope(scope_text(), now=NOW).config.expires_at, user=lambda: "alice")
    result = invoke("scope", "validate", str(SCOPE_FILES["healthy"]), ctx=later)
    assert result.exit_code == 1 and "SCOPE-004" in result.output


# -------------------------------------------------------------------------------------- runs list ----
def test_runs_list_without_a_database_is_an_infrastructure_error_that_says_how_to_fix_it(data_dir: Path) -> None:
    result = invoke("runs", "list", "--data-dir", str(data_dir))
    assert result.exit_code == 2 and "STORE-001" in result.output and "db upgrade" in result.output
    assert not data_dir.exists()  # listing never creates anything


def make_runs(data_dir: Path, count: int) -> list[str]:
    from datetime import timedelta  # noqa: PLC0415

    from scopedagent.storage.database import DataDir, open_database  # noqa: PLC0415

    database = open_database(DataDir(data_dir))
    ids = []
    for minute in range(count):
        with database.begin() as session:
            engagement = register_engagement(session, healthy_loaded(), now=NOW)
            run = create_run(
                session, engagement, actor=Actor(ActorType.HUMAN, "alice"), now=NOW + timedelta(minutes=minute)
            )
            ids.append(run.id)
    database.close()
    return ids


def test_runs_list_shows_id_state_attempt_time_and_engagement(data_dir: Path) -> None:
    init(data_dir)
    (run_id,) = make_runs(data_dir, 1)
    result = invoke("runs", "list", "--data-dir", str(data_dir))
    assert result.exit_code == 0
    line = next(line for line in result.output.splitlines() if run_id in line)
    assert "CREATED" in line and "attempt 1" in line and "lab-healthy-001" in line and "2026-11-20T12:00:00Z" in line


def test_runs_list_is_newest_first_and_paginates(data_dir: Path) -> None:
    init(data_dir)
    ids = make_runs(data_dir, 4)
    out = invoke("runs", "list", "--data-dir", str(data_dir), "--limit", "2", "--offset", "1").output
    assert ids[2] in out and ids[1] in out and ids[3] not in out and ids[0] not in out
    assert out.index(ids[2]) < out.index(ids[1])


def test_runs_list_with_no_runs_says_so(data_dir: Path) -> None:
    init(data_dir)
    result = invoke("runs", "list", "--data-dir", str(data_dir))
    assert result.exit_code == 0 and "no runs" in result.output.lower()


@pytest.mark.parametrize(("limit", "offset"), [("0", "0"), ("101", "0"), ("-1", "0"), ("5", "-1")])
def test_runs_list_bounds_are_enforced_with_exit_1(data_dir: Path, limit: str, offset: str) -> None:
    init(data_dir)
    result = invoke("runs", "list", "--data-dir", str(data_dir), "--limit", limit, "--offset", offset)
    assert result.exit_code == 1 and "POLICY-003" in result.output


def test_the_largest_page_is_allowed(data_dir: Path) -> None:
    init(data_dir)
    assert invoke("runs", "list", "--data-dir", str(data_dir), "--limit", "100").exit_code == 0


# ------------------------------------------------------------------------------------ audit verify ----
def test_audit_verify_reports_an_intact_chain(data_dir: Path) -> None:
    init(data_dir)
    (run_id,) = make_runs(data_dir, 1)
    result = invoke("audit", "verify", run_id, "--data-dir", str(data_dir))
    assert result.exit_code == 0 and "audit chain ok" in result.output and "1 event" in result.output


def test_audit_verify_exits_1_on_a_broken_chain_and_names_the_event(data_dir: Path) -> None:

    from scopedagent.storage.database import DataDir, open_database  # noqa: PLC0415

    init(data_dir)
    (run_id,) = make_runs(data_dir, 1)
    database = open_database(DataDir(data_dir))
    with database.begin() as session:
        for step in (RunState.SCOPE_VALIDATED, RunState.QUEUED):
            transition_run(session, run_id, step, actor=Actor(ActorType.WORKER, "w"), now=NOW)
    database.close()
    with raw_connection(data_dir / "evidence.sqlite") as raw:
        raw.execute("DROP TRIGGER audit_events_no_update")
        raw.execute("UPDATE audit_events SET reason = 'edited' WHERE id = 2")
    result = invoke("audit", "verify", run_id, "--data-dir", str(data_dir))
    assert result.exit_code == 1 and "AUDIT-001" in result.output and "2" in result.output


def test_audit_verify_of_an_unknown_run_exits_1(data_dir: Path) -> None:
    init(data_dir)
    result = invoke("audit", "verify", "no-such-run", "--data-dir", str(data_dir))
    assert result.exit_code == 1 and "POLICY-002" in result.output


# -------------------------------------------------------------------------------------------- misc ----
def test_the_help_lists_the_documented_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for word in ("db", "scope", "runs", "audit"):
        assert word in result.output


def test_the_default_context_uses_the_real_clock_and_the_os_user() -> None:
    from datetime import UTC, datetime  # noqa: PLC0415

    default = AppContext()
    assert abs((default.clock() - datetime.now(UTC)).total_seconds()) < 5 and default.clock().tzinfo is not None
    assert isinstance(default.user(), str) and default.user()


def test_the_default_data_directory_follows_xdg_data_home_at_run_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    result = invoke("db", "upgrade")
    assert result.exit_code == 0 and (tmp_path / "xdg" / "scopedagent" / "evidence.sqlite").exists()
    assert str(tmp_path / "xdg" / "scopedagent") in result.output


def test_without_xdg_the_default_is_under_the_home_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scopedagent.cli import default_data_dir  # noqa: PLC0415

    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert default_data_dir() == tmp_path / ".local" / "share" / "scopedagent"


def test_no_warning_when_the_plan_exactly_fits_the_budget(tmp_path: Path) -> None:
    data = scope_dict()
    data["max_requests"] = 5  # the healthy plan is exactly 5 operations
    path = tmp_path / "s.yaml"
    path.write_text(dump(data), encoding="utf-8")
    result = invoke("scope", "validate", str(path))
    assert result.exit_code == 0 and "warning" not in result.output
    data["max_requests"] = 4
    path.write_text(dump(data), encoding="utf-8")
    assert "warning" in invoke("scope", "validate", str(path)).output


def test_timestamps_are_printed_in_utc_whatever_zone_they_carry() -> None:
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415

    from scopedagent.cli import _stamp  # noqa: PLC0415

    moment = datetime(2026, 11, 20, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    assert _stamp(moment) == "2026-11-20T12:00:00Z"


def test_db_upgrade_says_the_database_is_ready(data_dir: Path) -> None:
    assert "database ready" in invoke("db", "upgrade", "--data-dir", str(data_dir)).output


# ------------------------------------------------------------------------------- AI-system scopes ----
def test_validating_the_ai_scope_shows_the_ai_targets_and_their_worst_case_consumption() -> None:
    from tests.support import AI_PACK  # noqa: PLC0415

    result = invoke("scope", "validate", str(SCOPE_FILES[AI_PACK]))
    assert result.exit_code == 0, result.output
    assert "planned operations: 5 (dns 0, tls 0, http 0, ai metadata 1, ai probes 4)" in result.output
    assert "ai targets: 1   probe requests: 4   worst-case tokens: 3200" in result.output
    assert "support-bot (chat_endpoint, test)" in result.output
    assert "not proof of authorization" in result.output


def test_a_web_only_scope_prints_no_ai_lines() -> None:
    result = invoke("scope", "validate", str(SCOPE_FILES["healthy"]))
    assert (
        "ai " not in result.output.replace("ai-", "")
        and "planned operations: 5 (dns 1, tls 1, http 3)" in result.output
    )


def test_an_ai_scope_that_allows_a_rule_is_refused_with_its_code_and_field(tmp_path: Path) -> None:
    from tests.support import ai_scope_dict  # noqa: PLC0415

    data = ai_scope_dict()
    data["ai_targets"][0]["rules"]["tool_invocation"] = "allowed"
    path = tmp_path / "ai.yaml"
    path.write_text(dump(data), encoding="utf-8")
    result = invoke("scope", "validate", str(path))
    assert (
        result.exit_code == 1
        and "error SCOPE-011" in result.output
        and "ai_targets[0].rules.tool_invocation" in result.output
    )


# ------------------------------------------------------------------------- --version and scope init ----
def test_version_prints_the_tool_name_and_version() -> None:
    from scopedagent import __version__  # noqa: PLC0415

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0 and result.output.strip() == f"scoped-agent {__version__}"


def test_the_version_flag_works_without_a_subcommand_and_before_one() -> None:
    assert (
        runner.invoke(app, ["--version", "db"]).exit_code == 0
    )  # eager: it answers before the subcommand is looked at


def test_init_writes_a_starter_scope_that_validates_and_expires_in_thirty_days(tmp_path: Path) -> None:
    from datetime import timedelta  # noqa: PLC0415

    from scopedagent.policy.scope import load_scope  # noqa: PLC0415

    path = tmp_path / "scope.yaml"
    result = invoke("scope", "init", str(path))
    assert result.exit_code == 0, result.output
    loaded = load_scope(path, now=NOW)
    assert loaded.config.expires_at == NOW + timedelta(days=30) and loaded.config.mode == "offline"
    assert loaded.config.follow_redirects is False and loaded.config.allowed_targets[0].host.endswith(".invalid")
    assert invoke("scope", "validate", str(path)).exit_code == 0


def test_the_starter_tells_the_user_what_to_edit_and_what_it_does_not_prove(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    result = invoke("scope", "init", str(path))
    text = path.read_text(encoding="utf-8")
    assert (
        "not proof of authorization" in result.output
        and "scope validate" in result.output
        and str(path) in result.output
    )
    assert "EDIT BEFORE USE" in text and "restriction" in text and "replace-with-your-reference" in text


def test_the_starter_uses_the_injected_clock(tmp_path: Path) -> None:
    from datetime import timedelta  # noqa: PLC0415

    later = AppContext(clock=lambda: NOW + timedelta(days=100), user=lambda: "alice")
    path = tmp_path / "scope.yaml"
    assert invoke("scope", "init", str(path), ctx=later).exit_code == 0
    assert "2027-03-" in path.read_text(encoding="utf-8")  # NOW + 100 days + 30 days = 2027-03-30


def test_init_never_overwrites_without_force(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text("keep: me\n", encoding="utf-8")
    result = invoke("scope", "init", str(path))
    assert result.exit_code == 1 and "POLICY-003" in result.output and "--force" in result.output
    assert path.read_text(encoding="utf-8") == "keep: me\n"
    assert invoke("scope", "init", str(path), "--force").exit_code == 0
    assert "EDIT BEFORE USE" in path.read_text(encoding="utf-8")


def test_init_refuses_a_missing_directory_and_a_directory_path(tmp_path: Path) -> None:
    missing = invoke("scope", "init", str(tmp_path / "no-such-dir" / "scope.yaml"))
    assert missing.exit_code == 1 and "POLICY-003" in missing.output and "does not exist" in missing.output
    assert not (tmp_path / "no-such-dir").exists()
    as_directory = invoke("scope", "init", str(tmp_path), "--force")
    assert (
        as_directory.exit_code == 1 and "POLICY-003" in as_directory.output and "is a directory" in as_directory.output
    )


def test_init_does_not_follow_a_symlink_that_points_elsewhere(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("do not touch", encoding="utf-8")
    link = tmp_path / "scope.yaml"
    link.symlink_to(victim)
    result = invoke("scope", "init", str(link), "--force")
    assert (
        result.exit_code == 1
        and "symbolic link" in result.output
        and victim.read_text(encoding="utf-8") == "do not touch"
    )


def test_the_starter_contains_no_real_host_and_no_secret_shaped_value(tmp_path: Path) -> None:
    import re  # noqa: PLC0415

    path = tmp_path / "scope.yaml"
    invoke("scope", "init", str(path))
    text = path.read_text(encoding="utf-8")
    hosts = re.findall(r"^\s*(?:- )?host:\s*(\S+)", text, re.MULTILINE)  # real YAML keys, not prose
    assert hosts and all(h.endswith(".invalid") for h in hosts)
    assert not re.search(r"[A-Za-z0-9+/_-]{32,}", text)


def test_the_starter_plans_fewer_operations_than_its_budget(tmp_path: Path) -> None:
    from scopedagent.policy.scope import load_scope  # noqa: PLC0415

    path = tmp_path / "scope.yaml"
    invoke("scope", "init", str(path))
    loaded = load_scope(path, now=NOW)
    assert 0 < len(loaded.planned) <= loaded.config.max_requests


def test_init_reports_a_write_failure_instead_of_crashing(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)  # readable and searchable, not writable
    try:
        result = invoke("scope", "init", str(locked / "scope.yaml"))
    finally:
        locked.chmod(0o700)
    assert result.exit_code == 1 and "POLICY-003" in result.output and "could not write" in result.output
    assert not (locked / "scope.yaml").exists()


def test_init_never_writes_a_starter_that_the_tool_itself_would_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scopedagent.cli as module  # noqa: PLC0415

    monkeypatch.setattr(module, "starter_scope", lambda now: "engagement_id: x\n")  # not a valid scope
    path = tmp_path / "scope.yaml"
    result = invoke("scope", "init", str(path))
    assert result.exit_code == 1 and "SCOPE-003" in result.output and not path.exists()
