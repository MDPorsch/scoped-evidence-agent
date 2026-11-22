"""docs/cli.md: `run` and `observations show`. The clock and user are injected; nothing reads the environment."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from scopedagent.cli import AppContext, app
from tests.support import AI_PACK, FIXTURES, NOW, SCOPE_FILES, dump, pack_variant, scope_dict
from tests.unit.test_scope_live import live_dict

pytestmark = pytest.mark.milestone("M2")

runner = CliRunner()
CTX = AppContext(clock=lambda: NOW, user=lambda: "alice")


def invoke(*args: str, ctx: AppContext = CTX) -> Any:
    return runner.invoke(app, list(args), obj=ctx)


def pack_path(name: str) -> str:
    return str(FIXTURES / "web_responses" / f"{name}.yaml")


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    path = tmp_path / "data"
    assert invoke("db", "upgrade", "--data-dir", str(path)).exit_code == 0
    return path


def do_run(
    data_dir: Path, name: str = "healthy", scope: Path | None = None, pack: str | None = None, *extra: str
) -> Any:
    return invoke(
        "run",
        "--scope",
        str(scope or SCOPE_FILES[name]),
        "--fixture",
        pack or pack_path(name),
        "--data-dir",
        str(data_dir),
        *extra,
    )


def run_id_of(output: str) -> str:
    return next(line.split()[1] for line in output.splitlines() if line.startswith("run "))


# ------------------------------------------------------------------------------------------- run ----
@pytest.mark.parametrize(
    ("name", "redactions", "drafts"), [("healthy", 0, 0), ("misconfigured", 2, 8), ("poisoned", 1, 2), (AI_PACK, 0, 2)]
)
def test_a_complete_offline_run_reports_its_coverage_and_its_drafts(
    data_dir: Path, name: str, redactions: int, drafts: int
) -> None:
    result = do_run(data_dir, name)
    assert result.exit_code == (3 if drafts else 0), result.output  # 3: complete, and a person has drafts to review
    out = result.output
    assert "coverage: complete" in out and f"redactions: {redactions}" in out and "state: DRAFTED" in out
    assert f"findings drafted: {drafts}" in out
    assert "scope sha256:" in out and "not proof of authorization" in out
    assert "a draft is not a finding" in out and "no draft is not proof that nothing is wrong" in out


def test_the_run_reports_planned_and_recorded_counts(data_dir: Path) -> None:
    out = do_run(data_dir).output
    assert "planned operations: 5" in out and "observations recorded: 5" in out and "artifacts stored: 3" in out


def test_an_incomplete_collection_exits_two_and_names_what_failed(data_dir: Path, tmp_path: Path) -> None:
    data = scope_dict("healthy")
    data["max_requests"] = 3
    scope = tmp_path / "small.yaml"
    scope.write_text(dump(data), encoding="utf-8")
    result = do_run(data_dir, "healthy", scope)
    assert result.exit_code == 2 and "coverage: incomplete" in result.output and "budget_exhausted: 2" in result.output


def test_a_pack_that_cannot_answer_an_operation_is_incomplete(data_dir: Path, tmp_path: Path) -> None:
    def edit(data: dict[str, Any]) -> None:
        del data["dns"]["lab.example.invalid"]

    result = do_run(data_dir, "healthy", None, str(pack_variant(tmp_path, "healthy", edit)))
    assert result.exit_code == 2 and "adapter_error: 1" in result.output


def test_the_live_flag_is_refused_and_nothing_is_stored(data_dir: Path) -> None:
    result = do_run(data_dir, "healthy", None, None, "--live")
    assert result.exit_code == 1 and "POLICY-001" in result.output
    assert "no runs" in invoke("runs", "list", "--data-dir", str(data_dir)).output.lower()


def test_a_live_scope_is_refused_and_nothing_is_stored(data_dir: Path, tmp_path: Path) -> None:
    data = live_dict("healthy")
    scope = tmp_path / "live.yaml"
    scope.write_text(dump(data), encoding="utf-8")
    result = do_run(data_dir, "healthy", scope)
    assert result.exit_code == 1 and "POLICY-001" in result.output
    assert "no runs" in invoke("runs", "list", "--data-dir", str(data_dir)).output.lower()


def test_an_expired_scope_is_refused_by_the_injected_clock(data_dir: Path) -> None:
    from datetime import timedelta  # noqa: PLC0415

    late = AppContext(clock=lambda: NOW + timedelta(days=60), user=lambda: "alice")
    result = invoke(
        "run",
        "--scope",
        str(SCOPE_FILES["healthy"]),
        "--fixture",
        pack_path("healthy"),
        "--data-dir",
        str(data_dir),
        ctx=late,
    )
    assert result.exit_code == 1 and "SCOPE-004" in result.output


def test_a_bad_scope_a_missing_pack_and_a_bad_pack_exit_one_with_their_codes(data_dir: Path, tmp_path: Path) -> None:
    assert "SCOPE-001" in do_run(data_dir, "healthy", tmp_path / "missing.yaml").output
    missing = do_run(data_dir, "healthy", None, str(tmp_path / "missing-pack.yaml"))
    assert missing.exit_code == 1 and "PACK-001" in missing.output
    bad = tmp_path / "bad-pack.yaml"
    bad.write_text("pack: abc\ndns:\n  UPPER.example.invalid: {}\n", encoding="utf-8")
    result = do_run(data_dir, "healthy", None, str(bad))
    assert result.exit_code == 1 and "PACK-003" in result.output
    assert "no runs" in invoke("runs", "list", "--data-dir", str(data_dir)).output.lower()


def test_a_run_without_a_database_is_an_infrastructure_error_that_creates_nothing(tmp_path: Path) -> None:
    missing = tmp_path / "no-database"
    result = do_run(missing)
    assert (
        result.exit_code == 2
        and "STORE-001" in result.output
        and "db upgrade" in result.output
        and not missing.exists()
    )


def test_the_run_appears_in_the_history_as_drafted_with_the_user_who_ran_it(data_dir: Path) -> None:
    run_id = run_id_of(do_run(data_dir).output)
    line = next(
        line for line in invoke("runs", "list", "--data-dir", str(data_dir)).output.splitlines() if run_id in line
    )
    assert "DRAFTED" in line and "lab-healthy-001" in line
    assert invoke("audit", "verify", run_id, "--data-dir", str(data_dir)).exit_code == 0


def test_two_runs_print_the_same_report_apart_from_the_run_id(data_dir: Path) -> None:
    first, second = do_run(data_dir).output, do_run(data_dir).output
    assert first.replace(run_id_of(first), "ID") == second.replace(run_id_of(second), "ID")


# ----------------------------------------------------------------------------- observations show ----
def test_observations_show_lists_each_observation_with_its_type_status_and_subject(data_dir: Path) -> None:
    run_id = run_id_of(do_run(data_dir).output)
    out = invoke("observations", "show", run_id, "--data-dir", str(data_dir)).output
    lines = [line for line in out.splitlines() if line.strip() and line.split()[0].isdigit()]
    assert len(lines) == 5
    assert "dns_metadata" in lines[0] and "lab.example.invalid" in lines[0] and "ok" in lines[0]
    assert "tls_metadata" in lines[1] and "lab.example.invalid:443" in lines[1]
    assert "http_metadata" in lines[2] and "/.well-known/security.txt" in lines[2]


def test_ai_observations_show_the_probe_subject(data_dir: Path) -> None:
    run_id = run_id_of(do_run(data_dir, AI_PACK).output)
    out = invoke("observations", "show", run_id, "--data-dir", str(data_dir)).output
    assert (
        "ai_metadata" in out
        and "/v1/models" in out
        and "probe canary-echo-v1[0]" in out
        and "probe output-structure-v1[1]" in out
    )


def test_observations_show_never_prints_a_secret_that_was_redacted(data_dir: Path) -> None:
    run_id = run_id_of(do_run(data_dir, "misconfigured").output)
    shown = invoke("observations", "show", run_id, "--data-dir", str(data_dir), "--json").output
    assert "SYNTHETIC-COOKIE-0001" not in shown and "SYNTHETIC-KEY-0001" not in shown and "[REDACTED]" in shown


def test_json_mode_prints_one_stored_payload_per_line(data_dir: Path) -> None:
    run_id = run_id_of(do_run(data_dir).output)
    out = invoke("observations", "show", run_id, "--data-dir", str(data_dir), "--json").output
    payloads = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert len(payloads) == 5 and payloads[0]["records"]["A"] == ["192.0.2.10"]


def test_observations_paginate_with_bounds(data_dir: Path) -> None:
    run_id = run_id_of(do_run(data_dir).output)
    page = invoke("observations", "show", run_id, "--data-dir", str(data_dir), "--limit", "2", "--offset", "3").output
    assert len([line for line in page.splitlines() if line.split() and line.split()[0].isdigit()]) == 2
    for limit, offset in (("0", "0"), ("101", "0"), ("5", "-1")):
        result = invoke(
            "observations", "show", run_id, "--data-dir", str(data_dir), "--limit", limit, "--offset", offset
        )
        assert result.exit_code == 1 and "POLICY-003" in result.output


def test_observations_of_an_unknown_run_exit_one(data_dir: Path) -> None:
    result = invoke("observations", "show", "no-such-run", "--data-dir", str(data_dir))
    assert result.exit_code == 1 and "POLICY-002" in result.output


def test_a_run_with_no_observations_says_so(data_dir: Path) -> None:
    # a refused run stores nothing, so create an empty run through the repository to list it
    from scopedagent.domain.state_machine import Actor, ActorType  # noqa: PLC0415
    from scopedagent.policy.scope import load_scope  # noqa: PLC0415
    from scopedagent.storage.database import DataDir, open_database  # noqa: PLC0415
    from scopedagent.storage.repositories import create_run, register_engagement  # noqa: PLC0415

    db = open_database(DataDir(data_dir))
    with db.begin() as session:
        engagement = register_engagement(session, load_scope(SCOPE_FILES["healthy"], now=NOW), now=NOW)
        run_id = create_run(session, engagement, actor=Actor(ActorType.HUMAN, "alice"), now=NOW).id
    db.close()
    assert "no observations" in invoke("observations", "show", run_id, "--data-dir", str(data_dir)).output.lower()


def test_the_coverage_line_counts_operations_that_never_ran() -> None:
    from types import SimpleNamespace  # noqa: PLC0415

    from scopedagent.cli import _coverage_line  # noqa: PLC0415
    from scopedagent.domain.outcome import Coverage, ErrorStatus  # noqa: PLC0415

    partial = SimpleNamespace(coverage=Coverage(planned=10, ok=6, by_status={ErrorStatus.TIMEOUT: 1}))
    assert _coverage_line(partial) == "coverage: incomplete (timeout: 1, not run: 3)"
    nothing = SimpleNamespace(coverage=Coverage(planned=4, ok=0, by_status={}))
    assert _coverage_line(nothing) == "coverage: incomplete (not run: 4)"
    assert _coverage_line(SimpleNamespace(coverage=Coverage(planned=4, ok=4, by_status={}))) == "coverage: complete"


def test_the_run_is_started_by_the_user_the_context_names(data_dir: Path) -> None:
    import contextlib  # noqa: PLC0415
    import sqlite3  # noqa: PLC0415

    assert do_run(data_dir).exit_code == 0
    with contextlib.closing(sqlite3.connect(data_dir / "evidence.sqlite")) as connection:
        actors = connection.execute(
            "SELECT actor_type, actor_id FROM audit_events WHERE action = 'run.created'"
        ).fetchall()
    assert actors == [("human", "alice")]


def test_the_coverage_line_lists_statuses_in_a_stable_order() -> None:
    from types import SimpleNamespace  # noqa: PLC0415

    from scopedagent.cli import _coverage_line  # noqa: PLC0415
    from scopedagent.domain.outcome import Coverage, ErrorStatus  # noqa: PLC0415

    statuses = {ErrorStatus.TIMEOUT: 1, ErrorStatus.ADAPTER_ERROR: 2}
    line = _coverage_line(SimpleNamespace(coverage=Coverage(planned=3, ok=0, by_status=statuses)))
    assert line == "coverage: incomplete (adapter_error: 2, timeout: 1)"


def test_observation_numbers_follow_the_offset(data_dir: Path) -> None:
    run_id = run_id_of(do_run(data_dir).output)
    shown = invoke("observations", "show", run_id, "--offset", "2", "--limit", "2", "--data-dir", str(data_dir))
    numbers = [line.split()[0] for line in shown.output.splitlines()[1:]]
    assert numbers == ["3", "4"]
