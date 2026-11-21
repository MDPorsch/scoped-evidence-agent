"""M3: the report (D-E64). One local file built only from the database: no artifact content, no export time, no overwrite."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from typer.testing import CliRunner

from scopedagent import __version__
from scopedagent.cli import AppContext, app
from scopedagent.domain.findings import ReviewDecision
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, ReportError
from scopedagent.output.report import build_report, render_json, render_markdown, write_report
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.repositories import review_finding
from tests.support import FIXTURES, NOW, SCOPE_FILES, assemble, findings_of, make_env, run_pack, scope_dict, dump

pytestmark = pytest.mark.milestone("M3")

ALICE = Actor(ActorType.HUMAN, "alice")
runner = CliRunner()
CTX = AppContext(clock=lambda: NOW, user=lambda: "alice")


@pytest.fixture
def env(tmp_path: Path) -> Any:
    db, store, data_dir = make_env(tmp_path)
    yield db, store, data_dir
    db.close()


def report_for(env: Any, name: str = "misconfigured", **kw: Any) -> tuple[dict[str, Any], str]:
    result = run_pack(env, name, **kw)
    db, _, _ = env
    with db.begin() as session:
        return build_report(session, result.run_id, tool_version=__version__), result.run_id


def confirm(
    env: Any, finding_id: str, decision: ReviewDecision = ReviewDecision.CONFIRMED, reason: str = "reproduced"
) -> None:
    db, _, _ = env
    with db.begin() as session:
        review_finding(session, finding_id, decision, reviewer=ALICE, reason=reason, now=NOW)


# ----------------------------------------------------------------------------------------------- the contents ----
def test_the_report_holds_the_run_the_scope_the_coverage_and_every_observation(env: Any) -> None:
    report, run_id = report_for(env)
    assert report["schema_version"] == 1
    assert report["tool"] == {"name": "scoped-agent", "version": __version__}
    assert report["run"]["id"] == run_id and report["run"]["state"] == "DRAFTED" and report["run"]["attempt"] == 1
    assert report["engagement"]["label"] == "lab-misconfigured-001"
    assert report["engagement"]["scope_sha256"] == "9de5beb7651f062e64cd09bff2abf44aaaa797f8f5b52a7e27c9d7ae6c7157a1"
    assert report["engagement"]["mode"] == "offline" and report["engagement"]["expires_at"].startswith("2026-12-31")
    assert report["coverage"] == {"planned": 6, "recorded": 6, "ok": 6, "other": {}, "complete": True}
    obs = report["observations"]
    assert [o["type"] for o in obs] == ["dns_metadata", "tls_metadata"] + ["http_metadata"] * 4
    assert obs[1]["subject"] == "bad.example.invalid:443" and obs[2]["subject"] == "https://bad.example.invalid:443/"
    for o in obs:
        assert set(o) == {"id", "type", "status", "subject", "source_hash", "normalized_input_hash", "collected_at"}
        assert len(o["source_hash"]) == 64 and len(o["normalized_input_hash"]) == 64


def test_the_report_never_names_the_person_who_started_the_run(env: Any) -> None:
    report, _ = report_for(env)
    assert "created_by" not in json.dumps(report)
    assert set(report["run"]) == {
        "id",
        "state",
        "attempt",
        "mode",
        "created_at",
        "started_at",
        "ended_at",
        "error_code",
    }


def test_artifacts_are_listed_by_hash_and_never_by_content(env: Any) -> None:
    report, _ = report_for(env)
    assert len(report["artifacts"]) == 3
    for artifact in report["artifacts"]:
        assert set(artifact) == {"sha256", "mime", "size", "redaction_status"}
    rendered = render_json(report) + render_markdown(report)
    assert "mailto:security@bad.example.invalid" not in rendered  # the security.txt body is an artifact
    assert (
        '"openapi": "3.0.1"' not in rendered and "Disallow: /backup" in rendered
    )  # the draft quotes one path as data; the file is not copied


def test_every_finding_is_in_the_report_with_its_details_and_a_draft_label(env: Any) -> None:
    report, _ = report_for(env)
    findings = report["findings"]
    assert [f["class"] for f in findings][:2] == ["tls_misconfiguration", "missing_security_header"]
    first = findings[0]
    assert first["status"] == "NEEDS_VALIDATION" and first["label"] == "DRAFT: not validated"
    assert first["title"] == "TLS configuration weaknesses on bad.example.invalid:443" and first["confidence"] == 0.9
    assert first["details"]["severity"] == "unknown" and first["details"]["suggested_severity"]["value"] == "medium"
    assert first["details"]["exploitability"]["assessment"] == "conditional"
    assert len(first["evidence"]) == 1 and first["reviews"] == []
    assert [s["kind"] for s in first["details"]["validation_steps"]][1] == "inspect_certificate_field"


def test_a_reviewed_finding_shows_its_decision_its_reviewer_and_its_reason(env: Any) -> None:
    result = run_pack(env, "misconfigured")
    db, _, _ = env
    ids = [f.id for f, _ in findings_of(db, result.run_id)]
    confirm(env, ids[0], ReviewDecision.CONFIRMED, "reproduced with the steps")
    confirm(env, ids[1], ReviewDecision.INCONCLUSIVE, "owner did not answer")
    with db.begin() as session:
        report = build_report(session, result.run_id, tool_version=__version__)
    first, second, third = report["findings"][:3]
    assert first["status"] == "VALIDATED" and first["label"] == "VALIDATED by a reviewer"
    assert first["reviews"] == [
        {
            "decision": "confirmed",
            "reviewer": "alice",
            "reason": "reproduced with the steps",
            "status_after": "VALIDATED",
            "reviewed_at": "2026-11-20T12:00:00Z",
        }
    ]
    assert second["status"] == "NEEDS_VALIDATION" and second["label"] == "DRAFT: not validated"
    assert second["reviews"][0]["decision"] == "inconclusive"
    assert third["reviews"] == []
    assert report["run"]["state"] == "HUMAN_REVIEW"


def test_a_closed_finding_is_labelled_as_such(env: Any) -> None:
    result = run_pack(env, "misconfigured")
    db, _, _ = env
    finding_id = findings_of(db, result.run_id)[0][0].id
    confirm(env, finding_id, ReviewDecision.NOT_EXPLOITABLE, "decommissioned")
    with db.begin() as session:
        report = build_report(session, result.run_id, tool_version=__version__)
    assert report["findings"][0]["label"] == "FALSE_POSITIVE: closed by a reviewer"
    assert report["findings"][0]["reviews"][0]["decision"] == "not_exploitable"


def test_the_audit_section_states_whether_the_chain_verified_and_its_head(env: Any) -> None:
    report, run_id = report_for(env)
    db, _, _ = env
    with db.begin() as session:
        count = verify_chain(session, run_id)
        head = session.execute(
            text("SELECT entry_hash FROM audit_events WHERE run_id = :r ORDER BY id DESC LIMIT 1"), {"r": run_id}
        ).scalar()
    assert report["audit"] == {"events": count, "chain_verified": True, "head_hash": head}


def test_a_broken_chain_is_reported_not_hidden(env: Any) -> None:
    result = run_pack(env, "misconfigured")
    db, _, data_dir = env
    import sqlite3  # noqa: PLC0415

    connection = sqlite3.connect(data_dir.db_path)
    try:
        connection.execute("DROP TRIGGER audit_events_no_update")
        connection.execute(
            "UPDATE audit_events SET reason = 'tampered' WHERE id = (SELECT min(id) FROM audit_events WHERE run_id = ?)",
            (result.run_id,),
        )
        connection.commit()
    finally:
        connection.close()
    with db.begin() as session:
        report = build_report(session, result.run_id, tool_version=__version__)
    assert report["audit"]["chain_verified"] is False


def test_an_incomplete_run_states_its_coverage_and_every_other_status(env: Any) -> None:
    data = scope_dict("misconfigured")
    data["max_requests"] = 3
    from scopedagent.policy.scope import parse_scope  # noqa: PLC0415

    report, _ = report_for(env, loaded=parse_scope(dump(data), now=NOW))
    coverage = report["coverage"]
    assert coverage["planned"] == 6 and coverage["recorded"] == 6 and coverage["complete"] is False
    assert coverage["ok"] == 3 and coverage["other"] == {"budget_exhausted": 3}


def test_a_run_that_never_recorded_its_plan_says_unknown(env: Any) -> None:
    result = run_pack(env, "healthy")
    db, _, _ = env
    with db.begin() as session:
        session.execute(text("UPDATE runs SET planned_operations = NULL WHERE id = :r"), {"r": result.run_id})
        report = build_report(session, result.run_id, tool_version=__version__)
    assert report["coverage"]["planned"] is None and report["coverage"]["complete"] is False


def test_the_fixed_notes_say_what_a_reader_must_not_assume(env: Any) -> None:
    report, _ = report_for(env)
    notes = " ".join(report["notes"]).lower()
    assert "a draft is not a finding" in notes
    assert "authorization" in notes and "not proof" in notes
    assert "was not collected" in notes or "not collected" in notes


def test_an_unknown_run_is_refused(env: Any) -> None:
    from scopedagent.errors import PolicyError  # noqa: PLC0415

    db, _, _ = env
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        build_report(session, "no-such-run", tool_version=__version__)
    assert caught.value.code is ErrorCode.POLICY_002


# ------------------------------------------------------------------------------------------ reproducibility ----
def test_the_same_run_exports_byte_identical_files(env: Any) -> None:
    result = run_pack(env, "misconfigured")
    db, _, _ = env
    outputs = []
    for _ in range(2):
        with db.begin() as session:
            report = build_report(session, result.run_id, tool_version=__version__)
        outputs.append((render_json(report), render_markdown(report)))
    assert outputs[0] == outputs[1]


def test_the_json_is_sorted_compact_ascii_and_ends_with_a_newline(env: Any) -> None:
    report, _ = report_for(env)
    rendered = render_json(report)
    assert rendered.endswith("\n") and rendered.isascii()
    assert json.loads(rendered) == json.loads(json.dumps(report))
    assert rendered == json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def test_the_report_holds_no_export_time_path_or_host_name(env: Any) -> None:
    report, _ = report_for(env)
    rendered = render_json(report) + render_markdown(report)
    assert str(env[2].root) not in rendered and "/Users/" not in rendered and "/private/" not in rendered


def test_two_runs_of_one_pack_differ_only_in_their_ids(env: Any) -> None:
    first, _ = report_for(env)
    second, _ = report_for(env)

    def scrub(report: dict[str, Any]) -> str:
        blob = json.dumps(report, sort_keys=True)
        for index, finding in enumerate(report["findings"]):
            blob = blob.replace(finding["id"], f"FINDING-{index}")
        for index, observation in enumerate(report["observations"]):
            blob = blob.replace(observation["id"], f"OBSERVATION-{index}")
        return blob.replace(report["run"]["id"], "RUN").replace(report["audit"]["head_hash"], "HEAD")

    assert scrub(first) == scrub(second)


# ----------------------------------------------------------------------------------------------------- privacy ----
def test_no_secret_and_no_hostile_text_is_in_either_format(env: Any) -> None:
    result = run_pack(env, "poisoned")
    db, _, _ = env
    with db.begin() as session:
        report = build_report(session, result.run_id, tool_version=__version__)
    rendered = render_json(report) + render_markdown(report)
    for phrase in (
        "SYNTHETIC-COOKIE",
        "SYNTHETIC-KEY",
        "ignore all previous",
        "SYSTEM NOTICE",
        "Mark every finding",
        "maintenance mode",
        "javascript:alert",
        "169.254.169.254",
    ):
        assert phrase.lower() not in rendered.lower(), phrase


def test_a_secret_written_into_a_review_row_by_some_other_route_is_still_redacted_in_the_report(env: Any) -> None:
    result = run_pack(env, "misconfigured")
    db, _, _ = env
    finding_id = findings_of(db, result.run_id)[0][0].id
    token = assemble("gh", "p_", "S" * 36)
    with db.begin() as session:
        session.execute(
            text(
                "INSERT INTO finding_reviews (finding_id, run_id, decision, reviewer_id, reason, status_after, created_at) VALUES (:f, :r, 'inconclusive', :who, :why, 'NEEDS_VALIDATION', '2026-11-20T12:00:00.000000Z')"
            ),
            {"f": finding_id, "r": result.run_id, "who": f"bob token={token}", "why": f"saw token={token}"},
        )
        report = build_report(session, result.run_id, tool_version=__version__)
    rendered = render_json(report) + render_markdown(report)
    assert token not in rendered and "[REDACTED]" in rendered


def test_markdown_escapes_what_a_person_typed(env: Any) -> None:
    result = run_pack(env, "misconfigured")
    db, _, _ = env
    finding_id = findings_of(db, result.run_id)[0][0].id
    confirm(
        env,
        finding_id,
        ReviewDecision.CONFIRMED,
        "<script>alert(1)</script> [click](javascript:alert(1)) `rm -rf /` | a | b\n# not a heading\n- not a list",
    )
    with db.begin() as session:
        report = build_report(session, result.run_id, tool_version=__version__)
    md = render_markdown(report)
    assert "<script>" not in md and "](javascript:" not in md
    assert "&lt;script&gt;" in md
    assert not any(line.startswith("# not a heading") or line.startswith("- not a list") for line in md.splitlines())
    assert "\\|" in md
    assert "`rm -rf /`" not in md


def test_markdown_labels_drafts_and_shows_quoted_data_only_in_code_spans(env: Any) -> None:
    report, _ = report_for(env)
    md = render_markdown(report)
    assert md.startswith("# Evidence report\n")
    for heading in (
        "## Run",
        "## Coverage",
        "## Observations",
        "## Artifacts",
        "## Findings",
        "## Audit trail",
        "## Notes",
    ):
        assert heading in md
    assert md.count("DRAFT: not validated") >= 8
    assert "`Server: Apache/2.4.49 (Unix)`" in md and "`Disallow: /admin`" in md
    assert md.endswith("\n") and "\r" not in md


def test_the_markdown_and_the_json_say_the_same_things(env: Any) -> None:
    report, _ = report_for(env)
    md = render_markdown(report)
    for finding in report["findings"]:
        assert finding["title"] in md and finding["id"] in md
        for condition in finding["details"]["conditions"]:
            assert condition.replace("|", "\\|") in md or condition in md
    for observation in report["observations"]:
        assert observation["id"] in md and observation["source_hash"] in md


# --------------------------------------------------------------------------------------------- writing it ----
def read_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_the_file_is_new_private_and_its_hash_is_returned(env: Any, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    target = out / "report.json"
    digest = write_report(target, "hello\n", data_dir=env[2].root)
    assert target.read_text() == "hello\n" and read_mode(target) == 0o600
    assert digest == hashlib.sha256(b"hello\n").hexdigest()
    assert [p.name for p in out.iterdir()] == ["report.json"]  # no temporary file is left


def refuse_write(path: Path, env: Any, message: str = "") -> ReportError:
    with pytest.raises(ReportError) as caught:
        write_report(path, "x\n", data_dir=env[2].root)
    assert caught.value.code is ErrorCode.REPORT_001
    assert message in str(caught.value)
    return caught.value


def test_an_existing_file_is_never_replaced(env: Any, tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("keep me")
    refuse_write(target, env, "exists")
    assert target.read_text() == "keep me"


def test_a_missing_parent_directory_is_not_created(env: Any, tmp_path: Path) -> None:
    refuse_write(tmp_path / "missing" / "report.json", env, "directory")
    assert not (tmp_path / "missing").exists()


def test_a_symlink_as_the_output_is_refused_and_its_target_untouched(env: Any, tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    link = tmp_path / "link.json"
    link.symlink_to(victim)
    refuse_write(link, env)
    assert victim.read_text() == "precious"
    dangling = tmp_path / "dangling.json"
    dangling.symlink_to(tmp_path / "nowhere")
    refuse_write(dangling, env)
    assert not (tmp_path / "nowhere").exists()


def test_a_symlinked_directory_anywhere_in_the_path_is_refused(env: Any, tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "alias").symlink_to(real)
    refuse_write(tmp_path / "alias" / "report.json", env, "symbolic link")
    assert list(real.iterdir()) == []


def test_dot_dot_in_the_path_is_refused_even_when_it_would_resolve_safely(env: Any, tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    refuse_write(tmp_path / "a" / ".." / "report.json", env, "..")
    assert not (tmp_path / "report.json").exists()


@pytest.mark.parametrize(
    "relative", ["report.json", "artifacts/report.json", "artifacts/ab/report.json", "evidence.sqlite-journal"]
)
def test_nothing_may_be_written_inside_the_data_directory(env: Any, relative: str) -> None:
    data_root: Path = env[2].root
    (data_root / "artifacts" / "ab").mkdir(parents=True, exist_ok=True)
    refuse_write(data_root / relative, env, "data directory")
    assert not (data_root / relative).exists()


def test_a_sibling_of_the_data_directory_is_allowed(env: Any) -> None:
    data_root: Path = env[2].root
    sibling = data_root.parent / "data-reports"
    sibling.mkdir()
    write_report(sibling / "r.md", "x\n", data_dir=data_root)
    assert (sibling / "r.md").exists()


@pytest.mark.parametrize("kind", ["directory", "fifo", "empty"])
def test_a_directory_a_pipe_or_an_empty_path_is_refused(env: Any, tmp_path: Path, kind: str) -> None:
    if kind == "directory":
        target = tmp_path / "dir"
        target.mkdir()
    elif kind == "fifo":
        target = tmp_path / "pipe"
        os.mkfifo(target)
    else:
        target = Path("")
    refuse_write(target, env)


def test_a_file_that_appears_between_the_check_and_the_write_is_not_overwritten(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "report.json"
    real_link = os.link

    def racing(src: Any, dst: Any, **kw: Any) -> None:
        Path(dst).write_text("someone else's file")
        real_link(src, dst, **kw)

    monkeypatch.setattr(os, "link", racing)
    refuse_write(target, env, "exists")
    assert target.read_text() == "someone else's file"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["data", "report.json"]  # no temporary file is left behind


def test_a_failed_write_leaves_no_file_and_no_temporary(
    env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    out.mkdir()

    def broken(_fd: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", broken)
    refuse_write(out / "report.json", env)
    assert list(out.iterdir()) == []


# ------------------------------------------------------------------------------------------------------ the CLI ----
def cli(*args: str) -> Any:
    return runner.invoke(app, list(args), obj=CTX)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    path = tmp_path / "cli-data"
    assert cli("db", "upgrade", "--data-dir", str(path)).exit_code == 0
    return path


def collect(data_dir: Path, name: str = "misconfigured") -> str:
    out = cli(
        "run",
        "--scope",
        str(SCOPE_FILES[name]),
        "--fixture",
        str(FIXTURES / "web_responses" / f"{name}.yaml"),
        "--data-dir",
        str(data_dir),
    )
    return next(line.split()[1] for line in out.output.splitlines() if line.startswith("run "))


@pytest.mark.parametrize("fmt", ["json", "md"])
def test_report_export_writes_the_file_and_prints_its_hash(data_dir: Path, tmp_path: Path, fmt: str) -> None:
    run_id = collect(data_dir)
    out_file = tmp_path / f"report.{fmt}"
    result = cli("report", "export", run_id, "--format", fmt, "--output", str(out_file), "--data-dir", str(data_dir))
    assert result.exit_code == 0, result.output
    digest = hashlib.sha256(out_file.read_bytes()).hexdigest()
    assert f"sha256: {digest}" in result.output and str(out_file) in result.output
    assert read_mode(out_file) == 0o600
    if fmt == "json":
        assert json.loads(out_file.read_text())["run"]["id"] == run_id
    else:
        assert out_file.read_text().startswith("# Evidence report")


def test_exporting_twice_to_two_files_gives_the_same_bytes(data_dir: Path, tmp_path: Path) -> None:
    run_id = collect(data_dir)
    for name in ("a.json", "b.json"):
        assert (
            cli(
                "report",
                "export",
                run_id,
                "--format",
                "json",
                "--output",
                str(tmp_path / name),
                "--data-dir",
                str(data_dir),
            ).exit_code
            == 0
        )
    assert (tmp_path / "a.json").read_bytes() == (tmp_path / "b.json").read_bytes()


def test_exporting_does_not_change_the_run_or_its_audit_trail(data_dir: Path, tmp_path: Path) -> None:
    from scopedagent.storage.database import DataDir, open_database  # noqa: PLC0415

    run_id = collect(data_dir)

    def snapshot() -> tuple[Any, ...]:
        db = open_database(DataDir(data_dir))
        try:
            with db.begin() as session:
                return (
                    session.execute(text("SELECT state FROM runs WHERE id = :r"), {"r": run_id}).scalar(),
                    session.execute(
                        text("SELECT count(*), max(entry_hash) FROM audit_events WHERE run_id = :r"), {"r": run_id}
                    ).one(),
                )
        finally:
            db.close()

    before = snapshot()
    assert (
        cli(
            "report",
            "export",
            run_id,
            "--format",
            "md",
            "--output",
            str(tmp_path / "r.md"),
            "--data-dir",
            str(data_dir),
        ).exit_code
        == 0
    )
    assert snapshot() == before


def test_report_export_refusals_exit_one_with_a_code_and_no_traceback(data_dir: Path, tmp_path: Path) -> None:
    run_id = collect(data_dir)
    existing = tmp_path / "there.json"
    existing.write_text("x")
    for args, code in (
        ([run_id, "--format", "json", "--output", str(existing)], "REPORT-001"),
        ([run_id, "--format", "json", "--output", str(tmp_path / "no" / "x.json")], "REPORT-001"),
        (["no-such-run", "--format", "json", "--output", str(tmp_path / "n.json")], "POLICY-002"),
    ):
        result = cli("report", "export", *args, "--data-dir", str(data_dir))
        assert result.exit_code == 1 and code in result.output and "Traceback" not in result.output
    assert not (tmp_path / "n.json").exists()


def test_an_unknown_format_is_a_usage_error_and_writes_nothing(data_dir: Path, tmp_path: Path) -> None:
    run_id = collect(data_dir)
    result = cli(
        "report", "export", run_id, "--format", "pdf", "--output", str(tmp_path / "x.pdf"), "--data-dir", str(data_dir)
    )
    assert result.exit_code == 2 and not (tmp_path / "x.pdf").exists()


def test_the_format_and_output_are_required(data_dir: Path) -> None:
    run_id = collect(data_dir)
    assert cli("report", "export", run_id, "--data-dir", str(data_dir)).exit_code == 2
    assert cli("report", "export", run_id, "--format", "json", "--data-dir", str(data_dir)).exit_code == 2


def test_export_refuses_a_path_inside_the_data_directory(data_dir: Path) -> None:
    run_id = collect(data_dir)
    result = cli(
        "report",
        "export",
        run_id,
        "--format",
        "json",
        "--output",
        str(data_dir / "r.json"),
        "--data-dir",
        str(data_dir),
    )
    assert result.exit_code == 1 and "REPORT-001" in result.output and not (data_dir / "r.json").exists()
