"""M3: the commands a person uses to read and review drafts (D-E63, D-E65)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from typer.testing import CliRunner

from scopedagent.cli import AppContext, app
from scopedagent.storage.database import DataDir, open_database
from tests.support import FIXTURES, NOW, SCOPE_FILES

pytestmark = pytest.mark.milestone("M3")

runner = CliRunner()
CTX = AppContext(clock=lambda: NOW, user=lambda: "alice")


def invoke(*args: str, input: str | None = None) -> Any:
    return runner.invoke(app, list(args), obj=CTX, input=input)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    path = tmp_path / "data"
    assert invoke("db", "upgrade", "--data-dir", str(path)).exit_code == 0
    return path


def collect(data_dir: Path, name: str = "misconfigured") -> str:
    result = invoke(
        "run",
        "--scope",
        str(SCOPE_FILES[name]),
        "--fixture",
        str(FIXTURES / "web_responses" / f"{name}.yaml"),
        "--data-dir",
        str(data_dir),
    )
    return next(line.split()[1] for line in result.output.splitlines() if line.startswith("run "))


def finding_ids(data_dir: Path, run_id: str) -> list[str]:
    db = open_database(DataDir(data_dir))
    try:
        with db.begin() as session:
            return list(
                session.execute(
                    text("SELECT id FROM finding_drafts WHERE run_id = :r ORDER BY rowid"), {"r": run_id}
                ).scalars()
            )
    finally:
        db.close()


# ----------------------------------------------------------------------------------------------------- run ----
def test_run_reports_how_many_drafts_await_review_and_exits_three(data_dir: Path) -> None:
    result = invoke(
        "run",
        "--scope",
        str(SCOPE_FILES["misconfigured"]),
        "--fixture",
        str(FIXTURES / "web_responses" / "misconfigured.yaml"),
        "--data-dir",
        str(data_dir),
    )
    assert result.exit_code == 3, result.output
    assert "findings drafted: 8 (awaiting review)" in result.output
    assert "coverage: complete" in result.output
    assert "a draft is not a finding" in result.output.lower()


def test_run_with_nothing_to_draft_says_so_and_exits_zero(data_dir: Path) -> None:
    result = invoke(
        "run",
        "--scope",
        str(SCOPE_FILES["healthy"]),
        "--fixture",
        str(FIXTURES / "web_responses" / "healthy.yaml"),
        "--data-dir",
        str(data_dir),
    )
    assert result.exit_code == 0
    assert "findings drafted: 0" in result.output
    assert "no draft is not proof that nothing is wrong" in result.output.lower()


# ----------------------------------------------------------------------------------------------- findings list ----
def test_findings_list_shows_each_draft_labelled_as_one(data_dir: Path) -> None:
    run_id = collect(data_dir)
    out = invoke("findings", "list", run_id, "--data-dir", str(data_dir))
    assert out.exit_code == 0, out.output
    lines = out.output.splitlines()
    assert "DRAFT: not validated" in out.output
    rows = [line for line in lines if "tls_misconfiguration" in line or "missing_security_header" in line]
    assert len(rows) == 2
    assert finding_ids(data_dir, run_id)[0][:8] in lines[1]
    assert "TLS configuration weaknesses on bad.example.invalid:443" in out.output
    assert len([line for line in lines if "DRAFT: not validated" in line]) == 8


def test_findings_list_of_a_run_with_no_drafts_says_so(data_dir: Path) -> None:
    run_id = collect(data_dir, "healthy")
    out = invoke("findings", "list", run_id, "--data-dir", str(data_dir))
    assert out.exit_code == 0 and "no findings drafted" in out.output


def test_findings_list_refuses_an_unknown_run(data_dir: Path) -> None:
    out = invoke("findings", "list", "nope", "--data-dir", str(data_dir))
    assert out.exit_code == 1 and "POLICY-002" in out.output


# ----------------------------------------------------------------------------------------------- findings show ----
def test_findings_show_prints_the_whole_draft_with_its_steps(data_dir: Path) -> None:
    run_id = collect(data_dir)
    tls_id = finding_ids(data_dir, run_id)[0]
    out = invoke("findings", "show", tls_id[:8], "--data-dir", str(data_dir))
    assert out.exit_code == 0, out.output
    text_out = out.output
    for needle in (
        "DRAFT: not validated",
        "TLS configuration weaknesses on bad.example.invalid:443",
        "class: tls_misconfiguration",
        "rule: R-TLS-01 (version 1)",
        "CWE-295, CWE-326, CWE-327 (suggestions to verify)",
        "confidence: 0.90",
        "severity: unknown (suggested: medium)",
        "The certificate is self-signed, so it cannot be chained to a trusted authority.",
        "exploitability: conditional",
        "validation steps",
        "1. read_recorded_observation",
        "2. inspect_certificate_field",
        "openssl s_client -connect bad.example.invalid:443 -servername bad.example.invalid -verify_return_error",
        "if the condition holds:",
        "if it does not:",
        "must not:",
        "stop if:",
        "decision guide",
        "remediation:",
        "evidence:",
    ):
        assert needle in text_out, needle
    assert "reviews: none" in text_out


def test_findings_show_a_full_id_works_too_and_a_short_or_unknown_or_ambiguous_one_does_not(data_dir: Path) -> None:
    run_id = collect(data_dir)
    ids = finding_ids(data_dir, run_id)
    assert invoke("findings", "show", ids[0], "--data-dir", str(data_dir)).exit_code == 0
    for ref in (ids[0][:7], "", "zzzzzzzz", "0" * 8):
        out = invoke("findings", "show", ref, "--data-dir", str(data_dir))
        assert out.exit_code in (1, 2), ref
    assert "Traceback" not in invoke("findings", "show", "zzzzzzzz", "--data-dir", str(data_dir)).output


def test_findings_show_never_prints_a_secret_or_hostile_text(data_dir: Path) -> None:
    run_id = collect(data_dir, "poisoned")
    for finding_id in finding_ids(data_dir, run_id):
        out = invoke("findings", "show", finding_id[:8], "--data-dir", str(data_dir)).output
        assert (
            "SYNTHETIC-COOKIE" not in out
            and "ignore all previous" not in out.lower()
            and "VALIDATED" not in out.replace("not validated", "")
        )


# --------------------------------------------------------------------------------------------- findings review ----
def review_args(
    finding_id: str, data_dir: Path, decision: str = "confirmed", reason: str = "ran the steps"
) -> list[str]:
    return [
        "findings",
        "review",
        finding_id[:8],
        "--decision",
        decision,
        "--reviewer",
        "alice",
        "--reason",
        reason,
        "--data-dir",
        str(data_dir),
    ]


def test_a_review_needs_the_first_eight_characters_of_the_id_typed_back(data_dir: Path) -> None:
    run_id = collect(data_dir)
    finding_id = finding_ids(data_dir, run_id)[0]
    out = invoke(*review_args(finding_id, data_dir), input=finding_id[:8] + "\n")
    assert out.exit_code == 0, out.output
    assert "confirmed" in out.output and "VALIDATED" in out.output and "alice" in out.output
    shown = invoke("findings", "show", finding_id[:8], "--data-dir", str(data_dir)).output
    assert "VALIDATED" in shown and "confirmed by alice: ran the steps" in shown and "DRAFT: not validated" not in shown


@pytest.mark.parametrize("typed", ["wrong", "", "  ", "ABCDEF12", "0" * 8])
def test_a_wrong_confirmation_changes_nothing(data_dir: Path, typed: str) -> None:
    run_id = collect(data_dir)
    finding_id = finding_ids(data_dir, run_id)[0]
    out = invoke(*review_args(finding_id, data_dir), input=typed + "\n")
    assert out.exit_code == 1 and "nothing was changed" in out.output
    shown = invoke("findings", "show", finding_id[:8], "--data-dir", str(data_dir)).output
    assert "reviews: none" in shown and "DRAFT: not validated" in shown


def test_there_is_no_way_to_skip_the_confirmation(data_dir: Path) -> None:
    run_id = collect(data_dir)
    finding_id = finding_ids(data_dir, run_id)[0]
    for flag in ("--yes", "--force", "-y", "--confirm", "--no-confirm"):
        out = invoke(*review_args(finding_id, data_dir), flag)
        assert out.exit_code == 2  # an unknown option: there is no such flag
    shown = invoke("findings", "show", finding_id[:8], "--data-dir", str(data_dir)).output
    assert "reviews: none" in shown


@pytest.mark.parametrize("decision", ["confirmed", "not_exploitable", "inconclusive"])
def test_each_decision_reports_the_status_it_gave(data_dir: Path, decision: str) -> None:
    run_id = collect(data_dir)
    finding_id = finding_ids(data_dir, run_id)[0]
    out = invoke(*review_args(finding_id, data_dir, decision), input=finding_id[:8] + "\n")
    assert out.exit_code == 0, out.output
    expected = {"confirmed": "VALIDATED", "not_exploitable": "FALSE_POSITIVE", "inconclusive": "NEEDS_VALIDATION"}[
        decision
    ]
    assert f"{decision} -> {expected}" in out.output


def test_an_unknown_decision_is_a_usage_error(data_dir: Path) -> None:
    run_id = collect(data_dir)
    finding_id = finding_ids(data_dir, run_id)[0]
    out = invoke(*review_args(finding_id, data_dir, "exploited"), input=finding_id[:8] + "\n")
    assert out.exit_code == 2


def test_a_review_without_a_reason_or_reviewer_is_refused(data_dir: Path) -> None:
    run_id = collect(data_dir)
    finding_id = finding_ids(data_dir, run_id)[0]
    blank = invoke(*review_args(finding_id, data_dir, reason="  "), input=finding_id[:8] + "\n")
    assert blank.exit_code == 1 and "STATE-004" in blank.output
    missing = invoke(
        "findings",
        "review",
        finding_id[:8],
        "--decision",
        "confirmed",
        "--data-dir",
        str(data_dir),
        input=finding_id[:8] + "\n",
    )
    assert missing.exit_code == 2


def test_reviewing_a_closed_finding_again_is_refused_with_its_code(data_dir: Path) -> None:
    run_id = collect(data_dir)
    finding_id = finding_ids(data_dir, run_id)[0]
    assert invoke(*review_args(finding_id, data_dir), input=finding_id[:8] + "\n").exit_code == 0
    again = invoke(*review_args(finding_id, data_dir, "not_exploitable"), input=finding_id[:8] + "\n")
    assert again.exit_code == 1 and "STATE-001" in again.output


def test_a_review_of_an_unknown_finding_is_refused_before_it_asks_anything(data_dir: Path) -> None:
    collect(data_dir)
    out = invoke(*review_args("deadbeef", data_dir), input="deadbeef\n")
    assert out.exit_code == 1 and "no such finding" in out.output


def test_the_review_command_never_asks_for_or_prints_a_secret(data_dir: Path) -> None:
    run_id = collect(data_dir)
    finding_id = finding_ids(data_dir, run_id)[0]
    token = "gh" + "p_" + "Q" * 36
    out = invoke(*review_args(finding_id, data_dir, reason=f"token={token}"), input=finding_id[:8] + "\n")
    assert out.exit_code == 0 and token not in out.output
    shown = invoke("findings", "show", finding_id[:8], "--data-dir", str(data_dir)).output
    assert token not in shown and "[REDACTED]" in shown
