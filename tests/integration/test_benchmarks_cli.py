"""D-E83 to D-E87: the benchmark commands, and the categories in `findings show` and in a report."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from scopedagent import cli as cli_module
from scopedagent.benchmarks.catalogue import STALE_AFTER_DAYS
from scopedagent.cli import AppContext, app
from tests.support import FIXTURES, NOW, SCOPE_FILES

pytestmark = pytest.mark.milestone("M7")

runner = CliRunner()


def invoke(*args: str, now: dt.datetime = NOW) -> Any:
    return runner.invoke(app, list(args), obj=AppContext(clock=lambda: now, user=lambda: "alice"))


@pytest.fixture
def run_id(tmp_path: Path) -> tuple[str, Path]:
    data = tmp_path / "data"
    assert invoke("db", "upgrade", "--data-dir", str(data)).exit_code == 0
    result = invoke(
        "run", "--scope", str(SCOPE_FILES["misconfigured"]),
        "--fixture", str(FIXTURES / "web_responses" / "misconfigured.yaml"), "--data-dir", str(data),
    )  # fmt: skip
    return next(line.split()[1] for line in result.output.splitlines() if line.startswith("run ")), data


# --------------------------------------------------------------------------------------------- the commands ----
def test_status_lists_each_edition_with_its_check_date_its_source_and_the_gaps() -> None:
    out = invoke("benchmarks", "status")
    assert out.exit_code == 0, out.output
    text = out.output
    assert "OWASP Top 10 2025   checked 2026-11-22 (0 days ago)" in text
    assert "source: https://owasp.org/Top10/2025/" in text
    assert "OWASP API Security Top 10 2023" in text and "OWASP Top 10 for LLM Applications 2026" in text
    assert "A04    Cryptographic Failures" in text and "R-TLS-01, R-REDIR-01" in text
    assert "A05    Injection" in text and "no rule yet" in text
    assert "3 of 10 categories have a rule" in text  # the web Top 10: A02, A04 and A07
    assert "2 of 10 categories have a rule" in text  # the API list: API8 and API9
    assert "4 of 10 categories have a rule" in text  # the LLM list
    assert "never a verdict" in text and "may be out of date" not in text


def test_status_says_so_when_a_benchmark_has_not_been_checked_for_longer_than_the_limit() -> None:
    later = NOW + dt.timedelta(days=STALE_AFTER_DAYS + 12)  # NOW is 2026-11-20: two days before the data was checked
    out = invoke("benchmarks", "status", now=later)
    assert out.exit_code == 0
    assert "not checked against its source for" in out.output and "docs/benchmarks.md" in out.output
    assert "3 benchmark(s) may be out of date" in out.output
    on_limit = dt.datetime(2026, 11, 22, tzinfo=dt.UTC) + dt.timedelta(days=STALE_AFTER_DAYS)
    assert "may be out of date" not in invoke("benchmarks", "status", now=on_limit).output


def test_rules_lists_every_rule_with_its_categories_and_the_reason() -> None:
    out = invoke("benchmarks", "rules")
    assert out.exit_code == 0
    assert out.output.count("\n  OWASP") >= 15 and "R-AI-02  (ai_system_prompt_leakage)" in out.output
    assert "OWASP Top 10 for LLM Applications 2026: LLM08 Hidden Context Exposure" in out.output
    assert "closest category" in out.output


def test_a_catalogue_that_does_not_match_the_rules_stops_both_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "unmapped", lambda ids: ["R-NEW-01"])
    for command in ("status", "rules"):
        out = invoke("benchmarks", command)
        assert out.exit_code == 1 and "R-NEW-01 has no benchmark mapping" in out.output
    monkeypatch.setattr(cli_module, "unmapped", lambda ids: [])
    monkeypatch.setattr(cli_module, "unknown_rules", lambda ids: ["R-OLD-01"])
    out = invoke("benchmarks", "status")
    assert out.exit_code == 1 and "maps R-OLD-01, which is not a rule" in out.output


def test_a_broken_catalogue_file_stops_status(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> Any:
        raise cli_module.CatalogueError("the catalogue is not valid at rules: test")

    monkeypatch.setattr(cli_module, "catalogue", broken)
    out = invoke("benchmarks", "status")
    assert out.exit_code == 1 and "not valid at rules" in out.output


# -------------------------------------------------------------------------- findings show and the report ----
def test_findings_show_names_the_closest_categories_and_says_they_are_not_a_verdict(run_id: tuple[str, Path]) -> None:
    run, data = run_id
    listed = invoke("findings", "list", run, "--data-dir", str(data)).output
    cors = next(line.split()[0] for line in listed.splitlines() if "permissive_cors" in line)
    shown = invoke("findings", "show", cors, "--data-dir", str(data))
    assert shown.exit_code == 0
    assert (
        "benchmarks (closest categories, not a verdict): OWASP Top 10 2025: A02 Security Misconfiguration; "
        "OWASP API Security Top 10 2023: API8 Security Misconfiguration"
    ) in shown.output


def test_a_finding_of_a_rule_the_catalogue_no_longer_knows_shows_no_categories_and_still_shows(
    run_id: tuple[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A draft stored under a rule that was later renamed or removed: its categories are simply absent, never invented."""
    run, data = run_id
    monkeypatch.setattr(cli_module, "references_for", lambda rule_id: ())
    listed = invoke("findings", "list", run, "--data-dir", str(data)).output
    shown = invoke("findings", "show", listed.splitlines()[1].split()[0], "--data-dir", str(data))
    assert shown.exit_code == 0 and "rule: R-" in shown.output and "benchmarks (closest" not in shown.output


def test_a_json_report_carries_each_findings_categories_and_the_editions_used(
    run_id: tuple[str, Path], tmp_path: Path
) -> None:
    run, data = run_id
    out_file = tmp_path / "report.json"
    assert (
        invoke(
            "report", "export", run, "--format", "json", "--output", str(out_file), "--data-dir", str(data)
        ).exit_code
        == 0
    )
    report = json.loads(out_file.read_text())
    editions = {b["key"]: (b["edition"], b["checked_on"]) for b in report["benchmarks"]}
    assert editions == {
        "owasp-top10": ("2025", "2026-11-22"),
        "owasp-api-top10": ("2023", "2026-11-22"),
        "owasp-llm-top10": ("2026", "2026-11-22"),
    }
    by_rule = {
        f["details"]["rule_id"]: [(b["benchmark"], b["category"]) for b in f["benchmarks"]] for f in report["findings"]
    }
    assert by_rule["R-TLS-01"] == [("owasp-top10", "A04")]
    assert by_rule["R-CORS-01"] == [("owasp-top10", "A02"), ("owasp-api-top10", "API8")]
    assert all(f["benchmarks"] for f in report["findings"])


def test_a_markdown_report_shows_the_categories_and_a_benchmarks_section(
    run_id: tuple[str, Path], tmp_path: Path
) -> None:
    run, data = run_id
    out_file = tmp_path / "report.md"
    assert (
        invoke("report", "export", run, "--format", "md", "--output", str(out_file), "--data-dir", str(data)).exit_code
        == 0
    )
    text = out_file.read_text()
    assert "- benchmarks (closest categories, not a verdict): OWASP Top 10 2025: A04 Cryptographic Failures" in text
    assert "## Benchmarks" in text and "A category is not a diagnosis." in text
    assert (
        "OWASP Top 10 for LLM Applications 2026, checked 2026-11-22: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"
        in text
    )
    assert text.index("## Findings") < text.index("## Benchmarks") < text.index("## Audit trail")
