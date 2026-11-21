"""M4: switching the model on and using it from the command line. Off by default, one command to enable, never a connection from `run`."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from scopedagent import cli as cli_module
from scopedagent.ai.config import config_path, default_config, load_config, save_config
from scopedagent.ai.protocol import ModelUnavailable, RewordReply, RewordRequest
from scopedagent.cli import AppContext, app
from scopedagent.storage.database import DataDir
from tests.support import FIXTURES, NOW, SCOPE_FILES

pytestmark = pytest.mark.milestone("M4")

runner = CliRunner()
CTX = AppContext(clock=lambda: NOW, user=lambda: "alice")
KEY = "sk-ant-api03-SYNTHETIC-KEY-0001"


def invoke(*args: str, input: str | None = None) -> Any:
    return runner.invoke(app, list(args), obj=CTX, input=input)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    path = tmp_path / "data"
    assert invoke("db", "upgrade", "--data-dir", str(path)).exit_code == 0
    return path


def collect(data_dir: Path, name: str = "misconfigured") -> str:
    out = invoke(
        "run",
        "--scope",
        str(SCOPE_FILES[name]),
        "--fixture",
        str(FIXTURES / "web_responses" / f"{name}.yaml"),
        "--data-dir",
        str(data_dir),
    )
    return next(line.split()[1] for line in out.output.splitlines() if line.startswith("run "))


class Fake:
    provider, model = "fake", "fake-model"

    def __init__(self, fail: ModelUnavailable | None = None) -> None:
        self.fail, self.requests = fail, []  # type: ignore[var-annotated]

    def reword(self, request: RewordRequest) -> RewordReply:
        self.requests.append(request)
        if self.fail:
            raise self.fail
        return RewordReply({i.id: "Put simply: " + i.text for i in request.items}, 30, 20)


# -------------------------------------------------------------------------------------------------- off by default ----
def test_the_model_is_off_until_it_is_enabled(data_dir: Path) -> None:
    out = invoke("ai", "status", "--data-dir", str(data_dir))
    assert out.exit_code == 0 and "AI wording: off" in out.output and "scoped-agent ai enable" in out.output
    assert not config_path(DataDir(data_dir).root).exists()


def test_reword_says_how_to_turn_it_on_when_it_is_off(data_dir: Path) -> None:
    run_id = collect(data_dir)
    out = invoke("findings", "reword", run_id, "--data-dir", str(data_dir))
    assert (
        out.exit_code == 1
        and "AI-002" in out.output
        and "scoped-agent ai enable" in out.output
        and "Traceback" not in out.output
    )


def test_run_says_nothing_about_the_model_while_it_is_off(data_dir: Path) -> None:
    out = invoke(
        "run",
        "--scope",
        str(SCOPE_FILES["misconfigured"]),
        "--fixture",
        str(FIXTURES / "web_responses" / "misconfigured.yaml"),
        "--data-dir",
        str(data_dir),
    )
    assert "AI wording" not in out.output


# ---------------------------------------------------------------------------------------------------- enabling ----
def test_the_offline_provider_is_enabled_in_one_command_with_no_question(data_dir: Path) -> None:
    out = invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    assert out.exit_code == 0, out.output
    assert "AI wording is on (offline, offline-fixture)" in out.output and "no connection is made" in out.output
    config = load_config(DataDir(data_dir).root)
    assert config is not None and (config.enabled, config.provider) == (True, "offline")
    assert stat.S_IMODE(config_path(DataDir(data_dir).root).stat().st_mode) == 0o600


def test_enabling_the_claude_provider_names_what_is_sent_and_asks_for_the_word_enable(data_dir: Path) -> None:
    out = invoke("ai", "enable", "--data-dir", str(data_dir), input="enable\n")
    assert out.exit_code == 0, out.output
    for phrase in (
        "rule text only",
        "api.anthropic.com",
        "placeholders",
        "never sends what a target said",
        "claude-opus-5-5",
    ):
        assert phrase in out.output, phrase
    config = load_config(DataDir(data_dir).root)
    assert config is not None and (config.provider, config.model, config.key_env, config.mask_hosts) == (
        "anthropic",
        "claude-opus-5-5",
        "ANTHROPIC_API_KEY",
        True,
    )


@pytest.mark.parametrize("typed", ["", "yes", "ENABLE", "enabl", "no"])
def test_any_other_answer_changes_nothing(data_dir: Path, typed: str) -> None:
    out = invoke("ai", "enable", "--data-dir", str(data_dir), input=typed + "\n")
    assert out.exit_code == 1 and "nothing was changed" in out.output
    assert not config_path(DataDir(data_dir).root).exists()


def test_yes_skips_the_question_and_the_options_are_kept(data_dir: Path) -> None:
    out = invoke(
        "ai",
        "enable",
        "--yes",
        "--model",
        "claude-haiku-5-5",
        "--key-env",
        "MY_KEY",
        "--no-mask-hosts",
        "--data-dir",
        str(data_dir),
    )
    assert out.exit_code == 0, out.output
    config = load_config(DataDir(data_dir).root)
    assert config is not None and (config.model, config.key_env, config.mask_hosts) == (
        "claude-haiku-5-5",
        "MY_KEY",
        False,
    )
    assert "host names are sent as they are" in out.output


@pytest.mark.parametrize("args", [["--model", "bad model"], ["--key-env", "lower"], ["--provider", "openai"]])
def test_a_bad_option_is_refused_and_writes_nothing(data_dir: Path, args: list[str]) -> None:
    out = invoke("ai", "enable", "--yes", *args, "--data-dir", str(data_dir))
    assert out.exit_code in (1, 2) and "Traceback" not in out.output
    assert not config_path(DataDir(data_dir).root).exists()


def test_a_missing_key_is_said_at_once_and_does_not_stop_the_enabling(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = invoke("ai", "enable", "--yes", "--data-dir", str(data_dir))
    assert (
        out.exit_code == 0 and "ANTHROPIC_API_KEY is not set" in out.output and "export ANTHROPIC_API_KEY" in out.output
    )


def test_a_key_that_is_set_is_acknowledged_without_ever_being_shown(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    enable = invoke("ai", "enable", "--yes", "--data-dir", str(data_dir))
    status = invoke("ai", "status", "--data-dir", str(data_dir))
    assert "ANTHROPIC_API_KEY is set" in enable.output and "ANTHROPIC_API_KEY is set" in status.output
    assert KEY not in enable.output + status.output and KEY not in config_path(DataDir(data_dir).root).read_text()


def test_status_shows_the_provider_model_limits_and_what_is_sent(data_dir: Path) -> None:
    invoke("ai", "enable", "--yes", "--data-dir", str(data_dir))
    out = invoke("ai", "status", "--data-dir", str(data_dir)).output
    for phrase in (
        "AI wording: on",
        "provider: anthropic",
        "model: claude-opus-5-5",
        "hosts masked: yes",
        "25 calls per run",
        "2048 output tokens per call",
        "60000 tokens per run",
        "rule sentences only",
    ):
        assert phrase in out, phrase


def test_disabling_keeps_the_file_and_the_saved_wordings_and_turns_the_model_off(data_dir: Path) -> None:
    invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    run_id = collect(data_dir)
    assert invoke("findings", "reword", run_id, "--data-dir", str(data_dir)).exit_code == 0
    out = invoke("ai", "disable", "--data-dir", str(data_dir))
    assert out.exit_code == 0 and "AI wording is off" in out.output and "saved wordings stay" in out.output
    config = load_config(DataDir(data_dir).root)
    assert config is not None and config.enabled is False
    assert "AI wording: off" in invoke("ai", "status", "--data-dir", str(data_dir)).output
    assert invoke("findings", "reword", run_id, "--data-dir", str(data_dir)).exit_code == 1
    ids = [
        line.split()[0]
        for line in invoke("findings", "list", run_id, "--data-dir", str(data_dir)).output.splitlines()[1:9]
    ]
    assert "Put simply:" in invoke("findings", "show", ids[0], "--data-dir", str(data_dir)).output


def test_disabling_when_it_was_never_on_is_harmless(data_dir: Path) -> None:
    out = invoke("ai", "disable", "--data-dir", str(data_dir))
    assert out.exit_code == 0 and "was not on" in out.output


# -------------------------------------------------------------------------------------------------- the use of it ----
def test_reword_with_the_offline_provider_reports_what_it_did(data_dir: Path) -> None:
    invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    run_id = collect(data_dir)
    out = invoke("findings", "reword", run_id, "--data-dir", str(data_dir))
    assert out.exit_code == 0, out.output
    assert "reworded" in out.output and "in 8 findings" in out.output and "offline-fixture" in out.output
    assert "calls: 8 ok" in out.output and "tokens: 0" in out.output
    again = invoke("findings", "reword", run_id, "--data-dir", str(data_dir))
    assert again.exit_code == 0 and "reworded 0 sentences" in again.output and "calls: 0" in again.output


def test_show_prints_the_rule_text_first_and_the_wording_labelled_below_it(data_dir: Path) -> None:
    invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    run_id = collect(data_dir)
    invoke("findings", "reword", run_id, "--data-dir", str(data_dir))
    first = invoke("findings", "list", run_id, "--data-dir", str(data_dir)).output.splitlines()[1].split()[0]
    out = invoke("findings", "show", first, "--data-dir", str(data_dir)).output
    assert out.index("conditions:") < out.index(
        "wording by a model (not verified; the rule's text above is authoritative):"
    )
    assert "  - condition 1: Put simply: The service negotiated TLSv1.0" in out
    assert "  - remediation: Put simply: " in out and "  - severity basis: Put simply: " in out


def test_a_report_carries_the_wordings_only_after_a_reword(data_dir: Path, tmp_path: Path) -> None:
    invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    run_id = collect(data_dir)
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    invoke("report", "export", run_id, "--format", "json", "--output", str(before), "--data-dir", str(data_dir))
    invoke("findings", "reword", run_id, "--data-dir", str(data_dir))
    invoke("report", "export", run_id, "--format", "json", "--output", str(after), "--data-dir", str(data_dir))
    assert all("wordings" not in f for f in json.loads(before.read_text())["findings"])
    assert all(f["wordings"] for f in json.loads(after.read_text())["findings"])


def test_one_finding_can_be_reworded_by_its_id(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    run_id = collect(data_dir)
    first = invoke("findings", "list", run_id, "--data-dir", str(data_dir)).output.splitlines()[1].split()[0]
    out = invoke("findings", "reword", run_id, "--finding", first, "--data-dir", str(data_dir))
    assert out.exit_code == 0 and "in 1 finding" in out.output and "calls: 1 ok" in out.output


def test_when_every_call_fails_the_rule_text_stands_and_the_exit_code_says_so(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_config(DataDir(data_dir).root, default_config("anthropic"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    fake = Fake(ModelUnavailable("unavailable", "RateLimitError"))
    monkeypatch.setattr(cli_module, "build_adapter", lambda config, environ: fake)
    run_id = collect(data_dir)
    out = invoke("findings", "reword", run_id, "--data-dir", str(data_dir))
    assert out.exit_code == 2 and "reworded 0 sentences" in out.output and "calls: 8 unavailable" in out.output
    assert "the rule's own sentences are what every draft shows" in out.output and KEY not in out.output


def test_a_missing_key_stops_the_command_before_any_call(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    save_config(DataDir(data_dir).root, default_config("anthropic"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    fake = Fake()
    monkeypatch.setattr(cli_module, "build_adapter", lambda config, environ: fake)
    run_id = collect(data_dir)
    out = invoke("findings", "reword", run_id, "--data-dir", str(data_dir))
    assert (
        out.exit_code == 1
        and "AI-002" in out.output
        and "ANTHROPIC_API_KEY is not set" in out.output
        and fake.requests == []
    )


def test_an_unknown_run_is_refused_before_any_call(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    fake = Fake()
    monkeypatch.setattr(cli_module, "build_adapter", lambda config, environ: fake)
    out = invoke("findings", "reword", "no-such-run", "--data-dir", str(data_dir))
    assert out.exit_code == 1 and "POLICY-002" in out.output and fake.requests == []


def test_the_key_is_given_to_the_adapter_factory_only_through_the_environment(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_config(DataDir(data_dir).root, default_config("anthropic").model_copy(update={"key_env": "MY_OWN_KEY"}))
    monkeypatch.setenv("MY_OWN_KEY", KEY)
    seen: dict[str, Any] = {}

    def factory(config: Any, environ: Any) -> Fake:
        seen["key"] = environ.get(config.key_env)
        return Fake()

    monkeypatch.setattr(cli_module, "build_adapter", factory)
    run_id = collect(data_dir)
    assert invoke("findings", "reword", run_id, "--data-dir", str(data_dir)).exit_code == 0
    assert seen["key"] == KEY


# ----------------------------------------------------------------------------------------------------- ai test ----
def test_the_test_command_works_offline(data_dir: Path) -> None:
    invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    out = invoke("ai", "test", "--data-dir", str(data_dir))
    assert (
        out.exit_code == 0 and "accepted" in out.output and "Put simply: The certificate is self-signed" in out.output
    )


def test_the_test_command_reports_a_failure_without_a_traceback(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_config(DataDir(data_dir).root, default_config("anthropic"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    monkeypatch.setattr(
        cli_module, "build_adapter", lambda config, environ: Fake(ModelUnavailable("refused", "refusal"))
    )
    out = invoke("ai", "test", "--data-dir", str(data_dir))
    assert out.exit_code == 1 and "refused" in out.output and "Traceback" not in out.output and KEY not in out.output


def test_the_test_command_refuses_when_the_model_is_off(data_dir: Path) -> None:
    out = invoke("ai", "test", "--data-dir", str(data_dir))
    assert out.exit_code == 1 and "AI-002" in out.output


def test_the_test_command_rejects_a_reply_that_fails_the_checks(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_config(DataDir(data_dir).root, default_config("anthropic"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)

    class Wrong(Fake):
        def reword(self, request: RewordRequest) -> RewordReply:
            return RewordReply({i.id: "A different sentence with 99 in it." for i in request.items}, 1, 1)

    monkeypatch.setattr(cli_module, "build_adapter", lambda config, environ: Wrong())
    out = invoke("ai", "test", "--data-dir", str(data_dir))
    assert out.exit_code == 1 and "rejected" in out.output


# ------------------------------------------------------------------------------------------- `run` stays closed ----
def test_run_hints_at_the_command_when_the_model_is_on_and_never_calls_it(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))

    def boom(config: Any, environ: Any) -> Any:
        raise AssertionError("run must never build a model adapter")

    monkeypatch.setattr(cli_module, "build_adapter", boom)
    out = invoke(
        "run",
        "--scope",
        str(SCOPE_FILES["misconfigured"]),
        "--fixture",
        str(FIXTURES / "web_responses" / "misconfigured.yaml"),
        "--data-dir",
        str(data_dir),
    )
    assert out.exit_code == 3 and "AI wording is on: run `scoped-agent findings reword" in out.output


def test_run_says_nothing_about_the_model_when_it_has_no_drafts(data_dir: Path) -> None:
    invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    out = invoke(
        "run",
        "--scope",
        str(SCOPE_FILES["healthy"]),
        "--fixture",
        str(FIXTURES / "web_responses" / "healthy.yaml"),
        "--data-dir",
        str(data_dir),
    )
    assert out.exit_code == 0 and "AI wording" not in out.output


def test_a_broken_configuration_is_refused_by_every_ai_command_and_run_still_works(data_dir: Path) -> None:
    path = config_path(DataDir(data_dir).root)
    path.write_text("not json")
    path.chmod(0o600)
    for args in (["ai", "status"], ["ai", "test"], ["ai", "disable"]):
        out = invoke(*args, "--data-dir", str(data_dir))
        assert out.exit_code == 1 and "AI-001" in out.output and "Traceback" not in out.output
    run = invoke(
        "run",
        "--scope",
        str(SCOPE_FILES["healthy"]),
        "--fixture",
        str(FIXTURES / "web_responses" / "healthy.yaml"),
        "--data-dir",
        str(data_dir),
    )
    assert run.exit_code == 0 and "AI-001" not in run.output


def test_a_broken_configuration_does_not_stop_a_run_that_has_drafts(data_dir: Path) -> None:
    path = config_path(DataDir(data_dir).root)
    path.write_text("not json")
    path.chmod(0o600)
    out = invoke(
        "run",
        "--scope",
        str(SCOPE_FILES["misconfigured"]),
        "--fixture",
        str(FIXTURES / "web_responses" / "misconfigured.yaml"),
        "--data-dir",
        str(data_dir),
    )
    assert out.exit_code == 3 and "AI-001" not in out.output and "AI wording" not in out.output


def test_the_status_of_the_offline_provider_asks_for_no_key(data_dir: Path) -> None:
    invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    out = invoke("ai", "status", "--data-dir", str(data_dir)).output
    assert "provider: offline" in out and "key:" not in out and "hosts masked: yes" in out


def test_enabling_does_not_replace_a_broken_configuration_it_refuses_and_leaves_it_alone(data_dir: Path) -> None:
    path = config_path(DataDir(data_dir).root)
    path.write_text("not json")
    path.chmod(0o600)
    out = invoke("ai", "enable", "--provider", "offline", "--data-dir", str(data_dir))
    assert out.exit_code == 1 and "AI-001" in out.output and "Traceback" not in out.output
    assert path.read_text() == "not json"
    path.chmod(0o644)  # an unsafe mode is refused too, and not repaired by enabling
    out = invoke("ai", "enable", "--yes", "--data-dir", str(data_dir))
    assert out.exit_code == 1 and "AI-001" in out.output and path.read_text() == "not json"


def sent_text(fake: Fake) -> str:
    return "\n".join(item.text for request in fake.requests for item in request.items)


def test_the_hosts_of_the_scope_are_masked_before_anything_is_sent_and_put_back_after(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_config(DataDir(data_dir).root, default_config("anthropic"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    fake = Fake()
    monkeypatch.setattr(cli_module, "build_adapter", lambda config, environ: fake)
    run_id = collect(data_dir)
    assert invoke("findings", "reword", run_id, "--data-dir", str(data_dir)).exit_code == 0
    assert "bad.example.invalid" not in sent_text(fake) and "HOST_A" in sent_text(fake)
    first = invoke("findings", "list", run_id, "--data-dir", str(data_dir)).output.splitlines()[1].split()[0]
    shown = invoke("findings", "show", first, "--data-dir", str(data_dir)).output
    assert "HOST_A" not in shown and "Put simply: The certificate's names do not cover bad.example.invalid." in shown


def test_the_hosts_to_mask_are_those_of_the_web_and_the_ai_targets_of_the_stored_scope() -> None:
    import yaml  # noqa: PLC0415

    from scopedagent.policy.scope import parse_scope  # noqa: PLC0415

    # no current rule names an AI target's host in a sentence, so this guards the helper itself rather than a visible effect
    web = parse_scope(SCOPE_FILES["misconfigured"].read_text(), now=NOW)
    ai = parse_scope(SCOPE_FILES["ai-support-bot"].read_text(), now=NOW)
    assert cli_module._scope_hosts(web.canonical_json) == ["bad.example.invalid"]
    assert cli_module._scope_hosts(ai.canonical_json) == ["assistant.example.invalid"]
    data = yaml.safe_load(SCOPE_FILES["ai-support-bot"].read_text())
    data["allowed_targets"] = yaml.safe_load(SCOPE_FILES["misconfigured"].read_text())["allowed_targets"]
    data["allowed_operations"] = ["dns_metadata", "ai_metadata", "ai_probe"]
    both = parse_scope(yaml.safe_dump(data), now=NOW)
    assert cli_module._scope_hosts(both.canonical_json) == ["bad.example.invalid", "assistant.example.invalid"]


def test_with_masking_off_the_host_is_sent_as_it_is(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    save_config(DataDir(data_dir).root, default_config("anthropic").model_copy(update={"mask_hosts": False}))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    fake = Fake()
    monkeypatch.setattr(cli_module, "build_adapter", lambda config, environ: fake)
    run_id = collect(data_dir)
    assert invoke("findings", "reword", run_id, "--data-dir", str(data_dir)).exit_code == 0
    assert "bad.example.invalid" in sent_text(fake) and "HOST_A" not in sent_text(fake)


def test_a_wording_that_contains_the_key_is_dropped_by_the_command_and_never_stored_or_shown(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_config(DataDir(data_dir).root, default_config("anthropic"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)

    class Leaky(Fake):
        def reword(self, request: RewordRequest) -> RewordReply:
            return RewordReply({i.id: i.text + " " + KEY for i in request.items}, 5, 5)

    monkeypatch.setattr(cli_module, "build_adapter", lambda config, environ: Leaky())
    run_id = collect(data_dir)
    out = invoke("findings", "reword", run_id, "--data-dir", str(data_dir))
    assert out.exit_code == 0 and "reworded 0 sentences" in out.output and KEY not in out.output
    assert "kept as the rule wrote them: 77" in out.output
    first = invoke("findings", "list", run_id, "--data-dir", str(data_dir)).output.splitlines()[1].split()[0]
    assert KEY not in invoke("findings", "show", first, "--data-dir", str(data_dir)).output
