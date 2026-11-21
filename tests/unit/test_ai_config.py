"""M4: the one small file that switches the model on. It holds no secret, is private, and is read as strictly as a scope."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from scopedagent.ai.config import CONFIG_NAME, AiConfig, AiLimits, config_path, default_config, load_config, save_config
from scopedagent.errors import AiError, ErrorCode

pytestmark = pytest.mark.milestone("M4")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "data"
    path.mkdir(mode=0o700)
    return path


def write_raw(root: Path, data: Any, mode: int = 0o600) -> Path:
    path = config_path(root)
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    path.chmod(mode)
    return path


def test_no_file_means_the_model_is_off(root: Path) -> None:
    assert load_config(root) is None
    assert config_path(root) == root / CONFIG_NAME == root / "ai.json"


def test_the_defaults_for_each_provider() -> None:
    claude = default_config("anthropic")
    assert (claude.enabled, claude.provider, claude.model, claude.key_env, claude.mask_hosts) == (
        True,
        "anthropic",
        "claude-opus-5-5",
        "ANTHROPIC_API_KEY",
        True,
    )
    assert (claude.limits.max_calls_per_run, claude.limits.max_output_tokens, claude.limits.max_total_tokens) == (
        25,
        2048,
        60000,
    )
    offline = default_config("offline")
    assert (offline.provider, offline.model, offline.enabled) == ("offline", "offline-fixture", True)


def test_a_saved_configuration_round_trips_and_is_private(root: Path) -> None:
    config = default_config("anthropic").model_copy(update={"model": "claude-haiku-5-5", "mask_hosts": False})
    save_config(root, config)
    assert load_config(root) == config
    assert stat.S_IMODE(config_path(root).stat().st_mode) == 0o600
    assert [p.name for p in root.iterdir()] == ["ai.json"]  # no temporary file is left


def test_saving_replaces_the_file_atomically_and_keeps_it_private(root: Path) -> None:
    save_config(root, default_config("offline"))
    save_config(root, default_config("anthropic"))
    assert load_config(root) == default_config("anthropic")
    assert stat.S_IMODE(config_path(root).stat().st_mode) == 0o600


def test_the_file_never_holds_a_key(root: Path) -> None:
    save_config(root, default_config("anthropic"))
    text = config_path(root).read_text()
    assert "sk-ant" not in text and "api_key" not in text.replace("key_env", "")
    assert set(json.loads(text)) == {"version", "enabled", "provider", "model", "key_env", "mask_hosts", "limits"}


@pytest.mark.parametrize(
    "bad",
    [
        {"extra": 1},
        {"provider": "openai"},
        {"model": "bad model"},
        {"model": ""},
        {"model": "x" * 65},
        {"model": "Claude"},
        {"key_env": "lower_case"},
        {"key_env": "A"},
        {"key_env": "HAS SPACE"},
        {"key_env": "X" * 65},
        {"enabled": "yes"},
        {"mask_hosts": 1},
        {"version": 2},
        {"limits": {"max_calls_per_run": 0}},
        {"limits": {"max_calls_per_run": 201}},
        {"limits": {"max_output_tokens": 255}},
        {"limits": {"max_output_tokens": 8193}},
        {"limits": {"max_total_tokens": 999}},
        {"limits": {"max_total_tokens": 500001}},
        {"limits": {"surprise": 1}},
    ],
)
def test_a_configuration_outside_the_schema_is_refused(bad: dict[str, Any]) -> None:
    data = json.loads(default_config("anthropic").model_dump_json())
    data.update(bad)
    with pytest.raises(ValidationError):
        AiConfig.model_validate(data)


def test_the_limit_edges_are_accepted() -> None:
    assert AiLimits(max_calls_per_run=1, max_output_tokens=256, max_total_tokens=1000)
    assert AiLimits(max_calls_per_run=200, max_output_tokens=8192, max_total_tokens=500000)


@pytest.mark.parametrize("text", ["", "not json", "[]", "null", '{"enabled": true}', "{" * 50])
def test_an_unreadable_file_is_refused_with_its_code_and_never_read_as_enabled(root: Path, text: str) -> None:
    write_raw(root, text)
    with pytest.raises(AiError) as caught:
        load_config(root)
    assert caught.value.code is ErrorCode.AI_001


def test_a_file_that_others_can_read_or_write_is_refused_not_fixed(root: Path) -> None:
    save_config(root, default_config("offline"))
    config_path(root).chmod(0o644)
    with pytest.raises(AiError) as caught:
        load_config(root)
    assert caught.value.code is ErrorCode.AI_001 and "accessible to other users" in str(caught.value)
    assert stat.S_IMODE(config_path(root).stat().st_mode) == 0o644  # not silently changed


def test_a_symbolic_link_is_refused(root: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text(default_config("offline").model_dump_json())
    target.chmod(0o600)
    config_path(root).symlink_to(target)
    with pytest.raises(AiError, match="symbolic link"):  # named as a link, not merely "not a regular file"
        load_config(root)
    with pytest.raises(AiError, match="symbolic link"):
        save_config(root, default_config("offline"))
    assert json.loads(target.read_text())["provider"] == "offline" and config_path(root).is_symlink()


def test_a_file_owned_by_another_user_is_refused(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    save_config(root, default_config("offline"))
    monkeypatch.setattr(os, "getuid", lambda: config_path(root).stat().st_uid + 1)
    with pytest.raises(AiError) as caught:
        load_config(root)
    assert "another user" in str(caught.value)


def test_a_directory_instead_of_a_file_is_refused(root: Path) -> None:
    config_path(root).mkdir()
    with pytest.raises(AiError):
        load_config(root)


def test_a_file_over_16_kib_is_refused_without_being_parsed(root: Path) -> None:
    write_raw(root, "{" + " " * 20_000 + "}")
    with pytest.raises(AiError) as caught:
        load_config(root)
    assert "too large" in str(caught.value)


def test_the_message_never_echoes_the_files_text(root: Path) -> None:
    write_raw(root, '{"model": "SYNTHETIC-SECRET-0001"}')
    with pytest.raises(AiError) as caught:
        load_config(root)
    assert "SYNTHETIC-SECRET-0001" not in str(caught.value)


def test_a_file_that_cannot_be_inspected_is_refused_and_not_read_as_off(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(self: Path) -> os.stat_result:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "lstat", denied)
    with pytest.raises(AiError) as caught:
        load_config(root)
    assert caught.value.code is ErrorCode.AI_001 and "could not be read" in str(caught.value)


def test_a_file_that_cannot_be_read_is_refused(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    save_config(root, default_config("offline"))

    def denied(self: Path) -> bytes:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_bytes", denied)
    with pytest.raises(AiError) as caught:
        load_config(root)
    assert caught.value.code is ErrorCode.AI_001 and "could not be read" in str(caught.value)


def test_a_write_that_fails_leaves_no_temporary_file_and_the_old_file_untouched(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_config(root, default_config("offline"))
    before = config_path(root).read_text()

    def failing(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", failing)
    with pytest.raises(AiError) as caught:
        save_config(root, default_config("anthropic"))
    assert caught.value.code is ErrorCode.AI_001 and "could not be written" in str(caught.value)
    assert config_path(root).read_text() == before
    assert sorted(p.name for p in root.iterdir()) == [CONFIG_NAME]
