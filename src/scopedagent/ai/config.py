"""The configuration that switches the model on: one small private file with no secret in it (docs/ai-adapter.md).

It is read as strictly as a scope: a size cap, no links, owned by the user, closed to others, a closed schema. A file
that is not right is refused with a code and is never read as "enabled".
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from scopedagent.errors import AiError, ErrorCode

CONFIG_NAME = "ai.json"
MAX_CONFIG_BYTES = 16 * 1024
Provider = Literal["anthropic", "offline"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


class AiLimits(_Model):
    max_calls_per_run: Annotated[int, Field(ge=1, le=200)] = 25
    max_output_tokens: Annotated[int, Field(ge=256, le=8192)] = 2048
    max_total_tokens: Annotated[int, Field(ge=1000, le=500_000)] = 60_000


class AiConfig(_Model):
    version: Literal[1] = 1
    enabled: bool
    provider: Provider
    model: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
    key_env: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{1,63}$")]
    mask_hosts: bool = True
    limits: AiLimits = AiLimits()


def config_path(root: Path) -> Path:
    return root / CONFIG_NAME


def default_config(provider: Provider) -> AiConfig:
    model = "claude-opus-5-5" if provider == "anthropic" else "offline-fixture"
    return AiConfig(enabled=True, provider=provider, model=model, key_env="ANTHROPIC_API_KEY")


def _refuse(message: str) -> AiError:
    return AiError(ErrorCode.AI_001, message)


def load_config(root: Path) -> AiConfig | None:
    """The configuration, or None when there is none (the model is off). An unsafe or invalid file raises `AiError`."""
    path = config_path(root)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise _refuse("the AI configuration could not be read") from None
    if stat.S_ISLNK(info.st_mode):
        raise _refuse("the AI configuration is a symbolic link")
    if not stat.S_ISREG(info.st_mode):
        raise _refuse("the AI configuration is not a regular file")
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise _refuse(f"the AI configuration is accessible to other users (mode {mode:o}); run: chmod 600 on it")
    if info.st_uid != os.getuid():
        raise _refuse("the AI configuration is owned by another user")
    if info.st_size > MAX_CONFIG_BYTES:
        raise _refuse("the AI configuration is too large")
    try:
        return AiConfig.model_validate_json(path.read_bytes())
    except ValidationError as exc:
        fields = ", ".join(sorted({".".join(str(p) for p in e["loc"]) or "the file" for e in exc.errors()}))
        raise _refuse(f"the AI configuration is not valid (check: {fields[:200]})") from None
    except OSError:
        raise _refuse("the AI configuration could not be read") from None


def save_config(root: Path, config: AiConfig) -> None:
    """Write the configuration atomically with mode 0600. Never follows a link and never leaves a temporary file."""
    path = config_path(root)
    if path.is_symlink():
        raise _refuse("the AI configuration is a symbolic link")
    descriptor, temporary = tempfile.mkstemp(prefix=".ai-", suffix=".tmp", dir=root)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(config.model_dump_json(indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except OSError:
        Path(temporary).unlink(missing_ok=True)
        raise _refuse("the AI configuration could not be written") from None
