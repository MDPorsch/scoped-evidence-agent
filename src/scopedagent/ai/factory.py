"""From a configuration to an adapter. The key is looked up here, in the environment, and nowhere else."""

from __future__ import annotations

from collections.abc import Mapping

from scopedagent.ai.anthropic_model import AnthropicModel
from scopedagent.ai.config import AiConfig
from scopedagent.ai.offline import OfflineModel
from scopedagent.ai.protocol import ModelAdapter


def build_adapter(config: AiConfig, environ: Mapping[str, str]) -> ModelAdapter:
    if config.provider == "offline":
        return OfflineModel()
    return AnthropicModel(
        config.model, environ.get(config.key_env, ""), max_output_tokens=config.limits.max_output_tokens
    )
