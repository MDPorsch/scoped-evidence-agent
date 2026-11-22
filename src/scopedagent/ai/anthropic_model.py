"""Claude through the official `anthropic` SDK: the only module that can reach a network (docs/ai-adapter.md).

The SDK is imported only when a call is made, so nothing else in the tool loads it. The base URL is fixed here: an
ANTHROPIC_BASE_URL in the environment cannot send the key elsewhere. The key is handed to the SDK client and nowhere
else; an error is reduced to its class name, so no message that could hold a key or a sentence is ever kept.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scopedagent.ai.prompt import RESPONSE_SCHEMA, SYSTEM_PROMPT, user_message
from scopedagent.ai.protocol import ModelUnavailable, RewordReply, RewordRequest
from scopedagent.ai.validation import parse_reply

ANTHROPIC_BASE_URL = "https://api.anthropic.com"
TIMEOUT_SECONDS = 60.0
INSTALL_HINT = "the anthropic package is not installed: pip install 'scoped-evidence-agent[ai]'"


def default_client(api_key: str) -> Any:
    import anthropic  # noqa: PLC0415

    return anthropic.Anthropic(api_key=api_key, base_url=ANTHROPIC_BASE_URL, timeout=TIMEOUT_SECONDS, max_retries=2)


class AnthropicModel:
    provider = "anthropic"

    def __init__(
        self,
        model: str,
        api_key: str,
        *,
        max_output_tokens: int = 2048,
        client_factory: Callable[[str], Any] = default_client,
    ) -> None:
        self.model = model
        self._key = api_key
        self._max = max_output_tokens
        self._factory = client_factory

    def __repr__(self) -> str:
        return f"AnthropicModel(model={self.model!r})"

    def reword(self, request: RewordRequest) -> RewordReply:
        if not self._key:
            raise ModelUnavailable("unavailable", "no API key: set the variable named in the configuration")
        try:
            client = self._factory(self._key)
        except ImportError:
            raise ModelUnavailable("unavailable", INSTALL_HINT) from None
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=self._max,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message(request)}],
                output_config={"effort": "low", "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}},
            )
        except Exception as exc:
            raise ModelUnavailable("unavailable", type(exc).__name__) from None
        if response.stop_reason == "refusal":
            raise ModelUnavailable("refused", "the model declined the request")
        if response.stop_reason == "max_tokens":
            raise ModelUnavailable("invalid", "the reply was cut off by the token limit")
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise ModelUnavailable("invalid", "the reply had no text")
        if self._key in text:
            raise ModelUnavailable("invalid", "the reply contained the key and was discarded")
        return RewordReply(
            parse_reply(text, request), int(response.usage.input_tokens), int(response.usage.output_tokens)
        )
