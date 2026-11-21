"""M4: the two model adapters. The Claude one is driven through the real SDK with a mock transport: nothing leaves the process."""

from __future__ import annotations

import json
import sys
from typing import Any

import httpx2
import pytest

from scopedagent.ai.anthropic_model import ANTHROPIC_BASE_URL, AnthropicModel, default_client
from scopedagent.ai.offline import OfflineModel
from scopedagent.ai.prompt import PROMPT_VERSION, RESPONSE_SCHEMA, SYSTEM_PROMPT
from scopedagent.ai.protocol import ModelUnavailable, RewordItem, RewordRequest
from scopedagent.ai.validation import validate_item
from tests.support import finding_golden

pytestmark = pytest.mark.milestone("M4")

KEY = "sk-ant-api03-SYNTHETIC-KEY-0001"
SENTENCE = "The certificate is self-signed, so it cannot be chained to a trusted authority."


def req(*texts: str) -> RewordRequest:
    return RewordRequest(tuple(RewordItem(f"condition-{i}", t, 300) for i, t in enumerate(texts)), PROMPT_VERSION)


def message(text: str | None, *, stop: str = "end_turn", usage: tuple[int, int] = (11, 7)) -> dict[str, Any]:
    content = [] if text is None else [{"type": "text", "text": text}]
    return {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5-5",
        "content": content,
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": {"input_tokens": usage[0], "output_tokens": usage[1]},
    }


class Recorder:
    def __init__(self, respond: Any) -> None:
        self.requests: list[httpx2.Request] = []
        self.respond = respond

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return self.respond(request)  # type: ignore[no-any-return]


def model_for(recorder: Recorder, *, key: str = KEY, max_output_tokens: int = 2048) -> AnthropicModel:
    def factory(api_key: str) -> Any:
        import anthropic  # noqa: PLC0415

        return anthropic.Anthropic(
            api_key=api_key,
            base_url=ANTHROPIC_BASE_URL,
            http_client=httpx2.Client(transport=httpx2.MockTransport(recorder.handler)),
            max_retries=0,
        )

    return AnthropicModel("claude-opus-5-5", key, max_output_tokens=max_output_tokens, client_factory=factory)


def ok_reply(ids: list[str], texts: list[str]) -> Recorder:
    body = json.dumps({"items": [{"id": i, "text": t} for i, t in zip(ids, texts, strict=True)]})
    return Recorder(lambda _r: httpx2.Response(200, json=message(body)))


# ------------------------------------------------------------------------------------------------- the wire ----
def test_the_request_has_exactly_the_documented_shape() -> None:
    recorder = ok_reply(["condition-0"], ["Put simply: " + SENTENCE])
    reply = model_for(recorder).reword(req(SENTENCE))
    (sent,) = recorder.requests
    assert (sent.method, str(sent.url)) == ("POST", "https://api.anthropic.com/v1/messages")
    assert sent.headers["x-api-key"] == KEY and "anthropic-version" in sent.headers
    body = json.loads(sent.content)
    assert set(body) == {"model", "max_tokens", "system", "messages", "output_config"}
    assert body["model"] == "claude-opus-5-5" and body["max_tokens"] == 2048 and body["system"] == SYSTEM_PROMPT
    assert body["output_config"] == {"effort": "low", "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}}
    assert [m["role"] for m in body["messages"]] == ["user"]  # no prefill: the last turn is the user's
    assert json.loads(body["messages"][0]["content"]) == {
        "prompt_version": PROMPT_VERSION,
        "items": [{"id": "condition-0", "text": SENTENCE, "max_chars": 300}],
    }
    assert KEY not in sent.content.decode()
    assert reply.texts == {"condition-0": "Put simply: " + SENTENCE} and (reply.input_tokens, reply.output_tokens) == (
        11,
        7,
    )


def test_no_sampling_parameter_no_tool_and_no_thinking_setting_is_sent() -> None:
    recorder = ok_reply(["condition-0"], [SENTENCE])
    model_for(recorder).reword(req(SENTENCE))
    body = json.loads(recorder.requests[0].content)
    for banned in (
        "temperature",
        "top_p",
        "top_k",
        "tools",
        "tool_choice",
        "thinking",
        "stream",
        "metadata",
        "stop_sequences",
    ):
        assert banned not in body


def test_the_token_cap_is_the_one_configured() -> None:
    recorder = ok_reply(["condition-0"], [SENTENCE])
    model_for(recorder, max_output_tokens=777).reword(req(SENTENCE))
    assert json.loads(recorder.requests[0].content)["max_tokens"] == 777


def test_the_system_prompt_treats_the_sentences_as_data_and_forbids_what_the_checks_forbid() -> None:
    lowered = SYSTEM_PROMPT.lower()
    for phrase in ("data", "do not add", "every number", "json"):
        assert phrase in lowered
    assert PROMPT_VERSION == "reword-v1"
    assert RESPONSE_SCHEMA["additionalProperties"] is False and RESPONSE_SCHEMA["required"] == ["items"]


def test_the_default_client_goes_only_to_the_fixed_endpoint_whatever_the_environment_says(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://evil.invalid")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "other-token")
    client = default_client(KEY)
    assert str(client.base_url).startswith("https://api.anthropic.com")
    assert client.api_key == KEY and client.timeout == 60.0 and client.max_retries == 2
    assert client.auth_token is None  # a bearer token from the environment is never sent


def test_the_key_is_not_in_the_adapters_text_form() -> None:
    model = AnthropicModel("claude-opus-5-5", KEY)
    assert KEY not in repr(model) and KEY not in str(model) and KEY not in str(vars(model).get("model", ""))
    assert (model.provider, model.model) == ("anthropic", "claude-opus-5-5")


# ---------------------------------------------------------------------------------------------- the failures ----
def unavailable(recorder: Recorder, *, key: str = KEY) -> ModelUnavailable:
    with pytest.raises(ModelUnavailable) as caught:
        model_for(recorder, key=key).reword(req(SENTENCE))
    return caught.value


def test_a_refusal_is_recorded_as_a_refusal() -> None:
    error = unavailable(Recorder(lambda _r: httpx2.Response(200, json=message(None, stop="refusal"))))
    assert error.status == "refused"


def test_a_reply_cut_off_by_the_token_cap_is_invalid_even_if_what_arrived_looks_complete() -> None:
    whole = json.dumps({"items": [{"id": "condition-0", "text": "Put simply: " + SENTENCE}]})
    error = unavailable(Recorder(lambda _r: httpx2.Response(200, json=message(whole, stop="max_tokens"))))
    assert error.status == "invalid" and "token limit" in error.detail
    cut = unavailable(Recorder(lambda _r: httpx2.Response(200, json=message('{"items": [', stop="max_tokens"))))
    assert cut.status == "invalid" and "token limit" in cut.detail


def test_a_reply_with_no_text_is_invalid() -> None:
    assert unavailable(Recorder(lambda _r: httpx2.Response(200, json=message(None)))).status == "invalid"


@pytest.mark.parametrize(
    ("code", "name"),
    [(401, "AuthenticationError"), (429, "RateLimitError"), (500, "InternalServerError"), (400, "BadRequestError")],
)
def test_an_api_error_is_unavailable_and_names_only_the_error_class(code: int, name: str) -> None:
    body = {"type": "error", "error": {"type": "api_error", "message": f"detail mentioning {KEY} and a sentence"}}
    error = unavailable(Recorder(lambda _r: httpx2.Response(code, json=body)))
    assert error.status == "unavailable" and error.detail == name
    assert KEY not in str(error) and "sentence" not in str(error)


def test_a_connection_failure_is_unavailable() -> None:
    def boom(_r: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("could not connect to " + KEY)

    error = unavailable(Recorder(boom))
    assert error.status == "unavailable" and error.detail == "APIConnectionError" and KEY not in str(error)


def test_an_empty_key_is_unavailable_before_any_client_is_built() -> None:
    calls: list[str] = []

    def factory(api_key: str) -> Any:
        calls.append(api_key)
        raise AssertionError("no client may be built without a key")

    with pytest.raises(ModelUnavailable) as caught:
        AnthropicModel("claude-opus-5-5", "", client_factory=factory).reword(req(SENTENCE))
    assert caught.value.status == "unavailable" and "key" in caught.value.detail and calls == []


def test_a_missing_sdk_says_how_to_install_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "anthropic", None)
    with pytest.raises(ModelUnavailable) as caught:
        AnthropicModel("claude-opus-5-5", KEY).reword(req(SENTENCE))
    assert caught.value.status == "unavailable" and "scoped-evidence-agent[ai]" in caught.value.detail


def test_a_reply_that_is_valid_json_of_the_wrong_shape_is_invalid() -> None:
    error = unavailable(
        Recorder(lambda _r: httpx2.Response(200, json=message('{"items": [{"id": "other", "text": "x"}]}')))
    )
    assert error.status == "invalid"


def test_a_reply_that_echoes_the_key_is_refused_as_a_whole() -> None:
    body = json.dumps(
        {"items": [{"id": "condition-0", "text": "Put simply: " + SENTENCE + " " + KEY}]}
    )  # a perfect shape
    error = unavailable(Recorder(lambda _r: httpx2.Response(200, json=message(body))))
    assert error.status == "invalid" and "key" in error.detail and KEY not in str(error)
    extra = json.dumps({"items": [{"id": "condition-0", "text": "Put simply: " + SENTENCE}], "note": KEY})
    assert unavailable(Recorder(lambda _r: httpx2.Response(200, json=message(extra)))).status == "invalid"


# --------------------------------------------------------------------------------------------- the offline model ----
def test_the_offline_model_is_deterministic_and_opens_nothing() -> None:
    model = OfflineModel()
    first, second = model.reword(req("One.", "Two.")), model.reword(req("One.", "Two."))
    assert first == second
    assert first.texts == {"condition-0": "Put simply: One.", "condition-1": "Put simply: Two."}
    assert (first.input_tokens, first.output_tokens) == (0, 0) and (model.provider, model.model) == (
        "offline",
        "offline-fixture",
    )


def test_the_offline_model_leaves_a_sentence_alone_when_its_prefix_would_not_fit() -> None:
    long = "a" * 295
    request = RewordRequest((RewordItem("condition-0", long, 300),), PROMPT_VERSION)
    assert OfflineModel().reword(request).texts == {"condition-0": long}


def test_the_offline_model_passes_the_checks_on_every_condition_of_every_golden_draft() -> None:
    checked = 0
    for name in ("misconfigured", "poisoned", "ai-support-bot"):
        for draft in finding_golden(name):
            for sentence in draft["conditions"]:
                request = RewordRequest((RewordItem("condition-0", sentence, 300),), PROMPT_VERSION)
                text = OfflineModel().reword(request).texts["condition-0"]
                assert validate_item(sentence, text, limit=300) is None, sentence
                checked += 1
    assert checked >= 20


# ------------------------------------------------------------------------------------------------- the factory ----
def test_the_factory_builds_the_offline_model_without_looking_for_a_key() -> None:
    from scopedagent.ai.config import default_config  # noqa: PLC0415
    from scopedagent.ai.factory import build_adapter  # noqa: PLC0415

    assert isinstance(build_adapter(default_config("offline"), {}), OfflineModel)


def test_the_factory_takes_the_key_from_the_named_variable_only() -> None:
    from scopedagent.ai.config import AiLimits, default_config  # noqa: PLC0415
    from scopedagent.ai.factory import build_adapter  # noqa: PLC0415

    config = default_config("anthropic").model_copy(
        update={"key_env": "MY_OWN_KEY", "limits": AiLimits(max_output_tokens=777)}
    )
    model = build_adapter(config, {"MY_OWN_KEY": KEY, "ANTHROPIC_API_KEY": "another-key"})
    assert isinstance(model, AnthropicModel) and (model.provider, model.model) == ("anthropic", "claude-opus-5-5")
    assert vars(model)["_key"] == KEY and vars(model)["_max"] == 777
    assert vars(build_adapter(config, {}))["_key"] == ""  # no variable: an empty key, which the adapter refuses to use
