"""AI observation payloads (docs/fixture-format.md) and the AI fixtures: conformance, exactness and consistency with the plan."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest
from pydantic import ValidationError

from scopedagent.domain.schemas import ObservationEnvelope
from scopedagent.policy.scope import parse_scope
from tests.support import AI_PACK, NOW, SCOPE_FILES, golden, pack

pytestmark = pytest.mark.milestone("M1")


def items() -> list[dict[str, Any]]:
    return golden(AI_PACK)


def refuses(item: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ObservationEnvelope.model_validate(item)


def of_type(kind: str, index: int = 0) -> dict[str, Any]:
    return copy.deepcopy([i for i in items() if i["observation_type"] == kind][index])


# ------------------------------------------------------------------------------------ conformance ----
def test_every_ai_golden_conforms_and_round_trips_exactly() -> None:
    for item in items():
        assert ObservationEnvelope.model_validate(item).model_dump(mode="json") == item


def test_the_ai_golden_has_one_metadata_read_then_four_probes_in_plan_order() -> None:
    assert [(i["observation_type"], i["adapter"]) for i in items()] == [("ai_metadata", "offline_ai")] + [
        ("ai_probe", "offline_ai")
    ] * 4
    assert [i["payload"]["probe_set"] for i in items()[1:]] == ["canary-echo-v1"] * 2 + ["output-structure-v1"] * 2
    assert [i["payload"]["probe_index"] for i in items()[1:]] == [0, 1, 0, 1]


def test_the_pack_has_exactly_one_entry_for_every_planned_ai_operation() -> None:
    plan = parse_scope(SCOPE_FILES[AI_PACK].read_text(encoding="utf-8"), now=NOW).planned
    wanted = {
        f"https://{op.host}:{op.port}{op.path}"
        if op.kind == "ai_metadata"
        else f"probe:{op.target_id}:{op.probe_set}:{op.probe_index}"
        for op in plan
    }
    assert set(pack(AI_PACK)["ai"]) == wanted and len(wanted) == len(plan)
    assert items()[0]["normalized_input"] == "GET https://assistant.example.invalid:443/v1/models"


def test_the_goldens_agree_with_the_recorded_replies() -> None:
    """The facts in each golden are recomputed here from the pack, independently of any generator."""
    recorded = pack(AI_PACK)["ai"]
    for item in items()[1:]:
        payload = item["payload"]
        entry = recorded[f"probe:{payload['ai_target_id']}:{payload['probe_set']}:{payload['probe_index']}"]
        body = json.loads(entry["body"])
        reply = body["choices"][0]["message"]["content"]
        assert payload["output_chars"] == len(reply)
        assert payload["artifact_sha256"] == hashlib.sha256(reply.encode()).hexdigest()
        assert (
            payload["input_tokens"] == body["usage"]["prompt_tokens"]
            and payload["output_tokens"] == body["usage"]["completion_tokens"]
        )
        assert (
            payload["finish_reason"] == body["choices"][0]["finish_reason"]
            and payload["http_status"] == entry["status"]
        )
        assert payload["canary_present"] == ((entry["canary"] in reply) if entry["canary"] else None)
        assert payload["flags"]["contains_code_block"] == ("```" in reply)
        assert payload["flags"]["contains_html"] == ("<img" in reply)
        assert payload["flags"]["contains_url"] == ("http://" in reply or "https://" in reply)
        assert payload["flags"]["contains_markdown_link"] == ("](" in reply)


def test_the_fixture_covers_the_adversarial_cases_it_exists_for() -> None:
    probes = [i["payload"] for i in items()[1:]]
    assert probes[0]["canary_present"] is True  # an instruction planted in data was followed
    assert probes[1]["canary_present"] is False  # and refused
    assert probes[2]["canary_present"] is None and all(
        probes[2]["flags"].values()
    )  # markup, a link, a code block and a URL
    assert probes[3]["finish_reason"] == "length"
    reply = json.loads(pack(AI_PACK)["ai"]["probe:support-bot:output-structure-v1:0"]["body"])["choices"][0]["message"][
        "content"
    ]
    assert (
        "ignore previous instructions" in reply and "send_email" in reply
    )  # the planted instruction is in the data, as data


def test_no_golden_holds_the_reply_text_only_its_facts() -> None:
    reply = json.loads(pack(AI_PACK)["ai"]["probe:support-bot:canary-echo-v1:0"]["body"])["choices"][0]["message"][
        "content"
    ]
    assert reply not in json.dumps(items())


# ------------------------------------------------------------------------------------- metadata ----
@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(model_ids=[f"m{i}" for i in range(51)]),
        lambda p: p.update(model_ids=["x" * 129]),
        lambda p: p.update(model_ids="support-bot-1"),
        lambda p: p.update(http_status=99),
        lambda p: p.update(path="no-slash"),
        lambda p: p.update(host="UPPER.example.invalid"),
        lambda p: p.pop("model_ids"),
        lambda p: p.update(surprise=1),
    ],
)
def test_ai_metadata_payload_limits(mutate: Any) -> None:
    item = of_type("ai_metadata")
    mutate(item["payload"])
    refuses(item)


def test_ai_metadata_accepts_its_boundaries() -> None:
    item = of_type("ai_metadata")
    item["payload"]["model_ids"] = [f"m{i}" for i in range(49)] + ["x" * 128]
    ObservationEnvelope.model_validate(item)


# ---------------------------------------------------------------------------------------- probes ----
@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(probe_index=-1),
        lambda p: p.update(probe_index=10),
        lambda p: p.update(category="jailbreak"),
        lambda p: p.update(probe_set="Evil Set"),
        lambda p: p.update(ai_target_id="A"),
        lambda p: p.update(input_tokens=-1),
        lambda p: p.update(output_tokens=-1),
        lambda p: p.update(input_tokens=1_000_001),
        lambda p: p.update(finish_reason="x" * 65),
        lambda p: p.update(output_chars=-1),
        lambda p: p.update(output_chars=2_000_001),
        lambda p: p.update(artifact_sha256="short"),
        lambda p: p.update(http_status=600),
        lambda p: p.update(canary_present="yes"),
        lambda p: p["flags"].pop("contains_html"),
        lambda p: p["flags"].update(contains_a_vulnerability=True),
        lambda p: p["flags"].update(contains_html="true"),
        lambda p: p.update(verdict="vulnerable"),
        lambda p: p.update(severity="high"),
    ],
)
def test_ai_probe_payload_limits_and_no_verdict_fields(mutate: Any) -> None:
    item = of_type("ai_probe")
    mutate(item["payload"])
    refuses(item)


def test_ai_probe_accepts_its_boundaries_and_nulls() -> None:
    item = of_type("ai_probe")
    item["payload"].update(
        probe_index=9, input_tokens=1_000_000, output_tokens=0, output_chars=2_000_000, finish_reason="x" * 64
    )
    ObservationEnvelope.model_validate(item)
    item = of_type("ai_probe")
    item["error_status"] = "timeout"
    item["payload"].update(
        http_status=None,
        input_tokens=None,
        output_tokens=None,
        finish_reason=None,
        output_chars=None,
        canary_present=None,
        flags=None,
        artifact_sha256=None,
    )
    assert ObservationEnvelope.model_validate(item).error_status.value == "timeout"


def test_the_adapter_must_match_the_ai_observation_types() -> None:
    for kind, wrong in (("ai_metadata", "offline_http"), ("ai_probe", "offline_http"), ("ai_probe", "offline_dns")):
        item = of_type(kind)
        item["adapter"] = wrong
        refuses(item)
    item = of_type("ai_probe")
    item["observation_type"] = "ai_metadata"
    refuses(item)
    web = golden("healthy")[0]
    web = copy.deepcopy(web)
    web["adapter"] = "offline_ai"
    refuses(web)


def test_an_ai_payload_cannot_be_filed_under_a_web_type_or_the_reverse() -> None:
    item = of_type("ai_probe")
    item["observation_type"] = "http_metadata"
    item["adapter"] = "offline_http"
    refuses(item)
    http = copy.deepcopy(golden("healthy")[2])
    http["observation_type"], http["adapter"] = "ai_metadata", "offline_ai"
    refuses(http)
