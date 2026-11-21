"""M3: what a draft may say is a closed vocabulary in strict models (D-E56, D-E57, D-E59). Nothing outside it can be stored."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from scopedagent.domain.findings import (
    INTRUSIVENESS,
    INVOCATION_KINDS,
    MAX_STEPS,
    Assessment,
    FindingDetails,
    Intrusiveness,
    ReviewDecision,
    SeverityValue,
    StepKind,
    ValidationStep,
    VulnClass,
)
from scopedagent.domain.schemas import FindingDraftCreate

pytestmark = pytest.mark.milestone("M3")


def step(**over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "order": 1,
        "kind": "read_recorded_observation",
        "intrusiveness": "none",
        "target": None,
        "cites": ["obs-1"],
        "condition": "the recorded fact is as listed",
        "action": "Open the stored observation and note the listed fields.",
        "example_invocation": None,
        "if_condition_holds": "The field has the recorded value.",
        "if_it_does_not": "The field differs; re-collect before concluding anything.",
        "record": "The field values and the time you looked.",
        "must_not": ["change anything"],
        "stop_if": "the observation cannot be found",
    }
    data.update(over)
    return data


def details(**over: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "rule_id": "R-TLS-01",
        "rule_version": 1,
        "vulnerability_class": "tls_misconfiguration",
        "cwe_candidates": ["CWE-295"],
        "conditions": ["The certificate is self-signed, so it cannot be chained to a trusted authority."],
        "exploitability": {
            "assessment": "conditional",
            "preconditions": ["A client that does not verify the certificate connects."],
            "attacker_position": "On the network path between a client and the service.",
            "unknowns": ["Whether any client pins this certificate."],
            "basis": "Rule R-TLS-01: the weakness was observed; nothing was exploited.",
        },
        "validation_steps": [step()],
        "validation_steps_dropped": [],
        "decision_guide": [
            {"outcome": "The condition holds and the service is in use.", "suggests": "confirmed"},
            {"outcome": "The service is decommissioned.", "suggests": "not_exploitable"},
            {"outcome": "Nobody can say.", "suggests": "inconclusive"},
        ],
        "remediation": "Present a certificate issued by a trusted authority.",
        "suggested_severity": {"value": "low", "basis": "One weakness, conditional on client behaviour."},
        "severity": "unknown",
        "facts": [],
        "assumptions": ["The stored observations are an accurate record of what the target answered."],
    }
    data.update(over)
    return data


# ------------------------------------------------------------------------------------- the vocabularies ----
def test_the_class_list_is_exactly_the_documented_one() -> None:
    assert {c.value for c in VulnClass} == {
        "tls_misconfiguration",
        "missing_security_header",
        "information_disclosure",
        "insecure_redirect",
        "exposed_api_documentation",
        "permissive_cors",
        "dns_external_reference",
        "ai_prompt_injection_susceptibility",
        "ai_system_prompt_leakage",
        "ai_sensitive_information_disclosure",
        "ai_output_handling",
    }


def test_the_assessment_vocabulary_has_no_confirmed() -> None:
    assert {a.value for a in Assessment} == {"not_assessed", "unlikely", "conditional", "likely_if_conditions_hold"}
    assert "confirmed" not in {a.value for a in Assessment}


def test_the_reviewer_decisions_are_exactly_three() -> None:
    assert {d.value for d in ReviewDecision} == {"confirmed", "not_exploitable", "inconclusive"}


def test_severity_suggestions_never_include_critical() -> None:
    assert {s.value for s in SeverityValue} == {"info", "low", "medium", "high"}


def test_the_step_kinds_are_the_closed_list_of_nine() -> None:
    assert {k.value for k in StepKind} == {
        "read_recorded_observation",
        "compare_recorded_observations",
        "rerequest_listed_path",
        "check_cors_for_declared_origin",
        "inspect_certificate_field",
        "re_resolve_name",
        "read_public_document",
        "rerun_library_probe",
        "owner_confirmation",
    }
    assert len(StepKind) == 9


def test_every_kind_has_an_intrusiveness_and_none_is_a_repeated_read() -> None:
    assert {i.value for i in Intrusiveness} == {"none", "single_read", "repeated_read"}
    assert set(INTRUSIVENESS) == set(StepKind)
    reads_nothing = {
        StepKind.READ_RECORDED_OBSERVATION,
        StepKind.COMPARE_RECORDED_OBSERVATIONS,
        StepKind.OWNER_CONFIRMATION,
    }
    for kind in StepKind:
        expected = Intrusiveness.NONE if kind in reads_nothing else Intrusiveness.SINGLE_READ
        assert INTRUSIVENESS[kind] is expected, kind
    assert Intrusiveness.REPEATED_READ not in set(INTRUSIVENESS.values())  # in the vocabulary, used by no kind


def test_only_five_kinds_may_carry_an_invocation() -> None:
    assert {
        StepKind.INSPECT_CERTIFICATE_FIELD,
        StepKind.REREQUEST_LISTED_PATH,
        StepKind.CHECK_CORS_FOR_DECLARED_ORIGIN,
        StepKind.RE_RESOLVE_NAME,
        StepKind.READ_PUBLIC_DOCUMENT,
    } == INVOCATION_KINDS


def test_a_draft_has_at_most_eight_steps() -> None:
    assert MAX_STEPS == 8


# ------------------------------------------------------------------------------------------ the details ----
def test_valid_details_are_accepted_and_round_trip() -> None:
    parsed = FindingDetails.model_validate(details())
    assert FindingDetails.model_validate_json(parsed.model_dump_json()) == parsed


@pytest.mark.parametrize(
    "over",
    [
        {"vulnerability_class": "remote_code_execution"},
        {"extra_field": 1},
        {"severity": "critical"},
        {"severity": "high"},
        {"cwe_candidates": ["CWE-ABC"]},
        {"cwe_candidates": ["CWE-1", "CWE-2", "CWE-3", "CWE-4", "CWE-5", "CWE-6"]},
        {"conditions": []},
        {"conditions": ["x"] * 9},
        {"conditions": ["x" * 301]},
        {"remediation": "x" * 501},
        {"facts": ["x"] * 7},
        {"facts": ["x" * 81]},
        {"rule_id": "tls-01"},
        {"rule_version": 0},
        {"decision_guide": []},
        {"validation_steps": [step()] * 9},
    ],
)
def test_details_outside_the_vocabulary_or_limits_are_refused(over: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        FindingDetails.model_validate(details(**over))


def test_an_assessment_of_confirmed_is_refused() -> None:
    bad = details()
    bad["exploitability"] = {**bad["exploitability"], "assessment": "confirmed"}
    with pytest.raises(ValidationError):
        FindingDetails.model_validate(bad)


def test_the_decision_guide_must_cover_each_decision_once() -> None:
    guide = [
        {"outcome": "a", "suggests": "confirmed"},
        {"outcome": "b", "suggests": "confirmed"},
        {"outcome": "c", "suggests": "inconclusive"},
    ]
    with pytest.raises(ValidationError):
        FindingDetails.model_validate(details(decision_guide=guide))


def test_the_details_are_immutable_values() -> None:
    parsed = FindingDetails.model_validate(details())
    with pytest.raises(ValidationError):
        parsed.rule_id = "R-TLS-02"  # type: ignore[misc]


# -------------------------------------------------------------------------------------------- the steps ----
@pytest.mark.parametrize(
    "over",
    [
        {"kind": "send_payload"},
        {"intrusiveness": "heavy"},
        {"order": 0},
        {"cites": []},
        {"action": "x" * 401},
        {"action": ""},
        {"if_condition_holds": ""},
        {"if_it_does_not": ""},
        {"must_not": []},
        {"stop_if": ""},
        {"example_invocation": "x" * 301},
        {"extra": 1},
        {"action": "Open it" + chr(0x202E) + " now."},
        {"action": "Open it\nnow."},
        {"action": "Open\x00 it."},
    ],
)
def test_a_step_outside_its_limits_or_with_control_text_is_refused(over: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ValidationStep.model_validate(step(**over))


def test_a_valid_step_is_accepted() -> None:
    assert ValidationStep.model_validate(step()).kind is StepKind.READ_RECORDED_OBSERVATION


# ----------------------------------------------------------------------------------------- the category ----
def test_a_class_id_with_underscores_is_a_valid_category() -> None:
    assert FindingDraftCreate(title="A title", category="tls_misconfiguration", confidence=0.5).category == (
        "tls_misconfiguration"
    )


@pytest.mark.parametrize("category", ["", "Tls", "_x", "a b", "a" * 41, "a;b"])
def test_a_malformed_category_is_still_refused(category: str) -> None:
    with pytest.raises(ValidationError):
        FindingDraftCreate(title="A title", category=category, confidence=0.5)
