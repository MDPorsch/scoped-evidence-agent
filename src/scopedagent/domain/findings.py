"""What a draft finding may say: closed vocabularies in strict models (D-E56 to D-E60, docs/correlator.md).

Nothing outside these lists can be stored. The assessment vocabulary has no `confirmed` (D-E57); a draft's own
severity is always `unknown`; a validation step is one of nine kinds and carries only what its template and the
checker allow (D-E58).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_STEPS = 8
_CONTROL = frozenset({"Cc", "Cf", "Zl", "Zp"})  # control, format (bidirectional marks), line and paragraph separators
_CWE = re.compile(r"CWE-[0-9]{1,5}")
_RULE_ID = re.compile(r"R-[A-Z]{2,5}-[0-9]{2}")
_OBSERVATION_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


class VulnClass(StrEnum):
    TLS_MISCONFIGURATION = "tls_misconfiguration"
    MISSING_SECURITY_HEADER = "missing_security_header"
    INFORMATION_DISCLOSURE = "information_disclosure"
    INSECURE_REDIRECT = "insecure_redirect"
    EXPOSED_API_DOCUMENTATION = "exposed_api_documentation"
    PERMISSIVE_CORS = "permissive_cors"
    DNS_EXTERNAL_REFERENCE = "dns_external_reference"
    AI_PROMPT_INJECTION_SUSCEPTIBILITY = "ai_prompt_injection_susceptibility"
    AI_SYSTEM_PROMPT_LEAKAGE = "ai_system_prompt_leakage"
    AI_SENSITIVE_INFORMATION_DISCLOSURE = "ai_sensitive_information_disclosure"
    AI_OUTPUT_HANDLING = "ai_output_handling"


class Assessment(StrEnum):
    """Whether the evidence supports a way in. There is no `confirmed`: only a person records that (D-E57)."""

    NOT_ASSESSED = "not_assessed"
    UNLIKELY = "unlikely"
    CONDITIONAL = "conditional"
    LIKELY_IF_CONDITIONS_HOLD = "likely_if_conditions_hold"


class SeverityValue(StrEnum):
    """A suggestion, never the tool's own severity. There is no `critical`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ReviewDecision(StrEnum):
    CONFIRMED = "confirmed"
    NOT_EXPLOITABLE = "not_exploitable"
    INCONCLUSIVE = "inconclusive"


class StepKind(StrEnum):
    READ_RECORDED_OBSERVATION = "read_recorded_observation"
    COMPARE_RECORDED_OBSERVATIONS = "compare_recorded_observations"
    REREQUEST_LISTED_PATH = "rerequest_listed_path"
    CHECK_CORS_FOR_DECLARED_ORIGIN = "check_cors_for_declared_origin"
    INSPECT_CERTIFICATE_FIELD = "inspect_certificate_field"
    RE_RESOLVE_NAME = "re_resolve_name"
    READ_PUBLIC_DOCUMENT = "read_public_document"
    RERUN_LIBRARY_PROBE = "rerun_library_probe"
    OWNER_CONFIRMATION = "owner_confirmation"


class Intrusiveness(StrEnum):
    NONE = "none"
    SINGLE_READ = "single_read"
    REPEATED_READ = "repeated_read"  # in the vocabulary, used by no kind: a step never repeats a request


_K = StepKind
INTRUSIVENESS: Mapping[StepKind, Intrusiveness] = MappingProxyType(
    {
        _K.READ_RECORDED_OBSERVATION: Intrusiveness.NONE,
        _K.COMPARE_RECORDED_OBSERVATIONS: Intrusiveness.NONE,
        _K.OWNER_CONFIRMATION: Intrusiveness.NONE,
        _K.REREQUEST_LISTED_PATH: Intrusiveness.SINGLE_READ,
        _K.CHECK_CORS_FOR_DECLARED_ORIGIN: Intrusiveness.SINGLE_READ,
        _K.INSPECT_CERTIFICATE_FIELD: Intrusiveness.SINGLE_READ,
        _K.RE_RESOLVE_NAME: Intrusiveness.SINGLE_READ,
        _K.READ_PUBLIC_DOCUMENT: Intrusiveness.SINGLE_READ,
        _K.RERUN_LIBRARY_PROBE: Intrusiveness.SINGLE_READ,
    }
)
INVOCATION_KINDS = frozenset(
    {
        _K.INSPECT_CERTIFICATE_FIELD,
        _K.REREQUEST_LISTED_PATH,
        _K.CHECK_CORS_FOR_DECLARED_ORIGIN,
        _K.RE_RESOLVE_NAME,
        _K.READ_PUBLIC_DOCUMENT,
    }
)


def _plain(value: str) -> str:
    if any(unicodedata.category(ch) in _CONTROL for ch in value):
        raise ValueError("text must be one plain line: no control, bidirectional or separator characters")
    return value


T80 = Annotated[str, Field(min_length=1, max_length=80), AfterValidator(_plain)]
T100 = Annotated[str, Field(min_length=1, max_length=100), AfterValidator(_plain)]
T200 = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_plain)]
T300 = Annotated[str, Field(min_length=1, max_length=300), AfterValidator(_plain)]
T400 = Annotated[str, Field(min_length=1, max_length=400), AfterValidator(_plain)]
T500 = Annotated[str, Field(min_length=1, max_length=500), AfterValidator(_plain)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


# Enums arrive as text from JSON and from tests; strict mode would refuse the text, so these fields are not strict.
ClassField = Annotated[VulnClass, Field(strict=False)]
AssessmentField = Annotated[Assessment, Field(strict=False)]
SeverityField = Annotated[SeverityValue, Field(strict=False)]
DecisionField = Annotated[ReviewDecision, Field(strict=False)]
KindField = Annotated[StepKind, Field(strict=False)]
IntrusivenessField = Annotated[Intrusiveness, Field(strict=False)]


class StepTarget(_Model):
    host: Annotated[str, Field(min_length=1, max_length=253)]
    port: Annotated[int, Field(ge=1, le=65535)] | None = None


class ValidationStep(_Model):
    order: Annotated[int, Field(ge=1, le=MAX_STEPS)]
    kind: KindField
    intrusiveness: IntrusivenessField
    target: StepTarget | None
    cites: Annotated[list[str], Field(min_length=1, max_length=MAX_STEPS)]
    condition: T200
    action: T400
    example_invocation: T300 | None
    if_condition_holds: T300
    if_it_does_not: T300
    record: T500
    must_not: Annotated[list[T100], Field(min_length=1, max_length=8)]
    stop_if: T200

    @field_validator("cites")
    @classmethod
    def _cites(cls, value: list[str]) -> list[str]:
        if any(not _OBSERVATION_ID.fullmatch(v) for v in value):
            raise ValueError("a cited observation id is letters, digits, - and _")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> ValidationStep:
        if INTRUSIVENESS[self.kind] is not self.intrusiveness:
            raise ValueError("the intrusiveness does not match the kind")
        if self.example_invocation is not None and self.kind not in INVOCATION_KINDS:
            raise ValueError("this kind of step carries no invocation")
        return self


class DroppedStep(_Model):
    kind: Annotated[str, Field(min_length=1, max_length=64)]
    rule: Literal["VS-01", "VS-02", "VS-03", "VS-04", "VS-05", "VS-06"]


class Exploitability(_Model):
    assessment: AssessmentField
    preconditions: Annotated[list[T300], Field(min_length=1, max_length=6)]
    attacker_position: T200
    unknowns: Annotated[list[T300], Field(min_length=1, max_length=6)]
    basis: T300


class SuggestedSeverity(_Model):
    value: SeverityField
    basis: T200


class DecisionOutcome(_Model):
    outcome: T300
    suggests: DecisionField


class FindingDetails(_Model):
    rule_id: Annotated[str, Field(pattern=_RULE_ID.pattern)]
    rule_version: Annotated[int, Field(ge=1)]
    vulnerability_class: ClassField
    cwe_candidates: Annotated[list[str], Field(max_length=5)]
    conditions: Annotated[list[T300], Field(min_length=1, max_length=8)]
    exploitability: Exploitability
    validation_steps: Annotated[list[ValidationStep], Field(max_length=MAX_STEPS)]
    validation_steps_dropped: Annotated[list[DroppedStep], Field(max_length=32)]
    decision_guide: Annotated[list[DecisionOutcome], Field(min_length=3, max_length=3)]
    remediation: T500
    suggested_severity: SuggestedSeverity
    severity: Literal["unknown"]
    facts: Annotated[list[T80], Field(max_length=6)]
    assumptions: Annotated[list[T300], Field(min_length=1, max_length=4)]

    @field_validator("cwe_candidates")
    @classmethod
    def _cwe(cls, value: list[str]) -> list[str]:
        if any(not _CWE.fullmatch(v) for v in value):
            raise ValueError("a CWE suggestion is CWE- and digits")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> FindingDetails:
        if sorted(g.suggests.value for g in self.decision_guide) != sorted(d.value for d in ReviewDecision):
            raise ValueError("the decision guide covers each reviewer decision exactly once")
        if [s.order for s in self.validation_steps] != list(range(1, len(self.validation_steps) + 1)):
            raise ValueError("steps are numbered from 1 in order")
        return self
