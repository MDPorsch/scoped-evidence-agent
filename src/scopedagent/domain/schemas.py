"""The normalised observation (docs/fixture-format.md) and the draft input. Strict models: unknown fields are refused.

Adapters emit these; storage validates them again. A payload holds facts, never verdicts: whether a certificate is
expired
is a rule evaluated against the run's clock later, so a stored observation never goes stale.
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from scopedagent.domain.outcome import ErrorStatus
from scopedagent.errors import ScopeError
from scopedagent.policy.scope import canonical_host, canonical_path

MAX_PARSED_BYTES = 8192
MAX_PARSED_DEPTH = 4
MAX_PARSED_KEYS = 64
_HEADER_NAME = re.compile(r"[a-z0-9_-]{1,64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CATEGORY = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
_AI_ID = r"^[a-z0-9][a-z0-9-]{1,39}$"
_API_ID = _AI_ID
_PARAM_NAME = r"^[a-z][a-z0-9_]{0,31}$"
_PARAM_VALUE = r"^[A-Za-z0-9._~-]{1,64}$"
_SHAPE_PATH = r"^\$(?:\.(?:[A-Za-z0-9_.-]{1,40}|\{key\}|\?)|\[\])*$"
_PROBE_SET = r"^[a-z0-9][a-z0-9-]{1,62}$"

Port = Annotated[int, Field(ge=1, le=65535)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
LaxTime = Annotated[AwareDatetime, Field(strict=False)]  # a JSON document carries timestamps as text


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


def _canonical_host(value: str) -> str:
    try:
        host = canonical_host(value)
    except ScopeError as exc:
        raise ValueError(exc.message) from None
    if host != value:
        raise ValueError("the host must already be in canonical form")
    return host


Host = Annotated[str, Field(max_length=253)]


class Target(_Model):
    host: Host
    scheme: Literal["http", "https"]
    port: Port

    _host = field_validator("host")(_canonical_host)


# ------------------------------------------------------------------------------------------ DNS ----
class DnsPayload(_Model):
    host: Host
    status: Literal["ok", "nxdomain", "no_data", "timeout", "error"]
    records: dict[Literal["A", "AAAA", "CNAME", "NS", "MX", "TXT", "CAA"], list[str]]

    _host = field_validator("host")(_canonical_host)

    @field_validator("records")
    @classmethod
    def _bounded(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        for entries in value.values():
            if len(entries) > 32 or any(len(e) > 255 for e in entries):
                raise ValueError("a record set has at most 32 entries of at most 255 characters")
        return value


# ------------------------------------------------------------------------------------------ TLS ----
class PublicKey(_Model):
    type: Literal["rsa", "ec", "ed25519", "ed448", "dsa", "unknown"]
    bits: Annotated[int, Field(ge=0, le=65536)] | None


class CertificateSummary(_Model):
    subject_cn: Annotated[str, Field(max_length=255)]
    issuer_cn: Annotated[str, Field(max_length=255)]
    san_dns: Annotated[list[Annotated[str, Field(max_length=255)]], Field(max_length=100)]
    not_before: LaxTime
    not_after: LaxTime
    signature_algorithm: Annotated[str, Field(max_length=64)]
    public_key: PublicKey
    self_signed: bool
    sha256_fingerprint: Sha256


class TlsPayload(_Model):
    host: Host
    port: Port
    status: Literal["ok", "handshake_failed", "timeout", "error"]
    tls_version: Literal["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"] | None
    certificate: CertificateSummary | None

    _host = field_validator("host")(_canonical_host)


# ------------------------------------------------------------------------------------------ HTTP ----
def _bounded_json(value: Any, depth: int = 1) -> None:
    if depth > MAX_PARSED_DEPTH + 1:
        raise ValueError(f"a parsed document may be nested at most {MAX_PARSED_DEPTH} levels")
    if isinstance(value, dict):
        if len(value) > MAX_PARSED_KEYS:
            raise ValueError(f"a parsed document may have at most {MAX_PARSED_KEYS} keys per object")
        for item in value.values():
            _bounded_json(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _bounded_json(item, depth + 1)


class BodySummary(_Model):
    size_bytes: Annotated[int, Field(ge=0, le=2_000_000)]
    truncated: bool
    content_type: Annotated[str, Field(max_length=255)] | None
    artifact_sha256: Sha256
    parsed: dict[str, Any] | None

    @field_validator("parsed")
    @classmethod
    def _parsed(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        _bounded_json(value)
        if len(json.dumps(value, ensure_ascii=True)) > MAX_PARSED_BYTES:
            raise ValueError(f"a parsed document may be at most {MAX_PARSED_BYTES} bytes")
        return value


def _check_headers(value: dict[str, list[str]]) -> dict[str, list[str]]:
    if len(value) > 64:
        raise ValueError("at most 64 headers")
    for name, values in value.items():
        if not _HEADER_NAME.fullmatch(name):
            raise ValueError("a header name is lower-case letters, digits, - and _, at most 64 characters")
        if len(values) > 64 or any(len(v) > 4096 for v in values):
            raise ValueError("a header has at most 64 values of at most 4096 characters")
    return value


class CookieFlags(_Model):
    """A cookie as a response set it: its name and three flags, never its value (docs/stage2-design.md, check A1)."""

    name: Annotated[str, Field(pattern=r"^(?:[A-Za-z0-9_.-]{1,64}|\?)$")]
    secure: bool
    http_only: bool
    same_site: Literal["strict", "lax", "none", "missing", "other"]


class HttpPayload(_Model):
    host: Host
    port: Port
    scheme: Literal["http", "https"]
    path: str
    method: Literal["GET", "HEAD"]
    http_status: Annotated[int, Field(ge=100, le=599)] | None
    headers: dict[str, list[str]]
    redirect_location: Annotated[str, Field(max_length=2048)] | None
    body: BodySummary | None
    cookies: Annotated[list[CookieFlags], Field(max_length=16)] = []  # absent in an observation stored before M7

    _host = field_validator("host")(_canonical_host)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        try:
            return canonical_path(value)
        except ScopeError as exc:
            raise ValueError(exc.message) from None

    @field_validator("headers")
    @classmethod
    def _headers(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        return _check_headers(value)


# ------------------------------------------------------------------------------ AI-system payloads ----
class AiMetadataPayload(_Model):
    host: Host
    port: Port
    scheme: Literal["http", "https"]
    path: str
    http_status: Annotated[int, Field(ge=100, le=599)] | None
    headers: dict[str, list[str]]
    model_ids: Annotated[list[Annotated[str, Field(max_length=128)]], Field(max_length=50)]
    body: BodySummary | None

    _host = field_validator("host")(_canonical_host)

    @field_validator("headers")
    @classmethod
    def _headers(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        return _check_headers(value)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        try:
            return canonical_path(value)
        except ScopeError as exc:
            raise ValueError(exc.message) from None


class AiFlags(_Model):
    """Structure present in a reply, nothing more. Whether it matters is a human's judgement."""

    contains_html: bool
    contains_markdown_link: bool
    contains_code_block: bool
    contains_url: bool


class AiProbePayload(_Model):
    ai_target_id: Annotated[str, Field(pattern=_AI_ID)]
    probe_set: Annotated[str, Field(pattern=_PROBE_SET)]
    probe_index: Annotated[int, Field(ge=0, le=9)]
    category: Literal[
        "prompt_injection", "system_prompt_leakage", "sensitive_information_disclosure", "output_handling"
    ]
    http_status: Annotated[int, Field(ge=100, le=599)] | None
    input_tokens: Annotated[int, Field(ge=0, le=1_000_000)] | None
    output_tokens: Annotated[int, Field(ge=0, le=1_000_000)] | None
    finish_reason: Annotated[str, Field(max_length=64)] | None
    output_chars: Annotated[int, Field(ge=0, le=2_000_000)] | None
    canary_present: bool | None
    flags: AiFlags | None
    artifact_sha256: Sha256 | None


# ----------------------------------------------------------------------------------------- API payloads ----
class _ApiRequest(_Model):
    api_target_id: Annotated[str, Field(pattern=_API_ID)]
    host: Host
    port: Port
    scheme: Literal["http", "https"]
    path: str

    _host = field_validator("host")(_canonical_host)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        try:
            return canonical_path(value)
        except ScopeError as exc:
            raise ValueError(exc.message) from None


class ApiSpecPayload(_ApiRequest):
    """The spec document as inventory: what it lists, never what it permits (D-E49)."""

    http_status: Annotated[int, Field(ge=100, le=599)] | None
    headers: dict[str, list[str]]
    body: BodySummary | None

    @field_validator("headers")
    @classmethod
    def _headers(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        return _check_headers(value)


class ShapeEntry(_Model):
    path: Annotated[str, Field(max_length=200, pattern=_SHAPE_PATH)]
    type: Literal["object", "array", "string", "number", "boolean", "null"]
    length: Annotated[int, Field(ge=0, le=2_000_000)] | None


class ApiFlags(_Model):
    """Structure present in a reply, nothing more. Whether it matters is a human's judgement."""

    has_stack_trace_markers: bool
    has_debug_markers: bool
    echoes_request_headers: bool


class ApiReadPayload(_ApiRequest):
    """One call of one endpoint as one principal. The body's values are never kept (D-E52): only its shape."""

    endpoint_id: Annotated[str, Field(pattern=_API_ID)]
    principal: Annotated[str, Field(pattern=_API_ID)]
    method: Literal["GET", "HEAD"]
    params: dict[Annotated[str, Field(pattern=_PARAM_NAME)], Annotated[str, Field(pattern=_PARAM_VALUE)]]
    http_status: Annotated[int, Field(ge=100, le=599)] | None
    headers: dict[str, list[str]]
    content_type: Annotated[str, Field(max_length=255)] | None
    size_bytes: Annotated[int, Field(ge=0, le=2_000_000)] | None
    truncated: bool
    shape_status: Literal["ok", "partial", "not_json", "none"]
    shape: Annotated[list[ShapeEntry], Field(max_length=200)]
    shape_digest: Sha256 | None
    flags: ApiFlags | None

    @field_validator("headers")
    @classmethod
    def _headers(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        return _check_headers(value)

    @model_validator(mode="after")
    def _consistent(self) -> ApiReadPayload:
        if (self.shape_status in ("ok", "partial")) != bool(self.shape) or (self.shape_digest is None) != (
            self.shape_status in ("not_json", "none")
        ):
            raise ValueError("a shape and its digest are present exactly when the body was JSON")
        return self


class ApiCors(_Model):
    allow_origin: Annotated[str, Field(max_length=255)] | None
    allow_credentials: Annotated[str, Field(max_length=16)] | None
    allow_methods: Annotated[str, Field(max_length=255)] | None
    allow_headers: Annotated[str, Field(max_length=1024)] | None


class ApiOptionsPayload(_ApiRequest):
    """The answer to an OPTIONS request that carries one declared origin, as headers."""

    endpoint_id: Annotated[str, Field(pattern=_API_ID)]
    origin: Annotated[str, Field(max_length=300)]
    http_status: Annotated[int, Field(ge=100, le=599)] | None
    allow: Annotated[list[Annotated[str, Field(pattern=r"^[A-Z]{3,10}$")]], Field(max_length=12)]
    cors: ApiCors | None


# -------------------------------------------------------------------------------------- envelope ----
Payload = (
    DnsPayload
    | TlsPayload
    | HttpPayload
    | AiMetadataPayload
    | AiProbePayload
    | ApiSpecPayload
    | ApiReadPayload
    | ApiOptionsPayload
)
PAYLOAD_MODELS: dict[str, type[_Model]] = {
    "dns_metadata": DnsPayload,
    "tls_metadata": TlsPayload,
    "http_metadata": HttpPayload,
    "ai_metadata": AiMetadataPayload,
    "ai_probe": AiProbePayload,
    "api_spec": ApiSpecPayload,
    "api_read": ApiReadPayload,
    "api_options": ApiOptionsPayload,
}
_ADAPTER_FOR = {
    "dns_metadata": "offline_dns",
    "tls_metadata": "offline_tls",
    "http_metadata": "offline_http",
    "ai_metadata": "offline_ai",
    "ai_probe": "offline_ai",
    "api_spec": "offline_api",
    "api_read": "offline_api",
    "api_options": "offline_api",
}


class ObservationEnvelope(_Model):
    adapter: Literal["offline_dns", "offline_tls", "offline_http", "offline_ai", "offline_api"]
    observation_type: Literal[
        "dns_metadata",
        "tls_metadata",
        "http_metadata",
        "ai_metadata",
        "ai_probe",
        "api_spec",
        "api_read",
        "api_options",
    ]
    target: Target
    normalized_input: Annotated[str, Field(min_length=1, max_length=512)]
    error_status: Annotated[ErrorStatus, Field(strict=False)]
    payload: Payload

    @model_validator(mode="before")
    @classmethod
    def _typed_payload(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("payload"), dict):
            model = PAYLOAD_MODELS.get(data.get("observation_type", ""))
            if model is not None:
                data = {**data, "payload": model.model_validate(data["payload"])}
        return data

    @model_validator(mode="after")
    def _consistent(self) -> ObservationEnvelope:
        if _ADAPTER_FOR[self.observation_type] != self.adapter:
            raise ValueError("the adapter does not produce this observation type")
        if not isinstance(self.payload, PAYLOAD_MODELS[self.observation_type]):
            raise ValueError("the payload does not match the observation type")
        return self


# ------------------------------------------------------------------------------------- findings ----
class FindingDraftCreate(_Model):
    title: Annotated[str, Field(min_length=5, max_length=160)]
    category: str
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]

    @field_validator("category")
    @classmethod
    def _category(cls, value: str) -> str:
        if not _CATEGORY.fullmatch(value):
            raise ValueError("category is lower-case letters, digits, hyphens and underscores, at most 40 characters")
        return value
