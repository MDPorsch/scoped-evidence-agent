"""The scope file: strict parsing, canonical hosts and paths, limits, the hash, and the plan (docs/scope-format.md).

A scope is a restriction, never proof of authorization (D-E02). It is ambiguous-or-refused: there is no best effort.
"""

from __future__ import annotations

import json
import math
import re
import stat
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import product
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from scopedagent.errors import ErrorCode, ScopeError
from scopedagent.logs import safe_text
from scopedagent.policy.probes import PROBE_SETS
from scopedagent.strictyaml import StrictYamlError, strict_load

MAX_SCOPE_BYTES = 64 * 1024
MAX_HOST_INPUT = 512
MAX_HOST = 253
MAX_PATH = 256
MAX_EXPIRY_DAYS = 366

_HOST_CHARS = re.compile(r"[a-z0-9.-]+")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PATH_CHARS = re.compile(r"/[A-Za-z0-9._~/-]*")
_ENGAGEMENT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
_APPROVAL_REF = re.compile(r"[A-Za-z0-9._:/#-]{3,128}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})")
_SCHEMES = ("http", "https")
_AI_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,39}")
_API_ID = _AI_ID
_PARAM_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")
_PARAM_VALUE = re.compile(r"[A-Za-z0-9._~-]{1,64}")
_PLACEHOLDER = re.compile(r"\{[^{}/]*\}")
_LABEL_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ,.:()_/-]{0,79}")
_ORIGIN = re.compile(r"https://([^/:?#@\s]+)(?::([0-9]{1,5}))?")
ANONYMOUS = "anonymous"
MAX_PARAMS = 4
_CONSTRAINT_ERRORS = {"greater_than", "greater_than_equal", "less_than", "less_than_equal", "too_short", "too_long"}

OperationKind = Literal[
    "dns_metadata", "tls_metadata", "http_metadata", "ai_metadata", "ai_probe", "api_spec", "api_read", "api_options"
]
AiOperation = Literal["ai_metadata", "ai_probe"]
ApiOperation = Literal["api_spec", "api_read", "api_options"]
AiCategory = Literal["prompt_injection", "system_prompt_leakage", "sensitive_information_disclosure", "output_handling"]
RULES_NOT_AVAILABLE = "not available in this version: only forbidden is accepted"


class ScopeValueError(ValueError):
    """Raised inside a validator so the error keeps its code when pydantic wraps it."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------------------- canonical forms ----
def canonical_host(raw: object) -> str:
    """Lower-case ASCII LDH labels (or valid xn-- labels), one trailing dot dropped, or a ScopeError (D-E04)."""
    if not isinstance(raw, str):
        raise ScopeError(ErrorCode.SCOPE_005, "a host must be text")
    if len(raw) > MAX_HOST_INPUT:
        raise ScopeError(ErrorCode.SCOPE_005, "the host is too long")
    if not raw.isascii():
        raise ScopeError(ErrorCode.SCOPE_005, "non-ASCII host names are not accepted: write the xn-- form")
    text = raw.lower()
    if text.endswith("."):
        text = text[:-1]
    if not _HOST_CHARS.fullmatch(text):
        raise ScopeError(
            ErrorCode.SCOPE_005,
            "the host may contain only letters, digits, hyphens and dots (no wildcard, port, path, user or escape)",
        )
    labels = text.split(".")
    if len(labels) < 2 or len(text) > MAX_HOST or not all(_LABEL.fullmatch(label) for label in labels):
        raise ScopeError(
            ErrorCode.SCOPE_005, "the host must be a name of at least two valid labels, at most 253 characters"
        )
    if labels[-1].isdigit():
        raise ScopeError(ErrorCode.SCOPE_005, "an IP address (or a name that looks like one) is not accepted")
    for label in labels:
        if label.startswith("xn--"):
            try:
                label.encode("ascii").decode("idna")
            except UnicodeError:
                raise ScopeError(ErrorCode.SCOPE_005, "an xn-- label is not valid IDNA") from None
    return text


def canonical_path(raw: object) -> str:
    """An exact request path: no query, fragment, escape, `.`/`..` segment or `//` (D-E05)."""
    if not isinstance(raw, str) or len(raw) > MAX_PATH or not _PATH_CHARS.fullmatch(raw):
        raise ScopeError(
            ErrorCode.SCOPE_006,
            "a path must start with / and use only letters, digits and . _ ~ - /, at most 256 characters",
        )
    segments = raw.split("/")[1:]
    for index, segment in enumerate(segments):
        if segment in {".", ".."}:
            raise ScopeError(ErrorCode.SCOPE_006, "a path may not contain a . or .. segment")
        if segment == "" and index != len(segments) - 1:
            raise ScopeError(ErrorCode.SCOPE_006, "a path may not contain an empty segment (//)")
    return raw


def _host_for_model(value: str) -> str:
    try:
        return canonical_host(value)
    except ScopeError as exc:
        raise ScopeValueError(exc.code, exc.message) from None


def _host_for_model_exact(value: str) -> None:
    """An origin's host must already be canonical: one spelling only."""
    if _host_for_model(value) != value:
        raise ScopeValueError(ErrorCode.SCOPE_005, "an origin's host must be in canonical form (lower-case, no dot)")


def _path_for_model(value: str) -> str:
    try:
        return canonical_path(value)
    except ScopeError as exc:
        raise ScopeValueError(exc.code, exc.message) from None


def _parse_expiry(value: object) -> datetime:
    hint = "expires_at must be a quoted UTC timestamp like '2026-12-31T23:59:00Z'"
    if not isinstance(value, str):
        raise ScopeValueError(ErrorCode.SCOPE_004, f"{hint} (an unquoted timestamp is read as a date object: quote it)")
    if not _TIMESTAMP.fullmatch(value):
        raise ScopeValueError(ErrorCode.SCOPE_004, hint)
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise ScopeValueError(ErrorCode.SCOPE_004, hint) from None
    return moment.astimezone(UTC)  # the pattern above guarantees an offset, so the result is always aware


# ---------------------------------------------------------------------------------------- schema ----
class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


class TargetEntry(_Model):
    host: str
    schemes: list[str]
    ports: Annotated[list[int], Field(min_length=1, max_length=8)]
    allowed_paths: Annotated[list[str], Field(max_length=20)] = []

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        return _host_for_model(value)

    @field_validator("schemes")
    @classmethod
    def _schemes(cls, value: list[str]) -> list[str]:
        if not value or any(s not in _SCHEMES for s in value) or len(set(value)) != len(value):
            raise ScopeValueError(
                ErrorCode.SCOPE_006, "schemes must be a non-empty list of unique values from: http, https"
            )
        return value

    @field_validator("ports")
    @classmethod
    def _ports(cls, value: list[int]) -> list[int]:
        if any(not 1 <= p <= 65535 for p in value) or len(set(value)) != len(value):
            raise ScopeValueError(ErrorCode.SCOPE_006, "ports must be unique integers from 1 to 65535")
        return value

    @field_validator("allowed_paths")
    @classmethod
    def _paths(cls, value: list[str]) -> list[str]:
        paths = [_path_for_model(p) for p in value]
        if len(set(paths)) != len(paths):
            raise ScopeValueError(ErrorCode.SCOPE_006, "allowed_paths must not repeat a path")
        return paths

    @model_validator(mode="after")
    def _one_dimension(self) -> TargetEntry:
        if len(self.schemes) > 1 and len(self.ports) > 1:
            raise ScopeValueError(
                ErrorCode.SCOPE_006,
                "an entry may not have several schemes and several ports: write one entry per pair (D-E22)",
            )
        return self


# ------------------------------------------------------------------------------- AI-system targets ----
class AiLimits(_Model):
    max_model_requests: Annotated[int, Field(ge=1, le=200)]
    max_input_tokens: Annotated[int, Field(ge=1, le=4000)]
    max_output_tokens: Annotated[int, Field(ge=1, le=2000)]
    max_total_tokens: Annotated[int, Field(ge=1, le=200_000)]


class _ForbiddenRules(_Model):
    """Every rule is required and `forbidden` is the only accepted value (D-E29, D-E48)."""

    @field_validator("*")
    @classmethod
    def _forbidden(cls, value: str) -> str:
        if value == "forbidden":
            return value
        if value == "allowed":
            raise ScopeValueError(ErrorCode.SCOPE_011, RULES_NOT_AVAILABLE)
        raise ScopeValueError(ErrorCode.SCOPE_003, "a rule must be exactly 'forbidden'")


class AiRules(_ForbiddenRules):
    tool_invocation: str
    persistent_state_writes: str
    personal_data_in_probes: str
    target_output_to_assistant_model: str


class AiTarget(_Model):
    id: str
    kind: Literal["chat_endpoint", "agent", "rag_service", "mcp_server"]
    layer: str
    environment: Literal["test", "staging", "production"]
    production_approval_ref: str | None = None
    host: str
    scheme: Literal["http", "https"]
    port: int
    api_style: Literal["openai_compatible", "messages", "custom_json"]
    operations: Annotated[list[AiOperation], Field(min_length=1)]
    metadata_paths: Annotated[list[str], Field(max_length=5)] = []
    probe_path: str | None = None
    probe_sets: list[str] = []
    test_categories: list[AiCategory] = []
    limits: AiLimits
    rules: AiRules

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _AI_ID.fullmatch(value):
            raise ScopeValueError(
                ErrorCode.SCOPE_003, "id must be 2 to 40 characters of a-z, 0-9 and -, starting with a letter or digit"
            )
        return value

    @field_validator("layer")
    @classmethod
    def _layer(cls, value: str) -> str:
        if value != "application":
            raise ScopeValueError(
                ErrorCode.SCOPE_011,
                "only the application layer can be tested: a model provider's own service is out of scope",
            )
        return value

    @field_validator("production_approval_ref")
    @classmethod
    def _production_ref(cls, value: str | None) -> str | None:
        if value is not None and not _APPROVAL_REF.fullmatch(value):
            raise ScopeValueError(
                ErrorCode.SCOPE_003,
                "production_approval_ref must be 3 to 128 characters of letters, digits and . _ : / # -",
            )
        return value

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        return _host_for_model(value)

    @field_validator("port")
    @classmethod
    def _port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ScopeValueError(ErrorCode.SCOPE_006, "port must be an integer from 1 to 65535")
        return value

    @field_validator("operations", "probe_sets", "test_categories")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ScopeValueError(ErrorCode.SCOPE_003, "a list may not repeat a value")
        return value

    @field_validator("metadata_paths")
    @classmethod
    def _metadata_paths(cls, value: list[str]) -> list[str]:
        paths = [_path_for_model(p) for p in value]
        if len(set(paths)) != len(paths):
            raise ScopeValueError(ErrorCode.SCOPE_006, "metadata_paths must not repeat a path")
        return paths

    @field_validator("probe_path")
    @classmethod
    def _probe_path(cls, value: str | None) -> str | None:
        return None if value is None else _path_for_model(value)

    @model_validator(mode="after")
    def _consistent(self) -> AiTarget:
        if (self.environment == "production") != (self.production_approval_ref is not None):
            raise ScopeValueError(
                ErrorCode.SCOPE_011,
                "production_approval_ref is required for environment production and accepted only there",
            )
        wants_metadata, wants_probe = "ai_metadata" in self.operations, "ai_probe" in self.operations
        if wants_metadata != bool(self.metadata_paths):
            raise ScopeValueError(
                ErrorCode.SCOPE_009, "metadata_paths are required for ai_metadata and valid only with it"
            )
        probe_fields = (self.probe_path is not None, bool(self.probe_sets), bool(self.test_categories))
        if wants_probe != all(probe_fields) or (not wants_probe and any(probe_fields)):
            raise ScopeValueError(
                ErrorCode.SCOPE_009,
                "probe_path, probe_sets and test_categories are required for ai_probe and valid only with it",
            )
        for set_id in self.probe_sets:
            probe_set = PROBE_SETS.get(set_id)
            if probe_set is None:
                raise ScopeValueError(
                    ErrorCode.SCOPE_011, "a probe set must be one of the reviewed library; a scope cannot define one"
                )
            if probe_set.category not in self.test_categories:
                raise ScopeValueError(
                    ErrorCode.SCOPE_011,
                    f"probe set {set_id} is in category {probe_set.category}, which this target does not authorize",
                )
        requests = self.probe_requests
        if requests > self.limits.max_model_requests:
            raise ScopeValueError(
                ErrorCode.SCOPE_007,
                f"the probe sets need {requests} requests but max_model_requests is {self.limits.max_model_requests}",
            )
        if self.worst_case_tokens > self.limits.max_total_tokens:
            raise ScopeValueError(
                ErrorCode.SCOPE_007,
                f"the worst case is {self.worst_case_tokens} tokens "
                f"but max_total_tokens is {self.limits.max_total_tokens}",
            )
        return self

    @property
    def probe_requests(self) -> int:
        return sum(PROBE_SETS[s].count for s in self.probe_sets) if "ai_probe" in self.operations else 0

    @property
    def worst_case_tokens(self) -> int:
        return self.probe_requests * (self.limits.max_input_tokens + self.limits.max_output_tokens)


# ------------------------------------------------------------------------------------- API targets ----
def _template_for_model(value: str) -> str:
    """A request path in which a whole segment may be `{name}`. The braces are the only addition to a canonical path."""
    if not isinstance(value, str):
        raise ScopeValueError(ErrorCode.SCOPE_006, "a path must be text")
    names: list[str] = []
    for segment in value.split("/")[1:]:
        if "{" in segment or "}" in segment:
            if not _PLACEHOLDER.fullmatch(segment) or not _PARAM_NAME.fullmatch(segment[1:-1]):
                raise ScopeValueError(
                    ErrorCode.SCOPE_006, "{name} must be a whole path segment, with a name of a-z, 0-9 and _"
                )
            names.append(segment[1:-1])
    if len(set(names)) != len(names):
        raise ScopeValueError(ErrorCode.SCOPE_006, "a parameter name may appear once in a path")
    _path_for_model(_PLACEHOLDER.sub("x", value))
    return value


def _placeholders(template: str) -> list[str]:
    return [segment[1:-1] for segment in template.split("/")[1:] if _PLACEHOLDER.fullmatch(segment)]


def _join(base_path: str, path: str) -> str:
    return path if base_path == "/" else base_path.rstrip("/") + path


class ApiLimits(_Model):
    max_api_requests: Annotated[int, Field(ge=1, le=400)]
    max_response_bytes: Annotated[int, Field(ge=1024, le=1_000_000)]


class ApiRules(_ForbiddenRules):
    state_changing_methods: str
    enumeration_or_fuzzing: str
    response_values_in_evidence: str
    spec_widens_scope: str


class ApiPrincipal(_Model):
    id: str
    label: str

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _API_ID.fullmatch(value):
            raise ScopeValueError(
                ErrorCode.SCOPE_003, "id must be 2 to 40 characters of a-z, 0-9 and -, starting with a letter or digit"
            )
        if value == ANONYMOUS:
            raise ScopeValueError(ErrorCode.SCOPE_003, "the principal anonymous always exists: do not list it")
        return value

    @field_validator("label")
    @classmethod
    def _label(cls, value: str) -> str:
        if not _LABEL_TEXT.fullmatch(value):
            raise ScopeValueError(
                ErrorCode.SCOPE_003, "a label is 1 to 80 characters of letters, digits, space and , . : ( ) _ / -"
            )
        return value


class ApiEndpoint(_Model):
    id: str
    method: str
    path: str
    params: dict[str, list[str]] = {}
    principals: Annotated[list[str], Field(min_length=1, max_length=4)]
    expect_auth: Literal["required", "none", "unknown"]

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _API_ID.fullmatch(value):
            raise ScopeValueError(
                ErrorCode.SCOPE_003, "id must be 2 to 40 characters of a-z, 0-9 and -, starting with a letter or digit"
            )
        return value

    @field_validator("method")
    @classmethod
    def _method(cls, value: str) -> str:
        if value not in ("GET", "HEAD"):
            raise ScopeValueError(
                ErrorCode.SCOPE_011, "state-changing or unsupported methods are not available in this version"
            )
        return value

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return _template_for_model(value)

    @field_validator("params")
    @classmethod
    def _params(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        if len(value) > MAX_PARAMS:
            raise ScopeValueError(ErrorCode.SCOPE_007, f"an endpoint may have at most {MAX_PARAMS} parameters")
        for name, values in value.items():
            if not _PARAM_NAME.fullmatch(name):
                raise ScopeValueError(ErrorCode.SCOPE_006, "a parameter name is a-z, 0-9 and _, starting with a letter")
            if not 1 <= len(values) <= 5 or len(set(values)) != len(values):
                raise ScopeValueError(ErrorCode.SCOPE_007, "a parameter lists 1 to 5 different values: no ranges")
            if any(not _PARAM_VALUE.fullmatch(v) for v in values):
                raise ScopeValueError(
                    ErrorCode.SCOPE_006, "a parameter value is 1 to 64 characters of letters, digits and . _ ~ -"
                )
        return value

    @field_validator("principals")
    @classmethod
    def _principals(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ScopeValueError(ErrorCode.SCOPE_009, "an endpoint may not list a principal twice")
        return value

    @model_validator(mode="after")
    def _params_match_the_path(self) -> ApiEndpoint:
        if set(_placeholders(self.path)) != set(self.params):
            raise ScopeValueError(
                ErrorCode.SCOPE_006, "every {name} in the path needs a params list, and every params list a {name}"
            )
        return self

    @property
    def combination_count(self) -> int:
        return math.prod(len(self.params[name]) for name in _placeholders(self.path))

    def combinations(self) -> list[tuple[tuple[str, str], ...]]:
        """Every listed value for every parameter, parameters in the order the path names them, values as listed."""
        names = _placeholders(self.path)
        return [tuple(zip(names, values, strict=True)) for values in product(*(self.params[n] for n in names))]


def resolve_path(base_path: str, template: str, values: tuple[tuple[str, str], ...]) -> str:
    """The exact request path of one endpoint call: the base path, then the template with each {name} filled in."""
    chosen = dict(values)
    segments = [chosen[s[1:-1]] if _PLACEHOLDER.fullmatch(s) else s for s in template.split("/")[1:]]
    return _join(base_path, "/" + "/".join(segments))


class ApiTarget(_Model):
    id: str
    kind: Literal["rest"]
    environment: Literal["test", "staging", "production"]
    production_approval_ref: str | None = None
    host: str
    scheme: Literal["http", "https"]
    port: int
    base_path: str
    operations: Annotated[list[ApiOperation], Field(min_length=1)]
    spec_paths: Annotated[list[str], Field(max_length=5)] = []
    principals: Annotated[list[ApiPrincipal], Field(max_length=10)] = []
    endpoints: Annotated[list[ApiEndpoint], Field(max_length=40)] = []
    cors_origins: Annotated[list[str], Field(max_length=3)] = []
    limits: ApiLimits
    rules: ApiRules

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _API_ID.fullmatch(value):
            raise ScopeValueError(
                ErrorCode.SCOPE_003, "id must be 2 to 40 characters of a-z, 0-9 and -, starting with a letter or digit"
            )
        return value

    @field_validator("production_approval_ref")
    @classmethod
    def _production_ref(cls, value: str | None) -> str | None:
        if value is not None and not _APPROVAL_REF.fullmatch(value):
            raise ScopeValueError(
                ErrorCode.SCOPE_003,
                "production_approval_ref must be 3 to 128 characters of letters, digits and . _ : / # -",
            )
        return value

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        return _host_for_model(value)

    @field_validator("port")
    @classmethod
    def _port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ScopeValueError(ErrorCode.SCOPE_006, "port must be an integer from 1 to 65535")
        return value

    @field_validator("base_path")
    @classmethod
    def _base_path(cls, value: str) -> str:
        return _path_for_model(value)

    @field_validator("operations")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ScopeValueError(ErrorCode.SCOPE_003, "a list may not repeat a value")
        return value

    @field_validator("spec_paths")
    @classmethod
    def _spec_paths(cls, value: list[str]) -> list[str]:
        paths = [_path_for_model(p) for p in value]
        if len(set(paths)) != len(paths):
            raise ScopeValueError(ErrorCode.SCOPE_006, "spec_paths must not repeat a path")
        return paths

    @field_validator("cors_origins")
    @classmethod
    def _origins(cls, value: list[str]) -> list[str]:
        for origin in value:
            match = _ORIGIN.fullmatch(origin)
            if match is None:
                raise ScopeValueError(
                    ErrorCode.SCOPE_006, "an origin is https://host or https://host:port, nothing more"
                )
            _host_for_model_exact(match.group(1))
            if match.group(2) is not None and (not 1 <= int(match.group(2)) <= 65535 or match.group(2) == "443"):
                raise ScopeValueError(ErrorCode.SCOPE_006, "an origin port is 1 to 65535, and not 443 (it is implied)")
        if len(set(value)) != len(value):
            raise ScopeValueError(ErrorCode.SCOPE_003, "a list may not repeat a value")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> ApiTarget:
        self._check_fields()
        self._check_principals()
        self._check_size()
        return self

    def _check_fields(self) -> None:
        if (self.environment == "production") != (self.production_approval_ref is not None):
            raise ScopeValueError(
                ErrorCode.SCOPE_011,
                "production_approval_ref is required for environment production and accepted only there",
            )
        wants = set(self.operations)
        for present, needed, name in (
            (bool(self.spec_paths), "api_spec" in wants, "spec_paths"),
            (bool(self.cors_origins), "api_options" in wants, "cors_origins"),
            (bool(self.endpoints), bool(wants & {"api_read", "api_options"}), "endpoints"),
        ):
            if present != needed:
                raise ScopeValueError(
                    ErrorCode.SCOPE_009, f"{name} are required for their operation and valid only with it"
                )

    def _check_principals(self) -> None:
        ids = [p.id for p in self.principals]
        if len(set(ids)) != len(ids):
            raise ScopeValueError(ErrorCode.SCOPE_009, "two principals share an id")
        known = {ANONYMOUS, *ids}
        endpoint_ids = [e.id for e in self.endpoints]
        if len(set(endpoint_ids)) != len(endpoint_ids):
            raise ScopeValueError(ErrorCode.SCOPE_005, "two endpoints share an id")
        for endpoint in self.endpoints:
            if not set(endpoint.principals) <= known:
                raise ScopeValueError(ErrorCode.SCOPE_009, "an endpoint lists a principal this target does not define")

    def _check_size(self) -> None:
        lengths = [len(path) for path in self.spec_paths]
        for (
            endpoint
        ) in self.endpoints:  # the longest path each endpoint can be asked at, with its longest values filled in
            lengths.append(
                len(_join(self.base_path, endpoint.path))
                + sum(max(len(v) for v in endpoint.params[n]) - len(n) - 2 for n in endpoint.params)
            )
        longest = max(lengths, default=0)
        if longest > MAX_PATH:
            raise ScopeValueError(ErrorCode.SCOPE_006, "a request path would be longer than 256 characters")
        origin = max((len(o) for o in self.cors_origins), default=0)
        if len(self.host) + longest + origin > 400:  # keeps the recorded request line within its 512-character field
            raise ScopeValueError(
                ErrorCode.SCOPE_006, "the host, the longest path and the origin are too long together"
            )
        if self.request_count > self.limits.max_api_requests:
            raise ScopeValueError(
                ErrorCode.SCOPE_007,
                f"the plan needs {self.request_count} requests but max_api_requests is {self.limits.max_api_requests}",
            )

    @property
    def request_count(self) -> int:
        ops = set(self.operations)
        spec = len(self.spec_paths) if "api_spec" in ops else 0
        reads = sum(e.combination_count * len(e.principals) for e in self.endpoints) if "api_read" in ops else 0
        options = len(self.endpoints) * len(self.cors_origins) if "api_options" in ops else 0
        return spec + reads + options


class ScopeConfig(_Model):
    engagement_id: str
    owner_approval_ref: str
    expires_at: datetime
    mode: Literal["offline", "live"] = "offline"
    allowed_targets: Annotated[list[TargetEntry], Field(max_length=20)]
    ai_targets: Annotated[list[AiTarget], Field(max_length=10)] = []
    api_targets: Annotated[list[ApiTarget], Field(max_length=10)] = []
    allowed_operations: Annotated[list[OperationKind], Field(min_length=1)]
    max_requests: Annotated[int, Field(ge=1, le=500)]
    max_parallelism: Annotated[int, Field(ge=1, le=4)] = 2
    per_request_timeout_seconds: Annotated[int, Field(ge=1, le=30)] = 5
    max_response_bytes: Annotated[int, Field(ge=1024, le=1_000_000)] = 100_000
    follow_redirects: bool = False

    @field_validator("engagement_id", mode="before")
    @classmethod
    def _engagement_id(cls, value: object) -> object:
        if isinstance(value, str) and not _ENGAGEMENT_ID.fullmatch(value):
            raise ScopeValueError(
                ErrorCode.SCOPE_003,
                "engagement_id must be 3 to 64 characters of a-z, 0-9, . _ - starting with a letter or digit",
            )
        return value

    @field_validator("owner_approval_ref", mode="before")
    @classmethod
    def _approval(cls, value: object) -> object:
        if isinstance(value, str) and not _APPROVAL_REF.fullmatch(value):
            raise ScopeValueError(
                ErrorCode.SCOPE_003, "owner_approval_ref must be 3 to 128 characters of letters, digits and . _ : / # -"
            )
        return value

    @field_validator("expires_at", mode="before")
    @classmethod
    def _expires(cls, value: object) -> datetime:
        return _parse_expiry(value)

    @field_validator("allowed_operations")
    @classmethod
    def _operations(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ScopeValueError(ErrorCode.SCOPE_003, "allowed_operations must not repeat an operation")
        return value

    @field_validator("follow_redirects")
    @classmethod
    def _no_redirects(cls, value: bool) -> bool:
        if value:
            raise ScopeValueError(
                ErrorCode.SCOPE_008, "follow_redirects must be false: redirects are recorded, never followed (D-E03)"
            )
        return value

    @model_validator(mode="after")
    def _cross_field(self) -> ScopeConfig:
        if not self.allowed_targets and not self.ai_targets and not self.api_targets:
            raise ScopeValueError(ErrorCode.SCOPE_007, "a scope needs at least one target")
        self._check_web_targets()
        self._check_ai_targets()
        self._check_api_targets()
        return self

    def _check_web_targets(self) -> None:
        seen: set[tuple[str, str, int]] = set()
        for entry in self.allowed_targets:
            for scheme in entry.schemes:
                for port in entry.ports:
                    key = (scheme, entry.host, port)
                    if key in seen:
                        raise ScopeValueError(
                            ErrorCode.SCOPE_005, "two entries name the same scheme, host and port: they are not merged"
                        )
                    seen.add(key)
        allowed = set(self.allowed_operations)
        if "dns_metadata" in allowed and not self.allowed_targets:
            raise ScopeValueError(ErrorCode.SCOPE_009, "dns_metadata is allowed but no web target is listed")
        if "tls_metadata" in allowed and not any("https" in e.schemes for e in self.allowed_targets):
            raise ScopeValueError(ErrorCode.SCOPE_009, "tls_metadata is allowed but no target uses https")
        if "http_metadata" in allowed and not any(e.allowed_paths for e in self.allowed_targets):
            raise ScopeValueError(ErrorCode.SCOPE_009, "http_metadata is allowed but no target lists an allowed path")

    def _check_ai_targets(self) -> None:
        ids: set[str] = set()
        endpoints: set[tuple[str, str, int]] = set()
        for ai in self.ai_targets:
            endpoint = (ai.scheme, ai.host, ai.port)
            if ai.id in ids or endpoint in endpoints:
                raise ScopeValueError(
                    ErrorCode.SCOPE_005, "two AI targets share an id or an endpoint: they are not merged"
                )
            ids.add(ai.id)
            endpoints.add(endpoint)
        allowed = set(self.allowed_operations)
        used_by_ai = {op for ai in self.ai_targets for op in ai.operations}
        if not used_by_ai <= allowed:
            raise ScopeValueError(ErrorCode.SCOPE_009, "an AI target uses an operation the scope does not allow")
        for kind in ("ai_metadata", "ai_probe"):
            if kind in allowed and kind not in used_by_ai:
                raise ScopeValueError(ErrorCode.SCOPE_009, f"{kind} is allowed but no AI target uses it")

    def _check_api_targets(self) -> None:
        ids: set[str] = set()
        endpoints: set[tuple[str, str, int]] = set()
        for api in self.api_targets:
            endpoint = (api.scheme, api.host, api.port)
            if api.id in ids or endpoint in endpoints:
                raise ScopeValueError(
                    ErrorCode.SCOPE_005, "two API targets share an id or an endpoint: they are not merged"
                )
            ids.add(api.id)
            endpoints.add(endpoint)
        allowed = set(self.allowed_operations)
        used_by_api = {op for api in self.api_targets for op in api.operations}
        if not used_by_api <= allowed:
            raise ScopeValueError(ErrorCode.SCOPE_009, "an API target uses an operation the scope does not allow")
        for kind in ("api_spec", "api_read", "api_options"):
            if kind in allowed and kind not in used_by_api:
                raise ScopeValueError(ErrorCode.SCOPE_009, f"{kind} is allowed but no API target uses it")


# ----------------------------------------------------------------------------------------- plan ----
@dataclass(frozen=True)
class PlannedOperation:
    kind: str
    host: str
    scheme: str
    port: int
    path: str | None
    target_id: str | None = None
    probe_set: str | None = None
    probe_index: int | None = None
    principal: str | None = None
    endpoint_id: str | None = None
    method: str | None = None
    origin: str | None = None
    params: tuple[tuple[str, str], ...] = ()


def plan_operations(config: ScopeConfig) -> tuple[PlannedOperation, ...]:
    """Per entry in file order: one DNS lookup per distinct host, one TLS handshake per https port, then each path
    (D-E23)."""
    allowed = set(config.allowed_operations)
    operations: list[PlannedOperation] = []
    seen_hosts: set[str] = set()
    for entry in config.allowed_targets:
        if "dns_metadata" in allowed and entry.host not in seen_hosts:
            operations.append(PlannedOperation("dns_metadata", entry.host, entry.schemes[0], entry.ports[0], None))
        seen_hosts.add(entry.host)
        if "tls_metadata" in allowed and "https" in entry.schemes:
            operations.extend(PlannedOperation("tls_metadata", entry.host, "https", port, None) for port in entry.ports)
        if "http_metadata" in allowed:
            for scheme in entry.schemes:
                for port in entry.ports:
                    operations.extend(
                        PlannedOperation("http_metadata", entry.host, scheme, port, path)
                        for path in entry.allowed_paths
                    )
    for ai in config.ai_targets:  # after every web entry; an AI target plans no dns, tls or http operation (D-E34)
        if "ai_metadata" in ai.operations:
            operations.extend(
                PlannedOperation("ai_metadata", ai.host, ai.scheme, ai.port, path, ai.id) for path in ai.metadata_paths
            )
        if "ai_probe" in ai.operations:
            for set_id in ai.probe_sets:
                operations.extend(
                    PlannedOperation("ai_probe", ai.host, ai.scheme, ai.port, ai.probe_path, ai.id, set_id, index)
                    for index in range(PROBE_SETS[set_id].count)
                )
    for api in config.api_targets:  # after every web and AI entry; an API target plans no dns, tls or http operation
        operations.extend(plan_api_target(api))
    return tuple(operations)


def plan_api_target(api: ApiTarget) -> list[PlannedOperation]:
    """Its spec reads, then each endpoint in file order with each combination of its parameter lists and each principal,
    then each endpoint's OPTIONS once per origin (the first listed value of each parameter) (docs/api-targets.md)."""
    where = (api.host, api.scheme, api.port)
    planned: list[PlannedOperation] = []
    if "api_spec" in api.operations:
        planned.extend(
            PlannedOperation("api_spec", *where, path, api.id, principal=ANONYMOUS, method="GET")
            for path in api.spec_paths
        )
    if "api_read" in api.operations:
        for endpoint in api.endpoints:
            for values in endpoint.combinations():
                planned.extend(
                    PlannedOperation(
                        "api_read",
                        *where,
                        resolve_path(api.base_path, endpoint.path, values),
                        api.id,
                        principal=principal,
                        endpoint_id=endpoint.id,
                        method=endpoint.method,
                        params=values,
                    )
                    for principal in endpoint.principals
                )
    if "api_options" in api.operations:
        for endpoint in api.endpoints:
            values = endpoint.combinations()[0]
            planned.extend(
                PlannedOperation(
                    "api_options",
                    *where,
                    resolve_path(api.base_path, endpoint.path, values),
                    api.id,
                    principal=ANONYMOUS,
                    endpoint_id=endpoint.id,
                    method="OPTIONS",
                    origin=origin,
                    params=values,
                )
                for origin in api.cors_origins
            )
    return planned


# ------------------------------------------------------------------------------------ hash/load ----
@dataclass(frozen=True)
class LoadedScope:
    config: ScopeConfig
    sha256: str
    canonical_json: str
    planned: tuple[PlannedOperation, ...]


def _normalised_ai(ai: AiTarget) -> dict[str, Any]:
    return {
        "id": ai.id,
        "kind": ai.kind,
        "layer": ai.layer,
        "environment": ai.environment,
        "production_approval_ref": ai.production_approval_ref,
        "host": ai.host,
        "scheme": ai.scheme,
        "port": ai.port,
        "api_style": ai.api_style,
        "operations": list(ai.operations),
        "metadata_paths": list(ai.metadata_paths),
        "probe_path": ai.probe_path,
        "probe_sets": list(ai.probe_sets),
        "test_categories": list(ai.test_categories),
        "limits": ai.limits.model_dump(),
        "rules": ai.rules.model_dump(),
    }


def _normalised_api(api: ApiTarget) -> dict[str, Any]:
    return {
        "id": api.id,
        "kind": api.kind,
        "environment": api.environment,
        "production_approval_ref": api.production_approval_ref,
        "host": api.host,
        "scheme": api.scheme,
        "port": api.port,
        "base_path": api.base_path,
        "operations": list(api.operations),
        "spec_paths": list(api.spec_paths),
        "principals": [{"id": p.id, "label": p.label} for p in api.principals],
        "endpoints": [
            {
                "id": e.id,
                "method": e.method,
                "path": e.path,
                "params": {name: list(values) for name, values in e.params.items()},
                "principals": list(e.principals),
                "expect_auth": e.expect_auth,
            }
            for e in api.endpoints
        ],
        "cors_origins": list(api.cors_origins),
        "limits": api.limits.model_dump(),
        "rules": api.rules.model_dump(),
    }


def normalised(config: ScopeConfig) -> dict[str, Any]:
    """The scope as it is hashed: defaults filled in, hosts canonical, the expiry in UTC, lists in the order given.

    `ai_targets` and `api_targets` are left out when empty, so a scope written before they existed keeps its hash.
    """
    result: dict[str, Any] = {
        "engagement_id": config.engagement_id,
        "owner_approval_ref": config.owner_approval_ref,
        "expires_at": config.expires_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": config.mode,
        "allowed_targets": [
            {"host": e.host, "schemes": list(e.schemes), "ports": list(e.ports), "allowed_paths": list(e.allowed_paths)}
            for e in config.allowed_targets
        ],
        "allowed_operations": list(config.allowed_operations),
        "max_requests": config.max_requests,
        "max_parallelism": config.max_parallelism,
        "per_request_timeout_seconds": config.per_request_timeout_seconds,
        "max_response_bytes": config.max_response_bytes,
        "follow_redirects": config.follow_redirects,
    }
    if config.ai_targets:
        result["ai_targets"] = [_normalised_ai(ai) for ai in config.ai_targets]
    if config.api_targets:
        result["api_targets"] = [_normalised_api(api) for api in config.api_targets]
    return result


def _location(loc: tuple[Any, ...]) -> str | None:
    parts = ""
    for item in loc:
        parts += f"[{item}]" if isinstance(item, int) else (f".{item}" if parts else str(item))
    return safe_text(parts, 120) or None


def _convert(exc: ValidationError) -> ScopeError:
    error = exc.errors()[0]
    original = (error.get("ctx") or {}).get("error")
    path = _location(error["loc"])
    if isinstance(original, ScopeValueError):
        return ScopeError(original.code, str(original), path=path)
    code = ErrorCode.SCOPE_007 if error["type"] in _CONSTRAINT_ERRORS else ErrorCode.SCOPE_003
    return ScopeError(code, safe_text(error["msg"], 200), path=path)


def check_not_expired(expires_at: datetime, now: datetime) -> None:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if now >= expires_at:
        raise ScopeError(ErrorCode.SCOPE_004, "the scope has expired", path="expires_at")


def parse_scope(text: str, *, now: datetime) -> LoadedScope:
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError:
        raise ScopeError(ErrorCode.SCOPE_001, "the scope is not valid text") from None
    if size > MAX_SCOPE_BYTES:
        raise ScopeError(ErrorCode.SCOPE_001, f"the scope is too large (limit {MAX_SCOPE_BYTES // 1024} KiB)")
    try:
        data = strict_load(text)
    except StrictYamlError as exc:
        code = ErrorCode.SCOPE_002 if exc.kind == "forbidden" else ErrorCode.SCOPE_001
        raise ScopeError(code, exc.message) from None
    if not isinstance(data, dict):
        raise ScopeError(ErrorCode.SCOPE_003, "a scope must be a YAML mapping")
    try:
        config = ScopeConfig.model_validate(data)
    except ValidationError as exc:
        raise _convert(exc) from None
    check_not_expired(config.expires_at, now)
    if config.expires_at > now + timedelta(days=MAX_EXPIRY_DAYS):
        raise ScopeError(
            ErrorCode.SCOPE_004, f"the scope may expire at most {MAX_EXPIRY_DAYS} days ahead", path="expires_at"
        )
    canonical = json.dumps(normalised(config), sort_keys=True, separators=(",", ":"))
    import hashlib  # noqa: PLC0415

    return LoadedScope(
        config, hashlib.sha256(canonical.encode("ascii")).hexdigest(), canonical, plan_operations(config)
    )


def load_scope(path: Path, *, now: datetime) -> LoadedScope:
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ScopeError(ErrorCode.SCOPE_001, "the scope path is not a regular file")
        with path.open("rb") as handle:
            raw = handle.read(MAX_SCOPE_BYTES + 1)
    except OSError:
        raise ScopeError(ErrorCode.SCOPE_001, "the scope file could not be read") from None
    if len(raw) > MAX_SCOPE_BYTES:
        raise ScopeError(ErrorCode.SCOPE_001, f"the scope is too large (limit {MAX_SCOPE_BYTES // 1024} KiB)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ScopeError(ErrorCode.SCOPE_001, "the scope is not valid UTF-8 text") from None
    if any(
        unicodedata.category(ch) == "Cs" for ch in text
    ):  # pragma: no cover - utf-8 decoding cannot yield surrogates
        raise ScopeError(ErrorCode.SCOPE_001, "the scope is not valid text")
    return parse_scope(text, now=now)
