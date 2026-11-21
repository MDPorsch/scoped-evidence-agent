"""The scope file: strict parsing, canonical hosts and paths, limits, the hash, and the plan (docs/scope-format.md).

A scope is a restriction, never proof of authorization (D-E02). It is ambiguous-or-refused: there is no best effort.
"""

from __future__ import annotations

import json
import re
import stat
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from scopedagent.errors import ErrorCode, ScopeError
from scopedagent.logs import safe_text
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
_CONSTRAINT_ERRORS = {"greater_than", "greater_than_equal", "less_than", "less_than_equal", "too_short", "too_long"}

OperationKind = Literal["dns_metadata", "tls_metadata", "http_metadata"]


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


class ScopeConfig(_Model):
    engagement_id: str
    owner_approval_ref: str
    expires_at: datetime
    mode: Literal["offline", "live"] = "offline"
    allowed_targets: Annotated[list[TargetEntry], Field(min_length=1, max_length=20)]
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
        if "tls_metadata" in self.allowed_operations and not any("https" in e.schemes for e in self.allowed_targets):
            raise ScopeValueError(ErrorCode.SCOPE_009, "tls_metadata is allowed but no target uses https")
        if "http_metadata" in self.allowed_operations and not any(e.allowed_paths for e in self.allowed_targets):
            raise ScopeValueError(ErrorCode.SCOPE_009, "http_metadata is allowed but no target lists an allowed path")
        return self


# ----------------------------------------------------------------------------------------- plan ----
@dataclass(frozen=True)
class PlannedOperation:
    kind: str
    host: str
    scheme: str
    port: int
    path: str | None


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
    return tuple(operations)


# ------------------------------------------------------------------------------------ hash/load ----
@dataclass(frozen=True)
class LoadedScope:
    config: ScopeConfig
    sha256: str
    canonical_json: str
    planned: tuple[PlannedOperation, ...]


def normalised(config: ScopeConfig) -> dict[str, Any]:
    """The scope as it is hashed: defaults filled in, hosts canonical, the expiry in UTC, lists in the order given."""
    return {
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
