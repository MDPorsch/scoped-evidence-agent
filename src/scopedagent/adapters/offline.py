"""The offline adapters: they answer a planned operation from a fixture pack, and never open a socket (D-E01).

Every answer passes the same path: validate the entry, clean control characters from structured text, redact,
cap, parse the few known documents into bounded facts, and build an observation that the strict schemas accept.
A malformed entry becomes a recorded parse error for that operation, a missing one an adapter error, an oversize
one a size-limit error: nothing is ever an empty success (AE-10, AE-13).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from scopedagent.adapters.base import Adapter, AdapterResult
from scopedagent.adapters.pack import Pack
from scopedagent.adapters.parse import (
    ParseFailure,
    ai_flags,
    allow_methods,
    api_markers,
    api_spec_summary,
    chat_completion,
    json_shape,
    models_summary,
    openapi_summary,
    robots_summary,
    security_txt_summary,
)
from scopedagent.domain.outcome import ErrorStatus
from scopedagent.domain.schemas import ObservationEnvelope
from scopedagent.logs import safe_text
from scopedagent.pipeline.redact import redact_headers_counted, redact_text
from scopedagent.policy.probes import PROBE_SETS
from scopedagent.policy.scope import PlannedOperation, ScopeConfig

_HEADER_NAME = re.compile(r"[a-z0-9_-]{1,64}")
_MIME = re.compile(r"[a-z0-9][a-z0-9.+-]{0,62}/[a-z0-9][a-z0-9.+-]{0,62}")
_DNS_STATUS = {
    "ok": ErrorStatus.OK,
    "nxdomain": ErrorStatus.OK,
    "no_data": ErrorStatus.OK,
    "timeout": ErrorStatus.TIMEOUT,
    "error": ErrorStatus.DNS_FAILURE,
}
_TLS_STATUS = {
    "ok": ErrorStatus.OK,
    "handshake_failed": ErrorStatus.TLS_FAILURE,
    "timeout": ErrorStatus.TIMEOUT,
    "error": ErrorStatus.ADAPTER_ERROR,
}
_ADAPTER = {
    "dns_metadata": "offline_dns",
    "tls_metadata": "offline_tls",
    "http_metadata": "offline_http",
    "ai_metadata": "offline_ai",
    "ai_probe": "offline_ai",
    "api_spec": "offline_api",
    "api_read": "offline_api",
    "api_options": "offline_api",
}


class _Failure(Exception):
    """An operation that cannot produce an answer: it becomes an error observation with this status."""

    def __init__(self, status: ErrorStatus) -> None:
        super().__init__(status.value)
        self.status = status


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized_input(op: PlannedOperation) -> str:
    """The request an operation answers, in one stable line (hashed for idempotency)."""
    if op.kind == "dns_metadata":
        return f"dns {op.host}"
    if op.kind == "tls_metadata":
        return f"tls {op.host}:{op.port}"
    if op.kind == "ai_probe":
        return f"PROBE {op.target_id} {op.probe_set} {op.probe_index}"
    if op.kind.startswith("api_"):
        line = f"API {op.principal} {op.method} {op.scheme}://{op.host}:{op.port}{op.path}"
        return f"{line} origin={op.origin}" if op.origin else line
    return f"GET {op.scheme}://{op.host}:{op.port}{op.path}"


def _envelope(op: PlannedOperation, status: ErrorStatus, payload: dict[str, Any]) -> ObservationEnvelope:
    return ObservationEnvelope.model_validate(
        {
            "adapter": _ADAPTER[op.kind],
            "observation_type": op.kind,
            "target": {"host": op.host, "scheme": op.scheme, "port": op.port},
            "normalized_input": normalized_input(op),
            "error_status": status.value,
            "payload": payload,
        }
    )


def _error_payload(op: PlannedOperation, status: ErrorStatus) -> dict[str, Any]:
    if op.kind == "dns_metadata":
        return {"host": op.host, "status": "timeout" if status is ErrorStatus.TIMEOUT else "error", "records": {}}
    if op.kind == "tls_metadata":
        tls = {ErrorStatus.TIMEOUT: "timeout", ErrorStatus.TLS_FAILURE: "handshake_failed"}.get(status, "error")
        return {"host": op.host, "port": op.port, "status": tls, "tls_version": None, "certificate": None}
    if op.kind == "ai_probe":
        return _probe_payload(op, http_status=None)
    if op.kind.startswith("api_"):
        return _api_payload(op)
    base = {
        "host": op.host,
        "port": op.port,
        "scheme": op.scheme,
        "path": op.path,
        "http_status": None,
        "headers": {},
        "body": None,
    }
    if op.kind == "ai_metadata":
        return {**base, "model_ids": []}
    return {**base, "method": "GET", "redirect_location": None}


def _api_payload(op: PlannedOperation, **facts: Any) -> dict[str, Any]:
    """The payload of an API operation that has no answer, with what an answer adds laid over it."""
    payload: dict[str, Any] = {
        "api_target_id": op.target_id,
        "host": op.host,
        "port": op.port,
        "scheme": op.scheme,
        "path": op.path,
    }
    if op.kind == "api_spec":
        payload |= {"http_status": None, "headers": {}, "body": None}
    elif op.kind == "api_read":
        payload |= {
            "endpoint_id": op.endpoint_id,
            "principal": op.principal,
            "method": op.method,
            "params": dict(op.params),
            "http_status": None,
            "headers": {},
            "content_type": None,
            "size_bytes": None,
            "truncated": False,
            "shape_status": "none",
            "shape": [],
            "shape_digest": None,
            "flags": None,
        }
    else:
        payload |= {
            "endpoint_id": op.endpoint_id,
            "origin": op.origin,
            "http_status": None,
            "allow": [],
            "cors": None,
        }
    return payload | facts


def error_result(op: PlannedOperation, status: ErrorStatus) -> AdapterResult:
    """An operation that produced no usable answer, recorded as what it is (never as a clean result)."""
    source = _canon({"error": status.value, "input": normalized_input(op)})
    return AdapterResult(_envelope(op, status, _error_payload(op, status)), source)


def _probe_payload(op: PlannedOperation, *, http_status: int | None, **facts: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ai_target_id": op.target_id,
        "probe_set": op.probe_set,
        "probe_index": op.probe_index,
        "category": PROBE_SETS[op.probe_set or ""].category,
        "http_status": http_status,
        "input_tokens": None,
        "output_tokens": None,
        "finish_reason": None,
        "output_chars": None,
        "canary_present": None,
        "flags": None,
        "artifact_sha256": None,
    }
    payload.update(facts)
    return payload


# ------------------------------------------------------------------------------------- an HTTP-style exchange ----
@dataclass(frozen=True)
class _Exchange:
    status: int
    headers: dict[str, list[str]]
    location: str | None
    content_type: str | None
    artifact: bytes | None  # the redacted text, or a placeholder for content that is not stored
    artifact_status: str
    artifact_mime: str | None
    size_bytes: int
    truncated: bool
    raw_text: str | None  # what was received (never stored): needed to measure a reply before it is redacted
    redacted_text: str | None
    redactions: int
    source: bytes


def _text_of(kept: bytes, truncated: bool) -> str | None:
    for drop in range(4 if truncated else 1):  # a cut can end inside one multi-byte character
        try:
            return kept[: len(kept) - drop].decode("utf-8")
        except UnicodeDecodeError:
            continue
    return None


def _raw_body(entry: dict[str, Any]) -> bytes | None:
    text, encoded = entry.get("body"), entry.get("body_base64")
    if text is not None and encoded is not None:
        raise _Failure(ErrorStatus.PARSE_ERROR)
    try:
        if encoded is not None:
            if not isinstance(encoded, str):
                raise _Failure(ErrorStatus.PARSE_ERROR)
            return base64.b64decode(encoded, validate=True)
        if text is not None:
            if not isinstance(text, str):
                raise _Failure(ErrorStatus.PARSE_ERROR)
            return text.encode("utf-8")
    except (binascii.Error, ValueError):
        raise _Failure(ErrorStatus.PARSE_ERROR) from None
    return None


def _exchange(entry: dict[str, Any], *, max_bytes: int, own_host: str) -> _Exchange:
    status = entry.get("status")
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        raise _Failure(ErrorStatus.PARSE_ERROR)
    raw_headers = entry.get("headers", {})
    if not isinstance(raw_headers, dict):
        raise _Failure(ErrorStatus.PARSE_ERROR)
    incoming: dict[str, list[str]] = {}
    for name, values in raw_headers.items():
        if not isinstance(name, str) or not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise _Failure(ErrorStatus.PARSE_ERROR)
        if not _HEADER_NAME.fullmatch(name.lower()):
            raise _Failure(ErrorStatus.PARSE_ERROR)
        incoming.setdefault(name.lower(), []).extend(values)
    if len(incoming) > 64 or any(len(v) > 64 or any(len(x) > 4096 for x in v) for v in incoming.values()):
        raise _Failure(ErrorStatus.SIZE_LIMIT)
    headers, redactions = redact_headers_counted(
        {k: [safe_text(x, 4096) for x in v] for k, v in incoming.items()}, own_host=own_host
    )
    location = headers["location"][0][:2048] if 300 <= status <= 399 and headers.get("location") else None
    content_type = headers["content-type"][0] if headers.get("content-type") else None

    raw = _raw_body(entry)
    artifact: bytes | None = None
    artifact_status, mime, size, truncated = "redacted", None, 0, False
    raw_text = redacted_text = None
    if raw:
        truncated = len(raw) > max_bytes
        kept = raw[:max_bytes]
        size = len(kept)
        compressed = any(e.strip().lower() not in ("", "identity") for e in incoming.get("content-encoding", []))
        raw_text = None if compressed else _text_of(kept, truncated)  # a compressed body is never decompressed
        if raw_text is None:
            artifact, artifact_status, mime = (
                f"[binary content: {size} bytes, not stored]".encode(),
                "metadata_only",
                "text/plain",
            )
        else:
            result = redact_text(raw_text, own_host=own_host)
            redacted_text, redactions = result.text, redactions + result.count
            artifact = redacted_text.encode("utf-8")
            media = (content_type or "").split(";")[0].strip().lower()
            mime = media if _MIME.fullmatch(media) else "application/octet-stream"
    stored = {**entry, "headers": headers}
    if redacted_text is not None and "body" in entry:
        stored["body"] = redacted_text
    return _Exchange(
        status,
        headers,
        location,
        content_type,
        artifact,
        artifact_status,
        mime,
        size,
        truncated,
        raw_text,
        redacted_text,
        redactions,
        _canon(stored),
    )


def _body_summary(ex: _Exchange, parsed: dict[str, Any] | None) -> dict[str, Any] | None:
    if ex.artifact is None:
        return None
    return {
        "size_bytes": ex.size_bytes,
        "truncated": ex.truncated,
        "content_type": ex.content_type[:255] if ex.content_type else None,
        "artifact_sha256": _sha(ex.artifact),
        "parsed": parsed,
    }


def _declared_error(entry: dict[str, Any]) -> ErrorStatus | None:
    """An answer the pack marks as a failure (a simulated timeout, say). `ok` is not a failure."""
    declared = entry.get("error")
    if declared is None:
        return None
    try:
        status = ErrorStatus(declared)
    except ValueError:
        return ErrorStatus.PARSE_ERROR
    return ErrorStatus.PARSE_ERROR if status is ErrorStatus.OK else status


# ----------------------------------------------------------------------------------------------- the adapters ----
class OfflineDns:
    name, operation = "offline_dns", "dns_metadata"

    def __init__(self, pack: Pack) -> None:
        self._pack = pack

    async def collect(self, operation: PlannedOperation) -> AdapterResult:
        entry = self._pack.dns.get(operation.host)
        if entry is None:
            return error_result(operation, ErrorStatus.ADAPTER_ERROR)
        status = _DNS_STATUS.get(entry.get("status"))  # type: ignore[arg-type]
        records = entry.get("records", {})
        if status is None or not isinstance(records, dict):
            return error_result(operation, ErrorStatus.PARSE_ERROR)
        count, cleaned = 0, {}
        for rtype, values in records.items():
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                return error_result(operation, ErrorStatus.PARSE_ERROR)
            redacted = [redact_text(safe_text(v, 10_000), own_host=operation.host) for v in values]
            count += sum(r.count for r in redacted)
            cleaned[rtype] = [r.text for r in redacted]
        try:
            envelope = _envelope(
                operation, status, {"host": operation.host, "status": entry["status"], "records": cleaned}
            )
        except ValidationError:
            return error_result(operation, ErrorStatus.PARSE_ERROR)
        return AdapterResult(envelope, _canon({**entry, "records": cleaned}), redactions=count)


class OfflineTls:
    name, operation = "offline_tls", "tls_metadata"

    def __init__(self, pack: Pack) -> None:
        self._pack = pack

    async def collect(self, operation: PlannedOperation) -> AdapterResult:
        entry = self._pack.tls.get(f"{operation.host}:{operation.port}")
        if entry is None:
            return error_result(operation, ErrorStatus.ADAPTER_ERROR)
        status = _TLS_STATUS.get(entry.get("status"))  # type: ignore[arg-type]
        certificate = entry.get("certificate")
        if status is None or not (certificate is None or isinstance(certificate, dict)):
            return error_result(operation, ErrorStatus.PARSE_ERROR)
        count, cleaned = 0, certificate
        if isinstance(certificate, dict):
            cleaned = dict(certificate)
            for field in ("subject_cn", "issuer_cn", "signature_algorithm"):
                if isinstance(cleaned.get(field), str):
                    result = redact_text(safe_text(cleaned[field], 10_000), own_host=operation.host)
                    cleaned[field], count = result.text, count + result.count
            if isinstance(cleaned.get("san_dns"), list):
                names: list[Any] = []
                for name in cleaned["san_dns"]:
                    if isinstance(name, str):
                        result = redact_text(safe_text(name, 10_000), own_host=operation.host)
                        names.append(result.text)
                        count += result.count
                    else:
                        names.append(name)  # not text: the schema refuses it and the entry becomes a parse error
                cleaned["san_dns"] = names
        payload = {
            "host": operation.host,
            "port": operation.port,
            "status": entry.get("status"),
            "tls_version": entry.get("version"),
            "certificate": cleaned,
        }
        try:
            envelope = _envelope(operation, status, payload)
        except ValidationError:
            return error_result(operation, ErrorStatus.PARSE_ERROR)
        return AdapterResult(envelope, _canon({**entry, "certificate": cleaned}), redactions=count)


def _key(op: PlannedOperation) -> str:
    return f"{op.scheme}://{op.host}:{op.port}{op.path}"


class OfflineHttp:
    name, operation = "offline_http", "http_metadata"

    def __init__(self, pack: Pack, max_response_bytes: int) -> None:
        self._pack, self._max = pack, max_response_bytes

    async def collect(self, operation: PlannedOperation) -> AdapterResult:
        entry = self._pack.http.get(_key(operation))
        if entry is None:
            return error_result(operation, ErrorStatus.ADAPTER_ERROR)
        if (declared := _declared_error(entry)) is not None:
            return error_result(operation, declared)
        try:
            ex = _exchange(entry, max_bytes=self._max, own_host=operation.host)
        except _Failure as failure:
            return error_result(operation, failure.status)
        outcome, parsed = ErrorStatus.SIZE_LIMIT if ex.truncated else ErrorStatus.OK, None
        if ex.redacted_text is not None and not ex.truncated:
            try:
                parsed = _parse_known(operation.path or "", ex.redacted_text)
            except ParseFailure:
                outcome = ErrorStatus.PARSE_ERROR
        payload = {
            "host": operation.host,
            "port": operation.port,
            "scheme": operation.scheme,
            "path": operation.path,
            "method": "GET",
            "http_status": ex.status,
            "headers": ex.headers,
            "redirect_location": ex.location,
            "body": _body_summary(ex, parsed),
        }
        try:
            envelope = _envelope(operation, outcome, payload)
        except ValidationError:
            return error_result(operation, ErrorStatus.PARSE_ERROR)
        return AdapterResult(envelope, ex.source, ex.artifact, ex.artifact_mime, ex.artifact_status, ex.redactions)  # type: ignore[arg-type]


def _parse_known(path: str, text: str) -> dict[str, Any] | None:
    if path == "/.well-known/security.txt":
        return security_txt_summary(text)
    if path == "/robots.txt":
        return robots_summary(text)
    if path == "/openapi.json":
        return openapi_summary(text)
    return None


class OfflineAiMetadata:
    name, operation = "offline_ai", "ai_metadata"

    def __init__(self, pack: Pack, max_response_bytes: int) -> None:
        self._pack, self._max = pack, max_response_bytes

    async def collect(self, operation: PlannedOperation) -> AdapterResult:
        entry = self._pack.ai.get(_key(operation))
        if entry is None:
            return error_result(operation, ErrorStatus.ADAPTER_ERROR)
        if (declared := _declared_error(entry)) is not None:
            return error_result(operation, declared)
        try:
            ex = _exchange(entry, max_bytes=self._max, own_host=operation.host)
        except _Failure as failure:
            return error_result(operation, failure.status)
        ids: list[str] = []
        outcome, parsed = ErrorStatus.SIZE_LIMIT if ex.truncated else ErrorStatus.OK, None
        if ex.redacted_text is not None and not ex.truncated:
            try:
                ids, parsed = models_summary(ex.redacted_text)
            except ParseFailure:
                outcome = ErrorStatus.PARSE_ERROR
        payload = {
            "host": operation.host,
            "port": operation.port,
            "scheme": operation.scheme,
            "path": operation.path,
            "http_status": ex.status,
            "headers": ex.headers,
            "model_ids": ids,
            "body": _body_summary(ex, parsed),
        }
        try:
            envelope = _envelope(operation, outcome, payload)
        except ValidationError:
            return error_result(operation, ErrorStatus.PARSE_ERROR)
        return AdapterResult(envelope, ex.source, ex.artifact, ex.artifact_mime, ex.artifact_status, ex.redactions)  # type: ignore[arg-type]


class OfflineAiProbe:
    name, operation = "offline_ai", "ai_probe"

    def __init__(self, pack: Pack, config: ScopeConfig, max_response_bytes: int) -> None:
        self._pack, self._max = pack, max_response_bytes
        self._styles = {target.id: target.api_style for target in config.ai_targets}

    async def collect(self, operation: PlannedOperation) -> AdapterResult:
        entry = self._pack.ai.get(f"probe:{operation.target_id}:{operation.probe_set}:{operation.probe_index}")
        if entry is None:
            return error_result(operation, ErrorStatus.ADAPTER_ERROR)
        if (declared := _declared_error(entry)) is not None:
            return error_result(operation, declared)
        try:
            ex = _exchange({**entry, "headers": {}}, max_bytes=self._max, own_host=operation.host)
        except _Failure as failure:
            return error_result(operation, failure.status)
        canary = entry.get("canary")
        if not isinstance(canary, str | type(None)):
            return error_result(operation, ErrorStatus.PARSE_ERROR)
        source = _canon({"canary": canary, "status": ex.status, "body": ex.redacted_text})
        if not 200 <= ex.status < 300:
            return self._result(
                operation, ErrorStatus.HTTP_ERROR, _probe_payload(operation, http_status=ex.status), source
            )
        if ex.truncated:
            return self._result(
                operation, ErrorStatus.SIZE_LIMIT, _probe_payload(operation, http_status=ex.status), source
            )
        try:
            if ex.raw_text is None:
                raise ParseFailure("the reply is not text")
            reply = chat_completion(ex.raw_text, self._styles.get(operation.target_id or "", "openai_compatible"))
        except ParseFailure:
            return self._result(
                operation, ErrorStatus.PARSE_ERROR, _probe_payload(operation, http_status=ex.status), source
            )
        redacted = redact_text(reply.content, own_host=operation.host)
        artifact = redacted.text.encode("utf-8")
        payload = _probe_payload(
            operation,
            http_status=ex.status,
            input_tokens=reply.input_tokens,
            output_tokens=reply.output_tokens,
            finish_reason=reply.finish_reason,
            output_chars=len(reply.content),
            canary_present=(canary in reply.content) if canary else None,
            flags=ai_flags(reply.content),
            artifact_sha256=_sha(artifact) if artifact else None,
        )
        return self._result(operation, ErrorStatus.OK, payload, source, artifact or None, redacted.count)

    @staticmethod
    def _result(
        op: PlannedOperation,
        status: ErrorStatus,
        payload: dict[str, Any],
        source: bytes,
        artifact: bytes | None = None,
        redactions: int = 0,
    ) -> AdapterResult:
        try:
            envelope = _envelope(op, status, payload)
        except ValidationError:
            return error_result(op, ErrorStatus.PARSE_ERROR)
        return AdapterResult(envelope, source, artifact, "text/plain" if artifact else None, "redacted", redactions)


# ------------------------------------------------------------------------------------------- API adapters ----
def _api_key(op: PlannedOperation) -> str:
    key = f"{op.principal}|{op.method}|{op.scheme}://{op.host}:{op.port}{op.path}"
    return f"{key}|{op.origin}" if op.origin else key


class _ApiAdapter:
    """What the three API adapters share: a pack entry per principal and request, and a limit per API target."""

    def __init__(self, pack: Pack, limits: Mapping[str, int]) -> None:
        self._pack, self._limits = pack, limits

    def _exchange(self, op: PlannedOperation) -> _Exchange | AdapterResult:
        entry = self._pack.api.get(_api_key(op))
        if entry is None:
            return error_result(op, ErrorStatus.ADAPTER_ERROR)
        if (declared := _declared_error(entry)) is not None:
            return error_result(op, declared)
        try:
            return _exchange(entry, max_bytes=self._limits[op.target_id or ""], own_host=op.host)
        except _Failure as failure:
            return error_result(op, failure.status)

    @staticmethod
    def _result(
        op: PlannedOperation,
        status: ErrorStatus,
        payload: dict[str, Any],
        source: bytes,
        redactions: int,
        artifact: tuple[bytes | None, str | None, str] = (None, None, "redacted"),
    ) -> AdapterResult:
        try:
            envelope = _envelope(op, status, payload)
        except ValidationError:
            return error_result(op, ErrorStatus.PARSE_ERROR)
        return AdapterResult(envelope, source, artifact[0], artifact[1], artifact[2], redactions)  # type: ignore[arg-type]


class OfflineApiSpec(_ApiAdapter):
    name, operation = "offline_api", "api_spec"

    async def collect(self, operation: PlannedOperation) -> AdapterResult:
        ex = self._exchange(operation)
        if isinstance(ex, AdapterResult):
            return ex
        outcome, parsed = ErrorStatus.SIZE_LIMIT if ex.truncated else ErrorStatus.OK, None
        if ex.redacted_text is not None and not ex.truncated:
            try:
                parsed = api_spec_summary(ex.redacted_text)
            except ParseFailure:
                outcome = ErrorStatus.PARSE_ERROR
        payload = _api_payload(operation, http_status=ex.status, headers=ex.headers, body=_body_summary(ex, parsed))
        return self._result(
            operation, outcome, payload, ex.source, ex.redactions, (ex.artifact, ex.artifact_mime, ex.artifact_status)
        )


class OfflineApiRead(_ApiAdapter):
    """One call as one principal. The body is read in memory to take its shape and three flags, and is then dropped:
    no artifact is stored and the source hash covers the shape, never a value (D-E52)."""

    name, operation = "offline_api", "api_read"

    async def collect(self, operation: PlannedOperation) -> AdapterResult:
        ex = self._exchange(operation)
        if isinstance(ex, AdapterResult):
            return ex
        outcome = ErrorStatus.SIZE_LIMIT if ex.truncated else ErrorStatus.OK
        text = None if ex.truncated or operation.method == "HEAD" else ex.redacted_text
        shape = json_shape(text)
        flags = api_markers(text, shape)
        entries = [{"path": p, "type": k, "length": n} for p, k, n in shape.entries]
        payload = _api_payload(
            operation,
            http_status=ex.status,
            headers=ex.headers,
            content_type=ex.content_type[:255] if ex.content_type else None,
            size_bytes=ex.size_bytes,
            truncated=ex.truncated,
            shape_status=shape.status,
            shape=entries,
            shape_digest=shape.digest,
            flags=flags,
        )
        source = _canon(
            {
                "status": ex.status,
                "headers": ex.headers,
                "size": ex.size_bytes,
                "shape_status": shape.status,
                "shape_digest": shape.digest,
                "flags": flags,
            }
        )
        return self._result(operation, outcome, payload, source, ex.redactions)


class OfflineApiOptions(_ApiAdapter):
    name, operation = "offline_api", "api_options"

    async def collect(self, operation: PlannedOperation) -> AdapterResult:
        ex = self._exchange(operation)
        if isinstance(ex, AdapterResult):
            return ex
        names = (
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
        )
        found = {n: (ex.headers.get(n) or [None])[0] for n in names}
        cors = (
            None
            if all(v is None for v in found.values())
            else dict(
                zip(
                    ("allow_origin", "allow_credentials", "allow_methods", "allow_headers"), found.values(), strict=True
                )
            )
        )
        allow = allow_methods(ex.headers.get("allow", []))
        payload = _api_payload(operation, http_status=ex.status, allow=allow, cors=cors)
        source = _canon({"status": ex.status, "allow": allow, "cors": cors})
        return self._result(operation, ErrorStatus.OK, payload, source, ex.redactions)


def build_adapters(pack: Pack, config: ScopeConfig) -> dict[str, Adapter]:
    """One adapter per operation kind, all reading the same pack."""
    limit = config.max_response_bytes
    api_limits = {api.id: min(limit, api.limits.max_response_bytes) for api in config.api_targets}  # the stricter wins
    return {
        "dns_metadata": OfflineDns(pack),
        "tls_metadata": OfflineTls(pack),
        "http_metadata": OfflineHttp(pack, limit),
        "ai_metadata": OfflineAiMetadata(pack, limit),
        "ai_probe": OfflineAiProbe(pack, config, limit),
        "api_spec": OfflineApiSpec(pack, api_limits),
        "api_read": OfflineApiRead(pack, api_limits),
        "api_options": OfflineApiOptions(pack, api_limits),
    }
