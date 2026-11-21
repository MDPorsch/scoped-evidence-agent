"""What crosses the container boundary, and nothing else (D-E44, docs/remote-live-design.md 4.7).

Controller to container: one `Job` on standard input, sent only after the isolation proof passed. Container to controller: one proof
line on standard output, then a directory of result files. The container is assumed hostile-input-exposed, so the controller treats
everything it returns as untrusted: every model here is strict, bounded, and checked again against what the controller planned.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from scopedagent.domain.schemas import Sha256
from scopedagent.policy.scope import PlannedOperation

MAX_OPERATIONS = 500
MAX_RESULT_BYTES = 256 * 1024  # one result file: an envelope is far smaller than this
MAX_ARTIFACT_BYTES = 1_000_000
MAX_PROOF_BYTES = 16 * 1024
RESULT_NAME = re.compile(r"result-([0-9]{1,4})\.json")
ARTIFACT_NAME = re.compile(r"artifact-([0-9]{1,4})\.bin")
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{1,63}")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


class AllowedPair(_Strict):
    address: str
    port: Annotated[int, Field(ge=1, le=65535)]


class JobOperation(_Strict):
    """One planned operation, with the one address it may be sent to (pinned by the controller; the container resolves nothing)."""

    index: Annotated[int, Field(ge=0, lt=MAX_OPERATIONS)]
    kind: Literal["tls_metadata", "http_metadata", "ai_metadata", "api_spec", "api_read", "api_options"]
    host: str
    scheme: Literal["http", "https"]
    port: Annotated[int, Field(ge=1, le=65535)]
    address: str
    path: str | None
    method: Literal["GET", "HEAD", "OPTIONS"]
    origin: str | None = None
    target_id: str | None = None
    principal: str | None = None
    endpoint_id: str | None = None
    params: dict[str, str] = {}
    credential_env: Annotated[str, Field(pattern=ENV_NAME.pattern)] | None = None

    def planned(self) -> PlannedOperation:
        return PlannedOperation(
            self.kind, self.host, self.scheme, self.port, self.path, self.target_id,
            principal=self.principal, endpoint_id=self.endpoint_id, method=self.method, origin=self.origin,
            params=tuple(self.params.items()),
        )  # fmt: skip


class Job(_Strict):
    version: Literal[1] = 1
    max_response_bytes: Annotated[int, Field(ge=1024, le=1_000_000)]
    per_request_timeout_seconds: Annotated[int, Field(ge=1, le=30)]
    requests_per_second: Annotated[int, Field(ge=1, le=10)]
    operations: Annotated[list[JobOperation], Field(max_length=MAX_OPERATIONS)]


class ProofCheck(_Strict):
    name: Annotated[str, Field(max_length=80)]
    passed: bool
    detail: Annotated[str, Field(max_length=200)]


class Proof(_Strict):
    """The container's own evidence that it is isolated. The controller refuses to continue unless every check passed."""

    version: Literal[1] = 1
    allowed: list[AllowedPair] = Field(max_length=MAX_OPERATIONS)
    checks: Annotated[list[ProofCheck], Field(min_length=1, max_length=32)]


class ArtifactRef(_Strict):
    file: str
    mime: Annotated[str, Field(max_length=255)]
    status: Literal["redacted", "metadata_only"]
    sha256: Sha256
    size: Annotated[int, Field(ge=0, le=MAX_ARTIFACT_BYTES)]


class Result(_Strict):
    """One operation's outcome: the envelope (validated again by the controller), its source hash and an optional artifact."""

    index: Annotated[int, Field(ge=0, lt=MAX_OPERATIONS)]
    envelope: dict[str, Any]
    source_hash: Sha256
    redactions: Annotated[int, Field(ge=0, le=1_000_000)]
    artifact: ArtifactRef | None = None
