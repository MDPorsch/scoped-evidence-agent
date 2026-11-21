"""Accept what the sandbox returned, or refuse all of it (D-E44, docs/remote-live-design.md 4.7).

The output directory is untrusted. Only `result-N.json` and `artifact-N.bin` files are read; anything else, a link, a directory, a file
over its cap, too many files, an index that was not planned, an envelope that is not valid, one that names a different request
than the controller planned, an artifact whose bytes do not match its hash, or any byte that holds a credential, refuses the whole
directory (`LIVE-004`). Nothing is read from a path the sandbox chose.
"""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from scopedagent.adapters.base import AdapterResult
from scopedagent.adapters.offline import normalized_input
from scopedagent.domain.schemas import ObservationEnvelope
from scopedagent.errors import ErrorCode, LiveFailed
from scopedagent.live.leakguard import LeakGuard, SecretLeak
from scopedagent.live.protocol import (
    ARTIFACT_NAME,
    MAX_ARTIFACT_BYTES,
    MAX_RESULT_BYTES,
    RESULT_NAME,
    Result,
)
from scopedagent.pipeline.redact import redact_text
from scopedagent.policy.scope import PlannedOperation


def _refuse(message: str) -> LiveFailed:
    return LiveFailed(ErrorCode.LIVE_004, f"the sandbox's output was refused: {message}")


def _read(path: Path, limit: int) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise _refuse(f"{path.name} is not a plain file")
    if info.st_size > limit:
        raise _refuse(f"{path.name} is over its size limit")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:  # pragma: no cover - a file that grows between the size check above and this read
        raise _refuse(f"{path.name} is over its size limit")
    return data


@dataclass(frozen=True)
class Accepted:
    results: dict[int, AdapterResult]


def accept_results(
    directory: Path,
    planned: dict[int, PlannedOperation],
    guard: LeakGuard,
) -> Accepted:
    """Every file in `directory` validated against `planned` ({index: the operation the controller asked for})."""
    try:
        names = sorted(p.name for p in directory.iterdir())
    except OSError:
        raise _refuse("the output directory could not be read") from None
    if len(names) > 2 * len(planned):
        raise _refuse("more files than operations")
    results: dict[int, tuple[Result, bytes | None]] = {}
    artifacts: dict[int, bytes] = {}
    for name in names:
        path = directory / name
        result_match, artifact_match = RESULT_NAME.fullmatch(name), ARTIFACT_NAME.fullmatch(name)
        if result_match is not None:
            index = int(result_match.group(1))
            if index not in planned:
                raise _refuse("a result for an operation that was not asked for")
            data = _read(path, MAX_RESULT_BYTES)
            try:
                guard.check(data, where=f"a result file {name}")
                parsed = Result.model_validate(json.loads(data))
            except SecretLeak as exc:
                raise _refuse(str(exc)) from None
            except (ValueError, ValidationError):
                raise _refuse(f"{name} is not a valid result") from None
            if parsed.index != index:
                raise _refuse(f"{name} names a different operation")
            results[index] = (parsed, None)
        elif artifact_match is not None:
            index = int(artifact_match.group(1))
            if index not in planned:
                raise _refuse("an artifact for an operation that was not asked for")
            data = _read(path, MAX_ARTIFACT_BYTES)
            try:
                guard.check(data, where=f"an artifact file {name}")
            except SecretLeak as exc:
                raise _refuse(str(exc)) from None
            artifacts[index] = data
        else:
            raise _refuse("a file that is not a result or an artifact")
    accepted: dict[int, AdapterResult] = {}
    for index, (parsed, _) in results.items():
        accepted[index] = _adapter_result(parsed, planned[index], artifacts.get(index))
    if set(artifacts) - set(results):
        raise _refuse("an artifact with no result")
    return Accepted(accepted)


def _adapter_result(result: Result, op: PlannedOperation, artifact: bytes | None) -> AdapterResult:
    try:
        envelope = ObservationEnvelope.model_validate(result.envelope)
    except ValidationError:
        raise _refuse("an envelope is not valid") from None
    target = envelope.target
    if (
        envelope.observation_type != op.kind
        or (target.host, target.scheme, target.port) != (op.host, op.scheme, op.port)
        or envelope.normalized_input != normalized_input(op)
    ):
        raise _refuse("an envelope names a different request than the one planned")
    body: bytes | None = None
    mime: str | None = None
    status: Literal["redacted", "metadata_only"] = "redacted"
    if (result.artifact is None) != (artifact is None):
        raise _refuse("an artifact and its description do not go together")
    if result.artifact is not None and artifact is not None:
        if hashlib.sha256(artifact).hexdigest() != result.artifact.sha256 or len(artifact) != result.artifact.size:
            raise _refuse("an artifact does not match its hash")
        if result.artifact.file != f"artifact-{result.index}.bin":
            raise _refuse("an artifact names a different file")
        body, mime, status = artifact, result.artifact.mime, result.artifact.status
        if status == "redacted":  # the controller redacts again: the sandbox is not trusted to have done it
            body = redact_text(artifact.decode("utf-8", "replace"), own_host=op.host).text.encode("utf-8")
    # the source hash is the sandbox's own claim: the stored hash is the SHA-256 of that line (docs/remote-live-design.md)
    return AdapterResult(envelope, result.source_hash.encode("ascii"), body, mime, status, result.redactions)
