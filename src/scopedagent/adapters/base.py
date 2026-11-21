"""The typed adapter protocol. An adapter answers ONE planned operation and returns a validated observation.

Adapters get no scope, no database and no network handle: they are handed an operation the policy engine already allowed
and return data. The orchestrator (M2) reserves budget before calling one and stores what it returns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from scopedagent.domain.schemas import ObservationEnvelope
from scopedagent.policy.scope import PlannedOperation


@dataclass(frozen=True)
class AdapterResult:
    """`source_bytes` are what the observation was derived from (hashed as `source_hash`); `body` is the redacted
    body, if any."""

    envelope: ObservationEnvelope
    source_bytes: bytes
    body: bytes | None = None


@runtime_checkable
class Adapter(Protocol):
    name: str
    operation: str

    async def collect(self, operation: PlannedOperation) -> AdapterResult: ...
