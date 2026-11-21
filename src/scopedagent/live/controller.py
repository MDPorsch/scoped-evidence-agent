"""`live run`: everything the controller does around the container (docs/remote-live-design.md 2 and 4).

Before anything leaves the machine: the scope is a live one, the authorization window is open, the operator acknowledged it on this
command, a recorded approval matches this exact scope, every credential promised is present. Then each host is resolved once and
judged address by address; the container is started with no route out, the firewall and self-test run inside it, and the
controller refuses to send the job unless every check passed. What comes back is untrusted: it is validated, scanned for secrets,
and only then stored through the same run pipeline as an offline run (budget, observations, artifacts, rules, audit).
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from scopedagent.adapters.base import Adapter, AdapterResult
from scopedagent.adapters.offline import OfflineDns, error_result, normalized_input
from scopedagent.adapters.pack import Pack
from scopedagent.domain.models import LiveRun
from scopedagent.domain.outcome import ErrorStatus
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, LiveFailed, LiveRefused
from scopedagent.live.leakguard import LeakGuard, SecretLeak
from scopedagent.live.outputcheck import accept_results
from scopedagent.live.protocol import ENV_NAME, AllowedPair, Job, JobOperation, Proof, ProofCheck
from scopedagent.live.resolver import Lookup, Resolution, resolve_hosts, system_lookup
from scopedagent.live.runtime import Runtime, validate_image
from scopedagent.pipeline.orchestrator import RunResult, execute_run
from scopedagent.policy.authorization import check_live_authorization, check_run_allowed
from scopedagent.policy.scope import ANONYMOUS, LoadedScope, PlannedOperation
from scopedagent.storage.approvals import require_approval
from scopedagent.storage.artifacts import ArtifactStore
from scopedagent.storage.audit import append_event
from scopedagent.storage.database import Database

WORKER = Actor(ActorType.WORKER, "live-controller")
LIVE_KINDS = {"tls_metadata", "http_metadata", "ai_metadata", "api_spec", "api_read", "api_options"}


@dataclass(frozen=True)
class LiveRequest:
    loaded: LoadedScope
    human: Actor
    now: datetime
    approval_id: str
    acknowledged: bool
    image: str
    credentials: Mapping[
        str, str
    ]  # "target-id" (AI) or "target-id/principal" (API) -> the name of an environment variable


def credential_key(op: PlannedOperation) -> str | None:
    """Which `--credential` name an operation is sent under, or None when it is sent with none."""
    if op.kind == "ai_metadata":
        return op.target_id
    if op.kind.startswith("api_") and op.principal not in (None, ANONYMOUS):
        return f"{op.target_id}/{op.principal}"
    return None


def check_credentials(loaded: LoadedScope, credentials: Mapping[str, str], environ: Mapping[str, str]) -> list[str]:
    """Every credential named exists in the scope and is set; every principal that needs one has one. Returns the secret values."""
    known = {k for op in loaded.planned if (k := credential_key(op)) is not None}
    required = {k for op in loaded.planned if op.kind.startswith("api_") and (k := credential_key(op)) is not None}
    unknown = sorted(set(credentials) - known)
    if unknown:
        raise LiveRefused(ErrorCode.LIVE_002, f"--credential names something the scope does not have: {unknown[0]}")
    clear = sorted(
        {
            k
            for op in loaded.planned
            if (k := credential_key(op)) is not None and k in credentials and op.scheme != "https"
        }
    )
    if clear:
        raise LiveRefused(
            ErrorCode.LIVE_002, f"--credential {clear[0]}: a credential is sent only over https, and that target is not"
        )
    missing = sorted(required - set(credentials))
    if missing:
        raise LiveRefused(
            ErrorCode.LIVE_002, f"no --credential for {missing[0]}: a principal other than anonymous needs one"
        )
    secrets: list[str] = []
    for key, env in credentials.items():
        if not ENV_NAME.fullmatch(env):
            raise LiveRefused(ErrorCode.LIVE_002, f"--credential {key}: {env!r} is not an environment variable name")
        value = environ.get(env, "")
        if not value:
            raise LiveRefused(ErrorCode.LIVE_002, f"--credential {key}: the environment variable {env} is not set")
        if len(value) < 8:
            raise LiveRefused(
                ErrorCode.LIVE_002, f"--credential {key}: the value in {env} is too short to be a credential"
            )
        secrets.append(value)
    return secrets


def verify_proof(proof: Proof, sent: list[AllowedPair]) -> None:
    """Refuse unless the container proved everything and reports exactly the allow-list it was given."""
    failed = [c.name for c in proof.checks if not c.passed]
    if failed:
        raise LiveFailed(ErrorCode.LIVE_003, f"the isolation self-test failed ({failed[0]}): nothing was collected")
    if {(p.address, p.port) for p in proof.allowed} != {(p.address, p.port) for p in sent}:
        raise LiveFailed(ErrorCode.LIVE_003, "the container reports a different allow-list than the one it was given")


def _dns_result(op: PlannedOperation, resolution: Resolution) -> AdapterResult:
    records: dict[str, list[str]] = {}
    for address in resolution.resolved:
        records.setdefault("AAAA" if ":" in address else "A", []).append(address)
    if resolution.canonical_name:
        records["CNAME"] = [resolution.canonical_name]  # recorded as data, never resolved or contacted
    entry = {"status": "ok" if records else "error", "records": records}
    pack = Pack("live", {op.host: entry}, {}, {}, {}, {})
    return asyncio.run(OfflineDns(pack).collect(op))


class PrecomputedAdapter:
    """Hands the orchestrator the result already obtained for an operation. It contacts nothing."""

    def __init__(self, kind: str, results: dict[str, AdapterResult], refused: dict[str, str]) -> None:
        self.name, self.operation = "live", kind
        self._results, self._refused = results, refused

    async def collect(self, operation: PlannedOperation) -> AdapterResult:
        key = normalized_input(operation)
        found = self._results.get(key)
        if found is not None:
            return found
        if key in self._refused:
            return error_result(operation, ErrorStatus.REFUSED_BY_POLICY)
        return error_result(operation, ErrorStatus.ADAPTER_ERROR)  # the sandbox returned nothing for it


def build_job(
    loaded: LoadedScope, resolutions: Mapping[str, Resolution], credentials: Mapping[str, str]
) -> tuple[Job, dict[int, PlannedOperation]]:
    """The operations the container will be asked to do, with the pinned address of each, and what the controller planned for them."""
    config = loaded.config
    egress_rate = config.egress.max_requests_per_second if config.egress is not None else 2
    operations: list[JobOperation] = []
    planned: dict[int, PlannedOperation] = {}
    for index, op in enumerate(
        loaded.planned[: config.max_requests]
    ):  # the budget is a hard stop: nothing past it is sent
        resolution = resolutions[op.host]
        if op.kind not in LIVE_KINDS or not resolution.addresses:
            continue
        key = credential_key(op)
        operations.append(
            JobOperation(
                index=index, kind=op.kind, host=op.host, scheme=op.scheme, port=op.port,  # type: ignore[arg-type]
                address=resolution.addresses[0], path=op.path, method=op.method or "GET",  # type: ignore[arg-type]
                origin=op.origin, target_id=op.target_id, principal=op.principal, endpoint_id=op.endpoint_id,
                params=dict(op.params), credential_env=credentials.get(key) if key else None,
            )
        )  # fmt: skip
        planned[index] = op
    return (
        Job(
            max_response_bytes=config.max_response_bytes,
            per_request_timeout_seconds=config.per_request_timeout_seconds,
            requests_per_second=egress_rate,
            operations=operations,
        ),
        planned,
    )


def _store_live_record(
    db: Database, run_id: str, request: LiveRequest, proof: Proof, resolutions: Mapping[str, Resolution]
) -> None:
    authorization = request.loaded.config.authorization
    assert authorization is not None  # noqa: S101 - a live scope always has one
    hosts = [
        {
            "host": r.host,
            "addresses": list(r.addresses),
            "resolved": list(r.resolved),
            "canonical_name": r.canonical_name,
            "refusal": r.refusal,
        }
        for r in resolutions.values()
    ]
    with db.begin() as session:
        session.add(
            LiveRun(
                run_id=run_id,
                approval_id=request.approval_id,
                engagement=authorization.engagement,
                image=request.image,
                proof_json=proof.model_dump_json(),
                resolutions_json=json.dumps(hosts, sort_keys=True),
                created_at=request.now,
            )
        )
        passed = sum(1 for c in proof.checks if c.passed)
        append_event(
            session,
            run_id=run_id,
            actor=WORKER,
            action="live.isolation",
            decision="allowed",
            reason=f"{passed} of {len(proof.checks)} checks passed; {len(proof.allowed)} pinned addresses",
            now=request.now,
        )
        append_event(
            session,
            run_id=run_id,
            actor=request.human,
            action="live.authorized",
            decision="allowed",
            reason=f"engagement {authorization.engagement}; approval {request.approval_id}; image {request.image[-20:]}",
            now=request.now,
        )
        for r in resolutions.values():
            reason = f"{r.host} -> {', '.join(r.addresses)}" if r.addresses else f"{r.host} not contacted: {r.refusal}"
            append_event(
                session,
                run_id=run_id,
                actor=WORKER,
                action="live.resolution",
                decision="allowed" if r.addresses else "denied",
                reason=reason,
                now=request.now,
            )


def run_live(
    db: Database,
    store: ArtifactStore,
    request: LiveRequest,
    *,
    runtime: Runtime,
    environ: Mapping[str, str],
    lookup: Lookup = system_lookup,
) -> RunResult:
    loaded = request.loaded
    validate_image(request.image)
    check_run_allowed(loaded, now=request.now, expected_sha256=loaded.sha256, live=True)
    check_live_authorization(loaded, now=request.now, acknowledged=request.acknowledged)
    with db.begin() as session:
        require_approval(session, request.approval_id, loaded, now=request.now)
    secrets = check_credentials(loaded, request.credentials, environ)
    guard = LeakGuard(secrets)
    config = loaded.config
    networks = list(config.egress.allowed_networks) if config.egress is not None else []
    resolutions = resolve_hosts([op.host for op in loaded.planned], networks, lookup)
    job, planned = build_job(loaded, resolutions, request.credentials)
    allow = sorted(
        {AllowedPair(address=o.address, port=o.port) for o in job.operations}, key=lambda p: (p.address, p.port)
    )
    parent = Path(tempfile.mkdtemp(prefix="scopedagent-live-"))
    out_dir = parent / "out"
    out_dir.mkdir()
    out_dir.chmod(0o777)  # the collector runs as an unprivileged user; the directory above it is private to this user
    accepted: dict[str, AdapterResult] = {}
    refused: dict[str, str] = {}
    proof = Proof(
        allowed=[],
        checks=[ProofCheck(name="no network operation was needed", passed=True, detail="no host was contacted")],
    )
    try:
        if job.operations:
            envs = sorted({o.credential_env for o in job.operations if o.credential_env})
            container = runtime.start(credential_envs=envs, out_dir=out_dir)
            try:
                proof = container.exchange_proof(allow)
                verify_proof(proof, allow)
                guard.check(proof.model_dump_json(), where="the isolation proof")
            except SecretLeak as exc:
                container.abort()
                raise LiveFailed(ErrorCode.LIVE_004, str(exc)) from None
            except BaseException:
                container.abort()
                raise
            container.send_job(job)
            code = container.finish()
            if code != 0:
                raise LiveFailed(ErrorCode.LIVE_004, f"the collector exited with status {code}")
            for index, answer in accept_results(out_dir, planned, guard).results.items():
                accepted[normalized_input(planned[index])] = answer
        for op in loaded.planned:
            resolution = resolutions[op.host]
            if op.kind == "dns_metadata":
                accepted[normalized_input(op)] = _dns_result(op, resolution)
            elif not resolution.addresses:
                refused[normalized_input(op)] = resolution.refusal or "refused"
    finally:
        shutil.rmtree(parent, ignore_errors=True)
    kinds = (
        "dns_metadata",
        "tls_metadata",
        "http_metadata",
        "ai_metadata",
        "api_spec",
        "api_read",
        "api_options",
        "ai_probe",
    )
    adapters: dict[str, Adapter] = {kind: PrecomputedAdapter(kind, accepted, refused) for kind in kinds}
    run = asyncio.run(
        execute_run(
            db, store, loaded=loaded, pack=Pack("live", {}, {}, {}, {}, {}), human=request.human, now=request.now,
            adapters=adapters, live=True,
        )
    )  # fmt: skip
    _store_live_record(db, run.run_id, request, proof, resolutions)
    return run
