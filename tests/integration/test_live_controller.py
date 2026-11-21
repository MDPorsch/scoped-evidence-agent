"""M6: `live run` end to end through the real run pipeline, with the container replaced by an in-process stand-in that runs the real
collector against a loopback server. Nothing here proves the container's isolation (that needs Docker: `tests/container`); everything
around it is real: the authorization gates, resolution and the address policy, the proof gate, validation of what comes back,
the leak guard, storage, the audit trail and the report."""

from __future__ import annotations

import copy
import socket
import tempfile
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from sqlalchemy import text

from scopedagent.domain.models import Run
from scopedagent.domain.outcome import ExitCode
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, LiveFailed, LiveRefused, PolicyError
from scopedagent.live import collector
from scopedagent.live.controller import LiveRequest, run_live
from scopedagent.live.protocol import AllowedPair, Job, Proof, ProofCheck
from scopedagent.live.ratelimit import RateLimiter
from scopedagent.output.report import build_report, render_json, render_markdown
from scopedagent.policy.scope import parse_scope
from scopedagent.storage.approvals import grant_approval, revoke_approval
from scopedagent.storage.audit import verify_chain
from tests.support import NOW, assemble, dump, everything_stored, make_env
from tests.support_live import HOST, http_response, serve
from tests.unit.test_scope_live import AUTH

pytestmark = [pytest.mark.milestone("M6"), pytest.mark.loopback]

HUMAN = Actor(ActorType.HUMAN, "alice")
IMAGE = "registry.example.invalid/scopedagent/collector@sha256:" + "a" * 64
PUBLIC = "93.184.216.34"
TOKEN_A = assemble("tok_a-", "SYNTHETIC", "-0001")
TOKEN_B = assemble("tok_b-", "SYNTHETIC", "-0002")
KEY = assemble("tok_live-", "SYNTHETIC", "-0001")


PORTS: dict[str, int] = {}


@dataclass
class Container:
    """The stand-in for a container: its self-test result is whatever the test says, and its collector is the real one."""

    port: int
    environ: dict[str, str] = field(default_factory=dict)
    failing_checks: tuple[str, ...] = ()
    exit_code: int = 0
    tamper: Any = None
    allowed_override: list[AllowedPair] | None = None
    started: int = 0
    aborted: int = 0
    job: Job | None = None
    credential_envs: list[str] = field(default_factory=list)
    out_dir: Path | None = None

    def start(self, *, credential_envs: list[str], out_dir: Path) -> Container:
        self.started += 1
        self.credential_envs, self.out_dir = credential_envs, out_dir
        return self

    def exchange_proof(self, allow: list[AllowedPair]) -> Proof:
        names = (
            "cannot reach a documentation address (IPv4)",
            "has no name resolution",
            "runs unprivileged with no capability",
        )
        checks = [ProofCheck(name=n, passed=n not in self.failing_checks, detail="test") for n in names]
        return Proof(allowed=self.allowed_override if self.allowed_override is not None else allow, checks=checks)

    def send_job(self, job: Job) -> None:
        self.job = job

        def plain(op: Any, timeout: float, connect: Any, *, verify: bool = True) -> Any:
            return socket.create_connection(
                ("127.0.0.1", self.port), timeout
            )  # the "pinned" address is not really there

        assert self.out_dir is not None
        # TLS and the peer-address check have their own unit tests over loopback (`test_live_collector.py`); here the stand-in
        # container speaks plain HTTP to the loopback server so that everything around the collector can be tested end to end.
        with mock.patch.object(collector, "_open", plain):
            collector.run_job(job, self.out_dir, self.environ, limiter=RateLimiter(10, sleep=lambda s: None))
        if self.tamper:
            self.tamper(self.out_dir)

    def finish(self) -> int:
        return self.exit_code

    def abort(self) -> None:
        self.aborted += 1


def lookup(addresses: list[str] | Exception, canonical: str | None = None) -> Any:
    calls: list[str] = []

    def find(host: str) -> tuple[list[str], str | None]:
        calls.append(host)
        if isinstance(addresses, Exception):
            raise addresses
        return addresses, canonical

    find.calls = calls  # type: ignore[attr-defined]
    return find


def live_scope(port: int, **edits: Any) -> Any:
    data: dict[str, Any] = {
        "engagement_id": "lab-live-001", "owner_approval_ref": "local-lab-consent", "expires_at": "2026-12-31T23:59:00Z",
        "mode": "live", "authorization": copy.deepcopy(AUTH),
        "allowed_targets": [{"host": HOST, "schemes": ["http"], "ports": [port], "allowed_paths": ["/", "/robots.txt"]}],
        "allowed_operations": ["dns_metadata", "http_metadata"],
        "max_requests": 20, "max_parallelism": 2, "per_request_timeout_seconds": 5, "max_response_bytes": 100_000, "follow_redirects": False,
    }  # fmt: skip
    data.update(edits)
    return parse_scope(dump(data), now=NOW)


def site(request: bytes) -> bytes:
    path = request.split(b" ")[1] if request else b"/"
    if path == b"/robots.txt":
        return http_response(
            200, {"Content-Type": "text/plain", "Server": "nginx"}, b"User-agent: *\nDisallow: /admin\n"
        )
    return http_response(200, {"Content-Type": "text/html", "Server": "nginx/1.14.0"}, b"<html>hello</html>")


@pytest.fixture
def env2(tmp_path: Path) -> Any:
    db, store, data_dir = make_env(tmp_path)
    yield db, store, data_dir
    db.close()


def approve(db: Any, scope: Any, until: Any = NOW + timedelta(days=7)) -> str:
    with db.begin() as session:
        return grant_approval(session, scope, until=until, actor=HUMAN, now=NOW).id


def go(
    env: Any,
    scope: Any,
    container: Container,
    *,
    approval_id: str | None = None,
    ack: bool = True,
    image: str = IMAGE,
    credentials: dict[str, str] | None = None,
    find: Any = None,
    environ: dict[str, str] | None = None,
    now: Any = NOW,
) -> Any:
    db, store, _ = env
    request = LiveRequest(
        loaded=scope, human=HUMAN, now=now, approval_id=approval_id or approve(db, scope), acknowledged=ack, image=image,
        credentials=credentials or {},
    )  # fmt: skip
    return run_live(db, store, request, runtime=container, environ=environ or {}, lookup=find or lookup([PUBLIC]))


def count(env: Any, table: str) -> int:
    with env[0].begin() as session:
        return int(session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one())


# ------------------------------------------------------------------------------------------- a good run ----
def test_a_live_run_is_the_same_pipeline_as_an_offline_one_with_a_proof_and_a_record(env2: Any) -> None:
    server, close = serve(site)
    try:
        scope = live_scope(server.port)
        container = Container(server.port)
        result = go(env2, scope, container)
    finally:
        close()
    assert result.state == "DRAFTED" and result.coverage.complete and result.planned == 3 and result.observations == 3
    assert (
        container.started == 1 and container.aborted == 0 and server.connections == 2
    )  # dns is the controller's, http is the container's
    kinds = (
        [
            r[0]
            for r in env2[0]
            .begin()
            .__enter__()
            .execute(text("SELECT observation_type FROM observations ORDER BY rowid"))
            .all()
        ]
        if False
        else None
    )
    with env2[0].begin() as session:
        types = [r[0] for r in session.execute(text("SELECT observation_type FROM observations ORDER BY rowid")).all()]
        run = session.get(Run, result.run_id)
        assert run is not None and run.mode == "live" and run.budget_spent == 3
        assert verify_chain(session, result.run_id) > 0
    assert types == ["dns_metadata", "http_metadata", "http_metadata"] and kinds is None
    assert result.exit_code in (ExitCode.OK, ExitCode.REVIEW)


def test_the_dns_observation_is_what_the_controller_resolved_and_a_cname_is_recorded_as_data(env2: Any) -> None:
    server, close = serve(site)
    try:
        go(
            env2,
            live_scope(server.port),
            Container(server.port),
            find=lookup([PUBLIC, "2606:4700:4700::1111"], "cdn.other.example.invalid"),
        )
    finally:
        close()
    with env2[0].begin() as session:
        records = session.execute(
            text("SELECT normalized_json FROM observations WHERE observation_type = 'dns_metadata'")
        ).scalar_one()
    assert (
        '"A":["93.184.216.34"]' in records
        and '"AAAA":["2606:4700:4700::1111"]' in records
        and "cdn.other.example.invalid" in records
    )
    assert server.connections == 2  # the CNAME's target was never contacted


def test_the_run_leaves_the_record_of_what_it_was_done_under(env2: Any) -> None:
    server, close = serve(site)
    try:
        scope = live_scope(server.port)
        result = go(env2, scope, Container(server.port))
    finally:
        close()
    with env2[0].begin() as session:
        row = session.execute(
            text("SELECT approval_id, engagement, image, proof_json, resolutions_json FROM live_runs")
        ).one()
        events = session.execute(
            text("SELECT action, decision, reason FROM audit_events WHERE run_id = :r"), {"r": result.run_id}
        ).all()
    assert row[1] == "ACME-2026-114" and row[2] == IMAGE and PUBLIC in row[4] and "cannot reach" in row[3]
    actions = [e[0] for e in events]
    assert {"live.isolation", "live.authorized", "live.resolution"} <= set(actions)
    assert any(e[0] == "live.isolation" and "3 of 3 checks passed" in e[2] for e in events)
    assert any(e[0] == "live.authorized" and "ACME-2026-114" in e[2] and row[0] in e[2] for e in events)


def test_the_report_says_the_authorization_was_declared_shows_the_proof_and_the_pinned_addresses(env2: Any) -> None:
    server, close = serve(site)
    try:
        result = go(env2, live_scope(server.port), Container(server.port))
    finally:
        close()
    with env2[0].begin() as session:
        report = build_report(session, result.run_id, tool_version="0.0.1")
    live = report["live"]
    assert (
        "declared by the operator for engagement ACME-2026-114" in live["attestation"]
        and "not verified by the tool" in live["attestation"]
    )
    assert (
        live["isolation"]["passed"] is True
        and live["isolation"]["pinned"] == [f"{PUBLIC}:{server.port}"]
        and live["image"] == IMAGE
    )
    assert live["hosts"] == [
        {"host": HOST, "addresses": [PUBLIC], "resolved": [PUBLIC], "canonical_name": None, "refusal": None}
    ]
    rendered = render_markdown(report)
    assert (
        "## Live collection" in rendered
        and "isolation proof: passed" in rendered
        and PUBLIC in rendered
        and "not verified by the tool" in rendered
    )
    assert '"live"' in render_json(report)


def test_an_offline_run_has_no_live_key_in_its_report(env2: Any) -> None:
    from tests.support import run_pack  # noqa: PLC0415

    result = run_pack(env2, "healthy")
    with env2[0].begin() as session:
        assert "live" not in build_report(session, result.run_id, tool_version="0.0.1")


def test_the_budget_is_a_hard_stop_for_what_is_sent(env2: Any) -> None:
    server, close = serve(site)
    try:
        container = Container(server.port)
        result = go(env2, live_scope(server.port, max_requests=2), container)
    finally:
        close()
    assert (
        server.connections == 1 and container.job is not None and len(container.job.operations) == 1
    )  # dns + one request: then stop
    with env2[0].begin() as session:
        statuses = [r[0] for r in session.execute(text("SELECT error_status FROM observations ORDER BY rowid")).all()]
    assert statuses == ["ok", "ok", "budget_exhausted"] and result.exit_code is ExitCode.INCOMPLETE


def test_the_rate_from_the_scope_reaches_the_job(env2: Any) -> None:
    server, close = serve(site)
    try:
        container = Container(server.port)
        go(env2, live_scope(server.port, egress={"max_requests_per_second": 5}), container)
    finally:
        close()
    assert (
        container.job is not None
        and container.job.requests_per_second == 5
        and container.job.per_request_timeout_seconds == 5
    )


def test_the_job_names_each_operation_with_its_pinned_address_and_nothing_else(env2: Any) -> None:
    server, close = serve(site)
    try:
        container = Container(server.port)
        go(env2, live_scope(server.port), container)
    finally:
        close()
    assert container.job is not None
    assert [(o.kind, o.address, o.port, o.path, o.method) for o in container.job.operations] == [
        ("http_metadata", PUBLIC, server.port, "/", "GET"),
        ("http_metadata", PUBLIC, server.port, "/robots.txt", "GET"),
    ]
    assert container.credential_envs == []


def test_the_temporary_directory_is_removed_after_a_run_and_after_a_failure(
    env2: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    server, close = serve(site)
    try:
        go(env2, live_scope(server.port), Container(server.port))
        assert list(scratch.iterdir()) == []
        with pytest.raises(LiveFailed):
            go(env2, live_scope(server.port, max_requests=19), Container(server.port, exit_code=9))
        assert list(scratch.iterdir()) == []
    finally:
        close()


# --------------------------------------------------------------------------------- the gates, in order ----
def nothing_happened(env: Any, container: Container, find: Any) -> None:
    assert container.started == 0 and find.calls == [] and count(env, "runs") == 0 and count(env, "observations") == 0


@pytest.mark.parametrize(
    "gate",
    ["ack", "image", "no-approval", "revoked", "expired", "scope-changed", "not-started", "window-over", "wrong-mode"],
)
def test_every_gate_refuses_before_anything_is_resolved_or_started(env2: Any, gate: str) -> None:
    server, close = serve(site)
    find, container = lookup([PUBLIC]), Container(server.port)
    scope = live_scope(server.port)
    kwargs: dict[str, Any] = {}
    expected: type[Exception] = LiveRefused
    if gate == "ack":
        kwargs["ack"] = False
    elif gate == "image":
        kwargs["image"] = "registry.example.invalid/collector:latest"
    elif gate == "no-approval":
        kwargs["approval_id"] = "0" * 32
    elif gate == "revoked":
        approval_id = approve(env2[0], scope)
        with env2[0].begin() as session:
            revoke_approval(session, approval_id, actor=HUMAN, reason="stop", now=NOW)
        kwargs["approval_id"] = approval_id
    elif gate == "expired":
        kwargs["approval_id"] = approve(env2[0], scope, until=NOW + timedelta(days=1))
        kwargs["now"] = NOW + timedelta(days=2)
    elif gate == "scope-changed":
        kwargs["approval_id"] = approve(env2[0], live_scope(server.port, max_requests=19))
    elif gate == "not-started":
        kwargs["now"] = NOW - timedelta(days=1)
        kwargs["approval_id"] = approve(env2[0], scope)
    elif gate == "window-over":
        kwargs["approval_id"] = approve(env2[0], scope, until=scope.config.authorization.not_after)
        kwargs["now"] = scope.config.authorization.not_after + timedelta(seconds=1)
    else:  # an offline scope is not a live scope
        scope = parse_scope(
            dump({**_raw(server.port), "mode": "offline", "authorization": None}).replace("authorization: null\n", ""),
            now=NOW,
        )
        expected = PolicyError
    try:
        with pytest.raises((expected, LiveRefused, PolicyError)):
            go(env2, scope, container, find=find, **kwargs)
    finally:
        close()
    nothing_happened(env2, container, find)
    assert server.connections == 0


def _raw(port: int) -> dict[str, Any]:
    import yaml  # noqa: PLC0415

    loaded = live_scope(port)
    return yaml.safe_load(
        dump(
            {
                "engagement_id": loaded.config.engagement_id,
                "owner_approval_ref": "local-lab-consent",
                "expires_at": "2026-12-31T23:59:00Z",
                "mode": "live",
                "authorization": AUTH,
                "allowed_targets": [
                    {"host": HOST, "schemes": ["http"], "ports": [port], "allowed_paths": ["/", "/robots.txt"]}
                ],
                "allowed_operations": ["dns_metadata", "http_metadata"],
                "max_requests": 20,
            }
        )
    )  # type: ignore[no-any-return]


def test_the_gate_codes_are_the_documented_ones(env2: Any) -> None:
    scope = live_scope(1)
    for kwargs, code in (
        ({"ack": False}, ErrorCode.LIVE_002),
        ({"image": "x:latest"}, ErrorCode.LIVE_001),
        ({"approval_id": "0" * 32}, ErrorCode.LIVE_002),
    ):
        with pytest.raises(LiveRefused) as caught:
            go(env2, scope, Container(1), **kwargs)
        assert caught.value.code is code and caught.value.exit_code == 1


# ---------------------------------------------------------------------------------------- addresses ----
@pytest.mark.parametrize(
    "bad", [["10.0.0.5"], ["169.254.169.254"], ["127.0.0.1"], ["::ffff:8.8.8.8"], [PUBLIC, "10.0.0.5"], ["fe80::1"], []]
)
def test_a_host_that_resolves_to_anything_not_acceptable_is_not_contacted_at_all(env2: Any, bad: list[str]) -> None:
    server, close = serve(site)
    container = Container(server.port)
    try:
        result = go(env2, live_scope(server.port), container, find=lookup(bad))
    finally:
        close()
    assert container.started == 0 and server.connections == 0  # no container, no connection: nothing to pin
    with env2[0].begin() as session:
        rows = session.execute(text("SELECT observation_type, error_status FROM observations ORDER BY rowid")).all()
        resolution = session.execute(
            text("SELECT reason FROM audit_events WHERE action = 'live.resolution'")
        ).scalar_one()
    assert rows == [
        ("dns_metadata", "ok" if bad else "dns_failure"),
        ("http_metadata", "refused_by_policy"),
        ("http_metadata", "refused_by_policy"),
    ]
    assert "not contacted" in resolution and result.exit_code is ExitCode.INCOMPLETE and not result.coverage.complete


def test_a_private_address_is_contacted_only_when_the_scope_lists_its_range(env2: Any) -> None:
    server, close = serve(site)
    try:
        refused = go(env2, live_scope(server.port), Container(server.port), find=lookup(["10.20.1.1"]))
        assert refused.exit_code is ExitCode.INCOMPLETE and server.connections == 0
        allowed = go(
            env2,
            live_scope(server.port, egress={"allowed_networks": ["10.20.0.0/16"]}),
            Container(server.port),
            find=lookup(["10.20.1.1"]),
        )
        assert allowed.coverage.complete and server.connections == 2
    finally:
        close()


def test_a_name_that_does_not_resolve_is_recorded_and_not_contacted(env2: Any) -> None:
    server, close = serve(site)
    try:
        result = go(env2, live_scope(server.port), Container(server.port), find=lookup(OSError("no such host")))
    finally:
        close()
    assert server.connections == 0 and result.exit_code is ExitCode.INCOMPLETE
    with env2[0].begin() as session:
        assert (
            "the name did not resolve"
            in session.execute(text("SELECT reason FROM audit_events WHERE action = 'live.resolution'")).scalar_one()
        )


def test_each_host_is_resolved_once_however_many_operations_it_has(env2: Any) -> None:
    server, close = serve(site)
    find = lookup([PUBLIC])
    try:
        go(env2, live_scope(server.port), Container(server.port), find=find)
    finally:
        close()
    assert find.calls == [HOST]


# --------------------------------------------------------------------------------------------- the proof ----
@pytest.mark.parametrize(
    "failing",
    ["cannot reach a documentation address (IPv4)", "has no name resolution", "runs unprivileged with no capability"],
)
def test_a_failed_self_test_means_nothing_is_sent_nothing_is_collected_and_no_run_exists(
    env2: Any, failing: str
) -> None:
    server, close = serve(site)
    container = Container(server.port, failing_checks=(failing,))
    try:
        with pytest.raises(LiveFailed) as caught:
            go(env2, live_scope(server.port), container)
    finally:
        close()
    assert caught.value.code is ErrorCode.LIVE_003 and failing in str(caught.value) and caught.value.exit_code == 2
    assert container.aborted == 1 and container.job is None and server.connections == 0
    assert count(env2, "runs") == 0 and count(env2, "observations") == 0 and count(env2, "live_runs") == 0


def test_a_container_that_reports_a_different_allow_list_is_refused(env2: Any) -> None:
    server, close = serve(site)
    container = Container(server.port, allowed_override=[AllowedPair(address="93.184.216.99", port=443)])
    try:
        with pytest.raises(LiveFailed, match="different allow-list"):
            go(env2, live_scope(server.port), container)
    finally:
        close()
    assert container.aborted == 1 and server.connections == 0 and count(env2, "runs") == 0


def test_a_collector_that_exits_with_an_error_is_a_failure_and_stores_nothing(env2: Any) -> None:
    server, close = serve(site)
    try:
        with pytest.raises(LiveFailed) as caught:
            go(env2, live_scope(server.port), Container(server.port, exit_code=4))
    finally:
        close()
    assert caught.value.code is ErrorCode.LIVE_004 and "status 4" in str(caught.value) and count(env2, "runs") == 0


# ----------------------------------------------------------------------------- what comes back is untrusted ----
def test_a_stray_file_in_the_output_directory_refuses_the_whole_run(env2: Any) -> None:
    server, close = serve(site)
    try:
        with pytest.raises(LiveFailed) as caught:
            go(
                env2,
                live_scope(server.port),
                Container(server.port, tamper=lambda d: (d / "payload.sh").write_text("#!/bin/sh")),
            )
    finally:
        close()
    assert caught.value.code is ErrorCode.LIVE_004 and count(env2, "runs") == 0 and count(env2, "artifacts") == 0


def test_an_envelope_for_the_wrong_request_refuses_the_whole_run(env2: Any) -> None:
    def swap(directory: Path) -> None:  # the planned operations are 1 and 2 (0 is the controller's own DNS answer)
        a, b = (directory / "result-1.json").read_text(), (directory / "result-2.json").read_text()
        (directory / "result-1.json").write_text(b.replace('"index":2', '"index":1'))
        (directory / "result-2.json").write_text(a.replace('"index":1', '"index":2'))

    server, close = serve(site)
    try:
        with pytest.raises(LiveFailed, match="different request"):
            go(env2, live_scope(server.port), Container(server.port, tamper=swap))
    finally:
        close()
    assert count(env2, "runs") == 0


# ------------------------------------------------------------------------------------------ credentials ----
def ai_scope(port: int, scheme: str = "https") -> Any:
    return live_scope(
        port,
        allowed_targets=[],
        allowed_operations=["ai_metadata"],
        ai_targets=[
            {
                "id": "support-bot", "kind": "chat_endpoint", "layer": "application", "environment": "test", "host": HOST,
                "scheme": scheme, "port": port, "api_style": "openai_compatible", "operations": ["ai_metadata"],
                "metadata_paths": ["/v1/models"],
                "limits": {"max_model_requests": 4, "max_input_tokens": 100, "max_output_tokens": 100, "max_total_tokens": 1000},
                "rules": {"tool_invocation": "forbidden", "persistent_state_writes": "forbidden", "personal_data_in_probes": "forbidden", "target_output_to_assistant_model": "forbidden"},
            }
        ],
    )  # fmt: skip


MODELS = http_response(
    200, {"Content-Type": "application/json"}, b'{"object": "list", "data": [{"id": "support-bot-1"}]}'
)


def test_a_credential_goes_to_the_declared_host_only_by_name_and_is_in_no_stored_byte(
    env2: Any, tmp_path: Path
) -> None:
    server, close = serve(lambda r: MODELS)
    container = Container(server.port, environ={"BOT_KEY": KEY})
    try:
        result = go(
            env2, ai_scope(server.port), container, credentials={"support-bot": "BOT_KEY"}, environ={"BOT_KEY": KEY}
        )
    finally:
        close()
    assert result.coverage.complete and f"Authorization: Bearer {KEY}" in server.received[0].decode()
    assert container.credential_envs == ["BOT_KEY"]  # passed by name
    assert container.job is not None and KEY not in container.job.model_dump_json()  # the job never holds a value
    assert KEY not in everything_stored(env2[0], env2[2])


@pytest.mark.parametrize("where", ["header", "body"])
def test_a_target_that_echoes_the_credential_back_fails_the_run_and_stores_nothing(env2: Any, where: str) -> None:
    echo = http_response(
        200,
        {"Content-Type": "application/json", **({"X-Echo": KEY} if where == "header" else {})},
        f'{{"object": "list", "data": [], "echo": "{KEY if where == "body" else ""}"}}'.encode(),
    )
    server, close = serve(lambda r: echo)
    try:
        with pytest.raises(LiveFailed) as caught:
            go(
                env2,
                ai_scope(server.port),
                Container(server.port, environ={"BOT_KEY": KEY}),
                credentials={"support-bot": "BOT_KEY"},
                environ={"BOT_KEY": KEY},
            )
    finally:
        close()
    assert KEY not in str(caught.value) and count(env2, "runs") == 0 and KEY not in everything_stored(env2[0], env2[2])


def test_the_leak_guard_also_catches_an_encoded_echo(env2: Any) -> None:
    import base64  # noqa: PLC0415

    encoded = base64.b64encode(KEY.encode()).decode()
    server, close = serve(
        lambda r: http_response(
            200, {"Content-Type": "application/json", "X-Debug": encoded}, b'{"object": "list", "data": []}'
        ),
    )
    try:
        with pytest.raises(LiveFailed):
            go(
                env2,
                ai_scope(server.port),
                Container(server.port, environ={"BOT_KEY": KEY}),
                credentials={"support-bot": "BOT_KEY"},
                environ={"BOT_KEY": KEY},
            )
    finally:
        close()


@pytest.mark.parametrize(
    ("credentials", "environ", "message"),
    [
        ({"nonexistent": "BOT_KEY"}, {"BOT_KEY": KEY}, "does not have"),
        ({"support-bot": "bot_key"}, {"bot_key": KEY}, "not an environment variable name"),
        ({"support-bot": "BOT_KEY"}, {}, "is not set"),
        ({"support-bot": "BOT_KEY"}, {"BOT_KEY": "short"}, "too short"),
    ],
)
def test_a_credential_that_is_wrong_is_refused_before_anything_starts(
    env2: Any, credentials: dict[str, str], environ: dict[str, str], message: str
) -> None:
    server, close = serve(lambda r: MODELS)
    container, find = Container(server.port), lookup([PUBLIC])
    try:
        with pytest.raises(LiveRefused, match=message):
            go(env2, ai_scope(server.port), container, credentials=credentials, environ=environ, find=find)
    finally:
        close()
    nothing_happened(env2, container, find)


def test_an_ai_target_without_a_credential_is_asked_without_one(env2: Any) -> None:
    server, close = serve(lambda r: MODELS)
    try:
        result = go(env2, ai_scope(server.port, "http"), Container(server.port))
    finally:
        close()
    assert result.coverage.complete and "Authorization" not in server.received[0].decode()


def test_a_credential_for_a_target_that_is_not_https_is_refused_before_anything_starts(env2: Any) -> None:
    server, close = serve(lambda r: MODELS)
    container, find = Container(server.port), lookup([PUBLIC])
    try:
        with pytest.raises(LiveRefused, match="only over https"):
            go(
                env2,
                ai_scope(server.port, "http"),
                container,
                credentials={"support-bot": "BOT_KEY"},
                environ={"BOT_KEY": KEY},
                find=find,
            )
    finally:
        close()
    nothing_happened(env2, container, find)


# ------------------------------------------------------------------------------------------ API principals ----
def api_live_scope() -> Any:
    from tests.unit.test_scope_live import live_dict  # noqa: PLC0415

    return parse_scope(dump(live_dict("api-orders")), now=NOW)


def json_ok(request: bytes) -> bytes:
    if b"/openapi.json" in request.split(b"\r\n")[0]:
        return http_response(
            200, {"Content-Type": "application/json"}, b'{"openapi": "3.0.0", "paths": {"/v1/projects": {"get": {}}}}'
        )
    return http_response(200, {"Content-Type": "application/json"}, b'{"id": "p-1001"}')


def test_a_principal_other_than_anonymous_needs_a_credential_and_each_gets_only_its_own(env2: Any) -> None:
    server, close = serve(json_ok)
    scope = api_live_scope()
    container = Container(server.port, environ={"A_KEY": TOKEN_A, "B_KEY": TOKEN_B})
    credentials = {"orders-api/tenant-a-user": "A_KEY", "orders-api/tenant-b-user": "B_KEY"}
    try:
        result = go(env2, scope, container, credentials=credentials, environ=container.environ)
    finally:
        close()
    assert (
        result.coverage.complete
        and result.observations == 11
        and sorted(container.credential_envs) == ["A_KEY", "B_KEY"]
    )

    def auth(request: bytes) -> str | None:
        line = next((x for x in request.decode().split("\r\n") if x.startswith("Authorization:")), None)
        return None if line is None else line.split(" ", 2)[2]

    sent = [auth(r) for r in server.received]
    a, b = TOKEN_A, TOKEN_B
    # spec, list (anonymous), list (a), p-1001 (a, b), p-2002 (a, b), health (anonymous), then three OPTIONS (anonymous)
    assert sent == [None, None, a, a, b, a, b, None, None, None, None]
    assert a not in everything_stored(env2[0], env2[2]) and b not in everything_stored(env2[0], env2[2])


def test_a_principal_without_a_credential_is_refused_before_anything_starts(env2: Any) -> None:
    server, close = serve(json_ok)
    container, find = Container(server.port), lookup([PUBLIC])
    try:
        with pytest.raises(LiveRefused, match="no --credential for orders-api/tenant-b-user"):
            go(
                env2,
                api_live_scope(),
                container,
                credentials={"orders-api/tenant-a-user": "A_KEY"},
                environ={"A_KEY": TOKEN_A},
                find=find,
            )
    finally:
        close()
    nothing_happened(env2, container, find)


def test_an_operation_the_sandbox_returned_nothing_for_is_recorded_as_an_error_not_invented(env2: Any) -> None:
    def drop_one(directory: Path) -> None:
        (directory / "result-2.json").unlink()
        (directory / "artifact-2.bin").unlink()

    server, close = serve(site)
    try:
        result = go(env2, live_scope(server.port), Container(server.port, tamper=drop_one))
    finally:
        close()
    with env2[0].begin() as session:
        statuses = [r[0] for r in session.execute(text("SELECT error_status FROM observations ORDER BY rowid")).all()]
    assert statuses == ["ok", "ok", "adapter_error"] and result.exit_code is ExitCode.INCOMPLETE


def test_the_report_of_a_refused_host_says_what_it_resolved_to_and_that_it_was_not_contacted(env2: Any) -> None:
    server, close = serve(site)
    try:
        result = go(env2, live_scope(server.port), Container(server.port), find=lookup(["10.0.0.5"]))
    finally:
        close()
    with env2[0].begin() as session:
        rendered = render_markdown(build_report(session, result.run_id, tool_version="0.0.1"))
    assert "not contacted" in rendered and "resolved to 10.0.0.5" in rendered and "isolation proof: passed" in rendered
