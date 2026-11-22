"""M6: the commands. `run` never starts a live scope; `live run` never starts an offline one; the container is never reached without
every gate; and with the stand-in container the command prints what a person needs and exits with the documented codes."""

from __future__ import annotations

import socket
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from scopedagent import cli as cli_module
from scopedagent.cli import AppContext, app
from scopedagent.policy.scope import parse_scope
from tests.integration.test_live_controller import PUBLIC, Container, live_scope
from tests.support import FIXTURES, NOW, SCOPE_FILES, dump, scope_dict
from tests.support_live import HOST, http_response, serve

pytestmark = [pytest.mark.milestone("M6"), pytest.mark.loopback]

CTX = AppContext(clock=lambda: NOW, user=lambda: "alice")
runner = CliRunner()
IMAGE = "registry.example.invalid/scopedagent/collector@sha256:" + "a" * 64


def invoke(*args: str, input: str | None = None) -> Any:
    return runner.invoke(app, list(args), obj=CTX, input=input)


def write_scope(tmp_path: Path, port: int) -> Path:
    import yaml  # noqa: PLC0415

    loaded = live_scope(port)
    data = {
        "engagement_id": loaded.config.engagement_id, "owner_approval_ref": "local-lab-consent", "expires_at": "2026-12-31T23:59:00Z",
        "mode": "live",
        "authorization": {"engagement": "ACME-2026-114", "not_before": "2026-11-20T00:00:00Z", "not_after": "2026-12-04T23:59:59Z"},
        "allowed_targets": [{"host": HOST, "schemes": ["http"], "ports": [port], "allowed_paths": ["/", "/robots.txt"]}],
        "allowed_operations": ["dns_metadata", "http_metadata"], "max_requests": 20,
    }  # fmt: skip
    path = tmp_path / "live.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def setup(tmp_path: Path, port: int) -> tuple[str, Path, str]:
    data = str(tmp_path / "data")
    assert invoke("db", "upgrade", "--data-dir", data).exit_code == 0
    scope = write_scope(tmp_path, port)
    sha = parse_scope(scope.read_text(), now=NOW).sha256
    out = invoke(
        "approvals",
        "grant",
        "--scope",
        str(scope),
        "--until",
        "2026-11-27T12:00:00Z",
        "--data-dir",
        data,
        input=sha[:8] + "\n",
    )
    assert out.exit_code == 0, out.output
    return data, scope, next(w for w in out.output.split() if len(w) == 32)


def test_an_approval_shows_the_checks_the_scope_switches_on_before_it_asks_for_the_typed_hash(tmp_path: Path) -> None:
    data = str(tmp_path / "data")
    assert invoke("db", "upgrade", "--data-dir", data).exit_code == 0
    plain = write_scope(tmp_path, 9)
    shown = invoke(
        "approvals", "grant", "--scope", str(plain), "--until", "2026-11-27T12:00:00Z", "--data-dir", data, input="\n"
    )
    assert "checks switched on" not in shown.output  # none switched on: nothing is said
    body = yaml.safe_load(plain.read_text())
    body["checks"] = {"passive": ["header_quality"]}
    checked = tmp_path / "checked.yaml"
    checked.write_text(yaml.safe_dump(body, sort_keys=False))
    sha = parse_scope(checked.read_text(), now=NOW).sha256
    out = invoke(
        "approvals",
        "grant",
        "--scope",
        str(checked),
        "--until",
        "2026-11-27T12:00:00Z",
        "--data-dir",
        data,
        input=sha[:8] + "\n",
    )
    assert out.exit_code == 0, out.output
    assert out.output.index("checks switched on: passive header_quality") < out.output.index(
        "Type the first 8 characters"
    )


def test_run_never_starts_a_live_scope_and_never_builds_a_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(image: str) -> Any:
        raise AssertionError("run must never build a container runtime")

    monkeypatch.setattr(cli_module, "_runtime", boom)
    data, scope, _ = setup(tmp_path, 8080)
    out = invoke(
        "run", "--scope", str(scope), "--fixture", str(FIXTURES / "web_responses" / "healthy.yaml"), "--data-dir", data
    )
    assert out.exit_code == 1 and "POLICY-001" in out.output and "scoped-agent live run" in out.output
    flag = invoke(
        "run",
        "--live",
        "--scope",
        str(SCOPE_FILES["healthy"]),
        "--fixture",
        str(FIXTURES / "web_responses" / "healthy.yaml"),
        "--data-dir",
        data,
    )
    assert flag.exit_code == 1 and "run never opens a connection" in flag.output


def test_live_run_refuses_an_offline_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_module, "_runtime", lambda image: (_ for _ in ()).throw(AssertionError("no runtime for an offline scope"))
    )
    data = str(tmp_path / "data")
    invoke("db", "upgrade", "--data-dir", data)
    out = invoke(
        "live",
        "run",
        "--scope",
        str(SCOPE_FILES["healthy"]),
        "--approval-id",
        "0" * 32,
        "--image",
        IMAGE,
        "--ack-authorization",
        "--data-dir",
        data,
    )
    assert out.exit_code == 1 and "POLICY-001" in out.output and "mode live" in out.output


@pytest.mark.parametrize(
    ("extra", "needle"),
    [
        (["--approval-id", "0" * 32], "--ack-authorization is required"),
        (
            ["--approval-id", "0" * 32, "--ack-authorization", "--image", "registry/collector:latest"],
            "pinned by digest",
        ),
        (["--approval-id", "0" * 32, "--ack-authorization"], "no such approval"),
    ],
)
def test_the_gates_are_refused_with_their_code_and_no_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: list[str], needle: str
) -> None:
    monkeypatch.setattr(
        cli_module, "_runtime", lambda image: (_ for _ in ()).throw(AssertionError("the gates come first"))
    )
    data, scope, _ = setup(tmp_path, 8080)
    args = ["live", "run", "--scope", str(scope), "--image", IMAGE, *extra, "--data-dir", data]
    if "--image" in extra:
        args = ["live", "run", "--scope", str(scope), *extra, "--data-dir", data]
    out = invoke(*args)
    assert out.exit_code == 1 and needle in out.output and "Traceback" not in out.output and ("LIVE-00" in out.output)


@pytest.mark.parametrize("bad", ["NOEQUALS", "=ENV", "name=", "a=B,a=C"])
def test_a_malformed_credential_option_is_refused(tmp_path: Path, bad: str) -> None:
    data, scope, approval_id = setup(tmp_path, 8080)
    args = [
        "live",
        "run",
        "--scope",
        str(scope),
        "--approval-id",
        approval_id,
        "--image",
        IMAGE,
        "--ack-authorization",
        "--credential",
        bad,
        "--data-dir",
        data,
    ]
    out = invoke(*args)
    assert out.exit_code in (1, 2) and "Traceback" not in out.output


def test_the_duplicate_credential_name_is_refused(tmp_path: Path) -> None:
    data, scope, approval_id = setup(tmp_path, 8080)
    out = invoke(
        "live",
        "run",
        "--scope",
        str(scope),
        "--approval-id",
        approval_id,
        "--image",
        IMAGE,
        "--ack-authorization",
        "--credential",
        "a=B1",
        "--credential",
        "a=B2",
        "--data-dir",
        data,
    )
    assert out.exit_code == 1 and "once per name" in out.output


def test_a_live_run_by_command_prints_the_attestation_the_result_and_exits_with_the_documented_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, close = serve(lambda r: http_response(200, {"Content-Type": "text/plain", "Server": "nginx"}, b"hello"))
    monkeypatch.setattr(cli_module, "_runtime", lambda image: Container(server.port))
    monkeypatch.setattr(
        "scopedagent.live.controller.system_lookup", lambda host: ([PUBLIC], None)
    )  # the resolver is the controller's only lookup; here it answers without a name server
    monkeypatch.setattr(cli_module, "run_live", _with_lookup(cli_module.run_live))
    try:
        data, scope, approval_id = setup(tmp_path, server.port)
        out = invoke(
            "live",
            "run",
            "--scope",
            str(scope),
            "--approval-id",
            approval_id,
            "--image",
            IMAGE,
            "--ack-authorization",
            "--data-dir",
            data,
        )
    finally:
        close()
    assert out.exit_code in (0, 3), out.output
    work = Path(data) / "live-work"
    assert WORK_ROOTS[-1] == work  # inside the data directory, so a VM-based Docker shares it
    assert stat.S_IMODE(work.stat().st_mode) == 0o700 and list(work.iterdir()) == []
    assert (
        "Authorization was declared by the operator for engagement ACME-2026-114" in out.output
        and "not verify it" in out.output
    )
    assert "planned operations: 3   observations recorded: 3" in out.output and "coverage: complete" in out.output
    assert "run " in out.output and socket is not None


WORK_ROOTS: list[Any] = []


def _with_lookup(real: Any) -> Any:
    def run(
        db: Any, store: Any, request: Any, *, runtime: Any, environ: Any, lookup: Any = None, work_root: Any = None
    ) -> Any:
        WORK_ROOTS.append(work_root)
        return real(
            db,
            store,
            request,
            runtime=runtime,
            environ=environ,
            lookup=lambda host: ([PUBLIC], None),
            work_root=work_root,
        )

    return run


def test_a_failed_self_test_by_command_exits_two_and_says_nothing_was_collected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, close = serve(lambda r: http_response(200, {}, b"x"))
    monkeypatch.setattr(
        cli_module, "_runtime", lambda image: Container(server.port, failing_checks=("has no name resolution",))
    )
    monkeypatch.setattr(cli_module, "run_live", _with_lookup(cli_module.run_live))
    try:
        data, scope, approval_id = setup(tmp_path, server.port)
        out = invoke(
            "live",
            "run",
            "--scope",
            str(scope),
            "--approval-id",
            approval_id,
            "--image",
            IMAGE,
            "--ack-authorization",
            "--data-dir",
            data,
        )
    finally:
        close()
    assert (
        out.exit_code == 2
        and "LIVE-003" in out.output
        and "nothing was collected" in out.output
        and server.connections == 0
    )


def test_the_real_runtime_is_a_docker_runtime_for_a_pinned_image() -> None:
    from scopedagent.live.runtime import DockerRuntime  # noqa: PLC0415

    assert isinstance(cli_module._runtime(IMAGE), DockerRuntime)
    assert dump(scope_dict()) and PUBLIC
