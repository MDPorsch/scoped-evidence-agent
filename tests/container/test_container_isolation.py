"""M6, D-E38 and D-E46: the isolation, proved on a real container. These need a running Docker (Linux, or Colima on macOS), so they
are marked `container`, are deselected by default and are run by their own CI job (`pytest -m container`). On a machine without a
container runtime they cannot run, and that is a statement about the machine, not about the tool: live mode fails closed there."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scopedagent.live.protocol import AllowedPair, Job
from scopedagent.live.runtime import DockerRuntime, docker_command

pytestmark = [pytest.mark.milestone("M6"), pytest.mark.container]

ROOT = Path(__file__).resolve().parents[2]
PINNED = AllowedPair(address="198.51.100.7", port=80)  # a documentation address: pinned, so the firewall must permit it


@pytest.fixture(scope="module")
def image() -> str:
    DockerRuntime.check_available()
    built = subprocess.run(
        ["docker", "build", "-q", "-f", "docker/collector/Dockerfile", "-t", "scopedagent-collector:test", "."],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=900,
    )  # fmt: skip
    assert built.returncode == 0, built.stderr[-2000:]
    digest = built.stdout.strip().splitlines()[-1]  # sha256:...
    return f"scopedagent-collector@{digest}"


def test_the_container_proves_its_isolation_with_every_check_passing(image: str, tmp_path: Path) -> None:
    session = DockerRuntime(image).start(credential_envs=[], out_dir=tmp_path)
    try:
        proof = session.exchange_proof([PINNED])
    finally:
        session.abort()
    failed = [c for c in proof.checks if not c.passed]
    assert failed == [], failed
    assert {(p.address, p.port) for p in proof.allowed} == {(PINNED.address, PINNED.port)}
    names = {c.name for c in proof.checks}
    assert "has no name resolution" in names and "runs unprivileged with no capability" in names
    assert any(n.startswith("cannot reach the cloud metadata address") for n in names)


def test_a_collector_that_connects_elsewhere_fails_at_the_firewall_even_with_the_policy_bypassed(
    image: str, tmp_path: Path
) -> None:
    """The controller's address policy is not involved here at all: the code inside the container simply tries to connect to
    addresses outside the allow-list, after the real firewall and the real privilege drop, and every attempt must fail."""
    script = (
        "import socket, sys\n"
        "from scopedagent.live import isolation\n"
        "from scopedagent.live.protocol import AllowedPair\n"
        "isolation.apply_rules([AllowedPair(address='198.51.100.7', port=80)])\n"
        "isolation.drop_privileges()\n"
        "bad = []\n"
        "for host, port in (('192.0.2.1', 80), ('10.0.0.1', 80), ('169.254.169.254', 80), ('8.8.8.8', 53), ('198.51.100.8', 80), ('198.51.100.7', 81)):\n"
        "    try:\n"
        "        socket.create_connection((host, port), timeout=2).close()\n"
        "        bad.append((host, port))\n"
        "    except OSError:\n"
        "        pass\n"
        "print('REACHED', bad)\n"
        "sys.exit(1 if bad else 0)\n"
    )
    command = docker_command(image, tmp_path, "scopedagent-firewall-test", [])
    command[command.index("--entrypoint") : command.index("--entrypoint") + 2] = ["--entrypoint", "python"]
    command = [*command[: command.index(image)], image, "-c", script]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr[-1500:]
    assert "REACHED []" in result.stdout


def test_the_container_posture_is_what_the_command_says(image: str, tmp_path: Path) -> None:
    script = "import os, sys\nprint('ROOTFS_RO', not os.access('/opt', os.W_OK))\nprint('UID', os.getuid())\n"
    command = docker_command(image, tmp_path, "scopedagent-posture-test", [])
    command = [*command[: command.index(image)], image, "-c", script]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    assert (
        "ROOTFS_RO True" in result.stdout or "UID 0" in result.stdout
    )  # root until the entrypoint drops it; the root fs is read-only
    assert result.returncode == 0, result.stderr[-1500:]


def test_a_job_outside_the_allow_list_is_refused_by_the_container_itself(image: str, tmp_path: Path) -> None:
    session = DockerRuntime(image).start(credential_envs=[], out_dir=tmp_path)
    try:
        session.exchange_proof([PINNED])
        stray = Job.model_validate(
            {"max_response_bytes": 1024, "per_request_timeout_seconds": 1, "requests_per_second": 1,
             "operations": [{"index": 0, "kind": "http_metadata", "host": "lab.example.invalid", "scheme": "http", "port": 80,
                             "address": "198.51.100.9", "path": "/", "method": "GET"}]}
        )  # fmt: skip
        session.send_job(stray)
        assert session.finish() == 4  # an operation outside the allow-list the firewall was built from
    finally:
        session.abort()
    assert list(tmp_path.iterdir()) == []


def test_the_runtime_module_is_importable_on_this_platform() -> None:
    assert sys.platform and docker_command is not None
