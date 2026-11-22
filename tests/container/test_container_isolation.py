"""M6, D-E38 and D-E46: the isolation, proved on a real container. These need a running Docker (Linux, or Colima on macOS), so they
are marked `container`, are deselected by default and are run by their own CI job (`pytest -m container`). On a machine without a
container runtime they cannot run, and that is a statement about the machine, not about the tool: live mode fails closed there."""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from scopedagent.live.isolation import OUTPUT_CHECK
from scopedagent.live.protocol import AllowedPair, Job, Proof
from scopedagent.live.runtime import DockerRuntime, docker_command

pytestmark = [pytest.mark.milestone("M6"), pytest.mark.container]

ROOT = Path(__file__).resolve().parents[2]
PINNED = AllowedPair(address="198.51.100.7", port=80)  # a documentation address: pinned, so the firewall must permit it


@pytest.fixture
def out_dir() -> Iterator[Path]:
    """The collector's output directory, as the controller makes it: world-writable (the collector is unprivileged) and under the
    home directory, which Colima and Docker Desktop share with their VM (the system temp directory is not shared there)."""
    base = Path.home() / ".cache" / "scopedagent-container-tests"
    base.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=base))
    path.chmod(0o777)
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture(scope="module")
def image() -> str:
    DockerRuntime.check_available()
    built = subprocess.run(
        ["docker", "build", "-q", "-f", "docker/collector/Dockerfile", "-t", "scopedagent-collector:test", "."],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=900,
    )  # fmt: skip
    assert built.returncode == 0, built.stderr[-2000:]
    return built.stdout.strip().splitlines()[
        -1
    ]  # the image ID, sha256:...: a locally built image has no repository digest


def test_the_container_proves_its_isolation_with_every_check_passing(image: str, out_dir: Path) -> None:
    session = DockerRuntime(image).start(credential_envs=[], out_dir=out_dir)
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
    assert OUTPUT_CHECK in names  # the unprivileged collector can write to the output directory it was given


def test_an_output_directory_the_collector_cannot_write_to_fails_the_proof_before_any_job(
    image: str, out_dir: Path
) -> None:
    """What went wrong on the first run on a Mac: the directory was not the one the VM shares, so the unprivileged collector could
    not write its results. The container now says so in its proof, before any request is sent. (A root-owned `/out` stands in for
    it, the same on every platform: file sharing on a Mac would let a merely `chmod`-ed directory through.)"""
    command = docker_command(image, out_dir, "scopedagent-unwritable-output", [])
    mount = command.index("-v")
    command[mount : mount + 2] = ["--tmpfs", "/out:rw,mode=0755"]
    allow = json.dumps({"allow": [PINNED.model_dump()]}) + "\n"
    result = subprocess.run(command, input=allow, capture_output=True, text=True, check=False, timeout=120)
    proof = Proof.model_validate_json(result.stdout.splitlines()[0])
    assert [c.name for c in proof.checks if not c.passed] == [OUTPUT_CHECK], proof
    assert result.returncode == 3  # no job was ever sent: stdin closed after the proof
    assert list(out_dir.iterdir()) == []


def test_a_collector_that_connects_elsewhere_fails_at_the_firewall_even_with_the_policy_bypassed(
    image: str, out_dir: Path
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
    command = docker_command(image, out_dir, "scopedagent-firewall-test", [])
    command[command.index("--entrypoint") : command.index("--entrypoint") + 2] = ["--entrypoint", "python"]
    command = [*command[: command.index(image)], image, "-c", script]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr[-1500:]
    assert "REACHED []" in result.stdout


def test_an_allowed_pair_is_reachable_and_the_same_address_on_another_port_is_not(image: str, out_dir: Path) -> None:
    """The positive control the test above lacks: a firewall that blocked everything would pass that one.

    Two listeners run in a helper container on the Docker bridge (so this process opens no socket and the test guard stays as it
    is). Only one of them is in the allow-list; both would accept the connection if the firewall let it through."""
    listen = (
        "import socket, time\n"
        "servers = []\n"
        "for port in (9001, 9002):\n"
        "    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', port)); s.listen(8)\n"
        "    servers.append(s)\n"
        "print('ready', flush=True)\n"
        "time.sleep(120)\n"
    )
    name = "scopedagent-positive-control-listener"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=60)
    started = subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, "--entrypoint", "python", image, "-c", listen],
        capture_output=True, text=True, check=False, timeout=120,
    )  # fmt: skip
    assert started.returncode == 0, started.stderr[-1500:]
    try:
        for _ in range(40):
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True, check=False, timeout=30)
            if "ready" in logs.stdout:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("the helper listener did not start: " + logs.stdout + logs.stderr[-500:])
        inspected = subprocess.run(
            ["docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],  # not .NetworkSettings.IPAddress: Docker 29 removed it
            capture_output=True, text=True, check=False, timeout=60,
        )  # fmt: skip
        address = inspected.stdout.strip()
        assert inspected.returncode == 0 and ipaddress.ip_address(address).version == 4, inspected.stderr
        script = (
            "import socket\n"
            "from scopedagent.live import isolation\n"
            "from scopedagent.live.protocol import AllowedPair\n"
            f"isolation.apply_rules([AllowedPair(address={address!r}, port=9001)])\n"
            "isolation.drop_privileges()\n"
            "def reach(host, port):\n"
            "    try:\n"
            "        socket.create_connection((host, port), timeout=3).close()\n"
            "        return True\n"
            "    except OSError:\n"
            "        return False\n"
            f"print('ALLOWED', reach({address!r}, 9001))\n"
            f"print('OTHER_PORT', reach({address!r}, 9002))\n"
            "print('DOCUMENTATION', reach('192.0.2.1', 80))\n"
        )
        command = docker_command(image, out_dir, "scopedagent-positive-control", [])
        command[command.index("--entrypoint") : command.index("--entrypoint") + 2] = ["--entrypoint", "python"]
        command = [*command[: command.index(image)], image, "-c", script]
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr[-1500:]
    assert "ALLOWED True" in result.stdout, result.stdout
    assert "OTHER_PORT False" in result.stdout and "DOCUMENTATION False" in result.stdout, result.stdout


def test_the_container_posture_is_what_the_command_says(image: str, out_dir: Path) -> None:
    script = "import os, sys\nprint('ROOTFS_RO', not os.access('/opt', os.W_OK))\nprint('UID', os.getuid())\n"
    command = docker_command(image, out_dir, "scopedagent-posture-test", [])
    command = [*command[: command.index(image)], image, "-c", script]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    assert result.returncode == 0, result.stderr[-1500:]
    # both: the root file system is read-only, and the process starts as root (it must, to install the firewall; it then drops)
    assert "ROOTFS_RO True" in result.stdout and "UID 0" in result.stdout, result.stdout


def test_a_job_outside_the_allow_list_is_refused_by_the_container_itself(image: str, out_dir: Path) -> None:
    session = DockerRuntime(image).start(credential_envs=[], out_dir=out_dir)
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
    assert list(out_dir.iterdir()) == []


def test_the_runtime_module_is_importable_on_this_platform() -> None:
    assert sys.platform and docker_command is not None
