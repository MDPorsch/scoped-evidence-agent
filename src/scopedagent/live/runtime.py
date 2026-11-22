"""Starting the collector in a container (D-E38). The container runtime is part of the trust base; the self-test is what shows it
behaved. A machine without a working runtime cannot run live mode at all: it fails closed with `LIVE-001`, and offline mode is
unaffected.

`docker_command` is the whole security posture of the container in one place: an image pinned by digest, a read-only root file
system, a small tmpfs, one output directory, no new privileges, every capability dropped except the three the entrypoint needs to
install a firewall and become an unprivileged user (and it drops those before the proof), memory, process and CPU limits, and no
credential on the command line (an environment variable is passed by name, so its value never appears in a process list).
"""

from __future__ import annotations

import re
import select
import shutil
import subprocess
import time
from pathlib import Path
from typing import IO, Protocol

from pydantic import ValidationError

from scopedagent.errors import ErrorCode, LiveFailed, LiveRefused
from scopedagent.live.protocol import MAX_PROOF_BYTES, AllowedPair, Job, Proof

IMAGE = re.compile(r"(?:[a-z0-9][a-z0-9._/:-]{0,200}@)?sha256:[0-9a-f]{64}")
WALL_CLOCK_SECONDS = 600
PROOF_TIMEOUT_SECONDS = 60


def validate_image(reference: str) -> str:
    """An image pinned by digest: `name@sha256:...`, or the bare `sha256:...` ID of an image built here. A tag is refused: it can move.

    A repository digest exists only once an image has been pushed, so a locally built image can only be named by its ID (a hash of
    its content, so as fixed as a digest). `docker run name@sha256:<id>` would instead try to pull `name` from a registry.
    """
    if not IMAGE.fullmatch(reference):
        raise LiveRefused(
            ErrorCode.LIVE_001,
            "the image must be pinned by digest, like registry/name@sha256:<64 hex digits> or the sha256:<64 hex digits> ID of an image you built: a tag can change",
        )
    return reference


def docker_command(image: str, out_dir: Path, name: str, credential_envs: list[str]) -> list[str]:
    command = [
        "docker", "run", "--rm", "-i",
        "--name", name,
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",  # noqa: S108 - a path inside the container
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "SETUID", "--cap-add", "SETGID",
        "--user", "0:0",
        "--memory", "256m", "--memory-swap", "256m", "--pids-limit", "64", "--cpus", "1",
        "--dns", "127.0.0.1",
        "-v", f"{out_dir}:/out:rw",
    ]  # fmt: skip
    for env in credential_envs:
        command += ["-e", env]  # by name: Docker reads the value from this process, so it is not in any argument
    command += ["--entrypoint", "python", validate_image(image), "-m", "scopedagent.live.isolation"]
    return command


class Session(Protocol):
    out_dir: Path

    def exchange_proof(self, allow: list[AllowedPair]) -> Proof: ...
    def send_job(self, job: Job) -> None: ...
    def finish(self) -> int: ...
    def abort(self) -> None: ...


class Runtime(Protocol):
    def start(self, *, credential_envs: list[str], out_dir: Path) -> Session: ...


def _readline(stream: IO[str], timeout: float, limit: int) -> str:
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready:
        raise LiveFailed(ErrorCode.LIVE_003, "the container did not report its isolation in time")
    line = stream.readline(limit + 1)
    if len(line) > limit:
        raise LiveFailed(ErrorCode.LIVE_003, "the container's report was too long")
    return line


class DockerSession:
    def __init__(self, process: subprocess.Popen[str], out_dir: Path, name: str) -> None:
        self._process, self.out_dir, self._name = process, out_dir, name

    def exchange_proof(self, allow: list[AllowedPair]) -> Proof:
        assert self._process.stdin is not None  # noqa: S101 - started with both pipes
        assert self._process.stdout is not None  # noqa: S101
        self._process.stdin.write('{"allow": [' + ",".join(p.model_dump_json() for p in allow) + "]}\n")
        self._process.stdin.flush()
        line = _readline(self._process.stdout, PROOF_TIMEOUT_SECONDS, MAX_PROOF_BYTES)
        try:
            return Proof.model_validate_json(line)
        except ValidationError:
            raise LiveFailed(ErrorCode.LIVE_003, "the container's isolation report was not valid") from None

    def send_job(self, job: Job) -> None:
        assert self._process.stdin is not None  # noqa: S101
        self._process.stdin.write(job.model_dump_json() + "\n")
        self._process.stdin.flush()
        self._process.stdin.close()

    def abort(self) -> None:
        """Stop a container that will not be given a job: closing its input makes it exit, and a stuck one is killed."""
        if self._process.stdin is not None and not self._process.stdin.closed:
            self._process.stdin.close()
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", self._name], capture_output=True, check=False, timeout=30)  # noqa: S603, S607
            self._process.kill()

    def finish(self) -> int:
        try:
            return self._process.wait(timeout=WALL_CLOCK_SECONDS)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", self._name], capture_output=True, check=False, timeout=30)  # noqa: S603, S607
            self._process.kill()
            raise LiveFailed(ErrorCode.LIVE_004, "the collector did not finish within its wall-clock limit") from None


class DockerRuntime:
    """The real thing. Needs a Linux network namespace: Linux, or Docker through Colima on macOS."""

    def __init__(self, image: str) -> None:
        self._image = validate_image(image)

    @staticmethod
    def check_available() -> None:
        if shutil.which("docker") is None:
            raise LiveFailed(ErrorCode.LIVE_001, "live mode needs a container runtime: `docker` was not found")
        probe = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if probe.returncode != 0 or not probe.stdout.strip():
            raise LiveFailed(ErrorCode.LIVE_001, "live mode needs a running container runtime: `docker info` failed")

    def start(self, *, credential_envs: list[str], out_dir: Path) -> Session:
        self.check_available()
        name = f"scopedagent-{int(time.time() * 1000)}"
        process = subprocess.Popen(  # noqa: S603
            docker_command(self._image, out_dir, name, credential_envs),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return DockerSession(process, out_dir, name)
