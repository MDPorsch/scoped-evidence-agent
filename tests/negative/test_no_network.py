"""X-01: nothing in this version opens a network connection, and nothing here can."""

from __future__ import annotations

import socket
import subprocess
import sys
import textwrap

import pytest

from tests.conftest import NetworkAttempt

pytestmark = pytest.mark.milestone("M1")


def test_the_guard_really_blocks_sockets() -> None:
    for call in (
        lambda: socket.socket(),
        lambda: socket.create_connection(("192.0.2.1", 80)),
        lambda: socket.getaddrinfo("lab.example.invalid", 443),
        lambda: socket.gethostbyname("lab.example.invalid"),
    ):
        with pytest.raises(NetworkAttempt):
            call()


def test_network_sockets_of_both_families_are_blocked_but_local_ones_are_not() -> None:
    for family in (socket.AF_INET, socket.AF_INET6):
        with pytest.raises(NetworkAttempt):
            socket.socket(family, socket.SOCK_STREAM)
        with pytest.raises(NetworkAttempt):
            socket.socket(family, socket.SOCK_DGRAM)
    left, right = socket.socketpair()  # what asyncio uses to wake its loop: local, reaches nothing
    left.close()
    right.close()
    local = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    local.close()


def test_an_offline_event_loop_can_run_under_the_guard() -> None:
    import asyncio  # noqa: PLC0415

    async def answer() -> int:
        return 42

    assert asyncio.run(answer()) == 42


def test_importing_the_package_loads_no_network_client_library() -> None:
    code = textwrap.dedent(
        """
        import sys
        import scopedagent, scopedagent.cli, scopedagent.policy.scope, scopedagent.storage.repositories, scopedagent.storage.artifacts
        clients = {"httpx", "requests", "urllib3", "aiohttp", "http.client", "urllib.request", "dns"}
        print(",".join(sorted(m for m in clients if m in sys.modules)))
        """
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True, timeout=60)
    # `socket` and `ssl` are deliberately not on this list: the standard library's own asyncio imports them when SQLAlchemy is
    # loaded. What this proves is that no HTTP or DNS client library is pulled in. That our own code imports no network module is
    # checked by test_no_source_file_imports_a_network_module, and that nothing can open a socket by the autouse guard.
    assert result.stdout.strip() == ""


def test_the_project_declares_no_network_client_dependency_yet() -> None:
    import tomllib  # noqa: PLC0415

    from tests.support import ROOT  # noqa: PLC0415

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    names = {d.split(">")[0].split("<")[0].split("=")[0].strip().lower() for d in declared}
    assert not names & {"httpx", "requests", "aiohttp", "urllib3", "dnspython", "cryptography"}, names


def test_no_source_file_imports_a_network_module() -> None:
    import re  # noqa: PLC0415

    from tests.support import ROOT  # noqa: PLC0415

    banned = re.compile(
        r"^\s*(import|from)\s+(socket|ssl|http\.client|urllib\.request|httpx|requests|aiohttp|dns)\b", re.MULTILINE
    )
    offenders = [
        str(p.relative_to(ROOT)) for p in (ROOT / "src").rglob("*.py") if banned.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []
