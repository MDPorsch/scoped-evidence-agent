"""Global test guards. Every test runs with the network closed (X-01): an offline tool must not need it.

The guard blocks sockets of the network families (IPv4 and IPv6) and name resolution. Local sockets (AF_UNIX) stay allowed:
asyncio uses one internally to wake its event loop, and a local socket reaches nothing.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest


class NetworkAttempt(AssertionError):
    """Raised by the guard: a test (or the code under test) tried to open a network socket."""


_NETWORK = {socket.AF_INET, socket.AF_INET6}
_RealSocket = socket.socket


class _GuardedSocket(_RealSocket):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.family in _NETWORK:
            self.close()
            raise NetworkAttempt("a network socket was opened during a test: offline mode must not use the network")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: Any, **_kwargs: Any) -> Any:
        raise NetworkAttempt("a network call was made during a test: offline mode must not use the network")

    monkeypatch.setattr(socket, "socket", _GuardedSocket)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)
