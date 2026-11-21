"""Global test guards. Every test runs with the network closed (X-01): an offline tool must not need it.

The guard blocks sockets of the network families (IPv4 and IPv6) and name resolution. Local sockets (AF_UNIX) stay allowed:
asyncio uses one internally to wake its event loop, and a local socket reaches nothing.

One exception, narrow and explicit: a test marked `loopback` (the live collector's own tests, which need a server to talk to) may
create network sockets, but bind and connect only on loopback addresses, and resolve only loopback literals.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest


class NetworkAttempt(AssertionError):
    """Raised by the guard: a test (or the code under test) tried to open a network socket."""


_NETWORK = {socket.AF_INET, socket.AF_INET6}
_RealSocket = socket.socket


def _is_loopback(host: object) -> bool:
    import ipaddress  # noqa: PLC0415

    try:
        return ipaddress.ip_address(str(host).split("%")[0]).is_loopback
    except ValueError:
        return False


class _GuardedSocket(_RealSocket):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.family in _NETWORK:
            self.close()
            raise NetworkAttempt("a network socket was opened during a test: offline mode must not use the network")


class _LoopbackSocket(_RealSocket):  # type: ignore[misc]
    """For a test marked `loopback` only: a network socket may exist, but it may bind and connect only on loopback."""

    def bind(self, address: Any) -> None:
        if self.family in _NETWORK and not _is_loopback(address[0]):
            raise NetworkAttempt("a loopback test bound a socket to an address that is not loopback")
        super().bind(address)

    def connect(self, address: Any) -> None:
        if self.family in _NETWORK and not _is_loopback(address[0]):
            raise NetworkAttempt("a loopback test connected to an address that is not loopback")
        super().connect(address)

    def connect_ex(self, address: Any) -> int:
        if self.family in _NETWORK and not _is_loopback(address[0]):
            raise NetworkAttempt("a loopback test connected to an address that is not loopback")
        return super().connect_ex(address)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    def blocked(*_args: Any, **_kwargs: Any) -> Any:
        raise NetworkAttempt("a network call was made during a test: offline mode must not use the network")

    if request.node.get_closest_marker("loopback") is not None:
        real_connection, real_getaddrinfo = socket.create_connection, socket.getaddrinfo

        def create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
            if not _is_loopback(address[0]):
                raise NetworkAttempt("a loopback test connected to an address that is not loopback")
            return real_connection(address, *args, **kwargs)

        def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
            if not _is_loopback(host):
                raise NetworkAttempt("a loopback test resolved a name: only loopback literals are allowed")
            return real_getaddrinfo(host, *args, **kwargs)

        monkeypatch.setattr(socket, "socket", _LoopbackSocket)
        monkeypatch.setattr(socket, "create_connection", create_connection)
        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(socket, "gethostbyname", blocked)
        return
    monkeypatch.setattr(socket, "socket", _GuardedSocket)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Any]:
    """(database, artifact store, data dir) on a fresh private store, closed afterwards."""
    from tests.support import make_env  # noqa: PLC0415

    db, store, data_dir = make_env(tmp_path)
    yield db, store, data_dir
    db.close()
