"""Global test guards. Every test runs with the network closed (X-01): an offline tool must not need it."""

from __future__ import annotations

import socket
from typing import Any

import pytest


class NetworkAttempt(AssertionError):
    """Raised by the guard: a test (or the code under test) tried to open a network socket."""


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: Any, **_kwargs: Any) -> Any:
        raise NetworkAttempt("a socket was opened during a test: offline mode must not use the network")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)
