"""Resolve each declared host once (D-E39). The only controller code that touches a name server.

The answer is judged address by address (`addresses.judge_host`) and pinned: the container is given `IP:port` pairs and has no DNS, so
there is no second lookup for a rebinding trick to answer differently. A name that does not resolve, or whose answers are not all
acceptable, is not contacted at all and its operations are recorded as refused.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass

from scopedagent.live.addresses import AddressRefused, judge_host

Lookup = Callable[[str], tuple[list[str], str | None]]


def system_lookup(host: str) -> tuple[list[str], str | None]:
    """(addresses in the order the system gave them, the canonical name when it differs from the one asked)."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM, flags=socket.AI_CANONNAME)
    canonical = infos[0][3] if infos and infos[0][3] and infos[0][3].lower() != host.lower() else None
    return [str(info[4][0]) for info in infos], canonical


@dataclass(frozen=True)
class Resolution:
    host: str
    addresses: tuple[str, ...]  # judged and deduplicated; empty when refused
    canonical_name: str | None  # data only: a CNAME is recorded, never resolved or contacted
    refusal: str | None  # why the host will not be contacted, safe to show
    resolved: tuple[
        str, ...
    ] = ()  # everything the name resolved to, judged or not: the DNS fact, whatever is contacted


def resolve_hosts(
    hosts: list[str], allowed_networks: list[str], lookup: Lookup = system_lookup
) -> dict[str, Resolution]:
    """Each distinct host once, in the order given."""
    result: dict[str, Resolution] = {}
    for host in dict.fromkeys(hosts):
        try:
            found, canonical = lookup(host)
        except OSError:
            result[host] = Resolution(host, (), None, "the name did not resolve")
            continue
        every = tuple(dict.fromkeys(found))
        try:
            result[host] = Resolution(host, tuple(judge_host(found, allowed_networks)), canonical, None, every)
        except AddressRefused as exc:
            result[host] = Resolution(host, (), canonical, str(exc), every)
    return result
