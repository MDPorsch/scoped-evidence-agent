"""Which addresses a live run may connect to (D-E39, docs/remote-live-design.md 4.3).

The rules are the ones `boundarycheck` ships, so the two tools cannot disagree: globally routable addresses are acceptable; private
ranges only when the scope lists them; a few ranges never, whatever is listed. The controller judges every address a host resolves
to, and the container's firewall (`isolation.py`) is a second, independent layer built from the same allow-list.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from typing import Final

MAX_NETWORKS: Final = 32
MAX_ADDRESS_TEXT: Final = 64

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network
_Address = ipaddress.IPv4Address | ipaddress.IPv6Address

# Never acceptable, whatever the operator lists. Each entry says why, for the refusal message.
NEVER: Final[tuple[tuple[_Net, str], ...]] = tuple(
    (ipaddress.ip_network(net), why)
    for net, why in (
        ("0.0.0.0/8", "the 'this network' range"),
        ("169.254.0.0/16", "link-local, where cloud metadata services live"),
        ("224.0.0.0/4", "multicast"),
        ("240.0.0.0/4", "reserved or broadcast"),
        ("fe80::/10", "link-local"),
        ("ff00::/8", "multicast"),
        ("::ffff:0:0/96", "an IPv4-mapped IPv6 address (it exists to reach an IPv4 host)"),
        ("64:ff9b::/96", "a NAT64 address (it exists to reach an IPv4 host through a gateway)"),
        ("64:ff9b:1::/48", "a NAT64 address (it exists to reach an IPv4 host through a gateway)"),
        ("2002::/16", "a 6to4 address (it embeds an IPv4 address)"),
        ("2001::/32", "a Teredo address (it embeds an IPv4 address)"),
        ("::/96", "an IPv4-compatible or unspecified IPv6 address"),
    )
)
_IPV6_LOOPBACK: Final = ipaddress.IPv6Address("::1")


class AddressRefused(ValueError):
    """An address may not be connected to. The message names the rule and is safe to show."""


def _never_reason(address: _Address) -> str | None:
    if address == _IPV6_LOOPBACK:
        return None  # ::1 sits inside ::/96 but is ordinary loopback: it needs listing like 127.0.0.1
    for network, why in NEVER:
        if address.version == network.version and address in network:
            return why
    return None


def parse_address(text: str) -> _Address:
    """An IP address literal, or `AddressRefused`. A zone id (`fe80::1%eth0`) is never accepted."""
    if not isinstance(text, str) or not text or len(text) > MAX_ADDRESS_TEXT:
        raise AddressRefused("not an IP address literal")
    if "%" in text:
        raise AddressRefused("an IP address with a zone id is never accepted")
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        raise AddressRefused("not an IP address literal") from None


def check_address(text: str, allowed_networks: Iterable[str] = ()) -> _Address:
    """The parsed address, or `AddressRefused` naming the rule. Safe to show: it holds the address and a rule, nothing else."""
    address = parse_address(text)
    why = _never_reason(address)
    if why is not None:
        raise AddressRefused(f"{address} is never allowed: {why}")
    if address.is_global:
        return address
    for network in allowed_networks:
        net = ipaddress.ip_network(network, strict=False)
        if address.version == net.version and address in net:
            return address
    raise AddressRefused(
        f"{address} is not a public address; add its range to egress.allowed_networks if it is your target's network"
    )


def validate_networks(networks: Sequence[str]) -> list[str]:
    """Check a scope's `allowed_networks` list. Returns it unchanged, or raises ValueError naming what is wrong."""
    if len(networks) > MAX_NETWORKS:
        raise ValueError(f"at most {MAX_NETWORKS} ranges may be listed")
    for text in networks:
        if not isinstance(text, str) or "/" not in text or "%" in text:
            raise ValueError("write each range with its prefix length, for example 10.20.0.0/16")
        try:
            net = ipaddress.ip_network(text, strict=True)
        except ValueError:
            raise ValueError("a listed range is not a valid network (host bits set, or a bad prefix)") from None
        for never, why in NEVER:
            if net.version == never.version and net.overlaps(never):
                raise ValueError(f"a listed range includes addresses that are never allowed ({why})")
    return list(networks)


def judge_host(addresses: Sequence[str], allowed_networks: Iterable[str] = ()) -> list[str]:
    """Every address a host resolved to must pass, or the host is not contacted at all (D-E39).

    Returns the addresses in the order given, deduplicated. An empty list is refused: a name that resolves to nothing has nothing to
    pin. Raises `AddressRefused` for the first address that fails, so one private address among public ones refuses the host.
    """
    if not addresses:
        raise AddressRefused("the host resolved to no address")
    networks = list(allowed_networks)
    accepted: list[str] = []
    for text in addresses:
        address = check_address(text, networks)
        if str(address) not in accepted:
            accepted.append(str(address))
    return accepted
