"""M6, D-E39 (docs/remote-live-design.md 4.3): which addresses a live run may connect to. Pure: no socket, no name server."""

from __future__ import annotations

import pytest

from scopedagent.live.addresses import AddressRefused, check_address, judge_host, parse_address, validate_networks

pytestmark = pytest.mark.milestone("M6")

PUBLIC = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "2a00:1450:4009:81f::200e"]
NEVER = [
    "0.0.0.0", "0.1.2.3", "169.254.169.254", "169.254.0.1", "224.0.0.1", "239.255.255.250", "255.255.255.255",
    "240.0.0.1", "::", "fe80::1", "febf::1", "ff02::1",
    "::ffff:8.8.8.8", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::808:808", "64:ff9b::a00:1",
    "2002:808:808::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "::8.8.8.8",
]  # fmt: skip
PRIVATE = [
    "127.0.0.1", "127.255.255.254", "::1", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.254",
    "192.168.0.1", "100.64.0.1", "100.127.255.254", "fc00::1", "fd12:3456::1",
]  # fmt: skip
EVERYTHING_PRIVATE = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "100.64.0.0/10",
    "fc00::/7",
    "::1/128",
)


def refusal(address: str, networks: tuple[str, ...] = ()) -> str | None:
    try:
        check_address(address, networks)
    except AddressRefused as exc:
        return str(exc)
    return None


@pytest.mark.parametrize("address", PUBLIC)
def test_a_public_address_is_acceptable_with_no_list(address: str) -> None:
    assert refusal(address) is None


@pytest.mark.parametrize("address", NEVER)
def test_these_are_refused_whatever_the_scope_lists(address: str) -> None:
    assert refusal(address) is not None and "never allowed" in str(refusal(address))
    assert refusal(address, EVERYTHING_PRIVATE) is not None


@pytest.mark.parametrize("address", PRIVATE)
def test_a_private_address_is_refused_unless_its_range_is_listed(address: str) -> None:
    assert "not a public address" in str(refusal(address))
    assert refusal(address, EVERYTHING_PRIVATE) is None


def test_a_listed_range_admits_only_itself() -> None:
    assert refusal("10.20.1.1", ("10.20.0.0/16",)) is None
    assert refusal("10.21.0.1", ("10.20.0.0/16",)) is not None
    assert refusal("192.168.1.1", ("10.20.0.0/16",)) is not None
    assert refusal("fd00::1", ("10.20.0.0/16",)) is not None  # a range of the other family never matches
    assert refusal("10.20.1.1", ("fd00::/8",)) is not None


@pytest.mark.parametrize(
    "text",
    [
        "",
        "localhost",
        "example.com",
        "1.2.3",
        "1.2.3.4.5",
        "::g",
        "fe80::1%eth0",
        "8.8.8.8%lo",
        "http://8.8.8.8",
        " 8.8.8.8",
        "8.8.8.8 ",
        "x" * 65,
        "999.1.1.1",
        "0x08080808",
        "8.8.8.08",
    ],
)
def test_anything_that_is_not_an_address_literal_is_refused(text: str) -> None:
    with pytest.raises(AddressRefused):
        parse_address(text)
    assert refusal(text) is not None


def test_non_text_is_refused() -> None:
    with pytest.raises(AddressRefused):
        parse_address(None)  # type: ignore[arg-type]


def test_ipv6_loopback_needs_listing_like_ipv4_loopback_and_is_not_swallowed_by_the_unspecified_range() -> None:
    assert "not a public address" in str(refusal("::1"))
    assert refusal("::1", ("::1/128",)) is None


# ---------------------------------------------------------------------------------------------- networks ----
@pytest.mark.parametrize("good", [["10.20.0.0/16"], ["fd00::/8"], ["192.168.1.0/24", "172.16.0.0/12"], []])
def test_a_valid_list_of_ranges_is_returned_unchanged(good: list[str]) -> None:
    assert validate_networks(good) == good


@pytest.mark.parametrize(
    "bad",
    [
        ["10.20.0.1"],
        ["10.20.0.1/16"],
        ["10.20.0.0/33"],
        ["fd00::/129"],
        ["not a network"],
        ["169.254.0.0/16"],
        ["169.254.1.0/24"],
        ["0.0.0.0/0"],
        ["::/0"],
        ["fe80::/10"],
        ["224.0.0.0/8"],
        ["10.0.0.0/8%x"],
        [""],
        [5],
    ],
)
def test_a_list_that_is_malformed_or_overlaps_a_never_range_is_refused(bad: list[str]) -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        validate_networks(bad)


def test_at_most_thirty_two_ranges() -> None:
    assert len(validate_networks([f"10.{i}.0.0/16" for i in range(32)])) == 32
    with pytest.raises(ValueError, match="at most 32"):
        validate_networks([f"10.{i}.0.0/16" for i in range(33)])


# ------------------------------------------------------------------------------------------------ hosts ----
def test_every_address_of_a_host_must_pass() -> None:
    assert judge_host(["8.8.8.8", "1.1.1.1"]) == ["8.8.8.8", "1.1.1.1"]
    with pytest.raises(AddressRefused, match="10.0.0.5"):
        judge_host(["8.8.8.8", "10.0.0.5"])  # one private address among public ones refuses the host
    with pytest.raises(AddressRefused, match="169.254.169.254"):
        judge_host(["1.1.1.1", "169.254.169.254"], EVERYTHING_PRIVATE)


def test_the_addresses_are_deduplicated_and_normalised_in_order() -> None:
    assert judge_host(["8.8.8.8", "8.8.8.8", "2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111"]) == [
        "8.8.8.8",
        "2606:4700:4700::1111",
    ]


def test_a_host_that_resolved_to_nothing_is_refused() -> None:
    with pytest.raises(AddressRefused, match="no address"):
        judge_host([])
