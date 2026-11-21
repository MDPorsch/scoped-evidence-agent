"""AE-04 and AE-18: a host or path is canonical or refused. There is no best effort (docs/scope-format.md)."""

from __future__ import annotations

import pytest
from scopedagent.errors import ErrorCode, ScopeError
from scopedagent.policy.scope import canonical_host, canonical_path

pytestmark = pytest.mark.milestone("M1")

UE = chr(0xFC)  # u with diaeresis: a non-ASCII letter
FULLWIDTH_DOT = chr(0x3002)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("lab.example.invalid", "lab.example.invalid"),
        ("LAB.Example.INVALID", "lab.example.invalid"),
        ("lab.example.invalid.", "lab.example.invalid"),
        ("a-b.c-d.example", "a-b.c-d.example"),
        ("a1.b2.c3", "a1.b2.c3"),
        ("xn--bcher-kva.example.invalid", "xn--bcher-kva.example.invalid"),
        ("XN--BCHER-KVA.example.invalid", "xn--bcher-kva.example.invalid"),
        ("a" * 63 + ".example.invalid", "a" * 63 + ".example.invalid"),
    ],
)
def test_canonical_hosts(raw: str, expected: str) -> None:
    assert canonical_host(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "*.example.invalid",
        "*",
        "lab.*.invalid",  # wildcards
        "192.0.2.10",
        "[2001:db8::1]",
        "2001:db8::1",
        "::1",
        "2130706433",
        "0177.0.0.1",
        "0x7f.1",  # IP forms
        "user@lab.example.invalid",
        "user:pw@lab.example.invalid",  # userinfo
        "lab.example.invalid:443",
        "lab.example.invalid/path",
        "lab.example.invalid?x=1",
        "lab.example.invalid#f",
        "lab%2eexample.invalid",
        "lab.example.invalid%00",
        "lab\\.example.invalid",
        "lab example.invalid",
        "lab..example.invalid",
        ".lab.example.invalid",
        "lab.example.invalid..",
        "-lab.example.invalid",
        "lab-.example.invalid",
        "lab_x.example.invalid",
        "localhost",
        "lab",  # one label
        "lab." + UE + ".invalid",
        UE + "lab.example.invalid",  # non-ASCII: write the xn-- form
        "lab" + FULLWIDTH_DOT + "example" + FULLWIDTH_DOT + "invalid",
        "lab.example.invalid" + chr(0),
        "lab.example.invalid\n",
        "lab.example.invalid\t",
        " lab.example.invalid",
        "a" * 64 + ".example.invalid",  # label too long
        ".".join(["a" * 60] * 5),  # name too long (> 253)
        "xn--.example.invalid",
        "xn--a.example.invalid",
        "xn--zzzzzzzz.example.invalid",
        "xn--bcher-kva-.example.invalid",
        "",
    ],
)
def test_ambiguous_or_forbidden_hosts_are_refused(raw: str) -> None:
    with pytest.raises(ScopeError) as caught:
        canonical_host(raw)
    assert caught.value.code is ErrorCode.SCOPE_005


def test_a_long_but_legal_name_is_accepted() -> None:
    name = ".".join(["a" * 61] * 4) + ".bc"
    assert 200 < len(name) <= 253
    assert canonical_host(name) == name


def test_a_name_of_exactly_253_characters_is_accepted_and_254_is_refused() -> None:
    exactly = ".".join(["a" * 63, "a" * 63, "a" * 63, "a" * 61])  # 63*3 + 61 + 3 dots = 253
    assert len(exactly) == 253
    assert canonical_host(exactly) == exactly
    with pytest.raises(ScopeError):
        canonical_host(exactly + "a")


@pytest.mark.parametrize("raw", [None, 5, b"lab.example.invalid", ["lab.example.invalid"]])
def test_a_host_that_is_not_text_is_refused(raw: object) -> None:
    with pytest.raises(ScopeError):
        canonical_host(raw)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "raw",
    [
        "/",
        "/robots.txt",
        "/.well-known/security.txt",
        "/a/b-c_d~e.json",
        "/a/",
        "/.hidden",
        "/..a",
        "/a.b/c",
        "/" + "a" * 255,
    ],
)
def test_accepted_paths_are_returned_unchanged(raw: str) -> None:
    assert canonical_path(raw) == raw


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "robots.txt",
        "a/b",
        "/a?b=1",
        "/a#frag",
        "/a%2e%2e/b",
        "/a%2Fb",
        "/%00",
        "//a",
        "/a//b",
        "/./a",
        "/a/./b",
        "/a/..",
        "/../a",
        "/a/../b",
        "/a b",
        "/a\tb",
        "/a\nb",
        "/" + UE,
        "/a;b",
        "/a:b",
        "/a@b",
        "/a\\b",
        "/*",
        "/" + "a" * 256,
        "/a" + chr(0),
    ],
)
def test_ambiguous_or_forbidden_paths_are_refused(raw: str) -> None:
    with pytest.raises(ScopeError) as caught:
        canonical_path(raw)
    assert caught.value.code is ErrorCode.SCOPE_006
