"""A scope file is operator input but it is parsed as hostile: injection, smuggling and confusables must all fail closed."""

from __future__ import annotations

from typing import Any

import pytest

from scopedagent.errors import ScopeError
from scopedagent.policy.scope import canonical_host, canonical_path, parse_scope
from tests.support import NOW, dump, scope_dict

pytestmark = pytest.mark.milestone("M1")

CONFUSABLES = {
    "cyrillic a": chr(0x430),
    "greek omicron": chr(0x3BF),
    "fullwidth a": chr(0xFF41),
    "zero width space": chr(0x200B),
    "zero width joiner": chr(0x200D),
    "right to left override": chr(0x202E),
    "word joiner": chr(0x2060),
    "soft hyphen": chr(0xAD),
    "bom": chr(0xFEFF),
    "tag latin a": chr(0xE0061),
    "combining acute": chr(0x301),
    "no break space": chr(0xA0),
    "ideographic space": chr(0x3000),
    "line separator": chr(0x2028),
}


@pytest.mark.parametrize("name", sorted(CONFUSABLES))
def test_confusable_and_invisible_characters_never_reach_a_host(name: str) -> None:
    char = CONFUSABLES[name]
    for raw in (
        f"lab{char}.example.invalid",
        f"{char}lab.example.invalid",
        f"lab.example.invalid{char}",
        f"lab.ex{char}ample.invalid",
    ):
        with pytest.raises(ScopeError):
            canonical_host(raw)


@pytest.mark.parametrize("name", sorted(CONFUSABLES))
def test_confusable_and_invisible_characters_never_reach_a_path_or_a_text_field(name: str) -> None:
    char = CONFUSABLES[name]
    with pytest.raises(ScopeError):
        canonical_path(f"/ro{char}bots.txt")
    for field in ("engagement_id", "owner_approval_ref"):
        data = scope_dict()
        data[field] = data[field] + char
        with pytest.raises(ScopeError):
            parse_scope(dump(data), now=NOW)


@pytest.mark.parametrize(
    "raw",
    [
        "lab.example.invalid\r\nHost: evil.example.invalid",  # header smuggling
        "lab.example.invalid%0d%0aX: y",
        "lab.example.invalid;evil.example.invalid",
        "lab.example.invalid,evil.example.invalid",
        "lab.example.invalid evil.example.invalid",
        "lab.example.invalid|evil.example.invalid",
        "lab.example.invalid`id`",
        "$(id).example.invalid",
        "lab.example.invalid'--",
        '"lab".example.invalid',
        "lab.example.invalid</script>",
    ],
)
def test_injection_shaped_hosts_are_refused(raw: str) -> None:
    with pytest.raises(ScopeError):
        canonical_host(raw)


@pytest.mark.parametrize(
    "raw", ["/a\r\nHost: evil", "/a%0d%0a", "/a;b", "/a`id`", "/$(id)", "/a'--", "/a<b", "/a|b", "/a,b", "/~root/../x"]
)
def test_injection_shaped_paths_are_refused(raw: str) -> None:
    with pytest.raises(ScopeError):
        canonical_path(raw)


def test_a_huge_input_is_refused_quickly_not_processed() -> None:
    import time  # noqa: PLC0415

    started = time.monotonic()
    with pytest.raises(ScopeError):
        parse_scope("a: " + "x" * 5_000_000, now=NOW)
    with pytest.raises(ScopeError):
        canonical_host("a" * 5_000_000)
    with pytest.raises(ScopeError):
        canonical_path("/" + "a" * 5_000_000)
    assert time.monotonic() - started < 2


def test_pathological_backtracking_input_is_handled_in_linear_time() -> None:
    import time  # noqa: PLC0415

    started = time.monotonic()
    for raw in ("a" * 60 + "!", ("a-" * 30) + "-", "a." * 120 + "!", "x" * 250 + "."):
        with pytest.raises(ScopeError):
            canonical_host(raw)
    for raw in ("/" + "a/" * 120 + "?", "/" + "a." * 120 + "%"):
        with pytest.raises(ScopeError):
            canonical_path(raw)
    assert time.monotonic() - started < 1


@pytest.mark.parametrize("value", [None, 1, 1.5, True, [], {}, b"x"])
@pytest.mark.parametrize("field", ["engagement_id", "owner_approval_ref"])
def test_non_text_in_text_fields_is_refused_with_a_scope_error_not_a_crash(field: str, value: Any) -> None:
    data = scope_dict()
    data[field] = value
    with pytest.raises(ScopeError):
        parse_scope(dump(data), now=NOW)


def test_error_messages_never_echo_the_offending_value_for_text_fields() -> None:
    data = scope_dict()
    data["owner_approval_ref"] = "has space SYNTHETIC-SECRET-0001"
    with pytest.raises(ScopeError) as caught:
        parse_scope(dump(data), now=NOW)
    assert "SYNTHETIC-SECRET-0001" not in str(caught.value)
