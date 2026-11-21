"""The strict loader: what a scope or a fixture pack may not contain (threat model B1, docs/scope-format.md)."""

from __future__ import annotations

import pytest
from scopedagent.errors import ErrorCode, ScopeError
from scopedagent.policy.scope import parse_scope

from tests.support import NOW, dump, scope_dict, scope_text

pytestmark = pytest.mark.milestone("M1")


def refused(text: str, code: ErrorCode) -> None:
    with pytest.raises(ScopeError) as caught:
        parse_scope(text, now=NOW)
    assert caught.value.code is code, caught.value


def test_a_valid_scope_parses() -> None:
    assert parse_scope(scope_text(), now=NOW).config.engagement_id == "lab-healthy-001"


@pytest.mark.parametrize(
    "text",
    [
        "a: &x [1]\nb: *x\n",  # alias
        "a: &x 1\n",  # anchor alone
        "base: &b {x: 1}\nother:\n  <<: *b\n",  # merge key through an alias
        "a: 1\n<<: {b: 2}\n",  # merge key, no alias
    ],
)
def test_aliases_anchors_and_merge_keys_are_refused(text: str) -> None:
    refused(scope_text() + text, ErrorCode.SCOPE_002)


def test_a_billion_laughs_document_is_refused_without_expanding() -> None:
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: *c\n"
    refused(bomb, ErrorCode.SCOPE_002)


def test_duplicate_keys_are_refused_at_any_level() -> None:
    refused(scope_text() + "max_requests: 500\n", ErrorCode.SCOPE_002)
    nested = scope_text().replace("    ports: [443]\n", "    ports: [443]\n    ports: [80]\n")
    refused(nested, ErrorCode.SCOPE_002)


@pytest.mark.parametrize("key_line", ["? [1, 2]\n: v\n", "1: one\n", "true: yes\n", "null: nothing\n"])
def test_keys_must_be_plain_strings(key_line: str) -> None:
    refused(scope_text() + key_line, ErrorCode.SCOPE_002)


def test_nesting_deeper_than_sixteen_is_refused() -> None:
    deep = "x: " + "[" * 40 + "1" + "]" * 40 + "\n"
    refused(scope_text() + deep, ErrorCode.SCOPE_002)


def test_a_file_over_64_kib_is_refused_before_parsing() -> None:
    refused(scope_text() + "# " + "a" * 70_000 + "\n", ErrorCode.SCOPE_001)


@pytest.mark.parametrize("text", ["", "   \n", "- a\n- b\n", "just text\n", "a: [unclosed\n", "---\na: 1\n---\nb: 2\n"])
def test_empty_non_mapping_malformed_or_multi_document_input_is_refused(text: str) -> None:
    with pytest.raises(ScopeError) as caught:
        parse_scope(text, now=NOW)
    assert caught.value.code in {ErrorCode.SCOPE_001, ErrorCode.SCOPE_002, ErrorCode.SCOPE_003}


def test_python_object_tags_are_not_constructed() -> None:
    with pytest.raises(ScopeError):
        parse_scope(scope_text() + "x: !!python/object/apply:os.system ['echo hi']\n", now=NOW)


def test_an_unquoted_timestamp_is_refused_with_a_hint_to_quote_it() -> None:
    text = scope_text().replace("'2026-12-31T23:59:00Z'", "2026-12-31T23:59:00Z")
    with pytest.raises(ScopeError) as caught:
        parse_scope(text, now=NOW)
    assert caught.value.code is ErrorCode.SCOPE_004 and "quote" in str(caught.value).lower()


def test_text_fields_refuse_control_and_bidi_characters() -> None:
    for bad in (chr(0), chr(0x1B), chr(0x202E), chr(0x200B), chr(0x2028)):
        data = scope_dict()
        data["owner_approval_ref"] = f"local{bad}consent"
        with pytest.raises(ScopeError):
            parse_scope(dump(data), now=NOW)
