"""M4: what the model may hand back (docs/ai-adapter.md). Every check is code; a failing item is dropped and the rule's sentence stands."""

from __future__ import annotations

import json
from typing import Any

import pytest

from scopedagent.ai.protocol import ModelUnavailable, RewordItem, RewordRequest
from scopedagent.ai.validation import (
    PROTECTED_WORDS,
    mask_hosts,
    parse_reply,
    protected_tokens,
    unmask,
    validate_item,
)

pytestmark = pytest.mark.milestone("M4")

ORIGINAL = "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected."


def request(*texts: str) -> RewordRequest:
    return RewordRequest(tuple(RewordItem(f"condition-{i}", t, 300) for i, t in enumerate(texts)), "reword-v1")


def reply(*pairs: tuple[str, Any]) -> str:
    return json.dumps({"items": [{"id": i, "text": t} for i, t in pairs]})


# ------------------------------------------------------------------------------------------ protected tokens ----
@pytest.mark.parametrize(
    ("text", "tokens"),
    [
        (ORIGINAL, {"2026-01-01T00:00:00Z"}),
        (
            "The certificate's RSA key is 1024 bits, shorter than the 2048 bits generally expected.",
            {"RSA", "1024", "2048"},
        ),
        ("The service negotiated TLSv1.0, a protocol version that is deprecated.", {"TLSv1.0"}),
        (
            "Strict-Transport-Security was absent from all 4 collected responses of this target.",
            {"Strict-Transport-Security", "4"},
        ),
        ("The API description at /openapi.json was served to an anonymous request.", {"API", "/openapi.json"}),
        ("robots.txt asks crawlers to skip 2 paths whose names suggest sensitive content.", {"robots.txt", "2"}),
        ("Some HOST_A and CWE-295 and SHA-1 or MD5.", {"HOST_A", "CWE-295", "SHA-1", "MD5"}),
        ("Server Apache/2.4.49 on bad.example.invalid.", {"/2.4.49", "bad.example.invalid"}),
        ("Rule R-TLS-01 found it.", {"R-TLS", "01"}),
    ],
)
def test_the_protected_tokens_of_a_sentence_are_its_numbers_dates_versions_names_paths_hosts_and_acronyms(
    text: str, tokens: set[str]
) -> None:
    assert protected_tokens(text) == tokens


def test_a_plain_sentence_has_no_protected_tokens() -> None:
    assert protected_tokens("The response redirects to an address that is not encrypted.") == set()


# ---------------------------------------------------------------------------------------------- one sentence ----
@pytest.mark.parametrize(
    "reworded",
    [
        ORIGINAL,
        "Before this observation was collected, the certificate had already expired on 2026-01-01T00:00:00Z.",
        "Put simply: the certificate expired on 2026-01-01T00:00:00Z, before this observation was collected.",
    ],
)
def test_a_faithful_rewording_is_accepted(reworded: str) -> None:
    assert validate_item(ORIGINAL, reworded, limit=300) is None


@pytest.mark.parametrize(
    ("reworded", "reason"),
    [
        ("The certificate expired on 2026-01-02T00:00:00Z, before this observation was collected.", "tokens"),
        ("The certificate expired, before this observation was collected.", "tokens"),
        ("The certificate expired on 2026-01-01T00:00:00Z, 3 days before this observation was collected.", "tokens"),
        (
            "The certificate expired on 2026-01-01T00:00:00Z over HTTPS, before this observation was collected.",
            "tokens",
        ),
        (
            "The Strict-Transport-Security certificate expired on 2026-01-01T00:00:00Z, before this observation was collected.",
            "tokens",
        ),
        ("", "empty"),
        ("   ", "empty"),
    ],
)
def test_a_rewording_that_changes_what_the_sentence_names_is_refused(reworded: str, reason: str) -> None:
    assert validate_item(ORIGINAL, reworded, limit=300) == reason


@pytest.mark.parametrize(
    "reworded",
    [
        "The certificate expired on 2026-01-01T00:00:00Z.\nbefore this observation was collected.",
        "The certificate expired on 2026-01-01T00:00:00Z, **before** this observation was collected.",
        "The certificate expired on 2026-01-01T00:00:00Z, [before](x) this observation was collected.",
        "The certificate expired on 2026-01-01T00:00:00Z <b>before</b> this observation was collected.",
        "The certificate expired on 2026-01-01T00:00:00Z, before this `observation` was collected.",
        'The certificate "expired" on 2026-01-01T00:00:00Z, before this observation was collected.',
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected. $(id)",
        "The certificate expired on 2026-01-01T00:00:00Z \\ before this observation was collected.",
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected {x}.",
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected. café",
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected." + chr(0x202E),
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected!",
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected?",
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected & recorded.",
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected=1.",
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected%.",
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected +",
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected@",
        "The certificate expired on 2026-01-01T00:00:00Z, before this observation was collected#",
    ],
)
def test_a_rewording_with_markup_links_code_or_odd_characters_is_refused(reworded: str) -> None:
    assert validate_item(ORIGINAL, reworded, limit=300) == "characters"


def test_a_path_the_original_does_not_name_is_refused() -> None:
    original = "The API description at /openapi.json was served to an anonymous request."
    assert (
        validate_item(original, "The API description at /admin was served to an anonymous request.", limit=300)
        == "tokens"
    )
    assert validate_item(original, original.replace("/openapi.json", "/openapi.json /admin"), limit=300) == "tokens"
    assert validate_item(original, "The API description was served to an anonymous request.", limit=300) == "tokens"
    assert (
        validate_item(original, "An anonymous request was served the API description at /openapi.json.", limit=300)
        is None
    )


def test_a_link_or_a_host_the_original_does_not_name_is_refused() -> None:
    assert validate_item(ORIGINAL, ORIGINAL + " See http://x.invalid/a for more.", limit=300) == "characters"
    assert validate_item(ORIGINAL, ORIGINAL + " See www.example.invalid for more.", limit=300) == "tokens"
    assert validate_item(ORIGINAL, ORIGINAL + " For example, e.g. this.", limit=300) == "tokens"


def test_a_rewording_over_the_fields_limit_or_twice_the_original_plus_sixty_is_refused() -> None:
    padded = ORIGINAL + " " + "word " * 40
    assert validate_item(ORIGINAL, padded, limit=3000) == "length"
    assert validate_item(ORIGINAL, ORIGINAL, limit=len(ORIGINAL) - 1) == "length"
    assert validate_item(ORIGINAL, ORIGINAL, limit=len(ORIGINAL)) is None


def test_the_length_rule_is_twice_the_original_plus_sixty_exactly() -> None:
    original = "Short sentence."
    allowed = 2 * len(original) + 60
    assert validate_item(original, ("a" * (allowed - 1)) + ".", limit=500) is None
    assert validate_item(original, ("a" * allowed) + ".", limit=500) == "length"


VERDICT_WORDS = (
    "confirmed", "verified", "proven", "proof", "exploit", "exploited", "exploitable", "critical",
    "severe", "definitely", "certainly", "guaranteed", "urgent", "immediately", "payload", "bypass",
)  # fmt: skip


def test_the_list_of_verdict_words_is_exactly_the_documented_one() -> None:
    assert frozenset(VERDICT_WORDS) == PROTECTED_WORDS  # written out here, so removing one from the code is noticed


@pytest.mark.parametrize("word", VERDICT_WORDS)
def test_a_word_of_verdict_the_original_does_not_use_is_refused(word: str) -> None:
    assert (
        validate_item(
            ORIGINAL,
            f"The certificate expired on 2026-01-01T00:00:00Z, {word} before this observation was collected.",
            limit=300,
        )
        == "words"
    )
    assert (
        validate_item(
            ORIGINAL,
            f"The certificate expired on 2026-01-01T00:00:00Z, {word.upper()} before this observation was collected.",
            limit=300,
        )
        == "words"
    )


def test_a_word_of_verdict_the_original_already_uses_may_stay() -> None:
    original = "Rule R-TLS-01 found weaknesses. Nothing was exploited."
    assert validate_item(original, "Rule R-TLS-01 found weaknesses, and nothing was exploited.", limit=300) is None
    assert (
        validate_item(original, "Rule R-TLS-01 found weaknesses, and nothing was exploited or proven.", limit=300)
        == "words"
    )


def test_a_rewording_that_contains_the_key_is_refused() -> None:
    key = "sk-ant-api03-SYNTHETIC-KEY-0001"
    assert validate_item(ORIGINAL, ORIGINAL + " x" + key, limit=300, secrets=(key,)) == "secret"
    assert validate_item(ORIGINAL, ORIGINAL, limit=300, secrets=(key,)) is None
    assert (
        validate_item(ORIGINAL, ORIGINAL + " x" + key, limit=300, secrets=("",)) is not None
    )  # an empty secret matches nothing special


# -------------------------------------------------------------------------------------------------- the reply ----
def test_a_valid_reply_is_returned_by_id() -> None:
    req = request("One sentence.", "Another sentence.")
    got = parse_reply(reply(("condition-0", "A."), ("condition-1", "B.")), req)
    assert got == {"condition-0": "A.", "condition-1": "B."}


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not json",
        "[]",
        "null",
        '"items"',
        "{}",
        '{"items": "x"}',
        '{"items": [], "extra": 1}',
        json.dumps({"items": [{"id": "condition-0", "text": "A."}, {"id": "condition-1", "text": "B."}], "note": "x"}),
        json.dumps({"items": [{"id": "condition-0", "text": "A.", "extra": 1}, {"id": "condition-1", "text": "B."}]}),
        json.dumps({"items": [{"id": "condition-0"}, {"id": "condition-1", "text": "B."}]}),
        json.dumps({"items": [{"id": "condition-0", "text": 5}, {"id": "condition-1", "text": "B."}]}),
        json.dumps({"items": [{"id": 0, "text": "A."}, {"id": "condition-1", "text": "B."}]}),
        json.dumps({"items": [{"id": "condition-0", "text": "A."}]}),
        json.dumps({"items": [{"id": "condition-0", "text": "A."}, {"id": "condition-0", "text": "B."}]}),
        json.dumps(
            {
                "items": [
                    {"id": "condition-0", "text": "A."},
                    {"id": "condition-1", "text": "B."},
                    {"id": "condition-2", "text": "C."},
                ]
            }
        ),
        json.dumps({"items": [{"id": "condition-0", "text": "A."}, {"id": "other", "text": "B."}]}),
        "```json\\n" + reply(("condition-0", "A."), ("condition-1", "B.")) + "\\n```",
        reply(("condition-0", "A."), ("condition-1", "B.")) + " trailing text",
        '{"items": [{"id": "condition-0", "text": "A."}, {"id": "condition-1", "text": "B."}]}' * 2,
    ],
)
def test_a_reply_that_is_not_exactly_the_requested_shape_is_invalid_as_a_whole(raw: str) -> None:
    with pytest.raises(ModelUnavailable) as caught:
        parse_reply(raw, request("One.", "Two."))
    assert caught.value.status == "invalid"


def test_a_reply_that_is_too_large_is_invalid_without_being_parsed() -> None:
    with pytest.raises(ModelUnavailable) as caught:
        parse_reply("{" + " " * 200_000 + "}", request("One."))
    assert caught.value.status == "invalid"


def test_the_error_names_the_problem_but_never_echoes_the_reply() -> None:
    secret = "SYNTHETIC-SECRET-0001"
    with pytest.raises(ModelUnavailable) as caught:
        parse_reply(f"not json {secret}", request("One."))
    assert secret not in str(caught.value) and secret not in caught.value.detail


# -------------------------------------------------------------------------------------------------- the hosts ----
def test_hosts_are_replaced_by_placeholders_and_put_back() -> None:
    texts = ["The certificate's names do not cover bad.example.invalid.", "Nothing here."]
    masked, mapping = mask_hosts(texts, ["bad.example.invalid", "other.example.invalid"])
    assert masked == ["The certificate's names do not cover HOST_A.", "Nothing here."]
    assert mapping == {"HOST_A": "bad.example.invalid"}
    assert unmask("It names HOST_A again.", mapping) == "It names bad.example.invalid again."


def test_the_longest_host_is_masked_first_and_case_does_not_matter() -> None:
    masked, mapping = mask_hosts(
        ["Seen on a.example.invalid and A.EXAMPLE.INVALID and example.invalid."],
        ["example.invalid", "a.example.invalid"],
    )
    assert masked == ["Seen on HOST_A and HOST_A and HOST_B."]
    assert mapping == {"HOST_A": "a.example.invalid", "HOST_B": "example.invalid"}


def test_a_host_inside_a_longer_name_is_not_masked() -> None:
    masked, _ = mask_hosts(["notbad.example.invalid and bad.example.invalid.evil"], ["bad.example.invalid"])
    assert masked == ["notbad.example.invalid and bad.example.invalid.evil"]


def test_nothing_is_masked_when_there_is_nothing_to_mask() -> None:
    assert mask_hosts(["A sentence."], []) == (["A sentence."], {})
    assert mask_hosts([], ["a.invalid"]) == ([], {})


def test_a_placeholder_the_model_invents_is_not_put_back() -> None:
    assert unmask("See HOST_Z.", {"HOST_A": "a.invalid"}) == "See HOST_Z."


def test_masked_sentences_keep_their_protected_placeholder_so_a_model_cannot_drop_the_host() -> None:
    original = "The certificate's names do not cover HOST_A."
    assert validate_item(original, "The names in the certificate do not cover HOST_A.", limit=300) is None
    assert validate_item(original, "The names in the certificate do not cover the host.", limit=300) == "tokens"
    assert validate_item(original, "The names in the certificate do not cover HOST_B.", limit=300) == "tokens"


def test_at_most_26_hosts_are_masked() -> None:
    hosts = [f"h{chr(97 + i)}.example.invalid" for i in range(26)] + ["extra.example.invalid"]
    text = " ".join(hosts)
    masked, mapping = mask_hosts([text], hosts)
    assert len(mapping) == 26 and masked[0].count("example.invalid") == 1  # the 27th host is left as it is
    assert set(mapping) == {f"HOST_{chr(65 + i)}" for i in range(26)}
