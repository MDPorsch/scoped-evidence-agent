"""AE-07, D-E12, D-E14: secrets are replaced before anything is stored. Secret-shaped values are built at run time, never literal."""

from __future__ import annotations

import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from scopedagent.pipeline.redact import REDACTED, is_sensitive_header, redact_headers, redact_text

pytestmark = pytest.mark.milestone("M2")


def jwt() -> str:
    return ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0", "dummysig" + "natureXYZ12"])


def github_token() -> str:
    return "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def aws_key() -> str:
    return "AK" + "IA" + "ABCDEFGHIJKLMNOP"


def pem() -> str:
    return "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\nabcdefghijkl\n-----END " + "RSA PRIVATE KEY-----"


# ----------------------------------------------------------------------------------------- headers ----
@pytest.mark.parametrize(
    "name",
    [
        "authorization",
        "Proxy-Authorization",
        "cookie",
        "Set-Cookie",
        "x-api-key",
        "X-Auth-Token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-amz-security-token",
        "x-access-token",
        "x-session-token",
        "x-client-secret",
        "x-db-password",
        "api-key",
        "x-apikey",
        "x-credentials",
    ],
)
def test_sensitive_header_names_are_recognised(name: str) -> None:
    assert is_sensitive_header(name)


@pytest.mark.parametrize(
    "name",
    [
        "content-type",
        "server",
        "x-powered-by",
        "strict-transport-security",
        "location",
        "x-ratelimit-remaining-requests",
        "x-request-id",
        "www-authenticate",
        "access-control-allow-origin",
        "x-debug-note",
        "cache-control",
        "etag",
    ],
)
def test_ordinary_header_names_are_not_redacted_by_name(name: str) -> None:
    assert not is_sensitive_header(name)


def test_header_names_are_lower_cased_and_sensitive_values_replaced_one_for_one() -> None:
    out = redact_headers(
        {"Set-Cookie": ["a=1; Path=/", "b=2"], "Server": ["nginx"], "X-API-KEY": ["SYNTHETIC-KEY-0001"]}
    )
    assert out == {"set-cookie": [REDACTED, REDACTED], "server": ["nginx"], "x-api-key": [REDACTED]}


def test_a_secret_shaped_value_in_an_ordinary_header_is_redacted_too() -> None:
    out = redact_headers({"x-debug-note": ["trace " + jwt()], "x-info": ["Bearer " + "abcdefgh12345678"]})
    assert jwt() not in out["x-debug-note"][0] and REDACTED in out["x-debug-note"][0]
    assert "abcdefgh12345678" not in out["x-info"][0]


def test_redacting_headers_never_mutates_its_input() -> None:
    original = {"Set-Cookie": ["a=1"]}
    redact_headers(original)
    assert original == {"Set-Cookie": ["a=1"]}


def test_duplicate_names_that_differ_only_in_case_are_merged_in_order() -> None:
    assert redact_headers({"Server": ["a"], "SERVER": ["b"]}) == {"server": ["a", "b"]}


# ------------------------------------------------------------------------------------------ text ----
@pytest.mark.parametrize(
    ("secret", "label"),
    [
        (jwt(), "jwt"),
        (github_token(), "github"),
        (aws_key(), "aws"),
        ("Bearer " + "q1w2e3r4t5y6u7i8", "bearer"),
        ("Basic " + "dXNlcjpwYXNzd29yZA==", "basic"),
        (pem(), "pem"),
    ],
)
def test_known_secret_shapes_are_replaced(secret: str, label: str) -> None:
    result = redact_text(f"before {secret} after")
    assert secret not in result.text and REDACTED in result.text and result.count >= 1, label
    assert result.text.startswith("before ") and result.text.endswith(" after")


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "api-key",
        "apikey",
        "access_key",
        "client_secret",
        "authorization",
        "auth_token",
    ],
)
@pytest.mark.parametrize("form", ["{key}={value}", '"{key}": "{value}"', "{key}: {value}", "'{key}':'{value}'"])
def test_a_value_after_a_sensitive_key_is_replaced_and_the_key_is_kept(key: str, form: str) -> None:
    value = "s3" + "cr3tValue" + "12345"
    result = redact_text("config " + form.format(key=key, value=value) + " end")
    assert value not in result.text and key in result.text and REDACTED in result.text


def test_text_without_secrets_is_returned_unchanged_with_a_zero_count() -> None:
    text = "User-agent: *\nDisallow: /admin\n# a comment about a token of appreciation\n"
    result = redact_text(text)
    assert result.text == text and result.count == 0


def test_prose_that_mentions_keywords_without_a_value_is_left_alone() -> None:
    text = "print your API key, token or password and put them in the report title"
    assert redact_text(text).text == text


def test_each_replacement_is_counted() -> None:
    assert redact_text(f"{jwt()} and {github_token()} and {aws_key()}").count == 3


def test_redaction_is_idempotent() -> None:
    once = redact_text(f"x {jwt()} y password=hunter2hunter2 z").text
    assert redact_text(once).text == once and redact_text(once).count == 0


def test_the_redaction_marker_itself_is_not_treated_as_a_secret() -> None:
    assert redact_text(f"token={REDACTED}").text == f"token={REDACTED}"


# --------------------------------------------------------------------------------------- e-mail ----
def test_an_email_at_another_domain_is_redacted() -> None:
    result = redact_text("Contact: someone@client-staff.example.invalid", own_host="lab.example.invalid")
    assert "someone@" not in result.text and REDACTED in result.text


def test_an_email_at_the_targets_own_host_or_a_subdomain_of_it_is_kept() -> None:
    text = "Contact: mailto:security@lab.example.invalid and ops@eu.lab.example.invalid"
    assert redact_text(text, own_host="lab.example.invalid").text == text


def test_a_lookalike_domain_is_not_the_targets_own_domain() -> None:
    result = redact_text(
        "a@evil-lab.example.invalid b@lab.example.invalid.evil.invalid", own_host="lab.example.invalid"
    )
    assert "a@" not in result.text and "b@" not in result.text


def test_without_a_known_host_every_email_is_redacted() -> None:
    assert "@" not in redact_text("security@lab.example.invalid").text


# ---------------------------------------------------------------------------------- robustness ----
def test_pathological_input_is_handled_in_linear_time() -> None:
    started = time.monotonic()
    for text in (
        "a" * 200_000,
        "token=" + "a" * 200_000,
        "eyJ" + "a" * 100_000 + "." * 3,
        "Bearer " + " " * 100_000,
        "@" * 100_000,
        "-----BEGIN " + "RSA PRIVATE KEY-----" + "x" * 100_000,
        "password" + "=" * 100_000,
    ):
        redact_text(text, own_host="lab.example.invalid")
    assert time.monotonic() - started < 3


@settings(max_examples=150, deadline=None)
@given(st.text(max_size=400))
def test_no_input_makes_redaction_crash_or_grow_without_bound(text: str) -> None:
    result = redact_text(text, own_host="lab.example.invalid")
    assert (
        isinstance(result.text, str) and result.count >= 0 and len(result.text) <= len(text) + 20 * max(result.count, 1)
    )


@settings(max_examples=100, deadline=None)
@given(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=12, max_size=40),
    st.sampled_from(["password", "secret", "token", "api_key"]),
)
def test_a_generated_value_after_a_sensitive_key_never_survives(value: str, key: str) -> None:
    assert value not in redact_text(f"{key}={value}").text
