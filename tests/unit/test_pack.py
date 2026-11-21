"""docs/fixture-format.md: a fixture pack is untrusted input, loaded with the same strictness as a scope."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from scopedagent.adapters.pack import MAX_PACK_BYTES, load_pack
from scopedagent.errors import ErrorCode, PackError
from tests.support import AI_PACK, FIXTURES, PACKS

pytestmark = pytest.mark.milestone("M2")

BASE: dict[str, Any] = {"pack": "unit-test"}


def write(tmp_path: Path, data: Any, name: str = "pack.yaml") -> Path:
    path = tmp_path / name
    path.write_text(data if isinstance(data, str) else yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def refused(tmp_path: Path, data: Any, code: ErrorCode) -> PackError:
    with pytest.raises(PackError) as caught:
        load_pack(write(tmp_path, data))
    assert caught.value.code is code, f"{caught.value.code}: {caught.value}"
    return caught.value


@pytest.mark.parametrize("name", [*PACKS, AI_PACK])
def test_every_committed_pack_loads(name: str) -> None:
    pack = load_pack(FIXTURES / "web_responses" / f"{name}.yaml")
    assert pack.name == name and (pack.dns or pack.ai)


def test_the_committed_packs_hold_the_documented_sections() -> None:
    healthy = load_pack(FIXTURES / "web_responses" / "healthy.yaml")
    assert (
        list(healthy.dns) == ["lab.example.invalid"]
        and list(healthy.tls) == ["lab.example.invalid:443"]
        and len(healthy.http) == 3
    )
    ai = load_pack(FIXTURES / "web_responses" / f"{AI_PACK}.yaml")
    assert not ai.dns and not ai.http and len(ai.ai) == 5


def test_every_section_is_optional(tmp_path: Path) -> None:
    pack = load_pack(write(tmp_path, BASE))
    assert pack.name == "unit-test" and not (pack.dns or pack.tls or pack.http or pack.ai)


@pytest.mark.parametrize("name", ["ab", "A" * 3, "-abc", "a b c", "a" * 41, "", "a_b"])
def test_the_pack_name_follows_its_pattern(tmp_path: Path, name: str) -> None:
    refused(tmp_path, {"pack": name}, ErrorCode.PACK_003)


def test_unknown_top_level_keys_and_wrong_types_are_refused(tmp_path: Path) -> None:
    refused(tmp_path, {**BASE, "extra": 1}, ErrorCode.PACK_003)
    refused(tmp_path, {**BASE, "dns": ["not", "a", "map"]}, ErrorCode.PACK_003)
    refused(tmp_path, {"pack": 5}, ErrorCode.PACK_003)
    refused(tmp_path, ["a", "list"], ErrorCode.PACK_003)
    refused(tmp_path, "just text\n", ErrorCode.PACK_003)


@pytest.mark.parametrize(
    "host",
    ["UPPER.example.invalid", "*.example.invalid", "192.0.2.10", "lab.example.invalid:443", "a b.example.invalid", ""],
)
def test_dns_keys_must_be_canonical_hosts(tmp_path: Path, host: str) -> None:
    refused(tmp_path, {**BASE, "dns": {host: {"status": "ok", "records": {}}}}, ErrorCode.PACK_003)


@pytest.mark.parametrize(
    "key",
    [
        "lab.example.invalid",
        "lab.example.invalid:0",
        "lab.example.invalid:65536",
        "UPPER.example.invalid:443",
        "lab.example.invalid:x",
        ":443",
        "https://lab.example.invalid:443",
    ],
)
def test_tls_keys_are_host_colon_port(tmp_path: Path, key: str) -> None:
    refused(tmp_path, {**BASE, "tls": {key: {"status": "ok"}}}, ErrorCode.PACK_003)


@pytest.mark.parametrize(
    "key",
    [
        "lab.example.invalid:443/robots.txt",
        "ftp://lab.example.invalid:443/x",
        "https://lab.example.invalid/robots.txt",
        "https://lab.example.invalid:443",
        "https://lab.example.invalid:443/a?b=1",
        "https://lab.example.invalid:443/a/../b",
        "https://UPPER.example.invalid:443/x",
        "https://u@lab.example.invalid:443/x",
        "https://lab.example.invalid:99999/x",
    ],
)
def test_http_keys_are_absolute_canonical_urls_with_an_explicit_port_and_no_query(tmp_path: Path, key: str) -> None:
    refused(tmp_path, {**BASE, "http": {key: {"status": 200}}}, ErrorCode.PACK_003)


@pytest.mark.parametrize(
    "key",
    [
        "probe:support-bot:canary-echo-v1",
        "probe:Bad:canary-echo-v1:0",
        "probe:support-bot:canary-echo-v1:x",
        "probe:support-bot:canary-echo-v1:-1",
        "probe:support-bot:canary-echo-v1:10",
        "probe::canary-echo-v1:0",
        "http://x",
        "probe:support-bot:canary-echo-v1:0:extra",
    ],
)
def test_ai_keys_are_a_metadata_url_or_a_probe_key(tmp_path: Path, key: str) -> None:
    refused(tmp_path, {**BASE, "ai": {key: {"status": 200}}}, ErrorCode.PACK_003)


def test_valid_keys_of_every_section_are_accepted(tmp_path: Path) -> None:
    data = {
        **BASE,
        "dns": {"a.example.invalid": {}},
        "tls": {"a.example.invalid:8443": {}},
        "http": {"http://a.example.invalid:8080/x/y": {}, "https://a.example.invalid:443/": {}},
        "ai": {"https://a.example.invalid:443/v1/models": {}, "probe:bot-1:canary-echo-v1:9": {}},
    }
    pack = load_pack(write(tmp_path, data))
    assert len(pack.http) == 2 and len(pack.ai) == 2


def test_each_section_is_capped_at_200_entries(tmp_path: Path) -> None:
    ok = {f"h{i}.example.invalid": {} for i in range(200)}
    assert len(load_pack(write(tmp_path, {**BASE, "dns": ok})).dns) == 200
    refused(tmp_path, {**BASE, "dns": {**ok, "h200.example.invalid": {}}}, ErrorCode.PACK_003)


def test_an_entry_must_be_a_mapping(tmp_path: Path) -> None:
    refused(tmp_path, {**BASE, "dns": {"a.example.invalid": "text"}}, ErrorCode.PACK_003)


# ------------------------------------------------------------------------------------ strict yaml ----
@pytest.mark.parametrize(
    "text",
    [
        "pack: abc\nx: &a [1]\ny: *a\n",
        "pack: abc\npack: def\n",
        "pack: abc\n<<: {a: 1}\n",
        "pack: abc\n? [1]\n: v\n",
        "pack: abc\nx: " + "[" * 40 + "1" + "]" * 40 + "\n",
    ],
)
def test_aliases_duplicate_keys_merge_keys_odd_keys_and_deep_nesting_are_refused(tmp_path: Path, text: str) -> None:
    refused(tmp_path, text, ErrorCode.PACK_002)


def test_python_tags_and_control_characters_are_refused(tmp_path: Path) -> None:
    with pytest.raises(PackError):
        load_pack(write(tmp_path, "pack: abc\nx: !!python/object/apply:os.system ['id']\n"))
    refused(tmp_path, "pack: abc\nx: a" + chr(0) + "b\n", ErrorCode.PACK_001)


def test_an_oversize_pack_is_refused_before_it_is_parsed(tmp_path: Path) -> None:
    assert MAX_PACK_BYTES == 2 * 1024 * 1024  # the documented limit, pinned here so a change is a reviewed change
    refused(tmp_path, "pack: abc\n# " + "a" * (2 * 1024 * 1024 + 10) + "\n", ErrorCode.PACK_001)


def test_a_pack_exactly_at_the_size_limit_loads(tmp_path: Path) -> None:
    head = "pack: abc\n# "
    text = head + "a" * (2 * 1024 * 1024 - len(head) - 1) + "\n"
    assert len(text.encode()) == 2 * 1024 * 1024
    assert load_pack(write(tmp_path, text)).name == "abc"


def test_text_that_is_not_utf8_is_refused_even_inside_a_comment(tmp_path: Path) -> None:
    bad = tmp_path / "comment.yaml"
    bad.write_bytes(b"pack: abc\n# \xff\n")
    with pytest.raises(PackError) as caught:
        load_pack(bad)
    assert caught.value.code is ErrorCode.PACK_001
    assert "UTF-8" in str(caught.value)


def test_an_empty_file_or_an_empty_list_is_not_a_pack(tmp_path: Path) -> None:
    for text in ("", "[]\n"):
        with pytest.raises(PackError) as caught:
            load_pack(write(tmp_path, text))
        assert caught.value.code is ErrorCode.PACK_003 and "mapping" in str(caught.value)


def test_a_missing_file_a_directory_a_fifo_and_non_utf8_are_refused(tmp_path: Path) -> None:
    for target in (tmp_path / "missing.yaml", tmp_path):
        with pytest.raises(PackError) as caught:
            load_pack(target)
        assert caught.value.code is ErrorCode.PACK_001
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)  # reading a FIFO would block forever
    with pytest.raises(PackError):
        load_pack(fifo)
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"pack: abc\n\xff\xfe\n")
    with pytest.raises(PackError) as caught:
        load_pack(bad)
    assert caught.value.code is ErrorCode.PACK_001


def test_pack_errors_exit_one_and_never_echo_values() -> None:
    error = PackError(ErrorCode.PACK_003, "message")
    assert error.exit_code == 1 and str(error) == "PACK-003: message"
