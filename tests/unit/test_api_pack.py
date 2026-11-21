"""M5, docs/fixture-format.md: the `api` section of a pack. A key says who asked and what, exactly."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from scopedagent.adapters.pack import MAX_ENTRIES, load_pack
from scopedagent.errors import ErrorCode, PackError
from tests.support import API_PACK, FIXTURES

pytestmark = pytest.mark.milestone("M5")

URL = "https://api.example.invalid:443/v1/projects"
ORIGIN = "https://x.example.invalid"


def write(tmp_path: Path, api: Any) -> Path:
    path = tmp_path / "pack.yaml"
    path.write_text(yaml.safe_dump({"pack": "unit-test", "api": api}, sort_keys=False), encoding="utf-8")
    return path


def refused(tmp_path: Path, api: Any) -> PackError:
    with pytest.raises(PackError) as caught:
        load_pack(write(tmp_path, api))
    assert caught.value.code is ErrorCode.PACK_003, f"{caught.value.code}: {caught.value}"
    return caught.value


def test_the_committed_api_pack_loads_with_eleven_answers() -> None:
    pack = load_pack(FIXTURES / "web_responses" / f"{API_PACK}.yaml")
    assert pack.name == API_PACK and len(pack.api) == 11 and pack.dns == pack.tls == pack.http == pack.ai == {}


def test_a_pack_without_an_api_section_has_an_empty_one() -> None:
    assert load_pack(FIXTURES / "web_responses" / "healthy.yaml").api == {}


@pytest.mark.parametrize(
    "key",
    [
        f"anonymous|GET|{URL}",
        f"tenant-a-user|GET|{URL}",
        "u1|HEAD|http://api.example.invalid:8080/health",
        f"anonymous|OPTIONS|{URL}|{ORIGIN}",
        f"anonymous|OPTIONS|{URL}|{ORIGIN}:8443",
        "anonymous|GET|https://api.example.invalid:443/",
    ],
)
def test_a_well_formed_key_is_accepted(tmp_path: Path, key: str) -> None:
    assert list(load_pack(write(tmp_path, {key: {"status": 200}})).api) == [key]


@pytest.mark.parametrize(
    "key",
    [
        "",
        URL,
        f"GET|{URL}",
        f"|GET|{URL}",
        f"Anonymous|GET|{URL}",
        f"a|GET|{URL}",
        f"anon ymous|GET|{URL}",
        f"anonymous|get|{URL}",
        f"anonymous|POST|{URL}",
        f"anonymous|DELETE|{URL}",
        f"anonymous|GET |{URL}",
        f"anonymous|GET|{URL}|{ORIGIN}|extra",
        f"anonymous|GET|{URL}|{ORIGIN}",
        f"anonymous|HEAD|{URL}|{ORIGIN}",
        f"anonymous|OPTIONS|{URL}",
        f"anonymous|OPTIONS|{URL}|http://x.example.invalid",
        f"anonymous|OPTIONS|{URL}|{ORIGIN}/",
        f"anonymous|OPTIONS|{URL}|{ORIGIN}/path",
        f"anonymous|OPTIONS|{URL}|*",
        f"anonymous|OPTIONS|{URL}|null",
        "anonymous|GET|https://api.example.invalid/v1/projects",
        "anonymous|GET|https://api.example.invalid:0/v1",
        "anonymous|GET|https://api.example.invalid:99999/v1",
        "anonymous|GET|https://API.example.invalid:443/v1",
        "anonymous|GET|https://api.example.invalid:443/v1?x=1",
        "anonymous|GET|https://api.example.invalid:443/v1/../x",
        "anonymous|GET|https://api.example.invalid:443/v1//x",
        "anonymous|GET|https://api.example.invalid:443/{id}",
        "anonymous|GET|ftp://api.example.invalid:443/v1",
    ],
)
def test_a_malformed_key_is_refused_with_the_pack_code(tmp_path: Path, key: str) -> None:
    refused(tmp_path, {key: {"status": 200}})


@pytest.mark.parametrize(
    "bad",
    ["text", 5, [1], {"anonymous|GET|" + URL: "text"}, {"anonymous|GET|" + URL: [1]}, {"anonymous|GET|" + URL: None}],
)
def test_the_section_must_be_a_mapping_of_mappings(tmp_path: Path, bad: Any) -> None:
    refused(tmp_path, bad)


def test_an_empty_section_is_no_answers(tmp_path: Path) -> None:
    for empty in ([], {}, None):
        assert load_pack(write(tmp_path, empty)).api == {}


def test_at_most_the_entry_limit_of_answers(tmp_path: Path) -> None:
    many = {f"anonymous|GET|https://api.example.invalid:443/p{i}": {"status": 200} for i in range(MAX_ENTRIES)}
    assert len(load_pack(write(tmp_path, many)).api) == MAX_ENTRIES
    many[f"anonymous|GET|https://api.example.invalid:443/p{MAX_ENTRIES}"] = {"status": 200}
    refused(tmp_path, many)


def test_the_error_names_the_key_but_cuts_it_short(tmp_path: Path) -> None:
    error = refused(tmp_path, {"x" * 500: {"status": 200}})
    assert len(str(error)) < 400
