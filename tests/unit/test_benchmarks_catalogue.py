"""D-E83 to D-E87: the OWASP benchmark catalogue: what is shipped, how it is checked and how it is read."""

from __future__ import annotations

import copy
import datetime as dt
import re
from typing import Any

import pytest
import yaml

from scopedagent.benchmarks import catalogue as cat_module
from scopedagent.benchmarks.catalogue import (
    CATALOGUE_FILE,
    STALE_AFTER_DAYS,
    CatalogueError,
    age_days,
    catalogue,
    coverage,
    is_stale,
    parse_catalogue,
    references_for,
    unknown_rules,
    unmapped,
)
from scopedagent.pipeline.rules import RULES

pytestmark = pytest.mark.milestone("M7")

# What was read from the sources on 2026-11-22. Changing an edition is a reviewed edit of the data AND of this table.
EDITIONS = {
    "owasp-top10": ("OWASP Top 10", "2025", [f"A{i:02d}" for i in range(1, 11)]),
    "owasp-api-top10": ("OWASP API Security Top 10", "2023", [f"API{i}" for i in range(1, 11)]),
    "owasp-llm-top10": ("OWASP Top 10 for LLM Applications", "2026", [f"LLM{i:02d}" for i in range(1, 11)]),
}
CHECKED = {"owasp-top10": "2026-11-22", "owasp-api-top10": "2026-11-22", "owasp-llm-top10": "2026-11-22"}
# The reviewed mapping of every rule, rule by rule. A new rule has no row here until someone decides where it belongs.
MAPPING = {
    "R-TLS-01": [("owasp-top10", "A04")],
    "R-HDR-01": [("owasp-top10", "A02")],
    "R-INFO-01": [("owasp-top10", "A02")],
    "R-INFO-02": [("owasp-top10", "A02")],
    "R-REDIR-01": [("owasp-top10", "A04")],
    "R-API-01": [("owasp-api-top10", "API9"), ("owasp-top10", "A02")],
    "R-CORS-01": [("owasp-top10", "A02"), ("owasp-api-top10", "API8")],
    "R-DNS-01": [("owasp-top10", "A02")],
    "R-AI-01": [("owasp-llm-top10", "LLM01")],
    "R-AI-02": [("owasp-llm-top10", "LLM08")],
    "R-AI-03": [("owasp-llm-top10", "LLM02")],
    "R-AI-04": [("owasp-llm-top10", "LLM10")],
}


def shipped_data() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(CATALOGUE_FILE.read_text(encoding="utf-8"))
    return loaded


def refused(data: Any) -> str:
    with pytest.raises(CatalogueError) as caught:
        parse_catalogue(yaml.safe_dump(data, sort_keys=False))
    return str(caught.value)


# -------------------------------------------------------------------------------------- the shipped data ----
def test_the_shipped_catalogue_is_valid_and_holds_the_three_editions_read_on_2026_11_22() -> None:
    cat = catalogue()
    assert [b.key for b in cat.benchmarks] == list(EDITIONS)
    for benchmark in cat.benchmarks:
        title, edition, ids = EDITIONS[benchmark.key]
        assert (benchmark.title, benchmark.edition) == (title, edition)
        assert [c.id for c in benchmark.categories] == ids
        assert benchmark.checked_on == CHECKED[benchmark.key] and benchmark.source.startswith("https://")


def test_key_category_names_are_the_ones_the_sources_use() -> None:
    names = {(b.key, c.id): c.name for b in catalogue().benchmarks for c in b.categories}
    assert names[("owasp-top10", "A01")] == "Broken Access Control"
    assert names[("owasp-top10", "A02")] == "Security Misconfiguration"
    assert names[("owasp-top10", "A05")] == "Injection"
    assert names[("owasp-top10", "A10")] == "Mishandling of Exceptional Conditions"
    assert names[("owasp-api-top10", "API1")] == "Broken Object Level Authorization"
    assert names[("owasp-api-top10", "API8")] == "Security Misconfiguration"
    assert names[("owasp-llm-top10", "LLM01")] == "Prompt Injection"
    assert names[("owasp-llm-top10", "LLM08")] == "Hidden Context Exposure"  # System Prompt Leakage in the 2025 edition
    assert names[("owasp-llm-top10", "LLM10")] == "Improper Output Handling"


def test_every_rule_is_mapped_and_nothing_is_mapped_that_is_not_a_rule() -> None:
    ids = [rule.id for rule in RULES]
    assert unmapped(ids) == [] and unknown_rules(ids) == []
    assert set(MAPPING) == set(ids)  # this table too


@pytest.mark.parametrize("rule_id", sorted(MAPPING))
def test_each_rule_is_mapped_to_exactly_the_reviewed_categories(rule_id: str) -> None:
    found = [(r.benchmark, r.category) for r in references_for(rule_id)]
    assert found == MAPPING[rule_id]
    assert all(r.note for r in references_for(rule_id))


def test_a_reference_names_its_edition_and_reads_as_a_label() -> None:
    (first, *_rest) = references_for("R-AI-02")
    assert first.label == "OWASP Top 10 for LLM Applications 2026: LLM08 Hidden Context Exposure"
    assert "2025" in first.note and "System Prompt Leakage" in first.note
    assert first.as_dict() == {
        "benchmark": "owasp-llm-top10",
        "title": "OWASP Top 10 for LLM Applications",
        "edition": "2026",
        "category": "LLM08",
        "name": "Hidden Context Exposure",
        "note": first.note,
    }
    assert references_for("R-NOPE-01") == ()


def test_the_catalogue_is_read_once() -> None:
    assert catalogue() is catalogue()


# ---------------------------------------------------------------------------------------------- coverage ----
def test_coverage_lists_each_category_with_the_rules_that_answer_it_and_the_gaps() -> None:
    rows = coverage()
    covered = {key: {c.id: rules for c, rules in table if rules} for key, table in rows.items()}
    assert covered["owasp-top10"] == {
        "A02": ("R-HDR-01", "R-INFO-01", "R-INFO-02", "R-API-01", "R-CORS-01", "R-DNS-01"),
        "A04": ("R-TLS-01", "R-REDIR-01"),
    }
    assert covered["owasp-api-top10"] == {"API8": ("R-CORS-01",), "API9": ("R-API-01",)}
    assert covered["owasp-llm-top10"] == {
        "LLM01": ("R-AI-01",),
        "LLM02": ("R-AI-03",),
        "LLM08": ("R-AI-02",),
        "LLM10": ("R-AI-04",),
    }
    assert all(len(table) == 10 for table in rows.values())
    assert ("A05", ()) in [(c.id, rules) for c, rules in rows["owasp-top10"]]  # Injection: no rule yet, said plainly


def test_unmapped_and_unknown_rules_are_reported_sorted() -> None:
    cat = catalogue()
    assert unmapped(["R-TLS-01", "R-ZZ-9", "R-AA-1"], cat) == ["R-AA-1", "R-ZZ-9"]
    assert unknown_rules(["R-TLS-01"], cat) == sorted(set(cat.rules) - {"R-TLS-01"})


def test_two_editions_that_reuse_a_category_id_are_told_apart() -> None:
    """When a new edition keeps ids (A01 in 2021 and in 2025), a rule mapped to one must not appear under the other."""
    data = shipped_data()
    old = copy.deepcopy(data["benchmarks"][0])
    old.update(key="owasp-top10-2021", edition="2021")
    data["benchmarks"].append(old)
    cat = parse_catalogue(yaml.safe_dump(data, sort_keys=False))
    rows = {key: {c.id: rules for c, rules in table} for key, table in coverage(cat).items()}
    assert rows["owasp-top10"]["A04"] == ("R-TLS-01", "R-REDIR-01")
    assert rows["owasp-top10-2021"]["A04"] == ()  # same id, other edition: nothing maps there


# ----------------------------------------------------------------------------------------------- staleness ----
def test_a_benchmark_is_stale_only_after_the_limit() -> None:
    benchmark = catalogue().benchmark("owasp-top10")
    checked = benchmark.checked_date
    assert checked == dt.date(2026, 11, 22) and STALE_AFTER_DAYS == 180
    assert age_days(benchmark, checked) == 0
    on_limit = checked + dt.timedelta(days=STALE_AFTER_DAYS)
    assert age_days(benchmark, on_limit) == 180 and not is_stale(benchmark, on_limit)
    assert is_stale(benchmark, on_limit + dt.timedelta(days=1))


# --------------------------------------------------------------------------------------------- validation ----
def test_the_shipped_data_survives_a_round_trip_through_the_parser() -> None:
    assert parse_catalogue(yaml.safe_dump(shipped_data(), sort_keys=False)) == catalogue()


def test_text_that_is_not_yaml_or_uses_a_forbidden_construct_is_refused() -> None:
    with pytest.raises(CatalogueError, match="not valid YAML"):
        parse_catalogue("a: [unclosed")
    with pytest.raises(CatalogueError, match="not valid YAML"):
        parse_catalogue("a: &x 1\nb: *x\n")
    with pytest.raises(CatalogueError, match="not valid at"):
        parse_catalogue("- just\n- a list\n")


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda d: d.update(schema_version=2), "schema_version"),
        (lambda d: d.update(extra=1), "extra"),
        (lambda d: d["benchmarks"].append(copy.deepcopy(d["benchmarks"][0])), "a benchmark key is listed twice"),
        (lambda d: d["benchmarks"][0]["categories"].append(dict(d["benchmarks"][0]["categories"][0])), "listed twice"),
        (lambda d: d["benchmarks"][0].update(source="http://owasp.org/Top10/2025/"), "https://"),
        (lambda d: d["benchmarks"][0].update(source="owasp.org"), "https://"),
        (lambda d: d["benchmarks"][0].update(checked_on="22 Nov 2026"), "checked_on must be a date"),
        (lambda d: d["benchmarks"][0].update(checked_on="2026-13-45"), "checked_on must be a date"),
        (lambda d: d["benchmarks"][0].update(key="Not A Key"), "key"),
        (lambda d: d["benchmarks"][0].update(categories=[]), "categories"),
        (lambda d: d["rules"]["R-TLS-01"][0].update(benchmark="no-such"), "unknown benchmark no-such"),
        (lambda d: d["rules"]["R-TLS-01"][0].update(category="A99"), "has no category A99"),
        (lambda d: d["rules"]["R-TLS-01"].append(dict(d["rules"]["R-TLS-01"][0])), "mapped twice"),
        (lambda d: d["rules"].update({"R-NEW-01": []}), "rules.R-NEW-01"),
        (lambda d: d["rules"].update({"tls": [dict(d["rules"]["R-TLS-01"][0])]}), "rules"),
        (lambda d: d["rules"]["R-TLS-01"][0].update(note=""), "note"),
        (lambda d: d["rules"]["R-TLS-01"][0].update(note="x" * 201), "note"),
    ],
)
def test_a_catalogue_with_a_mistake_is_refused_and_the_message_says_where(edit: Any, message: str) -> None:
    data = shipped_data()
    edit(data)
    assert message in refused(data)


def test_the_file_is_read_from_next_to_the_module() -> None:
    assert CATALOGUE_FILE.name == "catalogue.yaml" and CATALOGUE_FILE.parent.name == "benchmarks"
    assert re.fullmatch(r"[a-z0-9-]+", cat_module.catalogue().benchmarks[0].key)
