"""The benchmark catalogue: the OWASP editions this tool maps its checks to, and which check answers which category.

The data is a plain file, `catalogue.yaml`, so that updating a benchmark is a reviewed edit of data and not of code
(`docs/benchmarks.md`). A label is derived from a rule's id when it is shown. Nothing here is stored in a finding,
so a later edition relabels nothing that was recorded; a report says which editions it used.

A mapping is the closest category, never a verdict: a draft is not a finding, and a category is not a diagnosis.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from scopedagent.strictyaml import StrictYamlError, strict_load

CATALOGUE_FILE = Path(__file__).with_name("catalogue.yaml")
STALE_AFTER_DAYS = 180  # a benchmark not checked against its source for this long is reported as possibly out of date

_KEY = r"[a-z0-9][a-z0-9-]{1,31}"
_CATEGORY_ID = r"[A-Za-z0-9][A-Za-z0-9._-]{0,15}"
_RULE_ID = r"R-[A-Z0-9-]{2,20}"


class CatalogueError(ValueError):
    """The catalogue file is not valid. The message says where, never more."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Category(_Strict):
    id: Annotated[str, Field(pattern=f"^{_CATEGORY_ID}$")]
    name: Annotated[str, Field(min_length=3, max_length=80)]


class Benchmark(_Strict):
    key: Annotated[str, Field(pattern=f"^{_KEY}$")]
    title: Annotated[str, Field(min_length=3, max_length=80)]
    edition: Annotated[str, Field(min_length=1, max_length=16)]
    source: Annotated[str, Field(max_length=300)]
    checked_on: str
    categories: Annotated[list[Category], Field(min_length=1, max_length=30)]

    @field_validator("source")
    @classmethod
    def _https(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("a source must be an https:// address")
        return value

    @field_validator("checked_on")
    @classmethod
    def _date(cls, value: str) -> str:
        try:
            dt.date.fromisoformat(value)
        except ValueError:
            raise ValueError("checked_on must be a date like 2026-11-22") from None
        return value

    @model_validator(mode="after")
    def _unique_categories(self) -> Benchmark:
        ids = [c.id for c in self.categories]
        if len(set(ids)) != len(ids):
            raise ValueError(f"{self.key}: a category id is listed twice")
        return self

    @property
    def checked_date(self) -> dt.date:
        return dt.date.fromisoformat(self.checked_on)


class Mapping(_Strict):
    benchmark: Annotated[str, Field(pattern=f"^{_KEY}$")]
    category: Annotated[str, Field(pattern=f"^{_CATEGORY_ID}$")]
    note: Annotated[str, Field(min_length=3, max_length=200)]


class Catalogue(_Strict):
    schema_version: Literal[1]
    benchmarks: Annotated[list[Benchmark], Field(min_length=1, max_length=10)]
    rules: dict[
        Annotated[str, Field(pattern=f"^{_RULE_ID}$")], Annotated[list[Mapping], Field(min_length=1, max_length=6)]
    ]

    @model_validator(mode="after")
    def _consistent(self) -> Catalogue:
        keys = [b.key for b in self.benchmarks]
        if len(set(keys)) != len(keys):
            raise ValueError("a benchmark key is listed twice")
        known = {b.key: {c.id for c in b.categories} for b in self.benchmarks}
        for rule_id, mappings in self.rules.items():
            for mapping in mappings:
                if mapping.benchmark not in known:
                    raise ValueError(f"{rule_id}: unknown benchmark {mapping.benchmark}")
                if mapping.category not in known[mapping.benchmark]:
                    raise ValueError(f"{rule_id}: {mapping.benchmark} has no category {mapping.category}")
            pairs = [(m.benchmark, m.category) for m in mappings]
            if len(set(pairs)) != len(pairs):
                raise ValueError(f"{rule_id}: a category is mapped twice")
        return self

    def benchmark(self, key: str) -> Benchmark:
        return next(b for b in self.benchmarks if b.key == key)


@dataclass(frozen=True)
class Reference:
    """One category a rule answers, with the edition it was read from."""

    benchmark: str
    title: str
    edition: str
    category: str
    name: str
    note: str

    @property
    def label(self) -> str:
        return f"{self.title} {self.edition}: {self.category} {self.name}"

    def as_dict(self) -> dict[str, str]:
        """How a report lists it."""
        return {
            "benchmark": self.benchmark,
            "title": self.title,
            "edition": self.edition,
            "category": self.category,
            "name": self.name,
            "note": self.note,
        }


def parse_catalogue(text: str) -> Catalogue:
    try:
        data = strict_load(text)
    except StrictYamlError as exc:
        raise CatalogueError(f"the catalogue is not valid YAML: {exc.message}") from None
    try:
        return Catalogue.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first["loc"]) or "the file"
        raise CatalogueError(f"the catalogue is not valid at {where}: {first['msg']}") from None


@lru_cache(maxsize=1)
def catalogue() -> Catalogue:
    """The catalogue shipped with this version. Read once."""
    return parse_catalogue(CATALOGUE_FILE.read_text(encoding="utf-8"))


def references_for(rule_id: str, source: Catalogue | None = None) -> tuple[Reference, ...]:
    """The categories a rule answers, in catalogue order. Empty for a rule the catalogue does not know."""
    cat = source if source is not None else catalogue()
    found: list[Reference] = []
    for mapping in cat.rules.get(rule_id, []):
        benchmark = cat.benchmark(mapping.benchmark)
        name = next(c.name for c in benchmark.categories if c.id == mapping.category)
        found.append(
            Reference(mapping.benchmark, benchmark.title, benchmark.edition, mapping.category, name, mapping.note)
        )
    return tuple(found)


def unmapped(rule_ids: Iterable[str], source: Catalogue | None = None) -> list[str]:
    """Rules that have no entry in the catalogue (a rule was added without a mapping)."""
    cat = source if source is not None else catalogue()
    return sorted(set(rule_ids) - set(cat.rules))


def unknown_rules(rule_ids: Iterable[str], source: Catalogue | None = None) -> list[str]:
    """Entries in the catalogue for a rule that does not exist (a rule was removed or renamed)."""
    cat = source if source is not None else catalogue()
    return sorted(set(cat.rules) - set(rule_ids))


def coverage(source: Catalogue | None = None) -> dict[str, list[tuple[Category, tuple[str, ...]]]]:
    """For each benchmark, each category with the rules that answer it (an empty tuple means no rule does)."""
    cat = source if source is not None else catalogue()
    result: dict[str, list[tuple[Category, tuple[str, ...]]]] = {}
    for benchmark in cat.benchmarks:
        rows: list[tuple[Category, tuple[str, ...]]] = []
        for category in benchmark.categories:
            rules = tuple(
                rule_id
                for rule_id, mappings in cat.rules.items()
                if any(m.benchmark == benchmark.key and m.category == category.id for m in mappings)
            )
            rows.append((category, rules))
        result[benchmark.key] = rows
    return result


def age_days(benchmark: Benchmark, today: dt.date) -> int:
    return (today - benchmark.checked_date).days


def is_stale(benchmark: Benchmark, today: dt.date) -> bool:
    return age_days(benchmark, today) > STALE_AFTER_DAYS
