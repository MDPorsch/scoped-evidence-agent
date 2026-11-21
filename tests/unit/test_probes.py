"""D-E30: probe sets come only from a reviewed library; a scope can name one and can never define one."""

from __future__ import annotations

import re

import pytest

from scopedagent.policy.probes import PROBE_CATEGORIES, PROBE_SETS, ProbeSet

pytestmark = pytest.mark.milestone("M1")

# Written from docs/ai-targets.md, independently of the implementation.
EXPECTED = {
    "canary-echo-v1": ("prompt_injection", 2),
    "canary-instruction-in-data-v1": ("prompt_injection", 3),
    "system-prompt-canary-v1": ("system_prompt_leakage", 2),
    "seeded-data-canary-v1": ("sensitive_information_disclosure", 2),
    "output-structure-v1": ("output_handling", 2),
}


def test_the_library_is_exactly_the_documented_one() -> None:
    assert {k: (v.category, v.count) for k, v in PROBE_SETS.items()} == EXPECTED


def test_the_categories_are_the_four_documented_ones() -> None:
    assert {
        "prompt_injection",
        "system_prompt_leakage",
        "sensitive_information_disclosure",
        "output_handling",
    } == PROBE_CATEGORIES


def test_every_set_is_well_formed_and_versioned() -> None:
    for key, probe_set in PROBE_SETS.items():
        assert probe_set.id == key and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}-v[0-9]+", key)
        assert probe_set.category in PROBE_CATEGORIES and 1 <= probe_set.count <= 10 and probe_set.description.strip()


def test_the_library_cannot_be_changed_at_run_time() -> None:
    with pytest.raises(TypeError):
        PROBE_SETS["evil-v1"] = ProbeSet("evil-v1", "prompt_injection", 1, "x")  # type: ignore[index]
    with pytest.raises(TypeError):
        del PROBE_SETS["canary-echo-v1"]  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        PROBE_SETS["canary-echo-v1"].count = 99  # type: ignore[misc]


def test_a_set_that_is_not_in_the_library_is_not_a_set() -> None:
    assert "canary-echo-v2" not in PROBE_SETS and "evil-v1" not in PROBE_SETS and "" not in PROBE_SETS
