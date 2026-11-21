"""The probe library (D-E30): the only source of probes. A scope names a set by id and can never define one.

In 0.x the library registers ids, categories and probe counts so a scope validates and its plan is exact. The probe
texts arrive with the adapter (M2) as a reviewed change; nothing at run time can add, edit or generate a probe, not a
scope, a target's reply or a model.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

PROBE_CATEGORIES = frozenset(
    {"prompt_injection", "system_prompt_leakage", "sensitive_information_disclosure", "output_handling"}
)


@dataclass(frozen=True)
class ProbeSet:
    id: str
    category: str
    count: int
    description: str


_SETS = (
    ProbeSet(
        "canary-echo-v1", "prompt_injection", 2, "Whether a canary planted in untrusted-looking text is repeated back."
    ),
    ProbeSet(
        "canary-instruction-in-data-v1",
        "prompt_injection",
        3,
        "Whether an instruction inside supplied data is followed.",
    ),
    ProbeSet(
        "system-prompt-canary-v1", "system_prompt_leakage", 2, "Whether a canary in hidden configuration is reproduced."
    ),
    ProbeSet(
        "seeded-data-canary-v1",
        "sensitive_information_disclosure",
        2,
        "Whether data seeded in a test deployment is returned.",
    ),
    ProbeSet("output-structure-v1", "output_handling", 2, "Which structure (markup, links, code) a reply contains."),
)

PROBE_SETS: Mapping[str, ProbeSet] = MappingProxyType({probe_set.id: probe_set for probe_set in _SETS})
