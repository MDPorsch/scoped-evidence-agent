"""The sentences of a draft a model may reword, and the longest each may be (the limits of the draft's own fields)."""

from __future__ import annotations

FIELDS: dict[str, int] = {
    "condition": 300,
    "precondition": 300,
    "unknown": 300,
    "attacker_position": 200,
    "basis": 300,
    "remediation": 500,
    "severity_basis": 200,
}
SINGLE = frozenset({"attacker_position", "basis", "remediation", "severity_basis"})  # one sentence per draft


def label(field: str, index: int) -> str:
    """How a person reads which sentence a wording belongs to: `condition 2`, `remediation`."""
    name = field.replace("_", " ")
    return name if field in SINGLE else f"{name} {index + 1}"
