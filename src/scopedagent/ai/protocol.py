"""What a model adapter is: a function from rule sentences to reworded sentences. It has no other power (D-E60)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from scopedagent.logs import safe_text

Status = Literal["unavailable", "refused", "invalid"]
MAX_DETAIL = 200


@dataclass(frozen=True)
class RewordItem:
    id: str
    text: str
    limit: int


@dataclass(frozen=True)
class RewordRequest:
    items: tuple[RewordItem, ...]
    prompt_version: str


@dataclass(frozen=True)
class RewordReply:
    texts: dict[str, str]
    input_tokens: int
    output_tokens: int


class ModelUnavailable(Exception):
    """The model could not be used. `detail` is a short safe line (a class name or fixed phrase), never model text."""

    def __init__(self, status: Status, detail: str) -> None:
        self.status: Status = status
        self.detail = safe_text(detail, MAX_DETAIL).strip()
        super().__init__(f"{status}: {self.detail}")


class ModelAdapter(Protocol):
    provider: str
    model: str

    def reword(self, request: RewordRequest) -> RewordReply: ...
