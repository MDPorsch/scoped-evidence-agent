"""Parsers that turn hostile response text into small, bounded facts. They never fetch, execute or follow anything.

Nothing free-form is copied out of a document except the few named values below, each capped and stripped of
control characters: an OpenAPI title or description, for instance, is never read, so a sentence a target wrote
cannot travel into a stored field.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from scopedagent.logs import safe_text

_LINES = re.compile(r"\r\n|\n|\r")  # not str.splitlines(): that also splits on U+2028 and friends
_HTML = re.compile(r"<[A-Za-z][^>\n]{0,300}>")
_MARKDOWN_LINK = re.compile(r"\[[^\]\n]{1,200}\]\([^)\n]{1,500}\)")
_URL = re.compile(r"https?://")
MAX_TOKENS = 1_000_000


class ParseFailure(Exception):
    """The text is not the document it claims to be. The message is safe to show."""


def _clean(value: object, limit: int) -> str:
    return safe_text(str(value).strip(), limit).strip()  # strip first, so leading space does not eat the limit


MAX_JSON_DEPTH = 64
MAX_PARSED_JSON = 8000  # the schema allows 8192 bytes of parsed facts; stay under it so valid input is never refused


def _bound(parsed: dict[str, Any]) -> dict[str, Any]:
    """Drop entries from the longest list, last first, until the facts fit the schema's size limit."""
    while len(json.dumps(parsed, ensure_ascii=True)) > MAX_PARSED_JSON:
        lists = [value for value in parsed.values() if isinstance(value, list) and value]
        if not lists:
            break
        max(lists, key=lambda value: len(json.dumps(value, ensure_ascii=True))).pop()
    return parsed


def _too_deep(value: Any) -> bool:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            return True
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
        stack.extend((child, depth + 1) for child in children)
    return False


def _load(text: str, what: str) -> Any:
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        raise ParseFailure(f"the {what} is not valid JSON, or it is nested too deeply") from None
    if _too_deep(doc):
        raise ParseFailure(f"the {what} is nested too deeply (more than {MAX_JSON_DEPTH} levels)")
    return doc


def security_txt_summary(text: str) -> dict[str, Any]:
    contacts: list[str] = []
    expires: str | None = None
    for line in _LINES.split(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip().lower()
        if key == "contact" and len(contacts) < 5:
            contacts.append(_clean(value, 255))
        elif key == "expires" and expires is None:
            expires = _clean(value, 64)
    return _bound({"contact": contacts, "expires": expires})


def robots_summary(text: str) -> dict[str, Any]:
    agents: list[str] = []
    disallow: list[str] = []
    for line in _LINES.split(text):
        directive = line.split("#", 1)[0].strip()
        key, _, value = directive.partition(":")
        key, value = key.strip().lower(), _clean(value, 255)
        if key == "user-agent" and len(agents) < 50:
            agents.append(value)
        elif key == "disallow" and value and len(disallow) < 50:
            disallow.append(value)
    return _bound({"user_agents": agents, "disallow": disallow})


def openapi_summary(text: str) -> dict[str, Any]:
    doc = _load(text, "OpenAPI document")
    if not isinstance(doc, dict):
        raise ParseFailure("an OpenAPI document must be a JSON object")
    version = doc.get("openapi", doc.get("swagger"))
    if not isinstance(version, str):
        raise ParseFailure("the document has no openapi or swagger version")
    paths = doc.get("paths")
    servers = doc.get("servers")
    urls = [
        _clean(s["url"], 512)
        for s in (servers if isinstance(servers, list) else [])
        if isinstance(s, dict) and isinstance(s.get("url"), str)
    ][:20]
    components = doc.get("components")
    schemes = (components.get("securitySchemes") if isinstance(components, dict) else None) or doc.get(
        "securityDefinitions"
    )
    names = sorted(_clean(n, 64) for n in schemes if isinstance(n, str)) if isinstance(schemes, dict) else []
    return _bound(
        {
            "openapi": _clean(version, 32),
            "path_count": len(paths) if isinstance(paths, dict) else 0,
            "server_urls": urls,
            "security_schemes": names[:20],
        }
    )


def models_summary(text: str) -> tuple[list[str], dict[str, Any]]:
    doc = _load(text, "model list")
    if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
        raise ParseFailure("a model list is a JSON object with a data list")
    named = [e["id"] for e in doc["data"] if isinstance(e, dict) and isinstance(e.get("id"), str)]
    parsed: dict[str, Any] = {"model_count": len(named)}
    if isinstance(doc.get("object"), str):
        parsed["object"] = _clean(doc["object"], 32)
    return [_clean(i, 128) for i in named[:50]], parsed


@dataclass(frozen=True)
class ChatReply:
    content: str
    finish_reason: str | None
    input_tokens: int | None
    output_tokens: int | None


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_TOKENS else None


def chat_completion(text: str, api_style: str) -> ChatReply:
    if api_style != "openai_compatible":
        raise ParseFailure(f"api_style {api_style} is not supported by the offline adapter yet")
    doc = _load(text, "reply")
    choices = doc.get("choices") if isinstance(doc, dict) else None
    first = choices[0] if isinstance(choices, list) and choices else None
    message = first.get("message") if isinstance(first, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        raise ParseFailure("the reply is not an OpenAI-compatible chat completion")
    finish = first.get("finish_reason") if isinstance(first, dict) else None
    usage = doc.get("usage") if isinstance(doc.get("usage"), dict) else {}
    return ChatReply(
        content,
        _clean(finish, 64) if isinstance(finish, str) else None,
        _count(usage.get("prompt_tokens")),
        _count(usage.get("completion_tokens")),
    )


def ai_flags(text: str) -> dict[str, bool]:
    """Structure present in a reply: simple pattern matches, never a judgement (LIMITATIONS SE-17)."""
    return {
        "contains_html": _HTML.search(text) is not None,
        "contains_markdown_link": _MARKDOWN_LINK.search(text) is not None,
        "contains_code_block": "```" in text,
        "contains_url": _URL.search(text) is not None,
    }
