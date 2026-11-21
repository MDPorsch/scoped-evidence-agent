"""Parsers that turn hostile response text into small, bounded facts. They never fetch, execute or follow anything.

Nothing free-form is copied out of a document except the few named values below, each capped and stripped of
control characters: an OpenAPI title or description, for instance, is never read, so a sentence a target wrote
cannot travel into a stored field.
"""

from __future__ import annotations

import hashlib
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


# --------------------------------------------------------------------------------------------- API evidence ----
_OPERATION_VERBS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")
MAX_OPERATIONS = 10_000


def api_spec_summary(text: str) -> dict[str, Any]:
    """An OpenAPI document as inventory (D-E49): the version, how many operations it lists, the server URLs as data, the
    names of its security schemes and how many operations declare no security. Nothing in it is ever contacted."""
    summary = openapi_summary(text)
    doc = json.loads(text)  # parsed once already by openapi_summary, so it is valid, shallow JSON here
    paths = doc.get("paths") if isinstance(doc.get("paths"), dict) else {}
    top = doc.get("security")
    operations = unsecured = 0
    for item in list(paths.values())[:MAX_OPERATIONS]:
        if not isinstance(item, dict):
            continue
        for verb in _OPERATION_VERBS:
            operation = item.get(verb)
            if not isinstance(operation, dict) or operations >= MAX_OPERATIONS:
                continue
            operations += 1
            effective = operation.get("security", top)
            unsecured += 1 if effective is None or effective == [] else 0
    return _bound({**summary, "operation_count": operations, "operations_without_security": unsecured})


MAX_SHAPE_ENTRIES = 200
MAX_SHAPE_NODES = 50_000
MAX_SHAPE_DEPTH = 12
MANY_KEYS = 16  # an object with more keys than this is a map: its keys are data, so they are not recorded
_KEY = re.compile(r"[A-Za-z0-9_.-]{1,40}")
_CREDENTIAL_KEYS = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"})
_STACK_KEYS = frozenset({"stacktrace", "stack_trace", "traceback", "trace"})
_STACK_TEXT = re.compile(
    r"Traceback \(most recent call last\)"
    r"|\bat [A-Za-z_$][\w$.<>]*\([A-Za-z0-9_$.]+:\d+\)"
    r"|\bFile \"[^\"\n]{1,200}\", line \d+"
    r"|\.java:\d+\)"
    r"|goroutine \d+ \["
)
_DEBUG_TEXT = re.compile(r"[\"']?\bdebug[\"']?\s*[:=]\s*(?:true|1)\b|\bDEBUG\s*=\s*True\b", re.IGNORECASE)


@dataclass(frozen=True)
class Shape:
    """What a JSON body is made of, never what it says: field paths with a type and a length (D-E52)."""

    status: str  # ok, partial, not_json or none
    entries: tuple[tuple[str, str, int | None], ...]
    digest: str | None
    credential_keys: bool
    stack_keys: bool
    debug_keys: bool


def _json_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return "number"
    return "string" if isinstance(value, str) else "array" if isinstance(value, list) else "object"


def json_shape(text: str | None) -> Shape:
    """The shape of a JSON body: `$.items[].id` is a string of length 12, and so on. A key that is not a short plain name
    is recorded as `?`, and the keys of a map (more than 16) as `{key}`, so a body cannot smuggle a sentence or an id
    into a stored field."""
    if text is None:
        return Shape("none", (), None, False, False, False)
    try:
        doc = _load(text, "body")
    except ParseFailure:
        return Shape("not_json", (), None, False, False, False)
    seen: dict[tuple[str, str], int | None] = {}
    flags = {"credential": False, "stack": False, "debug": False}
    partial = False
    nodes = 0
    stack: list[tuple[Any, str, int]] = [(doc, "$", 1)]
    while stack:
        node, path, depth = stack.pop()
        nodes += 1
        if nodes > MAX_SHAPE_NODES:
            partial = True
            break
        kind = _json_type(node)
        length = len(node) if isinstance(node, (str, list)) else None
        key = (path, kind)
        previous = seen.get(key)
        seen[key] = length if previous is None else max(previous, length or 0)
        if depth >= MAX_SHAPE_DEPTH:
            partial = partial or isinstance(node, (dict, list)) and bool(node)
            continue
        if isinstance(node, dict):
            collapse = len(node) > MANY_KEYS
            for name, child in node.items():
                lowered = name.lower()
                flags["credential"] |= lowered in _CREDENTIAL_KEYS
                flags["stack"] |= lowered in _STACK_KEYS
                flags["debug"] |= lowered == "debug"
                label = "{key}" if collapse else (name if _KEY.fullmatch(name) else "?")
                stack.append((child, f"{path}.{label}", depth + 1))
        elif isinstance(node, list):
            stack.extend((child, f"{path}[]", depth + 1) for child in node[:50])
    ordered = sorted(seen.items())
    if len(ordered) > MAX_SHAPE_ENTRIES:
        ordered, partial = ordered[:MAX_SHAPE_ENTRIES], True
    entries = tuple((path, kind, length) for (path, kind), length in ordered)
    structure = json.dumps([[path, kind] for path, kind, _ in entries], separators=(",", ":"))
    digest = hashlib.sha256(structure.encode("utf-8")).hexdigest()
    return Shape("partial" if partial else "ok", entries, digest, flags["credential"], flags["stack"], flags["debug"])


def api_markers(text: str | None, shape: Shape) -> dict[str, bool]:
    """Structure a reviewer wants to look at, as three yes/no flags. Simple pattern matches, never a judgement."""
    body = text or ""
    return {
        "has_stack_trace_markers": shape.stack_keys or _STACK_TEXT.search(body) is not None,
        "has_debug_markers": shape.debug_keys or _DEBUG_TEXT.search(body) is not None,
        "echoes_request_headers": shape.credential_keys,
    }


_ALLOW_TOKEN = re.compile(r"[A-Z]{3,10}")


def allow_methods(values: list[str]) -> list[str]:
    """The methods an `Allow` header names (upper-case tokens only, at most 12, in order, once each)."""
    seen: list[str] = []
    for value in values:
        for token in value.split(","):
            token = token.strip()
            if _ALLOW_TOKEN.fullmatch(token) and token not in seen and len(seen) < 12:
                seen.append(token)
    return seen
