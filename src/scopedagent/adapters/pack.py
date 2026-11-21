"""Fixture packs (docs/fixture-format.md): the only data source in 0.x.

A pack is untrusted input, loaded as strictly as a scope. Only the shape of the pack and the form of every key
are checked here. An entry is validated when an adapter uses it, so one malformed answer becomes a recorded
parse error for that operation instead of stopping the run.
"""

from __future__ import annotations

import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scopedagent.errors import ErrorCode, PackError, ScopeError
from scopedagent.logs import safe_text
from scopedagent.policy.scope import canonical_host, canonical_path
from scopedagent.strictyaml import StrictYamlError, strict_load

MAX_PACK_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 200
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{2,39}")
_TLS_KEY = re.compile(r"([^:]+):([0-9]{1,5})")
_URL_KEY = re.compile(r"(https?)://([^/:]+):([0-9]{1,5})(/.*)")
_PROBE_KEY = re.compile(r"probe:([a-z0-9][a-z0-9-]{1,39}):([a-z0-9][a-z0-9-]{1,62}):([0-9])")
_API_KEY = re.compile(r"([a-z0-9][a-z0-9-]{1,39})\|(GET|HEAD|OPTIONS)\|([^|]+)(?:\|([^|]+))?")
_SECTIONS = ("dns", "tls", "http", "ai", "api")


@dataclass(frozen=True)
class Pack:
    name: str
    dns: dict[str, dict[str, Any]]
    tls: dict[str, dict[str, Any]]
    http: dict[str, dict[str, Any]]
    ai: dict[str, dict[str, Any]]
    api: dict[str, dict[str, Any]]


def _bad(message: str) -> PackError:
    return PackError(ErrorCode.PACK_003, message)


def _host(value: str, where: str) -> str:
    try:
        if canonical_host(value) != value:
            raise _bad(f"{where}: the host must be in canonical form")
    except ScopeError:
        raise _bad(f"{where}: not a valid host name") from None
    return value


def _port(digits: str, where: str) -> None:
    if not 1 <= int(digits) <= 65535:
        raise _bad(f"{where}: the port must be from 1 to 65535")


def _check_url_key(key: str, where: str) -> None:
    match = _URL_KEY.fullmatch(key)
    if match is None:
        raise _bad(f"{where}: a key is scheme://host:port/path with an explicit port and no query")
    _host(match.group(2), where)
    _port(match.group(3), where)
    try:
        canonical_path(match.group(4))
    except ScopeError:
        raise _bad(f"{where}: the path is not an exact canonical path") from None


def _check_api_key(key: str, where: str) -> None:
    match = _API_KEY.fullmatch(key)
    if match is None:
        raise _bad(f"{where}: an api key is principal|METHOD|scheme://host:port/path, and for OPTIONS |origin as well")
    _principal, method, url, origin = match.groups()
    _check_url_key(url, where)
    if (method == "OPTIONS") != (origin is not None):
        raise _bad(f"{where}: an OPTIONS key ends with |origin, and no other method has one")
    if origin is not None and re.fullmatch(r"https://[a-z0-9.-]+(?::[0-9]{1,5})?", origin) is None:
        raise _bad(f"{where}: the origin is https://host or https://host:port")


def _check_key(section: str, key: str) -> None:
    where = f"{section} key {safe_text(key, 60)!r}"
    if section == "dns":
        _host(key, where)
    elif section == "tls":
        match = _TLS_KEY.fullmatch(key)
        if match is None:
            raise _bad(f"{where}: a key is host:port")
        _host(match.group(1), where)
        _port(match.group(2), where)
    elif section == "api":
        _check_api_key(key, where)
    elif section == "ai" and key.startswith("probe:"):
        if _PROBE_KEY.fullmatch(key) is None:
            raise _bad(f"{where}: a probe key is probe:<ai target id>:<probe set>:<index 0-9>")
    else:
        _check_url_key(key, where)


def _section(data: dict[str, Any], section: str) -> dict[str, dict[str, Any]]:
    raw = data.get(section) or {}
    if not isinstance(raw, dict):
        raise _bad(f"{section} must be a mapping")
    if len(raw) > MAX_ENTRIES:
        raise _bad(f"{section} has more than {MAX_ENTRIES} entries")
    for key, entry in raw.items():
        _check_key(section, key)
        if not isinstance(entry, dict):
            raise _bad(f"{section} entry {safe_text(key, 60)!r} must be a mapping")
    return dict(raw)


def load_pack(path: Path) -> Pack:
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise PackError(ErrorCode.PACK_001, "the fixture path is not a regular file")
        with path.open("rb") as handle:
            raw = handle.read(MAX_PACK_BYTES + 1)
    except OSError:
        raise PackError(ErrorCode.PACK_001, "the fixture pack could not be read") from None
    if len(raw) > MAX_PACK_BYTES:
        raise PackError(
            ErrorCode.PACK_001, f"the fixture pack is too large (limit {MAX_PACK_BYTES // (1024 * 1024)} MiB)"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise PackError(ErrorCode.PACK_001, "the fixture pack is not valid UTF-8 text") from None
    try:
        data = strict_load(text)
    except StrictYamlError as exc:
        code = ErrorCode.PACK_002 if exc.kind == "forbidden" else ErrorCode.PACK_001
        raise PackError(code, exc.message) from None
    if not isinstance(data, dict):
        raise _bad("a pack must be a YAML mapping")
    unknown = set(data) - {"pack", *_SECTIONS}
    if unknown:
        raise _bad(f"unknown key {safe_text(sorted(unknown)[0], 40)!r}")
    name = data.get("pack")
    if not isinstance(name, str) or _NAME.fullmatch(name) is None:
        raise _bad("pack must be 3 to 40 characters of a-z, 0-9 and -, starting with a letter or digit")
    return Pack(name, *(_section(data, s) for s in _SECTIONS))
