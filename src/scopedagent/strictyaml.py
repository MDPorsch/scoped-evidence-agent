"""A YAML loader that refuses what a restriction file must not contain (threat model B1).

No aliases or anchors (an alias can expand into a denial of service), no merge keys, no duplicate keys, no keys that are
not plain strings, no deep nesting, no Python object tags, exactly one document.
"""

from __future__ import annotations

from typing import Any, Literal

import yaml

MAX_DEPTH = 16


class StrictYamlError(Exception):
    """`kind` is "syntax" for text that is not valid YAML and "forbidden" for a valid construct this tool refuses."""

    def __init__(self, kind: Literal["syntax", "forbidden"], message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


class _Loader(yaml.SafeLoader):
    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            raise StrictYamlError(
                "forbidden", "YAML aliases are not allowed (an alias can expand into a denial of service)"
            )
        if getattr(self.peek_event(), "anchor", None) is not None:  # type: ignore[no-untyped-call]
            raise StrictYamlError("forbidden", "YAML anchors (and the aliases that use them) are not allowed")
        self._depth += 1
        if self._depth > MAX_DEPTH:
            raise StrictYamlError("forbidden", f"the document is nested too deeply (more than {MAX_DEPTH} levels)")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        seen: set[str] = set()
        for key_node, _value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise StrictYamlError("forbidden", "YAML merge keys ('<<') are not allowed")
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str):
                raise StrictYamlError("forbidden", "every key must be a plain string")
            if key in seen:
                raise StrictYamlError("forbidden", f"duplicate key (line {key_node.start_mark.line + 1})")
            seen.add(key)
        return super().construct_mapping(node, deep)


def strict_load(text: str) -> Any:
    loader: _Loader | None = None
    try:
        loader = _Loader(text)  # the constructor already rejects control characters, so it belongs inside the try
        return loader.get_single_data()
    except StrictYamlError:
        raise
    except RecursionError:  # pragma: no cover - the depth cap stops nesting long before the interpreter's limit
        raise StrictYamlError("forbidden", "the document is nested too deeply") from None
    except yaml.YAMLError:
        raise StrictYamlError(
            "syntax", "the text is not valid YAML, or it uses a construct that is not allowed"
        ) from None
    finally:
        if loader is not None:
            loader.dispose()
