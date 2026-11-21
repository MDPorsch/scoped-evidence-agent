"""M4: the model is one optional, narrow door. These tests pin where it is, and that nothing else can reach it."""

from __future__ import annotations

import ast
import re
import tomllib

import pytest

from scopedagent.ai.protocol import ModelAdapter
from tests.support import ROOT

pytestmark = pytest.mark.milestone("M4")
SRC = ROOT / "src" / "scopedagent"
ANTHROPIC_MODULE = SRC / "ai" / "anthropic_model.py"


def sources() -> list[tuple[str, ast.Module]]:
    return [(str(p.relative_to(SRC)), ast.parse(p.read_text(encoding="utf-8"))) for p in sorted(SRC.rglob("*.py"))]


def test_the_sdk_is_imported_in_exactly_one_file_and_only_inside_a_function() -> None:
    found: list[tuple[str, bool]] = []
    for name, tree in sources():
        for node in ast.walk(tree):
            imported = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            if any(m == "anthropic" or m.startswith("anthropic.") for m in imported):
                found.append((name, node in tree.body))
    assert found == [("ai/anthropic_model.py", False)]  # not at module level: importing the tool never loads the SDK


def test_only_the_factory_and_the_tests_reach_the_anthropic_module() -> None:
    importers = {
        name
        for name, tree in sources()
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("anthropic_model")
    }
    assert importers == {"ai/factory.py"}


def test_only_two_commands_build_an_adapter() -> None:
    cli = (SRC / "cli.py").read_text(encoding="utf-8")
    assert (
        len(re.findall(r"\bbuild_adapter\(", cli)) == 2
    )  # `ai test` and `findings reword`; `run` and the rest never do
    others = [name for name, _ in sources() if name not in ("cli.py", "ai/factory.py")]
    for name in others:
        assert "build_adapter(" not in (SRC / name).read_text(encoding="utf-8"), name


def test_the_base_url_is_a_constant_and_no_environment_variable_names_it() -> None:
    tree = ast.parse(ANTHROPIC_MODULE.read_text(encoding="utf-8"))
    del tree.body[0]  # the module docstring, which explains the rule in words
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert [s for s in strings if s.startswith("https://")] == ["https://api.anthropic.com"]
    assert not [
        s for s in strings if "BASE_URL" in s or s.endswith("_KEY") or s.endswith("_TOKEN")
    ]  # no variable is read by name
    code = ast.unparse(tree)
    assert "os.environ" not in code and "getenv" not in code  # the key is looked up in one place, by the caller


def test_the_sdk_is_an_optional_extra_never_a_required_dependency() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert not any(d.lower().startswith("anthropic") for d in project["dependencies"])
    assert list(project["optional-dependencies"]["ai"]) == ["anthropic>=1,<2"]


def test_a_model_adapter_can_only_reword() -> None:
    assert set(ModelAdapter.__protocol_attrs__) == {"provider", "model", "reword"}  # type: ignore[attr-defined]


def test_the_model_modules_never_open_files_run_a_process_or_import_the_store_writers() -> None:
    banned = {"subprocess", "os", "shutil", "pathlib", "sqlite3", "sqlalchemy", "scopedagent.storage"}
    for name in ("protocol", "prompt", "validation", "offline", "anthropic_model", "fields"):
        tree = ast.parse((SRC / "ai" / f"{name}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            modules = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            assert not [m for m in modules if m in banned or any(m.startswith(b + ".") for b in banned)], (
                name,
                modules,
            )


def test_nothing_the_model_returns_is_used_as_a_command_or_a_path() -> None:
    reword = (SRC / "ai" / "reword.py").read_text(encoding="utf-8")
    assert not re.search(r"\b(eval|exec|compile|open|__import__)\(", reword)
