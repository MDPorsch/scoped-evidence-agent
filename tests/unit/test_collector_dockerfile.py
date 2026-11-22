"""The collector image is built from a few copied files; the package build fails if one it names is missing.

The first real CI build of the image failed because `NOTICE` (a `license-files` entry) was not copied. This test needs no
container runtime: it checks that every file the build reads is in the Dockerfile's first COPY line.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

pytestmark = pytest.mark.milestone("M6")

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "docker" / "collector" / "Dockerfile"


def copied_files() -> set[str]:
    for line in DOCKERFILE.read_text().splitlines():
        parts = line.split()
        if parts[:1] == ["COPY"] and "pyproject.toml" in parts:
            return set(parts[1:-1])  # the last word is the destination
    raise AssertionError("the Dockerfile copies no pyproject.toml")


def test_every_file_the_package_build_reads_is_copied_into_the_image() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    needed = {"pyproject.toml", project["readme"], *project["license-files"]}
    assert needed <= copied_files(), f"not copied into the image: {sorted(needed - copied_files())}"
    assert all((ROOT / name).is_file() for name in needed)


def test_the_source_is_copied_too() -> None:
    assert "COPY src ./src" in DOCKERFILE.read_text()
