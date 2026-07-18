import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

ALL_PY_FILES = sorted(REPO_ROOT.rglob("*.py"))

DIRECT_IMPORT_MODULES = [
    "common.constants",
    "payload.build",
    "payload.gsp_patch",
    "unlock.compute",
    "unlock.memory",
]


@pytest.mark.parametrize("py_file", ALL_PY_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_py_compile(py_file):
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(py_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("module_name", DIRECT_IMPORT_MODULES)
def test_direct_import(module_name):
    __import__(module_name)
