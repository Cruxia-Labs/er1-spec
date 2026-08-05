"""Make the differential fuzzer gate CI.

tests/differential_fuzz.py is the only PROPERTY-level cross-language check we have — it feeds
random documents to both canonical-JSON implementations and asserts they emit identical bytes or
both refuse. It existed, it passed, and nothing ran it: not pytest (the filename does not match
the default `test_*.py` pattern) and not the workflow. That is the second time a guard in this
repo turned out to be unattached, and the class is the point — a check nobody executes is a
comment.

Skipped when Node is unavailable.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).parent


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_python_and_js_canonicalize_identically():
    proc = subprocess.run(
        [sys.executable, str(HERE / "differential_fuzz.py"), "--cases", "800", "--seed", "7"],
        capture_output=True, text=True, cwd=HERE.parent,
    )
    assert proc.returncode == 0, f"differential fuzz failed:\n{proc.stdout}\n{proc.stderr}"
    assert "DIVERGENCES     : 0" in proc.stdout, proc.stdout
