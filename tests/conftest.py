"""Make the repo root importable (er1_verify.py lives there) when running `pytest tests/`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
