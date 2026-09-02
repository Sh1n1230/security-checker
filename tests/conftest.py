from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def raw_fixture():
    def _load(name: str) -> Any:
        return json.loads((FIXTURE_DIR / "raw" / name).read_text(encoding="utf-8"))

    return _load


@pytest.fixture
def fixture_dir() -> Path:
    return FIXTURE_DIR
