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


def pytest_addoption(parser: pytest.Parser) -> None:
    # 実 LLM の応答をカセットに記録する (鍵が必要・手動実行のみ。設計書 §25.3)
    parser.addoption(
        "--record",
        action="store_true",
        default=False,
        help="実 LLM を呼んで tests/cassettes/ に記録し直す",
    )


@pytest.fixture
def record_mode(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--record"))
