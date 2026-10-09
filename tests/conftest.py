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


@pytest.fixture(autouse=True)
def _utf8_stdio_for_child_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    """テストで起動する Python の子プロセス (偽の Reviewer など) の標準入出力を UTF-8 にする.

    process transport の契約は「プロンプトを UTF-8 で受け取り、UTF-8 で返す」(docs/process-transport.md)。
    Windows ではパイプ越しの標準入出力が既定でロケールの文字コード (cp1252 など) になり、
    偽の Reviewer が日本語を出力できずに落ちるため、テスト側で契約どおりにそろえる。
    起動時に読まれる変数なので、このプロセス自身の入出力には影響しない。
    """
    monkeypatch.setenv("PYTHONIOENCODING", "utf-8")
