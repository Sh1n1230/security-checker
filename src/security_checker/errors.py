"""エラー分類 (設計書 §20.1).

exit code との対応:
  ConfigError -> 2 / ToolFailed(--strict) -> 3 / ポリシー違反 -> 1
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """CLI の終了コード (設計書 §17.1)."""

    OK = 0
    POLICY_VIOLATION = 1
    CONFIG_ERROR = 2
    EXECUTION_ERROR = 3


class SecurityCheckerError(Exception):
    """本ツールが送出する例外の基底."""

    exit_code: ExitCode = ExitCode.EXECUTION_ERROR


class ConfigError(SecurityCheckerError):
    """設定ファイル / 環境変数の不備. 実行前に必ず停止する."""

    exit_code = ExitCode.CONFIG_ERROR


class InternalError(SecurityCheckerError):
    """想定外の内部エラー."""

    exit_code = ExitCode.EXECUTION_ERROR
