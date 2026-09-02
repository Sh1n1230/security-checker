"""Provider 例外の正規化 (設計書 §9.2).

下位の HTTP / プロセスのエラーをこの階層に写像し、上位 (scheduler) はこれだけを見る。
どれをリトライしてよいかを型で表す。
"""

from __future__ import annotations

from security_checker.errors import ExitCode, SecurityCheckerError


class ProviderError(SecurityCheckerError):
    """Provider 呼び出しの失敗."""

    exit_code = ExitCode.EXECUTION_ERROR
    retryable: bool = False

    def __init__(self, message: str, *, provider: str | None = None) -> None:
        super().__init__(message)
        self.provider = provider


class ProviderAuthError(ProviderError):
    """401 / 403. リトライしない. サーキットブレーカが即座に開く."""


class ProviderRateLimitError(ProviderError):
    """429. retry_after を持つ."""

    retryable = True

    def __init__(
        self,
        message: str,
        *,
        provider: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, provider=provider)
        self.retry_after = retry_after


class ProviderTimeoutError(ProviderError):
    """応答が時間内に返らなかった."""

    retryable = True


class ProviderServerError(ProviderError):
    """5xx / 接続エラー."""

    retryable = True


class ProviderBadRequestError(ProviderError):
    """400. スキーマ非対応などが含まれるため、降格して再試行する余地がある (§10.2)."""


class ProviderResponseError(ProviderError):
    """応答をパースできない. 修復リトライの対象."""
