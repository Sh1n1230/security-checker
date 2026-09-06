"""process transport — 任意のコマンドを Reviewer にする (設計書 §9.7).

特定の CLI を対象にした機能ではなく、次の契約を満たすもの**すべて**を Reviewer にできる
汎用機構である。対象が何であるかを、このコードは知らない。

    起動   : argv で指定されたコマンドを、非対話モードで実行する
    入力   : プロンプトを stdin (または一時ファイル) で渡す
    出力   : stdout にテキストを返す。そこから JSON を抽出する (§10.2)
    終了   : exit code 0 を成功とみなす

http との違いは正直に扱う (§9.7 の制約表):
  - Structured Output は `prompt_only` のみ。抽出 + 修復パスに依存する。
  - トークン / コストは計測できない。tokens は推定値、`cost_known` は False。
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Literal

from security_checker.context.budget import estimate_tokens
from security_checker.models.verdict import Usage
from security_checker.providers.base import (
    Capabilities,
    CompletionRequest,
    CompletionResponse,
    HealthStatus,
    StructuredMode,
)
from security_checker.providers.errors import (
    ProviderError,
    ProviderResponseError,
    ProviderServerError,
    ProviderTimeoutError,
)
from security_checker.providers.process.sandbox import (
    PromptVia,
    SandboxResult,
    run_sandboxed,
)
from security_checker.review.structured import extract_json

#: process transport の「方言」は 1 つだけ。テキストを渡してテキストを受け取る。
TEXT_IO_DIALECT = "text_io"
PARSE_MODES = ("json_in_stdout",)
STDERR_EXCERPT_LIMIT = 2000

Runner = Callable[..., Awaitable[SandboxResult]]


def process_capabilities(base: Capabilities) -> Capabilities:
    """process transport で構造的に決まってしまう capability を確定させる (§9.7).

    stdin/stdout の契約しかないため、スキーマ強制・system ロール・seed・temperature の
    いずれも「あることにできない」。利用者が上書きしても、実態は変わらないので揃える。
    """
    return base.model_copy(
        update={
            "structured_output": StructuredMode.PROMPT_ONLY,
            "supports_system_role": False,
            "supports_temperature": False,
            "supports_seed": False,
            "tool_calling": False,
            "vision": False,
        }
    )


class ProcessProvider:
    """非対話コマンドを 1 つの Provider として扱う."""

    transport: Literal["http", "process"] = "process"

    def __init__(
        self,
        *,
        name: str,
        command: Sequence[str],
        capabilities: Capabilities,
        model: str | None = None,
        prompt_via: PromptVia = "stdin",
        parse: str = "json_in_stdout",
        version: str | None = None,
        environ: Mapping[str, str] | None = None,
        runner: Runner | None = None,
    ) -> None:
        self.name = name
        self.dialect = TEXT_IO_DIALECT
        self.command = list(command)
        self.model = model or (self.command[0] if self.command else name)
        self.prompt_via = prompt_via
        self.parse = parse
        self.version = version
        self._capabilities = process_capabilities(capabilities)
        self._environ = environ
        self._runner: Runner = runner or run_sandboxed

    @property
    def capabilities(self) -> Capabilities:
        return self._capabilities

    async def complete(self, req: CompletionRequest) -> CompletionResponse:
        """1 起動 = 1 判定. リトライもレート制御もここには置かない (§22)."""
        prompt = self._render_prompt(req)
        started = time.monotonic()
        result = await self._run(prompt, timeout_s=req.timeout_s)
        return self._to_response(result, prompt, started)

    async def health_check(self) -> HealthStatus:
        """到達性の確認. 起動対象を実際には走らせず、存在とバージョンだけを見る."""
        from security_checker.providers.detect import command_version

        if not self.command:
            return HealthStatus(ok=False, detail="command が空です")
        found = command_version(self.command[0])
        if not found.available:
            return HealthStatus(ok=False, detail=found.reason)
        return HealthStatus(ok=True, detail=found.version)

    async def aclose(self) -> None:
        """プロセスは 1 回ごとに完結するため、保持する資源はない."""
        return None

    # --- 内部 -------------------------------------------------------------

    def _render_prompt(self, req: CompletionRequest) -> str:
        """system / user のロール分けを持たないため 1 本のテキストに畳む."""
        if not req.system:
            return req.user
        return f"{req.system}\n\n---\n\n{req.user}"

    async def _run(self, prompt: str, *, timeout_s: float) -> SandboxResult:
        try:
            result = await self._runner(
                self.command,
                prompt=prompt,
                prompt_via=self.prompt_via,
                timeout_s=timeout_s,
                environ=self._environ,
            )
        except FileNotFoundError as exc:
            raise ProviderError(
                f"{self.name}: コマンドが見つかりません: {self.command[0]}。"
                "PATH を確認するか、command に絶対パスを指定してください",
                provider=self.name,
            ) from exc
        except OSError as exc:
            raise ProviderError(
                f"{self.name}: コマンドを起動できません: {exc}", provider=self.name
            ) from exc

        if result.timed_out:
            raise ProviderTimeoutError(
                f"{self.name}: {timeout_s}s 以内に終了しませんでした (プロセスグループは回収済み)",
                provider=self.name,
            )
        if result.exit_code != 0:
            raise ProviderServerError(
                f"{self.name}: コマンドが exit {result.exit_code} で終了しました: "
                f"{_excerpt(result.stderr)}",
                provider=self.name,
            )
        return result

    def _to_response(
        self, result: SandboxResult, prompt: str, started: float
    ) -> CompletionResponse:
        if not result.stdout.strip():
            raise ProviderResponseError(
                f"{self.name}: stdout が空でした。非対話モードのフラグを確認してください: "
                f"{_excerpt(result.stderr)}",
                provider=self.name,
            )
        parsed = extract_json(result.stdout) if self.parse == "json_in_stdout" else None
        return CompletionResponse(
            text=result.stdout,
            parsed=parsed,
            usage=Usage(
                # 実測できないので推定値。参考表示であることを cost_known で示す (§9.7)。
                input_tokens=estimate_tokens(prompt),
                output_tokens=estimate_tokens(result.stdout),
                estimated_usd=None,
                cost_known=False,
            ),
            model_reported=None,
            latency_ms=int((time.monotonic() - started) * 1000),
            warnings=self._write_warnings(result),
            trace_params=self._trace_params(result),
            trace_response={
                "stderr": _excerpt(result.stderr),
                "exit_code": result.exit_code,
                "created_paths": list(result.created_paths),
            },
        )

    def _write_warnings(self, result: SandboxResult) -> list[str]:
        """書込検知 (§9.7 の 4). P3 が守られたことの実測を、黙って捨てない."""
        if not result.created_paths:
            return []
        return [
            f"{self.name}: Reviewer が隔離ディレクトリに書き込みを行いました "
            f"({', '.join(result.created_paths)})。"
            "レビュー対象リポジトリは変更されていませんが、"
            "書き込み能力を無効化するフラグを command に加えることを検討してください"
        ]

    def _trace_params(self, result: SandboxResult) -> dict[str, Any]:
        return {
            "argv": list(result.argv),
            "version": self.version,
            "prompt_via": self.prompt_via,
            "parse": self.parse,
            "cwd": "isolated-temp-dir",
        }


def _excerpt(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= STDERR_EXCERPT_LIMIT:
        return collapsed
    return collapsed[:STDERR_EXCERPT_LIMIT] + " …(truncated)"
