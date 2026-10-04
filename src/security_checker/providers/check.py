"""`providers list` / `providers check` (設計書 §29.3).

**新しい LLM を足したときに最初に叩くコマンド。** 設定を読んで、

  1. 設定が解決できるか (dialect・API キーの環境変数・プリセット)
  2. 到達できるか (health check)
  3. 構造化出力が往復するか (無害な合成コードを 1 件だけレビューさせ、スキーマに通す)

を順に確かめ、失敗した段で具体的な修正案を出す。3 は実際に 1 回呼び出すので、課金が発生しうる。
送るのは合成した数行のコードだけで、リポジトリのコードは送らない。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from security_checker.config.schema import ReviewerConfig
from security_checker.errors import SecurityCheckerError
from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, Severity
from security_checker.models.task import CodeContext, CodeSlice, RepoFacts, ReviewTask, TokenBudget
from security_checker.models.verdict import VerdictStatus
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderBadRequestError,
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
)
from security_checker.providers.http.dialects import DIALECTS
from security_checker.providers.presets.loader import load_http_presets, load_process_presets
from security_checker.providers.registry import build_provider, discover_plugin_providers
from security_checker.review.reviewer import Reviewer

#: 疎通確認に使う合成コード. 実在のリポジトリのコードは送らない
PROBE_CODE = "import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"


@dataclass
class Step:
    label: str
    ok: bool
    detail: str = ""


@dataclass
class CheckResult:
    name: str
    transport: str
    steps: list[Step] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.steps) and all(step.ok for step in self.steps)


def probe_task() -> ReviewTask:
    candidate = Candidate(
        id="providers-check",
        scanner="security-checker",
        category=Category.SAST,
        rule_id="providers-check.probe",
        title="subprocess with shell=True",
        message="疎通確認用の合成コードです",
        location=Location(path="probe.py", start_line=4, end_line=4),
        severity_reported=Severity.HIGH,
        cwe=["CWE-78"],
    )
    return ReviewTask(
        candidate=candidate,
        code_context=CodeContext(
            primary=CodeSlice(path="probe.py", start_line=1, end_line=4, text=PROBE_CODE)
        ),
        repo_facts=RepoFacts(languages=["python"]),
        budget=TokenBudget(max_tokens_per_task=2000),
    )


def _suggest(exc: Exception, reviewer: ReviewerConfig) -> str:
    if isinstance(exc, ProviderAuthError):
        return (
            f"認証に失敗しました。{reviewer.api_key_env or 'API キーの環境変数'} の値と、"
            "そのキーがこのモデルを使えるかを確認してください"
        )
    if isinstance(exc, ProviderRateLimitError):
        return "レート制限に当たりました。rate_limit.rpm を下げるか、時間をおいて再実行してください"
    if isinstance(exc, ProviderTimeoutError):
        return f"タイムアウトしました。timeout_s (現在 {reviewer.timeout_s}) を延ばしてください"
    if isinstance(exc, ProviderBadRequestError):
        return (
            "リクエストが拒否されました。model 名と dialect を確認し、構造化出力に対応していない"
            "エンドポイントなら capabilities.structured_output: prompt_only を指定してください"
        )
    if reviewer.transport == "process":
        return "command が非対話で JSON を標準出力に返すか、手元で直接実行して確認してください"
    return f"base_url ({reviewer.base_url}) に到達できるか確認してください"


async def check_reviewer(
    reviewer: ReviewerConfig, *, environ: dict[str, str] | None = None, probe: bool = True
) -> CheckResult:
    result = CheckResult(name=reviewer.name, transport=reviewer.transport)
    warnings: list[str] = []
    try:
        provider = build_provider(reviewer, environ=environ, warnings=warnings)
    except SecurityCheckerError as exc:
        result.steps.append(Step("設定", False, str(exc)))
        result.suggestions.append(
            "設定を直して再実行してください (config show --explain で確認できます)"
        )
        return result
    caps = provider.capabilities
    result.steps.append(
        Step(
            "設定",
            True,
            f"dialect={provider.dialect} model={getattr(provider, 'model', '-')} "
            f"structured={caps.structured_output.value}",
        )
    )
    result.suggestions.extend(warnings)

    try:
        health = await provider.health_check()
        result.steps.append(
            Step(
                "疎通",
                health.ok,
                health.detail or (f"{health.latency_ms} ms" if health.latency_ms else ""),
            )
        )
        if not health.ok:
            result.suggestions.append(_suggest(ProviderError(health.detail or ""), reviewer))
            return result
        if not probe:
            return result

        outcome = await Reviewer(
            reviewer.name,
            provider,
            max_output_tokens=reviewer.max_output_tokens,
            timeout_s=float(reviewer.timeout_s),
        ).review(probe_task())
        verdict = outcome.verdict
        if verdict.status is VerdictStatus.OK:
            result.steps.append(
                Step(
                    "構造化出力",
                    True,
                    f"vulnerable={verdict.vulnerable} confidence={verdict.confidence:.2f} "
                    f"(attempt {verdict.attempt}, {verdict.latency_ms} ms)",
                )
            )
            result.suggestions.extend(outcome.warnings)
            if not verdict.vulnerable:
                result.suggestions.append(
                    "合成コード (shell=True に引数を直接渡す) を「脆弱ではない」と判定しました。"
                    "動作はしていますが、このモデルの判定の質は eval で確かめてください"
                )
        else:
            result.steps.append(Step("構造化出力", False, verdict.reasoning))
            result.suggestions.append(
                "スキーマに沿った JSON が返りませんでした。"
                "capabilities.structured_output を json_mode か prompt_only に下げて試してください"
            )
    except ProviderError as exc:
        result.steps.append(Step("呼び出し", False, str(exc)))
        result.suggestions.append(_suggest(exc, reviewer))
    finally:
        await provider.aclose()
    return result


@dataclass
class ProviderCatalog:
    dialects: list[str]
    http_presets: dict[str, str]
    process_presets: dict[str, str]
    plugins: list[str]
    warnings: list[str]


def catalog() -> ProviderCatalog:
    """使える Provider の一覧. 推奨順は付けない (中立性 §9.8)."""
    plugins, warnings = discover_plugin_providers()
    http: Mapping[str, object] = load_http_presets()
    process: Mapping[str, object] = load_process_presets()
    return ProviderCatalog(
        dialects=sorted(DIALECTS),
        http_presets={name: getattr(p, "source", "bundled") for name, p in sorted(http.items())},
        process_presets={
            name: getattr(p, "source", "bundled") for name, p in sorted(process.items())
        },
        plugins=sorted(plugins),
        warnings=warnings,
    )
