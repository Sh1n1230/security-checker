"""設定スキーマ (設計書 §12).

全項目に既定値があり、設定ファイルなしでも動く。
`api_key:` という平文キーのフィールドは **意図的に存在しない** (§19.1)。
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from security_checker.models.enums import FindingStatus, Severity


class StrictModel(BaseModel):
    """未知キーを拒否する基底. 設定ミスを黙って無視しない."""

    model_config = ConfigDict(extra="forbid")


DEFAULT_EXCLUDES = (
    "**/vendor/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/.git/**",
    "**/.security-checker/**",
    "**/*.min.js",
)


class TargetConfig(StrictModel):
    root: str = "."
    mode: Literal["auto", "full", "diff"] = "auto"
    exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))


class ScannerConfig(StrictModel):
    enabled: bool = True
    timeout_s: int = Field(default=600, gt=0)
    extra_args: list[str] = Field(default_factory=list)


class SemgrepConfig(ScannerConfig):
    config: str = "p/default"


class GitleaksConfig(ScannerConfig):
    timeout_s: int = Field(default=300, gt=0)


class OsvConfig(ScannerConfig):
    timeout_s: int = Field(default=300, gt=0)


class TrivyConfig(ScannerConfig):
    scanners: list[str] = Field(default_factory=lambda: ["config"])


class ScannersConfig(StrictModel):
    semgrep: SemgrepConfig = SemgrepConfig()
    gitleaks: GitleaksConfig = GitleaksConfig()
    osv: OsvConfig = OsvConfig(enabled=False)
    trivy: TrivyConfig = TrivyConfig(enabled=False)


class ContextConfig(StrictModel):
    window_lines: int = Field(default=40, gt=0)
    max_callers: int = Field(default=3, ge=0)
    max_tokens_per_task: int = Field(default=8000, gt=0)
    include_repo_facts: bool = True


class RateLimit(StrictModel):
    rpm: int | None = Field(default=None, gt=0)
    tpm: int | None = Field(default=None, gt=0)


class ReviewerCapabilities(StrictModel):
    """capability の明示指定 (最優先・設計書 §9.3).

    エンドポイントを叩いても分からないため、利用者が上書きできる経路を必ず残す。
    """

    structured_output: Literal["json_schema", "json_mode", "prompt_only"] | None = None
    max_context_tokens: int | None = Field(default=None, gt=0)
    max_output_tokens: int | None = Field(default=None, gt=0)
    supports_system_role: bool | None = None
    supports_temperature: bool | None = None
    supports_seed: bool | None = None
    reasoning: bool | None = None


class ReviewerConfig(StrictModel):
    """Reviewer 定義 (P2 以降で使用).

    `transport` は必須。省略時に何かを推測して補完しない (§12)。
    """

    name: str
    transport: Literal["http", "process"]
    weight: float = Field(default=1.0, ge=0.0)
    timeout_s: int = Field(default=120, gt=0)
    concurrency: int = Field(default=1, gt=0)
    rate_limit: RateLimit = RateLimit()

    # http transport ("text_io" だけは process transport の方言)
    dialect: (
        Literal[
            "openai_chat",
            "anthropic_messages",
            "gemini_generate",
            "ollama_chat",
            "text_io",
        ]
        | None
    ) = None
    base_url: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    max_output_tokens: int = Field(default=2000, gt=0)
    num_ctx: int | None = Field(default=None, gt=0)
    headers: dict[str, str] = Field(default_factory=dict)
    capabilities: ReviewerCapabilities = ReviewerCapabilities()
    seed: int | None = None

    # process transport
    preset: str | None = None
    command: list[str] | None = None
    #: プロンプトの渡し方. どちらでも argv には本文を埋め込まない (設計書 §9.7)
    prompt_via: Literal["stdin", "file"] = "stdin"
    #: stdout の解釈方法. 現状は「最初の JSON オブジェクトを抽出する」のみ
    parse: Literal["json_in_stdout"] = "json_in_stdout"

    @model_validator(mode="after")
    def _validate_transport(self) -> ReviewerConfig:
        if self.transport == "http":
            if self.dialect == "text_io":
                raise ValueError(
                    f"reviewer '{self.name}': dialect: text_io は transport: process 専用です"
                )
            # preset を指定した場合、dialect / base_url はプリセットデータ側が供給しうる
            required = ("model",) if self.preset else ("dialect", "base_url", "model")
            missing = [field for field in required if getattr(self, field) is None]
            if missing:
                raise ValueError(
                    f"reviewer '{self.name}': transport: http には {', '.join(missing)} が必要です"
                    + ("" if self.preset else " (または preset)")
                )
        else:
            if self.preset is None and not self.command:
                raise ValueError(
                    f"reviewer '{self.name}': transport: process には preset か command が必要です"
                )
            if self.dialect not in (None, "text_io"):
                raise ValueError(
                    f"reviewer '{self.name}': transport: process の dialect は text_io のみです"
                )
        return self


class ConsensusConfig(StrictModel):
    min_votes: int = Field(default=2, ge=1)
    min_ratio: float = Field(default=0.5, ge=0.0, le=1.0)
    severity: Literal["median", "max", "weighted_mean"] = "median"


class WeightedConfig(StrictModel):
    threshold: float = Field(default=0.6, ge=0.0, le=1.0)


class JudgeConfig(StrictModel):
    reviewer: str | None = None
    fallback: Literal["consensus", "weighted"] = "consensus"


class AggregationConfig(StrictModel):
    strategy: str = "consensus"
    consensus: ConsensusConfig = ConsensusConfig()
    weighted: WeightedConfig = WeightedConfig()
    judge: JudgeConfig = JudgeConfig()


class PolicyConfig(StrictModel):
    fail_on: Severity = Severity.HIGH
    fail_on_status: list[FindingStatus] = Field(
        default_factory=lambda: [FindingStatus.CONFIRMED, FindingStatus.LIKELY]
    )
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    strict: bool = True
    baseline: str | None = None
    min_score: int | None = Field(default=None, ge=0, le=100)


class BudgetConfig(StrictModel):
    max_candidates: int = Field(default=200, gt=0)
    max_usd: float | None = Field(default=1.0, ge=0.0)
    max_total_tokens: int | None = Field(default=2_000_000, gt=0)
    on_exceed: Literal["stop_and_report", "warn_and_continue"] = "stop_and_report"


class ConcurrencyConfig(StrictModel):
    scanners: int = Field(default=4, gt=0)
    reviews_per_provider: int = Field(default=4, gt=0)


OutputFormat = Literal["terminal", "json", "markdown", "sarif"]


def _default_formats() -> list[OutputFormat]:
    # markdown も既定に含める。report.json は機械可読用で人間が読む物ではないため、
    # 既定のままだと「人間が読める保存済みレポート」が 1 つも残らない (§18.1)。
    return ["terminal", "json", "markdown"]


class OutputConfig(StrictModel):
    dir: str = ".security-checker/"
    formats: list[OutputFormat] = Field(default_factory=_default_formats)
    save_prompts: bool = False
    #: レポート本文 (LLM が書く自然言語) の言語. "auto" はロケールから推定する。
    #: 出力形式ごとに訳し直す場所はないため、ここが全形式に効く (設計書 §18)。
    language: str = "auto"


class GithubConfig(StrictModel):
    comment: bool = True
    comment_mode: Literal["sticky", "new"] = "sticky"
    inline_comments: bool = True
    inline_min_status: FindingStatus = FindingStatus.LIKELY
    max_inline_comments: int = Field(default=20, ge=0)


class LoggingConfig(StrictModel):
    level: Literal["debug", "info", "warn", "error"] = "info"
    format: Literal["text", "json"] = "text"


class Config(StrictModel):
    """解決済みの全設定."""

    version: Annotated[int, Field(ge=1)] = 1
    target: TargetConfig = TargetConfig()
    scanners: ScannersConfig = ScannersConfig()
    context: ContextConfig = ContextConfig()
    reviewers: list[ReviewerConfig] = Field(default_factory=list)
    aggregation: AggregationConfig = AggregationConfig()
    policy: PolicyConfig = PolicyConfig()
    budget: BudgetConfig = BudgetConfig()
    concurrency: ConcurrencyConfig = ConcurrencyConfig()
    output: OutputConfig = OutputConfig()
    github: GithubConfig = GithubConfig()
    logging: LoggingConfig = LoggingConfig()

    @model_validator(mode="after")
    def _validate_reviewers(self) -> Config:
        names = [reviewer.name for reviewer in self.reviewers]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"reviewer 名が重複しています: {', '.join(duplicates)}")
        if self.aggregation.strategy == "judge":
            judge_name = self.aggregation.judge.reviewer
            if judge_name is None:
                raise ValueError("aggregation.strategy: judge には judge.reviewer が必要です")
            if judge_name not in names:
                raise ValueError(
                    f"aggregation.judge.reviewer '{judge_name}' が reviewers に存在しません"
                )
        return self

    def scanner_settings(self) -> dict[str, ScannerConfig]:
        return {
            "semgrep": self.scanners.semgrep,
            "gitleaks": self.scanners.gitleaks,
            "osv": self.scanners.osv,
            "trivy": self.scanners.trivy,
        }

    def masked_dump(self) -> dict[str, Any]:
        """`config show` 用. 秘匿値は設計上そもそも保持しないが、名前解決の結果だけを見せる."""
        return self.model_dump(mode="json")
