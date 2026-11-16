"""まだ実装していない設定項目を、黙って無視しない (設計書 P9).

スキーマが受け付ける項目のうち、実装が追いついていないものがある。
黙って無視すると「設定したのに効かない」ことに気づけない — これは v1 で
「スキャナが失敗しても満点に見えた」のと同じ種類の事故である。

ここで検出して警告に積み、レポートとターミナルの両方に残す。
実装が入ったらエントリを消す。**エントリを消し忘れても害はないが、
実装と食い違ったままにしない**ために、対応するテストを一緒に置いてある。
"""

from __future__ import annotations

from security_checker.config.schema import MAJORITY_RATIO, Config, ContextConfig, ReviewerConfig


def unimplemented_warnings(config: Config) -> list[str]:
    """受け付けたが効かない設定の一覧を返す. 呼び出し側は必ず警告として残すこと.

    見ているのは、未実装の項目 (target.root・context.max_callers)、過半数に満たない
    min_ratio、transport や方言と合わない項目 (process に base_url、ollama_chat 以外に
    num_ctx など)、出力先や形式を変えてしまう extra_args。
    """
    warnings: list[str] = []

    # 検査対象は CLI の引数 (PATH) で決まる。target.root はどこからも読まれない。
    if config.target.root != ".":
        warnings.append(
            f"target.root ({config.target.root}) は使われません。"
            "検査対象は `security-checker scan PATH` / `review PATH` の引数で指定してください"
        )

    # 呼び出し元の収集は未実装で、CodeContext.callers は常に空。0 なら実際の挙動と一致する
    default_callers = ContextConfig.model_fields["max_callers"].default
    if config.context.max_callers not in (0, default_callers):
        warnings.append(
            f"context.max_callers ({config.context.max_callers}) は未実装のため効きません。"
            "LLM に渡す文脈に呼び出し元のコードは含まれません"
        )

    # 過半数に満たない票では likely にしない (§14.1)。0.5 未満を書いても 0.5 と同じ扱いになる
    if config.aggregation.consensus.min_ratio < MAJORITY_RATIO:
        warnings.append(
            f"aggregation.consensus.min_ratio ({config.aggregation.consensus.min_ratio}) は "
            "効きません。票が過半数に満たない候補は常に review_required になります"
        )

    warnings.extend(_output_flag_warnings(config))

    for reviewer in config.reviewers:
        warnings.extend(_transport_mismatch(reviewer))
        warnings.extend(_literal_sensitive_header_warnings(reviewer))

    for reviewer in config.reviewers:
        # num_ctx / keep_alive は ollama_chat 方言にしかない概念。
        # 別の方言に書いても効かないので、そのことを伝える。
        if reviewer.dialect == "ollama_chat":
            continue
        warnings.extend(
            f"reviewer '{reviewer.name}': {field} は ollama_chat 方言専用です。"
            f"dialect: {reviewer.dialect or '(未指定)'} では無視されます"
            for field in ("num_ctx", "keep_alive")
            if getattr(reviewer, field) is not None
        )

    return warnings


#: extra_args に書くと、security-checker が読む出力の先や形式を変えてしまうフラグ
_OUTPUT_FLAGS: dict[str, tuple[str, ...]] = {
    "semgrep": ("--output", "-o", "--sarif", "--text", "--gitlab-sast", "--junit-xml", "--emacs"),
    "gitleaks": ("--report-path", "-r", "--report-format", "-f"),
    "osv": ("--format", "-f", "--output"),
    "trivy": ("--format", "-f", "--output", "-o"),
}


def _output_flag_warnings(config: Config) -> list[str]:
    """出力を奪うフラグは、スキャナを失敗させる. 実行前に理由を伝える (§7.2)."""
    warnings: list[str] = []
    for name, settings in config.scanner_settings().items():
        for argument in settings.extra_args:
            flag = argument.split("=", 1)[0]
            if flag in _OUTPUT_FLAGS.get(name, ()):
                warnings.append(
                    f"scanners.{name}.extra_args の {flag} は使えません。"
                    "出力の先や形式を変えると結果を読めず、スキャナは failed になります"
                )
    return warnings


#: transport: process では読まれない項目 (http transport 専用)
_HTTP_ONLY = ("base_url", "api_key_env", "headers", "headers_env")
#: transport: http では読まれない項目 (process transport 専用)
_PROCESS_ONLY = ("command", "prompt_via")

_SENSITIVE_HTTP_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "api-key",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "private-token",
    }
)


def _literal_sensitive_header_warnings(reviewer: ReviewerConfig) -> list[str]:
    """Avoid silently accepting credentials embedded in HTTP reviewer configs.

    Include only header names in warnings: logging their values would recreate
    the very credential disclosure this check is intended to prevent.
    """
    if reviewer.transport != "http":
        return []
    names = sorted(
        name
        for name, value in reviewer.headers.items()
        if value
        and (
            name.casefold() in _SENSITIVE_HTTP_HEADERS
            or name.casefold().endswith(("-api-key", "-token"))
        )
    )
    if not names:
        return []
    return [
        (
            f"reviewer '{reviewer.name}': 機密 HTTP ヘッダ ({', '.join(names)}) の値が "
            "headers に直接設定されています。資格情報は headers_env から環境変数で指定してください"
        )
    ]


def _transport_mismatch(reviewer: ReviewerConfig) -> list[str]:
    """transport に合わない項目は、書いても Provider に渡らない. そのことを伝える."""
    defaults = ReviewerConfig.model_fields
    ignored = _HTTP_ONLY if reviewer.transport == "process" else _PROCESS_ONLY
    return [
        f"reviewer '{reviewer.name}': {field} は transport: {reviewer.transport} では使われません"
        for field in ignored
        if getattr(reviewer, field) != defaults[field].get_default(call_default_factory=True)
    ]
