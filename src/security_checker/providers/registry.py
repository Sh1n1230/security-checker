"""ReviewerConfig から Provider を組み立てる (設計書 §9.3, §29).

capability の決定順序: 利用者の明示指定 → プリセットデータ → 互換性の高いモードへのフォールバック。
"""

from __future__ import annotations

import os
from importlib.metadata import EntryPoint, entry_points
from ipaddress import ip_address
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from pydantic import ValidationError

from security_checker.errors import ConfigError, SecurityCheckerError
from security_checker.providers.base import (
    Capabilities,
    CapabilityOverrides,
    LLMProvider,
    StructuredMode,
)
from security_checker.providers.detect import command_version
from security_checker.providers.http.dialects import DIALECTS, DialectOptions
from security_checker.providers.http.transport import HttpProvider
from security_checker.providers.presets.loader import (
    BasePreset,
    HttpPreset,
    ProcessPreset,
    load_http_presets,
    load_process_presets,
    resolve_http_preset,
    resolve_process_preset,
)
from security_checker.providers.process.runner import ProcessProvider

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    import httpx

    from security_checker.config.schema import ReviewerConfig

ENTRY_POINT_GROUP = "security_checker.providers"


def discover_plugin_providers() -> dict[str, EntryPoint]:
    """外部パッケージが登録した Provider を探す. 読み込むのは設定に書かれたものだけ."""
    return {entry.name: entry for entry in entry_points(group=ENTRY_POINT_GROUP)}


def build_plugin_provider(
    reviewer: ReviewerConfig, plugins: Mapping[str, EntryPoint] | None = None
) -> LLMProvider:
    """`transport: plugin` の Reviewer から Provider を作る.

    entry point の先は `factory(reviewer: ReviewerConfig) -> LLMProvider`。
    未登録の名前と読み込みの失敗は設定エラーにする (黙って別の Provider に落とさない)。
    """
    available = plugins if plugins is not None else discover_plugin_providers()
    entry = available.get(reviewer.plugin or "")
    if entry is None:
        raise ConfigError(
            f"reviewer '{reviewer.name}': plugin '{reviewer.plugin}' は entry point "
            f"({ENTRY_POINT_GROUP}) に登録されていません。"
            f"登録済み: {', '.join(sorted(available)) or '(なし)'}"
        )
    try:
        factory: Callable[[ReviewerConfig], LLMProvider] = entry.load()
        return factory(reviewer)
    except SecurityCheckerError:
        raise
    except Exception as exc:  # プラグイン側の任意の失敗を、原因の分かる設定エラーにする
        raise ConfigError(
            f"reviewer '{reviewer.name}': plugin '{entry.name}' を読み込めません "
            f"({type(exc).__name__}): {exc}"
        ) from exc


def resolve_api_key(reviewer: ReviewerConfig, environ: dict[str, str] | None = None) -> str | None:
    """API キーは環境変数からのみ取得する (設計書 §19.1)."""
    if reviewer.api_key_env is None:
        return None
    source = environ if environ is not None else dict(os.environ)
    value = source.get(reviewer.api_key_env)
    if not value:
        raise ConfigError(
            f"reviewer '{reviewer.name}': 環境変数 {reviewer.api_key_env} が設定されていません。"
            f"`export {reviewer.api_key_env}=...` を実行するか、api_key_env を修正してください"
        )
    return value


def resolve_headers(
    reviewer: ReviewerConfig, environ: dict[str, str] | None = None
) -> dict[str, str]:
    """追加ヘッダ. headers_env の値は API キーと同じく環境変数からのみ取得する (§19.1)."""
    source = environ if environ is not None else dict(os.environ)
    headers = dict(reviewer.headers)
    for name, variable in reviewer.headers_env.items():
        value = source.get(variable)
        if not value:
            raise ConfigError(
                f"reviewer '{reviewer.name}': ヘッダ {name} の環境変数 {variable} "
                "が設定されていません。"
                f"`export {variable}=...` を実行するか、headers_env を修正してください"
            )
        headers[name] = value
    return headers


def warn_insecure_credential_transport(
    reviewer: ReviewerConfig, base_url: str, api_key_env: str | None, warnings: list[str]
) -> None:
    """ローカル以外のホストへ平文の HTTP で資格情報を送る設定なら、警告を足す.

    API キーやヘッダの値が経路上で読める。警告には値を載せない (ホスト名だけ)。
    """
    if not (api_key_env or reviewer.headers_env):
        return
    parts = urlsplit(base_url)
    if parts.scheme.lower() != "http":
        return
    try:
        hostname = parts.hostname
    except ValueError:
        return
    if not hostname or hostname.lower() == "localhost":
        return
    try:
        if ip_address(hostname).is_loopback:
            return
    except ValueError:
        pass
    warnings.append(
        f"reviewer '{reviewer.name}': base_url が http:// で、ホスト {hostname} はローカルではありません。"
        "api_key_env / headers_env の値が平文 (plaintext) で送られます。https:// を使ってください"
    )


def resolve_capabilities(
    reviewer: ReviewerConfig,
    preset: BasePreset | None,
    dialect_defaults: Mapping[str, object] | None = None,
) -> Capabilities:
    """4 段構え: 既定 → 方言の形から決まる値 → プリセット → 利用者の明示指定 (後勝ち)."""
    base = Capabilities.model_validate(
        {
            **Capabilities(structured_output=StructuredMode.JSON_MODE).model_dump(mode="json"),
            **(dialect_defaults or {}),
        }
    )
    if preset is not None and preset.capabilities:
        try:
            base = Capabilities.model_validate(
                {**base.model_dump(mode="json"), **preset.capabilities}
            )
        except ValidationError as exc:  # プリセットのデータ不備を設定エラーとして返す
            raise ConfigError(
                f"プリセット '{preset.name}' の capabilities が不正です: {exc}"
            ) from exc
    overrides = CapabilityOverrides.model_validate(
        reviewer.capabilities.model_dump(exclude_none=True)
    )
    # モデルの出力上限は Reviewer の希望では変わらない. 引き上げたいときは
    # capabilities.max_output_tokens を明示する (上の overrides で効く) (#610)
    return overrides.apply(base)


def build_http_provider(
    reviewer: ReviewerConfig,
    *,
    environ: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
    presets: dict[str, HttpPreset] | None = None,
    warnings: list[str] | None = None,
) -> HttpProvider:
    """`transport: http` の Reviewer から Provider を作る."""
    available = presets if presets is not None else load_http_presets()
    preset = resolve_http_preset(
        available, name=reviewer.preset, base_url=reviewer.base_url, model=reviewer.model
    )

    dialect_name = reviewer.dialect or (preset.dialect if preset else None)
    base_url = reviewer.base_url or (preset.base_url if preset else None)
    if dialect_name is None or base_url is None or reviewer.model is None:
        raise ConfigError(
            f"reviewer '{reviewer.name}': dialect / base_url / model を解決できません。"
            "設定に直接書くか、preset を指定してください"
        )
    factory = DIALECTS.get(dialect_name)
    if factory is None:
        raise ConfigError(
            f"reviewer '{reviewer.name}': 未知の dialect '{dialect_name}'。"
            f"利用可能: {', '.join(sorted(DIALECTS))}"
        )
    # 方言ごとの追加パラメータ。ここに「どの方言か」の分岐は作らない (P1)。
    # 使わない方言は受け取って無視する。
    options = DialectOptions(num_ctx=reviewer.num_ctx, keep_alive=reviewer.keep_alive)

    api_key_env = reviewer.api_key_env or (preset.api_key_env if preset else None)
    key_source = reviewer.model_copy(update={"api_key_env": api_key_env})
    dialect = factory(options)
    api_key = resolve_api_key(key_source, environ)
    headers = resolve_headers(reviewer, environ)
    if warnings is not None:
        warn_insecure_credential_transport(reviewer, base_url, api_key_env, warnings)
    return HttpProvider(
        name=reviewer.name,
        dialect=dialect,
        base_url=base_url,
        model=reviewer.model,
        capabilities=resolve_capabilities(reviewer, preset, dialect.default_capabilities()),
        api_key=api_key,
        extra_headers=headers,
        client=client,
    )


def build_process_provider(
    reviewer: ReviewerConfig,
    *,
    environ: dict[str, str] | None = None,
    presets: dict[str, ProcessPreset] | None = None,
    warnings: list[str] | None = None,
) -> ProcessProvider:
    """`transport: process` の Reviewer から Provider を作る (§9.7).

    プリセットは省略記法にすぎない。`command` を直接書けば、プリセットが
    1 つも無くても動く — これが P2.5 の受け入れ条件そのものである。
    """
    available = presets if presets is not None else load_process_presets()
    preset = resolve_process_preset(available, name=reviewer.preset)

    command = reviewer.command or (list(preset.command) if preset else None)
    if not command:
        raise ConfigError(
            f"reviewer '{reviewer.name}': command を解決できません。"
            "command を直接書くか、preset を指定してください"
        )

    sink = warnings if warnings is not None else []
    _warn_unless_readonly_declared(reviewer, preset, sink)
    capabilities = resolve_capabilities(reviewer, preset)
    if reviewer.capabilities.structured_output not in (None, StructuredMode.PROMPT_ONLY.value):
        sink.append(
            f"reviewer '{reviewer.name}': transport: process の構造化出力は prompt_only のみです。"
            f"指定された {reviewer.capabilities.structured_output} は無視されます (§9.7)"
        )

    # command 直書きなら設定側が、preset 経由ならプリセットデータ側が渡し方を決める。
    direct = bool(reviewer.command)
    prompt_via = reviewer.prompt_via if direct or preset is None else preset.prompt_via
    parse = reviewer.parse if direct or preset is None else preset.parse
    return ProcessProvider(
        name=reviewer.name,
        command=command,
        capabilities=capabilities,
        model=reviewer.model or (preset.name if preset else None),
        prompt_via=prompt_via,
        parse=parse,
        version=command_version(command[0]).version,
        environ=environ,
    )


def _warn_unless_readonly_declared(
    reviewer: ReviewerConfig,
    preset: ProcessPreset | None,
    warnings: list[str],
) -> None:
    """書き込み能力の無効化を、本体は検証できない (§9.7 の 2).

    プリセットが `requires_readonly_flags: true` を申告している場合を除き、
    「その責任は利用者にある」ことを起動時に明示する。黙って起動しない。
    """
    if preset is not None and preset.requires_readonly_flags and not reviewer.command:
        return
    warnings.append(
        f"reviewer '{reviewer.name}': process transport は隔離した一時ディレクトリで起動し、"
        "書き込みがあれば検知しますが、コマンド自体の書き込み能力を無効化できているかは"
        "本体からは検証できません。非対話・ツール無効 (または読み取り専用) の指定が"
        "command に含まれていることを確認してください (§9.7)"
    )


def build_provider(
    reviewer: ReviewerConfig,
    *,
    environ: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
    presets: dict[str, HttpPreset] | None = None,
    plugins: Mapping[str, EntryPoint] | None = None,
    warnings: list[str] | None = None,
) -> LLMProvider:
    """transport に応じた Provider を作る."""
    if reviewer.transport == "http":
        return build_http_provider(
            reviewer, environ=environ, client=client, presets=presets, warnings=warnings
        )
    if reviewer.transport == "process":
        return build_process_provider(reviewer, environ=environ, warnings=warnings)
    return build_plugin_provider(reviewer, plugins)
